#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

    use brokk_bifrost_analysis::CodeUnitIndex;
    use brokk_bifrost_analysis::analyzer::QueryScope;
    use brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedInverseReferenceIndex;
    use brokk_bifrost_rust_analysis::analyzer::rust::RustSupport;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use std::sync::Arc;

    use std::collections::BTreeSet;

    use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

    use brokk_bifrost_rust_analysis::analyzer::rust::native_rename::RustBindingTargetProof;

    use brokk_bifrost_rust_analysis::analyzer::rust::native_rename::RustBindingWorldOutcome;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::RustDefinitionShadowResult;

    use brokk_bifrost_rust_analysis::analyzer::rust::native_rename::RustRenameSafetyOutcome;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::RustSelectedReferenceIndexOutcome;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::RustUsageShadowResult;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::RustWorkspaceBindingWorldResult;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::RustWorkspaceGraphShadowResult;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingSite;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingWorld;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

    use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageGraphBuildOutcome;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::build_rust_selected_reference_index;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::build_workspace_usage_graph_with_cancellation;

    use brokk_bifrost_rust_analysis::analyzer::rust::native_rename::native_rust_rename;

    use brokk_bifrost_core::path_utils::rel_path_string;

    use brokk_bifrost_rust_analysis::analyzer::rust::native_rename::selected_rust_binding_world;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::selected_rust_definition_shadow_result;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::selected_rust_definition_shadow_result_with_after_open;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::selected_rust_rename_shadow_result;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::selected_rust_usage_shadow_result;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::selected_rust_workspace_binding_world;

    use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::selected_rust_workspace_graph_shadow_result;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

    use brokk_bifrost_analysis::analyzer::rename::RenameSelection;

    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_test_macros::hardwon;

    fn rust_shadow_site(source: &str, spelling: &str) -> ResolvedReferenceSite {
        let start_byte = source.rfind(spelling).expect("Rust shadow call");
        brokk_bifrost_analysis::test_support::resolved_reference_site(
            "src/lib.rs".to_string(),
            spelling.to_string(),
            Range {
                start_byte,
                end_byte: start_byte + spelling.len(),
                start_line: 3,
                end_line: 3,
            },
        )
    }

    fn rust_shadow_tree(source: &str) -> tree_sitter::Tree {
        brokk_bifrost_analysis::test_support::parse_fixture_tree(
            source,
            tree_sitter_rust::LANGUAGE.into(),
        )
    }

    fn assert_rust_shadow_case(
        source: &str,
        spelling: &str,
        extra_files: &[(&str, &str)],
        expected_status: DefinitionLookupStatus,
        expected_names: &[&str],
    ) {
        let mut project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source);
        for &(path, contents) in extra_files {
            project = project.file(path, contents);
        }
        let fixture = project.build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, spelling);
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let (status, definitions) = match native {
            RustDefinitionShadowResult::Complete {
                status,
                definitions,
                ..
            } => (status, definitions),
            RustDefinitionShadowResult::Incomplete {
                definitions,
                completion,
                ..
            } if expected_status == DefinitionLookupStatus::Ambiguous => {
                // Equal-precedence targets retain their scoped precedence
                // evidence; rustc rejects this case with E0659.
                let crate::analyzer::resolution::ResolutionCompletion::Incomplete(reasons) =
                    completion
                else {
                    unreachable!("incomplete shadow result retains its reasons")
                };
                assert!(reasons.iter().all(|reason| matches!(reason,
                    crate::analyzer::resolution::ResolutionIncompleteReason::InconsistentPrecedence(_))),
                    "{reasons:?}");
                (DefinitionLookupStatus::Ambiguous, definitions)
            }
            other => panic!("Rust shadow case must complete for {spelling}: {other:#?}"),
        };
        assert_eq!(status, expected_status);
        let mut names = definitions
            .iter()
            .map(CodeUnit::short_name)
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, expected_names);
    }

    #[test]
    #[hardwon("#12812: vec macro certification omitted unit input reads from the request receipt")]
    fn rust_macro_type_certification_records_closure_inputs() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::{IAnalyzer, capture_query_reads};
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};
        let source = "pub fn probe() { let bytes = vec![1u8]; bytes; }";
        let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname=\"macro_receipt\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nhelper={path=\"helper\"}\n",
        )
        .file("helper/Cargo.toml", "[package]\nname=\"helper\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
        .file("helper/src/lib.rs", "pub fn helper() {}")
        .file("src/lib.rs", "mod child;")
        .file("src/child.rs", source)
        .build();
        let store = Arc::new(
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap(),
        );
        let project = fixture.project_dyn();
        let context =
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::revision_image_store_context(
                project.as_ref(),
                store.clone(),
            );
        let analyzer = RustAnalyzer::new_with_config_store_context(
            project,
            brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap();
        assert!(analyzer.all_declarations().next().is_some());
        let file = fixture.file("src/child.rs");
        let site = rust_shadow_site(source, "bytes");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let (answer, reads) =
            capture_query_reads(&analyzer, || RustSupport.resolve_type_bounded(query));

        assert!(
            reads.keys().into_iter().any(|read| matches!(read,
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    question: LookupQuestion::Derivation(question), ..
                } if kind.0 == "derivation:rust_file_units:v1"
                    && question.rel_path.as_deref() == Some("src/child.rs")
            )),
            "{reads:?}"
        );
        let inputs = reads
            .keys()
            .into_iter()
            .filter_map(|read| match read {
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    question: LookupQuestion::Derivation(question),
                    ..
                } if kind.0 == "derivation:rust_unit_inputs:v2" => question.subject,
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            inputs.len(),
            2,
            "macro certification must record its unit closure: {reads:?}; answer: {answer:?}"
        );
        let (kind, question, digest) = reads
            .keys()
            .into_iter()
            .find_map(|read| match read {
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    question: LookupQuestion::Derivation(question),
                    digest,
                } if kind.0 == "derivation:rust_file_units:v1"
                    && question.rel_path.as_deref() == Some("src/child.rs") =>
                {
                    Some((kind, question, digest))
                }
                _ => None,
            })
            .unwrap();
        drop(_scope);
        std::fs::write(
            fixture.root().join("src/main.rs"),
            "#![no_implicit_prelude]\nmod child;\nfn main() {}\n",
        )
        .unwrap();
        let project = fixture.project_dyn();
        let context =
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::revision_image_store_context(
                project.as_ref(),
                store,
            );
        let reopened = RustAnalyzer::new_with_config_store_context(
            project,
            brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap();
        assert!(reopened.all_declarations().next().is_some());
        assert_ne!(
            IAnalyzer::derivations(&reopened)
                .unwrap()
                .replay(&reopened, kind, &question),
            brokk_bifrost_analysis::analyzer::derivation_host::ReplayResult::Identity(
                brokk_bifrost_semantic::analyzer::semantic::derivation::OutputIdentity(digest)
            ),
            "adding a target must invalidate the retained membership answer"
        );
    }

    #[test]
    #[hardwon(
        "#4488: additive derive metadata falsely opened unrelated authored reverse inventory"
    )]
    fn derive_surface_keeps_authored_reverse_complete() {
        use brokk_bifrost_rust_analysis::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

        use brokk_bifrost_rust_analysis::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;

        use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

        use brokk_bifrost_core::analyzer::usages::model::UsageProof;

        let source = concat!(
            "#[derive(Unknown)] pub struct Generated;\n",
            "pub struct Worker; impl Worker { pub fn run(self) {} }\n",
            "pub fn caller() { let worker = Worker; worker.run(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname='derive_views'\nversion='0.1.0'\nedition='2024'\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let target = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "run" && unit.is_function())
            .unwrap();
        let result =
            with_rust_selected_reverse_queries(&analyzer, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[target])
            });
        let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
            panic!("authored reverse lookup must be available: {result:?}");
        };
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].edges.len(), 1, "{rows:?}");
        assert_eq!(rows[0].edges[0].proof, UsageProof::Proven, "{rows:?}");
        assert_eq!(rows[0].completeness, EdgeCompleteness::Complete, "{rows:?}");
    }

    #[test]
    fn selected_rust_forward_mixed_module_and_type_prefixes_retain_both_targets() {
        let source = concat!(
            "pub mod modules;\n",
            "pub mod types;\n",
            "use crate::modules::Api;\n",
            "use crate::types::Api;\n",
            "pub fn caller() { Api::target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"mixed-prefix\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/modules.rs", "pub mod Api { pub fn target() {} }\n")
            .file(
                "src/types.rs",
                "pub struct Api;\nimpl Api { pub fn target() {} }\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "target");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };

        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let definitions = match native {
            RustDefinitionShadowResult::Complete {
                status,
                definitions,
                ..
            } => {
                assert_eq!(
                    status,
                    DefinitionLookupStatus::Ambiguous,
                    "a complete mixed prefix must remain ambiguous"
                );
                definitions
            }
            RustDefinitionShadowResult::Incomplete { definitions, .. } => definitions,
            other => panic!("mixed module/type prefix must retain native targets: {other:#?}"),
        };
        assert_eq!(
            definitions.len(),
            2,
            "native forward targets: {definitions:#?}"
        );
        assert!(definitions.iter().any(|unit| {
            unit.source().rel_path() == std::path::Path::new("src/modules.rs")
                && unit.identifier() == "target"
                && unit.owner_identifier() == Some("Api")
        }));
        assert!(definitions.iter().any(|unit| {
            unit.source().rel_path() == std::path::Path::new("src/types.rs")
                && unit.identifier() == "target"
                && unit.owner_identifier() == Some("Api")
        }));
    }

    #[test]
    fn production_rename_shadow_detects_counterfactual_lexical_capture() {
        let source = concat!(
            "pub fn target() {}\n",
            "pub fn caller() {\n",
            "    let renamed = || {};\n",
            "    target();\n",
            "}\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration_start = source.find("target").expect("target declaration");

        let error = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            file,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect_err("production rename must reject lexical capture");
        assert_eq!(error.kind, "incomplete_analysis");
        assert!(error.message.contains("CapturedOrRebound"), "{error:#?}");
    }

    #[test]
    fn production_rename_shadow_proves_lexical_near_miss_safe_in_closed_library() {
        let source = concat!(
            "pub fn target() {}\n",
            "pub fn caller() {\n",
            "    {\n",
            "        let renamed = || {};\n",
            "        renamed();\n",
            "    }\n",
            "    target();\n",
            "}\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration_start = source.find("target").expect("target declaration");

        let result = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            file,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect("production rename returns its non-mutating edits");
        let native =
            selected_rust_rename_shadow_result(&analyzer, fixture.project(), &result, "renamed");

        assert_eq!(native, RustRenameSafetyOutcome::Safe);
        let file = fixture.file("src/lib.rs");
        let target = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        let result = brokk_bifrost_analysis::analyzer::rename::RenameProvider::rename(
            &brokk_bifrost_rust_analysis::analyzer::rust::native_rename::RustNativeRenameProvider,
            &analyzer,
            fixture.project(),
            &target,
            "renamed",
        )
        .expect("native-only preparation proves the near miss safe");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].edits.len(), 2);
        for edit in &result.files[0].edits {
            assert_eq!(&source[edit.start_byte..edit.end_byte], "target");
            assert_eq!(edit.new_text, "renamed");
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            native_rust_rename(&analyzer, fixture.project(), &target, "renamed", &cancelled)
                .is_err()
        );
    }

    #[hardwon(
        "4ea6d2b2f5cb: qualified Rust path prefixes were not resolved from selected source authority during rename"
    )]
    #[test]
    fn native_rename_updates_import_targets_without_changing_aliases() {
        for (import, call, expected_edits) in [
            ("use crate::api::target;", "target", 2),
            ("use crate::api::target as local;", "local", 1),
        ] {
            let source = format!("pub mod api;\n{import}\npub fn caller() {{ {call}(); }}\n");
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"rename_import\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", source.clone())
                .file("src/api.rs", "pub fn target() {}\n")
                .build();
            let analyzer = RustAnalyzer::new(fixture.project_dyn());
            let target = analyzer
                .declarations(&fixture.file("src/api.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .unwrap();
            let result = native_rust_rename(
                &analyzer,
                fixture.project(),
                &target,
                "renamed",
                &CancellationToken::new(),
            )
            .expect("native import references must produce a capture-safe rename");
            assert_eq!(result.files.len(), 2, "{result:?}");
            let imported = result
                .files
                .iter()
                .find(|file| file.file == fixture.file("src/lib.rs"))
                .unwrap();
            assert_eq!(imported.edits.len(), expected_edits, "{result:?}");
            for edit in &imported.edits {
                assert_eq!(&source[edit.start_byte..edit.end_byte], "target");
                assert_eq!(edit.new_text, "renamed");
            }
            let declaration = result
                .files
                .iter()
                .find(|file| file.file == fixture.file("src/api.rs"))
                .unwrap();
            assert_eq!(declaration.edits.len(), 1, "{result:?}");
        }
    }

    #[test]
    #[hardwon(
        "4ea6d2b2f5cb: qualified Rust path prefixes were not resolved from selected source authority during rename"
    )]
    fn native_rename_preserves_qualified_prefixes_in_counterfactual_content() {
        let mut failures = Vec::new();
        for (label, source) in [
            (
                "module prefix",
                "pub mod inner { pub fn target() {} }\npub fn caller() { inner::target(); }\n",
            ),
            (
                "enum prefix",
                "pub enum Choice { target }\npub fn caller() { let _ = Choice::target; }\n",
            ),
            (
                "module declaration",
                "pub mod target { pub fn member() {} }\npub fn caller() { target::member(); }\n",
            ),
            (
                "enum declaration",
                "pub enum target { Member }\npub fn caller() { let _ = target::Member; }\n",
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"rename_prefix\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", source)
                .build();
            let analyzer = RustAnalyzer::new(fixture.project_dyn());
            let target = analyzer
                .declarations(&fixture.file("src/lib.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .expect("fixture target declaration");
            match native_rust_rename(
                &analyzer,
                fixture.project(),
                &target,
                "renamed",
                &CancellationToken::new(),
            ) {
                Ok(result) => {
                    assert_eq!(result.files.len(), 1, "{label}: {result:?}");
                    assert_eq!(result.files[0].edits.len(), 2, "{label}: {result:?}");
                    for edit in &result.files[0].edits {
                        assert_eq!(&source[edit.start_byte..edit.end_byte], "target");
                        assert_eq!(edit.new_text, "renamed");
                    }
                }
                Err(error) if label == "module declaration" => {
                    assert!(error.contains("OverlayFrontierUnknown"), "{error}");
                    assert!(error.contains("overlay adds a module edge"), "{error}");
                    assert!(error.contains("#12219"), "{error}");
                }
                Err(error) => failures.push((label, error)),
            }
        }
        assert!(
            failures.is_empty(),
            "qualified counterfactual rename failures: {failures:?}"
        );
    }

    // R4.6 (#3250): the native rename consumer must refuse rather than answer
    // from a reference inventory it cannot prove complete. A refusal is a
    // reviewable outcome; a rename built on partial references silently edits
    // some call sites and leaves others behind.
    #[test]
    #[hardwon("#12260: incomplete rename evidence dumped interner IDs and absolute paths")]
    fn native_rename_refuses_an_unprovable_reference_inventory() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"rename_refusal\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn target() {}\npub fn caller() { target(); }\nunknown_macro!(target);\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "target")
            .expect("target declaration");
        let outcome = native_rust_rename(
            &analyzer,
            fixture.project(),
            &target,
            "renamed",
            &CancellationToken::new(),
        );
        let error = outcome.expect_err(
            "an unprovable reference inventory must refuse the rename, not edit a subset",
        );
        assert!(
            error.contains("incomplete or ambiguous"),
            "the refusal must name the evidence it lacked: {error}"
        );
        assert!(
            error.contains("src/lib.rs"),
            "the evidence must identify its workspace-relative site: {error}"
        );
        assert!(
            !error.contains("SegmentId("),
            "the evidence must not expose interner IDs: {error}"
        );
        assert!(
            !error.contains("ast_id"),
            "the evidence must not expose AST digests: {error}"
        );
        assert!(
            !error.contains(&fixture.root().to_string_lossy().to_string()),
            "the evidence must not expose the absolute project root: {error}"
        );
    }

    #[test]
    fn production_rename_shadow_accepts_counterfactuals_based_on_prepared_overlay() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"rename_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn target() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "target")
        );
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let request: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(Arc::clone(&request));
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        let result = crate::symbol_rename::rename_symbol(
            &analyzer,
            request.as_ref(),
            file,
            RenameSelection::ByteOffset(source.find("target").expect("target declaration")),
            "renamed",
        )
        .expect("prepared overlay rename returns non-mutating edits");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].edits.len(), 2);
        let native =
            selected_rust_rename_shadow_result(&analyzer, request.as_ref(), &result, "renamed");
        assert_eq!(
            native,
            RustRenameSafetyOutcome::Safe,
            "hypothetical renamed bytes must validate against their live base, not themselves"
        );
    }

    #[test]
    #[hardwon("3e4862340fb8: Cargo profiles sharing one Rust source invalidated rename safety")]
    fn production_rename_shadow_proves_shared_explicit_target_safe() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                concat!(
                    "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[[bin]]\nname = \"same-source\"\npath = \"src/lib.rs\"\n",
                ),
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declaration_start = source.find("target").expect("target declaration");

        let result = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            file,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect("production rename returns its non-mutating edits");
        let native =
            selected_rust_rename_shadow_result(&analyzer, fixture.project(), &result, "renamed");

        assert_eq!(
            native,
            RustRenameSafetyOutcome::Safe,
            "enumerating every Cargo profile closes the shared-source counterfactual"
        );
    }

    #[test]
    fn production_rename_shadow_detects_named_import_over_wildcard_capture() {
        let source = concat!(
            "pub mod provider;\n",
            "pub mod named;\n",
            "use crate::provider::*;\n",
            "use crate::named::renamed;\n",
            "pub fn caller() { target(); }\n",
        );
        let provider_source = "pub fn target() {}\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/provider.rs", provider_source)
            .file("src/named.rs", "pub fn renamed() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let provider = fixture.file("src/provider.rs");
        let declaration_start = provider_source.find("target").expect("target declaration");

        let error = crate::symbol_rename::rename_symbol(
            &analyzer,
            fixture.project(),
            provider,
            RenameSelection::ByteOffset(declaration_start),
            "renamed",
        )
        .expect_err("production rename must reject named-import capture");
        assert_eq!(error.kind, "incomplete_analysis");
        assert!(error.message.contains("CapturedOrRebound"), "{error:#?}");
    }

    #[test]
    #[hardwon("#5780: conflicting glob targets retain scoped precedence evidence")]
    fn production_structural_resolver_shadows_local_absent_and_ambiguous_rust_points() {
        assert_rust_shadow_case(
            "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
            "target",
            &[],
            DefinitionLookupStatus::Resolved,
            &["target"],
        );
        assert_rust_shadow_case(
            "pub fn caller() -> usize { missing() }\n",
            "missing",
            &[],
            DefinitionLookupStatus::NoDefinition,
            &[],
        );
        assert_rust_shadow_case(
            "#[link(name = \"native\")]\nunsafe extern \"C\" { fn foreign() -> usize; }\npub fn caller() -> usize { unsafe { foreign() } }\n",
            "foreign",
            &[],
            DefinitionLookupStatus::Resolved,
            &["foreign"],
        );
        assert_rust_shadow_case(
            "pub union Bits { word: u32, bytes: [u8; 4] }\npub fn read(value: Bits) -> u32 { unsafe { value.word } }\n",
            "Bits",
            &[],
            DefinitionLookupStatus::Resolved,
            &["Bits"],
        );
        assert_rust_shadow_case(
            "pub struct Unit;\npub fn make() -> Unit { Unit }\n",
            "Unit",
            &[],
            DefinitionLookupStatus::Resolved,
            &["Unit"],
        );
        assert_rust_shadow_case(
            "pub struct Tuple(pub u32);\npub fn make() -> Tuple { Tuple(1) }\n",
            "Tuple",
            &[],
            DefinitionLookupStatus::Resolved,
            &["Tuple"],
        );
        assert_rust_shadow_case(
            "pub fn target() -> usize { 1 }\npub fn generic<T, const N: usize>(value: T) -> usize { let _ = [0; N]; let _ = value; target() }\n",
            "target",
            &[],
            DefinitionLookupStatus::Resolved,
            &["target"],
        );
        assert_rust_shadow_case(
            "pub mod model;\npub use model::Tuple;\npub fn make() -> Tuple { Tuple(1) }\n",
            "Tuple",
            &[("src/model.rs", "pub struct Tuple(pub u32);\n")],
            DefinitionLookupStatus::Resolved,
            &["Tuple"],
        );
        assert_rust_shadow_case(
            "pub static READY: bool = true;\npub fn caller() { if READY {} }\n",
            "READY",
            &[],
            DefinitionLookupStatus::Resolved,
            &["_module_.READY"],
        );
        assert_rust_shadow_case(
            "pub static mut COUNTER: usize = 0;\npub fn reset() { unsafe { COUNTER = 1; } }\n",
            "COUNTER",
            &[],
            DefinitionLookupStatus::Resolved,
            &["_module_.COUNTER"],
        );
        assert_rust_shadow_case(
            "pub static LIMIT: usize = 4;\npub fn values() { let _ = 0..LIMIT; }\n",
            "LIMIT",
            &[],
            DefinitionLookupStatus::Resolved,
            &["_module_.LIMIT"],
        );
        assert_rust_shadow_case(
            concat!(
                "pub mod left;\n",
                "pub mod right;\n",
                "pub use left::*;\n",
                "pub use right::*;\n",
                "pub fn caller() -> usize { target() }\n",
            ),
            "target",
            &[
                ("src/left.rs", "pub fn target() -> usize { 1 }\n"),
                ("src/right.rs", "pub fn target() -> usize { 2 }\n"),
            ],
            DefinitionLookupStatus::Ambiguous,
            &["target", "target"],
        );
    }

    #[test]
    fn production_native_shadow_fails_closed_for_unprojectable_local_items() {
        let source = "pub fn caller() -> usize { fn local() -> usize { 1 } local() }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "local");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };

        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let RustDefinitionShadowResult::Incomplete {
            definitions,
            completion,
            ..
        } = native
        else {
            panic!("local item must remain an explicit native boundary: {native:#?}")
        };
        assert!(definitions.is_empty());
        assert_ne!(completion, ResolutionCompletion::Complete);
        // Items declared in a block expression are in scope throughout the
        // block (Rust reference, block expressions and items), so `local()`
        // does have a definition and an answer of "none" would be an absence
        // rather than a correct negative. The shadow comparator above still
        // holds the whole selection to the producer's gap, because the
        // whole-workspace graph has no node for a block-local declaration and
        // that incompleteness is the graph's to hear.
        //
        // The production point route answers the definition. It found the
        // binding, and since 2026-09-11 (`b3836b21f`) the item carries an
        // out-of-graph canonical source declaration, so the projection the gap
        // said was missing exists and the route discharges the gap against it
        // (`rust::native_points`, `adapt_definition_answer`). This expectation
        // was `Incomplete` with an `incomplete_binding` diagnostic, which
        // described the state before that declaration was published: the route
        // could then say only that it had found the binding and could not
        // project it, and before that it failed the whole operation with
        // `Unavailable(MissingDefinitionUnit)`.
        let BoundedResolution::Complete { value, .. } =
            RustSupport.resolve_definition_bounded(query)
        else {
            panic!("uncancelled local-item query must retain its native boundary")
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(value.definitions.is_empty(), "{value:#?}");
        assert_eq!(
            value
                .lexical_definition
                .as_ref()
                .map(|definition| (definition.identifier.as_str(), definition.kind)),
            Some((
                "local",
                brokk_bifrost_core::analyzer::model::DeclarationKind::BlockLocalItem
            )),
            "{value:#?}"
        );
    }

    #[test]
    #[hardwon("#9194: a type-specific local kind lost Rust point and reverse gap discharge")]
    fn block_local_type_keeps_point_and_reverse_discharge() {
        use brokk_bifrost_rust_analysis::analyzer::rust::selected_reverse::{
            RustSelectedReverseOutcome, with_rust_selected_reverse_queries,
        };

        let source =
            "pub struct Local;\npub fn outer() {\n    struct Local; let _: Local = todo!();\n}\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname='local_type_control'\nversion='0.1.0'\nedition='2024'\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "Local");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let BoundedResolution::Complete { value, .. } =
            RustSupport.resolve_definition_bounded(query)
        else {
            panic!("local type point lookup must complete");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(value.definitions.is_empty(), "{value:#?}");
        assert_eq!(
            value
                .lexical_definition
                .as_ref()
                .map(|definition| definition.kind),
            Some(brokk_bifrost_core::analyzer::model::DeclarationKind::BlockLocalType)
        );

        let global = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "Local")
            .expect("global Local");
        let reverse =
            with_rust_selected_reverse_queries(&analyzer, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[global])
            });
        let RustSelectedReverseOutcome::Ready(Some(rows)) = reverse else {
            panic!("global type reverse lookup must be available: {reverse:?}");
        };
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(
            rows[0].edges.is_empty(),
            "local type must not reference the global: {rows:?}"
        );
        assert_eq!(rows[0].completeness, EdgeCompleteness::Complete, "{rows:?}");
    }

    #[test]
    #[ignore = "finds real bug: function-local macro enumeration retains two UnsupportedSemantic reasons instead of Complete (#2767). Owner: selected_rust_workspace_binding_world"]
    fn partition_2767_local_macro_enumeration_is_complete() {
        let world = partition_binding_world(
            "fn unrelated() { macro_rules! value { () => { 1 }; } let _ = value!(); }\nfn target() {}\nfn caller() { target(); }\n",
        );
        assert_eq!(world.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn production_call_relations_preserve_exact_and_ambiguous_rust_calls() {
        let source = concat!(
            "pub mod left;\n",
            "pub mod right;\n",
            "pub use left::*;\n",
            "pub use right::*;\n",
            "pub fn exact(value: usize) -> usize { value }\n",
            "pub fn caller() -> usize { exact(1) + target(2) }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file(
                "src/left.rs",
                "pub fn target(value: usize) -> usize { value }\n",
            )
            .file(
                "src/right.rs",
                "pub fn target(value: usize) -> usize { value }\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let caller = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .expect("caller declaration");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let outgoing = CallRelationService::outgoing(&analyzer, scope.token(), &caller, 16);
        assert_eq!(outgoing.sites.len(), 3, "{outgoing:#?}");
        assert!(!outgoing.truncated && !outgoing.cancelled, "{outgoing:#?}");
        assert_eq!(
            outgoing
                .sites
                .iter()
                .filter(|site| site.proof == UsageProof::Proven)
                .count(),
            1
        );
        assert_eq!(
            outgoing
                .sites
                .iter()
                .filter(|site| site.proof == UsageProof::Unproven)
                .count(),
            2
        );
        assert!(outgoing.sites.iter().all(|site| {
            site.kind == CallSyntaxKind::Function
                && site.receiver.is_none()
                && site.arguments.len() == 1
                && site.arguments[0].position == Some(0)
                && site.arguments[0].name.is_none()
                && site.arguments[0].formal_index.is_none()
                && site.arguments[0].formal_name.is_none()
                && !site.arguments[0].variadic
                && !site.arguments[0].spread
        }));
        // Relation-layer ambiguity has no analyzer failure reason; RQL
        // reserves reason_kind for AnalysisFailed diagnostics.
        assert!(outgoing.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode::TargetsAmbiguous
                && diagnostic.reason_kind.is_none()
        }));

        let exact = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "exact")
            .expect("exact target declaration");
        let left_target = analyzer
            .declarations(&fixture.file("src/left.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("ambiguous left target declaration");
        let incoming_exact =
            CallRelationService::incoming(&analyzer, scope.token(), &exact, 16, 16);
        assert_eq!(incoming_exact.sites.len(), 1, "{incoming_exact:#?}");
        assert_eq!(incoming_exact.sites[0].caller, caller);
        assert_eq!(incoming_exact.sites[0].proof, UsageProof::Proven);
        assert_eq!(incoming_exact.sites[0].kind, CallSyntaxKind::Function);
        assert!(incoming_exact.sites[0].receiver.is_none());
        assert_eq!(incoming_exact.sites[0].arguments.len(), 1);

        let incoming_ambiguous =
            CallRelationService::incoming(&analyzer, scope.token(), &left_target, 16, 16);
        assert_eq!(incoming_ambiguous.sites.len(), 1, "{incoming_ambiguous:#?}");
        assert_eq!(incoming_ambiguous.sites[0].caller, caller);
        assert_eq!(incoming_ambiguous.sites[0].proof, UsageProof::Unproven);
    }

    #[test]
    fn production_binding_world_keeps_local_calls_proven_with_unrelated_gaps() {
        let mut incomplete_local_calls = Vec::new();
        for extra_source in [
            "",
            "fn unrelated() { external::missing(); }\n",
            "use external::Unknown;\nfn unrelated(_: Unknown) {}\n",
            "#[cfg(test)] mod tests { #[test] fn check() { super::target(); } }\n",
            "fn methods(value: Unknown) { value.method(); value.method::<usize>(); }\n",
            "fn indirect(function: fn(), pair: (fn(),), values: [fn(); 1]) { (function)(); pair.0(); values[0](); }\n",
            "struct Subject;\nimpl Subject { fn method(&self) {} }\n",
            "fn generic<T>(_: T) {}\n",
            "fn pattern(pair: (usize, usize)) { let (left, right) = pair; }\n",
        ] {
            let source = format!("{extra_source}fn target() {{}}\nfn caller() {{ target(); }}\n");
            let world = binding_world(&source, "shadow");
            if extra_source.is_empty() {
                assert_eq!(
                    world.completion(),
                    &ResolutionCompletion::Complete,
                    "unused call-result projections must not weaken the binding world"
                );
            }
            let site = assert_local_call_targets(&world, &source);
            if site.completion() != &ResolutionCompletion::Complete {
                incomplete_local_calls.push((extra_source, site.clone()));
            }
        }
        assert!(
            incomplete_local_calls.is_empty(),
            "unrelated input must not weaken a local declaration binding: {incomplete_local_calls:#?}"
        );
    }

    #[test]
    #[hardwon("cf6242ee4553: a function-local Rust import alias made a sibling call incomplete")]
    fn partition_2767_local_import_alias_keeps_sibling_call_proven() {
        assert_unrelated_item_keeps_local_call_proven(
            "enum Mode { Exact }\nfn unrelated() { use Mode as Alias; }",
        );
    }

    #[test]
    #[hardwon(
        "#12203: the rename binding world certified completeness under an overlay-added module edge"
    )]
    fn rename_binding_world_overlay_frontier() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname='overlay_control'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod caller;\npub fn target() {}\n")
            .file("src/caller.rs", "pub fn caller() { crate::target(); }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        assert!(!disk.declarations(&fixture.file("src/lib.rs")).is_empty());
        for (source, complete) in [
            (
                "pub fn caller() { crate::target(); let _body = 1; }\n",
                true,
            ),
            (
                "#[path = \"../not-yet-written.rs\"] mod added;\npub fn caller() { crate::target(); }\n",
                false,
            ),
        ] {
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            let caller = fixture.file("src/caller.rs");
            assert!(overlay.set(caller.abs_path(), source.to_owned()));
            let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
            assert!(!analyzer.declarations(&caller).is_empty());
            let target = analyzer
                .declarations(&fixture.file("src/lib.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .expect("target");
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
                ..
            } = analyzer
                .inner
                .selected_rust_resolution_overlay_inputs(
                    snapshots.as_ref(),
                    &CancellationToken::default(),
                )
                .unwrap()
            else {
                panic!("overlay inputs must be available");
            };
            let result = selected_rust_binding_world(
                &analyzer,
                snapshots.as_ref(),
                RustBindingTargetProof::Current(&target),
                &masks,
                content_mounts,
                &CancellationToken::default(),
            );
            let RustBindingWorldOutcome::Ready(world) = result else {
                panic!("binding world must be available: {result:?}");
            };
            assert_eq!(
                world.completion() == &ResolutionCompletion::Complete,
                complete,
                "{world:?}"
            );
            if !complete {
                assert!(
                    format!("{:?}", world.completion()).contains("OverlayFrontierUnknown"),
                    "{world:?}"
                );
            }
        }
    }

    fn partition_binding_world(source: &str) -> SelectedRustBindingWorld {
        binding_world(source, "partition")
    }

    fn binding_world(source: &str, package_name: &str) -> SelectedRustBindingWorld {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                format!(
                    "[package]\nname = \"{package_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
                ),
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("local target declaration");
        let result = selected_rust_binding_world(
            &analyzer,
            analyzer.inner.selected_workspace_snapshots().as_ref(),
            RustBindingTargetProof::Current(&target),
            &[],
            Vec::new(),
            &CancellationToken::default(),
        );
        let RustBindingWorldOutcome::Ready(world) = result else {
            panic!("local binding world must be available: {result:?}")
        };
        world
    }

    fn assert_unrelated_item_keeps_local_call_proven(extra_source: &str) {
        let source = format!("{extra_source}\nfn target() {{}}\nfn caller() {{ target(); }}\n");
        let world = partition_binding_world(&source);
        let site = assert_local_call_targets(&world, &source);
        assert_eq!(
            site.completion(),
            &ResolutionCompletion::Complete,
            "unrelated item must not weaken the local call: {extra_source}"
        );
    }

    fn assert_local_call_targets<'a>(
        world: &'a SelectedRustBindingWorld,
        source: &str,
    ) -> &'a SelectedRustBindingSite {
        let call_start = source.rfind("target()").expect("local call");
        let site = world
            .sites()
            .iter()
            .find(|site| {
                site.metadata()
                    .is_some_and(|metadata| metadata.start_byte() == call_start)
            })
            .expect("local call has a structured binding site");
        assert_eq!(site.definitions(), std::slice::from_ref(world.target()));
        site
    }

    #[test]
    #[hardwon(
        "b9f5fb23eeb2: malformed Rust coverage in an unrelated block weakened a local binding"
    )]
    fn partition_2767_malformed_block_keeps_local_call_proven() {
        assert_unrelated_item_keeps_local_call_proven("fn unrelated() { let = ; }");
    }

    #[test]
    #[hardwon("b9f5fb23eeb2: malformed Rust scope was treated as complete for an affected call")]
    fn partition_2767_malformed_scope_keeps_affected_call_incomplete() {
        let source = "fn target() {}\nfn caller() { let broken = ; target(); }\n";
        let world = partition_binding_world(source);
        assert_ne!(world.completion(), &ResolutionCompletion::Complete);
        assert_eq!(world.sites().len(), 1);
        let site = &world.sites()[0];
        assert_eq!(site.definitions(), std::slice::from_ref(world.target()));
        assert_ne!(site.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    #[hardwon(
        "cf6242ee4553: unknown Rust attribute expansions were omitted from binding completeness"
    )]
    fn partition_2767_unknown_attributes_preserve_existing_call_bindings() {
        for extra in [
            "#[serde(rename_all = \"snake_case\")] enum Mode { Exact }",
            "#[derive(serde::Serialize)] #[other::transform] struct Params;",
            "mod serde {} #[derive(serde::Serialize)] #[serde(rename_all = \"snake_case\")] enum Mode { Exact }",
            "extern crate other as serde; #[derive(serde::Serialize)] #[serde(rename_all = \"snake_case\")] enum Mode { Exact }",
        ] {
            let world = partition_binding_world(&format!(
                "{extra}\nfn target() {{}}\nfn caller() {{ target(); }}\n"
            ));
            let sites = world
                .sites()
                .iter()
                .filter(|site| site.definitions().contains(world.target()))
                .collect::<Vec<_>>();
            assert_eq!(sites.len(), 1, "{extra}");
            assert_eq!(
                sites[0].completion(),
                &ResolutionCompletion::Complete,
                "{extra}"
            );
        }
    }

    #[test]
    fn partition_2767_derive_helper_closes_without_opening_unrelated_items() {
        let world = partition_binding_world(
            "#[cfg(any())] use serde::Serialize; #[derive(Serialize)] #[serde(rename_all = \"snake_case\")] enum Mode { Exact }\nfn target() {}\nfn caller() { target(); }\n",
        );
        let sites = world
            .sites()
            .iter()
            .filter(|site| site.definitions().contains(world.target()))
            .collect::<Vec<_>>();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    #[hardwon(
        "cf6242ee4553: unresolved local Rust imports were omitted from the affected call boundary"
    )]
    fn partition_2767_local_import_keeps_affected_call_incomplete() {
        let world = partition_binding_world(
            "enum Mode { Exact }\nfn target() {}\nfn caller() { use *; target(); }\n",
        );
        assert_eq!(world.sites().len(), 1);
        assert_ne!(
            world.sites()[0].completion(),
            &ResolutionCompletion::Complete
        );
    }

    #[test]
    #[hardwon("cf6242ee4553: generated inventory gaps hid valid Rust reference sites")]
    fn partition_2767_eight_reference_bindings() {
        let files = [
            (
                "src/lib.rs",
                "mod missing_tests; mod mcp_diff; mod mcp_registry; mod scoped_project; mod searchtools_service;\n",
            ),
            (
                "src/missing_tests.rs",
                r#"
use serde::Serialize;
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode { Exact }
fn scan_target() {}
fn caller() { scan_target(); }
fn unrelated() { macro_rules! value { () => { 1 }; } let _ = value!(); }
fn alias_scope() { use Mode as Alias; }
"#,
            ),
            ("src/mcp_diff.rs", "pub fn diff_tool_descriptors() {}\n"),
            (
                "src/mcp_registry.rs",
                r#"
fn discovery_instructions() {}
fn discover() { discovery_instructions(); }
fn registry() { crate::mcp_diff::diff_tool_descriptors(); }
"#,
            ),
            (
                "src/scoped_project.rs",
                r#"
use crate::searchtools_service::SearchToolsService;
fn caller() { SearchToolsService::tool_is_workspace_independent(); }
"#,
            ),
            (
                "src/searchtools_service.rs",
                r#"
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params { value: bool }
pub struct SearchToolsService;
impl SearchToolsService {
    pub fn tool_is_workspace_independent() {}
    fn call_tool_output_with_transport_queue_wait_inner(&self) {}
    fn call_2583(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
    fn call_2597(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
    fn call_2623(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
    fn call_2645(&self) { self.call_tool_output_with_transport_queue_wait_inner(); }
}
"#,
            ),
        ];
        let mut project = InlineTestProject::with_language(Language::Rust).file(
            "Cargo.toml",
            "[package]\nname = \"partition\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        );
        for (path, source) in files {
            project = project.file(path, source);
        }
        let fixture = project.build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let mut proven = 0;
        for (name, count) in [
            ("scan_target", 1),
            ("diff_tool_descriptors", 1),
            ("discovery_instructions", 1),
            ("tool_is_workspace_independent", 1),
            ("call_tool_output_with_transport_queue_wait_inner", 4),
        ] {
            let target = analyzer
                .all_declarations()
                .find(|unit| unit.identifier() == name)
                .unwrap();
            let RustBindingWorldOutcome::Ready(world) = selected_rust_binding_world(
                &analyzer,
                analyzer.inner.selected_workspace_snapshots().as_ref(),
                RustBindingTargetProof::Current(&target),
                &[],
                Vec::new(),
                &CancellationToken::default(),
            ) else {
                panic!("fixture reverse world must be ready for {name}");
            };
            let sites = world
                .sites()
                .iter()
                .filter(|site| site.definitions().contains(world.target()))
                .collect::<Vec<_>>();
            assert_eq!(sites.len(), count, "{name}");
            for site in sites {
                assert_eq!(
                    site.definitions(),
                    std::slice::from_ref(world.target()),
                    "{name}"
                );
                assert_eq!(site.completion(), &ResolutionCompletion::Complete, "{name}");
                proven += 1;
            }
        }
        assert_eq!(proven, 8);
    }

    #[test]
    #[hardwon("ab936fc5ed31: selected Rust barrel imports produced duplicate canonical rows")]
    fn selected_shadow_barrel_import_has_one_canonical_row() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"barrel\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "\nmod service;\npub use service::Foo as Bar;\nmod consumer;\n",
            )
            .file("src/service.rs", "pub struct Foo;\n")
            .file(
                "src/consumer.rs",
                "use crate::Bar;\npub fn consume(_: Bar) {}\n",
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "Foo")
            .expect("barrel target");
        let index =
            match build_rust_selected_reference_index(&analyzer, &CancellationToken::default()) {
                RustSelectedReferenceIndexOutcome::Ready(index) => index,
                RustSelectedReferenceIndexOutcome::Unavailable(detail)
                | RustSelectedReferenceIndexOutcome::Stale(detail)
                | RustSelectedReferenceIndexOutcome::StoreError(detail) => panic!("{detail}"),
                RustSelectedReferenceIndexOutcome::Cancelled => panic!("unexpected cancellation"),
            };
        let inverse = index.inverse_for(&target);
        let consumer = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.usage_kind == UsageHitKind::Import
                    && edge.site.file == fixture.file("src/consumer.rs")
            })
            .expect("consumer import");
        assert!(
            consumer.reference_kind.known().contains(
                brokk_bifrost_core::analyzer::usages::model::ReferenceKind::TypeReference
            )
        );
        assert_eq!(consumer.proof, UsageProof::Proven);
        let imports = inverse
            .edges
            .iter()
            .filter(|edge| edge.usage_kind == UsageHitKind::Import)
            .map(|edge| {
                (
                    edge.site.file.clone(),
                    edge.site.range.start_byte,
                    edge.site.range.end_byte,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            imports,
            vec![
                (fixture.file("src/consumer.rs"), 11, 14),
                (fixture.file("src/lib.rs"), 31, 34),
            ],
            "{inverse:#?}"
        );
    }

    #[test]
    fn production_import_reference_locations_follow_grouped_overlay_identity() {
        let original = "pub mod model;\nuse crate::model::{target as chosen, target as other};\npub fn caller() { chosen(); other(); }\n";
        let replacement = "// shifted import locations\npub mod model;\nuse crate::model::{replacement as chosen, replacement as other};\npub fn caller() { chosen(); other(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"import_sites\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", original)
            .file(
                "src/model.rs",
                "pub fn target() {}\npub fn replacement() {}\n",
            )
            .build();
        let db_path = fixture.root().join("selected-import-overlays.db");
        let open = || {
            let project = fixture.project_dyn();
            let store = Arc::new(
                brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(&db_path)
                    .unwrap(),
            );
            let context = brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::revision_image_store_context(
                project.as_ref(),
                store,
            );
            RustAnalyzer::new_with_config_store_context(
                project,
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
                context,
                None,
            )
            .unwrap()
        };
        let disk = open();
        let file = fixture.file("src/lib.rs");
        let mut prepared = Vec::new();
        for source in [original, replacement] {
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            assert!(overlay.set(file.abs_path(), source.to_owned()));
            let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
            assert!(!analyzer.declarations(&file).is_empty());
            prepared.push(analyzer);
        }
        let check = |analyzer: &RustAnalyzer, source: &str, name: &str| {
            let target = analyzer
                .all_declarations()
                .find(|unit| unit.identifier() == name)
                .unwrap();
            let outcome =
                build_rust_selected_reference_index(analyzer, &CancellationToken::default());
            let index = match outcome {
                RustSelectedReferenceIndexOutcome::Ready(index) => index,
                RustSelectedReferenceIndexOutcome::Unavailable(detail)
                | RustSelectedReferenceIndexOutcome::Stale(detail)
                | RustSelectedReferenceIndexOutcome::StoreError(detail) => {
                    panic!("import index: {detail}")
                }
                RustSelectedReferenceIndexOutcome::Cancelled => panic!("unexpected cancellation"),
            };
            let inverse = index.inverse_for(&target);
            let actual = inverse
                .edges
                .iter()
                .filter(|edge| edge.usage_kind == UsageHitKind::Import && edge.site.file == file)
                .map(|edge| (edge.site.range.start_byte, edge.site.range.end_byte))
                .collect::<BTreeSet<_>>();
            // The path's target token only. An `as` alias is the new name the
            // use declaration binds, not a second naming of the imported item
            // (the Rust Reference, use declarations), so `chosen` and `other`
            // are declaration sites rather than import edges.
            let expected = source
                .match_indices(name)
                .filter(|(start, _)| *start < source.find("pub fn caller").unwrap())
                .map(|(start, _)| (start, start + name.len()))
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected, "{inverse:?}");
        };
        for (analyzer, source, name) in [
            (&prepared[0], original, "target"),
            (&prepared[1], replacement, "replacement"),
            (&prepared[0], original, "target"),
        ] {
            check(analyzer, source, name);
        }
        drop(prepared);
        drop(disk);
        let reopened = open();
        for (source, name) in [
            (original, "target"),
            (replacement, "replacement"),
            (original, "target"),
        ] {
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            assert!(overlay.set(file.abs_path(), source.to_owned()));
            let analyzer = reopened.clone_with_project(Arc::new(overlay.snapshot()));
            assert!(!analyzer.declarations(&file).is_empty());
            assert!(
                analyzer
                    .inner
                    .cached_canonical_source_state(&file, source)
                    .is_none(),
                "reopened overlays must exercise persisted content, not a retained producer arena"
            );
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let SelectedResolutionOverlayInputsOutcome::Ready {
                content_mounts: mounts,
                ..
            } = analyzer
                .inner
                .selected_rust_resolution_overlay_inputs(
                    snapshots.as_ref(),
                    &CancellationToken::default(),
                )
                .unwrap()
            else {
                panic!("reopened overlay publication must be ready");
            };
            assert_eq!(mounts.len(), 1);
            check(&analyzer, source, name);
        }
    }

    #[test]
    fn production_reference_index_covers_trait_impl_bodies_with_local_proof() {
        use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"local_proof\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "fn target() {}\n",
                    "struct Service;\n",
                    "trait Contract { fn skipped(&self); }\n",
                    "impl Contract for Service { fn skipped(&self) { target(); } }\n",
                    "fn caller() { target(); }\n",
                ),
            )
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("local target declaration");
        let declarations = analyzer.all_declarations().collect::<Vec<_>>();
        let contract = declarations
            .iter()
            .find(|unit| unit.identifier() == "Contract")
            .cloned()
            .expect("trait declaration");
        let service = declarations
            .iter()
            .find(|unit| unit.identifier() == "Service")
            .cloned()
            .expect("impl subject declaration");
        let trait_skipped = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "skipped" && unit.owner_identifier() == Some("Contract")
            })
            .cloned()
            .expect("retained trait signature declaration");
        assert_eq!(analyzer.parent_of(&trait_skipped), Some(contract.clone()));
        let skipped = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "skipped" && unit.owner_identifier() == Some("Service")
            })
            .cloned()
            .expect("actual impl method declaration");
        assert_eq!(analyzer.parent_of(&skipped), Some(service));
        assert_ne!(trait_skipped.declaration_id(), skipped.declaration_id());
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("selected reference index must be available")
        };
        assert!(index.covers_target(&target));
        assert!(index.covers_target(&trait_skipped));
        assert!(index.covers_target(&skipped));
        let inverse = index.inverse_for(&target);
        assert!(inverse.covers(EdgeAxis::ProofAttribution));
        // The body inventory is closed. Abstract trait Self uncertainty belongs
        // to its typed frontier rather than this unrelated inverse projection.
        assert!(inverse.covers(EdgeAxis::InverseProjection), "{inverse:?}");
        assert_eq!(inverse.edges.len(), 2, "{inverse:?}");
        assert!(
            inverse
                .edges
                .iter()
                .all(|edge| edge.proof == UsageProof::Proven)
        );
        assert_eq!(
            inverse
                .edges
                .iter()
                .map(|edge| edge.site.enclosing.as_ref().map(CodeUnit::identifier))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([Some("caller"), Some("skipped")])
        );
        assert!(!matches!(
            index.inverse_for(&skipped).completeness,
            EdgeCompleteness::Incomplete { reasons }
                if reasons.contains(&EdgeIncompleteReason::InverseIndexTargetUncovered)
        ));
        let files = [fixture.file("src/lib.rs")].into_iter().collect();
        let reverse = selected_rust_usage_shadow_result(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&files),
            100,
        );
        let RustUsageShadowResult::Complete {
            sites,
            capped: false,
        } = reverse
        else {
            panic!("direct reverse must include the enumerated impl caller: {reverse:?}")
        };
        assert_eq!(sites.len(), 2, "{sites:?}");
        assert_eq!(
            sites
                .iter()
                .map(|site| site.enclosing.identifier())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["caller", "skipped"])
        );
    }

    #[test]
    fn production_reference_index_retains_inherent_callables_without_free_binders() {
        use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;

        let source = concat!(
            "fn target() {}\n",
            "fn method() {}\n",
            "pub struct Service;\n",
            "impl Service { pub fn method(&self) { target(); method(); } }\n",
            "impl Service { pub fn associated() { target(); } }\n",
            "fn caller() { target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"inherent_bodies\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declarations = analyzer.all_declarations().collect::<Vec<_>>();
        let declaration = |name, start_text| {
            let start = source.find(start_text).expect("unique declaration prefix");
            declarations
                .iter()
                .find(|unit| {
                    unit.identifier() == name
                        && analyzer
                            .ranges(unit)
                            .iter()
                            .any(|range| range.start_byte == start)
                })
                .cloned()
                .expect("exact parser declaration")
        };
        let target = declaration("target", "fn target()");
        let free_method = declaration("method", "fn method()");
        let method = declaration("method", "pub fn method(");
        let associated = declaration("associated", "pub fn associated()");
        let caller = declaration("caller", "fn caller()");

        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("inherent body reference index must be available")
        };
        for unit in [&target, &free_method, &method, &associated, &caller] {
            assert!(
                index.covers_target(unit),
                "missing exact native crosswalk for {unit:?}"
            );
        }
        let inverse = index.inverse_for(&target);
        assert!(inverse.covers(EdgeAxis::ProofAttribution));
        assert!(
            inverse.covers(EdgeAxis::InverseProjection),
            "supported inherent bodies retain complete reference inventory"
        );
        let owners = inverse
            .edges
            .iter()
            .map(|edge| {
                assert_eq!(edge.target, target);
                assert_eq!(edge.proof, UsageProof::Proven);
                assert_eq!(edge.usage_kind, UsageHitKind::Reference);
                assert_eq!(edge.site.file, file);
                assert_eq!(
                    &source[edge.site.range.start_byte..edge.site.range.end_byte],
                    "target"
                );
                edge.site
                    .enclosing
                    .clone()
                    .expect("body call has an exact callable owner")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(inverse.edges.len(), 3, "{inverse:?}");
        assert_eq!(owners, BTreeSet::from([method.clone(), associated, caller]));

        let free_inverse = index.inverse_for(&free_method);
        assert_eq!(free_inverse.edges.len(), 1, "{free_inverse:?}");
        let edge = &free_inverse.edges[0];
        assert_eq!(edge.proof, UsageProof::Proven);
        assert_eq!(edge.site.enclosing.as_ref(), Some(&method));
        assert_eq!(
            edge.site.range.start_byte,
            source.find("method();").expect("free call in method body")
        );
        assert!(
            index.inverse_for(&method).edges.is_empty(),
            "method() inside a method body must not become an implicit self call"
        );
    }

    #[test]
    fn production_reference_index_keeps_root_qualified_terminal_edges_exact() {
        use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;

        let source = concat!(
            "pub fn target() {}\n",
            "pub mod api { pub fn target() {} }\n",
            "pub fn caller() { crate::api::target(); target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"root_reference\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let declarations = analyzer.all_declarations().collect::<Vec<_>>();
        let target_declaration_starts = source
            .match_indices("pub fn target() {}")
            .map(|(start, _)| start)
            .collect::<Vec<_>>();
        assert_eq!(target_declaration_starts.len(), 2);
        let root_target = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "target"
                    && analyzer
                        .ranges(unit)
                        .iter()
                        .any(|range| range.start_byte == target_declaration_starts[0])
            })
            .cloned()
            .expect("root target declaration");
        let api_target = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "target"
                    && analyzer
                        .ranges(unit)
                        .iter()
                        .any(|range| range.start_byte == target_declaration_starts[1])
            })
            .cloned()
            .expect("api target declaration");
        let caller = declarations
            .iter()
            .find(|unit| unit.identifier() == "caller")
            .cloned()
            .expect("caller declaration");
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("selected reference index must be available")
        };

        let qualified_start = source
            .find("crate::api::target()")
            .expect("qualified terminal call")
            + "crate::api::".len();
        let plain_start = source.rfind("target();").expect("plain terminal call");
        let assert_terminal_edge =
            |inverse: &EdgeDerivationResult, target: &CodeUnit, expected_start: usize| {
                assert!(inverse.covers(EdgeAxis::ProofAttribution));
                assert_eq!(inverse.edges.len(), 1, "{inverse:?}");
                let edge = &inverse.edges[0];
                assert_eq!(edge.target, *target);
                assert_eq!(edge.site.file, file);
                assert_eq!(edge.site.range.start_byte, expected_start);
                assert_eq!(edge.site.range.end_byte, expected_start + "target".len());
                assert_eq!(edge.site.enclosing.as_ref(), Some(&caller));
                assert_eq!(edge.proof, UsageProof::Proven);
                assert_eq!(edge.usage_kind, UsageHitKind::Reference);
                assert_ne!(edge.usage_kind, UsageHitKind::Import);
            };

        let qualified = index.inverse_for(&api_target);
        assert_terminal_edge(&qualified, &api_target, qualified_start);
        let plain = index.inverse_for(&root_target);
        assert_terminal_edge(&plain, &root_target, plain_start);
        assert!(
            qualified
                .edges
                .iter()
                .all(|edge| edge.site.enclosing.as_ref() == Some(&caller))
        );
        assert!(
            plain
                .edges
                .iter()
                .all(|edge| edge.site.enclosing.as_ref() == Some(&caller))
        );
    }

    #[test]
    #[hardwon(
        "a359fa9c0331: selected Rust references read disk instead of an unprepared open buffer"
    )]
    fn production_reference_index_answers_an_unprepared_overlay_from_its_buffer() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"overlay_preflight\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", source)
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "caller")
        );
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            file.abs_path(),
            "pub fn target() {}\npub fn caller() {}\n".to_owned()
        ));
        let request_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(request_project);
        // R6.4: the first call over an open buffer must answer. The selected
        // overlay inputs now fetch the buffer's file state, so the index is
        // built from the buffer's own facts rather than refused for want of a
        // prior hydrating call. What must never happen is answering from the
        // disk row: the buffer deletes the call, so `target` has no callers.
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("an open Rust buffer answers on its first selected operation")
        };
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("overlay target declaration");
        assert!(
            index.inverse_for(&target).edges.is_empty(),
            "the buffer deleted the only call, so the disk edge must not survive"
        );
    }

    #[test]
    fn production_reference_index_follows_changed_and_cleared_overlays() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"overlay_authority\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub fn target() {}\npub fn caller() { target(); }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "caller")
        );
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            file.abs_path(),
            "pub fn target() {}\npub fn caller() {}\n".to_owned()
        ));
        let prepared = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            prepared
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        let RustSelectedReferenceIndexOutcome::Ready(prepared_index) =
            build_rust_selected_reference_index(&prepared, &CancellationToken::default())
        else {
            panic!("prepared overlay reference index must be available")
        };
        let prepared_target = prepared
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("prepared target declaration");
        assert!(
            prepared_index
                .inverse_for(&prepared_target)
                .edges
                .is_empty(),
            "prepared overlay removes the caller-to-target edge"
        );

        assert!(overlay.set(file.abs_path(), "pub fn different() {}\n".to_owned()));
        let changed = prepared.clone_with_project(Arc::new(overlay.snapshot()));
        // The new bytes are hydrated on demand, so the request answers from
        // them. The property that matters is that it cannot reuse the earlier
        // prepared facts: `target` and `caller` are gone from the buffer.
        assert!(
            matches!(
                build_rust_selected_reference_index(&changed, &CancellationToken::default()),
                RustSelectedReferenceIndexOutcome::Ready(_)
            ),
            "new buffer bytes answer from themselves"
        );
        assert!(
            changed
                .declarations(&file)
                .iter()
                .all(|unit| unit.identifier() == "different"),
            "{:?}",
            changed.declarations(&file)
        );
        assert!(
            matches!(
                build_rust_selected_reference_index(&prepared, &CancellationToken::default()),
                RustSelectedReferenceIndexOutcome::Ready(_)
            ),
            "the frozen prepared request retains its original authority"
        );

        assert!(overlay.clear(&file.abs_path()));
        let cleared = prepared.clone_with_project(Arc::new(overlay.snapshot()));
        let RustSelectedReferenceIndexOutcome::Ready(cleared_index) =
            build_rust_selected_reference_index(&cleared, &CancellationToken::default())
        else {
            panic!("cleared overlay must select the persisted disk reference index")
        };
        let cleared_target = cleared
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("cleared target declaration");
        let inverse = cleared_index.inverse_for(&cleared_target);
        assert_eq!(inverse.edges.len(), 1, "disk caller-to-target edge");
        let edge = &inverse.edges[0];
        assert_eq!(edge.site.file, file);
        assert_eq!(
            edge.site.enclosing.as_ref().map(CodeUnit::identifier),
            Some("caller")
        );
        assert_eq!(edge.target, cleared_target);
    }

    #[test]
    #[hardwon("#11546: root topology overlays certify callers from the hidden disk module graph")]
    fn production_reference_index_root_topology_overlays_fail_closed() {
        let mut failures = Vec::new();
        for (case, source) in [
            ("removed", "mod api;\n"),
            (
                "retargeted",
                "mod api;\n#[path = \"other.rs\"] mod caller;\n",
            ),
            ("gated", "mod api;\n#[cfg(any())] mod caller;\n"),
        ] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", "mod api; mod caller;\n")
                .file("src/api.rs", "pub fn target() {}\n")
                .file("src/caller.rs", "pub fn caller() { crate::api::target(); }\n")
                .file("src/other.rs", "pub fn other() {}\n")
                .build();
            let disk = RustAnalyzer::new(fixture.project_dyn());
            let target = disk
                .all_declarations()
                .find(|unit| unit.identifier() == "target")
                .expect("disk target");
            let RustSelectedReferenceIndexOutcome::Ready(index) =
                build_rust_selected_reference_index(&disk, &CancellationToken::default())
            else {
                panic!("{case}: disk index unavailable")
            };
            let baseline = index.inverse_for(&target);
            assert_eq!(baseline.edges.len(), 1, "{case}: disk {baseline:?}");
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            let root = fixture.file("src/lib.rs");
            assert!(overlay.set(root.abs_path(), source.to_owned()));
            let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
            match build_rust_selected_reference_index(&selected, &CancellationToken::default()) {
                RustSelectedReferenceIndexOutcome::Ready(index) => {
                    let answer = index.inverse_for(&target);
                    eprintln!("{case}: {answer:?}");
                    if answer.completeness == EdgeCompleteness::Complete
                        && answer.edges.iter().any(|edge| {
                            edge.site.file == fixture.file("src/caller.rs")
                                && edge.proof == UsageProof::Proven
                        })
                    {
                        failures.push(case);
                    }
                }
                RustSelectedReferenceIndexOutcome::Unavailable(detail)
                | RustSelectedReferenceIndexOutcome::Stale(detail)
                | RustSelectedReferenceIndexOutcome::StoreError(detail) => {
                    panic!("{case}: unexpected index failure: {detail}");
                }
                RustSelectedReferenceIndexOutcome::Cancelled => panic!("{case}: cancelled"),
            }
            assert!(overlay.clear(&root.abs_path()));
            let cleared = selected.clone_with_project(Arc::new(overlay.snapshot()));
            let RustSelectedReferenceIndexOutcome::Ready(index) =
                build_rust_selected_reference_index(&cleared, &CancellationToken::default())
            else {
                panic!("{case}: cleared index unavailable")
            };
            let restored = index.inverse_for(&target);
            eprintln!("{case} cleared: {restored:?}");
            assert_eq!(restored.edges.len(), 1, "{case}: cleared disk answer");
        }
        assert!(failures.is_empty(), "stale complete callers: {failures:?}");
    }

    // The nested, unchanged-overlay and forward companions of the root-topology
    // repro above. `caller/mod.rs` declares `deep`, whose file calls the target.
    fn root_topology_fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "mod api; mod caller;\n")
            .file("src/api.rs", "pub fn target() {}\n")
            .file("src/caller/mod.rs", "mod deep;\n")
            .file("src/caller/deep.rs", "pub fn caller() { crate::api::target(); }\n")
            .build()
    }

    /// Whether the selected index proves a complete caller in `src/caller/deep.rs`.
    fn deep_caller_is_proven_complete(
        selected: &RustAnalyzer,
        target: &CodeUnit,
        deep: &brokk_bifrost_core::analyzer::model::ProjectFile,
    ) -> bool {
        match build_rust_selected_reference_index(selected, &CancellationToken::default()) {
            RustSelectedReferenceIndexOutcome::Ready(index) => {
                let answer = index.inverse_for(target);
                answer.completeness == EdgeCompleteness::Complete
                    && answer
                        .edges
                        .iter()
                        .any(|edge| edge.site.file == *deep && edge.proof == UsageProof::Proven)
            }
            other => panic!(
                "selected index unavailable: {}",
                match other {
                    RustSelectedReferenceIndexOutcome::Unavailable(d)
                    | RustSelectedReferenceIndexOutcome::Stale(d)
                    | RustSelectedReferenceIndexOutcome::StoreError(d) => d,
                    _ => "cancelled".to_owned(),
                }
            ),
        }
    }

    #[test]
    #[hardwon(
        "#11546: removing a module declaration left its descendants placed from the persisted module graph"
    )]
    fn production_reference_index_root_topology_overlay_unplaces_descendants_and_keeps_unchanged_edges()
     {
        let fixture = root_topology_fixture();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let target = disk
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("disk target");
        let deep = fixture.file("src/caller/deep.rs");
        assert!(
            deep_caller_is_proven_complete(&disk, &target, &deep),
            "disk answer"
        );
        let root = fixture.file("src/lib.rs");
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        // `deep.rs` is two edges below the edited root: only the removed
        // `mod caller;` edge changed, so the worklist must reach it.
        assert!(overlay.set(root.abs_path(), "mod api;\n".to_owned()));
        let removed = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            !deep_caller_is_proven_complete(&removed, &target, &deep),
            "a descendant of a removed module stayed proven"
        );
        // A comment-only edit and a byte-identical overlay keep the edge.
        for source in [
            "mod api; mod caller;\n// edited\n",
            "mod api; mod caller;\n",
        ] {
            assert!(overlay.set(root.abs_path(), source.to_owned()));
            let kept = disk.clone_with_project(Arc::new(overlay.snapshot()));
            assert!(
                deep_caller_is_proven_complete(&kept, &target, &deep),
                "an unchanged edge lost its placement: {source:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#11546: an include! edge removed, retargeted or gated in a changed host left the included file and its modules placed"
    )]
    fn production_reference_index_root_topology_overlay_unplaces_include_edges() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "mod api;\ninclude!(\"splice.rs\");\n")
            .file("src/api.rs", "pub fn target() {}\n")
            .file("src/splice.rs", "pub fn spliced() { crate::api::target(); }\nmod nested;\n")
            .file("src/nested.rs", "pub fn nested_caller() { crate::api::target(); }\n")
            .file("src/other.rs", "pub fn other() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let target = disk
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("disk target");
        let splice = fixture.file("src/splice.rs");
        let nested = fixture.file("src/nested.rs");
        assert!(
            deep_caller_is_proven_complete(&disk, &target, &splice),
            "disk answer for the included file"
        );
        assert!(
            deep_caller_is_proven_complete(&disk, &target, &nested),
            "disk answer for the module the included file declares"
        );
        let root = fixture.file("src/lib.rs");
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        for (case, source) in [
            ("removed", "mod api;\n"),
            ("retargeted", "mod api;\ninclude!(\"other.rs\");\n"),
            (
                "gated",
                "mod api;\n#[cfg(any())]\nmod gated {\n    include!(\"splice.rs\");\n}\n",
            ),
        ] {
            assert!(overlay.set(root.abs_path(), source.to_owned()));
            let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
            let RustSelectedReferenceIndexOutcome::Ready(index) =
                build_rust_selected_reference_index(&selected, &CancellationToken::default())
            else {
                panic!("{case}: index unavailable")
            };
            let answer = index.inverse_for(&target);
            for file in [&splice, &nested] {
                assert!(
                    !answer
                        .edges
                        .iter()
                        .any(|edge| edge.site.file == *file && edge.proof == UsageProof::Proven),
                    "{case}: {} stayed proven through the dead include edge: {answer:?}",
                    file.rel_path().display()
                );
            }
        }
        // A comment-only edit keeps the include edge and both placements. The
        // search over an edited include host reports its own inventory gap, so
        // the check is that the included files still carry proven callers.
        assert!(overlay.set(
            root.abs_path(),
            "mod api;\ninclude!(\"splice.rs\");\n// edited\n".to_owned()
        ));
        let kept = disk.clone_with_project(Arc::new(overlay.snapshot()));
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&kept, &CancellationToken::default())
        else {
            panic!("kept include host: index unavailable")
        };
        let answer = index.inverse_for(&target);
        for file in [&splice, &nested] {
            assert!(
                answer
                    .edges
                    .iter()
                    .any(|edge| edge.site.file == *file && edge.proof == UsageProof::Proven),
                "an unchanged include edge lost {}: {answer:?}",
                file.rel_path().display()
            );
        }
    }

    #[test]
    #[hardwon(
        "#11546: an inline module removed by an overlay stayed placed for readers of the persisted view"
    )]
    fn production_reference_index_root_topology_overlay_unplaces_a_removed_inline_module() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file(
                "src/lib.rs",
                "mod api;\nmod m {\n    pub fn inline_caller() { crate::api::target(); }\n    mod child;\n}\n",
            )
            .file("src/api.rs", "pub fn target() {}\n")
            .file("src/m/child.rs", "pub fn child_caller() { crate::api::target(); }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let target = disk
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("disk target");
        let root = fixture.file("src/lib.rs");
        let child = fixture.file("src/m/child.rs");
        assert!(
            deep_caller_is_proven_complete(&disk, &target, &root),
            "disk answer for the inline caller"
        );
        assert!(
            deep_caller_is_proven_complete(&disk, &target, &child),
            "disk answer for the module the inline module declares"
        );
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        // Removed, and renamed (the old module scope has no counterpart, so its
        // persisted placement must not survive for any reader).
        for (case, source) in [
            ("removed", "mod api;\n"),
            (
                "renamed",
                "mod api;\nmod n {\n    pub fn inline_caller() { crate::api::target(); }\n    mod child;\n}\n",
            ),
        ] {
            assert!(overlay.set(root.abs_path(), source.to_owned()));
            let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
            for file in [&root, &child] {
                assert!(
                    !deep_caller_is_proven_complete(&selected, &target, file),
                    "{case}: {} stayed proven after the inline module changed",
                    file.rel_path().display()
                );
            }
        }
    }

    /// Whether the selected index holds a proven caller edge in `file`, whatever
    /// the answer's completeness (an edited include host reports its own gap).
    fn has_proven_caller_edge(
        selected: &RustAnalyzer,
        target: &CodeUnit,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    ) -> bool {
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(selected, &CancellationToken::default())
        else {
            panic!("selected index unavailable")
        };
        let answer = index.inverse_for(target);
        answer
            .edges
            .iter()
            .any(|edge| edge.site.file == *file && edge.proof == UsageProof::Proven)
    }

    #[test]
    #[hardwon(
        "#11546: an overlay dropping one of two include! edges to a file unplaced it for the host that still includes it"
    )]
    fn production_reference_index_root_topology_overlay_keeps_a_file_another_host_still_includes() {
        // lib.rs and host_b.rs both include shared.rs in the crate root module.
        // The persisted walk collapses the two routes into one placement of
        // shared.rs, so it dies only when no host keeps an edge to it. The
        // changed host is the crate root: an overlay on an included file is a
        // separate macro-stage limitation.
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file(
                "src/lib.rs",
                "mod api;\ninclude!(\"shared.rs\");\ninclude!(\"host_b.rs\");\n",
            )
            .file("src/api.rs", "pub fn target() {}\n")
            .file("src/host_b.rs", "include!(\"shared.rs\");\n")
            .file(
                "src/shared.rs",
                "pub fn shared_caller() { crate::api::target(); }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let target = disk
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("disk target");
        let shared = fixture.file("src/shared.rs");
        assert!(
            has_proven_caller_edge(&disk, &target, &shared),
            "disk answer"
        );
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        let root = fixture.file("src/lib.rs");
        assert!(overlay.set(
            root.abs_path(),
            "mod api;\ninclude!(\"host_b.rs\");\n".to_owned()
        ));
        let one_dropped = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            has_proven_caller_edge(&one_dropped, &target, &shared),
            "host_b.rs still includes shared.rs, so its placement must survive"
        );
        // No host reaches shared.rs any more: host_b.rs is unplaced with the
        // include that mounted it, and shared.rs with it.
        assert!(overlay.set(root.abs_path(), "mod api;\n".to_owned()));
        let none_left = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            !has_proven_caller_edge(&none_left, &target, &shared),
            "no host includes shared.rs any more, so it must be unplaced"
        );
    }

    #[test]
    #[hardwon(
        "#11546: a comment-only overlay unplaced the children of a #[path] inline module, whose scope the edge check skipped"
    )]
    fn production_reference_index_root_topology_overlay_keeps_children_of_a_path_inline_module() {
        let lib = |path: &str, tail: &str| {
            format!("mod api;\n#[path = \"{path}\"]\nmod m {{\n    mod child;\n}}\n{tail}")
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", lib("alternate", ""))
            .file("src/api.rs", "pub fn target() {}\n")
            .file(
                "src/alternate/child.rs",
                "pub fn child_caller() { crate::api::target(); }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let target = disk
            .all_declarations()
            .find(|unit| unit.identifier() == "target")
            .expect("disk target");
        let child = fixture.file("src/alternate/child.rs");
        assert!(
            deep_caller_is_proven_complete(&disk, &target, &child),
            "disk answer for the child of the #[path] inline module"
        );
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        let root = fixture.file("src/lib.rs");
        assert!(overlay.set(root.abs_path(), lib("alternate", "// edited\n")));
        let comment_only = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            deep_caller_is_proven_complete(&comment_only, &target, &child),
            "a comment-only edit unplaced the child of a #[path] inline module"
        );
        // The inline #[path] moves where `mod child;` resolves, so a changed
        // attribute retargets the child and the persisted placement is dead.
        assert!(overlay.set(root.abs_path(), lib("elsewhere", "")));
        let retargeted = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            !deep_caller_is_proven_complete(&retargeted, &target, &child),
            "a retargeted inline #[path] left the old child placed"
        );
    }

    #[test]
    #[hardwon(
        "#11546: removing an included file unplaced its whole host container, including unrelated sibling modules"
    )]
    fn selected_rust_removed_included_file_unplaces_only_itself() {
        use brokk_bifrost_analysis::CancellationToken;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
            SelectedResolutionOverlayMask,
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "mod api;\ninclude!(\"splice.rs\");\n")
            .file("src/api.rs", "pub fn target() {}\n")
            .file("src/splice.rs", "mod nested;\n")
            .file("src/nested.rs", "pub fn nested() {}\n")
            .build();
        let analyzer = fixture.workspace_analyzer(Default::default());
        let store = analyzer.store().unwrap();
        let workspace = {
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::WorkspaceId(
                conn.query_row(
                    "SELECT workspace_id FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            )
        };
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace, &["rust".into()])
            .unwrap();
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &[SelectedResolutionLanguage::new("rust", Language::Rust)],
                &[SelectedResolutionOverlayMask::removal(
                    "rust",
                    "src/splice.rs",
                )],
                &CancellationToken::default(),
            )
            .unwrap()
        else {
            panic!("complete selection");
        };
        let conn = selection.connection();
        let placed_files = |sql: &str| -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        // Only the included file and the module it declares are unplaced; the
        // host container's other members keep their placements.
        assert_eq!(
            placed_files(
                "SELECT DISTINCT member.rel_path FROM temp.selected_rust_unplaced_placements AS unplaced
                 JOIN main.resolution_unit_summary_members AS member
                   ON member.summary_id=unplaced.summary_id AND member.member_ordinal=unplaced.member_ordinal
                 ORDER BY 1"
            ),
            ["src/nested.rs", "src/splice.rs"]
        );
        assert_eq!(
            placed_files(
                "SELECT DISTINCT member.rel_path FROM temp.rust_unit_summary_placements AS placement
                 JOIN main.resolution_unit_summary_members AS member
                   ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
                 ORDER BY 1"
            ),
            ["src/api.rs", "src/lib.rs"]
        );
    }

    #[test]
    #[hardwon(
        "#11546: forward resolution followed a module edge the selected root no longer declares"
    )]
    fn selected_rust_forward_does_not_resolve_through_a_removed_module_edge() {
        let fixture = root_topology_fixture();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "target")
        );
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("src/lib.rs").abs_path(),
            "mod api;\n".to_owned()
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        let source = "pub fn caller() { crate::api::target(); }\n";
        let file = fixture.file("src/caller/deep.rs");
        let site = rust_shadow_site(source, "target");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &selected,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        // The unplaced file compiles in no selected crate: a typed non-answer,
        // never a resolved definition and never an empty "complete" one.
        match selected_rust_definition_shadow_result(&selected, query) {
            RustDefinitionShadowResult::UnsupportedCallerProfile { .. }
            | RustDefinitionShadowResult::Incomplete { .. } => {}
            other => panic!("an unplaced caller must not resolve: {other:?}"),
        }
    }

    /// `api.rs` calls `helper`, which `caller.rs` declares. The overlay removes
    /// `mod caller;`, so `caller.rs` is unplaced in the selected root.
    fn unplaced_declaration_fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"unplaced_signal\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "mod api; mod caller;\n")
            .file("src/api.rs", "pub fn call() { crate::caller::helper(); }\n")
            .file("src/caller.rs", "pub fn helper() {}\n")
            .build()
    }

    #[test]
    #[hardwon(
        "#11546: a declaration in an overlay-unplaced file reported a complete caller set from its same-blob uses"
    )]
    fn selected_rust_reverse_of_a_declaration_in_an_unplaced_file_is_incomplete() {
        let fixture = unplaced_declaration_fixture();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let helper = disk
            .all_declarations()
            .find(|unit| unit.identifier() == "helper")
            .expect("disk helper");
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&disk, &CancellationToken::default())
        else {
            panic!("disk index unavailable")
        };
        let baseline = index.inverse_for(&helper);
        assert_eq!(baseline.edges.len(), 1, "disk {baseline:?}");
        assert_eq!(baseline.completeness, EdgeCompleteness::Complete);
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("src/lib.rs").abs_path(),
            "mod api;\n".to_owned()
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        match build_rust_selected_reference_index(&selected, &CancellationToken::default()) {
            RustSelectedReferenceIndexOutcome::Ready(index) => {
                let answer = index.inverse_for(&helper);
                assert_ne!(
                    answer.completeness,
                    EdgeCompleteness::Complete,
                    "an unplaced declaration's caller set cannot be complete: {answer:?}"
                );
            }
            RustSelectedReferenceIndexOutcome::Unavailable(_)
            | RustSelectedReferenceIndexOutcome::Stale(_)
            | RustSelectedReferenceIndexOutcome::StoreError(_) => {
                // A typed non-answer is also fail closed.
            }
            RustSelectedReferenceIndexOutcome::Cancelled => panic!("cancelled"),
        }
    }

    #[test]
    #[hardwon(
        "#11546: a definition lookup through an overlay-unplaced module answered complete from the missing module"
    )]
    fn selected_rust_definition_through_an_unplaced_module_is_incomplete() {
        let fixture = unplaced_declaration_fixture();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        let source = "pub fn call() { crate::caller::helper(); }\n";
        let file = fixture.file("src/api.rs");
        let lookup = |analyzer: &RustAnalyzer| {
            let site = rust_shadow_site(source, "helper");
            let tree = rust_shadow_tree(source);
            selected_rust_definition_shadow_result(
                analyzer,
                BoundedReceiverQuery {
                    analyzer,
                    file: &file,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
            )
        };
        match lookup(&disk) {
            RustDefinitionShadowResult::Complete { definitions, .. } => assert!(
                definitions.iter().any(|unit| unit.identifier() == "helper"),
                "{definitions:?}"
            ),
            other => panic!("disk lookup must resolve: {other:?}"),
        }
        assert!(overlay.set(
            fixture.file("src/lib.rs").abs_path(),
            "mod api;\n".to_owned()
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        if let RustDefinitionShadowResult::Complete { definitions, .. } = lookup(&selected) {
            panic!(
                "the selected root no longer mounts caller.rs, yet the lookup is complete: {definitions:?}"
            );
        }
    }

    #[test]
    #[hardwon("#11546: a cfg-inactive sibling `mod` kept a removed module placed")]
    fn selected_rust_cfg_inactive_include_sibling_does_not_keep_module_placed() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"include_sibling\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "include!(\"extra.rs\");\n#[cfg(any())] mod child;\nmod caller;\npub fn root() {}\n",
            )
            .file("src/extra.rs", "mod child;\n")
            .file("src/child.rs", "pub fn f() { crate::root(); }\n")
            .file("src/caller.rs", "pub fn caller() { crate::child::f(); }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let root_function = disk
            .all_declarations()
            .find(|unit| unit.identifier() == "root")
            .expect("root function");
        let RustSelectedReferenceIndexOutcome::Ready(disk_index) =
            build_rust_selected_reference_index(&disk, &CancellationToken::default())
        else {
            panic!("disk reverse index unavailable")
        };
        let disk_answer = disk_index.inverse_for(&root_function);
        assert_eq!(disk_answer.completeness, EdgeCompleteness::Complete);
        assert!(
            disk_answer.edges.iter().any(|edge| {
                edge.target == root_function
                    && edge.site.file == fixture.file("src/child.rs")
                    && edge.proof == UsageProof::Proven
            }),
            "disk caller edge: {disk_answer:?}"
        );

        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("src/extra.rs").abs_path(),
            "// removed `mod child;`\n".to_owned()
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        let lookup_source = "pub fn caller() { crate::child::f(); }\n";
        let file = fixture.file("src/caller.rs");
        let site = brokk_bifrost_analysis::test_support::resolved_reference_site(
            "src/caller.rs".to_owned(),
            "f".to_owned(),
            Range {
                start_byte: lookup_source.rfind('f').expect("f call"),
                end_byte: lookup_source.rfind('f').expect("f call") + 1,
                start_line: 1,
                end_line: 1,
            },
        );
        let tree = rust_shadow_tree(lookup_source);
        let lookup = |analyzer: &RustAnalyzer| {
            selected_rust_definition_shadow_result(
                analyzer,
                BoundedReceiverQuery {
                    analyzer,
                    file: &file,
                    source: lookup_source,
                    tree: Some(&tree),
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
            )
        };
        assert!(matches!(
            lookup(&disk),
            RustDefinitionShadowResult::Complete { .. }
        ));
        let forward = lookup(&selected);
        assert!(
            !matches!(forward, RustDefinitionShadowResult::Complete { .. }),
            "an unchanged caller resolved through the removed child module: {forward:?}"
        );

        match build_rust_selected_reference_index(&selected, &CancellationToken::default()) {
            RustSelectedReferenceIndexOutcome::Ready(index) => {
                let answer = index.inverse_for(&root_function);
                assert_ne!(
                    answer.completeness,
                    EdgeCompleteness::Complete,
                    "unplaced child caller cannot form a complete reverse answer: {answer:?}"
                );
            }
            RustSelectedReferenceIndexOutcome::Unavailable(detail)
            | RustSelectedReferenceIndexOutcome::Stale(detail)
            | RustSelectedReferenceIndexOutcome::StoreError(detail) => {
                panic!("selected reverse index unavailable: {detail}")
            }
            RustSelectedReferenceIndexOutcome::Cancelled => {
                panic!("selected reverse index cancelled")
            }
        }
    }

    #[test]
    #[hardwon("#11546: a glob re-export of an overlay-unplaced module answered a lookup complete")]
    fn selected_rust_definition_through_a_glob_of_an_unplaced_module_is_incomplete() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"unplaced_glob\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "mod api; mod caller; mod user;\n")
            .file("src/api.rs", "pub use crate::caller::*;\n")
            .file("src/caller.rs", "pub fn helper() {}\n")
            .file(
                "src/user.rs",
                "use crate::api::*;\npub fn call() { helper(); }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let source = "use crate::api::*;\npub fn call() { helper(); }\n";
        let file = fixture.file("src/user.rs");
        let lookup = |analyzer: &RustAnalyzer| {
            let site = rust_shadow_site(source, "helper");
            let tree = rust_shadow_tree(source);
            selected_rust_definition_shadow_result(
                analyzer,
                BoundedReceiverQuery {
                    analyzer,
                    file: &file,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
            )
        };
        match lookup(&disk) {
            RustDefinitionShadowResult::Complete { definitions, .. } => assert!(
                definitions.iter().any(|unit| unit.identifier() == "helper"),
                "{definitions:?}"
            ),
            other => panic!("disk lookup must resolve: {other:?}"),
        }
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("src/lib.rs").abs_path(),
            "mod api; mod user;\n".to_owned()
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        if let RustDefinitionShadowResult::Complete { definitions, .. } = lookup(&selected) {
            panic!(
                "the selected root no longer mounts caller.rs, yet the glob lookup is complete: {definitions:?}"
            );
        }
    }

    #[test]
    #[hardwon("#11666: a missing name through a glob of an unplaced module answered NoDefinition")]
    fn selected_rust_missing_name_through_a_glob_of_an_unplaced_module_is_incomplete() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"unplaced_glob_missing\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "mod api; mod caller; mod user;\n")
            .file("src/api.rs", "pub use crate::caller::*;\n")
            .file("src/caller.rs", "pub fn helper() {}\n")
            .file(
                "src/user.rs",
                "use crate::api::*;\npub fn call() { missing(); }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let source = "use crate::api::*;\npub fn call() { missing(); }\n";
        let file = fixture.file("src/user.rs");
        let lookup = |analyzer: &RustAnalyzer| {
            let site = rust_shadow_site(source, "missing");
            let tree = rust_shadow_tree(source);
            selected_rust_definition_shadow_result(
                analyzer,
                BoundedReceiverQuery {
                    analyzer,
                    file: &file,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
            )
        };
        // Without an overlay the glob source is placed, so the absence is
        // proven: a complete empty answer.
        match lookup(&disk) {
            RustDefinitionShadowResult::Complete { definitions, .. } => {
                assert!(definitions.is_empty(), "{definitions:?}")
            }
            other => panic!("disk lookup of a missing name must be a complete miss: {other:?}"),
        }
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("src/lib.rs").abs_path(),
            "mod api; mod user;\n".to_owned()
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        if let RustDefinitionShadowResult::Complete { definitions, .. } = lookup(&selected) {
            panic!(
                "the glob source caller.rs is unplaced, so its missing name is not proven absent: {definitions:?}"
            );
        }
    }

    const API_WITH_OWN: &str = "pub use crate::caller::*;\npub fn own() {}\n";

    /// Looks `name` up at its last spelling in `lookup_source`, the content of
    /// `lookup_file`, in a crate whose `api.rs` is `api` and whose `mid.rs` globs `caller`,
    /// once on disk and once with a root that no longer mounts `caller.rs` and
    /// that also applies `edits` (relative path, content): `(disk, selected)`.
    fn lookup_beside_an_unplaced_glob_source(
        api: &str,
        lookup_file: &str,
        lookup_source: &str,
        name: &str,
        edits: &[(&str, &str)],
    ) -> (RustDefinitionShadowResult, RustDefinitionShadowResult) {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"unplaced_glob_shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "mod api; mod caller; mod mid; mod user;\n")
            .file("src/api.rs", api)
            .file("src/caller.rs", "pub fn helper() {}\n")
            .file("src/mid.rs", "pub use crate::caller::*;\n")
            .file(
                "src/user.rs",
                format!("use crate::api::*;\npub fn call() {{ {name}(); }}\n"),
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file(lookup_file);
        let lookup = |analyzer: &RustAnalyzer| {
            let site = rust_shadow_site(lookup_source, name);
            let tree = rust_shadow_tree(lookup_source);
            selected_rust_definition_shadow_result(
                analyzer,
                BoundedReceiverQuery {
                    analyzer,
                    file: &file,
                    source: lookup_source,
                    tree: Some(&tree),
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
            )
        };
        let before = lookup(&disk);
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("src/lib.rs").abs_path(),
            "mod api; mod mid; mod user;\n".to_owned()
        ));
        for (path, content) in edits {
            assert!(overlay.set(fixture.file(path).abs_path(), (*content).to_owned()));
        }
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        (before, lookup(&selected))
    }

    /// `lookup_beside_an_unplaced_glob_source` for a call of `name` in `user.rs`,
    /// which globs `api`.
    fn lookup_through_an_api_that_globs_an_unplaced_caller(
        name: &str,
        edits: &[(&str, &str)],
    ) -> (RustDefinitionShadowResult, RustDefinitionShadowResult) {
        lookup_beside_an_unplaced_glob_source(
            API_WITH_OWN,
            "src/user.rs",
            &format!("use crate::api::*;\npub fn call() {{ {name}(); }}\n"),
            name,
            edits,
        )
    }

    #[test]
    #[hardwon("#11666: an explicitly declared name was made incomplete by an unplaced glob source")]
    fn selected_rust_explicit_name_beside_an_unplaced_glob_source_stays_complete() {
        let (disk, selected) = lookup_through_an_api_that_globs_an_unplaced_caller("own", &[]);
        for (which, result) in [("disk", disk), ("selected", selected)] {
            match result {
                RustDefinitionShadowResult::Complete { definitions, .. } => assert!(
                    definitions.iter().any(|unit| unit.identifier() == "own"),
                    "{which}: {definitions:?}"
                ),
                other => panic!(
                    "{which}: api.rs declares `own`, so no glob source can change it: {other:?}"
                ),
            }
        }
    }

    #[test]
    #[hardwon(
        "#11666: a stale persisted binding of an overlay-edited module stopped the glob walk"
    )]
    fn selected_rust_overlay_removed_explicit_name_beside_an_unplaced_glob_source_is_incomplete() {
        // The overlay deletes `own` from api.rs, so the persisted binding is
        // stale and the unplaced `caller` could now supply the name.
        let (disk, selected) = lookup_through_an_api_that_globs_an_unplaced_caller(
            "own",
            &[("src/api.rs", "pub use crate::caller::*;\n")],
        );
        assert!(
            matches!(disk, RustDefinitionShadowResult::Complete { ref definitions, .. } if !definitions.is_empty()),
            "{disk:?}"
        );
        if let RustDefinitionShadowResult::Complete { definitions, .. } = selected {
            panic!("api.rs no longer declares `own`, so the lookup is not proven: {definitions:?}");
        }
    }

    #[test]
    fn selected_rust_undeclared_name_beside_an_unplaced_glob_source_is_incomplete() {
        let (disk, selected) = lookup_through_an_api_that_globs_an_unplaced_caller("missing", &[]);
        assert!(
            matches!(disk, RustDefinitionShadowResult::Complete { ref definitions, .. } if definitions.is_empty()),
            "{disk:?}"
        );
        if let RustDefinitionShadowResult::Complete { definitions, .. } = selected {
            panic!("`missing` could come from the unplaced glob source: {definitions:?}");
        }
    }

    #[test]
    #[hardwon(
        "#11546: Cargo-route surfaces keep the disk module graph under a root topology overlay"
    )]
    fn cargo_route_surfaces_root_topology_overlays_fail_closed() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_rust::graph_support::RustSource;

        let mut stale = Vec::new();
        for (case, source) in [
            ("disk", "mod api; mod caller;\n"),
            ("removed", "mod api;\n"),
            (
                "retargeted",
                "mod api;\n#[path = \"other.rs\"] mod caller;\n",
            ),
            ("gated", "mod api;\n#[cfg(any())] mod caller;\n"),
        ] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"root_topology_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", "mod api; mod caller;\n")
                .file("src/api.rs", "pub fn target() {}\n")
                .file("src/caller.rs", "pub fn caller() { crate::api::target(); }\n")
                .file("src/other.rs", "pub fn other() {}\n")
                .build();
            let disk = RustAnalyzer::new(fixture.project_dyn());
            let caller_file = fixture.file("src/caller.rs");
            let root = fixture.file("src/lib.rs");
            let api = fixture.file("src/api.rs");
            let other_file = fixture.file("src/other.rs");
            let caller_unit = disk
                .all_declarations()
                .find(|unit| unit.identifier() == "caller")
                .expect("disk caller");
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            let surfaces = |label: &str, analyzer: &RustAnalyzer| {
                let mut out: Vec<(String, String, bool)> = Vec::new();
                let scope = AnalyzerQueryScope::new(analyzer);
                let routes =
                    <RustAnalyzer as RustSource>::file_routes(analyzer, &caller_file, None);
                match &routes {
                    Ok(routes) => {
                        out.push((
                            "file_routes.target_roots".into(),
                            format!("{:?}", routes.target_roots(&caller_file)),
                            routes.is_complete(),
                        ));
                        out.push((
                            "file_routes.is_in_target".into(),
                            format!("{}", routes.is_in_target(&caller_file)),
                            routes.is_complete(),
                        ));
                        let targeting = routes.module_declarations_targeting(&caller_file);
                        out.push((
                            "file_routes.module_declarations_targeting".into(),
                            format!("{:?}", targeting),
                            routes.is_complete(),
                        ));
                        let declared = routes.module_declarations_declared_in(&root);
                        out.push((
                            "file_routes.declared_in(lib.rs) start bytes".into(),
                            format!(
                                "{:?}",
                                declared
                                    .declarations
                                    .iter()
                                    .map(|d| (
                                        d.declaration_start_byte,
                                        d.target_file.rel_path().display().to_string()
                                    ))
                                    .collect::<Vec<_>>()
                            ),
                            routes.is_complete(),
                        ));
                        out.push((
                            "file_routes.production_witness".into(),
                            format!("{}", routes.file_has_production_witness(&caller_file)),
                            routes.is_complete(),
                        ));
                    }
                    Err(error) => {
                        out.push(("file_routes".into(), format!("error {error:?}"), false))
                    }
                }
                // A file no persisted unit holds: under an overlay a declaration
                // the persisted units do not carry may place it, so the answer
                // is a typed gap rather than a complete "not in a target".
                match <RustAnalyzer as RustSource>::file_routes(analyzer, &other_file, None) {
                    Ok(routes) => out.push((
                        "file_routes(other.rs).target_roots".into(),
                        format!("{:?}", routes.target_roots(&other_file)),
                        routes.is_complete(),
                    )),
                    Err(error) => out.push((
                        "file_routes(other.rs).target_roots".into(),
                        format!("error {error:?}"),
                        false,
                    )),
                }
                let test_only = IAnalyzer::file_is_test_only(analyzer, &caller_file);
                out.push((
                    "file_is_test_only".into(),
                    format!("{test_only:?}"),
                    test_only.is_ok(),
                ));
                let in_test = IAnalyzer::in_test_region(analyzer, &caller_unit);
                out.push((
                    "in_test_region".into(),
                    format!("{in_test:?}"),
                    in_test.is_ok(),
                ));
                let declared = analyzer.declarations(&caller_file);
                out.push((
                    "declarations(caller.rs)".into(),
                    format!(
                        "{:?}",
                        declared
                            .iter()
                            .map(|unit| unit.fq_name().to_string())
                            .collect::<Vec<_>>()
                    ),
                    true,
                ));
                let contains = <RustAnalyzer as RustSource>::package_contains(
                    analyzer,
                    scope.token(),
                    &caller_file,
                    None,
                );
                out.push((
                    "package_contains(caller.rs)".into(),
                    format!("{:?}", contains.as_ref().map(|a| a.value)),
                    contains.as_ref().is_ok_and(|a| a.complete),
                ));
                for package in ["root_topology_overlay", "caller", "crate::caller"] {
                    let files = <RustAnalyzer as RustSource>::package_files_of(
                        analyzer,
                        scope.token(),
                        package,
                        None,
                    );
                    out.push((
                        format!("package_files_of({package})"),
                        format!(
                            "{:?}",
                            files.as_ref().map(|a| {
                                let mut v = a
                                    .value
                                    .iter()
                                    .map(|f| f.rel_path().display().to_string())
                                    .collect::<Vec<_>>();
                                v.sort();
                                v
                            })
                        ),
                        files.as_ref().is_ok_and(|a| a.complete),
                    ));
                }
                let crates = <RustAnalyzer as RustSource>::crate_package_names(
                    analyzer,
                    scope.token(),
                    "root_topology_overlay",
                    None,
                );
                out.push((
                    "crate_package_names".into(),
                    format!("{:?}", crates.as_ref().map(|a| a.value.clone())),
                    crates.as_ref().is_ok_and(|a| a.complete),
                ));
                let reaching = <RustAnalyzer as RustSource>::files_that_can_reference_target_of(
                    analyzer, &api, None,
                );
                out.push((
                    "files_that_can_reference_target_of(api.rs)".into(),
                    format!(
                        "{:?}",
                        reaching.as_ref().map(|a| {
                            let mut v = a
                                .value
                                .iter()
                                .map(|f| f.rel_path().display().to_string())
                                .collect::<Vec<_>>();
                            v.sort();
                            v
                        })
                    ),
                    reaching.as_ref().is_ok_and(|a| a.complete),
                ));
                for (surface, answer, complete) in &out {
                    eprintln!("SURFACE {case} [{label}] {surface} complete={complete} :: {answer}");
                }
                out
            };
            let baseline = surfaces("disk", &disk);
            assert!(overlay.set(root.abs_path(), source.to_owned()));
            let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
            // Routes asked before any selected operation hydrated the buffer.
            let cold = surfaces("overlay-cold", &selected);
            // Routes asked after a selected operation hydrated the buffer, as
            // a product request that first resolves a reference would.
            let hot = disk.clone_with_project(Arc::new(overlay.snapshot()));
            assert!(matches!(
                build_rust_selected_reference_index(&hot, &CancellationToken::default()),
                RustSelectedReferenceIndexOutcome::Ready(_)
            ));
            let under = surfaces("overlay-hot", &hot);
            assert!(overlay.clear(&root.abs_path()));
            let cleared = selected.clone_with_project(Arc::new(overlay.snapshot()));
            let restored = surfaces("cleared", &cleared);
            // Surfaces whose right answer under the overlay is the disk answer,
            // with the contract that says so:
            // - declaration names come from the Cargo manifest and the file's
            //   path (`crate_naming`), never from the `mod` edges;
            // - a package name no crate has is empty in every state;
            // - a file outside every module tree is never classified test-only
            //   (`RustCargoRouteIndex::file_is_test_only`);
            // - the route index evaluates no profile, so a `cfg` other than
            //   `test` leaves a declaration routing (`cargo_routes.rs`, the
            //   decoration comment in the module-child builder).
            let unchanged_by_contract = |surface: &str| {
                matches!(
                    surface,
                    "declarations(caller.rs)"
                        | "package_files_of(caller)"
                        | "package_files_of(crate::caller)"
                ) || (case != "disk" && matches!(surface, "file_is_test_only" | "in_test_region"))
                    || (case == "gated"
                        && matches!(
                            surface,
                            "file_routes.target_roots"
                                | "file_routes.is_in_target"
                                | "file_routes.production_witness"
                                | "files_that_can_reference_target_of(api.rs)"
                        ))
            };
            if case != "disk" {
                for (label, under) in [("cold", &cold), ("hot", &under)] {
                    for ((surface, base_answer, _), (_, answer, complete)) in
                        baseline.iter().zip(under)
                    {
                        if *complete && answer == base_answer && !unchanged_by_contract(surface) {
                            stale.push(format!("{case} [{label}]: {surface}"));
                        }
                    }
                    // The overlay moved the edge, so the declaring file's own
                    // declarations are the overlay's, not the disk's.
                    let declared = |rows: &[(String, String, bool)]| {
                        rows.iter()
                            .find(|(surface, _, _)| surface.starts_with("file_routes.declared_in"))
                            .map(|(_, answer, _)| answer.clone())
                    };
                    assert_ne!(
                        declared(under),
                        declared(&baseline),
                        "{case} [{label}]: the overlaid root's declarations are the disk's"
                    );
                    if case != "gated" {
                        for (surface, answer, _) in under {
                            match surface.as_str() {
                                "file_routes.target_roots" => {
                                    assert_eq!(answer, "[]", "{case} [{label}]: {surface}")
                                }
                                "file_routes.is_in_target" | "file_routes.production_witness" => {
                                    assert_eq!(answer, "false", "{case} [{label}]: {surface}")
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            for ((surface, base_answer, _), (_, answer, _)) in baseline.iter().zip(&restored) {
                assert_eq!(answer, base_answer, "{case}: cleared {surface}");
            }
        }
        assert!(stale.is_empty(), "stale complete surfaces: {stale:#?}");
    }

    #[test]
    #[hardwon(
        "#11546: Cargo-route derivations hashed the revision's file content, so an overlay moved no unit's route inputs"
    )]
    fn cargo_route_body_edit_overlay_moves_only_the_edited_units_inputs() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_rust::graph_support::RustSource;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId;

        let manifest = |name: &str| {
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"left\", \"right\"]\nresolver = \"2\"\n",
            )
            .file("left/Cargo.toml", manifest("left"))
            .file("left/src/lib.rs", "mod leaf;\n")
            .file("left/src/leaf.rs", "pub fn leaf() {}\n")
            .file("right/Cargo.toml", manifest("right"))
            .file("right/src/lib.rs", "mod leaf;\n")
            .file("right/src/leaf.rs", "pub fn leaf() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let left_leaf = fixture.file("left/src/leaf.rs");
        let right_leaf = fixture.file("right/src/leaf.rs");
        let routes_asked = |analyzer: &RustAnalyzer| {
            let _scope = AnalyzerQueryScope::new(analyzer);
            [&left_leaf, &right_leaf].map(|file| {
                let routes = <RustAnalyzer as RustSource>::file_routes(analyzer, file, None)
                    .expect("file routes");
                (routes.target_roots(file), routes.is_complete())
            })
        };
        let tokens = |analyzer: &RustAnalyzer| {
            [
                analyzer
                    .route_unit_input_tokens_for_test("left/src/leaf.rs")
                    .expect("left unit token"),
                analyzer
                    .route_unit_input_tokens_for_test("right/src/leaf.rs")
                    .expect("right unit token"),
            ]
        };
        let on_disk = routes_asked(&disk);
        for (roots, complete) in &on_disk {
            assert!(*complete && roots.len() == 1, "disk routes: {on_disk:?}");
        }
        let disk_tokens = tokens(&disk);
        assert!(disk_tokens.iter().all(|units| units.len() == 1));

        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        // A body edit: the module declarations and the member set are
        // unchanged, so the routes are the disk routes and stay definite.
        assert!(overlay.set(
            left_leaf.abs_path(),
            "pub fn leaf() { let _edited = 1; }\n".to_owned()
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert_eq!(
            routes_asked(&selected),
            on_disk,
            "a body edit keeps the routes definite and equal"
        );
        // The route derivations are keyed by these tokens, so only the edited
        // unit's derivations are re-derived under the overlay.
        let overlay_tokens = tokens(&selected);
        assert_eq!(
            overlay_tokens[0][0].0, disk_tokens[0][0].0,
            "same left unit"
        );
        assert_ne!(
            overlay_tokens[0][0].1, disk_tokens[0][0].1,
            "the edited unit's route inputs see the overlay content"
        );
        assert_eq!(
            overlay_tokens[1], disk_tokens[1],
            "the untouched unit's route inputs are the disk's"
        );
        // The derivation engine is per analyzer, and an overlay's derivations
        // are not retained, so the clone recomputes what it is asked.
        let counters = |analyzer: &RustAnalyzer| {
            IAnalyzer::snapshot_caches(analyzer)
                .expect("snapshot caches")
                .derivations()
                .counters(DerivationKindId("derivation:rust_unit_routes:v1"))
        };
        eprintln!("ROUTE COUNTERS disk: {:?}", counters(&disk));
        eprintln!("ROUTE COUNTERS overlay: {:?}", counters(&selected));
    }

    #[test]
    #[hardwon("#12202: review found an overlay mod declaration missed by persisted placements")]
    fn cargo_route_overlay_added_placement_does_not_certify_old_units() {
        use brokk_bifrost_rust::graph_support::RustSource;

        let manifest = |name: &str| {
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"left\", \"right\"]\nresolver = \"2\"\n",
            )
            .file("left/Cargo.toml", manifest("left"))
            .file("left/src/lib.rs", "mod leaf;\n")
            .file("left/src/leaf.rs", "pub fn leaf() {}\n")
            .file("right/Cargo.toml", manifest("right"))
            .file("right/src/lib.rs", "pub fn right() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let leaf = fixture.file("left/src/leaf.rs");
        {
            let _scope = AnalyzerQueryScope::new(&disk);
            let routes = <RustAnalyzer as RustSource>::file_routes(&disk, &leaf, None)
                .expect("disk file routes");
            assert!(routes.is_complete());
            assert_eq!(routes.target_roots(&leaf).len(), 1);
        }
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("right/src/lib.rs").abs_path(),
            "#[path = \"../../left/src/leaf.rs\"] mod shared;\npub fn right() {}\n".to_owned(),
        ));
        let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
        let _scope = AnalyzerQueryScope::new(&selected);
        if let Ok(routes) = <RustAnalyzer as RustSource>::file_routes(&selected, &leaf, None) {
            assert!(
                !routes.is_complete() || routes.target_roots(&leaf).len() == 2,
                "persisted units omitted the placement introduced by the overlay"
            );
        }
    }

    /// An overlay request re-derives the routes of the units it touches, and
    /// nothing else: the work does not grow with the crates around them. The
    /// workspace is a chain of crates, each depending on the one before it; one
    /// body edit lands in a middle crate, and the route question asked is that
    /// crate's own. The same edit and question in a workspace twice as large
    /// does the same work, and only the edited unit's route inputs move.
    #[test]
    fn cargo_route_overlay_recompute_is_bounded_by_the_touched_unit() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_rust::graph_support::RustSource;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId;

        const TOUCHED: usize = 2;
        // The kinds a route question can demand, by their registered ids.
        const KINDS: [&str; 5] = [
            "derivation:rust_unit_routes:v1",
            "derivation:rust_unit_inputs:v2",
            "derivation:rust_unit_naming:v1",
            "derivation:rust_unit_package_rows:v1",
            "derivation:rust_broad_file_units:v1",
        ];
        // Per kind: (recomputed, not retainable) on the overlay request.
        let overlay_work = |crates: usize| -> Vec<(&'static str, u64, u64)> {
            let members = (0..crates)
                .map(|index| format!("\"c{index}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let mut project = InlineTestProject::with_language(Language::Rust).file(
                "Cargo.toml",
                format!("[workspace]\nmembers = [{members}]\nresolver = \"2\"\n"),
            );
            for index in 0..crates {
                let dependency = if index == 0 {
                    String::new()
                } else {
                    format!("c{} = {{ path = \"../c{}\" }}\n", index - 1, index - 1)
                };
                project = project
                    .file(
                        format!("c{index}/Cargo.toml"),
                        format!(
                            "[package]\nname = \"c{index}\"\nversion = \"0.1.0\"\n\
                             edition = \"2024\"\n[dependencies]\n{dependency}"
                        ),
                    )
                    .file(format!("c{index}/src/lib.rs"), "mod leaf;\n")
                    .file(format!("c{index}/src/leaf.rs"), "pub fn leaf() {}\n");
            }
            let fixture = project.build();
            let disk = RustAnalyzer::new(fixture.project_dyn());
            let leaf_path = |index: usize| format!("c{index}/src/leaf.rs");
            let touched_leaf = fixture.file(leaf_path(TOUCHED));
            let tokens = |analyzer: &RustAnalyzer| {
                (0..crates)
                    .map(|index| {
                        analyzer
                            .route_unit_input_tokens_for_test(&leaf_path(index))
                            .expect("unit token")
                    })
                    .collect::<Vec<_>>()
            };
            let disk_tokens = tokens(&disk);

            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            assert!(overlay.set(
                touched_leaf.abs_path(),
                "pub fn leaf() { let _edited = 1; }\n".to_owned()
            ));
            let selected = disk.clone_with_project(Arc::new(overlay.snapshot()));
            // Key side: only the edited unit's route inputs move.
            let overlay_tokens = tokens(&selected);
            for index in 0..crates {
                assert_eq!(
                    overlay_tokens[index] != disk_tokens[index],
                    index == TOUCHED,
                    "unit c{index}: only the edited unit's route inputs may move"
                );
            }
            // Work side: the route question of the touched crate.
            let routes = {
                let _scope = AnalyzerQueryScope::new(&selected);
                <RustAnalyzer as RustSource>::file_routes(&selected, &touched_leaf, None)
                    .expect("file routes")
            };
            assert!(
                routes.is_complete() && routes.target_roots(&touched_leaf).len() == 1,
                "a body edit keeps the touched crate's routes definite"
            );
            let derivations = IAnalyzer::snapshot_caches(&selected)
                .expect("snapshot caches")
                .derivations();
            KINDS
                .into_iter()
                .map(|kind| {
                    let counters = derivations.counters(DerivationKindId(kind));
                    eprintln!("OVERLAY WORK crates={crates} {kind}: {counters:?}");
                    (kind, counters.recomputed, counters.not_retainable)
                })
                .collect()
        };
        let small = overlay_work(6);
        let large = overlay_work(12);
        assert_eq!(
            small[0],
            ("derivation:rust_unit_routes:v1", 1, 1),
            "the overlay request re-derives the touched unit's routes only: {small:?}"
        );
        assert_eq!(
            small, large,
            "doubling the unrelated crates must not change the overlay request's work"
        );
    }

    #[test]
    #[hardwon("a359fa9c0331: the selected Rust index refused a new open source on its first query")]
    fn production_reference_index_answers_an_unprepared_new_source_overlay() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"new_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn target() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        assert!(
            disk.all_declarations()
                .any(|unit| unit.identifier() == "target")
        );
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(
            fixture.file("src/new.rs").abs_path(),
            "pub fn caller() { crate::target(); }\n".to_owned()
        ));
        let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
        // A buffer for a file no persisted mount carries is hydrated the same
        // way, so the first call answers instead of refusing.
        assert!(
            matches!(
                build_rust_selected_reference_index(&analyzer, &CancellationToken::default()),
                RustSelectedReferenceIndexOutcome::Ready(_)
            ),
            "a new source buffer answers from its own facts"
        );
    }

    #[test]
    #[hardwon(
        "cee0ead34a66: retargeted root-qualified Rust overlays retained stale reference edges"
    )]
    fn production_reference_index_retargets_root_qualified_overlay_without_stale_edges() {
        let disk_source = concat!(
            "pub mod left;\n",
            "pub mod right;\n",
            "pub fn caller() { crate::left::target(); }\n",
        );
        let overlay_source = disk_source.replace("crate::left::target", "crate::right::target");
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"root_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", disk_source)
            .file("src/left.rs", "pub fn target() {}\n")
            .file("src/right.rs", "pub fn target() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let left_file = fixture.file("src/left.rs");
        let right_file = fixture.file("src/right.rs");
        let all_declarations = disk.all_declarations().collect::<Vec<_>>();
        let left_target = all_declarations
            .iter()
            .find(|unit| unit.source() == &left_file && unit.identifier() == "target")
            .cloned()
            .expect("left target declaration");
        let right_target = all_declarations
            .iter()
            .find(|unit| unit.source() == &right_file && unit.identifier() == "target")
            .cloned()
            .expect("right target declaration");
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(file.abs_path(), overlay_source.clone()));
        let request_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(request_project);
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        let updated_start = overlay_source
            .find("crate::right::target()")
            .expect("updated qualified terminal call")
            + "crate::right::".len();
        let selected =
            match selected_rust_workspace_binding_world(&analyzer, &CancellationToken::default()) {
                RustWorkspaceBindingWorldResult::Ready(selected) => selected,
                RustWorkspaceBindingWorldResult::Unavailable(detail) => {
                    panic!("selected overlay binding world unavailable: {detail}")
                }
                RustWorkspaceBindingWorldResult::Stale(detail) => {
                    panic!("selected overlay binding world stale: {detail}")
                }
                RustWorkspaceBindingWorldResult::Cancelled => {
                    panic!("selected overlay binding world cancelled")
                }
                RustWorkspaceBindingWorldResult::StoreError(detail) => {
                    panic!("selected overlay binding world store error: {detail}")
                }
            };
        let expected_right_definition = selected
            .definition_units
            .iter()
            .find(|(_, unit)| *unit == &right_target)
            .map(|(definition, _)| definition)
            .expect("selected overlay definition units contain right target");
        let updated_site = selected
            .world
            .sites()
            .iter()
            .find(|site| {
                site.file() == &file
                    && site
                        .metadata()
                        .is_some_and(|metadata| metadata.start_byte() == updated_start)
            })
            .expect("selected overlay world retains updated qualified terminal site");
        assert_eq!(
            updated_site.completion(),
            &ResolutionCompletion::Complete,
            "updated selected site completion: {updated_site:?}"
        );
        assert_eq!(
            updated_site.definitions(),
            std::slice::from_ref(expected_right_definition),
            "updated selected site definitions: site={updated_site:?}, right={right_target:?}, units={:?}",
            selected.definition_units.values().collect::<Vec<_>>()
        );
        let RustSelectedReferenceIndexOutcome::Ready(index) =
            build_rust_selected_reference_index(&analyzer, &CancellationToken::default())
        else {
            panic!("selected overlay reference index must be available")
        };
        let updated = index.inverse_for(&right_target);
        assert_eq!(updated.edges.len(), 1, "{updated:?}");
        let edge = &updated.edges[0];
        assert_eq!(edge.target, right_target);
        assert_eq!(edge.site.file, file);
        assert_eq!(edge.site.range.start_byte, updated_start);
        assert_eq!(edge.site.range.end_byte, updated_start + "target".len());
        assert_eq!(edge.proof, UsageProof::Proven);
        assert_eq!(edge.usage_kind, UsageHitKind::Reference);
        assert!(index.inverse_for(&left_target).edges.is_empty());
    }

    #[test]
    fn production_workspace_graph_shadow_preserves_bare_local_import_edges_and_line_weights() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub mod dep;\n",
                    "use dep::target;\n",
                    "pub fn caller() -> usize { target() + target() }\n",
                    "pub fn second() -> usize { target() }\n",
                ),
            )
            .file("src/dep.rs", "pub fn target() -> usize { 1 }\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let catalog = WorkspaceUsageCatalog::build(&analyzer);
        let selected = BTreeSet::from([UsageEcosystem::Rust]);
        let cancellation = CancellationToken::default();
        let WorkspaceUsageGraphBuildOutcome::Complete(graph) =
            build_workspace_usage_graph_with_cancellation(
                &analyzer,
                catalog,
                &selected,
                &cancellation,
            )
        else {
            panic!("uncancelled Rust workspace graph build")
        };

        let native = selected_rust_workspace_graph_shadow_result(&analyzer, &graph, &cancellation);
        let RustWorkspaceGraphShadowResult::Complete(native) = native else {
            panic!("simple library Rust graph must complete: {native:#?}")
        };
        assert!(native.truncated.is_empty());
        assert!(native.unproven_inbound.is_empty());
        assert_eq!(native.edges.len(), 2);
        assert!(native.edges.iter().all(|((caller, callee), counts)| {
            matches!(caller.identifier(), "caller" | "second")
                && callee.identifier() == "target"
                && counts.calls == 1
                && counts.total() == 1
        }));
    }

    #[test]
    fn production_rust_support_answers_a_dirty_buffer_on_its_first_call() {
        let disk = "pub struct DiskWidget;\npub fn make() -> DiskWidget { DiskWidget }\n";
        let buffer = "pub struct BufferWidget;\npub fn make() -> BufferWidget { BufferWidget }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"dirty_support\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", disk)
            .build();
        let file = fixture.file("src/lib.rs");
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(file.abs_path(), buffer.to_owned()));
        let analyzer = RustAnalyzer::new(fixture.project_dyn())
            .clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);

        let mut site = rust_shadow_site(buffer, "BufferWidget");
        site.path = rel_path_string(&file);
        let tree = rust_shadow_tree(buffer);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: buffer,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };

        let BoundedResolution::Complete {
            value: definition, ..
        } = RustSupport.resolve_definition_bounded(query)
        else {
            panic!("a dirty Rust buffer completes on its first definition call")
        };
        assert_eq!(
            definition.status,
            DefinitionLookupStatus::Resolved,
            "{definition:#?}"
        );
        assert_eq!(
            definition
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>(),
            vec!["BufferWidget".to_owned()],
        );

        let BoundedResolution::Complete {
            value: projected, ..
        } = RustSupport.resolve_type_bounded(query)
        else {
            panic!("a dirty Rust buffer completes on its first type call")
        };
        assert_ne!(
            projected.status,
            brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus::Unavailable,
            "{projected:#?}"
        );
    }

    #[test]
    fn production_structural_resolver_shadows_rust_budget_and_cancellation_terminals() {
        let source = concat!(
            "pub mod model;\n",
            "pub use model::target as alias;\n",
            "pub fn caller() -> usize { alias() }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/model.rs", "pub fn target() -> usize { 1 }\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(source, "alias");
        let tree = rust_shadow_tree(source);
        let caller_cancellation = CancellationToken::new();
        let baseline_query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: Some(&caller_cancellation),
        };
        // An analyzer's first selected operation charges more receiver-analysis
        // work than its later ones, because the first one populates the
        // retained selection and typed-frontier reads that the rest reuse.
        // Measured on this tree at HEAD: cold (setup_nodes 0,
        // summary_expansions 13, scope_nodes 657) and warm (0, 10, 621),
        // identical on every operation after the first. The exact-budget and
        // one-unit-under properties below are about one steady-state
        // operation, so discard the cold operation before measuring.
        let cold = selected_rust_definition_shadow_result(&analyzer, baseline_query);
        assert!(matches!(cold, RustDefinitionShadowResult::Complete { .. }));
        let baseline = selected_rust_definition_shadow_result(&analyzer, baseline_query);
        let RustDefinitionShadowResult::Complete {
            work: baseline_work,
            ..
        } = baseline
        else {
            panic!("default Rust shadow budget must complete")
        };
        let exact_query = BoundedReceiverQuery {
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_summary_expansions: baseline_work.summary_expansions,
                    max_scope_nodes: baseline_work.scope_nodes,
                    ..Default::default()
                },
            ..baseline_query
        };
        assert!(matches!(
            selected_rust_definition_shadow_result(&analyzer, exact_query),
            RustDefinitionShadowResult::Complete { work, .. } if work == baseline_work
        ));
        assert!(matches!(
            RustSupport.resolve_definition_bounded(exact_query),
            BoundedResolution::Complete { .. }
        ));
        let under_query = BoundedReceiverQuery {
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_summary_expansions: baseline_work.summary_expansions,
                    max_scope_nodes: baseline_work.scope_nodes - 1,
                    ..Default::default()
                },
            ..baseline_query
        };
        assert!(matches!(
            selected_rust_definition_shadow_result(&analyzer, under_query),
            RustDefinitionShadowResult::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
        assert!(!caller_cancellation.is_cancelled());

        let exhausted = BoundedReceiverQuery {
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                    max_scope_nodes: 0,
                    ..Default::default()
                },
            ..baseline_query
        };
        let native = selected_rust_definition_shadow_result(&analyzer, exhausted);
        assert!(matches!(
            native,
            RustDefinitionShadowResult::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
        assert!(!caller_cancellation.is_cancelled());

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_query = BoundedReceiverQuery {
            budget: Default::default(),
            cancellation: Some(&cancelled),
            ..exhausted
        };
        let native = selected_rust_definition_shadow_result(&analyzer, cancelled_query);
        assert!(matches!(
            native,
            RustDefinitionShadowResult::Cancelled { .. }
        ));
    }

    #[test]
    #[hardwon("#4480: common intrinsic seeds exhausted the receiver work budget")]
    fn selected_rust_local_method_receiver_ignores_repeated_intrinsic_seed_values() {
        let mut source = String::from(
            "fn hybrid(model: &str) -> bool {\n    let model = model.trim().to_ascii_lowercase();\n    model.starts_with(\"kimi-k2.5\")\n}\n\nfn unrelated_literals() {\n    let _ = [\n",
        );
        for _ in 0..12_000 {
            source.push_str("        \"unrelated string value\",\n");
        }
        source.push_str("    ];\n}\n");

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"intrinsic_descriptor_budget\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", &source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let site = rust_shadow_site(&source, "model");
        let tree = rust_shadow_tree(&source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: &source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };

        let BoundedResolution::Complete { value, work } =
            RustSupport.resolve_definition_bounded(query)
        else {
            panic!("repeated unrelated intrinsic seeds must not exhaust receiver analysis")
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(value.definitions.is_empty(), "{value:#?}");
        let local = value
            .lexical_definition
            .as_ref()
            .expect("method receiver resolves to its local let binding");
        assert_eq!(local.identifier, "model");
        assert_eq!(
            local.name_range.start_byte,
            source.find("let model").expect("local binding") + "let ".len()
        );
        assert!(
            work.scope_nodes < 5_000,
            "the descriptor read should charge distinct descriptors, not all 12,000 string seeds: {work:?}"
        );
    }

    #[test]
    #[hardwon("33c9cafaff12: a selected import name from ordinary source content was not resolved")]
    fn production_structural_resolver_follows_unsaved_import_name() {
        let disk_source = concat!(
            "pub mod model;\n",
            "pub use model::target as alias;\n",
            "pub fn caller() -> usize { alias() }\n",
        );
        let overlay_source = concat!(
            "pub mod model;\n",
            "pub use model::replacement as alias;\n",
            "pub fn caller() -> usize { alias() }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", disk_source)
            .file(
                "src/model.rs",
                "pub fn target() -> usize { 1 }\npub fn replacement() -> usize { 2 }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(file.abs_path(), overlay_source.to_string()));
        let request_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let analyzer = disk.clone_with_project(request_project);
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.short_name() == "caller")
        );
        let site = rust_shadow_site(overlay_source, "alias");
        let tree = rust_shadow_tree(overlay_source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: overlay_source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let native = selected_rust_definition_shadow_result(&analyzer, query);
        let RustDefinitionShadowResult::Complete {
            status: DefinitionLookupStatus::Resolved,
            definitions,
            ..
        } = native
        else {
            panic!("selected import name must resolve to its actual target: {native:#?}")
        };
        let expected = analyzer
            .declarations(&fixture.file("src/model.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "replacement")
            .expect("parsed replacement declaration");
        assert_eq!(definitions, [expected]);
    }

    #[test]
    fn production_rust_shadow_rejects_a_generation_change_after_open() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let changed_source = "pub fn target() {}\npub fn caller() { target(); target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(file.abs_path(), source.to_string()));
        let request_project: Arc<dyn Project> = overlay.clone();
        let analyzer = disk.clone_with_project(request_project);
        let _ = analyzer.declarations(&file);
        let site = rust_shadow_site(source, "target");
        let tree = rust_shadow_tree(source);
        let query = BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: Default::default(),
            cancellation: None,
        };
        let result =
            selected_rust_definition_shadow_result_with_after_open(&analyzer, query, || {
                assert!(overlay.set(file.abs_path(), changed_source.to_string()));
            });
        assert!(
            matches!(result, RustDefinitionShadowResult::Stale(_)),
            "{result:?}"
        );
    }

    // #11682: overlays that ADD a module, include or cfg-activated edge.
    //
    // The mirror of the #11546 tests above. The selected placement relation is
    // filled from persisted placements, so a module the overlay adds has no
    // placement; the fill records it in temp.selected_rust_added_edges and the
    // gap view reports it.

    /// `fixture` with the `edits` laid over it as an overlay.
    fn overlay_selected(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        disk: &RustAnalyzer,
        edits: &[(&str, &str)],
    ) -> RustAnalyzer {
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        for (path, source) in edits {
            assert!(overlay.set(fixture.file(path).abs_path(), (*source).to_owned()));
        }
        disk.clone_with_project(Arc::new(overlay.snapshot()))
    }

    /// The definition lookup of the last `spelling` in `source`, which the
    /// overlay holds as `rel`.
    fn overlay_lookup(
        analyzer: &RustAnalyzer,
        fixture: &crate::inline_project::BuiltInlineTestProject,
        rel: &str,
        source: &str,
        spelling: &str,
    ) -> RustDefinitionShadowResult {
        let file = fixture.file(rel);
        let site = rust_shadow_site(source, spelling);
        let tree = rust_shadow_tree(source);
        selected_rust_definition_shadow_result(
            analyzer,
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: Default::default(),
                cancellation: None,
            },
        )
    }

    #[test]
    #[hardwon("#11834: a decided-true cfg module must retain its module and names")]
    fn selected_cfg_active_module_keeps_names() {
        let source = "#[cfg(unix)] mod gated; fn run() { let _: gated::Gated; }";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname='placement'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                ".cargo/config.toml",
                "[build]\ntarget='x86_64-unknown-linux-gnu'\n",
            )
            .file("src/lib.rs", source)
            .file("src/gated.rs", "pub struct Gated;")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let result = overlay_lookup(&rust, &fixture, "src/lib.rs", source, "Gated");
        let definitions = match result {
            RustDefinitionShadowResult::Complete { definitions, .. }
            | RustDefinitionShadowResult::Incomplete { definitions, .. } => definitions,
            other => panic!("active module: {other:?}"),
        };
        assert!(
            definitions.iter().any(|unit| unit.short_name() == "Gated"),
            "{definitions:?}"
        );
    }

    /// A lookup that the overlay answers `Complete` with no definition is the
    /// fail-open answer: it certifies an absence the disk workspace refutes.
    fn complete_miss(result: &RustDefinitionShadowResult) -> bool {
        matches!(result, RustDefinitionShadowResult::Complete { definitions, .. } if definitions.is_empty())
    }

    #[test]
    #[hardwon("#11682: a path through a module the overlay adds answered a complete NoDefinition")]
    fn selected_rust_bare_path_through_an_added_module_is_not_a_complete_miss() {
        let mut failures = Vec::new();
        for foo_on_disk in [false, true] {
            for spelling in ["crate::foo::bar", "self::foo::bar", "foo::bar"] {
                let mut project = InlineTestProject::with_language(Language::Rust)
                    .file("Cargo.toml", "[package]\nname = \"added_bare\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                    .file("src/lib.rs", "mod api;\n")
                    .file("src/api.rs", "pub fn f() {}\n");
                if foo_on_disk {
                    project = project.file("src/foo.rs", "pub fn bar() {}\n");
                }
                let fixture = project.build();
                let disk = RustAnalyzer::new(fixture.project_dyn());
                let source = format!("mod api;\nmod foo;\npub fn call() {{ {spelling}(); }}\n");
                let mut edits = vec![("src/lib.rs", source.as_str())];
                if !foo_on_disk {
                    edits.push(("src/foo.rs", "pub fn bar() {}\n"));
                }
                let selected = overlay_selected(&fixture, &disk, &edits);
                let result = overlay_lookup(&selected, &fixture, "src/lib.rs", &source, "bar");
                eprintln!("on_disk={foo_on_disk} {spelling}: {result:?}");
                if complete_miss(&result) {
                    failures.push((foo_on_disk, spelling));
                }
            }
        }
        assert!(failures.is_empty(), "complete misses: {failures:?}");
    }

    /// Lib files for the glob tests: `bar` is declared in files that no edge
    /// mounts (`foo.rs`, `gone.rs` behind a false cfg, `extra.rs`), and the
    /// glob importers `user.rs` (direct) and `user2.rs` (through `hub.rs`, which
    /// re-exports the crate root's glob) are never changed.
    fn added_edge_glob_fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_glob\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "mod user; mod user2; mod hub;\n#[cfg(any())] mod gone;\n",
            )
            .file("src/user.rs", "use crate::*;\npub fn call() { bar(); }\n")
            .file("src/hub.rs", "pub use crate::*;\n")
            .file(
                "src/user2.rs",
                "use crate::hub::*;\npub fn call() { bar(); }\n",
            )
            .file("src/foo.rs", "pub fn bar() {}\n")
            .file("src/gone.rs", "pub fn bar() {}\n")
            .file("src/extra.rs", "pub fn bar() {}\n")
            .build()
    }

    #[test]
    #[hardwon(
        "#11682: a glob of a module whose inventory the overlay grew answered a complete NoDefinition"
    )]
    fn selected_rust_glob_of_a_module_with_an_added_edge_is_not_a_complete_miss() {
        let fixture = added_edge_glob_fixture();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let mut failures = Vec::new();
        for (kind, lib) in [
            (
                "added mod",
                "mod user; mod user2; mod hub;\n#[cfg(any())] mod gone;\nmod foo;\npub use foo::bar;\n",
            ),
            (
                "gate removed",
                "mod user; mod user2; mod hub;\nmod gone;\npub use gone::bar;\n",
            ),
            (
                "added include",
                "mod user; mod user2; mod hub;\n#[cfg(any())] mod gone;\ninclude!(\"extra.rs\");\n",
            ),
        ] {
            let selected = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib)]);
            // The importers are unchanged files: only the root's edges moved.
            for (rel, source) in [
                ("src/user.rs", "use crate::*;\npub fn call() { bar(); }\n"),
                (
                    "src/user2.rs",
                    "use crate::hub::*;\npub fn call() { bar(); }\n",
                ),
            ] {
                let result = overlay_lookup(&selected, &fixture, rel, source, "bar");
                eprintln!("{kind} {rel}: {result:?}");
                if complete_miss(&result) {
                    failures.push((kind, rel));
                }
            }
        }
        assert!(failures.is_empty(), "complete misses: {failures:?}");
    }

    #[test]
    #[hardwon("#11682: a #[path] retarget left the parent inventory closed")]
    fn selected_rust_path_attribute_retarget_opens_the_parent_inventory_and_a_kept_edge_does_not() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_retarget\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "#[path = \"x.rs\"] mod foo;\nmod user;\n")
            .file("src/x.rs", "pub fn bar() {}\n")
            .file("src/y.rs", "pub fn bar() {}\n")
            .file(
                "src/user.rs",
                "use crate::*;\npub fn call() { missing(); }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let user = "use crate::*;\npub fn call() { missing(); }\n";
        let lookup = |lib: &str| {
            let selected = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib)]);
            overlay_lookup(&selected, &fixture, "src/user.rs", user, "missing")
        };
        // The same edge, the same target file: the persisted topology stands.
        let kept = lookup("// edited\n#[path = \"x.rs\"] mod foo;\nmod user;\n");
        assert!(
            complete_miss(&kept),
            "a byte-changed root that keeps its edge must stay a proven absence: {kept:?}"
        );
        // Another target file under the same module name is a new edge.
        let retargeted = lookup("#[path = \"y.rs\"] mod foo;\nmod user;\n");
        assert!(
            !complete_miss(&retargeted),
            "a retargeted #[path] edge names a file no persisted placement holds: {retargeted:?}"
        );
    }

    /// An inline `mod foo { .. }` the overlay adds needs no edge: the changed
    /// declaring file's own selected facts declare the module and its items, so
    /// point lookups resolve it, and a glob from an unchanged file finds it.
    #[test]
    fn selected_rust_inline_module_added_in_a_changed_file_resolves() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_inline\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "mod user;\n")
            .file("src/user.rs", "use crate::*;\npub fn call() { bar(); }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let lib = "mod user;\nmod inline_foo { pub fn bar() {} }\npub use inline_foo::bar;\n\
                   pub fn call() { inline_foo::bar(); crate::inline_foo::bar(); }\n";
        let selected = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib)]);
        let user = "use crate::*;\npub fn call() { bar(); }\n";
        let mut answers = vec![overlay_lookup(
            &selected,
            &fixture,
            "src/user.rs",
            user,
            "bar",
        )];
        answers.push(overlay_lookup(
            &selected,
            &fixture,
            "src/lib.rs",
            lib,
            "bar",
        ));
        for answer in &answers {
            eprintln!("inline module: {answer:?}");
            assert!(!complete_miss(answer), "{answer:?}");
        }
    }

    /// `#[macro_use] mod macros;` on an added edge moves macro scope into the
    /// parent. The textual macro walk reads child modules from persisted
    /// placements, so the macro name must not come back a complete miss.
    #[test]
    #[hardwon(
        "#11682: a macro defined in a #[macro_use] module the overlay adds answered NoDefinition"
    )]
    fn selected_rust_macro_use_module_added_by_an_overlay_is_not_a_complete_miss() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_macro_use\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn call() {}\n")
            .file("src/macros.rs", "macro_rules! m { () => {}; }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let lib = "#[macro_use]\nmod macros;\npub fn call() { m!(); }\n";
        let selected = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib)]);
        let answer = overlay_lookup(&selected, &fixture, "src/lib.rs", lib, "m");
        eprintln!("macro_use: {answer:?}");
        assert!(!complete_miss(&answer), "{answer:?}");
    }

    /// A macro the persisted walk already resolves is no proof once an overlay
    /// adds a `#[macro_use] mod` or an include before the call: the added file
    /// can define a later macro of the same name, which shadows the earlier one
    /// in textual scope. A Complete answer holding only the old target is stale.
    #[test]
    #[hardwon(
        "#11682: a macro call that already resolved stayed Complete after an overlay added a shadowing macro_use module or include"
    )]
    fn selected_rust_added_macro_scope_edge_reopens_a_macro_that_already_resolves() {
        let mut stale = Vec::new();
        for (kind, edge) in [
            ("macro_use mod", "#[macro_use]\nmod macros;\n"),
            ("include", "include!(\"macros.rs\");\n"),
        ] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"added_macro_shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .file(
                    "src/lib.rs",
                    "macro_rules! m { () => {}; }\npub fn call() { m!(); }\n",
                )
                .file("src/macros.rs", "macro_rules! m { () => {}; }\n")
                .build();
            let disk = RustAnalyzer::new(fixture.project_dyn());
            let before = "macro_rules! m { () => {}; }\npub fn call() { m!(); }\n";
            let on_disk = overlay_lookup(&disk, &fixture, "src/lib.rs", before, "m");
            assert!(
                matches!(on_disk, RustDefinitionShadowResult::Complete { ref definitions, .. } if !definitions.is_empty()),
                "{kind}: the macro resolves before the overlay: {on_disk:?}"
            );
            let lib =
                format!("macro_rules! m {{ () => {{}}; }}\n{edge}pub fn call() {{ m!(); }}\n");
            let selected = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib.as_str())]);
            let result = overlay_lookup(&selected, &fixture, "src/lib.rs", &lib, "m");
            eprintln!("{kind}: {result:?}");
            if matches!(result, RustDefinitionShadowResult::Complete { .. }) {
                stale.push(kind);
            }
        }
        assert!(
            stale.is_empty(),
            "Complete answers with the old target: {stale:?}"
        );
    }

    /// An overlay that adds a module behind a cfg the selected configuration
    /// cannot decide (`my_flag` is a custom atom, and an incomplete Cargo feature
    /// set reads the same way) leaves the edge unknown. The persisted topology
    /// has no gap for an edge it never held, so the reverse set must not come
    /// back Complete without the caller that edge may mount.
    #[test]
    #[hardwon("#11682: an overlay-added edge under an unknown cfg was dropped, not opened")]
    fn selected_rust_reverse_references_do_not_miss_a_caller_behind_an_unknown_cfg_edge() {
        for (case, lib_added, extra_files) in [
            (
                "mod",
                "pub fn top() {}\n#[cfg(my_flag)] mod caller;\n",
                vec![("src/caller.rs", "pub fn call() { crate::top(); }\n")],
            ),
            (
                "enclosing inline cfg",
                "pub fn top() {}\n#[cfg(my_flag)] mod wrap { mod caller; }\n",
                vec![("src/wrap/caller.rs", "pub fn call() { crate::top(); }\n")],
            ),
            (
                "include under cfg",
                "pub fn top() {}\n#[cfg(my_flag)] mod wrap { include!(\"caller.rs\"); }\n",
                vec![("src/caller.rs", "pub fn call() { crate::top(); }\n")],
            ),
        ] {
            let mut project = InlineTestProject::with_language(Language::Rust).file(
                "Cargo.toml",
                "[package]\nname = \"added_unknown\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn top() {}\n");
            for (path, source) in &extra_files {
                project = project.file(*path, *source);
            }
            let fixture = project.build();
            let disk = RustAnalyzer::new(fixture.project_dyn());
            let target = disk
                .all_declarations()
                .find(|unit| unit.identifier() == "top")
                .expect("disk target");
            let caller = fixture.file(extra_files[0].0);
            let added = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib_added)]);
            assert!(
                !reverse_misses_caller(&added, &target, &caller),
                "{case}: the overlay adds an edge that may mount the caller, yet the reverse set is complete without it"
            );
        }
    }

    /// The files whose persisted placements the selection unplaces when the
    /// overlay removes `removed` from `fixture`, read from the fill's own relation.
    fn unplaced_files_after_removing(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        removed: &str,
    ) -> Vec<String> {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
            SelectedResolutionOverlayMask,
        };
        let analyzer = fixture.workspace_analyzer(Default::default());
        let store = analyzer.store().unwrap();
        let workspace = {
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::WorkspaceId(
                conn.query_row(
                    "SELECT workspace_id FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            )
        };
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace, &["rust".into()])
            .unwrap();
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &[SelectedResolutionLanguage::new("rust", Language::Rust)],
                &[SelectedResolutionOverlayMask::removal("rust", removed)],
                &CancellationToken::default(),
            )
            .unwrap()
        else {
            panic!("complete selection");
        };
        selection
            .connection()
            .prepare(
                "SELECT DISTINCT member.rel_path FROM temp.selected_rust_unplaced_placements AS unplaced
                 JOIN main.resolution_unit_summary_members AS member
                   ON member.summary_id=unplaced.summary_id AND member.member_ordinal=unplaced.member_ordinal
                 ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// `host_b.rs` includes `shared.rs`, and so does the root. A removed host
    /// kills the files it alone includes, but a file that a live host still
    /// includes keeps its placement: the dead host's edge is not the file's.
    #[test]
    #[hardwon("#11752: removing one host's include unplaced a file the root still includes")]
    fn selected_rust_removed_include_host_unplaces_only_what_no_live_host_includes() {
        let fixture = |lib: &str| {
            InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"shared_include\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", lib)
                .file("src/host_b.rs", "include!(\"shared.rs\");\n")
                .file("src/shared.rs", "pub fn shared() {}\n")
                .build()
        };
        // The root includes shared.rs itself: only host_b.rs goes.
        assert_eq!(
            unplaced_files_after_removing(
                &fixture("include!(\"shared.rs\");\ninclude!(\"host_b.rs\");\n"),
                "src/host_b.rs"
            ),
            ["src/host_b.rs"]
        );
        // Control: host_b.rs alone includes shared.rs, so both go.
        assert_eq!(
            unplaced_files_after_removing(&fixture("include!(\"host_b.rs\");\n"), "src/host_b.rs"),
            ["src/host_b.rs", "src/shared.rs"]
        );
    }

    /// Whether the reverse set of `target` is `Complete` and holds no edge from
    /// `caller`: the answer the disk workspace refutes once `caller` is mounted.
    fn reverse_misses_caller(
        selected: &RustAnalyzer,
        target: &CodeUnit,
        caller: &brokk_bifrost_core::analyzer::model::ProjectFile,
    ) -> bool {
        match build_rust_selected_reference_index(selected, &CancellationToken::default()) {
            RustSelectedReferenceIndexOutcome::Ready(index) => {
                let answer = index.inverse_for(target);
                answer.completeness == EdgeCompleteness::Complete
                    && !answer.edges.iter().any(|edge| edge.site.file == *caller)
            }
            // A typed non-answer is also fail closed.
            RustSelectedReferenceIndexOutcome::Unavailable(_)
            | RustSelectedReferenceIndexOutcome::Stale(_)
            | RustSelectedReferenceIndexOutcome::StoreError(_) => false,
            RustSelectedReferenceIndexOutcome::Cancelled => panic!("cancelled"),
        }
    }

    #[test]
    #[hardwon(
        "#11682: reverse references missed a caller in a file the overlay mounted or re-activated"
    )]
    fn selected_rust_reverse_references_do_not_miss_a_caller_in_an_added_module() {
        for (case, lib_disk, lib_added, lib_control) in [
            (
                "re-activated",
                "pub fn top() {}\n#[cfg(any())] mod caller;\n",
                "pub fn top() {}\nmod caller;\n",
                "pub fn top() {}\n// edited\n#[cfg(any())] mod caller;\n",
            ),
            (
                "orphan on disk",
                "pub fn top() {}\n",
                "pub fn top() {}\nmod caller;\n",
                "pub fn top() {}\n// edited\n",
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"added_reverse\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", lib_disk)
                .file("src/caller.rs", "pub fn call() { crate::top(); }\n")
                .build();
            let disk = RustAnalyzer::new(fixture.project_dyn());
            let target = disk
                .all_declarations()
                .find(|unit| unit.identifier() == "top")
                .expect("disk target");
            let caller = fixture.file("src/caller.rs");
            // A file that no edge mounts is in no crate: Complete with no caller is right.
            let control = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib_control)]);
            assert!(
                reverse_misses_caller(&control, &target, &caller),
                "{case}: an unmounted caller is correctly absent from a complete set"
            );
            let added = overlay_selected(&fixture, &disk, &[("src/lib.rs", lib_added)]);
            assert!(
                !reverse_misses_caller(&added, &target, &caller),
                "{case}: the overlay mounts the caller, yet the reverse set is complete without it"
            );
        }
    }

    #[test]
    #[hardwon("#11682: package_contains denied a file an overlay mounted")]
    fn selected_rust_package_contains_is_incomplete_for_an_added_edge_target() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_package_member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn root() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let selected = overlay_selected(
            &fixture,
            &disk,
            &[
                ("src/lib.rs", "include!(\"foo.rs\");\npub fn root() {}\n"),
                ("src/foo.rs", "pub fn added() {}\n"),
                ("src/orphan.rs", "pub fn orphan() {}\n"),
            ],
        );
        let _scope = AnalyzerQueryScope::new(&selected);

        let added = selected
            .package_view()
            .contains(&fixture.file("src/foo.rs"), None)
            .expect("added target membership");
        assert!(!added.value, "new file has no persisted package row");
        assert!(!added.complete, "the overlay edge makes absence unknown");

        let orphan = selected
            .package_view()
            .contains(&fixture.file("src/orphan.rs"), None)
            .expect("orphan membership");
        assert!(!orphan.value, "orphan has no package membership");
        assert!(orphan.complete, "no overlay edge targets the orphan");
    }

    /// A file included inside an inline module belongs to that inline module,
    /// whose container has no opening file of its own. A `mod foo;` added to
    /// such a file must still be an added edge: with its directories unknown
    /// the edge keeps a NULL target, and with the host's directories known the
    /// target files are named by the walk's rule (the including file's module
    /// directory plus the inline chain).
    #[test]
    #[hardwon(
        "#11682: a mod added in a file included inside an inline module produced no added edge"
    )]
    fn selected_rust_mod_added_in_a_file_included_in_an_inline_module_is_an_added_edge() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_in_included\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "mod inl { include!(\"d.rs\"); }\nmod user;\n")
            .file("src/d.rs", "pub fn d() {}\n")
            .file("src/user.rs", "pub fn call() { crate::inl::foo::x(); }\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let user = "pub fn call() { crate::inl::foo::x(); }\n";
        let selected = overlay_selected(
            &fixture,
            &disk,
            &[
                ("src/d.rs", "mod foo;\npub fn d() {}\n"),
                ("src/inl/foo.rs", "pub fn x() {}\n"),
            ],
        );
        let result = overlay_lookup(&selected, &fixture, "src/user.rs", user, "x");
        eprintln!("added in included-in-inline: {result:?}");
        assert!(
            !complete_miss(&result),
            "the included file mounts crate::inl::foo, so the lookup is not a proven absence: {result:?}"
        );
        let _scope = AnalyzerQueryScope::new(&selected);
        let contains = selected
            .package_view()
            .contains(&fixture.file("src/inl/foo.rs"), None)
            .expect("membership");
        assert!(!contains.value && !contains.complete, "{contains:?}");
    }

    /// The inline step of the directory derivation matches a placement to its own
    /// declaration by scope identity: one file can declare same-named inline
    /// modules under different parents with different `#[path]` values, and only
    /// the including module's directory is a candidate.
    #[test]
    #[hardwon(
        "#11682: same-named inline modules in one file under different parents leaked each other's #[path] into an added edge's candidates"
    )]
    fn selected_rust_added_mod_in_an_inline_module_uses_only_its_own_declaration_path() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"same_named_inline\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "mod a {\n    #[path = \"pa\"]\n    mod common { include!(\"d.rs\"); }\n}\n\
                 mod b {\n    #[path = \"pb\"]\n    mod common {}\n}\n",
            )
            .file("src/d.rs", "pub fn d() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let selected = overlay_selected(
            &fixture,
            &disk,
            &[
                ("src/d.rs", "mod foo;\npub fn d() {}\n"),
                ("src/a/pa/foo.rs", "pub fn x() {}\n"),
                ("src/a/pb/foo.rs", "pub fn y() {}\n"),
                ("src/b/pb/foo.rs", "pub fn z() {}\n"),
            ],
        );
        let _scope = AnalyzerQueryScope::new(&selected);
        let contains = |rel: &str| {
            let answer = selected
                .package_view()
                .contains(&fixture.file(rel), None)
                .expect("membership");
            assert!(!answer.value, "{rel}: no persisted package row");
            answer.complete
        };
        assert!(
            !contains("src/a/pa/foo.rs"),
            "the including module's own directory"
        );
        assert!(
            contains("src/a/pb/foo.rs"),
            "the other `common`'s #[path] is not a candidate"
        );
        assert!(
            contains("src/b/pb/foo.rs"),
            "nor is a file below the other parent"
        );
    }

    /// `contains` reads the added-edge relation directly and records no read of
    /// it. That is safe because every reuse of its answer is bound to one
    /// selection: the request memo is replaced at each outermost query scope
    /// (`RustRouteRequestMemo`), the engine caches only the unit-row derivations
    /// that `contains` composes with a fresh read of the relation (an overlay
    /// authority retains no derivation: `derivation_host/authority.rs`
    /// `retention_refusal`), and a recorded derivation read cannot be replayed
    /// against an overlay head (`AnalyzerDerivations::replay` answers
    /// `Missing`, which `read_verification.rs` turns into
    /// `ReverseDependencyEvidenceMissing`).
    /// This test follows the sequence the review asked about: the target is
    /// queried while absent from every edge, then another file gains the edge,
    /// on the same long-lived analyzer family, and the answer matches a fresh
    /// analyzer's; the negative recorded first must not replay as unchanged.
    #[test]
    fn selected_rust_package_contains_follows_an_edge_another_file_gains_later() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::read_ledger::{
            LookupKind, LookupQuestion, ReadKey, ReadLedger,
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_package_replay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn root() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let foo = ("src/foo.rs", "pub fn foo() {}\n");
        let edge = ("src/lib.rs", "mod foo;\npub fn root() {}\n");
        let unmounted = overlay_selected(&fixture, &disk, &[foo]);
        let mounted = overlay_selected(&fixture, &disk, &[edge, foo]);
        let target = fixture.file("src/foo.rs");
        let ledger = Arc::new(ReadLedger::new());
        let first = {
            let _scope = AnalyzerQueryScope::with_read_ledger(&unmounted, ledger.clone());
            unmounted.package_view().contains(&target, None).unwrap()
        };
        assert!(
            !first.value && first.complete,
            "no edge reaches foo.rs: {first:?}"
        );
        // The same family, later: lib.rs gains `mod foo;`.
        let later = {
            let _scope = AnalyzerQueryScope::new(&mounted);
            mounted.package_view().contains(&target, None).unwrap()
        };
        let fresh_disk = RustAnalyzer::new(fixture.project_dyn());
        let fresh = overlay_selected(&fixture, &fresh_disk, &[edge, foo]);
        let from_scratch = {
            let _scope = AnalyzerQueryScope::new(&fresh);
            fresh.package_view().contains(&target, None).unwrap()
        };
        assert!(
            !later.complete,
            "the added edge makes absence unknown: {later:?}"
        );
        assert_eq!(
            (later.value, later.complete),
            (from_scratch.value, from_scratch.complete),
            "incremental and from-scratch answers agree"
        );
        // The negative recorded first names the file-units derivation; the overlay
        // head cannot replay it, so a consumer that recorded it is invalidated.
        let (kind, question, digest) = ledger
            .keys()
            .into_iter()
            .find_map(|read| match read {
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(kind),
                    question: LookupQuestion::Derivation(question),
                    digest,
                } if kind.0 == "derivation:rust_file_units:v1" => Some((kind, question, digest)),
                _ => None,
            })
            .expect("the negative records the file-units derivation");
        let replayed = IAnalyzer::derivations(&mounted)
            .expect("derivation host")
            .replay(&mounted, kind, &question);
        assert_ne!(
            replayed,
            brokk_bifrost_analysis::analyzer::derivation_host::ReplayResult::Identity(
                brokk_bifrost_semantic::analyzer::semantic::derivation::OutputIdentity(digest)
            ),
            "an overlay head must not replay the recorded negative as unchanged"
        );
    }

    /// An added `mod x;` has no target file in any persisted row either, so the
    /// fill names each file it can mount by the module walk's own path rule:
    /// `x.rs` and `x/mod.rs` below the declaring module's directory, or the
    /// `#[path]` value below the declaring file's directory.
    #[test]
    #[hardwon(
        "#11682: package membership of a file mounted by an overlay-added `mod x;` was a complete negative"
    )]
    fn selected_rust_package_contains_is_incomplete_for_an_added_module_edge_target() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"added_package_module\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "mod api;\nmod nested;\npub fn root() {}\n")
            .file("src/api.rs", "pub fn api() {}\n")
            .file("src/nested/mod.rs", "pub fn nested() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let selected = overlay_selected(
            &fixture,
            &disk,
            &[
                (
                    "src/lib.rs",
                    "mod api;\nmod nested;\nmod foo;\n#[path = \"x/y.rs\"]\nmod z;\npub fn root() {}\n",
                ),
                // A file module (`api.rs`) and a `mod.rs` module both open their
                // children below their own module directory.
                ("src/api.rs", "mod child;\npub fn api() {}\n"),
                ("src/nested/mod.rs", "mod inner;\npub fn nested() {}\n"),
                ("src/foo.rs", "pub fn foo() {}\n"),
                ("src/x/y.rs", "pub fn y() {}\n"),
                ("src/api/child.rs", "pub fn child() {}\n"),
                ("src/nested/inner.rs", "pub fn inner() {}\n"),
                ("src/orphan.rs", "pub fn orphan() {}\n"),
                // `#[path]` replaces the name rule: `z.rs` is not a candidate.
                ("src/z.rs", "pub fn z() {}\n"),
            ],
        );
        let _scope = AnalyzerQueryScope::new(&selected);
        let contains = |rel: &str| {
            let answer = selected
                .package_view()
                .contains(&fixture.file(rel), None)
                .expect("membership");
            assert!(!answer.value, "{rel}: no persisted package row");
            answer.complete
        };
        for mounted in [
            "src/foo.rs",
            "src/foo/mod.rs",
            "src/x/y.rs",
            "src/api/child.rs",
            "src/api/child/mod.rs",
            "src/nested/inner.rs",
            "src/nested/inner/mod.rs",
        ] {
            assert!(!contains(mounted), "{mounted}: an added `mod` can mount it");
        }
        for unmounted in ["src/orphan.rs", "src/z.rs", "src/api/orphan.rs"] {
            assert!(
                contains(unmounted),
                "{unmounted}: no added edge can mount it"
            );
        }
    }
}
