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
        assert_eq!(
            consumer.reference_kind,
            Some(brokk_bifrost_core::analyzer::usages::model::ReferenceKind::TypeReference)
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
}
