#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::{ProcedureHandle, SemanticWork};

    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;
    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::read_verification::ChangedFacts;

    use brokk_bifrost_analysis::analyzer::semantic::invalidation::DerivedArtifactId;

    use brokk_bifrost_analysis::analyzer::read_verification::HeadInputs;

    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::IndexFamily;

    use brokk_bifrost_analysis::analyzer::invalidation::InvalidationReason;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupKind;

    use brokk_bifrost_analysis::analyzer::read_verification::LookupMemo;

    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupQuestion;

    use brokk_bifrost_analysis::analyzer::read_verification::LookupReplayLimits;

    use brokk_bifrost_analysis::analyzer::read_verification::NoSummaryAnswers;

    use brokk_bifrost_analysis::analyzer::read_verification::ProcedureDispatchReadCallError;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::ReadKey;

    use brokk_bifrost_analysis::analyzer::read_verification::ReadVerdict;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_analysis::analyzer::read_verification::procedure_dispatch_read_call;

    use brokk_bifrost_analysis::analyzer::read_verification::verify_procedure_dispatch_read;

    use brokk_bifrost_analysis::analyzer::read_verification::verify_read_set;

    use brokk_bifrost_analysis::analyzer::read_verification::verify_read_set_for_artifact;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::ClassIdentity;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::DispatchHint;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::DispatchHintCallSiteKey;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::DispatchHintSet;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::DispatchHints;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::MemberDeclaration;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::SourceSite;

    use brokk_bifrost_analysis::analyzer::semantic::type_flow::SourceSiteKind;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::WorkspaceIcfgProvider;
    use brokk_bifrost_test_macros::hardwon;
    fn workspace(alpha: &str) -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::TypeScript)
            .file("src/alpha.ts", alpha)
            .file("src/beta.ts", "export function beta() {\n  return 2;\n}\n")
            .build()
    }
    const ORIGINAL: &str = "export function alpha() {\n  return 1;\n}\n";
    fn wrapper_procedure(
        project: &crate::inline_project::BuiltInlineTestProject,
        analyzer: &WorkspaceAnalyzer,
    ) -> ProcedureHandle {
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &project.file("src/main.ts"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("wrapper")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("wrapper procedure")
    }
    fn dispatch_read(
        project: &crate::inline_project::BuiltInlineTestProject,
        analyzer: &WorkspaceAnalyzer,
    ) -> (ReadKey, Range) {
        let cancellation = CancellationToken::default();
        let procedure = wrapper_procedure(project, analyzer);
        let call = procedure
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| procedure.call_site_handle(call.id))
            .expect("wrapper call");
        let range = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::exact_call_range(&call)
            .expect("exact wrapper call range");
        let mut dispatch_budget = SemanticBudget::default();
        let outcome = analyzer
            .semantic_oracle_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("wrapper dispatch");
        let brokk_bifrost_analysis::analyzer::semantic::DispatchReadAttribution::Attributed(read) =
            brokk_bifrost_analysis::analyzer::semantic::icfg::dispatch_read_attribution(
                &call, &outcome,
            )
        else {
            panic!("one exact authored call must have a replayable read")
        };
        (read, range)
    }
    #[test]
    fn procedure_dispatch_read_survives_a_preceding_sibling_edit() {
        let base = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function sibling() { return 1; }\n",
                    "function leaf(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return leaf(value); }\n",
                ),
            )
            .build();
        let head = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function sibling() { return 1000000; }\n",
                    "function leaf(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return leaf(value); }\n",
                ),
            )
            .build();
        let base_analyzer = base.workspace_analyzer(AnalyzerConfig::default());
        let head_analyzer = head.workspace_analyzer(AnalyzerConfig::default());
        let (read, base_range) = dispatch_read(&base, &base_analyzer);
        let (head_read, head_range) = dispatch_read(&head, &head_analyzer);

        assert_ne!(base.root(), head.root(), "the mount must not enter the key");
        assert_ne!(
            base_range, head_range,
            "the absolute call moved with its sibling"
        );
        assert_eq!(read, head_read, "question and answer are procedure-local");
        assert!(matches!(
            &read,
            ReadKey::Lookup {
                kind: LookupKind::ProcedureDispatch,
                question: LookupQuestion::ProcedureCallSite { .. },
                ..
            }
        ));

        let changed = ChangedFacts::between(&base_analyzer, &head_analyzer);
        assert_eq!(
            verify_read_set(
                &head_analyzer,
                &changed,
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                std::slice::from_ref(&read),
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            ),
            ReadVerdict::Unchanged
        );
    }
    #[test]
    fn structured_procedure_dispatch_read_address_preserves_interruptions() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function leaf(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return leaf(value); }\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let (read, _) = dispatch_read(&project, &analyzer);
        let procedure = wrapper_procedure(&project, &analyzer);

        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let (call, expected) = procedure_dispatch_read_call(
            &procedure,
            &read,
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .expect("address resolution stays within budget")
        .expect("the read names the live wrapper call");
        assert_eq!(call.procedure(), &procedure);
        let ReadKey::Lookup { digest, .. } = &read else {
            panic!("dispatch attribution is a lookup read")
        };
        assert_eq!(expected, *digest);

        let mut limits = SemanticWork::default_limits();
        limits.call_sites = 1;
        let mut exhausted = SemanticBudget::new(limits).expect("valid tight budget");
        exhausted.charge_work(SemanticWork {
            call_sites: 1,
            ..SemanticWork::default()
        });
        assert!(
            procedure_dispatch_read_call(
                &procedure,
                &read,
                &mut SemanticRequest::new(&mut exhausted, &cancellation),
            )
            .expect("existing-call traversal never refuses")
            .is_some()
        );
        assert!(exhausted.root_work_peak().call_sites > limits.call_sites);
        assert!(exhausted.first_refusal().is_none());

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let mut cancelled_budget = SemanticBudget::default();
        assert_eq!(
            procedure_dispatch_read_call(
                &procedure,
                &read,
                &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
            ),
            Err(ProcedureDispatchReadCallError::Cancelled)
        );
    }
    #[test]
    fn exact_procedure_dispatch_replay_uses_the_active_receiver_hints() {
        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "hinted.py",
                concat!(
                    "class A:\n",
                    "    def foo(self):\n",
                    "        return 1\n",
                    "\n",
                    "def caller(x):\n",
                    "    return x.foo()\n",
                ),
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("hinted.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Python semantic materialization")
            .available_value()
            .cloned()
            .expect("Python semantic artifact");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = procedure
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| procedure.call_site_handle(call.id))
            .expect("dynamic member call");
        let declarations = workspace.analyzer().get_declarations(&file);
        let class = declarations
            .iter()
            .find(|declaration| declaration.is_class())
            .cloned()
            .expect("class A declaration");
        let member = declarations
            .into_iter()
            .find(|declaration| declaration.terminal_name() == "foo")
            .expect("A.foo declaration");
        let mapping = call
            .procedure()
            .semantics()
            .source_mapping(
                call.procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("live call")
                    .source,
            )
            .expect("call source mapping");
        let hints = DispatchHints::new(vec![DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(call.procedure(), call.id()),
            vec![DispatchHint::new(
                MemberDeclaration::Workspace(member),
                ClassIdentity::Workspace(class),
                SourceSite {
                    file,
                    span: mapping.locator.anchor().span(),
                    kind: SourceSiteKind::DeclaredParameter,
                },
            )],
            true,
            brokk_bifrost_analysis::analyzer::semantic::type_flow::DispatchHintProof::Proven,
        )]);
        let hinted = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &workspace, None, hints,
        );
        let mut attribution_budget = SemanticBudget::default();
        let hinted_outcome = hinted
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut attribution_budget, &cancellation),
            )
            .expect("hinted dispatch");
        let brokk_bifrost_analysis::analyzer::semantic::DispatchReadAttribution::Attributed(
            hinted_read,
        ) = brokk_bifrost_analysis::analyzer::semantic::icfg::dispatch_read_attribution(
            &call,
            &hinted_outcome,
        )
        else {
            panic!("the hinted call must have an exact dispatch read")
        };

        let mut hinted_replay_budget = SemanticBudget::default();
        assert!(verify_procedure_dispatch_read(
            &workspace,
            hinted.oracle(),
            &hinted_read,
            &mut SemanticRequest::new(&mut hinted_replay_budget, &cancellation),
        ));

        let unhinted = workspace.semantic_oracle_provider();
        let mut unhinted_replay_budget = SemanticBudget::default();
        assert!(
            !verify_procedure_dispatch_read(
                &workspace,
                &unhinted,
                &hinted_read,
                &mut SemanticRequest::new(&mut unhinted_replay_budget, &cancellation),
            ),
            "a default-provider replay must not certify a hint-dependent read"
        );
    }
    #[test]
    fn procedure_dispatch_read_rotates_for_a_different_logical_target() {
        let base = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function leaf(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return leaf(value); }\n",
                ),
            )
            .build();
        let head = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function twig(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return twig(value); }\n",
                ),
            )
            .build();
        let base_analyzer = base.workspace_analyzer(AnalyzerConfig::default());
        let head_analyzer = head.workspace_analyzer(AnalyzerConfig::default());
        let (read, _) = dispatch_read(&base, &base_analyzer);
        let (head_read, _) = dispatch_read(&head, &head_analyzer);

        let (
            ReadKey::Lookup {
                question,
                digest: base_answer,
                ..
            },
            ReadKey::Lookup {
                question: head_question,
                digest: head_answer,
                ..
            },
        ) = (&read, &head_read)
        else {
            panic!("dispatch attribution must be a lookup")
        };
        assert_eq!(
            question, head_question,
            "the call address itself did not move"
        );
        assert_ne!(base_answer, head_answer, "the target lineage must move");

        let changed = ChangedFacts::between(&base_analyzer, &head_analyzer);
        let verdict = verify_read_set(
            &head_analyzer,
            &changed,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            std::slice::from_ref(&read),
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );
        assert!(matches!(
            verdict.changed().map(|changed| &changed.reason),
            Some(InvalidationReason::DependencyFingerprintChanged { .. })
        ));
    }
    #[test]
    fn procedure_dispatch_replay_fails_closed_when_its_exact_call_disappears_or_exceeds_budget() {
        let base = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function leaf(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return leaf(value); }\n",
                ),
            )
            .build();
        let removed = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function leaf(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return value; }\n",
                ),
            )
            .build();
        let base_analyzer = base.workspace_analyzer(AnalyzerConfig::default());
        let removed_analyzer = removed.workspace_analyzer(AnalyzerConfig::default());
        let (read, _) = dispatch_read(&base, &base_analyzer);
        let removed_facts = ChangedFacts::between(&base_analyzer, &removed_analyzer);
        let removed_verdict = verify_read_set(
            &removed_analyzer,
            &removed_facts,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            std::slice::from_ref(&read),
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );
        assert!(matches!(
            removed_verdict.changed().map(|changed| &changed.reason),
            Some(InvalidationReason::ReverseDependencyEvidenceMissing { .. })
        ));

        let unchanged = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "src/main.ts",
                concat!(
                    "function leaf(value: number) { return value; }\n",
                    "export function wrapper(value: number) { return leaf(value); }\n",
                ),
            )
            .build();
        let unchanged_analyzer = unchanged.workspace_analyzer(AnalyzerConfig::default());
        let unchanged_facts = ChangedFacts::between(&base_analyzer, &unchanged_analyzer);
        let mut limits = LookupReplayLimits::default();
        limits.semantic.procedures = 1;
        let budgeted_verdict = verify_read_set(
            &unchanged_analyzer,
            &unchanged_facts,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &[read],
            limits,
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );
        assert!(matches!(
            budgeted_verdict.changed().map(|changed| &changed.reason),
            Some(InvalidationReason::ReverseDependencyEvidenceMissing { .. })
        ));
    }
    #[test]
    fn changing_a_canonical_import_invalidates_both_module_keys() {
        let base = workspace(
            "import { value } from 'old_library';\nexport function alpha() { return value; }\n",
        );
        let head = workspace(
            "import { value } from 'new_library';\nexport function alpha() { return value; }\n",
        );
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );

        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        for module in ["old_library", "new_library"] {
            assert!(
                changed.contains(IndexFamily::ImportPathSegment, module.as_bytes()),
                "changed canonical import must invalidate module {module}"
            );
        }
    }
    #[test]
    fn a_rename_changes_the_names_of_both_the_old_and_the_new_blob() {
        let base = workspace(ORIGINAL);
        let head = workspace("export function renamed() {\n  return 1;\n}\n");
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );

        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        assert!(changed.path_changed(Language::TypeScript, "src/alpha.ts"));
        assert!(!changed.path_changed(Language::TypeScript, "src/beta.ts"));
        for name in ["alpha", "renamed"] {
            assert!(
                changed.contains(IndexFamily::DefinitionExact, name.as_bytes()),
                "the exact name `{name}` must be in the changed set"
            );
            assert!(
                changed.contains(IndexFamily::DefinitionNormalizedTail, name.as_bytes()),
                "the normalized tail `{name}` must be in the changed set"
            );
            assert!(
                changed.contains(IndexFamily::DefinitionIdentifier, name.as_bytes()),
                "the identifier `{name}` must be in the changed set"
            );
        }
        assert!(
            !changed.contains(IndexFamily::DefinitionExact, b"beta"),
            "an untouched file's names must stay out of the changed set"
        );
    }
    /// A probe that found no file at a path is verified by the head's own path
    /// map: still nothing there is still the same answer, and a file there now
    /// is the content change that answers it.
    #[test]
    fn an_absent_path_that_the_head_fills_invalidates_the_unit_that_probed_it() {
        let base = workspace(ORIGINAL);
        let base_analyzer = base.workspace_analyzer(AnalyzerConfig::default());
        let keys = [ReadKey::path_absent(Language::TypeScript, "src/gamma.ts")];
        let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();

        let unchanged_head = workspace(ORIGINAL);
        let unchanged_analyzer = unchanged_head.workspace_analyzer(AnalyzerConfig::default());
        let unchanged = ChangedFacts::between(&base_analyzer, &unchanged_analyzer);
        assert_eq!(
            verify_read_set(
                &unchanged_analyzer,
                &unchanged,
                &inputs,
                &keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            ),
            ReadVerdict::Unchanged,
            "a head that still has no file there answers the probe the same way"
        );

        let filled_head = InlineTestProject::with_language(Language::TypeScript)
            .file("src/alpha.ts", ORIGINAL)
            .file("src/beta.ts", "export function beta() {\n  return 2;\n}\n")
            .file(
                "src/gamma.ts",
                "export function gamma() {\n  return 3;\n}\n",
            )
            .build();
        let filled_analyzer = filled_head.workspace_analyzer(AnalyzerConfig::default());
        let filled = ChangedFacts::between(&base_analyzer, &filled_analyzer);
        let verdict = verify_read_set(
            &filled_analyzer,
            &filled,
            &inputs,
            &keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );
        let changed = verdict
            .changed()
            .expect("a path the head now has invalidates the probe that found nothing there");
        assert_eq!(
            (changed.reason.stable_label(), changed.key.stable_label()),
            ("input_content_changed", "path_absent"),
            "unexpected verdict {changed:#?}"
        );
    }
    #[test]
    fn explicit_artifact_identity_names_the_changed_read_verdict() {
        let base = workspace(ORIGINAL);
        let head = workspace(ORIGINAL);
        let base_analyzer = base.workspace_analyzer(AnalyzerConfig::default());
        let head_analyzer = head.workspace_analyzer(AnalyzerConfig::default());
        let changed = ChangedFacts::between(&base_analyzer, &head_analyzer);
        let recorded_epoch = StableDigest::sha256(b"recorded-epoch");
        let head_epoch = StableDigest::sha256(b"head-epoch");
        let artifact = DerivedArtifactId::procedure_summary(StableDigest::sha256(b"summary"));
        let inputs = HeadInputs {
            epoch: head_epoch,
            ..brokk_bifrost_analysis::test_support::read_ledger_test_inputs()
        };

        let verdict = verify_read_set_for_artifact(
            artifact,
            &head_analyzer,
            &changed,
            &inputs,
            &[ReadKey::Epoch(recorded_epoch)],
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );

        let changed = verdict.changed().expect("the recorded epoch moved");
        assert_eq!(changed.reason.artifact(), artifact);
        assert!(matches!(
            changed.reason,
            InvalidationReason::EpochChanged { before, after, .. }
                if before == recorded_epoch && after == head_epoch
        ));
    }
    #[test]
    fn a_comment_only_edit_changes_the_blob_and_no_index_key() {
        let base = workspace(ORIGINAL);
        let head = workspace("// a note\nexport function alpha() {\n  return 1;\n}\n");
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );

        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        assert!(
            changed.path_changed(Language::TypeScript, "src/alpha.ts"),
            "the blob moved, so the path is changed"
        );
        // Every key the edited blob publishes it published before: the two
        // sides contribute the same names, so the changed-key set holds them
        // -- but no key of the *other* file enters, and the names are the same
        // ones on both sides rather than a new spelling.
        assert!(changed.contains(IndexFamily::DefinitionExact, b"alpha"));
        assert!(
            !changed.contains(IndexFamily::DefinitionExact, b"beta"),
            "an untouched file's names must stay out of the changed set"
        );
    }
    #[test]
    #[hardwon("cdbc6503162c: new declarations failed to invalidate negative name lookups")]
    fn an_added_file_contributes_every_definition_name_key_it_declares() {
        let base = workspace(ORIGINAL);
        let head = InlineTestProject::with_language(Language::TypeScript)
            .file("src/alpha.ts", ORIGINAL)
            .file("src/beta.ts", "export function beta() {\n  return 2;\n}\n")
            .file(
                "src/gamma.ts",
                "export function gamma() {\n  return 3;\n}\n",
            )
            .build();
        let changed = ChangedFacts::between(
            &base.workspace_analyzer(AnalyzerConfig::default()),
            &head.workspace_analyzer(AnalyzerConfig::default()),
        );

        assert!(changed.is_complete(), "{:?}", changed.incompleteness());
        assert!(changed.path_changed(Language::TypeScript, "src/gamma.ts"));
        for family in [
            IndexFamily::DefinitionExact,
            IndexFamily::DefinitionNormalizedTail,
            IndexFamily::DefinitionIdentifier,
        ] {
            assert!(
                changed.contains(family, b"gamma"),
                "an added declaration must publish its `{}` key",
                family.stable_label()
            );
        }
        assert!(
            !changed.contains(IndexFamily::DefinitionIdentifier, b"beta"),
            "an untouched file's names must stay out of the changed set"
        );
    }
}
