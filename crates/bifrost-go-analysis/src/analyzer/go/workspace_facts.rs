//! Position-free certificates for Go's generation authorities.
use super::GoAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic::StableDigest;
use brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs;
use brokk_bifrost_analysis::analyzer::{FactSubject, IAnalyzer, Language, WorkspaceFactFamily};

pub(super) fn profile_answer(value: Option<[u8; 32]>) -> StableDigest {
    let mut hash =
        brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(b"go-build-profile-v1");
    hash.value(&[u8::from(value.is_some())]);
    if let Some(value) = value {
        hash.value(&value);
    }
    StableDigest::from_array(hash.finish())
}

// Failure text can contain checkout paths and source positions. It cannot
// certify a reusable answer; only the successful, empty state gets a fact.
pub(super) fn selection_error_answer(error: &str) -> Option<StableDigest> {
    error
        .is_empty()
        .then(|| StableDigest::sha256(b"go-build-selection-ready-v1"))
}

pub(super) fn selection_input(name: &str, answer: StableDigest) -> AuthorityInputs<'static> {
    AuthorityInputs::Fact {
        language: Language::Go,
        subject: FactSubject::Named { name: name.into() },
        answer,
    }
}

pub(super) fn answer(
    analyzer: &dyn IAnalyzer,
    family: WorkspaceFactFamily,
    language: Language,
    subject: &FactSubject,
) -> Option<StableDigest> {
    if language != Language::Go {
        return None;
    }
    let go = brokk_bifrost_analysis::analyzer::resolve_analyzer::<GoAnalyzer>(analyzer)?;
    match (family, subject) {
        (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Named { name }) => go
            .workspace_indexes(subject.clone())
            .ok()
            .map(|indexes| StableDigest::from_array(indexes.hierarchy.read_answer(name))),
        (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Whole) => go
            .workspace_indexes(FactSubject::Whole)
            .ok()
            .map(|indexes| StableDigest::from_array(indexes.usage_answer)),
        (WorkspaceFactFamily::GoWorkspacePaths, FactSubject::Whole) => Some(
            StableDigest::from_array(go.workspace_path_index().read_answer()),
        ),
        (WorkspaceFactFamily::GoImportFacts, FactSubject::Whole) => Some(go.import_facts().answer),
        (WorkspaceFactFamily::GoReverseImports, FactSubject::Whole) => {
            go.reverse_import_index().answer
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::Named { name })
            if name.as_ref() == "profile" =>
        {
            Some(profile_answer(*go.profile_read()))
        }
        (WorkspaceFactFamily::GoBuildSelection, FactSubject::Named { name })
            if name.as_ref() == "error" =>
        {
            selection_error_answer(&go.selection_error_read())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{
        LookupKind, LookupQuestion, ReadKey, capture_query_reads,
    };
    use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_test_macros::hardwon;

    fn fixture(other: &str) -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file(
                "target.go",
                "package repro\ntype Target struct {}\nfunc (Target) Ping() {}\n",
            )
            .file("other.go", other)
            .build()
    }

    fn questions() -> Vec<(WorkspaceFactFamily, FactSubject)> {
        vec![
            (
                WorkspaceFactFamily::GoWorkspaceIndexes,
                FactSubject::Named {
                    name: "example.com/repro.Target".into(),
                },
            ),
            (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Whole),
            (WorkspaceFactFamily::GoWorkspacePaths, FactSubject::Whole),
            (WorkspaceFactFamily::GoImportFacts, FactSubject::Whole),
            (WorkspaceFactFamily::GoReverseImports, FactSubject::Whole),
            (
                WorkspaceFactFamily::GoBuildSelection,
                FactSubject::Named {
                    name: "profile".into(),
                },
            ),
            (
                WorkspaceFactFamily::GoBuildSelection,
                FactSubject::Named {
                    name: "error".into(),
                },
            ),
        ]
    }

    fn verify_fact(
        head: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        base: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        family: WorkspaceFactFamily,
        subject: FactSubject,
        recorded: StableDigest,
    ) -> brokk_bifrost_analysis::analyzer::ReadVerdict {
        use brokk_bifrost_analysis::analyzer::{
            ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
        };
        let key = ReadKey::lookup(
            LookupKind::WorkspaceFact,
            LookupQuestion::WorkspaceFact {
                family,
                language: Language::Go,
                subject,
            },
            recorded,
        );
        brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
            head,
            &ChangedFacts::between(base, head),
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &[key],
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
    }

    #[test]
    fn workspace_authorities_repeat_the_same_snapshot_answers() {
        let project = fixture("package repro\ntype Other interface { Missing() }\n");
        let go = GoAnalyzer::new(project.project_dyn());
        go.selection_error_write().clear();
        for (family, subject) in questions() {
            let first = answer(&go, family, Language::Go, &subject).expect("Go fact answer");
            assert_eq!(
                Some(first),
                answer(&go, family, Language::Go, &subject),
                "{family:?} {subject:?}"
            );
            for _ in 0..2 {
                let (_, reads) =
                    capture_query_reads(&go, || answer(&go, family, Language::Go, &subject));
                assert_eq!(reads.unattributed_reads(), 0);
                assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::Lookup { kind: LookupKind::WorkspaceFact, question: LookupQuestion::WorkspaceFact { family: recorded, subject: recorded_subject, .. }, digest: recorded_answer } if *recorded == family && *recorded_subject == subject && *recorded_answer == first)), "{family:?}: {:?}", reads.keys());
            }
        }
    }

    #[test]
    fn a_comment_above_declarations_preserves_workspace_authority_answers() {
        let project = fixture("package repro\ntype Other interface { Missing() }\n");
        let base = GoAnalyzer::new(project.project_dyn());
        base.selection_error_write().clear();
        let before = questions()
            .into_iter()
            .map(|(family, subject)| answer(&base, family, Language::Go, &subject))
            .collect::<Vec<_>>();
        project.file("other.go").write("// comment before the first declaration\npackage repro\ntype Other interface { Missing() }\n").unwrap();
        let head = GoAnalyzer::new(project.project_dyn());
        head.selection_error_write().clear();
        let after = questions()
            .into_iter()
            .map(|(family, subject)| answer(&head, family, Language::Go, &subject))
            .collect::<Vec<_>>();
        assert_eq!(before, after);
    }

    #[test]
    #[hardwon("#7496: a warm hierarchy answer ignored an unimported interface edit")]
    fn an_unimported_interface_edit_changes_the_hierarchy_certificate() {
        let project = fixture("package repro\ntype Other interface { Missing() }\n");
        let base = GoAnalyzer::new(project.project_dyn());
        let subject = FactSubject::Named {
            name: "example.com/repro.Target".into(),
        };
        let before = answer(
            &base,
            WorkspaceFactFamily::GoWorkspaceIndexes,
            Language::Go,
            &subject,
        )
        .unwrap();
        let base_workspace = project.workspace_analyzer(Default::default());
        assert_eq!(
            verify_fact(
                &base_workspace,
                &base_workspace,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                subject.clone(),
                before
            ),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
        project
            .file("other.go")
            .write("package repro\ntype Other interface { Ping() }\n")
            .unwrap();
        let head_workspace = project.workspace_analyzer(Default::default());
        assert_ne!(
            verify_fact(
                &head_workspace,
                &base_workspace,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                subject.clone(),
                before
            ),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
        let head = GoAnalyzer::new(project.project_dyn());
        assert_ne!(
            Some(before),
            answer(
                &head,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                Language::Go,
                &subject
            )
        );
    }

    #[test]
    fn an_unimported_package_edit_changes_complete_inventory_and_usage_answers() {
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file("target.go", "package repro\ntype Target struct {}\n")
            .file(
                "extra/other_test.go",
                "package extra\ntype Other struct {}\n",
            )
            .build();
        let base = GoAnalyzer::new(project.project_dyn());
        let subjects = [
            (WorkspaceFactFamily::GoWorkspacePaths, FactSubject::Whole),
            (WorkspaceFactFamily::GoImportFacts, FactSubject::Whole),
            (WorkspaceFactFamily::GoWorkspaceIndexes, FactSubject::Whole),
        ];
        let before = subjects
            .iter()
            .map(|(family, subject)| answer(&base, *family, Language::Go, subject).unwrap())
            .collect::<Vec<_>>();
        let base_workspace = project.workspace_analyzer(Default::default());
        project
            .file("extra/other_test.go")
            .write("package extra_test\ntype Other struct {}\n")
            .unwrap();
        let head_workspace = project.workspace_analyzer(Default::default());
        let head = GoAnalyzer::new(project.project_dyn());
        for ((family, subject), before) in subjects.iter().zip(before) {
            assert_ne!(
                verify_fact(
                    &head_workspace,
                    &base_workspace,
                    *family,
                    subject.clone(),
                    before
                ),
                brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged,
                "{family:?}"
            );
            assert_ne!(
                Some(before),
                answer(&head, *family, Language::Go, subject),
                "{family:?}"
            );
        }
    }

    #[test]
    fn an_unimported_importer_edit_changes_the_reverse_import_certificate() {
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file("target.go", "package repro\ntype Target struct {}\n")
            .file("other/other.go", "package other\n")
            .build();
        let base = project.workspace_analyzer(Default::default());
        let family = WorkspaceFactFamily::GoReverseImports;
        let subject = FactSubject::Whole;
        let before = answer(base.analyzer(), family, Language::Go, &subject).unwrap();
        assert_eq!(
            verify_fact(&base, &base, family, subject.clone(), before),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
        project
            .file("other/other.go")
            .write("package other\nimport \"example.com/repro\"\nvar value repro.Target\n")
            .unwrap();
        let head = project.workspace_analyzer(Default::default());
        let after = answer(head.analyzer(), family, Language::Go, &subject)
            .expect("the changed head has a complete reverse-import answer");
        assert_ne!(before, after);
        assert_ne!(
            verify_fact(&head, &base, family, subject, before),
            brokk_bifrost_analysis::analyzer::ReadVerdict::Unchanged
        );
    }

    #[test]
    fn selected_build_state_changes_its_own_named_answers() {
        let project = fixture("package repro\n");
        let go = GoAnalyzer::new(project.project_dyn());
        go.selection_error_write().clear();
        let profile = FactSubject::Named {
            name: "profile".into(),
        };
        let error = FactSubject::Named {
            name: "error".into(),
        };
        let before_profile = answer(
            &go,
            WorkspaceFactFamily::GoBuildSelection,
            Language::Go,
            &profile,
        )
        .unwrap();
        let before_error = answer(
            &go,
            WorkspaceFactFamily::GoBuildSelection,
            Language::Go,
            &error,
        )
        .unwrap();
        *go.profile_write() = Some([41; 32]);
        *go.selection_error_write() = "selected build refused".into();
        assert_ne!(
            Some(before_profile),
            answer(
                &go,
                WorkspaceFactFamily::GoBuildSelection,
                Language::Go,
                &profile
            )
        );
        let (failed, reads) = capture_query_reads(&go, || {
            answer(
                &go,
                WorkspaceFactFamily::GoBuildSelection,
                Language::Go,
                &error,
            )
        });
        assert!(
            failed.is_none(),
            "failure text has no position-free certificate: {before_error:?}"
        );
        assert!(reads.unattributed_reads() > 0);
    }

    #[test]
    #[hardwon(
        "#2445: cloning Go build-selection memos recorded answers during recording-view construction"
    )]
    fn copying_an_analyzer_does_not_consult_build_selection() {
        let project = fixture("package repro\n");
        let go = GoAnalyzer::new(project.project_dyn());
        *go.profile_write() = Some([41; 32]);
        *go.selection_error_write() = "selected build refused".into();
        let ((cloned, rebound), reads) = capture_query_reads(&go, || {
            (go.clone(), go.clone_with_project(project.project_dyn()))
        });
        assert!(reads.keys().is_empty(), "{:?}", reads.keys());
        assert_eq!(reads.unattributed_reads(), 0);
        for copy in [cloned, rebound] {
            assert_eq!(*copy.profile_read(), Some([41; 32]));
            assert_eq!(&*copy.selection_error_read(), "selected build refused");
            *copy.profile_write() = Some([42; 32]);
            *copy.selection_error_write() = "copy selection changed".into();
            assert_eq!(*go.profile_read(), Some([41; 32]));
            assert_eq!(&*go.selection_error_read(), "selected build refused");
        }
    }

    #[test]
    #[hardwon("#2445: Go workspace-index builds rejected correctly transported source reads")]
    fn workspace_index_worker_records_files_into_the_owners_capture() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::read_key_recorded_on_active_ledgers;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryScope};
        use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;
        use brokk_bifrost_go::graph::resolver::{GoGraphSource, build_go_workspace_indexes};

        let project = fixture("package repro\ntype Other interface { Ping() }\n");
        let go = GoAnalyzer::new(project.project_dyn());
        let file = project.file("target.go");
        let target = go
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "Target")
            .unwrap();
        let files = go.get_analyzed_files().into_iter().collect::<Vec<_>>();
        let memo = PoolSafeMemo::new();
        // Capture the actual builder's reads before the authority replaces
        // them with its answer Fact. The pool transports the owner's frame.
        let (indexes, reads) = capture_query_reads(&go, || {
            memo.get_or_try_build_on_dedicated_pool(|| {
                assert!(go.current_thread_read_ledger().is_none());
                let scope = AnalyzerQueryScope::new(&go);
                let source = GoGraphSource {
                    token: scope.token(),
                    index: &go,
                    imports: &go,
                    type_aliases: &go,
                    workspace_paths: &go.workspace_path_index(),
                    package_clauses: &go,
                    source_facts: &go,
                };
                let indexes = build_go_workspace_indexes(source, &files)?;
                let oid = go.inner.resolve_live_oid_for_file(&file).unwrap();
                assert!(read_key_recorded_on_active_ledgers(
                    &go,
                    &go.inner.file_read_key(&file, oid)
                ));
                assert!(scope.store_error().is_none());
                Ok::<_, brokk_bifrost_go::graph::resolver::GoGraphBuildError>(indexes)
            })
            .unwrap()
        });
        assert!(indexes.hierarchy.supports(&target));
        assert!(reads.keys().iter().any(
            |key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "target.go")
        ));
        assert_eq!(reads.unattributed_reads(), 0);
    }

    #[test]
    fn changed_module_receipts_cannot_certify_a_retained_generation() {
        let project = fixture("package repro\n");
        let retained = GoAnalyzer::new(project.project_dyn());
        let target = project.file("target.go");
        assert!(!retained.declarations(&target).is_empty());
        project
            .file("go.mod")
            .write("module example.com/changed\n\ngo 1.23\n")
            .unwrap();
        let head = GoAnalyzer::new(project.project_dyn());
        assert!(!head.declarations(&target).is_empty());
        let (units, reads) = capture_query_reads(&retained, || retained.declarations(&target));
        assert!(!units.is_empty());
        assert!(
            reads.unattributed_reads() > 0,
            "new raw probes do not describe the retained generation's cached identities"
        );
    }

    #[test]
    #[hardwon("#7496: restored module inputs hid a source memo fill under another namespace")]
    fn restored_module_inputs_do_not_certify_a_mismounted_cache_fill() {
        use super::super::source_storage::CanonicalGoSourceFacts;
        let project = fixture("package repro\n");
        let mut retained = GoAnalyzer::new(project.project_dyn());
        let target = project.file("target.go");
        retained.inner.clear_retained_file_states_for_test();
        project
            .file("go.mod")
            .write("module example.com/changed\n\ngo 1.23\n")
            .unwrap();
        let changed = GoAnalyzer::new(project.project_dyn());
        assert!(!changed.declarations(&target).is_empty());
        let (facts, reads) = capture_query_reads(&retained, || {
            retained
                .inner
                .canonical_go_source_facts(&target, &retained.memo_caches.source_facts)
        });
        assert!(facts.is_some());
        assert!(reads.unattributed_reads() > 0);
        project
            .file("go.mod")
            .write("module example.com/repro\n\ngo 1.23\n")
            .unwrap();
        let restored = GoAnalyzer::new(project.project_dyn());
        assert!(!restored.declarations(&target).is_empty());
        let (facts, reads) = capture_query_reads(&retained, || {
            retained
                .inner
                .canonical_go_source_facts(&target, &retained.memo_caches.source_facts)
        });
        let cached = facts.unwrap();
        let fresh = restored
            .inner
            .canonical_go_source_facts(&target, &restored.memo_caches.source_facts)
            .unwrap();
        assert!(
            cached.declaration_units == fresh.declaration_units || reads.unattributed_reads() > 0,
            "cached identities were mounted from different inputs: cached {:?}, fresh {:?}",
            cached.declaration_units,
            fresh.declaration_units
        );
    }

    #[test]
    fn an_unready_hierarchy_inventory_refuses_reuse() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module \"invalid path\"\n")
            .file("target.go", "package repro\ntype Target struct {}\n")
            .build();
        let go = GoAnalyzer::new(project.project_dyn());
        let (value, reads) = capture_query_reads(&go, || {
            answer(
                &go,
                WorkspaceFactFamily::GoWorkspaceIndexes,
                Language::Go,
                &FactSubject::Named {
                    name: "repro.Target".into(),
                },
            )
        });
        assert!(value.is_none());
        assert!(reads.unattributed_reads() > 0);
    }

    #[test]
    fn warm_import_memos_replay_module_files_and_absent_probes() {
        let project = InlineTestProject::with_language(Language::Go)
            .with_git()
            .file("go.mod", "module example.com/repro\n\ngo 1.23\n")
            .file("pkg/target.go", "package pkg\ntype Target struct {}\n")
            .file(
                "main.go",
                "package main\nimport \"example.com/repro/pkg\"\nvar value pkg.Target\n",
            )
            .build();
        let go = GoAnalyzer::new(project.project_dyn());
        let main = project.file("main.go");
        let target = project.file("pkg/target.go");
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&go, || {
                let units = go.imported_code_units_of(&main);
                assert!(!units.is_empty());
                go.referencing_files_of(&target)
            });
            assert_eq!(reads.unattributed_reads(), 0);
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "go.mod")), "{:?}", reads.keys());
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "pkg/go.mod")), "{:?}", reads.keys());
        }
        // A retained source-fact hit also uses the identity-input hook.
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&go, || go.declarations(&target));
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "pkg/go.mod")));
        }
    }
}
