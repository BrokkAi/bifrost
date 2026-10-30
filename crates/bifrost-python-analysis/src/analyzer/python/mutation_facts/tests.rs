use super::*;
use crate::analyzer::python::PythonAnalyzer;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::read_verification::{NoSummaryAnswers, replay_lookup};
use brokk_bifrost_analysis::analyzer::{
    LookupKind, LookupQuestion, ReadKey, capture_query_reads, resolve_analyzer,
};

fn module_read(analyzer: &dyn IAnalyzer) -> bool {
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer).unwrap();
    python.cached_module_member_mutation_free("pkg", "value", || {
        module_member_mutation_free(analyzer, "pkg", "value", 200_000, &|| true)
    })
}

fn class_read(analyzer: &dyn IAnalyzer) -> bool {
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer).unwrap();
    python.cached_class_member_mutation_free(&[vec!["pkg.C"]], "run", || {
        class_member_mutation_free(analyzer, &["pkg.C".into()], "run")
    })
}

fn fact(
    source: &str,
    read: fn(&dyn IAnalyzer) -> bool,
    family: WorkspaceFactFamily,
) -> StableDigest {
    let project = InlineTestProject::with_language(Language::Python)
        .file("caller.py", "from pkg import value, C\n")
        .file("unimported.py", source)
        .build();
    let workspace = project.workspace_analyzer(Default::default());
    // Exercise the memo's warm read after filling outside the outer capture.
    read(workspace.analyzer());
    let (_, reads) = capture_query_reads(workspace.analyzer(), || read(workspace.analyzer()));
    assert_eq!(reads.unattributed_reads(), 0);
    let facts = reads
        .keys()
        .into_iter()
        .filter_map(|key| match key {
            ReadKey::Lookup {
                kind: LookupKind::WorkspaceFact,
                question:
                    LookupQuestion::WorkspaceFact {
                        family: recorded,
                        language,
                        subject,
                    },
                digest,
            } if recorded == family => Some((language, subject, digest)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(facts.len(), 1, "{facts:?}");
    let (language, subject, digest) = &facts[0];
    assert_eq!(
        replay_lookup(
            &workspace,
            LookupKind::WorkspaceFact,
            &LookupQuestion::WorkspaceFact {
                family,
                language: *language,
                subject: subject.clone()
            },
            Default::default(),
            &NoSummaryAnswers
        ),
        Some(*digest)
    );
    *digest
}

#[test]
fn module_mutation_unimported_write_changes_the_fact() {
    assert_ne!(
        fact(
            "marker = 0\n",
            module_read,
            WorkspaceFactFamily::PythonModuleMemberMutation
        ),
        fact(
            "import pkg\npkg.value = None\n",
            module_read,
            WorkspaceFactFamily::PythonModuleMemberMutation
        )
    );
}
#[test]
fn module_mutation_same_snapshot_repeats_the_fact() {
    assert_eq!(
        fact(
            "marker = 0\n",
            module_read,
            WorkspaceFactFamily::PythonModuleMemberMutation
        ),
        fact(
            "marker = 0\n",
            module_read,
            WorkspaceFactFamily::PythonModuleMemberMutation
        )
    );
}
#[test]
fn module_mutation_leading_comment_preserves_the_fact() {
    assert_eq!(
        fact(
            "import pkg\npkg.value = None\n",
            module_read,
            WorkspaceFactFamily::PythonModuleMemberMutation
        ),
        fact(
            "# unchanged mutation\nimport pkg\npkg.value = None\n",
            module_read,
            WorkspaceFactFamily::PythonModuleMemberMutation
        )
    );
}
#[test]
fn class_mutation_unimported_write_rejects_its_fact() {
    use brokk_bifrost_analysis::analyzer::read_verification::{
        ChangedFacts, LookupMemo, ReadVerdict, verify_read_set,
    };
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("caller.py", "from pkg import C\n")
        .file("unimported.py", "marker = 0\n")
        .build();
    let base = project.workspace_analyzer(Default::default());
    class_read(base.analyzer());
    let (_, capture) = capture_query_reads(base.analyzer(), || class_read(base.analyzer()));
    assert_eq!(capture.unattributed_reads(), 0);
    let reads = capture.keys();
    assert_eq!(
        reads.len(),
        1,
        "only the class-mutation Fact is needed: {reads:?}"
    );
    assert!(matches!(
        &reads[0],
        ReadKey::Lookup {
            question: LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::PythonClassMemberMutation,
                ..
            },
            ..
        }
    ));
    project
        .file("unimported.py")
        .write("from pkg import C\nC.run = None\n")
        .unwrap();
    let head = project.workspace_analyzer(Default::default());
    let changed = ChangedFacts::between(&base, &head);
    let verdict = verify_read_set(
        &head,
        &changed,
        &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
        &reads,
        Default::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    assert_ne!(
        verdict,
        ReadVerdict::Unchanged,
        "own Fact must reject without field-slot coverage"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#2445: delegate-owned mutation captures rejected Facts recorded through the workspace facade"
)]
fn class_mutation_same_snapshot_repeats_the_fact() {
    assert_eq!(
        fact(
            "marker = 0\n",
            class_read,
            WorkspaceFactFamily::PythonClassMemberMutation
        ),
        fact(
            "marker = 0\n",
            class_read,
            WorkspaceFactFamily::PythonClassMemberMutation
        )
    );
}
#[test]
fn class_mutation_leading_comment_preserves_the_fact() {
    assert_eq!(
        fact(
            "from pkg import C\nC.run = None\n",
            class_read,
            WorkspaceFactFamily::PythonClassMemberMutation
        ),
        fact(
            "# unchanged mutation\nfrom pkg import C\nC.run = None\n",
            class_read,
            WorkspaceFactFamily::PythonClassMemberMutation
        )
    );
}
