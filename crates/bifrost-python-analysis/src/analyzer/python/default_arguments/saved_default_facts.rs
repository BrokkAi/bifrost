use super::super::PythonAnalyzer;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::{
    FactSubject, Language, LookupQuestion, ReadKey, WorkspaceFactFamily, capture_query_reads,
    resolve_analyzer,
};

fn saved_default_fact(source: &str) -> StableDigest {
    let project = InlineTestProject::with_language(Language::Python)
        .file("caller.py", "def caller():\n    pass\n")
        .file("unimported.py", source)
        .build();
    let workspace = project.workspace_analyzer(Default::default());
    let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
    // Build outside a capture, as the oracle may do at construction time.
    let safety = python.saved_default_argument_safety();
    let (_, reads) = capture_query_reads(python, || python.saved_default_argument_safety());
    assert_eq!(reads.unattributed_reads(), 0);
    let keys = reads.keys();
    assert_eq!(keys.len(), 1);
    let ReadKey::Lookup {
        question:
            LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::PythonSavedDefaults,
                language: Language::Python,
                subject: FactSubject::Whole,
            },
        digest,
        ..
    } = &keys[0]
    else {
        panic!("expected whole saved-default Fact: {keys:?}");
    };
    assert_eq!(*digest, safety.fact_fingerprint());
    assert_eq!(
        brokk_bifrost_analysis::analyzer::read_verification::replay_lookup(
            &workspace,
            brokk_bifrost_analysis::analyzer::LookupKind::WorkspaceFact,
            &LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::PythonSavedDefaults,
                language: Language::Python,
                subject: FactSubject::Whole,
            },
            Default::default(),
            &brokk_bifrost_analysis::analyzer::read_verification::NoSummaryAnswers,
        ),
        Some(*digest),
    );
    *digest
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#2445: Python analyzer did not forward warm memo reads to the capture"
)]
fn saved_defaults_warm_reads_record_the_whole_value() {
    let source = "def target(value=False):\n    pass\n";
    assert_eq!(saved_default_fact(source), saved_default_fact(source));
}

#[test]
fn saved_defaults_unimported_metadata_write_changes_the_fact() {
    assert_ne!(
        saved_default_fact("def target(value=False):\n    pass\n"),
        saved_default_fact("def target(value=False):\n    pass\ntarget.__defaults__ = (True,)\n"),
    );
}

#[test]
fn saved_defaults_comment_edit_preserves_the_fact() {
    assert_eq!(
        saved_default_fact("def target(value=False):\n    pass\ntarget.__defaults__ = (True,)\n"),
        saved_default_fact(
            "# unchanged metadata\ndef target(value=False):\n    pass\ntarget.__defaults__ = (True,)\n"
        ),
    );
}

#[test]
fn saved_defaults_redefined_owners_have_distinct_function_identities() {
    let mutated = "def outer():\n    def target(value=False):\n        pass\n    target.__defaults__ = (True,)\n";
    let unchanged = "def outer():\n    def target(value=False):\n        pass\n";
    let first = format!("{mutated}\n{unchanged}");
    let second = format!("{unchanged}\n{mutated}");
    assert_ne!(saved_default_fact(&first), saved_default_fact(&second));
    assert_eq!(
        saved_default_fact(&first),
        saved_default_fact(&format!("# metadata unchanged\n{first}"))
    );
}
