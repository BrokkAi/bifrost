//! Whole Python authority receipts replay independently of byte positions.
use super::*;
use crate::analyzer::read_ledger::{FactSubject, LookupQuestion, ReadKey, WorkspaceFactFamily};
use crate::analyzer::semantic::StableDigest;
use crate::analyzer::{
    ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
    capture_query_reads, replay_lookup,
};

fn fixture() -> inline_project::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Python)
        .with_git()
        .file(
            "pyproject.toml",
            "[tool.setuptools.packages.find]\nwhere = ['.']\n",
        )
        .file("a.py", "class Base:\n    pass\n")
        .file("b.py", "class Other:\n    pass\n")
        .file(
            "seed.py",
            "from a import Base\nclass Seed(Base):\n    pass\n",
        )
        .file(
            "unimported.py",
            "from a import Base\nclass Extra(Base):\n    pass\n",
        )
        .file("pkg/__init__.py", "marker = 0\n")
        .file("pkg/pkg/__init__.py", "")
        .file("pkg/pkg/mod.py", "class Item:\n    pass\n")
        .build()
}

fn capture(
    workspace: &WorkspaceAnalyzer,
    family: WorkspaceFactFamily,
) -> (StableDigest, Vec<ReadKey>) {
    let (answer, reads) = capture_query_reads(workspace.analyzer(), || {
        brokk_bifrost_analysis::analyzer::languages::language_support(Language::Python)
            .expect("Python support")
            .workspace_fact_answer(
                workspace.analyzer(),
                family,
                Language::Python,
                &FactSubject::Whole,
            )
            .expect("whole authority")
    });
    assert_eq!(reads.unattributed_reads(), 0);
    let keys = reads.keys();
    assert!(keys.iter().any(|key| matches!(key, ReadKey::Lookup { question: LookupQuestion::WorkspaceFact { family: found, subject: FactSubject::Whole, .. }, .. } if *found == family)), "{keys:?}");
    (answer, keys)
}

fn rejects_changed_authority(family: WorkspaceFactFamily) {
    let project = fixture();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let (before, keys) = capture(&base, family);
    let (file, replacement) = match family {
        WorkspaceFactFamily::PythonModuleSpellings => (
            "pkg/__init__.py",
            "import os\n__path__.append(os.path.join(os.path.dirname(__file__), 'pkg'))\n",
        ),
        WorkspaceFactFamily::PythonDescendants
        | WorkspaceFactFamily::PythonReverseImports
        | WorkspaceFactFamily::PythonUsageIndex => (
            "unimported.py",
            "from b import Other\nclass Extra(Other):\n    pass\n",
        ),
        _ => unreachable!(),
    };
    assert!(
        !keys
            .iter()
            .any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == file)),
        "authority inputs must be subsumed: {keys:?}"
    );
    project
        .file(file)
        .write(replacement)
        .expect("mutate authority outside seed import closure");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    let (after, _) = capture(&head, family);
    assert_ne!(before, after);
    let key = keys.iter().find(|key| matches!(key, ReadKey::Lookup { question: LookupQuestion::WorkspaceFact { family: found, .. }, .. } if *found == family)).unwrap();
    let ReadKey::Lookup {
        kind,
        question,
        digest,
    } = key
    else {
        unreachable!()
    };
    assert_ne!(
        Some(*digest),
        replay_lookup(
            &head,
            *kind,
            question,
            LookupReplayLimits::default(),
            &NoSummaryAnswers
        )
    );
    let changed = ChangedFacts::between(&base, &head);
    let artifact = crate::analyzer::invalidation::DerivedArtifactId::new(
        crate::analyzer::invalidation::DerivedArtifactKind::PolicyEvaluationUnit,
        crate::analyzer::read_ledger::read_set_digest(&keys).digest(),
    );
    assert_ne!(
        ReadVerdict::Unchanged,
        crate::analyzer::verify_read_set_for_artifact(
            artifact,
            &head,
            &changed,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new()
        )
    );
}

fn repeats_equal(family: WorkspaceFactFamily) {
    let project = fixture();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let answer = capture(&workspace, family).0;
    assert_eq!(answer, capture(&workspace, family).0);
    let rebuilt = project.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(answer, capture(&rebuilt, family).0);
}

fn ignores_leading_comment(family: WorkspaceFactFamily) {
    let project = fixture();
    let base = project.workspace_analyzer(AnalyzerConfig::default());
    let before = capture(&base, family).0;
    project.file("unimported.py").write("# positions move before every relevant declaration\nfrom a import Base\nclass Extra(Base):\n    pass\n").expect("insert leading comment");
    project
        .file("pkg/__init__.py")
        .write("# comment before the package statement\nmarker = 0\n")
        .expect("insert marker comment");
    let head = project.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(before, capture(&head, family).0);
}

macro_rules! family_cases {
    ($module:ident, $family:ident) => {
        mod $module {
            use super::*;
            #[test]
            fn unimported_edit_invalidates_receipt() {
                rejects_changed_authority(WorkspaceFactFamily::$family);
            }
            #[test]
            fn same_snapshot_repeats_equal() {
                repeats_equal(WorkspaceFactFamily::$family);
            }
            #[test]
            fn leading_comment_preserves_digest() {
                ignores_leading_comment(WorkspaceFactFamily::$family);
            }
        }
    };
}
family_cases!(python_module_spellings, PythonModuleSpellings);
// Keep this existing family case explicit so the source gate can resolve its
// warm-read certificate without expanding the family_cases macro.
mod python_descendants {
    use super::*;

    #[test]
    fn unimported_edit_invalidates_receipt() {
        rejects_changed_authority(WorkspaceFactFamily::PythonDescendants);
    }

    #[test]
    fn same_snapshot_repeats_equal() {
        let project = fixture();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let answer = capture(&workspace, WorkspaceFactFamily::PythonDescendants).0;
        assert_eq!(
            answer,
            capture(&workspace, WorkspaceFactFamily::PythonDescendants).0
        );
        let rebuilt = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            answer,
            capture(&rebuilt, WorkspaceFactFamily::PythonDescendants).0
        );
    }

    #[test]
    fn leading_comment_preserves_digest() {
        ignores_leading_comment(WorkspaceFactFamily::PythonDescendants);
    }
}
family_cases!(python_reverse_imports, PythonReverseImports);
family_cases!(python_usage_index, PythonUsageIndex);
