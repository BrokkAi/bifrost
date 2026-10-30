//! Regression coverage for C# workspace-authority certificates.
use super::*;
use brokk_bifrost_analysis::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
    WorkspaceAnalyzer, capture_query_reads, verify_read_set_for_artifact,
};
use brokk_bifrost_analysis::inline_project::InlineTestProject;
use brokk_bifrost_test_macros::hardwon;

fn alias_answer(workspace: &WorkspaceAnalyzer) -> StableDigest {
    CSharpSupport
        .workspace_fact_answer(
            workspace.analyzer(),
            WorkspaceFactFamily::CSharpGlobalUsingAliases,
            Language::CSharp,
            &FactSubject::Whole,
        )
        .expect("complete aliases")
}

fn configuration_answer(workspace: &WorkspaceAnalyzer) -> StableDigest {
    CSharpSupport
        .workspace_fact_answer(
            workspace.analyzer(),
            WorkspaceFactFamily::CSharpCompilationConfiguration,
            Language::CSharp,
            &FactSubject::Whole,
        )
        .expect("complete configuration")
}

#[test]
#[hardwon("#7496: a warm global-using authority lost its unimported file dependency")]
fn global_alias_edit_rejects_a_warm_certificate() {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .with_git()
        .file("Globals.cs", "global using Parent = A.Base;\n")
        .file("Target.cs", "public class Target {}\n")
        .build();
    let base = fixture.workspace_analyzer(AnalyzerConfig::default());
    let old_answer = alias_answer(&base);
    let (_, reads) = capture_query_reads(base.analyzer(), || alias_answer(&base));
    assert_eq!(reads.unattributed_reads(), 0);
    assert!(
        !reads.keys().is_empty(),
        "a warm authority must record its fact"
    );
    fixture
        .file("Globals.cs")
        .write("global using Parent = B.Base;\n")
        .unwrap();
    let head = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_ne!(old_answer, alias_answer(&head));
    let changed = ChangedFacts::between(&base, &head);
    let keys = reads.keys();
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest(&keys).digest(),
    );
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
        &keys,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    assert_ne!(verdict, ReadVerdict::Unchanged);
}

#[test]
fn global_alias_snapshot_answers_are_deterministic() {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Globals.cs",
            "global using Z = Zed.Type;\nglobal using A = Alpha.Type;\n",
        )
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let first = alias_answer(&workspace);
    let second = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(first, alias_answer(&second));
}

#[test]
fn a_comment_above_global_usings_preserves_the_alias_answer() {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("Globals.cs", "global using Parent = A.Base;\n")
        .build();
    let base = fixture.workspace_analyzer(AnalyzerConfig::default());
    let answer = alias_answer(&base);
    fixture
        .file("Globals.cs")
        .write("// Shift every import position.\nglobal using Parent = A.Base;\n")
        .unwrap();
    let head = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(answer, alias_answer(&head));
}

#[test]
fn an_unimported_props_edit_rejects_a_compilation_certificate() {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .with_git()
        .file("Target.cs", "public class Target {}\n")
        .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file(
            "Directory.Build.props",
            "<Project><PropertyGroup><AssemblyName>A</AssemblyName></PropertyGroup></Project>",
        )
        .build();
    let base = fixture.workspace_analyzer(AnalyzerConfig::default());
    let old_answer = configuration_answer(&base);
    let (_, reads) = capture_query_reads(base.analyzer(), || configuration_answer(&base));
    assert_eq!(reads.unattributed_reads(), 0);
    assert!(!reads.keys().is_empty());
    fixture
        .file("Directory.Build.props")
        .write("<Project><PropertyGroup><AssemblyName>B</AssemblyName></PropertyGroup></Project>")
        .unwrap();
    let head = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_ne!(old_answer, configuration_answer(&head));
    let changed = ChangedFacts::between(&base, &head);
    let keys = reads.keys();
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest(&keys).digest(),
    );
    let verdict = verify_read_set_for_artifact(
        artifact,
        &head,
        &changed,
        &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
        &keys,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    assert_ne!(verdict, ReadVerdict::Unchanged);
}

#[test]
fn compilation_snapshot_answers_are_deterministic() {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("Target.cs", "public class Target {}\n")
        .build();
    let first = fixture.workspace_analyzer(AnalyzerConfig::default());
    let second = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(configuration_answer(&first), configuration_answer(&second));
}

#[test]
fn a_comment_above_a_class_preserves_the_compilation_answer() {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("Target.cs", "public class Target {}\n")
        .build();
    let base = fixture.workspace_analyzer(AnalyzerConfig::default());
    let answer = configuration_answer(&base);
    fixture
        .file("Target.cs")
        .write("// Shift the declaration.\npublic class Target {}\n")
        .unwrap();
    let head = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(answer, configuration_answer(&head));
}
