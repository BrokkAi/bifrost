//! Regression coverage for C# workspace-authority certificates.
use super::*;
use brokk_bifrost_analysis::analyzer::ReadKey;
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

/// Records one receipt that reads through the inner tree-sitter analyzer and
/// through the outer membership funnel, as a policy unit over C# does.
fn scope_receipt(workspace: &WorkspaceAnalyzer) -> Vec<ReadKey> {
    let csharp =
        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<CSharpAnalyzer>(
            workspace.analyzer(),
        )
        .expect("C# analyzer");
    let (_, reads) = capture_query_reads(workspace.analyzer(), || {
        csharp.inner.analyzed_live_files();
        csharp.selected_usage_graph_configurations();
    });
    assert_eq!(reads.unattributed_reads(), 0);
    let keys = reads.keys().to_vec();
    assert!(
        keys.iter().any(|key| matches!(key, ReadKey::Scope { .. })),
        "{keys:?}"
    );
    keys
}

fn receipt_verdict(
    base: &WorkspaceAnalyzer,
    head: &WorkspaceAnalyzer,
    keys: &[ReadKey],
) -> ReadVerdict {
    let artifact = DerivedArtifactId::new(
        DerivedArtifactKind::PolicyEvaluationUnit,
        brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest(keys).digest(),
    );
    verify_read_set_for_artifact(
        artifact,
        head,
        &ChangedFacts::between(base, head),
        &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
        keys,
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    )
}

fn csharp_receipt_fixture() -> brokk_bifrost_analysis::inline_project::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::CSharp)
        .with_git()
        .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("Target.cs", "public class Target {}\n")
        .file("Other.cs", "public class Other {}\n")
        .build()
}

#[test]
#[hardwon(
    "#13307: C# scope reads recorded the source-only identity but verified against the compilation-config identity"
)]
fn a_scope_bearing_csharp_receipt_verifies_unchanged_on_an_unchanged_head() {
    let fixture = csharp_receipt_fixture();
    let base = fixture.workspace_analyzer(AnalyzerConfig::default());
    let keys = scope_receipt(&base);
    let head = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(receipt_verdict(&base, &head, &keys), ReadVerdict::Unchanged);
}

#[test]
fn an_unnamed_global_using_rejects_a_scope_bearing_csharp_receipt() {
    let fixture = csharp_receipt_fixture();
    let base = fixture.workspace_analyzer(AnalyzerConfig::default());
    let keys = scope_receipt(&base);
    fixture
        .file("Other.cs")
        .write("global using System;\npublic class Other {}\n")
        .unwrap();
    let head = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_ne!(receipt_verdict(&base, &head, &keys), ReadVerdict::Unchanged);
}

#[test]
fn a_compilation_config_edit_rejects_a_scope_bearing_csharp_receipt() {
    let fixture = csharp_receipt_fixture();
    let base = fixture.workspace_analyzer(AnalyzerConfig::default());
    let keys = scope_receipt(&base);
    fixture
        .file("App.csproj")
        .write("<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><LangVersion>9</LangVersion></PropertyGroup></Project>")
        .unwrap();
    let head = fixture.workspace_analyzer(AnalyzerConfig::default());
    assert_ne!(receipt_verdict(&base, &head, &keys), ReadVerdict::Unchanged);
}

#[test]
#[hardwon(
    "#13307: the inner analyzer recorded a source-only scope identity that the C# verifier never matched"
)]
fn the_inner_and_outer_csharp_scope_keys_agree() {
    let fixture = csharp_receipt_fixture();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let csharp =
        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<CSharpAnalyzer>(
            workspace.analyzer(),
        )
        .expect("C# analyzer");
    assert_eq!(
        csharp.inner.scope_read_key(),
        IAnalyzer::workspace_scope_read_key(csharp, &[Language::CSharp])
    );
}

#[test]
fn external_index_hits_record_the_original_two_input_facts() {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("Caller.cs", "class Caller {}")
        .build();
    let analyzer = CSharpAnalyzer::new_with_config(
        Arc::new(fixture.project().clone()),
        AnalyzerConfig::default(),
    );
    let (index, cold) = capture_query_reads(&analyzer, || analyzer.external_declaration_index());
    let (retained, warm) = capture_query_reads(&analyzer, || analyzer.external_declaration_index());
    assert!(Arc::ptr_eq(&index, &retained));
    assert_eq!(cold.keys(), warm.keys());
    assert_eq!(warm.unattributed_reads(), 0);
    assert_eq!(warm.keys().len(), 2);
    for family in [
        WorkspaceFactFamily::CSharpDependencyInputs,
        WorkspaceFactFamily::CSharpArtifactInputs,
    ] {
        assert!(warm.keys().iter().any(|key| matches!(key, brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
            question: brokk_bifrost_analysis::analyzer::LookupQuestion::WorkspaceFact { family: actual, language: Language::CSharp, subject: FactSubject::Whole }, ..
        } if *actual == family)));
        assert!(
            CSharpSupport
                .workspace_fact_answer(&analyzer, family, Language::CSharp, &FactSubject::Whole)
                .is_some()
        );
        assert!(
            CSharpSupport
                .workspace_fact_answer(&analyzer, family, Language::Java, &FactSubject::Whole)
                .is_none()
        );
        assert!(
            CSharpSupport
                .workspace_fact_answer(
                    &analyzer,
                    family,
                    Language::CSharp,
                    &FactSubject::Named {
                        name: "wrong".into()
                    }
                )
                .is_none()
        );
    }
}
