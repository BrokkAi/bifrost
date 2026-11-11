//! Acceptance controls for the selected C# compilation input identity.
use super::*;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::ConfigurationCertificate;
use brokk_bifrost_test_macros::hardwon;

fn fixture() -> (BuiltInlineTestProject, CSharpAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("A.cs", "namespace Demo { class A { B field; } }")
        .file("B.cs", "namespace Demo { class B {} }")
        .build();
    let analyzer = CSharpAnalyzer::from_project(fixture.project().clone());
    (fixture, analyzer)
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn selected_configuration_certifies_cold_and_hot() {
    let (_fixture, analyzer) = fixture();
    let snapshot = analyzer.inner.selected_workspace_snapshots()["csharp"].clone();
    let identity = *analyzer.compilation_input_digest().unwrap().as_bytes();
    let connection = analyzer.inner.analyzer_store().read_conn().unwrap();
    for _ in 0..2 {
        let (certificate, reads) =
            brokk_bifrost_analysis::analyzer::capture_query_reads(&analyzer, || {
                IAnalyzer::certify_selected_configuration(
                    &analyzer,
                    Language::CSharp,
                    &snapshot,
                    &identity,
                    &connection,
                )
            });
        assert_eq!(certificate, ConfigurationCertificate::Certified);
        assert!(
            !reads.keys().is_empty(),
            "a certified read must record the configuration fact"
        );
    }
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn stale_selected_configuration_is_uncertified() {
    let (_fixture, analyzer) = fixture();
    let snapshot = analyzer.inner.selected_workspace_snapshots()["csharp"].clone();
    let mut stale = *analyzer.compilation_input_digest().unwrap().as_bytes();
    stale[0] ^= 1;
    let connection = analyzer.inner.analyzer_store().read_conn().unwrap();
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &analyzer,
            Language::CSharp,
            &snapshot,
            &stale,
            &connection
        ),
        ConfigurationCertificate::Uncertified
    );
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn oversized_configuration_cannot_certify() {
    let (fixture, initial) = fixture();
    let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
    fixture
        .file("Directory.Build.props")
        .write("x".repeat(2 * 1024 * 1024 + 1))
        .unwrap();
    let analyzer = CSharpAnalyzer::from_project(fixture.project().clone());
    let connection = analyzer.inner.analyzer_store().read_conn().unwrap();
    let (certificate, reads) =
        brokk_bifrost_analysis::analyzer::capture_query_reads(&analyzer, || {
            IAnalyzer::certify_selected_configuration(
                &analyzer,
                Language::CSharp,
                &snapshot,
                &[0; 32],
                &connection,
            )
        });
    assert_eq!(certificate, ConfigurationCertificate::Uncertified);
    assert!(reads.reuse_refused());
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn unsaved_configuration_overlay_refuses_reuse() {
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    let (fixture, initial) = fixture();
    let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
    let identity = *initial.compilation_input_digest().unwrap().as_bytes();
    let connection = initial.inner.analyzer_store().read_conn().unwrap();
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &initial,
            Language::CSharp,
            &snapshot,
            &identity,
            &connection
        ),
        ConfigurationCertificate::Certified,
    );
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(
        fixture.file("App.csproj").abs_path(),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup /></Project>".to_owned(),
    ));
    let request = initial.clone_with_project(Arc::new(overlay.snapshot()));
    let (certificate, reads) =
        brokk_bifrost_analysis::analyzer::capture_query_reads(&request, || {
            IAnalyzer::certify_selected_configuration(
                &request,
                Language::CSharp,
                &snapshot,
                &identity,
                &connection,
            )
        });
    assert_eq!(certificate, ConfigurationCertificate::Uncertified);
    assert!(reads.reuse_refused());
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn absent_configuration_becoming_present_changes_identity() {
    let (fixture, initial) = fixture();
    let old_identity = *initial.compilation_input_digest().unwrap().as_bytes();
    fixture.file("Directory.Build.props").write("").unwrap();
    let updated = CSharpAnalyzer::from_project(fixture.project().clone());
    let snapshot = updated.inner.selected_workspace_snapshots()["csharp"].clone();
    let new_identity = *updated.compilation_input_digest().unwrap().as_bytes();
    assert_ne!(old_identity, new_identity);
    let connection = updated.inner.analyzer_store().read_conn().unwrap();
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &updated,
            Language::CSharp,
            &snapshot,
            &old_identity,
            &connection,
        ),
        ConfigurationCertificate::Uncertified,
    );
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &updated,
            Language::CSharp,
            &snapshot,
            &new_identity,
            &connection,
        ),
        ConfigurationCertificate::Certified,
    );
}
