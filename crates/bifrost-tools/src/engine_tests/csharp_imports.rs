use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    csharp_imports::{CSharpImportPrecedence, probe_imports},
};
use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
use brokk_bifrost_core::{analyzer::Language, cancellation::CancellationToken};

#[test]
fn csharp_import_rules_join_real_scopes_and_activation() {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_imports::csharp_import_rules_join_real_scopes_and_activation",
                "--nocapture",
            ])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "child ran: {output:?}"
        );
        return;
    }
    // An editing buffer can place a reference before the using sequence.
    // It remains an authored site, but activation must exclude its binding.
    let source = r#"namespace A {
    using Name = Outer.Name;
    namespace B.C {
        class Before { Local earlier; }
        using Inner;
        using Local = Same.Local;
        using static Helpers;
        class Caller { Name field; Local local; void Run() { Invoke(); } }
    }
}
"#;
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("Imports.cs", source)
        .build();
    let context = single_connection_store_context_for_test(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let _workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::new("csharp", Language::CSharp)];
    let cancellation = CancellationToken::new();
    let project = fixture.project_dyn();
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                project.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            ),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("selected C# operation");
    };
    let probe = probe_imports(&operation, "Imports.cs", &cancellation)
        .unwrap()
        .unwrap();
    assert!(!probe.binders.is_empty(), "{probe:?}");
    assert!(
        probe.binders.iter().all(|(_, _, no_route)| *no_route),
        "{probe:?}"
    );
    assert!(
        probe
            .binders
            .iter()
            .any(|(bound, imported, _)| bound.as_deref() == Some("Name")
                && imported.as_deref() == Some("Name")),
        "{probe:?}"
    );
    let at = |needle: &str| source.find(needle).unwrap();
    let precedences = |position| {
        probe
            .bindings
            .iter()
            .filter(|(start, _)| *start == position)
            .map(|(_, precedence)| *precedence)
            .collect::<Vec<_>>()
    };
    let name = precedences(at("Name field"));
    let local = precedences(at("Local local"));
    let invoke = precedences(at("Invoke()"));
    println!("{probe:?}");
    assert!(
        probe.references.contains(&at("Local earlier")),
        "before-activation reference is stored: {probe:?}"
    );
    assert_eq!(
        name,
        vec![
            CSharpImportPrecedence { depth: 1, rank: 1 },
            CSharpImportPrecedence { depth: 1, rank: 1 },
            CSharpImportPrecedence { depth: 3, rank: 0 }
        ]
    );
    assert_eq!(
        local,
        vec![
            CSharpImportPrecedence { depth: 1, rank: 0 },
            CSharpImportPrecedence { depth: 1, rank: 1 },
            CSharpImportPrecedence { depth: 1, rank: 1 }
        ]
    );
    assert_eq!(invoke, vec![CSharpImportPrecedence { depth: 3, rank: 1 }]);
    // The stored earlier field reference precedes the using sequence activation.
    assert!(precedences(at("Local earlier")).is_empty(), "{probe:?}");
}
