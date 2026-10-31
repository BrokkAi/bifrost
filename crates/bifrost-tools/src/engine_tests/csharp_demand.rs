use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::resolution::SelectedSemanticLocator;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    csharp_demand::probe_type,
};
use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
use brokk_bifrost_core::{analyzer::Language, cancellation::CancellationToken};

#[test]
fn csharp_demand_searches_only_reached_namespace_levels() {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_demand_searches_only_reached_namespace_levels",
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
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    let source = "namespace A.B { public class Caller { public class Nested {} Peer p; X x; Nested n; OuterOnly o; } }";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("App/Caller.cs", source)
        .file("App/Inner.cs", "namespace A.B { public class X {} public class Nested {} }")
        .file(
            "App/Outer.cs",
            "namespace A { public class X {} public class OuterOnly {} }",
        )
        .file(
            "App/Multi.cs",
            "namespace A.B { public class Peer {} } namespace Other { public class Peer {} public class X {} }",
        )
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
    for (name, marker, expected) in [
        ("Peer", "Peer p", ("App/Multi.cs", "A.B.Peer")),
        ("X", "X x", ("App/Inner.cs", "A.B.X")),
        ("Nested", "Nested n", ("App/Caller.cs", "A.B.Caller$Nested")),
        ("OuterOnly", "OuterOnly o", ("App/Outer.cs", "A.OuterOnly")),
    ] {
        let start = source.find(marker).unwrap();
        let locator = SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Caller.cs",
            start,
            start + name.len(),
        );
        let measure = std::env::var_os("BIFROST_SQL_PROFILE").is_some();
        if measure {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::begin_production_selected_sql_trace(&store);
        }
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
        if measure {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::checkpoint_production_selected_sql_trace();
        }
        let _request = brokk_bifrost_core::cache_db::sql_profile::request_scope(name);
        let result = probe_type(&operation, &snapshots["csharp"], &locator, &cancellation)
            .unwrap()
            .unwrap();
        drop(operation);
        let targets = result.targets;
        let visited = result.visited;
        if measure {
            let cost = brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::finish_production_selected_sql_trace(&store);
            let ordinary = cost.statements.iter().filter(|sql| sql.trim() == brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_namespaces::ORDINARY_CANDIDATES.trim()).count();
            let staged = cost.statements.iter().filter(|sql| sql.trim() == brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_namespaces::STAGED_CANDIDATES.trim()).count();
            eprintln!(
                "C# {name}: total={} ordinary={ordinary} staged={staged} remaining={} visits={visited:?}",
                cost.statement_count(),
                cost.statement_count() - ordinary - staged
            );
        }
        assert_eq!(
            targets,
            vec![(expected.0.to_owned(), expected.1.to_owned())],
            "{name}: {visited:?}"
        );
        let inner = vec!["A".to_owned(), "B".to_owned()];
        let outer = vec!["A".to_owned()];
        if name == "Nested" {
            assert!(
                !visited.is_empty() && visited.iter().all(Option::is_none),
                "nested type stops before package tiers: {visited:?}"
            );
        } else {
            assert!(
                visited.contains(&Some(inner)),
                "{name} reached inner package: {visited:?}"
            );
            assert_eq!(
                visited.contains(&Some(outer)),
                name == "OuterOnly",
                "outer visits: {visited:?}"
            );
        }
    }
}

#[test]
fn csharp_demand_unmodeled_using_stops_outer_namespace_lookup() {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "engine_tests::csharp_demand::csharp_demand_unmodeled_using_stops_outer_namespace_lookup", "--nocapture"])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "child ran: {output:?}"
        );
        return;
    }
    // Namespace-body extern aliases await BrokkAi/tree-sitter-c-sharp#5.
    for (case, source, other, expected, compilation_unit) in [
        (
            "alias",
            "namespace A { class X {} namespace B { using X = Other.Y; class C { X f; } } }",
            "namespace Other { class Y {} }",
            None,
            false,
        ),
        (
            "namespace",
            "namespace A { class X {} namespace B { using Other; class C { X f; } } }",
            "namespace Other { class X {} }",
            None,
            false,
        ),
        (
            "static",
            "namespace A { class X {} namespace B { using static Other.Y; class C { X f; } } }",
            "namespace Other { class Y { public class X {} } }",
            None,
            false,
        ),
        (
            "extern_outer",
            "extern alias X; namespace A { class X {} namespace B { class C { X f; } } }",
            "",
            Some(("App/Caller.cs", "A.X")),
            false,
        ),
        (
            "global",
            "namespace A { class X {} namespace B { class C { X f; } } }",
            "global using X = Other.Y; namespace Other { class Y {} }",
            Some(("App/Caller.cs", "A.X")),
            false,
        ),
        (
            "global_only",
            "namespace A { namespace B { class C { X f; } } }",
            "global using X = Other.Y; namespace Other { class Y {} }",
            None,
            true,
        ),
        (
            "member",
            "namespace A.B { using Z = Other.W; class C { X f; } }",
            "namespace A.B { class X {} } namespace Other { class W {} }",
            Some(("App/Other.cs", "A.B.X")),
            false,
        ),
    ] {
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
            .file("App/Caller.cs", source)
            .file("App/Other.cs", other)
            .build();
        let context =
            single_connection_store_context_for_test(fixture.project_dyn().as_ref()).unwrap();
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
        let start = source.find("X f").unwrap();
        let locator = SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Caller.cs",
            start,
            start + 1,
        );
        let result = probe_type(&operation, &snapshots["csharp"], &locator, &cancellation)
            .unwrap()
            .unwrap();
        if let Some((file, name)) = expected {
            assert_eq!(result.targets, vec![(file.to_owned(), name.to_owned())]);
            assert!(
                result.using_gaps.is_empty(),
                "{case}: {:?}",
                result.using_gaps
            );
            if case == "global" {
                assert_eq!(
                    result
                        .visited
                        .iter()
                        .filter_map(Option::as_ref)
                        .collect::<Vec<_>>(),
                    vec![&vec!["A".to_owned(), "B".to_owned()], &vec!["A".to_owned()]]
                );
            }
            // Existing generic source gaps are independent of this barrier.
            // Pin the winner and absence of a using-tier gap, not unrelated
            // language capabilities.
        } else {
            assert!(result.targets.is_empty(), "{case}: {:?}", result.targets);
            assert_ne!(
                result.completion,
                brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete,
                "{case}: visits={:?}, gaps={:?}, reasons={:?}",
                result.visited,
                result.using_gaps,
                result.named_reasons
            );
            assert!(
                result
                    .named_reasons
                    .iter()
                    .any(|(name, _)| *name == "csharp_using_tier_unmodeled"),
                "{case}: visits={:?}, gaps={:?}, reasons={:?}",
                result.visited,
                result.using_gaps,
                result.named_reasons
            );
            let level = if compilation_unit {
                None
            } else {
                Some(vec!["A".to_owned(), "B".to_owned()])
            };
            assert!(!result.using_gaps.is_empty(), "{case}: gap ran");
            assert!(
                result.using_gaps.iter().all(|gap| gap.namespace == level),
                "{case}: {:?}",
                result.using_gaps
            );
        }
        // Every case references X from inside A.B, so the walk always reaches A.B.
        assert!(
            result
                .visited
                .contains(&Some(vec!["A".to_owned(), "B".to_owned()])),
            "{case}: {:?}",
            result.visited
        );
        if case == "global_only" {
            // The trace records the compilation unit as the empty namespace path.
            assert_eq!(
                result.visited.last(),
                Some(&Some(Vec::new())),
                "{:?}",
                result.visited
            );
        }
        assert!(
            result.visited.contains(&Some(vec!["A".to_owned()]))
                == (case == "extern_outer" || case == "global" || case == "global_only"),
            "{case}: {:?}",
            result.visited
        );
        if case == "extern_outer" {
            assert!(
                !result.visited.contains(&Some(vec![])),
                "outer compilation unit was not read: {:?}",
                result.visited
            );
        }
        eprintln!(
            "C# tier case {case} passed: targets={:?}, visits={:?}",
            result.targets, result.visited
        );
    }
}
