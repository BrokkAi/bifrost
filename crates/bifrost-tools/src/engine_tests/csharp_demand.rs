use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::QueryScope;
use brokk_bifrost_analysis::analyzer::resolution::SelectedSemanticLocator;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    csharp_demand::probe_type,
};
use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context;
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
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let cancellation = CancellationToken::new();
    let project = fixture.project_dyn();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<
                brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
            >(workspace.analyzer())
            .expect("C# analyzer"),
        );
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
                )
                .with_analyzer(&services),
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
            Some(("App/Other.cs", "Other.Y")),
            false,
        ),
        (
            "namespace",
            "namespace A { class X {} namespace B { using Other; class C { X f; } } }",
            "namespace Other { class X {} }",
            Some(("App/Other.cs", "Other.X")),
            false,
        ),
        (
            "static",
            "namespace A { class X {} namespace B { using static Other.Y; class C { X f; } } }",
            "namespace Other { class Y { public class X {} } }",
            Some(("App/Other.cs", "Other.Y$X")),
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
            Some(("App/Other.cs", "Other.Y")),
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
        let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
        let workspace_id = context.workspace_id.clone();
        let store = std::sync::Arc::clone(&context.store);
        let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
            context,
        )
        .unwrap();
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
            .unwrap();
        let languages = [SelectedResolutionLanguage::with_epoch(
            "csharp",
            Language::CSharp,
            brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
        )];
        let cancellation = CancellationToken::new();
        let project = fixture.project_dyn();
        let services =
            brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
                brokk_bifrost_analysis::analyzer::resolve_analyzer::<
                    brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
                >(workspace.analyzer())
                .expect("C# analyzer"),
            );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    project.as_ref(),
                    &workspace_id,
                    &snapshots,
                    &languages,
                    &[],
                )
                .with_analyzer(&services),
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
            if case == "namespace" || case == "static" {
                assert!(
                    result
                        .named_reasons
                        .iter()
                        .any(|(name, _)| *name == "csharp_external_unindexed"),
                    "{case}: {:?}",
                    result.named_reasons
                );
            } else {
                assert!(
                    result.using_gaps.is_empty(),
                    "{case}: {:?}",
                    result.using_gaps
                );
            }
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
                    .any(|(name, _)| *name == "csharp_compilation_usings_incomplete"),
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
                == (case == "alias"
                    || case == "namespace"
                    || case == "static"
                    || case == "extern_outer"
                    || case == "global"
                    || case == "global_only"),
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

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: C# certification deadlocked on a single-connection store inside a selected operation"
)]
fn csharp_configuration_overlay_refuses_pooled_demand() {
    // This regression now runs on the pooled store.
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_configuration_overlay_refuses_pooled_demand",
                "--nocapture",
            ])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return;
    }
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    let source = "class Caller { Peer value; } class Peer {}";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("App/Caller.cs", source)
        .build();
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".into()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<
                brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
            >(workspace.analyzer())
            .unwrap(),
        );
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
            )
            .with_analyzer(&services),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("selected C# operation");
    };
    assert!(brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_configuration_admission(&operation).unwrap());
    drop(operation);
    let source_overlay = OverlayProject::new(std::sync::Arc::clone(&project));
    assert!(source_overlay.set(
        fixture.file("App/Caller.cs").abs_path(),
        "class Caller { Peer other; } class Peer {}".into(),
    ));
    let source_analyzer =
        workspace.clone_with_project(std::sync::Arc::new(source_overlay.snapshot()));
    let source_services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<
                brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
            >(source_analyzer.analyzer())
            .unwrap(),
        );
    // The selected inventory retains the disk project; the request analyzer has
    // unrelated source overlay content. Certification uses the retained reader.
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                project.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            )
            .with_analyzer(&source_services),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("source overlay selected operation");
    };
    assert!(brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_configuration_admission(&operation).unwrap());
    drop(operation);

    let config_overlay = OverlayProject::new(std::sync::Arc::clone(&project));
    assert!(config_overlay.set(
        fixture.file("App/App.csproj").abs_path(),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup /></Project>".into(),
    ));
    let config_analyzer =
        workspace.clone_with_project(std::sync::Arc::new(config_overlay.snapshot()));
    let config_services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<
                brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
            >(config_analyzer.analyzer())
            .unwrap(),
        );
    // A request analyzer can see a changed editor configuration after the
    // disk selection opens. Admission must refuse on its held connection.
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                project.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            )
            .with_analyzer(&config_services),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("configuration request selected operation");
    };
    assert!(!brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_configuration_admission(&operation).unwrap());
    drop(operation);

    let outcome = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                &config_overlay,
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            )
            .with_analyzer(&services),
            &cancellation,
        )
        .unwrap();
    assert!(matches!(
        outcome,
        SelectedResolutionOperationOpenOutcome::Unavailable(
            brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "csharp" && persisted_relative_path == "App/App.csproj"
    ));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: a live configuration overlay could change between two admissions of one C# operation"
)]
fn csharp_live_configuration_overlay_refuses_the_next_admission() {
    // This regression now runs on the pooled store.
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_live_configuration_overlay_refuses_the_next_admission",
                "--nocapture",
            ])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::{
        FactSubject, ReadKey, WorkspaceFactFamily,
    };
    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupQuestion;
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file(
            "App/Caller.cs",
            "class Caller { Peer value; } class Peer {}",
        )
        .build();
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    // The request analyzer reads this live overlay itself, not a snapshot of
    // it, so a later edit reaches the operation that is already open.
    let disk = fixture.project_dyn();
    let live = std::sync::Arc::new(OverlayProject::new(std::sync::Arc::clone(&disk)));
    let request = workspace.clone_with_project(live.clone());
    let csharp = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
        brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
    >(request.analyzer())
    .unwrap();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            csharp,
        );
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".into()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let cancellation = CancellationToken::new();
    // Begin the query before retaining the selected operation's only reader.
    brokk_bifrost_analysis::analyzer::capture_query_reads(csharp, || ());
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                disk.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            )
            .with_analyzer(&services),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("selected C# operation");
    };
    let admit = || {
        brokk_bifrost_analysis::analyzer::capture_query_reads(csharp, || {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_configuration_admission(&operation).unwrap()
        })
    };
    let (admitted, reads) = admit();
    assert!(admitted, "an unchanged configuration certifies");
    assert!(!reads.reuse_refused());
    let keys = reads.keys();
    assert!(
        keys.iter().any(|key| matches!(
            key,
            ReadKey::Lookup {
                question: LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::CSharpCompilationConfiguration,
                    language: Language::CSharp,
                    subject: FactSubject::Whole,
                },
                ..
            }
        )),
        "admission must record the configuration fact: {keys:?}"
    );
    assert!(live.set(
        fixture.file("App/App.csproj").abs_path(),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup /></Project>".into(),
    ));
    // Same operation, same captured handle: the next admission re-certifies
    // against the live overlay and refuses before any retained caller hit.
    let (admitted, reads) = admit();
    assert!(
        !admitted,
        "a changed live configuration overlay must refuse"
    );
    assert!(
        reads.reuse_refused(),
        "a refused admission must refuse reuse"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9962: nested C# store reads inside a selected operation deadlocked a single-connection store"
)]
fn csharp_nested_selected_reads_on_pooled_store() {
    // This regression now runs on the pooled store.
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_nested_selected_reads_on_pooled_store",
                "--nocapture",
            ])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    let source = "class Caller { Peer value; } class Peer {}";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("App/Caller.cs", source)
        .build();
    let disk = fixture.project_dyn();
    let context = ephemeral_store_context(disk.as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        std::sync::Arc::clone(&disk),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let overlay = OverlayProject::new(std::sync::Arc::clone(&disk));
    assert!(overlay.set(fixture.file("App/Caller.cs").abs_path(), source.into(),));
    let request = workspace.clone_with_project(std::sync::Arc::new(overlay.snapshot()));
    let csharp = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
        brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
    >(request.analyzer())
    .unwrap();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            csharp,
        );
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".into()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let cancellation = CancellationToken::new();
    // Begin the query before retaining the selected operation's only reader.
    brokk_bifrost_analysis::analyzer::capture_query_reads(csharp, || ());
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                disk.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            )
            .with_analyzer(&services),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("selected C# operation");
    };
    let locator = SelectedSemanticLocator::for_reference_range("csharp", "App/Caller.cs", 15, 19);
    // Both nested reads use immutable (workspace, generation, revision) rows;
    // their answers do not depend on the connection's snapshot.
    let (result, reads) = brokk_bifrost_analysis::analyzer::capture_query_reads(csharp, || {
        probe_type(&operation, &snapshots["csharp"], &locator, &cancellation)
    });
    assert!(
        !reads.keys().is_empty(),
        "selected demand must record reads"
    );
    let result = result.unwrap().unwrap();
    assert_eq!(
        result.targets,
        vec![("App/Caller.cs".into(), "Peer".into())]
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12013: an uncertified C# reference absence was counted as an omitted uses() candidate"
)]
fn csharp_reference_inventory_certificate() {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_reference_inventory_certificate",
                "--nocapture",
            ])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "{output:?}"
        );
        return;
    }
    use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        ReferenceInventoryCompleteness, SelectedResolutionContextMetrics,
        SelectedResolutionLocated, SelectedResolutionOperationOutcome,
    };
    for trial in [true, false] {
        for (language, storage, path, source, expected) in [
            (
                Language::CSharp,
                "csharp",
                "App/Caller.cs",
                "class Caller { int Value() { return 1; } }",
                "certified",
            ),
            (
                Language::CSharp,
                "csharp",
                "App/Caller.cs",
                "class Caller { Caller Value() { return this; } }",
                "incomplete",
            ),
            (
                Language::Go,
                "go",
                "caller.go",
                "package app\ntype Caller struct {}\n",
                "unavailable",
            ),
        ] {
            let fixture = InlineTestProject::with_language(language)
                .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
                .file(path, source)
                .build();
            let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
            let workspace_id = context.workspace_id.clone();
            let store = std::sync::Arc::clone(&context.store);
            let mut config = AnalyzerConfig::default();
            if !trial {
                config.csharp.native_trial =
                    brokk_bifrost_core::analyzer::config::CSharpNativeTrial::Off;
            }
            let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
                fixture.project_dyn(),
                config,
                context,
            )
            .unwrap();
            let snapshots = store
                .workspace_snapshots_for_current_languages(&workspace_id, &[storage.to_owned()])
                .unwrap();
            let languages = [SelectedResolutionLanguage::with_epoch(
                storage,
                language,
                if language == Language::CSharp && trial {
                    brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch()
                } else {
                    brokk_bifrost_analysis::analyzer::store::resolution::resolution_bundle_epoch(
                        language,
                    )
                },
            )];
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
                panic!("selected operation");
            };
            let start = source.find("Caller").unwrap();
            let locator =
                SelectedSemanticLocator::for_reference_range(storage, path, start, start + 6);
            let contexts = operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let outcome = operation
                .resolve_reference(
                    contexts,
                    &locator,
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing(
                certificate,
            )) = outcome
            else {
                panic!("expected Missing: {outcome:?}");
            };
            if trial && language == Language::CSharp {
                use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
                use brokk_bifrost_analysis::analyzer::usages::get_definition::{
                    DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch,
                };
                let analyzer = workspace.analyzer();
                let scope = AnalyzerQueryScope::new(analyzer);
                let outcomes = resolve_definition_batch(
                    analyzer,
                    scope.token(),
                    vec![DefinitionLookupRequest {
                        file: brokk_bifrost_core::analyzer::model::ProjectFile::new(
                            project.root(),
                            path,
                        ),
                        line: None,
                        column: None,
                        start_byte: Some(start),
                        end_byte: Some(start + 6),
                    }],
                );
                if expected == "certified" {
                    assert_eq!(outcomes[0].status, DefinitionLookupStatus::NotAReference);
                } else {
                    assert_eq!(outcomes[0].status, DefinitionLookupStatus::Unavailable);
                    assert!(matches!(
                        outcomes[0].incomplete_evidence.as_ref().unwrap().completion,
                        ResolutionCompletion::Incomplete(_)
                    ));
                }
            }
            let expected = if !trial { "unavailable" } else { expected };
            match expected {
                "certified" => assert_eq!(certificate, ReferenceInventoryCompleteness::Certified),
                "incomplete" => assert!(
                    matches!(certificate, ReferenceInventoryCompleteness::Incomplete(_)),
                    "{certificate:?}"
                ),
                _ => assert_eq!(certificate, ReferenceInventoryCompleteness::Unavailable),
            }
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12013: a retained C# NotAReference survived an edit that decertified the file"
)]
fn csharp_reference_inventory_warm_edit() {
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch,
    };
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    let initial = "class C { int Value; }";
    for edited in [
        "class C {     Other field; }",
        "class C { int Value; C M() { return this; } }",
    ] {
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
            .file("App/Caller.cs", initial)
            .build();
        let project = fixture.project_dyn();
        let file = ProjectFile::new(project.root(), "App/Caller.cs");
        let mut config = AnalyzerConfig::default();
        config.csharp.native_trial = brokk_bifrost_core::analyzer::config::CSharpNativeTrial::On;
        let build = || {
            WorkspaceAnalyzer::build_with_store_context_for_test(
                project.clone(),
                config.clone(),
                ephemeral_store_context(project.as_ref()).unwrap(),
            )
            .unwrap()
        };
        let warm = build();
        let lookup = |workspace: &WorkspaceAnalyzer| {
            let analyzer = workspace.analyzer();
            let scope = AnalyzerQueryScope::new(analyzer);
            resolve_definition_batch(
                analyzer,
                scope.token(),
                vec![DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(14),
                    end_byte: Some(19),
                }],
            )
            .remove(0)
        };
        assert_eq!(lookup(&warm).status, DefinitionLookupStatus::NotAReference);
        file.write(edited).unwrap();
        let updated = warm.update(&std::collections::BTreeSet::from([file.clone()]));
        let actual = lookup(&updated);
        let cold = lookup(&build());
        assert_ne!(
            actual.status,
            DefinitionLookupStatus::NotAReference,
            "edited={edited}; actual={actual:?}; cold={cold:?}"
        );
        assert_eq!(actual.status, cold.status);
        assert_eq!(
            format!("{:?}", actual.incomplete_evidence),
            format!("{:?}", cold.incomplete_evidence)
        );
    }
}

// Raw C# placement and global-using reads are covered by certification keys
// recorded where the operation builds its handle.
#[test]
fn csharp_certified_raw_read_receipt_contract() {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_certified_raw_read_receipt_contract",
                "--nocapture",
            ])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::{
        FactSubject, ReadKey, WorkspaceFactFamily,
    };
    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupQuestion;
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file(
            "App/Caller.cs",
            "global using System; class Caller { Peer value; } class Peer {}",
        )
        .build();
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let disk = fixture.project_dyn();
    let csharp = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
        brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
    >(workspace.analyzer())
    .unwrap();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            csharp,
        );
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".into()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let cancellation = CancellationToken::new();
    // Begin the query before retaining the selected operation's only reader.
    brokk_bifrost_analysis::analyzer::capture_query_reads(csharp, || ());
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                disk.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            )
            .with_analyzer(&services),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("selected C# operation");
    };
    let admit = || {
        brokk_bifrost_analysis::analyzer::capture_query_reads(csharp, || {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_certified_reader_receipt(&operation, "App/Caller.cs").unwrap()
        })
    };
    let (admitted, reads) = admit();
    assert_eq!(admitted, 1, "one placement exercises both raw readers");
    assert!(!reads.reuse_refused());
    let keys = reads.keys();
    assert!(
        keys.iter().any(|key| matches!(
            key,
            ReadKey::Lookup {
                question: LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::CSharpCompilationConfiguration,
                    language: Language::CSharp,
                    subject: FactSubject::Whole,
                },
                ..
            }
        )),
        "admission must record the configuration fact: {keys:?}"
    );

    assert!(
        keys.iter().any(|key| matches!(
            key,
            ReadKey::Scope { languages, .. } if languages.as_ref() == [Language::CSharp]
        )),
        "certification must record C# membership: {keys:?}"
    );
}
