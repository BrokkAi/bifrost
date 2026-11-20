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
use brokk_bifrost_test_macros::hardwon;

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

/// Factory admission over real selected C# sources: only a nonstatic,
/// nonpartial class owner with one supported application and a complete
/// receiver source is admitted; every other shape is a named rejection.
#[test]
fn csharp_base_receiver_factory_admits_only_proven_class_owners() {
    use brokk_bifrost_analysis::analyzer::resolution::BaseReceiverRejection;

    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_base_receiver_factory_admits_only_proven_class_owners",
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

    let files = [
        (
            "App/Base.cs",
            "namespace Cases { public class Base { public int Shared() => 1; public virtual string Name() => \"\"; } }",
        ),
        (
            "App/Child.cs",
            "namespace Cases { public class Child : Base { int Call() => base.Shared(); static int StaticCall() => base.Shared(); } }",
        ),
        (
            "App/GenericChild.cs",
            "namespace Cases { public class GenericBase<T> { public int Shared() => 1; } public class GenericChild<Tc> : GenericBase<Tc> { int Call() => base.Shared(); } }",
        ),
        (
            "App/Struct.cs",
            "namespace Cases { public struct Value { public override string ToString() => base.ToString(); } }",
        ),
        (
            "App/PartialBase.cs",
            "namespace Cases { public partial class PartialBase { public int Shared() => 1; } }",
        ),
        (
            "App/PartialChild.cs",
            "namespace Cases { public partial class PartialChild : PartialBase { int Call() => base.Shared(); } }",
        ),
        (
            "App/PartialChild.Other.cs",
            "namespace Cases { public partial class PartialChild { int Other() => 2; } }",
        ),
    ];
    let mut project = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />");
    for (path, source) in files {
        project = project.file(path, source);
    }
    let fixture = project.build();
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
    let admit = |path: &str, nth: usize, needle: &str, member: &str| {
        let source = files.iter().find(|(file, _)| *file == path).unwrap().1;
        let start = source.match_indices(needle).nth(nth).unwrap().0 + needle.len() - member.len();
        let locator = SelectedSemanticLocator::for_reference_range(
            "csharp",
            path,
            start,
            start + member.len(),
        );
        operation
            .admit_base_receiver_for_test(&locator, &cancellation)
            .unwrap()
            .unwrap_or_else(|| panic!("{path}: no selected reference"))
    };
    let admitted = admit("App/Child.cs", 0, "base.Shared", "Shared").expect("instance class owner");
    assert!(admitted.provisional_reasons.len() <= 1, "{admitted:#?}");
    assert_eq!(
        admitted.completion,
        brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete
    );
    admit("App/GenericChild.cs", 0, "base.Shared", "Shared")
        .expect("generic class owner with a written parent application");
    assert_eq!(
        admit("App/Child.cs", 1, "base.Shared", "Shared").unwrap_err(),
        BaseReceiverRejection::ReceiverSourceOpen,
        "a static member keeps its UnsupportedExpression gap on the source axis"
    );
    assert_eq!(
        admit("App/PartialChild.cs", 0, "base.Shared", "Shared").unwrap_err(),
        BaseReceiverRejection::OwnerPartial
    );
    assert_eq!(
        admit("App/Struct.cs", 0, "base.ToString", "ToString").unwrap_err(),
        BaseReceiverRejection::OwnerNotClass
    );
    let start = files[1].1.find("base.Shared").unwrap() + "base.".len();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(
        operation
            .admit_base_receiver_for_test(
                &SelectedSemanticLocator::for_reference_range(
                    "csharp",
                    "App/Child.cs",
                    start,
                    start + "Shared".len(),
                ),
                &cancelled,
            )
            .map(|admitted| admitted.is_none_or(|admitted| admitted.is_err()))
            .unwrap_or(true),
        "a cancelled read never admits a base receiver"
    );
}

#[test]
#[hardwon("#7314: unpublishable receiver proof still discharged transfer gaps")]
fn csharp_base_context_reads_real_selected_member_and_replays_both_receipts() {
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedBaseReceiverContextProofCycleForTest;

    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine_tests::csharp_demand::csharp_base_context_reads_real_selected_member_and_replays_both_receipts",
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

    use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
    use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey};
    use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
    use brokk_bifrost_analysis::analyzer::resolution::fact_source::{
        OwnerStaticAuthority, SelectedReceiverProofReceipt, TypedFactInventoryEvidence,
    };
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
    };
    use brokk_bifrost_core::analyzer::ProjectFile;

    let base =
        "namespace Cases { public class Base { public int Field; public int Shared() => 1; } }";
    let child = "namespace Cases { public class Child : Base { int Call() => base.Shared(); int Read() => base.Field; int Bare() => Field; int InstanceCall() => this.Shared(); static int StaticCall() => base.Shared(); } }";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("App/Base.cs", base)
        .file("App/Child.cs", child)
        .file(
            "App/PartialBase.One.cs",
            "namespace Cases { public partial class PartialBase { public int Shared() => 1; } }",
        )
        .file(
            "App/PartialBase.Two.cs",
            "namespace Cases { public partial class PartialBase { public int Other() => 2; } }",
        )
        .file(
            "App/PartialChild.cs",
            "namespace Cases { public partial class PartialChild : PartialBase { int Call() => base.Shared(); } }",
        )
        .file(
            "App/PartialChild.Other.cs",
            "namespace Cases { public partial class PartialChild { int Other() => 2; } }",
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

    for (needle, member) in [("base.Shared()", "Shared"), ("base.Field", "Field")] {
        let start = child.find(needle).unwrap() + "base.".len();
        let locator = SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Child.cs",
            start,
            start + member.len(),
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
        let cycle: SelectedBaseReceiverContextProofCycleForTest = operation
            .base_receiver_context_proof_cycle_for_test(&locator, &cancellation)
            .unwrap()
            .unwrap_or_else(|| {
                let observation = operation
                    .read_base_receiver_context_for_test(&locator, &cancellation)
                    .unwrap();
                panic!("selected base receiver proof for {needle}: {observation:#?}")
            });
        let file = ProjectFile::new(fixture.root(), "App/Child.cs");
        let request = DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + member.len()),
        };
        let ordinary = resolve_definition_batch_with_source(
            workspace.analyzer(),
            vec![request],
            file,
            child.to_owned().into(),
        );
        let [ordinary] = ordinary.as_slice() else {
            panic!("ordinary C# member answer: {ordinary:?}");
        };
        assert_ne!(
            ordinary.status,
            DefinitionLookupStatus::Resolved,
            "the ordinary member answer remains open for {needle}: {ordinary:#?}"
        );
        assert!(
            ordinary.diagnostics.iter().any(|diagnostic| {
                diagnostic.kind == "incomplete_binding"
                    && diagnostic.message.contains("UnsupportedSemantic")
            }),
            "the original member gap remains on the ordinary answer for {needle}: {ordinary:#?}"
        );
        assert_eq!(cycle.fill.receipt, SelectedReceiverProofReceipt::Captured);
        assert!(
            cycle.node_replay_usable,
            "clean Base replay has the genuine composite token"
        );
        assert_eq!(
            cycle.node_replay_receipt,
            SelectedReceiverProofReceipt::Replayed,
            "clean-slot/node replay revalidates the Base proof"
        );
        assert_eq!(
            cycle.owner_application_node_replay_receipt,
            Some(SelectedReceiverProofReceipt::Replayed),
            "clean-slot/node replay must also revalidate OwnerApplication"
        );
        assert_eq!(
            cycle.same_session_hit.receipt,
            SelectedReceiverProofReceipt::Replayed
        );
        assert_eq!(
            cycle.fill.observation.source_inventory,
            TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
        );
        assert_eq!(
            cycle.fill.observation.completion,
            ResolutionCompletion::Complete,
            "instance-context base source may license only its exact UnsupportedTypeSyntax gap"
        );
        assert_eq!(
            cycle.fill.observation.reference_completion,
            ResolutionCompletion::Complete,
            "the raw reference completion remains its own axis"
        );
        assert_eq!(
            cycle.fill.observation.receiver_source_completion,
            Some(ResolutionCompletion::Complete),
            "the effective receiver-source completion is recorded separately"
        );
        assert_eq!(
            cycle.fill.observation.owner_staticness,
            OwnerStaticAuthority::KnownNonStatic,
            "owner staticness from recorded C# facts for {needle}: {:#?}",
            cycle.fill.observation
        );
        assert_eq!(
            ordinary.status,
            DefinitionLookupStatus::Incomplete,
            "the ordinary member answer remains open for {needle}"
        );
        assert!(!cycle.fill.observation.provisional_reasons.is_empty());
        assert_eq!(
            cycle.head_replay_answer, cycle.fill.observation.answer,
            "base reference must replay under the exact canonical question"
        );
        assert_eq!(
            cycle.owner_application_head_replay_answer,
            cycle.fill.observation.owner_application_answer,
            "owner application must replay under its separate exact question"
        );
        assert_eq!(
            cycle.same_session_hit.observation.owner_application_receipt,
            SelectedReceiverProofReceipt::Replayed,
            "base hit must revalidate the owner application too"
        );
        assert_eq!(
            cycle.question.source(),
            cycle.owner_application_question.source(),
            "both receipts must bind to the same selected source"
        );
    }

    let needle = "base.Shared()";
    let member = "Shared";
    let start = child.rfind(needle).unwrap() + "base.".len();
    let locator = SelectedSemanticLocator::for_reference_range(
        "csharp",
        "App/Child.cs",
        start,
        start + member.len(),
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
        panic!("selected C# operation for static-method negative control");
    };
    let bare_start = child.find("=> Field;").unwrap() + "=> ".len();
    let bare_locator = SelectedSemanticLocator::for_reference_range(
        "csharp",
        "App/Child.cs",
        bare_start,
        bare_start + "Field".len(),
    );
    let negative = operation
        .raw_base_receiver_proof_cycle_for_test(&bare_locator, &cancellation)
        .unwrap()
        .expect("real bare Field source question");
    assert_eq!(
        negative.fill.receipt,
        SelectedReceiverProofReceipt::Captured
    );
    assert_eq!(negative.hit.receipt, SelectedReceiverProofReceipt::Replayed);
    assert_eq!(
        negative.node_receipt,
        SelectedReceiverProofReceipt::Replayed
    );
    assert_eq!(
        negative.owner_node_receipt, None,
        "no child question is fabricated for a raw negative"
    );
    for observed in [&negative.fill, &negative.hit] {
        assert!(
            observed.usable_receipt.is_some(),
            "raw negative retains its own real receipt"
        );
        assert!(observed.observation.canonical_answer.is_some());
        assert!(
            observed.observation.answer.is_none(),
            "raw receipt is not positive Base permission"
        );
        assert!(observed.observation.owner.is_none());
        assert!(observed.observation.owner_application.is_none());
        assert_eq!(
            observed.observation.owner_application_receipt,
            SelectedReceiverProofReceipt::Unretained
        );
    }
    assert_eq!(negative.head, negative.fill.observation.canonical_answer);
    assert_eq!(
        negative.hit.observation.canonical_answer,
        negative.fill.observation.canonical_answer
    );

    let static_method = operation
        .read_base_receiver_context_for_test(&locator, &cancellation)
        .unwrap()
        .unwrap()
        .observation;
    assert_eq!(
        static_method.source_inventory,
        TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
    );
    assert_eq!(
        static_method.owner_staticness,
        OwnerStaticAuthority::KnownNonStatic,
        "the owner class is nonstatic even though the method context is static"
    );
    assert!(
        matches!(
            &static_method.receiver_source_completion,
            Some(ResolutionCompletion::Incomplete(reasons))
                if reasons.iter().any(|reason| matches!(
                    reason,
                    brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(id)
                        if !static_method.provisional_reasons.contains(id)
                ))
        ),
        "static-method UnsupportedExpression and other nonlicensed receiver gaps remain on the source axis: {static_method:#?}"
    );
    assert!(
        matches!(
            &static_method.completion,
            ResolutionCompletion::Incomplete(reasons)
                if reasons.iter().any(|reason| matches!(
                    reason,
                    brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(id)
                        if !static_method.provisional_reasons.contains(id)
                ))
        ),
        "the conservative aggregate still includes nonlicensed receiver gaps: {static_method:#?}"
    );

    let (unseeded, _) = capture_query_reads(workspace.analyzer(), || {
        brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_selected_receiver_proof_capture_for_test(|| {
            operation.owner_application_seed_cycle_for_test(
                static_method.receiver_slot.expect("actual Super receiver slot"),
                &cancellation,
            )
        }).unwrap()
    });
    for answer in unseeded {
        assert!(
            answer.is_empty(),
            "NotProvided is omitted from the product seed list; a Super slot stays unseeded even when its raw receipt is refused: {answer:?}"
        );
    }

    let application = static_method
        .owner_application
        .expect("real Child source application");
    let [owner_fill, owner_hit] = operation
        .owner_application_seed_cycle_for_test(application, &cancellation)
        .unwrap();
    assert!(
        matches!(
            owner_fill.as_slice(),
            [brokk_bifrost_analysis::analyzer::resolution::ConditionalTypeSeedRead::Ready(_)]
        ),
        "normal source owner seed: {owner_fill:?}"
    );
    assert!(matches!(
        owner_hit.as_slice(),
        [brokk_bifrost_analysis::analyzer::resolution::ConditionalTypeSeedRead::Ready(_)]
    ));
    let (owner_capture, owner_capture_reads) = capture_query_reads(workspace.analyzer(), || {
        brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_selected_receiver_proof_capture_for_test(|| operation.owner_application_seed_cycle_for_test(application, &cancellation)).unwrap()
    });
    let [owner_refused_fill, owner_recaptured] = owner_capture;
    assert!(
        matches!(
            owner_refused_fill.as_slice(),
            [brokk_bifrost_analysis::analyzer::resolution::ConditionalTypeSeedRead::Open { .. }]
        ),
        "unusable Owner capture must not seed TypeObject: {owner_refused_fill:?}"
    );
    assert!(matches!(
        owner_recaptured.as_slice(),
        [brokk_bifrost_analysis::analyzer::resolution::ConditionalTypeSeedRead::Ready(_)]
    ));
    assert!(owner_capture_reads.reuse_refused());
    let ((owner_replay, owner_replay_reads), owner_replay_hits) = brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_owner_application_proof_replay_for_test(|| {
        capture_query_reads(workspace.analyzer(), || operation.owner_application_seed_cycle_for_test(application, &cancellation).unwrap())
    });
    let [owner_before_replay, owner_refused_hit] = owner_replay;
    assert!(
        owner_replay_hits > 0,
        "actual Owner memo replay reached the normal refusal channel"
    );
    assert!(matches!(
        owner_before_replay.as_slice(),
        [brokk_bifrost_analysis::analyzer::resolution::ConditionalTypeSeedRead::Ready(_)]
    ));
    assert!(
        matches!(
            owner_refused_hit.as_slice(),
            [brokk_bifrost_analysis::analyzer::resolution::ConditionalTypeSeedRead::Open { .. }]
        ),
        "unusable Owner replay must not seed TypeObject: {owner_refused_hit:?}"
    );
    assert!(owner_replay_reads.reuse_refused());

    let partial_source = "namespace Cases { public partial class PartialChild : PartialBase { int Call() => base.Shared(); } }";
    let partial_start = partial_source.find("base.Shared()").unwrap() + "base.".len();
    let partial_locator = SelectedSemanticLocator::for_reference_range(
        "csharp",
        "App/PartialChild.cs",
        partial_start,
        partial_start + "Shared".len(),
    );
    let partial = operation
        .read_base_receiver_context_for_test(&partial_locator, &cancellation)
        .unwrap()
        .unwrap()
        .observation;
    assert_eq!(partial.owner_partial, Some(true));
    assert_eq!(partial.owner_staticness, OwnerStaticAuthority::Unknown);
    assert!(
        partial.answer.is_none(),
        "a partial owner cannot license the base source question: {partial:#?}"
    );

    let missing_owner_application = operation
        .read_base_receiver_context_without_owner_application_for_test(
            static_method.reference,
            &cancellation,
        )
        .unwrap();
    assert_eq!(missing_owner_application.observation.owner_partial, None);
    assert_eq!(
        missing_owner_application.observation.owner_staticness,
        OwnerStaticAuthority::Unknown
    );
    assert!(missing_owner_application.observation.answer.is_none());
    assert_eq!(
        missing_owner_application.receipt,
        SelectedReceiverProofReceipt::Unretained
    );

    let instance_start = child.find("base.Shared()").unwrap() + "base.".len();
    let instance_locator = SelectedSemanticLocator::for_reference_range(
        "csharp",
        "App/Child.cs",
        instance_start,
        instance_start + "Shared".len(),
    );
    let owner_change_replay = operation
        .replay_base_receiver_context_node_after_owner_change_for_test(
            &instance_locator,
            &cancellation,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        owner_change_replay.0,
        SelectedReceiverProofReceipt::Unretained,
        "Base node replay must refuse reuse after the owner application answer changes"
    );
    assert_eq!(
        owner_change_replay.1,
        Some(SelectedReceiverProofReceipt::Captured),
        "the changed owner application was normally recaptured before Base refused"
    );

    let unestablished = operation
        .read_base_receiver_context_with_unestablished_routes_for_test(
            static_method.reference,
            &cancellation,
        )
        .unwrap();
    assert_eq!(
        unestablished.receipt,
        SelectedReceiverProofReceipt::Unretained
    );
    assert_eq!(
        unestablished.observation.source_inventory,
        TypedFactInventoryEvidence::Unestablished
    );
    assert!(unestablished.observation.answer.is_none());
    assert!(!matches!(
        unestablished.observation.completion,
        ResolutionCompletion::Incomplete(ref reasons)
            if reasons.iter().any(|reason| matches!(reason, brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::Cancelled))
    ));

    let missing_frontier = operation
        .read_base_receiver_context_without_frontier_for_test(
            static_method.reference,
            &cancellation,
        )
        .unwrap();
    assert_eq!(
        missing_frontier.receipt,
        SelectedReceiverProofReceipt::Unretained
    );
    assert!(missing_frontier.observation.answer.is_none());

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let cancelled_observation = operation
        .read_base_receiver_context_reference_for_test(static_method.reference, &cancelled)
        .unwrap();
    assert_eq!(
        cancelled_observation.receipt,
        SelectedReceiverProofReceipt::Unretained
    );
    assert!(matches!(
        cancelled_observation.observation.completion,
        ResolutionCompletion::Incomplete(ref reasons)
            if reasons.iter().any(|reason| matches!(reason, brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::Cancelled))
    ));

    let field_start = child.find("base.Field").unwrap() + "base.".len();
    let field_locator = SelectedSemanticLocator::for_reference_range(
        "csharp",
        "App/Child.cs",
        field_start,
        field_start + "Field".len(),
    );
    let (changed, changed_reads) = capture_query_reads(workspace.analyzer(), || {
        operation
            .replay_base_receiver_context_after_question_change_for_test(
                &instance_locator,
                &field_locator,
                &cancellation,
            )
            .unwrap()
            .expect("two selected Base questions")
    });
    let (changed, pending_after_changed, base_memo_after_changed) = changed;
    assert_eq!(changed.receipt, SelectedReceiverProofReceipt::Unretained);
    assert!(changed.usable_receipt.is_none());
    assert!(changed.observation.canonical_answer.is_some());
    assert!(changed.observation.answer.is_none());
    assert_eq!(
        changed.observation.owner_application_receipt,
        SelectedReceiverProofReceipt::Replayed,
        "OwnerApplication replay remains an independently observable channel"
    );
    assert!(pending_after_changed.is_empty());
    assert!(!base_memo_after_changed);
    assert!(changed_reads.reuse_refused());
    assert_eq!(
        changed_reads
            .keys()
            .iter()
            .filter(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::SelectedReceiverProof,
                    ..
                }
            ))
            .count(),
        2,
        "both OwnerApplication and Base proof read channels reach the enclosing ledger"
    );

    // A previously affirmative StateMap must not survive refused clean reuse.
    operation.with_owner_application_clean_reuse_for_test(
        &instance_locator, application, &cancellation, |resume| {
            for _ in 0..2 {
                let values = resume().unwrap().expect("normal clean resumed state");
                assert!(values.iter().any(|value| matches!(value,
                    brokk_bifrost_analysis::analyzer::resolution::ResolutionSlotValue::TypeObject(_, _))));
            }
        },
    ).unwrap();
    let ((refused_clean, clean_hits), clean_reads) = capture_query_reads(
        workspace.analyzer(),
        || {
            operation.with_owner_application_clean_reuse_for_test(
            &instance_locator, application, &cancellation, |resume| {
                brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_owner_application_proof_replay_for_test(resume)
            },
        ).unwrap()
        },
    );
    assert!(
        clean_hits > 0,
        "the clean evaluator path really replayed OwnerApplication"
    );
    let error =
        refused_clean.expect_err("late affirmative refusal must not copy the old TypeObject");
    assert!(
        error
            .to_string()
            .contains("Previously affirmative receiver authority refused"),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("Slot("),
        "full consumer context: {error:?}"
    );
    assert!(clean_reads.reuse_refused());
    let cancel_reuse = CancellationToken::new();
    let cancelled_clean = operation
        .with_owner_application_clean_reuse_for_test(
            &instance_locator,
            application,
            &cancel_reuse,
            |resume| {
                cancel_reuse.cancel();
                resume()
            },
        )
        .unwrap()
        .unwrap();
    assert!(
        cancelled_clean.is_none(),
        "cancellation takes the existing typed path, not a late-refusal error"
    );

    // Refuse the actual child during Base node replay, not standalone Owner.
    let ((child_cycle, child_reads), child_hits) = brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_owner_application_proof_replay_for_test(|| {
        capture_query_reads(workspace.analyzer(), || operation.base_receiver_context_proof_cycle_for_test(&instance_locator, &cancellation).unwrap().unwrap())
    });
    assert!(child_hits > 0);
    assert_eq!(
        child_cycle.node_replay_receipt,
        SelectedReceiverProofReceipt::Unretained
    );
    assert_eq!(
        child_cycle.owner_application_node_replay_receipt,
        Some(SelectedReceiverProofReceipt::Unretained)
    );
    assert!(
        !child_cycle.node_replay_usable,
        "a refused child never grants the Base composite"
    );
    assert!(child_reads.reuse_refused());
    assert_eq!(
        child_reads
            .keys()
            .iter()
            .filter(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::SelectedReceiverProof,
                    ..
                }
            ))
            .count(),
        2,
        "Base node replay forwards both question channels even when the child refuses"
    );
    let ((child_hit, hit_count), hit_reads) = capture_query_reads(workspace.analyzer(), || {
        operation.with_base_receiver_hit_for_test(&instance_locator, &cancellation, |hit| {
            brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_owner_application_proof_replay_for_test(hit)
        }).unwrap()
    });
    let child_hit = child_hit.unwrap();
    assert!(hit_count > 0);
    assert_eq!(child_hit.receipt, SelectedReceiverProofReceipt::Unretained);
    assert!(child_hit.usable_receipt.is_none());
    assert!(child_hit.observation.answer.is_none());
    assert!(child_hit.observation.canonical_answer.is_some());
    assert!(hit_reads.reuse_refused());
    assert_eq!(
        hit_reads
            .keys()
            .iter()
            .filter(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::SelectedReceiverProof,
                    ..
                }
            ))
            .count(),
        2,
        "Base memo hit forwards both question channels even when the child refuses"
    );

    let (refused_fill, refused_reads) = capture_query_reads(workspace.analyzer(), || {
        brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_selected_receiver_proof_capture_after_for_test(
            1,
            || operation.read_base_receiver_context_with_state_for_test(&instance_locator, &cancellation),
        )
        .unwrap()
        .expect("selected Base proof")
    });
    let (refused_fill, pending_after_refused_fill, base_memo_after_refused_fill) = refused_fill;
    assert_eq!(
        refused_fill.receipt,
        SelectedReceiverProofReceipt::Unretained
    );
    assert!(refused_fill.usable_receipt.is_none());
    assert!(refused_fill.observation.canonical_answer.is_some());
    assert!(refused_fill.observation.answer.is_none());
    assert!(pending_after_refused_fill.is_empty());
    assert!(!base_memo_after_refused_fill);
    assert!(refused_reads.reuse_refused());
    assert_eq!(
        refused_reads
            .keys()
            .iter()
            .filter(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::SelectedReceiverProof,
                    ..
                }
            ))
            .count(),
        2,
        "the complete nested proof read set, including its refusal, forwards to the enclosing ledger"
    );

    let this_shared_start = child.find("this.Shared()").unwrap() + "this.".len();
    let this_shared_locator = SelectedSemanticLocator::for_reference_range(
        "csharp",
        "App/Child.cs",
        this_shared_start,
        this_shared_start + "Shared".len(),
    );
    let run_this_query = || {
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
            panic!("selected C# current-instance operation");
        };
        let context = operation
            .empty_contexts(&ResolutionCompletion::Complete)
            .unwrap();
        operation.resolve_native_type_site_bounded(
            context,
            &this_shared_locator,
            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
            &cancellation,
            &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics,
        )
    };
    let (_native_result, native_reads) =
        capture_query_reads(workspace.analyzer(), || run_this_query().unwrap());
    assert!(
        native_reads.keys().iter().any(|key| matches!(
            key,
            ReadKey::Lookup {
                kind: LookupKind::SelectedReceiverProof,
                question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::SelectedReceiverProof(
                    brokk_bifrost_semantic::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion::CurrentInstanceTransfer { .. }
                ),
                ..
            }
        )),
        "the normal C# worklist reaches a current-instance transfer proof: {:?}",
        native_reads.keys()
    );

    let (refused_capture, capture_hits) =
        brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_current_instance_receiver_proof_capture_for_test(
            || capture_query_reads(workspace.analyzer(), || run_this_query().unwrap()),
        );
    let (refused_capture, refused_capture_reads) = refused_capture;
    assert!(
        capture_hits > 0,
        "the ordinary C# query captured its real transfer proof {capture_hits} times"
    );
    assert!(refused_capture_reads.reuse_refused());
    assert!(refused_capture_reads.keys().iter().any(|key| matches!(
        key,
        ReadKey::Lookup {
            kind: LookupKind::SelectedReceiverProof,
            question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::SelectedReceiverProof(
                brokk_bifrost_semantic::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion::CurrentInstanceTransfer { .. }
            ),
            ..
        }
    )));
    let refused_completion = match &refused_capture {
        brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Complete {
            value: brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome::Native(
                brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated::Found(answer),
            ),
            ..
        } => answer.answer.completion(),
        _ => panic!("current-instance proof refusal preserves a terminal answer"),
    };
    assert!(
        matches!(
            refused_completion,
            ResolutionCompletion::Incomplete(reasons)
                if reasons.iter().any(|reason| matches!(
                    reason,
                    brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(_)
                ))
        ),
        "unpublishable current-instance proof must leave the receiver semantic gap open: {refused_completion:?}"
    );

    let (refused_replay, replay_hits) =
        brokk_bifrost_analysis::analyzer::native_points::with_unpublishable_current_instance_receiver_proof_replay_for_test(
            || capture_query_reads(workspace.analyzer(), run_this_query),
        );
    let replay_error = match refused_replay.0 {
        Err(error) => error,
        Ok(_) => panic!("a previously affirmative receiver cannot advance after replay refusal"),
    };
    assert!(
        replay_error
            .to_string()
            .contains("Previously affirmative receiver authority refused"),
        "{replay_error:?}"
    );
    assert!(
        replay_error.to_string().contains("CurrentInstanceTransfer"),
        "full proof context: {replay_error:?}"
    );
    assert!(
        replay_hits > 0,
        "the ordinary C# query replayed its captured transfer proof"
    );
    assert!(refused_replay.1.reuse_refused());
    assert!(refused_replay.1.keys().iter().any(|key| matches!(
        key,
        ReadKey::Lookup {
            kind: LookupKind::SelectedReceiverProof,
            question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::SelectedReceiverProof(
                brokk_bifrost_semantic::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion::CurrentInstanceTransfer { .. }
            ),
            ..
        }
    )));
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

// Exercise the selected store/installer/common-frame boundary, including empty
// written inventories. Expected parents are source declarations, not model IDs.
fn check_normalized_csharp_roots(files: &[(&str, &str)], cases: &[(&str, &str, Option<&str>)]) {
    use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        SelectedNativeDefinition, SelectedNativeDefinitions, SelectedResolutionOperationOutcome,
    };
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    let mut builder = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />");
    for &(path, text) in files {
        builder = builder.file(path, text);
    }
    let fixture = builder.build();
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
        brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
    >(workspace.analyzer())
    .expect("C# analyzer");
    let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(analyzer);
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            analyzer,
        );
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
    // Selected operations retain a reader. Load source units before opening
    // it so the analyzer can record its selected parse-variant read.
    let units = cases
        .iter()
        .map(|&(file, name, _)| {
            let declarations = analyzer.declarations(&fixture.file(file));
            declarations
                .iter()
                .find(|unit| unit.identifier() == name && unit.is_class())
                .cloned()
                .unwrap_or_else(|| panic!("source type {name} in {file}: {declarations:?}"))
        })
        .collect::<Vec<_>>();
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
        panic!("selected root operation");
    };
    for ((_, name, expected), unit) in cases.iter().zip(&units) {
        let session = ResolutionSession::unbounded();
        let outcome = operation
            .selected_normalized_direct_parents(unit, &cancellation, &session)
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(answer) = outcome else {
            panic!("{name}: {outcome:?}");
        };
        if let Some(expected) = expected {
            assert_eq!(
                answer.completion,
                ResolutionCompletion::Complete,
                "{name}: {answer:?}"
            );
            assert!(
                answer
                    .parents
                    .iter()
                    .all(|parent| parent.completion == ResolutionCompletion::Complete),
                "{name}: {answer:?}"
            );
            let targets = answer
                .parents
                .iter()
                .flat_map(|parent| parent.targets.iter().copied())
                .collect::<Vec<_>>();
            let SelectedNativeDefinitions::Ready(units) = operation
                .selected_hierarchy_definition_units(&targets, &cancellation, &session)
                .unwrap()
            else {
                panic!("root units");
            };
            let names = units
                .into_iter()
                .map(|(_, definition)| match definition {
                    SelectedNativeDefinition::Unit(unit) => unit.fq_name().to_string(),
                    other => panic!("expected source root: {other:?}"),
                })
                .collect::<Vec<_>>();
            let expected = if expected.is_empty() {
                Vec::new()
            } else {
                vec![(*expected).to_owned()]
            };
            assert_eq!(names, expected, "{name}: {answer:?}");
            assert!(
                answer
                    .parents
                    .iter()
                    .all(|parent| parent.reference != parent.frontier),
                "whole-type frontier retained: {answer:?}"
            );
        } else {
            assert_ne!(
                answer.completion,
                ResolutionCompletion::Complete,
                "open owner {name}: {answer:?}"
            );
            assert!(
                answer.parents.iter().all(|parent| !matches!(parent.kind,
                    Some(brokk_bifrost_analysis::analyzer::resolution::NominalSupertypeKind::ImplicitSuperclass))
                    || parent.completion != ResolutionCompletion::Complete),
                "open written evidence cannot prove an implicit class parent: {name}: {answer:?}"
            );
            assert!(
                answer
                    .parents
                    .iter()
                    .all(|parent| parent.completion != ResolutionCompletion::Complete),
                "{name}: {answer:?}"
            );
        }
    }
}

#[test]
fn csharp_selected_roots_keep_partial_and_interface_frontiers_open() {
    if run_csharp_root_trial("csharp_selected_roots_keep_partial_and_interface_frontiers_open") {
        return;
    }
    check_normalized_csharp_roots(
        &[
            (
                "App/Core.cs",
                "namespace System { public class Object {} public class ValueType : Object {} public class Enum : ValueType {} }",
            ),
            (
                "App/Types.cs",
                "namespace Cases { public class Plain {} public record Record {} public struct S {} public record struct RS {} public enum E { Zero } public interface I {} public class B {} public class HasB : B {} public partial class Split {} }",
            ),
            (
                "App/Second.cs",
                "namespace Cases { public partial class Split : B {} }",
            ),
        ],
        &[
            ("App/Core.cs", "Object", Some("")),
            ("App/Types.cs", "Plain", Some("System.Object")),
            ("App/Types.cs", "Record", Some("System.Object")),
            ("App/Types.cs", "S", Some("System.ValueType")),
            ("App/Types.cs", "RS", Some("System.ValueType")),
            ("App/Types.cs", "E", Some("System.Enum")),
            ("App/Types.cs", "HasB", Some("Cases.B")),
            ("App/Types.cs", "I", Some("")),
            ("App/Types.cs", "Split", None),
            ("App/Second.cs", "Split", None),
        ],
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: direct invalid-base classification was lost before implicit-root decisions"
)]
fn csharp_invalid_authored_parents_keep_direct_and_root_authority_open() {
    if run_csharp_root_trial("csharp_invalid_authored_parents_keep_direct_and_root_authority_open")
    {
        return;
    }
    // Keep each invalid construct in its own selected compilation so an
    // unrelated unsupported declaration cannot make this control open first.
    for (name, target, child) in [
        (
            "InvalidStruct",
            "public struct S {}",
            "public class InvalidStruct : S {}",
        ),
        (
            "InvalidEnum",
            "public enum E { Zero }",
            "public class InvalidEnum : E {}",
        ),
        (
            "InvalidDelegate",
            "public delegate void D();",
            "public class InvalidDelegate : D {}",
        ),
        (
            "InvalidParameter`1",
            "",
            "public class InvalidParameter<T> : T {}",
        ),
        (
            "InvalidAlias",
            "public struct S {}",
            "using Bad = global::Cases.S; public class InvalidAlias : Bad {}",
        ),
    ] {
        check_normalized_csharp_roots(
            &[
                (
                    "App/Core.cs",
                    "namespace System { public class Object {} public class ValueType : Object {} public class Enum : ValueType {} }",
                ),
                ("App/Target.cs", &format!("namespace Cases {{ {target} }}")),
                ("App/Child.cs", &format!("namespace Cases {{ {child} }}")),
            ],
            &[("App/Child.cs", name, None)],
        );
    }
}

#[test]
fn csharp_proved_class_parent_does_not_require_an_object_inventory() {
    if run_csharp_root_trial("csharp_proved_class_parent_does_not_require_an_object_inventory") {
        return;
    }
    check_normalized_csharp_roots(
        &[(
            "App/Types.cs",
            "using OuterChosen = Cases.B; namespace Cases { using Chosen = global::Cases.B; public class B {} public class C : B {} public class Shadow : B { public class B {} } public class GBase<T> {} public class Generic<T> : GBase<T> {} public class AliasChild : Chosen {} public class OuterAlias : OuterChosen {} public class Outer { public class Nested {} public class Child : Nested {} } }",
        )],
        &[
            ("App/Types.cs", "C", Some("Cases.B")),
            ("App/Types.cs", "Shadow", Some("Cases.B")),
            ("App/Types.cs", "Generic`1", Some("Cases.GBase`1")),
            ("App/Types.cs", "Child", Some("Cases.Outer$Nested")),
            ("App/Types.cs", "AliasChild", Some("Cases.B")),
            // An unindexed assembly can supply Cases.OuterChosen before
            // lookup reaches the compilation-unit alias. Do not erase it.
            ("App/Types.cs", "OuterAlias", None),
        ],
    );
}

fn run_csharp_root_trial(name: &str) -> bool {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("engine_tests::csharp_demand::{name}"),
            "--nocapture",
        ])
        .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: binding-only member projection must preserve unmodeled invocation applicability"
)]
fn csharp_binding_only_member_invocation_remains_open() {
    if run_csharp_root_trial("csharp_binding_only_member_invocation_remains_open") {
        return;
    }
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
    };
    let source = "public class C { public void M() {} public void Probe() { this.M(); } }";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>")
        .file("App/obj/project.assets.json", "{\"project\":{\"restore\":{\"originalTargetFrameworks\":[\"net10.0\"]}}}")
        .file("App/obj/App.csproj.nuget.g.props", "<Project/>")
        .file("App/obj/App.csproj.nuget.g.targets", "<Project/>")
        .file("App/System.cs", "namespace System { public class Object {} }")
        .file("App/Caller.cs", source)
        .build();
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap(),
    )
    .unwrap();
    let file = brokk_bifrost_core::analyzer::ProjectFile::new(
        fixture.project_dyn().root(),
        "App/Caller.cs",
    );
    let start = source.find("this.M").unwrap() + "this.".len();
    let outcomes = resolve_definition_batch_with_source(
        workspace.analyzer(),
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + 1),
        }],
        file,
        source.into(),
    );
    let [outcome] = outcomes.as_slice() else {
        panic!("actual invocation outcomes: {outcomes:?}")
    };
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    assert_eq!(
        outcome.definitions.len(),
        1,
        "the actual member inventory must find M: {outcome:?}"
    );
    assert_eq!(outcome.definitions[0].fq_name_str(), "C.M");
    let applicability = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.kind == "csharp_method_applicability_unmodeled")
        .collect::<Vec<_>>();
    assert_eq!(applicability.len(), 1, "{outcome:?}");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding"),
        "{outcome:?}"
    );
    println!("CSHARP_BINDING_ONLY_INVOCATION {outcome:#?}");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: source-member access uncertainty suppressed every selected placement"
)]
fn csharp_source_member_routes_keep_access_open() {
    if run_csharp_root_trial("csharp_source_member_routes_keep_access_open") {
        return;
    }
    use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_references;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    let source = "namespace Cases { public class C { public static void Public() {} private static void Hidden() {} } public class Use { public void Test() { C.Public(); C.Hidden(); C.Missing(); } } }";
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
    let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
        brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
    >(workspace.analyzer())
    .unwrap();
    let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(analyzer);
    let expected_public = analyzer
        .declarations(&fixture.file("App/Caller.cs"))
        .into_iter()
        .find(|unit| unit.is_function() && unit.identifier() == "Public")
        .unwrap()
        .fq_name_str()
        .to_owned();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            analyzer,
        );
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
        panic!("source member operation");
    };
    let names = ["Public", "Hidden", "Missing"];
    let locators = names.map(|name| {
        let start = source.find(&format!("C.{name}()")).unwrap() + 2;
        SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Caller.cs",
            start,
            start + name.len(),
        )
    });
    let probes = probe_references(&operation, &snapshots["csharp"], &locators, &cancellation)
        .unwrap()
        .unwrap();
    assert_eq!(probes.len(), names.len());
    for (name, probe) in names.into_iter().zip(probes) {
        eprintln!(
            "{name}: {:?}; {:?}; {:?}",
            probe.targets, probe.completion, probe.named_reasons
        );
        assert_ne!(
            probe.completion,
            ResolutionCompletion::Complete,
            "access is not proved: {name}"
        );
        assert!(
            probe
                .named_reasons
                .iter()
                .any(|(kind, _)| *kind == "csharp_member_access_unmodeled"),
            "the exact access gap must survive every placement: {name}: {:?}",
            probe.named_reasons
        );
        if name == "Missing" {
            assert!(probe.targets.is_empty(), "missing member has no target");
        }
        if name == "Public" {
            assert_eq!(
                probe.targets,
                vec![("App/Caller.cs".to_owned(), expected_public.clone())],
                "real public source target with access still Open"
            );
        }
    }
}

const PRIVATE_ORDINARY_ACCESS_CALLER: &str = "public class Use { public void Probe(Derived d, Part p) { d.Hidden(); d.Hidden(); d.Pick(\"value\"); p.Hidden(); } }";
const PRIVATE_ACCESS_CALLER: &str = "public class Use : Derived { public void Probe() { this.Hidden(); this.Hidden(); this.Pick(\"value\"); } } public class PartUse : Part { public void Probe() { this.Hidden(); } }";
const PRIVATE_ACCESS_TARGETS: &str = "public class Derived : Base { private void Hidden() {} private void Pick(System.String value) {} private void Helper() {} public void Inside() { this.Hidden(); this.Helper(); this.Helper(); } } public partial class Part : Base { private void Hidden() {} }";

fn private_access_project(targets: &str) -> InlineTestProject {
    InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>")
        .file("App/obj/project.assets.json", "{\"project\":{\"restore\":{\"originalTargetFrameworks\":[\"net10.0\"]}}}")
        .file("App/obj/App.csproj.nuget.g.props", "<Project/>")
        .file("App/obj/App.csproj.nuget.g.targets", "<Project/>")
        .file("App/System.cs", "namespace System { public class Object {} public class String : Object {} }")
        .file("App/Base.cs", "public class Base { public void Hidden() {} public void Pick(System.Object value) {} }")
        .file("App/Targets.cs", targets)
        .file("App/Caller.cs", PRIVATE_ACCESS_CALLER)
}

fn private_access_native_lookup(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    file: brokk_bifrost_core::analyzer::ProjectFile,
    source: &str,
    prefix: &str,
    member: &str,
) -> (
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome,
    usize,
    Vec<brokk_bifrost_analysis::analyzer::read_ledger::ReadKey>,
) {
    let start = source.find(&format!("{prefix}.{member}")).unwrap() + prefix.len() + 1;
    private_access_native_lookup_at(analyzer, file, source, start, start + member.len())
}

fn private_access_native_lookup_at(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    file: brokk_bifrost_core::analyzer::ProjectFile,
    source: &str,
    start: usize,
    end: usize,
) -> (
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome,
    usize,
    Vec<brokk_bifrost_analysis::analyzer::read_ledger::ReadKey>,
) {
    use brokk_bifrost_analysis::analyzer::native_points::{
        native_point_operation_open_count_for_test,
        reset_native_point_operation_open_count_for_test,
    };
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        DefinitionLookupRequest, resolve_definition_batch_with_source,
    };
    let ledger =
        std::sync::Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
    let scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_read_ledger(
        analyzer,
        std::sync::Arc::clone(&ledger),
    );
    reset_native_point_operation_open_count_for_test();
    let outcomes = resolve_definition_batch_with_source(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(end),
        }],
        file,
        source.into(),
    );
    let native_entries = native_point_operation_open_count_for_test();
    let [outcome] = outcomes.as_slice() else {
        panic!("one normal point request: {outcomes:#?}");
    };
    let outcome = outcome.clone();
    drop(scope);
    (outcome, native_entries, ledger.keys())
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: private admission needed complete containing-type authority for nested and sibling callers"
)]
fn csharp_private_access_containing_types_distinguish_nested_sibling_partial_and_lambda() {
    if run_csharp_root_trial(
        "csharp_private_access_containing_types_distinguish_nested_sibling_partial_and_lambda",
    ) {
        return;
    }
    let source = "public class Owner { private static void Secret() {} public class Nested { public void Probe() { Owner.Secret(); var action = () => Owner.Secret(); } } public class Other { private static void Secret() {} } public class Sibling { public void Probe() { Other.Secret(); } } public partial class Partial { public void Probe() { Owner.Secret(); } } }";
    let fixture = private_access_project(PRIVATE_ACCESS_TARGETS)
        .file("App/Owners.cs", source)
        .build();
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap(),
    )
    .unwrap();
    let points = source
        .match_indices("Owner.Secret")
        .map(|(start, _)| start + 6)
        .collect::<Vec<_>>();
    assert_eq!(points.len(), 3);
    let sibling = source.find("Other.Secret").unwrap() + 6;
    let cases = [points[0], points[1], sibling, points[2]].map(|start| {
        private_access_native_lookup_at(
            workspace.analyzer(),
            fixture.file("App/Owners.cs"),
            source,
            start,
            start + 6,
        )
    });
    println!("PRIVATE_CONTAINING_TYPE_NATIVE_CASES {cases:#?}");
    for (outcome, entries, _) in &cases {
        assert!(*entries > 0, "actual public native branch: {outcome:#?}");
    }
    for ordinal in [0, 1] {
        let outcome = &cases[ordinal].0;
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name_str())
                .collect::<Vec<_>>(),
            ["Owner.Secret"],
            "nested/lambda {ordinal}: {outcome:#?}"
        );
        assert!(
            !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "csharp_private_access_unknown"),
            "{outcome:#?}"
        );
    }
    let sibling = &cases[2].0;
    assert!(
        sibling.definitions.is_empty(),
        "complete sibling chain cannot access Other's private member: {sibling:#?}"
    );
    assert!(
        !sibling
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "csharp_private_access_unknown"),
        "{sibling:#?}"
    );
    let partial = &cases[3].0;
    assert!(
        partial
            .definitions
            .iter()
            .any(|unit| unit.fq_name_str() == "Owner.Secret"),
        "unproven partial chain retains the candidate: {partial:#?}"
    );
    assert!(
        partial
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "csharp_private_access_unknown"),
        "{partial:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: private admission must preserve accessible bases without poisoning public synthetic roots"
)]
fn csharp_private_candidates_preserve_accessible_alternatives_and_partial_uncertainty() {
    if run_csharp_root_trial(
        "csharp_private_candidates_preserve_accessible_alternatives_and_partial_uncertainty",
    ) {
        return;
    }
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
    let fixture = private_access_project(PRIVATE_ACCESS_TARGETS).build();
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap(),
    )
    .unwrap();
    let caller = fixture.file("App/Caller.cs");
    let target = fixture.file("App/Targets.cs");
    let cases = [
        private_access_native_lookup(
            workspace.analyzer(),
            caller.clone(),
            PRIVATE_ACCESS_CALLER,
            "this",
            "Hidden",
        ),
        private_access_native_lookup(
            workspace.analyzer(),
            caller.clone(),
            PRIVATE_ACCESS_CALLER,
            "this",
            "Pick",
        ),
        private_access_native_lookup(
            workspace.analyzer(),
            target,
            PRIVATE_ACCESS_TARGETS,
            "this",
            "Helper",
        ),
        private_access_native_lookup_at(
            workspace.analyzer(),
            caller,
            PRIVATE_ACCESS_CALLER,
            PRIVATE_ACCESS_CALLER.rfind("this.Hidden").unwrap() + 5,
            PRIVATE_ACCESS_CALLER.rfind("this.Hidden").unwrap() + 11,
        ),
    ];
    println!("PRIVATE_ACCESS_NATIVE_CASES {cases:#?}");
    for (ordinal, (outcome, entries, _)) in cases.iter().enumerate() {
        assert!(
            *entries > 0,
            "normal native branch must execute: {outcome:#?}"
        );
        let expected = if ordinal == 3 {
            DefinitionLookupStatus::Ambiguous
        } else {
            DefinitionLookupStatus::Incomplete
        };
        assert_eq!(outcome.status, expected, "{outcome:#?}");
    }
    let names = cases
        .iter()
        .map(|(outcome, _, _)| {
            outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name_str().to_owned())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(names[0], ["Base.Hidden"]);
    assert_eq!(names[1], ["Base.Pick"]);
    assert_eq!(names[2], ["Derived.Helper"]);
    assert!(
        names[3].iter().any(|name| name == "Part.Hidden"),
        "partial candidate stays visible: {cases:#?}"
    );
    assert!(
        names[3].iter().any(|name| name == "Base.Hidden"),
        "unknown private does not hide the base: {cases:#?}"
    );
    for (outcome, _, _) in &cases[..3] {
        assert!(
            !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "csharp_private_access_unknown"),
            "known nonpartial contexts and nonmember binders do not introduce private uncertainty: {outcome:#?}"
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "csharp_method_applicability_unmodeled"),
            "invocation remains unmodeled: {outcome:#?}"
        );
    }
    for kind in [
        "csharp_private_access_unknown",
        "partial_type_written_parents_open",
        "incomplete_binding",
    ] {
        assert!(
            cases[3]
                .0
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == kind),
            "partial ambiguity must retain {kind}: {cases:#?}"
        );
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: denied private candidate source dependence must survive candidate and signature capture replacement"
)]
fn csharp_denied_private_file_certificate_replays_source_changes_and_rejects_binding_mismatch() {
    if run_csharp_root_trial(
        "csharp_denied_private_file_certificate_replays_source_changes_and_rejects_binding_mismatch",
    ) {
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
    use brokk_bifrost_analysis::analyzer::read_verification::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        SelectedAnalyzerServices, SelectedSourceFileCertificate,
    };
    let fixture = private_access_project(PRIVATE_ACCESS_TARGETS).build();
    let base = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap(),
    )
    .unwrap();
    let (outcome, entries, keys) = private_access_native_lookup(
        base.analyzer(),
        fixture.file("App/Caller.cs"),
        PRIVATE_ACCESS_CALLER,
        "this",
        "Hidden",
    );
    println!("PRIVATE_DENIED_READS {outcome:#?} entries={entries} keys={keys:#?}");
    assert!(entries > 0);
    assert_eq!(
        outcome
            .definitions
            .iter()
            .map(|unit| unit.fq_name_str())
            .collect::<Vec<_>>(),
        ["Base.Hidden"]
    );
    let owner_keys = keys.iter().filter(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "App/Targets.cs")).cloned().collect::<Vec<_>>();
    let stable_keys = keys.iter().filter(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "App/Base.cs")).cloned().collect::<Vec<_>>();
    assert_eq!(
        owner_keys.len(),
        1,
        "one explicit owner input despite denied target: {keys:#?}"
    );
    assert_eq!(
        stable_keys.len(),
        1,
        "stable base source control: {keys:#?}"
    );
    let changed_source = format!("\n\n{PRIVATE_ACCESS_TARGETS}\n");
    let changed_fixture = private_access_project(&changed_source).build();
    let head = WorkspaceAnalyzer::build_with_store_context_for_test(
        changed_fixture.project_dyn(),
        AnalyzerConfig::default(),
        ephemeral_store_context(changed_fixture.project_dyn().as_ref()).unwrap(),
    )
    .unwrap();
    let changed = ChangedFacts::between(&base, &head);
    let verify = |reads: &[ReadKey]| {
        verify_read_set(
            &head,
            &changed,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            reads,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
    };
    let changed_owner = verify(&owner_keys);
    assert!(matches!(changed_owner.changed().map(|changed| &changed.reason), Some(brokk_bifrost_analysis::analyzer::invalidation::InvalidationReason::InputContentChanged { .. })), "owner bytes changed, not missing authority: {changed_owner:?}");
    assert_eq!(
        std::fs::read(fixture.file("App/Caller.cs").abs_path()).unwrap(),
        std::fs::read(changed_fixture.file("App/Caller.cs").abs_path()).unwrap()
    );
    assert_eq!(verify(&stable_keys), ReadVerdict::Unchanged);
    let restored_fixture = private_access_project(PRIVATE_ACCESS_TARGETS).build();
    let restored = WorkspaceAnalyzer::build_with_store_context_for_test(
        restored_fixture.project_dyn(),
        AnalyzerConfig::default(),
        ephemeral_store_context(restored_fixture.project_dyn().as_ref()).unwrap(),
    )
    .unwrap();
    let unchanged = ChangedFacts::between(&base, &restored);
    assert_eq!(
        verify_read_set(
            &restored,
            &unchanged,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &owner_keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new()
        ),
        ReadVerdict::Unchanged
    );
    let ReadKey::File {
        blob,
        parse_variant,
        ..
    } = owner_keys[0]
    else {
        unreachable!()
    };
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            base.analyzer(),
        );
    let file = fixture.file("App/Targets.cs");
    let mut wrong_variant = parse_variant;
    match &mut wrong_variant {
        brokk_bifrost_core::gitblob::ParseVariant::Empty => {
            wrong_variant = brokk_bifrost_core::gitblob::ParseVariant::Digest([0; 32])
        }
        brokk_bifrost_core::gitblob::ParseVariant::Digest(value) => value[0] ^= 1,
    }
    let epoch = brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch();
    for (label, variant, producer, accepted) in [
        ("matching", parse_variant, epoch, true),
        ("wrong-variant", wrong_variant, epoch, false),
        (
            "wrong-producer",
            parse_variant,
            "unselected-producer",
            false,
        ),
    ] {
        let ledger =
            std::sync::Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
        let scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_read_ledger(
            base.analyzer(),
            std::sync::Arc::clone(&ledger),
        );
        let actual = services.certify_selected_source_file(&SelectedSourceFileCertificate {
            file: &file,
            oid: blob,
            parse_variant: variant,
            producer_epoch: producer,
        });
        drop(scope);
        println!(
            "PRIVATE_SOURCE_CERTIFICATE {label} accepted={actual} keys={:#?} reuse_refused={} unattributed={}",
            ledger.keys(),
            ledger.reuse_refused(),
            ledger.unattributed_reads()
        );
        assert_eq!(actual, accepted, "{label}");
        assert_eq!(
            ledger.is_bounded(),
            accepted,
            "each source certificate owns an independent receipt: {label}"
        );
        if accepted {
            assert!(ledger.keys().iter().any(|key| matches!(key, ReadKey::File { rel_path, blob: observed, parse_variant: observed_variant, .. } if rel_path.as_ref() == "App/Targets.cs" && *observed == blob && *observed_variant == parse_variant)));
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: caller-independent hierarchy entries shared private admission across inside and outside references"
)]
fn csharp_private_access_contexts_share_same_type_entries_and_preserve_request_order() {
    if run_csharp_root_trial(
        "csharp_private_access_contexts_share_same_type_entries_and_preserve_request_order",
    ) {
        return;
    }
    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::{
        access_context_cross_site_reuses_for_test, reset_access_context_cross_site_reuses_for_test,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_references;
    let fixture = private_access_project(PRIVATE_ACCESS_TARGETS).build();
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let (outside, entries, _) = private_access_native_lookup(
        workspace.analyzer(),
        fixture.file("App/Caller.cs"),
        PRIVATE_ACCESS_CALLER,
        "this",
        "Hidden",
    );
    println!("PRIVATE_CONTEXT_PUBLIC_CONTROL {outside:#?} native_entries={entries}");
    assert!(entries > 0);
    assert_eq!(
        outside
            .definitions
            .iter()
            .map(|unit| unit.fq_name_str())
            .collect::<Vec<_>>(),
        ["Base.Hidden"]
    );
    let caller_sites = PRIVATE_ACCESS_CALLER
        .match_indices("this.Hidden")
        .take(2) // The two real call sites in Use share one enclosing type.
        .map(|(start, _)| start + 5)
        .collect::<Vec<_>>();
    assert_eq!(caller_sites.len(), 2);
    let inside = PRIVATE_ACCESS_TARGETS.find("this.Hidden").unwrap() + 5;
    let locators = [
        SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Caller.cs",
            caller_sites[0],
            caller_sites[0] + 6,
        ),
        SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Targets.cs",
            inside,
            inside + 6,
        ),
        SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Caller.cs",
            caller_sites[1],
            caller_sites[1] + 6,
        ),
    ];
    let context_reads =
        std::sync::Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
    let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_read_ledger(
        workspace.analyzer(),
        std::sync::Arc::clone(&context_reads),
    );
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            workspace.analyzer(),
        );
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
    let run = |locators: &[SelectedSemanticLocator]| {
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
            panic!("normal selected context operation");
        };
        probe_references(&operation, &snapshots["csharp"], locators, &cancellation)
            .unwrap()
            .expect("real admitted source references")
    };
    reset_access_context_cross_site_reuses_for_test();
    let forward = run(&locators);
    let reuse = access_context_cross_site_reuses_for_test();
    let reversed_locators = locators.iter().rev().cloned().collect::<Vec<_>>();
    let mut reverse = run(&reversed_locators);
    reverse.reverse();
    let fresh = locators
        .iter()
        .map(|locator| run(std::slice::from_ref(locator)).remove(0))
        .collect::<Vec<_>>();
    println!(
        "PRIVATE_CONTEXT_FORWARD {forward:#?}\nPRIVATE_CONTEXT_REVERSE {reverse:#?}\nPRIVATE_CONTEXT_FRESH {fresh:#?}\nSAME_TYPE_CROSS_SITE_ENTRY_REUSES {reuse}"
    );
    assert!(
        reuse > 0,
        "distinct references from the same nonpartial type must hit the same actual hierarchy entry"
    );
    for index in 0..locators.len() {
        assert_eq!(forward[index].targets, fresh[index].targets);
        assert_eq!(reverse[index].targets, fresh[index].targets);
        assert_eq!(forward[index].named_reasons, fresh[index].named_reasons);
        assert_eq!(reverse[index].named_reasons, fresh[index].named_reasons);
    }
    assert!(
        forward[0]
            .targets
            .iter()
            .all(|(_, name)| name == "Base.Hidden")
    );
    assert!(
        forward[2]
            .targets
            .iter()
            .all(|(_, name)| name == "Base.Hidden")
    );
    assert!(
        forward[1]
            .targets
            .iter()
            .any(|(_, name)| name == "Derived.Hidden"),
        "same-class private target retained: {forward:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: selected mount variant projection referenced a nonexistent TEMP column instead of the selected blob key"
)]
fn csharp_selected_access_source_round_trips_the_selected_blob_variant() {
    if run_csharp_root_trial("csharp_selected_access_source_round_trips_the_selected_blob_variant")
    {
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::{ReadKey, ReadLedger};
    use brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedSemanticLookupOutcome;
    use brokk_bifrost_analysis::native_resolution_test_support::SelectedTypedFactSource;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    let fixture = private_access_project(PRIVATE_ACCESS_TARGETS)
        .file("App/Caller.cs", PRIVATE_ORDINARY_ACCESS_CALLER)
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
    let file = fixture.file("App/Caller.cs");
    let expected_oid = workspace
        .analyzer()
        .indexed_blob_oid(&file)
        .expect("real indexed source");
    let expected_variant = workspace
        .analyzer()
        .selected_parse_variant(&file)
        .expect("real configured source decision");
    assert_ne!(
        expected_variant,
        brokk_bifrost_core::gitblob::ParseVariant::Empty
    );
    let ledger = std::sync::Arc::new(ReadLedger::new());
    let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_read_ledger(
        workspace.analyzer(),
        std::sync::Arc::clone(&ledger),
    );
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            workspace.analyzer(),
        );
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let project = fixture.project_dyn();
    let cancellation = CancellationToken::new();
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
        panic!("real selected source inventory");
    };
    let start = PRIVATE_ORDINARY_ACCESS_CALLER.find("d.Hidden").unwrap() + 2;
    let locator =
        SelectedSemanticLocator::for_reference_range("csharp", "App/Caller.cs", start, start + 6);
    let lexical = operation.ready().lexical_source();
    let SelectedSemanticLookupOutcome::Found(found) = lexical
        .lookup_semantic_sites(&locator, &cancellation, &ResolutionSession::unbounded())
        .unwrap()
    else {
        panic!("normal selected reference");
    };
    assert_eq!(found.len(), 1);
    let source = operation
        .ready()
        .typed_source()
        .selected_access_reference(found[0].semantic(), &cancellation)
        .unwrap()
        .expect("canonical selected reference with File authority");
    println!(
        "SELECTED_ACCESS_SOURCE_ROUNDTRIP {source:#?}\nREADS {:#?}",
        ledger.keys()
    );
    assert_eq!(source.source.file, file);
    assert_eq!(
        (source.source.start_byte, source.source.end_byte),
        (start, start + 6)
    );
    assert!(source.owner.flatten().is_some());
    let files = ledger.keys().into_iter().filter(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref()=="App/Caller.cs")).collect::<Vec<_>>();
    assert_eq!(files.len(), 1);
    assert!(
        matches!(&files[0], ReadKey::File { blob, parse_variant, .. } if *blob==expected_oid && *parse_variant==expected_variant)
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: genuine lexical parameters and type formals were misclassified as unproven private members"
)]
fn csharp_private_access_keeps_lexical_formals_out_of_member_admission_and_receiver_ready() {
    if run_csharp_root_trial(
        "csharp_private_access_keeps_lexical_formals_out_of_member_admission_and_receiver_ready",
    ) {
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::{
        LookupKind, LookupQuestion, ReadKey, ReadLedger,
    };
    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::receiver_proof::CurrentInstanceTransferObservation;
    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::receiver_proof_tests::{
        ReceiverProofTestDecorator, install_receiver_proof_test_decorator,
    };
    use brokk_bifrost_analysis::analyzer::resolution::{
        ConditionalTypeSeedRead, ResolutionCompletion, ResolutionSlotValue,
    };
    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::{
        SelectedReceiverProofAnswer, SelectedReceiverProofQuestion,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_current_instance_receiver_frontier;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        SelectedResolutionLocated, SelectedResolutionOperationOutcome,
    };
    #[derive(Default)]
    struct Observe {
        seeds: std::sync::Mutex<Vec<(String, ConditionalTypeSeedRead)>>,
        installed: std::sync::Mutex<Vec<SelectedReceiverProofQuestion>>,
        transfers: std::sync::Mutex<
            Vec<(
                SelectedReceiverProofQuestion,
                CurrentInstanceTransferObservation,
            )>,
        >,
    }
    impl ReceiverProofTestDecorator for Observe {
        fn conditional_seed_evaluated(&self, source_path: &str, read: &ConditionalTypeSeedRead) {
            if matches!(source_path, "App/Generic.cs" | "App/Z.cs") {
                self.seeds
                    .lock()
                    .unwrap()
                    .push((source_path.to_owned(), read.clone()));
            }
        }
        fn installed_read(&self, question: &SelectedReceiverProofQuestion) {
            if matches!(
                question.source().rel_path.as_ref(),
                "App/Generic.cs" | "App/Z.cs"
            ) {
                self.installed.lock().unwrap().push(question.clone());
            }
        }
        fn transfer_proof_read(
            &self,
            question: &SelectedReceiverProofQuestion,
            read: &CurrentInstanceTransferObservation,
        ) {
            if matches!(
                question.source().rel_path.as_ref(),
                "App/Generic.cs" | "App/Z.cs"
            ) {
                self.transfers
                    .lock()
                    .unwrap()
                    .push((question.clone(), read.clone()));
            }
        }
    }
    let generic = "public class Generic<T> { private T saved; public void Known() {} public void Probe(T argument) { var local = argument; this.Known(); } }";
    let zero = "public class Z { public void Known() {} public void Probe() { this.Known(); } }";
    let fixture = private_access_project(PRIVATE_ACCESS_TARGETS)
        .file("App/Generic.cs", generic)
        .file("App/Z.cs", zero)
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
    let observed = std::sync::Arc::new(Observe::default());
    let _observation = install_receiver_proof_test_decorator(observed.clone());
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let project = fixture.project_dyn();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            workspace.analyzer(),
        );
    let mut receiver_cases = Vec::new();
    for (path, source) in [("App/Generic.cs", generic), ("App/Z.cs", zero)] {
        observed.seeds.lock().unwrap().clear();
        observed.installed.lock().unwrap().clear();
        observed.transfers.lock().unwrap().clear();
        let ledger = std::sync::Arc::new(ReadLedger::new());
        let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_read_ledger(
            workspace.analyzer(),
            ledger.clone(),
        );
        let cancellation = CancellationToken::new();
        let SelectedResolutionOperationOpenOutcome::Ready(mut operation) = store
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
            panic!("normal selected receiver operation")
        };
        let start = source.find("this.Known").unwrap() + 5;
        let locator =
            SelectedSemanticLocator::for_reference_range("csharp", path, start, start + 5);
        let outcome =
            probe_current_instance_receiver_frontier(&mut operation, &locator, &cancellation)
                .unwrap();
        let seeds = observed.seeds.lock().unwrap().clone();
        let installed = observed.installed.lock().unwrap().clone();
        let transfers = observed.transfers.lock().unwrap().clone();
        let keys = ledger.keys();
        println!(
            "ACTUAL_CURRENT_INSTANCE_FRONTIER {path} {outcome:#?}\nHOOK_SEEDS {seeds:#?}\nINSTALLED {installed:#?}\nTRANSFER_PROOFS {transfers:#?}\nREAD_KEYS {keys:#?}"
        );
        receiver_cases.push((path, outcome, seeds, installed, transfers, keys));
    }
    let (member, member_entries, keys) = private_access_native_lookup(
        workspace.analyzer(),
        fixture.file("App/Generic.cs"),
        generic,
        "this",
        "Known",
    );
    let start = generic.rfind("argument").unwrap();
    let (parameter, parameter_entries, parameter_keys) = private_access_native_lookup_at(
        workspace.analyzer(),
        fixture.file("App/Generic.cs"),
        generic,
        start,
        start + 8,
    );
    println!(
        "GENERIC_PRIVATE_NONMEMBER_MEMBER {member:#?} native_entries={member_entries}\nGENERIC_PRIVATE_NONMEMBER_PARAMETER {parameter:#?} native_entries={parameter_entries}\nMEMBER_KEYS {keys:#?}\nPARAMETER_KEYS {parameter_keys:#?}"
    );
    assert!(member_entries > 0);
    assert_eq!(member.definitions.len(), 1, "{member:#?}");
    assert_eq!(member.definitions[0].identifier(), "Known");
    assert_eq!(
        parameter
            .lexical_definition
            .as_ref()
            .map(|definition| definition.identifier.as_str()),
        Some("argument")
    );
    for outcome in [&member, &parameter] {
        assert!(
            !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "csharp_private_access_unknown"),
            "canonical nonmember binders are not private candidates: {outcome:#?}"
        );
    }
    for (path, outcome, seeds, installed, transfers, keys) in receiver_cases {
        let Some(SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
            probe,
        ))) = outcome
        else {
            panic!("exact selected receiver authority and normal native demand are required")
        };
        let [frontier] = probe.answer.projected_frontiers() else {
            panic!("exact receiver frontier: {probe:#?}")
        };
        assert_eq!(frontier.slot(), probe.receiver);
        assert_eq!(
            frontier.completion(),
            &ResolutionCompletion::Complete,
            "{probe:#?}"
        );
        let [runtime] = frontier.possible_values() else {
            panic!("exact runtime receiver: {probe:#?}")
        };
        assert!(
            matches!(
                runtime,
                ResolutionSlotValue::Runtime {
                    addressable: false,
                    ..
                }
            ),
            "post-transfer Runtime, not owner TypeObject: {probe:#?}"
        );
        assert!(seeds.iter().any(|(actual_path, read)| actual_path == path && matches!(read,
            ConditionalTypeSeedRead::Ready(seed) if seed.slot == probe.application && matches!(seed.value, ResolutionSlotValue::TypeObject(..)) && seed.value.ty() == runtime.ty())),
            "the same exact generic/zeroarity owner application seeds this runtime: {seeds:#?}");
        let transfer_keys = keys
            .iter()
            .filter_map(|key| match key {
                ReadKey::Lookup {
                    kind: LookupKind::SelectedReceiverProof,
                    question: LookupQuestion::SelectedReceiverProof(question),
                    digest,
                } if question.source().rel_path.as_ref() == path
                    && matches!(
                        question,
                        SelectedReceiverProofQuestion::CurrentInstanceTransfer { .. }
                    ) =>
                {
                    Some((question, digest))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [transfer_key] = transfer_keys.as_slice() else {
            panic!("one real receiver proof question: {keys:#?}")
        };
        let (transfer_question, transfer_digest) = *transfer_key;
        assert!(
            installed.contains(transfer_question),
            "actual receiver Slot -> question node subscription: {installed:#?}"
        );
        assert!(
            !probe.expected_receiver_syntax_gaps.is_empty(),
            "this fixture publishes provisional receiver syntax gaps with exact provenance: {probe:#?}"
        );
        let semantic_complete = transfers
            .iter()
            .filter(|(question, read)| {
                question == transfer_question
                    && read.completion == Some(ResolutionCompletion::Complete)
            })
            .collect::<Vec<_>>();
        assert!(!semantic_complete.is_empty(), "{transfers:#?}");
        for (_, read) in semantic_complete {
            assert_eq!(
                read.discharged_gap_reasons, probe.expected_receiver_syntax_gaps,
                "only independently published exact-site UnsupportedTypeSyntax gaps may be discharged"
            );
            let Some(answer @ SelectedReceiverProofAnswer::ExhaustedIncomplete { .. }) =
                &read.answer
            else {
                panic!(
                    "canonical input observation preserves the raw provisional gap; no missing authority: {read:#?}"
                )
            };
            assert_eq!(
                transfer_digest,
                &answer.canonical_digest(),
                "the normal Lookup records that exact raw-input answer, not semantic Runtime completion"
            );
        }
        assert!(keys.iter().any(|key| matches!(key,
            ReadKey::Lookup { kind: LookupKind::SelectedReceiverProof, question: LookupQuestion::SelectedReceiverProof(SelectedReceiverProofQuestion::OwnerApplication { source, .. }), .. }
                if source.rel_path.as_ref() == path)), "normal owner/formal/argument receipt: {keys:#?}");
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: source-member access uncertainty suppressed every selected placement"
)]
fn csharp_absolute_source_member_routes_keep_access_open() {
    if run_csharp_root_trial("csharp_absolute_source_member_routes_keep_access_open") {
        return;
    }
    use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_references;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    let source = "namespace Cases { public class C { public static void Public() {} private static void Hidden() {} } public class Use { public void Test() { global::Cases.C.Public(); global::Cases.C.Hidden(); global::Cases.C.Missing(); } } }";
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
    let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
        brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
    >(workspace.analyzer())
    .unwrap();
    let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(analyzer);
    let expected_public = analyzer
        .declarations(&fixture.file("App/Caller.cs"))
        .into_iter()
        .find(|unit| unit.is_function() && unit.identifier() == "Public")
        .unwrap()
        .fq_name_str()
        .to_owned();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            analyzer,
        );
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
        panic!("source member operation");
    };
    let names = ["Public", "Hidden", "Missing"];
    let locators = names.map(|name| {
        let start =
            source.find(&format!("global::Cases.C.{name}()")).unwrap() + "global::Cases.C.".len();
        SelectedSemanticLocator::for_reference_range(
            "csharp",
            "App/Caller.cs",
            start,
            start + name.len(),
        )
    });
    let probes = probe_references(&operation, &snapshots["csharp"], &locators, &cancellation)
        .unwrap()
        .unwrap();
    assert_eq!(probes.len(), names.len());
    for (name, probe) in names.into_iter().zip(probes) {
        eprintln!(
            "{name}: {:?}; {:?}; {:?}",
            probe.targets, probe.completion, probe.named_reasons
        );
        assert_ne!(
            probe.completion,
            ResolutionCompletion::Complete,
            "access is not proved: {name}"
        );
        assert!(
            probe
                .named_reasons
                .iter()
                .any(|(kind, _)| *kind == "csharp_member_access_unmodeled"),
            "the exact access gap must survive every placement: {name}: {:?}",
            probe.named_reasons
        );
        if name == "Missing" {
            assert!(probe.targets.is_empty(), "missing member has no target");
        }
        if name == "Public" {
            assert_eq!(
                probe.targets,
                vec![("App/Caller.cs".to_owned(), expected_public.clone())],
                "real public source target with access still Open"
            );
        }
    }
}

#[test]
fn csharp_source_half_static_qualified_pair_preserves_access_gap() {
    if run_csharp_root_trial("csharp_source_half_static_qualified_pair_preserves_access_gap") {
        return;
    }
    use brokk_bifrost_analysis::analyzer::native_points::{
        native_point_operation_open_count_for_test,
        reset_native_point_operation_open_count_for_test,
    };
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
    };
    let source = "namespace Cases { public class C { public static void Known() {} public static void Probe() { C.Known(); C.Missing(); } } }";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("App/Caller.cs", source)
        .build();
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap(),
    )
    .unwrap();
    let file = brokk_bifrost_core::analyzer::ProjectFile::new(
        fixture.project_dyn().root(),
        "App/Caller.cs",
    );
    let request = |marker: &str, member: &str| {
        let start = source.find(marker).unwrap() + "C.".len();
        DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + member.len()),
        }
    };
    reset_native_point_operation_open_count_for_test();
    let known_outcomes = resolve_definition_batch_with_source(
        workspace.analyzer(),
        vec![request("C.Known()", "Known")],
        file.clone(),
        source.into(),
    );
    let known_native_opens = native_point_operation_open_count_for_test();
    reset_native_point_operation_open_count_for_test();
    let missing_outcomes = resolve_definition_batch_with_source(
        workspace.analyzer(),
        vec![request("C.Missing()", "Missing")],
        file,
        source.into(),
    );
    let missing_native_opens = native_point_operation_open_count_for_test();
    println!(
        "CSHARP_SOURCE_HALF_STATIC_PAIR marker=Known native_opens={known_native_opens} outcomes={known_outcomes:#?}"
    );
    println!(
        "CSHARP_SOURCE_HALF_STATIC_PAIR marker=Missing native_opens={missing_native_opens} outcomes={missing_outcomes:#?}"
    );
    assert!(
        known_native_opens > 0,
        "normal public Known point must open selected native operation: {known_outcomes:#?}"
    );
    assert!(
        missing_native_opens > 0,
        "normal public Missing point must open selected native operation: {missing_outcomes:#?}"
    );
    let [known] = known_outcomes.as_slice() else {
        panic!("actual source-half Known outcomes: {known_outcomes:?}")
    };
    let [missing] = missing_outcomes.as_slice() else {
        panic!("actual source-half Missing outcomes: {missing_outcomes:?}")
    };
    assert_eq!(
        known.status,
        DefinitionLookupStatus::Incomplete,
        "{known:#?}"
    );
    assert_eq!(known.definitions.len(), 1, "{known:#?}");
    assert_eq!(known.definitions[0].fq_name_str(), "Cases.C.Known");
    assert!(
        known
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "csharp_member_access_unmodeled"),
        "known source member keeps access uncertainty: {known:#?}"
    );
    assert_eq!(
        missing.status,
        DefinitionLookupStatus::Incomplete,
        "missing source member must remain access-open: {missing:#?}"
    );
    assert!(missing.definitions.is_empty(), "{missing:#?}");
    assert!(
        missing
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "csharp_member_access_unmodeled"),
        "missing source member must retain the access gap: {missing:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7314: expression-rooted member chains omitted the terminal reference and receiver transport"
)]
fn csharp_expression_receiver_preserves_actual_property_output_and_static_uncertainty() {
    if run_csharp_root_trial(
        "csharp_expression_receiver_preserves_actual_property_output_and_static_uncertainty",
    ) {
        return;
    }
    use brokk_bifrost_analysis::analyzer::resolution::ResolutionSlotValue;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        SelectedResolutionLocated, SelectedResolutionOperationOutcome,
        csharp_demand::probe_expression_receiver_frontier,
    };
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
    let plain = "public class Plain { public int Own; public Plain Self => this; public int Probe() => this.Self.Own; public static int Invalid() => this.Self.Own; }";
    let generic = "public class Generic<T> { public T Identity(T value) => value; public Generic<T> Self => this; public T Probe(T value) => this.Self.Identity(value); }";
    let fixture = private_access_project(PRIVATE_ACCESS_TARGETS)
        .file("App/Plain.cs", plain)
        .file("App/Generic.cs", generic)
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
    let project = fixture.project_dyn();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            workspace.analyzer(),
        );
    let mut cases = Vec::new();
    // Collect every outcome before assertions: a generic projection failure must
    // not mask the independent nongeneric and static receiver observations.
    for (label, path, source, start, length) in [
        (
            "plain",
            "App/Plain.cs",
            plain,
            plain.find("Self.Own").unwrap() + 5,
            3,
        ),
        (
            "generic",
            "App/Generic.cs",
            generic,
            generic.find("Self.Identity").unwrap() + 5,
            8,
        ),
        (
            "static",
            "App/Plain.cs",
            plain,
            plain.rfind("Self.Own").unwrap() + 5,
            3,
        ),
    ] {
        let probe_ledger =
            std::sync::Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
        let probe_scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_read_ledger(
            workspace.analyzer(),
            probe_ledger.clone(),
        );
        let cancellation = CancellationToken::new();
        let SelectedResolutionOperationOpenOutcome::Ready(mut operation) = store
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
            panic!("normal selected expression operation");
        };
        let locator =
            SelectedSemanticLocator::for_reference_range("csharp", path, start, start + length);
        let frontier =
            probe_expression_receiver_frontier(&mut operation, &locator, &cancellation).unwrap();
        drop(operation);
        let probe_keys = probe_ledger.keys();
        drop(probe_scope);
        let (product, entries, keys) = private_access_native_lookup_at(
            workspace.analyzer(),
            fixture.file(path),
            source,
            start,
            start + length,
        );
        println!(
            "ACTUAL_EXPRESSION_RECEIVER {label} {frontier:#?}\nPROBE_KEYS {probe_keys:#?}\nPRODUCT {product:#?} native_entries={entries}\nKEYS {keys:#?}"
        );
        cases.push((label, frontier, product, entries));
    }
    for (label, probe, product, entries) in cases {
        assert!(entries > 0, "normal native product entry: {label}");
        let probe =
            probe.unwrap_or_else(|| panic!("published expression reference and transfer: {label}"));
        // These assertions describe actual observed source rows, not an
        // Established inventory claim. Normal evaluation supplies the answers.
        assert!(probe.role_read.is_exhausted(), "{probe:#?}");
        assert_eq!(probe.observed_roles.len(), 2, "{probe:#?}");
        assert!(probe.observed_roles.iter().any(|row| row.row().slot() == probe.input
            && row.row().role() == brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole::ExpressionValue), "{probe:#?}");
        assert!(probe.observed_roles.iter().any(|row| row.row().slot() == probe.receiver
            && row.row().role() == brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole::Receiver), "{probe:#?}");
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            &probe.receiver_answer
        else {
            panic!("normal receiver query: {probe:#?}");
        };
        let [receiver] = answer.projected_frontiers() else {
            panic!("one actual requested receiver: {probe:#?}");
        };
        assert_eq!(receiver.slot(), probe.receiver);
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(input)) =
            &probe.input_answer
        else {
            panic!("normal input query: {probe:#?}");
        };
        let [input] = input.projected_frontiers() else {
            panic!("one actual requested expression output: {probe:#?}");
        };
        assert_eq!(input.slot(), probe.input);
        use brokk_bifrost_analysis::analyzer::resolution::{
            LoweringGapOrigin, ResolutionCompletion, ResolutionIncompleteReason,
        };
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
        assert!(
            matches!(receiver.completion(), ResolutionCompletion::Incomplete(_)),
            "{probe:#?}"
        );
        assert!(
            probe.receiver_gap_provenance.iter().any(|gap| gap.origin()
                == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedTypeSyntax)
                && receiver.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(gap.reason())
                )),
            "receiver retains its own syntax reason: {probe:#?}"
        );
        assert!(
            matches!(answer.completion(), ResolutionCompletion::Incomplete(_)),
            "{probe:#?}"
        );
        assert_eq!(
            product.status,
            DefinitionLookupStatus::Incomplete,
            "{product:#?}"
        );
        if label == "static" {
            assert!(
                matches!(input.completion(), ResolutionCompletion::Incomplete(_)),
                "{probe:#?}"
            );
        } else {
            // Known two-answers-for-one-fact defect: the property-output slot
            // omits its own site's UnsupportedTypeSyntax because resolution gaps
            // carry no typed slot impact (#12552); producer precision is #12494.
            // When #12552 lands, restore BOTH slots to Incomplete.
            assert_eq!(
                input.completion(),
                &ResolutionCompletion::Complete,
                "{label}: {probe:#?}"
            );
        }
        if label == "static" {
            use brokk_bifrost_analysis::analyzer::resolution::LoweringGapOrigin;
            use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
            assert!(
                probe
                    .receiver_gap_provenance
                    .iter()
                    .any(|expression| expression.origin()
                        == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedExpression)
                        && probe
                            .receiver_gap_provenance
                            .iter()
                            .any(|syntax| syntax.origin()
                                == LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnsupportedTypeSyntax
                                )
                                && syntax.fragment() == expression.fragment()
                                && syntax.source_site() == expression.source_site())
                        && probe
                            .observed_roles
                            .iter()
                            .any(|role| role.row().slot() == probe.input
                                && role.fragment() == expression.fragment())),
                "the static-this gaps share their actual source site in the input fragment: {probe:#?}"
            );
            // The observed role identifies the fragment, not the inner site's
            // coordinate. Do not substitute the OUTER Own metadata site for it.
            assert!(
                product.definitions.is_empty(),
                "static this cannot select Own: {product:#?}"
            );
            for frontier in [input, receiver] {
                assert!(
                    frontier.possible_values().is_empty(),
                    "static this leaves BOTH the expression output and receiver empty: {probe:#?}"
                );
            }
        } else {
            assert_eq!(product.definitions.len(), 1, "{label}: {product:#?}");
            assert_eq!(
                product.definitions[0].identifier(),
                if label == "plain" { "Own" } else { "Identity" }
            );
            for frontier in [input, receiver] {
                let [
                    ResolutionSlotValue::Runtime {
                        ty, addressable, ..
                    },
                ] = frontier.possible_values()
                else {
                    panic!("{label}: exactly one actual Runtime on BOTH slots: {probe:#?}");
                };
                assert_eq!(
                    ty.identity(),
                    probe.owner,
                    "actual selected source owner: {probe:#?}"
                );
                assert_eq!(ty.indirection(), 0, "{probe:#?}");
                assert_eq!(ty.reference_indirection(), 0, "{probe:#?}");
                assert!(!addressable, "{probe:#?}");
            }
            assert_eq!(
                input.possible_values(),
                receiver.possible_values(),
                "Preserve retains the actual input value at the receiver: {probe:#?}"
            );
        }
    }
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

#[test]
#[hardwon(
    "#7314: C# receiver-proof receipts hashed the absolute checkout root, so diff-base BASE could never replay"
)]
fn csharp_receiver_proof_receipts_replay_across_checkout_roots() {
    if run_csharp_root_trial("csharp_receiver_proof_receipts_replay_across_checkout_roots") {
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey};
    use brokk_bifrost_analysis::analyzer::read_verification::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        verify_read_set,
    };
    let first = private_access_project(PRIVATE_ACCESS_TARGETS).build();
    let second = private_access_project(PRIVATE_ACCESS_TARGETS).build();
    assert_ne!(first.root(), second.root());
    let build = |fixture: &crate::inline_project::BuiltInlineTestProject| {
        WorkspaceAnalyzer::build_with_store_context_for_test(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
            ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap(),
        )
        .unwrap()
    };
    let base = build(&first);
    let head = build(&second);
    let proof_reads =
        |workspace: &WorkspaceAnalyzer, fixture: &crate::inline_project::BuiltInlineTestProject| {
            let (_, _, keys) = private_access_native_lookup(
                workspace.analyzer(),
                fixture.file("App/Caller.cs"),
                PRIVATE_ACCESS_CALLER,
                "this",
                "Hidden",
            );
            keys.into_iter()
                .filter(|key| {
                    matches!(
                        key,
                        ReadKey::Lookup {
                            kind: LookupKind::SelectedReceiverProof,
                            ..
                        }
                    )
                })
                .collect::<Vec<_>>()
        };
    let before = proof_reads(&base, &first);
    let after = proof_reads(&head, &second);
    assert!(
        !before.is_empty(),
        "receiver proof reads must actually be captured"
    );
    assert_eq!(
        before, after,
        "same source and question have equal receipts"
    );
    assert_eq!(
        verify_read_set(
            &head,
            &ChangedFacts::between(&base, &head),
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &before,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        ),
        ReadVerdict::Unchanged
    );
}

/// Re-run `test` in a child with the native C# trial on; true in the child.
fn in_native_csharp_child(test: &str) -> bool {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    false
}

struct CSharpReceipt {
    _fixture: crate::inline_project::BuiltInlineTestProject,
    workspace: WorkspaceAnalyzer,
    keys: Vec<brokk_bifrost_analysis::analyzer::read_ledger::ReadKey>,
    admitted: usize,
    reuse_refused: bool,
}

impl CSharpReceipt {
    /// The keys one placement and its global-using inventory record.
    fn record(files: &[(&str, &str)], caller: &str) -> Self {
        let mut builder = InlineTestProject::with_language(Language::CSharp);
        for (path, text) in files {
            builder = builder.file(*path, *text);
        }
        let fixture = builder.build();
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
        let (admitted, reads) = brokk_bifrost_analysis::analyzer::capture_query_reads(
            csharp,
            || {
                brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_certified_reader_receipt(&operation, caller).unwrap()
            },
        );
        let (keys, reuse_refused) = (reads.keys(), reads.reuse_refused());
        drop(operation);
        drop(services);
        Self {
            _fixture: fixture,
            workspace,
            keys,
            admitted,
            reuse_refused,
        }
    }

    /// The recorded global-using fact: its compilation label and digest.
    fn global_using_fact(&self) -> (String, [u8; 32]) {
        use brokk_bifrost_analysis::analyzer::read_ledger::{
            FactSubject, ReadKey, WorkspaceFactFamily,
        };
        use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupQuestion;
        let mut facts = self.keys.iter().filter_map(|key| match key {
            ReadKey::Lookup {
                question:
                    LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::CSharpCompilationGlobalUsings,
                        subject: FactSubject::Named { name },
                        ..
                    },
                digest,
                ..
            } => Some((name.to_string(), *digest.as_bytes())),
            _ => None,
        });
        let fact = facts.next().expect("a global-using fact is recorded");
        assert!(
            facts.next().is_none(),
            "one compilation, one fact: {:?}",
            self.keys
        );
        fact
    }

    /// Verify this receipt's keys against `head`.
    fn verify_on(
        &self,
        head: &CSharpReceipt,
    ) -> brokk_bifrost_analysis::analyzer::read_verification::ReadVerdict {
        use brokk_bifrost_analysis::analyzer::read_verification::{
            ChangedFacts, LookupMemo, NoSummaryAnswers, verify_read_set,
        };
        verify_read_set(
            &head.workspace,
            &ChangedFacts::between(&self.workspace, &head.workspace),
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &self.keys,
            Default::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
    }
}

const APP_CSPROJ: (&str, &str) = ("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />");
const CALLER: (&str, &str) = (
    "App/Caller.cs",
    "global using System; class Caller { Peer value; } class Peer {}",
);

// Raw C# placement and global-using reads record their own dependencies:
// certification records the configuration fact and overlay membership only.
#[test]
fn csharp_certified_raw_read_receipt_contract() {
    if !in_native_csharp_child(
        "engine_tests::csharp_demand::csharp_certified_raw_read_receipt_contract",
    ) {
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::{
        FactSubject, ReadKey, WorkspaceFactFamily,
    };
    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupQuestion;
    let receipt = CSharpReceipt::record(&[APP_CSPROJ, CALLER], "App/Caller.cs");
    assert_eq!(
        receipt.admitted, 1,
        "one placement exercises both raw readers"
    );
    assert!(!receipt.reuse_refused);
    let keys = &receipt.keys;
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
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "App/Caller.cs"
        )),
        "membership must record the queried path's own version: {keys:?}"
    );
    assert_eq!(receipt.global_using_fact().0, "App/App.csproj");
    assert!(
        !keys.iter().any(|key| matches!(key, ReadKey::Scope { .. })),
        "no whole-C#-scope read: {keys:?}"
    );
}

#[test]
#[hardwon(
    "#13276: an edit that adds no global using invalidated native C# receipts through the whole C# scope key"
)]
fn csharp_receipt_survives_edits_that_add_no_global_using() {
    if !in_native_csharp_child(
        "engine_tests::csharp_demand::csharp_receipt_survives_edits_that_add_no_global_using",
    ) {
        return;
    }
    let base = CSharpReceipt::record(
        &[
            APP_CSPROJ,
            CALLER,
            ("App/Peer.cs", "class Other { int Run() { return 0; } }"),
        ],
        "App/Caller.cs",
    );
    // Editing the body of an existing non-carrier .cs file and adding a new
    // sibling without a global using each leave the compilation's global-using
    // inventory (K4) untouched.
    let head = CSharpReceipt::record(
        &[
            APP_CSPROJ,
            ("App/Caller.cs", CALLER.1),
            ("App/Peer.cs", "class Other { int Run() { return 1; } }"),
            ("App/Extra.cs", "class Extra { void Body() { } }"),
        ],
        "App/Caller.cs",
    );
    assert_eq!(base.global_using_fact(), head.global_using_fact());
    let verdict = base.verify_on(&head);
    assert!(verdict.is_unchanged(), "{verdict:?}");
}

#[test]
#[hardwon(
    "#13276: the precise global-using key must still move when a global using is added, removed or changed"
)]
fn csharp_receipt_invalidates_when_a_global_using_changes() {
    if !in_native_csharp_child(
        "engine_tests::csharp_demand::csharp_receipt_invalidates_when_a_global_using_changes",
    ) {
        return;
    }
    use brokk_bifrost_analysis::analyzer::read_ledger::{ReadKey, WorkspaceFactFamily};
    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupQuestion;
    let peer = |text: &'static str| [APP_CSPROJ, CALLER, ("App/Peer.cs", text)];
    for (what, base_files, head_files) in [
        (
            "add a global using in a sibling",
            peer("class Peer2 {}"),
            peer("global using System.Text; class Peer2 {}"),
        ),
        (
            "add a global static using",
            peer("class Peer2 {}"),
            peer("global using static System.Math; class Peer2 {}"),
        ),
        (
            "add a global alias",
            peer("class Peer2 {}"),
            peer("global using T = System.Text.StringBuilder; class Peer2 {}"),
        ),
        (
            "remove a sibling's global using",
            peer("global using System.Text; class Peer2 {}"),
            peer("class Peer2 {}"),
        ),
        (
            "modify a sibling's global using",
            peer("global using System.Text; class Peer2 {}"),
            peer("global using System.Linq; class Peer2 {}"),
        ),
        (
            "turn a global using into a global static using",
            peer("global using System.Text; class Peer2 {}"),
            peer("global using static System.Text; class Peer2 {}"),
        ),
        (
            "add a new file that declares a global using",
            peer("class Peer2 {}"),
            [
                APP_CSPROJ,
                CALLER,
                ("App/NewGlobal.cs", "global using System.Linq;"),
            ],
        ),
        (
            // Documented over-invalidation: K4 folds (blob_oid, parse_variant) of
            // carrier files that declare a global using so `global using X` <->
            // `global using static X` invalidates without an unindexed catalog join,
            // so a body edit inside a carrier file also moves K4.
            "edit the body of a carrier file that declares a global using",
            peer("global using System.Text; class Peer2 { int Run() { return 1; } }"),
            peer("global using System.Text; class Peer2 { int Run() { return 2; } }"),
        ),
    ] {
        let base = CSharpReceipt::record(&base_files, "App/Caller.cs");
        let head = CSharpReceipt::record(&head_files, "App/Caller.cs");
        let verdict = base.verify_on(&head);
        let changed = verdict
            .changed()
            .unwrap_or_else(|| panic!("{what}: the receipt must not survive"));
        assert!(
            matches!(
                &changed.key,
                ReadKey::Lookup {
                    question: LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::CSharpCompilationGlobalUsings,
                        ..
                    },
                    ..
                }
            ),
            "{what}: the global-using fact must be the key that moved: {changed:?}"
        );
        assert_ne!(
            base.global_using_fact().1,
            head.global_using_fact().1,
            "{what}: incremental and from-scratch digests must agree on the change"
        );
    }
}

#[test]
#[hardwon(
    "#13276: a global using in an unrelated compilation must not move this compilation's fact"
)]
fn csharp_global_using_fact_is_per_compilation() {
    if !in_native_csharp_child(
        "engine_tests::csharp_demand::csharp_global_using_fact_is_per_compilation",
    ) {
        return;
    }
    let lib_a = [
        ("LibA/LibA.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
        ("LibA/Caller.cs", "global using System; class Caller { }"),
    ];
    let lib_b = |text: &'static str| {
        [
            ("LibB/LibB.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />"),
            ("LibB/Other.cs", text),
        ]
    };
    let files = |b: [(&'static str, &'static str); 2]| {
        let mut files = lib_a.to_vec();
        files.extend(b);
        files
    };
    let base = CSharpReceipt::record(&files(lib_b("class Other { }")), "LibA/Caller.cs");
    let head = CSharpReceipt::record(
        &files(lib_b("global using System.Text; class Other { }")),
        "LibA/Caller.cs",
    );
    assert_eq!(base.global_using_fact().0, "LibA/LibA.csproj");
    assert_eq!(base.global_using_fact(), head.global_using_fact());
    let verdict = base.verify_on(&head);
    assert!(verdict.is_unchanged(), "{verdict:?}");
}
