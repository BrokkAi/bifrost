//! Bounded hierarchy traversal and overlay invalidation regressions for the C# graph resolver.

use crate::analyzer::usages::csharp_graph::csharp_graph_source;
use crate::analyzer::usages::csharp_graph::shared::CSharpAuthoritativeUsageBatch;
use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverBudgetLimit};
use crate::analyzer::{
    AnalyzerQueryScope, CSharpAnalyzer, CodeUnit, IAnalyzer, Language, QueryScope, resolve_analyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use crate::test_support::AnalyzerFixture;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_csharp::graph::resolver::{
    compatible_receiver_type_names, nearest_member_candidates_for_owner_inner,
};
use std::fmt::Write;

fn type_definition(analyzer: &dyn IAnalyzer, fqn: &str) -> CodeUnit {
    analyzer
        .get_definitions(fqn)
        .into_iter()
        .find(CodeUnit::is_class)
        .unwrap_or_else(|| panic!("missing type {fqn}"))
}

fn deep_wide_hierarchy_source(depth: usize, width: usize) -> String {
    let mut source = String::from("namespace Demo;\n");
    for index in 0..width {
        writeln!(source, "public interface IWide{index} {{}}").expect("write interface");
    }
    source.push_str("public class Root { public void RootMethod() {} }\n");
    write!(source, "public class Level0 : Root").expect("write level zero");
    for index in 0..width {
        write!(source, ", IWide{index}").expect("write interface base");
    }
    source.push_str(" {}\n");
    for index in 1..=depth {
        writeln!(
            source,
            "public class Level{index} : Level{} {{}}",
            index - 1
        )
        .expect("write hierarchy level");
    }
    source
}

fn hierarchy_fixture() -> AnalyzerFixture {
    let source = deep_wide_hierarchy_source(12, 16);
    AnalyzerFixture::new_for_language(Language::CSharp, &[("Hierarchy.cs", &source)])
}

fn csharp_usage_sites(result: FuzzyResult, target: &CodeUnit) -> HashSet<(String, usize, usize)> {
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        ..
    } = result
    else {
        panic!("expected successful C# usage result, got {result:#?}");
    };
    hits_by_overload
        .get(target)
        .into_iter()
        .flatten()
        .chain(unproven_by_overload.get(target).into_iter().flatten())
        .map(|hit| {
            (
                hit.file.rel_path().to_string_lossy().into_owned(),
                hit.start_offset,
                hit.end_offset,
            )
        })
        .collect()
}

#[test]
fn bounded_receiver_hierarchy_stops_before_materializing_a_wide_walk() {
    let fixture = hierarchy_fixture();
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
    let leaf_fqn = "Demo.Level12".to_string();

    let complete_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let compatible = compatible_receiver_type_names(
        csharp,
        token,
        &csharp_graph_source(analyzer),
        std::slice::from_ref(&leaf_fqn),
        false,
        Some(&complete_session),
    );
    assert!(compatible.contains("Demo.Root"), "{compatible:#?}");
    assert!(compatible.contains("Demo.IWide15"), "{compatible:#?}");
    assert!(matches!(
        complete_session.finish(()),
        BoundedResolution::Complete { .. }
    ));

    let budget = ReceiverAnalysisBudget {
        max_scope_nodes: 48,
        ..ReceiverAnalysisBudget::default()
    };
    let bounded_session = ResolutionSession::bounded(budget, None);
    let compatible = compatible_receiver_type_names(
        csharp,
        token,
        &csharp_graph_source(analyzer),
        std::slice::from_ref(&leaf_fqn),
        false,
        Some(&bounded_session),
    );
    assert!(
        compatible.is_empty(),
        "terminal budget exhaustion must discard partial hierarchy evidence"
    );
    assert!(matches!(
        bounded_session.finish(()),
        BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes,
            work,
        } if work.scope_nodes == budget.max_scope_nodes
    ));
}

#[test]
fn bounded_member_hierarchy_observes_mid_walk_cancellation() {
    let fixture = hierarchy_fixture();
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
    let leaf = type_definition(analyzer, "Demo.Level12");

    let exact_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let members = nearest_member_candidates_for_owner_inner(
        &csharp_graph_source(analyzer),
        csharp,
        token,
        &leaf,
        "RootMethod",
        None,
        Some(0),
        false,
        Some(&exact_session),
    );
    assert!(
        matches!(members.as_slice(), [member] if member.fq_name() == "Demo.Root.RootMethod"),
        "{members:#?}"
    );
    assert!(matches!(
        exact_session.finish(()),
        BoundedResolution::Complete { .. }
    ));

    let cancelled_work = (16..512).step_by(8).find_map(|checks| {
        let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
        let session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let members = nearest_member_candidates_for_owner_inner(
            &csharp_graph_source(analyzer),
            csharp,
            token,
            &leaf,
            "RootMethod",
            None,
            Some(0),
            false,
            Some(&session),
        );
        match session.finish(members) {
            BoundedResolution::Cancelled { work }
                if work.scope_nodes > 0 && work.summary_expansions >= 2 =>
            {
                Some(work)
            }
            _ => None,
        }
    });
    assert!(
        cancelled_work.is_some(),
        "expected deterministic cancellation after at least two hierarchy expansions"
    );
}

#[test]
fn csharp_inverse_scans_use_overlay_source_in_revision_a_b_a() {
    use crate::analyzer::{CodeUnitIndex, OverlayProject, Project, ProjectFile};
    use crate::inline_project::InlineTestProject;
    use std::sync::Arc;

    let disk = "class C { public void Target() {} public void Run() {} }";
    let dirty = "class C { public void Target() {} public void Run() { Target(); } }";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("Overlay.cs", disk)
        .build();
    let file = ProjectFile::new(fixture.root(), "Overlay.cs");
    let base = CSharpAnalyzer::from_project(fixture.project().clone());
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    let roots = HashSet::from_iter([file.clone()]);
    for (source, expected_sites) in [(disk, 0), (dirty, 1), (disk, 0)] {
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let analyzer = base.clone_with_project(overlay.clone() as Arc<dyn Project>);
        let target = analyzer
            .get_definitions("C.Target")
            .into_iter()
            .find(CodeUnit::is_function)
            .expect("target declaration");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let batch = CSharpAuthoritativeUsageBatch::new(&analyzer, scope.token(), &roots)
            .expect("C# authoritative batch");
        let result = batch
            .find_usages(std::slice::from_ref(&target), &roots, 100)
            .into_fuzzy_result();
        assert_eq!(csharp_usage_sites(result, &target).len(), expected_sites);
    }
    assert_eq!(std::fs::read_to_string(file.abs_path()).unwrap(), disk);
}
