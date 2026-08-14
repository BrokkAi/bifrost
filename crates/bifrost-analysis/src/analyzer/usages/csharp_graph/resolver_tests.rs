//! The two bounded-resolution unit tests for
//! [`brokk_bifrost_csharp::graph::resolver`], kept on this side of the seam.
//!
//! They drive `compatible_receiver_type_names` and
//! `nearest_member_candidates_for_owner_inner` -- the session-metering inners
//! themselves, not the wrappers -- against a real `CSharpAnalyzer` built by
//! `AnalyzerFixture`, which is analysis-side test support the C# crate cannot
//! depend on. Rewriting them against a hand-rolled `CSharpSource` would
//! have changed what they prove, so the tests stay and the two inners are `pub`
//! in the crate.

use crate::analyzer::usages::csharp_graph::csharp_graph_source;
use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverBudgetLimit};
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, Language, resolve_analyzer};
use crate::cancellation::CancellationToken;
use crate::test_support::AnalyzerFixture;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_csharp::graph::resolver::{
    compatible_receiver_type_names, nearest_member_candidates_for_owner_inner,
};
use std::fmt::Write;

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

fn type_definition(analyzer: &dyn IAnalyzer, fqn: &str) -> CodeUnit {
    analyzer
        .get_definitions(fqn)
        .into_iter()
        .find(CodeUnit::is_class)
        .unwrap_or_else(|| panic!("missing type {fqn}"))
}

#[test]
fn bounded_receiver_hierarchy_stops_before_materializing_a_wide_walk() {
    let fixture = hierarchy_fixture();
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
    let leaf_fqn = "Demo.Level12".to_string();

    let complete_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let compatible = compatible_receiver_type_names(
        csharp,
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
    let members = nearest_member_candidates_for_owner_inner(
        &csharp_graph_source(analyzer),
        csharp,
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
