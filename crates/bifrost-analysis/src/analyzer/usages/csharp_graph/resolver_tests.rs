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
use crate::analyzer::usages::csharp_graph::shared::{
    CSharpAuthoritativeUsageBatch, CSharpAuthoritativeUsageRequest, CSharpQueryResolver,
};
use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverBudgetLimit};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, Language, resolve_analyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
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
fn authoritative_batch_prepares_union_roots_once_and_keeps_per_target_file_bounds() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::CSharp,
        &[
            (
                "Models.cs",
                "namespace Demo; public class Alpha {} public class Beta {}",
            ),
            (
                "UseA.cs",
                "namespace Demo; public class UseA { Alpha alpha; Beta beta; }",
            ),
            (
                "UseB.cs",
                "namespace Demo; public class UseB { Alpha alpha; Beta beta; }",
            ),
            (
                "UseAlias.cs",
                "using AliasAlpha = Demo.Alpha; namespace Demo; public class UseAlias { AliasAlpha alpha; }",
            ),
        ],
    );
    let analyzer = fixture.analyzer.analyzer();
    let alpha = type_definition(analyzer, "Demo.Alpha");
    let beta = type_definition(analyzer, "Demo.Beta");
    let roots: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();
    let use_a = roots
        .iter()
        .find(|file| file.rel_path().to_string_lossy() == "UseA.cs")
        .expect("UseA.cs")
        .clone();
    let use_b = roots
        .iter()
        .find(|file| file.rel_path().to_string_lossy() == "UseB.cs")
        .expect("UseB.cs")
        .clone();
    let use_alias = roots
        .iter()
        .find(|file| file.rel_path().to_string_lossy() == "UseAlias.cs")
        .expect("UseAlias.cs")
        .clone();
    let only_a = HashSet::from_iter([use_a]);
    let only_b = HashSet::from_iter([use_b]);
    let only_alias = HashSet::from_iter([use_alias]);

    let scope = AnalyzerQueryScope::new(analyzer);
    let batch = CSharpAuthoritativeUsageBatch::new(analyzer, scope.token(), &roots)
        .expect("C# authoritative batch");
    assert_eq!(batch.prepared_file_count_for_test(), roots.len());

    let resolver = CSharpQueryResolver::try_new(analyzer).expect("C# resolver");
    let ordinary_alpha = resolver
        .find_usages(
            analyzer,
            std::slice::from_ref(&alpha),
            &UsageScanScope::new(&only_a),
            100,
        )
        .into_fuzzy_result();
    let requests = [
        CSharpAuthoritativeUsageRequest::new(std::slice::from_ref(&alpha), &only_a, 100),
        CSharpAuthoritativeUsageRequest::new(std::slice::from_ref(&beta), &only_a, 100),
    ];
    let mut batch_results = batch.find_usages_batch(&requests).into_iter();
    let batch_alpha = batch_results
        .next()
        .expect("Alpha batch result")
        .into_fuzzy_result();
    let batch_beta_in_a = batch_results
        .next()
        .expect("Beta batch result")
        .into_fuzzy_result();
    assert!(batch_results.next().is_none());
    assert_eq!(
        csharp_usage_sites(ordinary_alpha, &alpha),
        csharp_usage_sites(batch_alpha, &alpha)
    );
    let beta_sites_in_a = csharp_usage_sites(batch_beta_in_a, &beta);
    assert!(!beta_sites_in_a.is_empty(), "expected the shared Beta use");
    assert!(
        beta_sites_in_a.iter().all(|(path, _, _)| path == "UseA.cs"),
        "shared file-major scan leaked another file: {beta_sites_in_a:#?}"
    );
    assert_eq!(
        batch.batch_file_scan_count_for_test(),
        1,
        "two targets sharing one candidate file must traverse that file once"
    );

    let alias_alpha = batch
        .find_usages(std::slice::from_ref(&alpha), &only_alias, 100)
        .into_fuzzy_result();
    let alias_sites = csharp_usage_sites(alias_alpha, &alpha);
    assert!(!alias_sites.is_empty(), "expected the aliased Alpha use");
    assert!(
        alias_sites.iter().all(|(path, _, _)| path == "UseAlias.cs"),
        "alias fallback leaked another file: {alias_sites:#?}"
    );

    let batch_beta = batch
        .find_usages(std::slice::from_ref(&beta), &only_b, 100)
        .into_fuzzy_result();
    let beta_sites = csharp_usage_sites(batch_beta, &beta);
    assert!(!beta_sites.is_empty(), "expected the bounded Beta use");
    assert!(
        beta_sites.iter().all(|(path, _, _)| path == "UseB.cs"),
        "authoritative candidate bounds leaked another file: {beta_sites:#?}"
    );
    assert_eq!(
        batch.prepared_file_count_for_test(),
        roots.len(),
        "target queries must reuse the fixed prepared-file map"
    );
    assert_eq!(
        batch.batch_file_scan_count_for_test(),
        3,
        "each later one-file request adds exactly one file-major traversal"
    );
}
