//! C# member-dispatch attribution conformance for #1477, Milestone 3.
//!
//! C# classifies no occurrence roles yet (#1473/#1724), so the
//! `occurrences -> candidates_of` pipeline the Java, Rust and TS/Python
//! conformance files use cannot reach a C# member site. The rows are therefore
//! asserted where they are produced: on the production resolution trace itself,
//! which is the same emission those projections will render once C# gains role
//! classification.
//!
//! What the fixtures pin down is the milestone's rule set -- the exact owner
//! the resolver found the member on, the hop distance to that owner, the
//! contiguous route it took, and the language-neutral dispatch bucket -- plus
//! the boundaries this language's seams honestly cannot state: an
//! undifferentiated supertype edge, a static access the syntax does not
//! distinguish, and an extension method the extension seam returns without the
//! receiver type it matched.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::get_definition::{
    DefinitionLookupRequest, ResolutionTraceResult, TraceCandidate, TraceCandidateRef,
    resolve_definition_batch_with_trace,
};
use brokk_bifrost::{CSharpAnalyzer, CancellationToken, IAnalyzer, Language};
use std::sync::Arc;

/// Resolve the reference spelled `member` inside the last occurrence of
/// `needle` in `path`, with the trace recording.
fn trace_at(
    analyzer: &dyn IAnalyzer,
    project: &crate::common::BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
    member: &str,
) -> (bool, ResolutionTraceResult) {
    let anchor = source.rfind(needle).expect("fixture must contain needle");
    let start = anchor + needle.rfind(member).expect("needle must contain member");
    let file = project.file(path);
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(start),
        end_byte: Some(start + member.len()),
    };
    let mut resolved = resolve_definition_batch_with_trace(
        analyzer,
        vec![request],
        file,
        Arc::from(source),
        &CancellationToken::new(),
    );
    assert_eq!(resolved.len(), 1, "one request resolves to one trace");
    let (outcome, trace) = resolved.remove(0);
    (!outcome.definitions.is_empty(), trace)
}

fn csharp_trace(
    files: &[(&str, &str)],
    path: &str,
    needle: &str,
    member: &str,
) -> ResolutionTraceResult {
    let (resolved, trace) = csharp_trace_raw(files, path, needle, member);
    assert!(resolved, "the fixture must resolve: {:?}", trace.candidates);
    trace
}

fn csharp_trace_raw(
    files: &[(&str, &str)],
    path: &str,
    needle: &str,
    member: &str,
) -> (bool, ResolutionTraceResult) {
    let mut project = InlineTestProject::with_language(Language::CSharp);
    for (name, source) in files {
        project = project.file(*name, *source);
    }
    let project = project.build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let source = files
        .iter()
        .find(|(name, _)| *name == path)
        .expect("the traced file must be part of the fixture")
        .1;
    trace_at(&analyzer, &project, path, source, needle, member)
}

fn selected(trace: &ResolutionTraceResult) -> Vec<&TraceCandidate> {
    trace.selected().collect()
}

fn fq_name(candidate: &TraceCandidate) -> String {
    match &candidate.candidate {
        TraceCandidateRef::Unit(unit) => unit.fq_name(),
        other => panic!("expected a unit-backed candidate, got {other:?}"),
    }
}

/// The route a candidate reports, rendered as `(hop, from, to, relation)` so a
/// test can state the exact hierarchy edges the walk took.
fn route(candidate: &TraceCandidate) -> Vec<(usize, String, String, String)> {
    candidate
        .member
        .as_ref()
        .expect("candidate must be attributed")
        .route
        .iter()
        .map(|hop| {
            (
                hop.hop,
                hop.from.fq_name(),
                hop.to.fq_name(),
                hop.relation.label().to_owned(),
            )
        })
        .collect()
}

/// A method inherited through two `:` base-class hops: the row names the root
/// class as the exact owner, states depth two, and renders the contiguous route
/// the walk took. A same-name member on an unrelated type is never considered.
#[test]
fn csharp_inherited_method_is_attributed_with_owner_depth_and_route() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             class Root { public void Run() { } }\n\
             class Base : Root { }\n\
             class Service : Base { }\n\
             class Decoy { public void Run() { } }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n\
             }\n",
        )],
        "App.cs",
        "service.Run()",
        "Run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.Root.Run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "App.Root");
    assert_eq!(member.hierarchy_depth, 2);
    assert_eq!(member.dispatch_tier.label(), "inherited_or_promoted");
    assert_eq!(
        route(row),
        vec![
            (
                0,
                "App.Service".to_owned(),
                "App.Base".to_owned(),
                "supertype".to_owned()
            ),
            (
                1,
                "App.Base".to_owned(),
                "App.Root".to_owned(),
                "supertype".to_owned()
            ),
        ]
    );
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "App.Decoy.Run"),
        "a same-name member outside the receiver's hierarchy is never considered: {:?}",
        trace.candidates
    );
}

/// A member declared on the receiver's own class outranks the same-name
/// inherited one: the row states the receiver's own class at depth zero with an
/// empty route, and the hidden deeper declaration is never computed, so nothing
/// claims it was considered.
#[test]
fn csharp_direct_member_precedence_is_attributed_at_depth_zero() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             class Base { public void Run() { } }\n\
             class Service : Base { public void Run() { } }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n\
             }\n",
        )],
        "App.cs",
        "service.Run()",
        "Run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.Service.Run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "App.Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier.label(), "inherent_or_direct");
    assert!(member.route.is_empty(), "depth zero has no route to walk");
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "App.Base.Run"),
        "the hidden base declaration is never computed, so it gets no row: {:?}",
        trace.candidates
    );
}

/// A property read through a field-typed receiver is attributed exactly like a
/// method: the field's declared type is the route base, and the property's
/// declaring class is the owner one hop away.
#[test]
fn csharp_inherited_property_is_attributed_at_depth_one() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             class Base { public int Size { get; set; } }\n\
             class Service : Base { }\n\
             class Caller { Service service; int Go() { return service.Size; } }\n\
             }\n",
        )],
        "App.cs",
        "service.Size",
        "Size",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.Base.Size");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "App.Base");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(member.dispatch_tier.label(), "inherited_or_promoted");
    assert_eq!(
        route(row),
        vec![(
            0,
            "App.Service".to_owned(),
            "App.Base".to_owned(),
            "supertype".to_owned()
        )]
    );
}

/// An unqualified member reference resolves against the enclosing class, and
/// the enclosing class is the route base exactly as an explicit receiver would
/// be.
#[test]
fn csharp_unqualified_member_is_attributed_against_the_enclosing_class() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             class Base { protected void Run() { } }\n\
             class Service : Base { void Go() { Run(); } }\n\
             }\n",
        )],
        "App.cs",
        "Run();",
        "Run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.Base.Run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "App.Base");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(
        route(row),
        vec![(
            0,
            "App.Service".to_owned(),
            "App.Base".to_owned(),
            "supertype".to_owned()
        )]
    );
}

/// An overload the walk computed and then discarded on the call's argument
/// count alone is a row, not a silence: it is rejected with the callable-axis
/// reason (#1478) and carries the same owner and depth attribution the winner
/// carries.
#[test]
fn csharp_overload_discarded_on_arity_is_recorded_as_a_deferred_rejection() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             class Service {\n\
             public void Run() { }\n\
             public void Run(int count) { }\n\
             }\n\
             class Caller { void Go(Service service) { service.Run(1); } }\n\
             }\n",
        )],
        "App.cs",
        "service.Run(1)",
        "Run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    assert_eq!(fq_name(selected[0]), "App.Service.Run");
    assert_eq!(
        selected[0]
            .member
            .as_ref()
            .expect("attributed")
            .applicability
            .label(),
        "applicable"
    );

    let rejected: Vec<&TraceCandidate> = trace.rejected().collect();
    assert_eq!(rejected.len(), 1, "{:?}", trace.candidates);
    let loser = rejected[0];
    assert_eq!(fq_name(loser), "App.Service.Run");
    assert_eq!(loser.outcome.label(), "rejected", "{:?}", trace.candidates);
    let member = loser.member.as_ref().expect("a loser is attributed too");
    assert_eq!(member.owner.fq_name(), "App.Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier.label(), "inherent_or_direct");
    assert_eq!(member.applicability.label(), "inapplicable");
}

/// A near miss for the arity rejection above: with no same-name overload to
/// lose, nothing is rejected. An absent rejection row must mean "the walk
/// discarded nothing", not "the walk was not instrumented".
#[test]
fn csharp_single_overload_leaves_no_rejection_row() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             class Service { public void Run(int count) { } }\n\
             class Caller { void Go(Service service) { service.Run(1); } }\n\
             }\n",
        )],
        "App.cs",
        "service.Run(1)",
        "Run",
    );
    assert_eq!(selected(&trace).len(), 1, "{:?}", trace.candidates);
    assert_eq!(
        trace.rejected().count(),
        0,
        "nothing was discarded: {:?}",
        trace.candidates
    );
}

/// A member reached across two partial declarations of the same class is
/// attributed at depth zero: the parts are one type, not a hierarchy, so the
/// row must not manufacture a hop between them.
#[test]
fn csharp_partial_type_member_is_attributed_at_depth_zero() {
    let trace = csharp_trace(
        &[
            (
                "ServicePartA.cs",
                "namespace App {\n\
                 partial class Service { void Go() { Run(); } }\n\
                 }\n",
            ),
            (
                "ServicePartB.cs",
                "namespace App {\n\
                 partial class Service { public void Run() { } }\n\
                 }\n",
            ),
        ],
        "ServicePartA.cs",
        "Run();",
        "Run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.Service.Run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "App.Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier.label(), "inherent_or_direct");
    assert!(
        member.route.is_empty(),
        "partial parts are one type, so there is no hop to record"
    );
}

/// Expected gap (#1477 rule 2, #1724): an interface member is
/// `inherited_or_promoted` over a `supertype` hop, not `trait_or_interface`.
///
/// Both C# ancestor sources report one undifferentiated supertype list -- the
/// unbudgeted path asks the type-hierarchy provider, the bounded path resolves
/// the declaration's raw `: A, IB` spellings -- so no layer the walk reads says
/// which entry was the interface. The bucket the walk can prove is the
/// inherited one; the interface bucket would be an invention. This test locks
/// the honest answer in so a later change cannot quietly start guessing.
#[test]
fn csharp_interface_member_states_the_bucket_the_walk_can_prove() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             interface IRunnable { void Run(); }\n\
             class Service : IRunnable { }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n\
             }\n",
        )],
        "App.cs",
        "service.Run()",
        "Run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.IRunnable.Run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "App.IRunnable");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(
        member.dispatch_tier.label(),
        "inherited_or_promoted",
        "the ancestor source does not differentiate an interface edge"
    );
    assert_eq!(
        route(row),
        vec![(
            0,
            "App.Service".to_owned(),
            "App.IRunnable".to_owned(),
            "supertype".to_owned()
        )]
    );
}

/// Expected gap (#1477 rule 2): a static member accessed through its type name
/// is attributed as an ordinary direct member.
///
/// C# spells a static access exactly like an instance one (`Type.Member`), so
/// the reference site cannot state the static bucket, and the C# adapter
/// records no `callable_is_static` signature metadata, so the declaration
/// cannot state it either. Depth and owner are still exact; only the bucket is
/// the weaker, provable one.
#[test]
fn csharp_static_member_states_the_bucket_the_walk_can_prove() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             static class MathUtils { public static int Twice(int value) { return value + value; } }\n\
             class Caller { int Go() { return MathUtils.Twice(2); } }\n\
             }\n",
        )],
        "App.cs",
        "MathUtils.Twice(2)",
        "Twice",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.MathUtils.Twice");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "App.MathUtils");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(
        member.dispatch_tier.label(),
        "inherent_or_direct",
        "nothing the walk reads distinguishes a static access from an instance one"
    );
}

/// Expected gap (#1477 rule 2): an extension method carries no attribution.
///
/// `visible_extension_method_candidates` admits a method by matching its
/// declared receiver spelling against a set of compatible receiver type names
/// -- the receiver's own type, its supertypes, and names this workspace never
/// indexed -- and returns only the declarations. It reports neither which name
/// matched nor the type it matched, so the get-definition side holds no owner
/// and no hop distance. An unattributed row is honest here; a depth-zero one
/// would claim the extension was declared on the receiver's own type.
#[test]
fn csharp_extension_method_is_selected_without_attribution() {
    let trace = csharp_trace(
        &[(
            "App.cs",
            "namespace App {\n\
             class Service { }\n\
             static class ServiceExtensions { public static void Run(this Service service) { } }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n\
             }\n",
        )],
        "App.cs",
        "service.Run()",
        "Run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "App.ServiceExtensions.Run");
    assert!(
        row.member.is_none(),
        "the extension seam names no owner it matched, so the row states none: {:?}",
        row.member
    );
}

/// A same-name member on an unrelated type is neither selected nor attributed
/// even when the receiver's own hierarchy has no such member at all.
#[test]
fn csharp_wrong_owner_decoy_is_never_selected() {
    let (resolved, trace) = csharp_trace_raw(
        &[(
            "App.cs",
            "namespace App {\n\
             class Decoy { public void Run() { } }\n\
             class Service { }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n\
             }\n",
        )],
        "App.cs",
        "service.Run()",
        "Run",
    );
    assert!(
        !resolved,
        "an unrelated type's member must not answer the reference: {:?}",
        trace.candidates
    );
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "App.Decoy.Run"),
        "the decoy is never considered: {:?}",
        trace.candidates
    );
}
