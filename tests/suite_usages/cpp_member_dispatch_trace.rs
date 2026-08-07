//! C++ member-dispatch attribution conformance for #1477, Milestone 3.
//!
//! These tests drive `resolve_definition_batch_with_trace` directly rather than
//! the `candidates_of` CodeQuery projection the Java and Rust tranches use. The
//! projection needs occurrence rows, and the C++ adapter declares
//! `NO_OCCURRENCE_ROLE_SUPPORT` (#1724), so no `member_position` occurrence
//! exists to hang candidate rows on. The trace rows themselves are the same
//! rows the projection would render once that gap closes.
//!
//! What the C++ member seams can attribute:
//!
//! - a member declared on the receiver's own class: depth zero, empty route,
//!   `inherent_or_direct`;
//! - a member reached through the base-class walk: the exact derivation route
//!   the walk took, one hop per `:` base clause, `inherited_or_promoted`;
//! - an overload the call-shape filter refused: a rejected row deferring to the
//!   callable axis (#1478).
//!
//! What they cannot: static-vs-instance. The declaration store indexes a static
//! and a non-static member under the same `owner.member` form, and no
//! structured modifier reaches the member seams, so no C++ candidate claims
//! `static_or_companion`. `cpp_scope_qualified_static_member_is_not_claimed_static`
//! locks that gap in rather than papering over it with a guess.

use crate::common::InlineTestProject;
use brokk_bifrost_analysis::CppAnalyzer;
use brokk_bifrost_analysis::analyzer::structural::resolution::{
    HierarchyRelation, MemberDispatchTier, RejectionReason,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionLookupRequest, ResolutionTraceResult, TraceCandidate, TraceCandidateRef,
    resolve_definition_batch_with_source_and_cancellation, resolve_definition_batch_with_trace,
};
use brokk_bifrost_analysis::cancellation::CancellationToken;
use std::sync::Arc;

const FILE: &str = "app.cpp";

/// The byte range of `token` inside the single occurrence of `anchor`. Both
/// must be unique enough to name one reference site in the fixture.
fn reference_range(source: &str, anchor: &str, token: &str) -> (usize, usize) {
    let anchor_start = source
        .find(anchor)
        .unwrap_or_else(|| panic!("fixture must contain the anchor `{anchor}`"));
    assert_eq!(
        source.matches(anchor).count(),
        1,
        "the anchor `{anchor}` must name exactly one site"
    );
    let start = anchor_start
        + anchor
            .find(token)
            .unwrap_or_else(|| panic!("anchor `{anchor}` must contain `{token}`"));
    (start, start + token.len())
}

/// Resolve one reference with a trace installed, and assert the traced
/// resolution reports exactly what the untraced one does. The trace is an
/// emission; a divergence here would mean it changed a decision.
fn trace_of(source: &str, anchor: &str, token: &str) -> ResolutionTraceResult {
    let project = InlineTestProject::new().file(FILE, source).build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file(FILE);
    let (start_byte, end_byte) = reference_range(source, anchor, token);
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(start_byte),
        end_byte: Some(end_byte),
    };
    let text: Arc<str> = Arc::from(source);

    let untraced = resolve_definition_batch_with_source_and_cancellation(
        &analyzer,
        vec![request.clone()],
        file.clone(),
        Arc::clone(&text),
        &CancellationToken::new(),
    );
    let mut traced = resolve_definition_batch_with_trace(
        &analyzer,
        vec![request],
        file,
        text,
        &CancellationToken::new(),
    );
    assert_eq!(traced.len(), 1, "one request yields one traced outcome");
    let (outcome, trace) = traced.remove(0);
    assert_eq!(
        outcome.status, untraced[0].status,
        "recording must not change the outcome status"
    );
    assert_eq!(
        outcome.definitions, untraced[0].definitions,
        "recording must not change the reported definitions"
    );
    trace
}

fn unit_name(row: &TraceCandidate) -> String {
    match &row.candidate {
        TraceCandidateRef::Unit(unit) => unit.fq_name(),
        other => panic!("expected a workspace declaration row, got {other:?}"),
    }
}

/// The selected rows that carry member attribution, which is what these tests
/// are about. A traced request also records the receiver-type lookups it went
/// through, and those are not member finds.
fn attributed_selection(trace: &ResolutionTraceResult) -> Vec<&TraceCandidate> {
    trace
        .selected()
        .filter(|row| row.member.is_some())
        .collect()
}

fn only_selected(trace: &ResolutionTraceResult) -> &TraceCandidate {
    let selected = attributed_selection(trace);
    assert_eq!(
        selected.len(),
        1,
        "expected exactly one attributed selection, got {:?}",
        trace.candidates
    );
    selected[0]
}

/// The route as `(hop, from, to, relation)`, which is the whole contiguity
/// claim in one comparable shape.
fn route(row: &TraceCandidate) -> Vec<(usize, String, String, HierarchyRelation)> {
    row.member
        .as_ref()
        .expect("row carries member attribution")
        .route
        .iter()
        .map(|hop| (hop.hop, hop.from.fq_name(), hop.to.fq_name(), hop.relation))
        .collect()
}

fn assert_no_row_for(trace: &ResolutionTraceResult, fq_name: &str) {
    assert!(
        trace.candidates.iter().all(|row| !matches!(
            &row.candidate,
            TraceCandidateRef::Unit(unit) if unit.fq_name() == fq_name
        )),
        "`{fq_name}` must never be considered: {:?}",
        trace.candidates
    );
}

/// A member the receiver's own class declares: the direct lookup answers, the
/// base-class walk never runs, and the row says depth zero with no route. The
/// base's same-named member is hidden by C++ name lookup and is never computed,
/// so it gets no row at all -- an absent row, not a weaker one.
#[test]
fn cpp_direct_member_precedence_is_attributed_at_depth_zero() {
    let trace = trace_of(
        "struct Base { void run() {} };\n\
         struct Derived : Base { void run() {} };\n\
         void caller(Derived* derived) { derived->run(); }\n",
        "derived->run()",
        "run",
    );
    let row = only_selected(&trace);
    let member = row.member.as_ref().expect("attribution");
    assert_eq!(unit_name(row), "Derived.run");
    assert_eq!(member.owner.fq_name(), "Derived");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert!(member.route.is_empty(), "depth zero has no route to walk");
    assert_no_row_for(&trace, "Base.run");
}

/// A member only the base class declares: the direct lookup finds nothing, the
/// base-class walk takes one derivation hop, and the row owns the base one hop
/// away in the inherited bucket. The unrelated class with the same member name
/// is not in the receiver's hierarchy and is never considered.
#[test]
fn cpp_inherited_member_is_attributed_through_one_base_hop() {
    let trace = trace_of(
        "struct Base { void run() {} };\n\
         struct Derived : Base {};\n\
         struct Decoy { void run() {} };\n\
         void caller(Derived* derived) { derived->run(); }\n",
        "derived->run()",
        "run",
    );
    let row = only_selected(&trace);
    let member = row.member.as_ref().expect("attribution");
    assert_eq!(unit_name(row), "Base.run");
    assert_eq!(member.owner.fq_name(), "Base");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::InheritedOrPromoted
    );
    assert_eq!(
        route(row),
        vec![(
            0,
            "Derived".to_owned(),
            "Base".to_owned(),
            HierarchyRelation::Extends
        )]
    );
    assert_no_row_for(&trace, "Decoy.run");
}

/// Two derivation levels: the route is contiguous from the receiver's own class
/// to the class that declares the member, one hop per base clause, and its
/// length is exactly the reported depth.
#[test]
fn cpp_inherited_member_route_is_contiguous_across_two_hops() {
    let trace = trace_of(
        "struct Root { void run() {} };\n\
         struct Middle : Root {};\n\
         struct Leaf : Middle {};\n\
         void caller(Leaf* leaf) { leaf->run(); }\n",
        "leaf->run()",
        "run",
    );
    let row = only_selected(&trace);
    let member = row.member.as_ref().expect("attribution");
    assert_eq!(unit_name(row), "Root.run");
    assert_eq!(member.hierarchy_depth, 2);
    assert_eq!(
        route(row),
        vec![
            (
                0,
                "Leaf".to_owned(),
                "Middle".to_owned(),
                HierarchyRelation::Extends
            ),
            (
                1,
                "Middle".to_owned(),
                "Root".to_owned(),
                HierarchyRelation::Extends
            ),
        ]
    );
}

/// Multiple inheritance: two base routes exist and the row records the one the
/// walk actually took to the member, never the other branch.
#[test]
fn cpp_multiple_inheritance_records_the_branch_the_walk_took() {
    let trace = trace_of(
        "struct Left { void ping() {} };\n\
         struct Right { void pong() {} };\n\
         struct Both : Left, Right {};\n\
         void caller(Both* both) { both->pong(); }\n",
        "both->pong()",
        "pong",
    );
    let row = only_selected(&trace);
    let member = row.member.as_ref().expect("attribution");
    assert_eq!(unit_name(row), "Right.pong");
    assert_eq!(member.owner.fq_name(), "Right");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(
        route(row),
        vec![(
            0,
            "Both".to_owned(),
            "Right".to_owned(),
            HierarchyRelation::Extends
        )],
        "the route names the base the member was found on, not the sibling base"
    );
}

/// A member name that exists only on an unrelated class: the receiver's own
/// class and its whole base chain declare nothing of that name, so no candidate
/// is ever attributed to the decoy and none is selected from it.
#[test]
fn cpp_wrong_owner_decoy_is_never_considered() {
    let trace = trace_of(
        "struct Decoy { void run() {} };\n\
         struct Base {};\n\
         struct Derived : Base { void start() {} };\n\
         void caller(Derived* derived) { derived->run(); }\n",
        "derived->run()",
        "run",
    );
    assert_no_row_for(&trace, "Decoy.run");
    assert!(
        attributed_selection(&trace).is_empty(),
        "nothing in the receiver's hierarchy declares `run`: {:?}",
        trace.candidates
    );
}

/// A scope-qualified reference to a static data member. The seam proves the
/// member is declared directly on the named owner and nothing more: it never
/// reads a `static` specifier, and the `Owner::member` spelling is not proof of
/// staticness either (`&Owner::field` and `receiver->Base::method()` share it).
/// So the row states `inherent_or_direct` at depth zero, and no C++ row claims
/// the static/companion bucket. Closing this gap needs a structured modifier on
/// the indexed declaration, not a spelling check.
#[test]
fn cpp_scope_qualified_static_member_is_not_claimed_static() {
    let trace = trace_of(
        "struct Counter { static int total; };\n\
         int Counter::total = 0;\n\
         int read_total() { return Counter::total; }\n",
        "return Counter::total",
        "total",
    );
    let row = only_selected(&trace);
    let member = row.member.as_ref().expect("attribution");
    assert_eq!(member.owner.fq_name(), "Counter");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert!(
        trace.candidates.iter().all(|row| row
            .member
            .as_ref()
            .is_none_or(|member| member.dispatch_tier != MemberDispatchTier::StaticOrCompanion)),
        "no C++ seam holds the static fact, so none may claim the bucket: {:?}",
        trace.candidates
    );
}

/// An overload set the call-shape filter narrows: the loser is a row, not a
/// silence, and its reason defers to the callable axis (#1478) because the only
/// thing it lost on was the argument list.
#[test]
fn cpp_overload_loser_defers_to_the_callable_axis() {
    let trace = trace_of(
        "struct Service {\n\
         \x20 void run(int one) {}\n\
         \x20 void run(int one, int two) {}\n\
         };\n\
         void caller(Service* service) { service->run(1); }\n",
        "service->run(1)",
        "run",
    );
    let selected = attributed_selection(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let rejected: Vec<_> = trace
        .rejected()
        .filter(|row| row.member.is_some())
        .collect();
    assert!(
        !rejected.is_empty(),
        "the discarded overload must be a row: {:?}",
        trace.candidates
    );
    for row in rejected {
        assert_eq!(
            row.outcome,
            brokk_bifrost_analysis::analyzer::structural::resolution::CandidateOutcome::Rejected(
                RejectionReason::CallableApplicabilityDeferred
            ),
            "{:?}",
            trace.candidates
        );
        let member = row.member.as_ref().expect("attribution");
        assert_eq!(member.owner.fq_name(), "Service");
        assert_eq!(member.hierarchy_depth, 0);
    }
}
