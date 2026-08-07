//! Go member-dispatch attribution conformance for #1477, Milestone 3.
//!
//! Go has one production `receiver.member` seam: the breadth-first promotion
//! walk in `go_indexed_field_lookup_with_method_set`. It searches the receiver's
//! own type first, then the types its embedded fields name, one embedding level
//! at a time, and stops at the first level that yields a candidate. Every fact
//! the rows here assert is one that walk already held:
//!
//! - the owner is the promotion path's own owner name, resolved to the one
//!   declaration it names;
//! - the depth is the number of embedding hops from the receiver's type to that
//!   owner, and the route is exactly those hops, so each is `embedded`;
//! - `trait_or_interface` is claimed only where the walk's own method-set filter
//!   observed that the candidate declares no receiver, which in Go is exactly an
//!   interface method element;
//! - a method the method-set filter excluded (a `*T` method reached through a
//!   non-addressable `T`) is a rejected row, because Go's method set is a
//!   declaration space rather than a visibility or call-shape rule.
//!
//! These tests drive the production trace directly rather than through
//! `candidates_of`. Go classifies no occurrence roles (#1724), so there is no
//! `member_position` occurrence for the CodeQuery projections to start from;
//! `code_query_candidate_hierarchy.rs` locks that gap in from the query side.
//! The rows asserted here are the same rows those projections will carry once
//! Go learns occurrence-role classification.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{HierarchyRelation, MemberDispatchTier, RejectionReason};
use brokk_bifrost::usages::get_definition::trace::{
    MemberEnrichment, resolve_definition_batch_with_trace,
};
use brokk_bifrost::usages::get_definition::{
    DefinitionLookupRequest, ResolutionTraceResult, TraceCandidate, TraceCandidateRef,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use std::sync::Arc;

/// The trace of one `receiver.member` reference: the last occurrence of
/// `expression` in `source`, focused on `member`.
fn trace_for(source: &str, expression: &str, member: &str) -> ResolutionTraceResult {
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("main.go");

    let expression_start = source
        .rfind(expression)
        .expect("expression is in the source");
    let start_byte = expression_start + expression.find(member).expect("member is in expression");
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(start_byte),
        end_byte: Some(start_byte + member.len()),
    };
    let mut traced = resolve_definition_batch_with_trace(
        workspace.analyzer(),
        vec![request],
        file,
        Arc::<str>::from(source),
        &CancellationToken::new(),
    );
    assert_eq!(traced.len(), 1, "one request produces one trace");
    traced.pop().expect("one trace").1
}

fn unit_name(candidate: &TraceCandidate) -> String {
    match &candidate.candidate {
        TraceCandidateRef::Unit(unit) => unit.fq_name(),
        other => panic!("expected a unit-backed candidate, got {other:?}"),
    }
}

/// The single selected row of `trace`, with its member attribution.
fn selected_member(trace: &ResolutionTraceResult) -> (String, MemberEnrichment) {
    let selected: Vec<&TraceCandidate> = trace.selected().collect();
    assert_eq!(selected.len(), 1, "{trace:#?}");
    let row = selected[0];
    let member = row
        .member
        .as_ref()
        .unwrap_or_else(|| panic!("the selected candidate must be attributed: {trace:#?}"));
    (unit_name(row), (**member).clone())
}

/// A route is contiguous, starts at the receiver's declared owner, ends at the
/// candidate's owner, and is empty exactly when the depth is zero.
fn assert_route_is_contiguous(member: &MemberEnrichment, receiver_owner: &str) {
    assert_eq!(
        member.route.len(),
        member.hierarchy_depth,
        "a route has exactly one hop per hierarchy level: {member:#?}"
    );
    if member.hierarchy_depth == 0 {
        return;
    }
    assert_eq!(
        member.route[0].from.fq_name(),
        receiver_owner,
        "a route starts at the receiver's declared owner: {member:#?}"
    );
    for (index, hop) in member.route.iter().enumerate() {
        assert_eq!(hop.hop, index, "{member:#?}");
        assert_eq!(
            hop.relation,
            HierarchyRelation::Embedded,
            "every Go promotion hop is an embedding edge: {member:#?}"
        );
        if index > 0 {
            assert_eq!(
                member.route[index - 1].to.fq_name(),
                hop.from.fq_name(),
                "hops are contiguous: {member:#?}"
            );
        }
    }
    assert_eq!(
        member
            .route
            .last()
            .expect("a non-empty route has a last hop")
            .to
            .fq_name(),
        member.owner.fq_name(),
        "a route terminates at the candidate's owner: {member:#?}"
    );
}

/// A method promoted through one embedded struct, with a same-name method on an
/// unrelated type present. The walk finds it one embedding hop away, so the row
/// states `main.Base` as the exact owner at depth 1 with a single `embedded`
/// hop, and the decoy is never considered.
#[test]
fn go_promoted_method_is_attributed_at_its_embedding_depth() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Base struct{}\n\
         func (Base) Run() {}\n\
         \n\
         type Service struct{ Base }\n\
         \n\
         type Decoy struct{}\n\
         func (Decoy) Run() {}\n\
         \n\
         func caller(s Service) { s.Run() }\n",
        "s.Run()",
        "Run",
    );
    let (name, member) = selected_member(&trace);
    assert_eq!(name, "main.Base.Run", "{trace:#?}");
    assert_eq!(member.owner.fq_name(), "main.Base", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 1, "{trace:#?}");
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::InheritedOrPromoted,
        "{trace:#?}"
    );
    assert_route_is_contiguous(&member, "main.Service");
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| !unit_name_contains(row, "Decoy")),
        "the wrong-owner decoy is never considered: {trace:#?}"
    );
}

fn unit_name_contains(candidate: &TraceCandidate, needle: &str) -> bool {
    match &candidate.candidate {
        TraceCandidateRef::Unit(unit) => unit.fq_name().contains(needle),
        _ => false,
    }
}

/// Two embedding levels: the route is two contiguous hops through the exact
/// intermediate type the walk expanded, not a single collapsed edge.
#[test]
fn go_two_hop_promotion_records_the_exact_embedding_chain() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Root struct{}\n\
         func (Root) Run() {}\n\
         \n\
         type Middle struct{ Root }\n\
         type Service struct{ Middle }\n\
         \n\
         func caller(s Service) { s.Run() }\n",
        "s.Run()",
        "Run",
    );
    let (name, member) = selected_member(&trace);
    assert_eq!(name, "main.Root.Run", "{trace:#?}");
    assert_eq!(member.owner.fq_name(), "main.Root", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 2, "{trace:#?}");
    assert_route_is_contiguous(&member, "main.Service");
    assert_eq!(member.route[0].to.fq_name(), "main.Middle", "{trace:#?}");
    assert_eq!(member.route[1].from.fq_name(), "main.Middle", "{trace:#?}");
}

/// A method on the receiver's own type outranks the same-name promoted method.
/// The walk stops at level zero, so the row states depth zero with an empty
/// route, and the shadowed promoted declaration -- which the walk never reaches
/// -- gets no row at all.
#[test]
fn go_direct_member_precedence_is_attributed_at_depth_zero() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Base struct{}\n\
         func (Base) Run() {}\n\
         \n\
         type Service struct{ Base }\n\
         func (Service) Run() {}\n\
         \n\
         func caller(s Service) { s.Run() }\n",
        "s.Run()",
        "Run",
    );
    let (name, member) = selected_member(&trace);
    assert_eq!(name, "main.Service.Run", "{trace:#?}");
    assert_eq!(member.owner.fq_name(), "main.Service", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 0, "{trace:#?}");
    assert!(member.route.is_empty(), "{trace:#?}");
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::InherentOrDirect,
        "{trace:#?}"
    );
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| !unit_name_contains(row, "Base.Run")),
        "the hidden promoted member is never computed by the production walk, \
         so no row may claim it was considered: {trace:#?}"
    );
}

/// A method declared by the receiver's interface type. The walk's own method-set
/// filter observes that the candidate declares no receiver, which is what makes
/// it an interface method element, so the bucket is `trait_or_interface` while
/// the depth axis independently stays zero.
#[test]
fn go_interface_method_is_attributed_as_open_dispatch_at_depth_zero() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Greeter interface{ Greet() string }\n\
         \n\
         type Decoy struct{}\n\
         func (Decoy) Greet() string { return \"\" }\n\
         \n\
         func caller(g Greeter) { g.Greet() }\n",
        "g.Greet()",
        "Greet",
    );
    let (name, member) = selected_member(&trace);
    assert_eq!(name, "main.Greeter.Greet", "{trace:#?}");
    assert_eq!(member.owner.fq_name(), "main.Greeter", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 0, "{trace:#?}");
    assert!(member.route.is_empty(), "{trace:#?}");
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::TraitOrInterface,
        "{trace:#?}"
    );
}

/// An embedded interface: the bucket and the depth are independent axes, so the
/// row is `trait_or_interface` *and* one embedding hop away.
#[test]
fn go_embedded_interface_method_is_open_dispatch_one_hop_away() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Greeter interface{ Greet() string }\n\
         type Full interface {\n\
         \tGreeter\n\
         \tName() string\n\
         }\n\
         \n\
         func caller(f Full) { f.Greet() }\n",
        "f.Greet()",
        "Greet",
    );
    let (name, member) = selected_member(&trace);
    assert_eq!(name, "main.Greeter.Greet", "{trace:#?}");
    assert_eq!(member.owner.fq_name(), "main.Greeter", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 1, "{trace:#?}");
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::TraitOrInterface,
        "{trace:#?}"
    );
    assert_route_is_contiguous(&member, "main.Full");
}

/// A struct field promoted through an embedded struct is the same walk and gets
/// the same attribution as a promoted method: field selection and method
/// selection are one seam in Go.
#[test]
fn go_promoted_struct_field_is_attributed_through_the_same_walk() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Base struct{ Label string }\n\
         type Service struct{ Base }\n\
         \n\
         func caller(s Service) { _ = s.Label }\n",
        "s.Label",
        "Label",
    );
    let (name, member) = selected_member(&trace);
    assert_eq!(name, "main.Base.Label", "{trace:#?}");
    assert_eq!(member.owner.fq_name(), "main.Base", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 1, "{trace:#?}");
    assert_route_is_contiguous(&member, "main.Service");
}

/// A `*Service` method reached through a non-addressable `Service` value. The
/// method-set filter computes the candidate and discards it, so it is a rejected
/// row -- attributed with the same owner and depth an admitted candidate would
/// get -- and nothing is selected. `wrong_declaration_space` is the reason: in
/// Go the method is not in the value type's method set at all, which is neither
/// a visibility rule nor a call-argument rule.
#[test]
fn go_method_set_exclusion_is_a_rejected_row_not_a_missing_one() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Service struct{}\n\
         func (*Service) PointerOnly() {}\n\
         \n\
         func MakeValue() Service { return Service{} }\n\
         \n\
         func caller() { MakeValue().PointerOnly() }\n",
        "MakeValue().PointerOnly()",
        "PointerOnly",
    );
    assert_eq!(
        trace.selected().count(),
        0,
        "a value receiver selects no pointer-only method: {trace:#?}"
    );
    let rejected: Vec<&TraceCandidate> = trace
        .rejected()
        .filter(|row| unit_name_contains(row, "PointerOnly"))
        .collect();
    assert_eq!(rejected.len(), 1, "{trace:#?}");
    let row = rejected[0];
    assert_eq!(
        row.outcome,
        brokk_bifrost::analyzer::structural::CandidateOutcome::Rejected(
            RejectionReason::WrongDeclarationSpace
        ),
        "{trace:#?}"
    );
    let member = row
        .member
        .as_ref()
        .unwrap_or_else(|| panic!("a rejected member row is attributed too: {trace:#?}"));
    assert_eq!(member.owner.fq_name(), "main.Service", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 0, "{trace:#?}");
    assert!(member.route.is_empty(), "{trace:#?}");
}

/// The same pointer-only method reached through an addressable value is in the
/// method set, so the near miss above is a method-set decision rather than a
/// blanket refusal of pointer receivers.
#[test]
fn go_addressable_receiver_admits_the_same_pointer_only_method() {
    let trace = trace_for(
        "package main\n\
         \n\
         type Service struct{}\n\
         func (*Service) PointerOnly() {}\n\
         \n\
         func caller() {\n\
         \tvar addressable Service\n\
         \taddressable.PointerOnly()\n\
         }\n",
        "addressable.PointerOnly()",
        "PointerOnly",
    );
    let (name, member) = selected_member(&trace);
    assert_eq!(name, "main.Service.PointerOnly", "{trace:#?}");
    assert_eq!(member.hierarchy_depth, 0, "{trace:#?}");
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::InherentOrDirect,
        "{trace:#?}"
    );
    assert!(
        trace
            .rejected()
            .all(|row| !unit_name_contains(row, "PointerOnly")),
        "an admitted candidate is not also a rejection: {trace:#?}"
    );
}

/// A package-level function selected through a package qualifier is not member
/// selection: no owner type, no method set, no promotion walk. The stated gap is
/// that such a reference resolves with no member attribution at all, rather than
/// being given a plausible-looking depth zero on its package.
#[test]
fn go_package_level_function_selection_is_not_attributed_as_a_member() {
    let trace = trace_for(
        "package main\n\
         \n\
         func Helper() {}\n\
         \n\
         func caller() { Helper() }\n",
        "Helper()",
        "Helper",
    );
    assert!(
        trace.candidates.iter().all(|row| row.member.is_none()),
        "a package-level function is not a member selection: {trace:#?}"
    );
}
