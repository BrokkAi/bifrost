//! Kotlin member-candidate attribution conformance for #1477, Milestone 3.
//!
//! Kotlin's member walk (`get_definition/kotlin.rs::kotlin_member_candidates`)
//! is a breadth-first search over the receiver's own type, its companion when
//! the receiver was named as a type, then its supertypes, then the extension
//! functions visible at the site. Each of those is a different dispatch bucket,
//! and this file pins what the walk is allowed to claim about each.
//!
//! Two limits are pinned as *expected gaps* rather than worked around:
//!
//! - the walk expands ancestors through `get_direct_ancestors`, which reports
//!   undifferentiated supertypes, so a superclass hop and an interface hop are
//!   the same edge here and both record `supertype`/`inherited_or_promoted`;
//! - an extension is admitted by `type_conforms_to`, which answers yes or no
//!   without metering the distance it walked, so only an extension declared
//!   directly on the receiver's own type carries attribution.
//!
//! These assertions run against the production trace rather than the
//! `candidates_of` CodeQuery projection because Kotlin's structural adapter
//! still classifies no occurrence roles (#1473), so no Kotlin occurrence row
//! reaches that projection yet. The rows this file checks are the same rows
//! the projection will publish once it does.

use crate::common::InlineTestProject;
use brokk_bifrost::CancellationToken;
use brokk_bifrost::analyzer::ProjectFile;
use brokk_bifrost::analyzer::structural::{HierarchyRelation, MemberDispatchTier, PrecedenceTier};
use brokk_bifrost::analyzer::usages::get_definition::DefinitionLookupRequest;
use brokk_bifrost::analyzer::usages::get_definition::trace::{
    MemberEnrichment, TraceCandidate, TraceCandidateRef, resolve_definition_batch_with_trace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use std::sync::Arc;

/// Every candidate row the Kotlin resolver recorded for the member token
/// `member` at its `occurrence`-th appearance in `source` (0-based).
fn member_candidates(source: &str, member: &str, occurrence: usize) -> Vec<TraceCandidate> {
    let project = InlineTestProject::new().file("App.kt", source).build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let file: ProjectFile = project.file("App.kt");

    let start = source
        .match_indices(member)
        .map(|(index, _)| index)
        .nth(occurrence)
        .unwrap_or_else(|| panic!("`{member}` does not occur {occurrence} times in the fixture"));
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(start),
        end_byte: Some(start + member.len()),
    };
    let mut traced = resolve_definition_batch_with_trace(
        workspace.analyzer(),
        vec![request],
        file,
        Arc::from(source),
        &CancellationToken::new(),
    );
    assert_eq!(traced.len(), 1, "one request, one trace");
    let (outcome, trace) = traced.remove(0);
    assert!(
        !outcome.definitions.is_empty() || !trace.candidates.is_empty(),
        "the fixture must reach the Kotlin member walk: {outcome:?}"
    );
    trace.candidates
}

fn fq_name(row: &TraceCandidate) -> String {
    match &row.candidate {
        TraceCandidateRef::Unit(unit) => unit.fq_name(),
        other => panic!("expected a unit-backed candidate, got {other:?}"),
    }
}

fn selected(rows: &[TraceCandidate]) -> Vec<&TraceCandidate> {
    rows.iter().filter(|row| row.is_selected()).collect()
}

/// The single selected row for a fixture, with its member attribution.
fn sole_selected(rows: &[TraceCandidate]) -> (String, MemberEnrichment) {
    let selected = selected(rows);
    assert_eq!(selected.len(), 1, "expected one winner, got {selected:?}");
    let row = selected[0];
    let member = row
        .member
        .as_ref()
        .unwrap_or_else(|| panic!("the winner must carry member attribution: {row:?}"));
    (fq_name(row), (**member).clone())
}

/// An inherited member is attributed to the exact supertype it was declared on,
/// at the breadth-first depth of that supertype, with a contiguous route made
/// of the edges the walk took. The same-name decoy outside the hierarchy is
/// never reached, so no row mentions it.
#[test]
fn inherited_member_is_attributed_to_its_owner_with_the_exact_route() {
    let rows = member_candidates(
        r#"open class Root { fun run() {} }
open class Base : Root()
class Service : Base()
class Decoy { fun run() {} }
fun caller(service: Service) { service.run() }
"#,
        "run",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Root.run");
    assert_eq!(member.owner.fq_name(), "Root");
    assert_eq!(member.hierarchy_depth, 2);
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::InheritedOrPromoted
    );
    assert_eq!(
        selected(&rows)[0].tier,
        Some(PrecedenceTier::InheritedMember)
    );

    let route: Vec<(usize, String, String, HierarchyRelation)> = member
        .route
        .iter()
        .map(|hop| (hop.hop, hop.from.fq_name(), hop.to.fq_name(), hop.relation))
        .collect();
    assert_eq!(
        route,
        vec![
            (
                0,
                "Service".to_owned(),
                "Base".to_owned(),
                // `get_direct_ancestors` reports undifferentiated supertypes,
                // so the walk cannot tell an `extends` edge from an
                // `implements` edge and must not claim it can.
                HierarchyRelation::Supertype
            ),
            (
                1,
                "Base".to_owned(),
                "Root".to_owned(),
                HierarchyRelation::Supertype
            ),
        ],
        "the route is contiguous and terminates at the candidate's owner"
    );
    assert!(
        !rows.iter().any(|row| fq_name(row).starts_with("Decoy")),
        "the wrong-owner decoy is never considered: {rows:?}"
    );
}

/// A direct member outranks the same-name inherited one. The row states the
/// direct find: the receiver's own type, depth zero, empty route,
/// `inherent_or_direct`. The hidden supertype declaration is never computed by
/// the walk, so no row claims it was considered.
#[test]
fn direct_member_precedence_is_attributed_at_depth_zero() {
    let rows = member_candidates(
        r#"open class Base { open fun run() {} }
class Service : Base() { override fun run() {} }
fun caller(service: Service) { service.run() }
"#,
        "run",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service.run");
    assert_eq!(member.owner.fq_name(), "Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert!(
        member.route.is_empty(),
        "a direct member has no route to walk"
    );
    assert_eq!(selected(&rows)[0].tier, Some(PrecedenceTier::OwnMember));
    assert!(
        !rows.iter().any(|row| fq_name(row) == "Base.run"),
        "the hidden deeper member is never computed, so no row may claim it \
         was considered: {rows:?}"
    );
}

/// A companion member reached through a type-qualified receiver is its own
/// dispatch bucket. The route states the promotion edge out of the class that
/// declares the companion, so it still terminates at the candidate's owner,
/// while the precedence tier stays `own_member`: a companion of the receiver's
/// own type is not inherited from anywhere.
#[test]
fn companion_member_is_attributed_at_the_static_or_companion_tier() {
    let rows = member_candidates(
        r#"class Service {
    companion object { fun create() {} }
}
class Decoy { fun create() {} }
fun caller() { Service.create() }
"#,
        "create",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service.Companion.create");
    assert_eq!(member.owner.fq_name(), "Service.Companion");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::StaticOrCompanion);
    assert_eq!(member.route.len(), 1);
    assert_eq!(member.route[0].hop, 0);
    assert_eq!(member.route[0].from.fq_name(), "Service");
    assert_eq!(member.route[0].to.fq_name(), "Service.Companion");
    assert_eq!(member.route[0].relation, HierarchyRelation::Embedded);
    assert_eq!(
        selected(&rows)[0].tier,
        Some(PrecedenceTier::OwnMember),
        "a companion of the receiver's own type is that type's own member"
    );
    assert!(
        !rows.iter().any(|row| fq_name(row).starts_with("Decoy")),
        "{rows:?}"
    );
}

/// An instance member of the receiver's own type outranks the same-name
/// companion member, which is the lower-tier near miss for the companion
/// fixture above: the walk reads the class scope before the companion scope,
/// so the companion declaration is never computed.
#[test]
fn a_direct_member_shadows_the_same_name_companion_member() {
    let rows = member_candidates(
        r#"class Service {
    fun create() {}
    companion object { fun create() {} }
}
fun caller(service: Service) { service.create() }
"#,
        "create",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service.create");
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert_eq!(member.hierarchy_depth, 0);
    assert!(
        !rows
            .iter()
            .any(|row| fq_name(row) == "Service.Companion.create"),
        "the shadowed companion member is never computed: {rows:?}"
    );
}

/// An extension function declared directly on the receiver's own type is the
/// `extension` bucket at depth zero: the seam holds the declared receiver it
/// admitted the extension against, and that receiver is the receiver's type
/// itself, so the empty route is exact rather than assumed.
#[test]
fn extension_on_the_receivers_own_type_is_attributed_at_depth_zero() {
    let rows = member_candidates(
        r#"class Service
class Decoy
fun Service.describe() {}
fun Decoy.describe() {}
fun caller(service: Service) { service.describe() }
"#,
        "describe",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "describe");
    assert_eq!(member.owner.fq_name(), "Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::Extension);
    assert!(member.route.is_empty());
}

/// A member declared on the receiver's own type outranks a same-name
/// extension, which is the extension bucket's near miss: the walk returns from
/// the class scope and never reaches the extension ladder, so the extension
/// gets no row at all.
#[test]
fn a_declared_member_shadows_a_same_name_extension() {
    let rows = member_candidates(
        r#"class Service { fun describe() {} }
fun Service.describe() {}
fun caller(service: Service) { service.describe() }
"#,
        "describe",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service.describe");
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert_eq!(rows.len(), 1, "the extension is never computed: {rows:?}");
}

/// Expected gap (#1477 rule 2): an extension declared on a *supertype* of the
/// receiver is admitted by `type_conforms_to`, which answers the conformance
/// question without metering the hops it walked. The seam therefore does not
/// hold a depth or a route for it, and the candidate stays unattributed. An
/// unattributed candidate is honest; a depth zero here would be a lie.
#[test]
fn an_extension_on_a_supertype_is_selected_but_left_unattributed() {
    let rows = member_candidates(
        r#"open class Base
class Service : Base()
fun Base.describe() {}
fun caller(service: Service) { service.describe() }
"#,
        "describe",
        1,
    );
    let selected = selected(&rows);
    assert_eq!(selected.len(), 1, "{rows:?}");
    assert_eq!(fq_name(selected[0]), "describe");
    assert!(
        selected[0].member.is_none(),
        "`type_conforms_to` does not meter the distance it walked, so this \
         seam must state absence rather than a guessed depth: {rows:?}"
    );
}

/// A member the walk computed and then discarded because it cannot accept the
/// call's argument list is a row, not a silence, and it carries the same owner
/// and depth attribution the winner would have. The reason defers to the
/// callable axis (#1478) rather than claiming a resolution verdict.
#[test]
fn an_arity_rejected_overload_is_recorded_with_its_own_attribution() {
    let rows = member_candidates(
        r#"class Service {
    fun run(first: Int) {}
}
fun caller(service: Service) { service.run() }
"#,
        "run",
        1,
    );
    let rejected: Vec<&TraceCandidate> = rows.iter().filter(|row| !row.is_selected()).collect();
    let row = rejected
        .iter()
        .find(|row| fq_name(row) == "Service.run")
        .unwrap_or_else(|| panic!("the arity loser must be recorded: {rows:?}"));
    assert_eq!(
        row.outcome.rejection().map(|reason| reason.label()),
        Some("callable_applicability_deferred"),
        "{rows:?}"
    );
    let member = row
        .member
        .as_ref()
        .expect("a discarded candidate carries the attribution the walk held");
    assert_eq!(member.owner.fq_name(), "Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
}
