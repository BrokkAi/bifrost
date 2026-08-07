//! Scala member-candidate attribution conformance for #1477, Milestone 3.
//!
//! Scala's forward member walk (`get_definition/scala.rs`) reaches a member in
//! one of four ways, and each is a different dispatch bucket:
//!
//! - the receiver's own declared owner (`inherent_or_direct` at depth zero), or
//!   that owner when it is a singleton object, which is Scala's static side
//!   (`static_or_companion`);
//! - a supertype found by the breadth-first ancestor walk, which is
//!   `trait_or_interface` when the analyzer's indexed trait facts say the owner
//!   is a trait and `inherited_or_promoted` otherwise;
//! - an extension method whose declared receiver type is the receiver's own
//!   owner (`extension` at depth zero);
//! - and, for a candidate the walk computed and the call-shape filter then
//!   discarded, a rejected row that defers to the callable axis (#1478).
//!
//! One limit is pinned as an *expected gap* rather than worked around: Scala
//! indexes one declaration per overload and overloads share a fq name, while
//! the trace's member-attribution channel is keyed by fq name. Where one
//! overload of a name was attributed and a same-named one was not, the name is
//! left unattributed rather than letting one overload's facts speak for the
//! other's.
//!
//! These assertions run against the production trace rather than the
//! `candidates_of` CodeQuery projection because Scala's structural adapter
//! classifies no occurrence roles (#1724), so no Scala occurrence row reaches
//! that projection yet. The rows this file checks are the same rows the
//! projection will publish once it does.

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

/// Every candidate row the Scala resolver recorded for the member token
/// `member` at its `occurrence`-th appearance in `source` (0-based).
fn member_candidates(source: &str, member: &str, occurrence: usize) -> Vec<TraceCandidate> {
    let project = InlineTestProject::new().file("App.scala", source).build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let file: ProjectFile = project.file("App.scala");

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
        "the fixture must reach the Scala member walk: {outcome:?}"
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

fn route(member: &MemberEnrichment) -> Vec<(usize, String, String, HierarchyRelation)> {
    member
        .route
        .iter()
        .map(|hop| (hop.hop, hop.from.fq_name(), hop.to.fq_name(), hop.relation))
        .collect()
}

/// An inherited member is attributed to the exact superclass it is declared on,
/// at the breadth-first depth of that class, with a contiguous route made of
/// the edges the walk took. The same-name decoy outside the hierarchy is never
/// reached, so no row mentions it.
#[test]
fn inherited_member_is_attributed_to_its_owner_with_the_exact_route() {
    let rows = member_candidates(
        r#"class Root { def run(): Unit = {} }
class Base extends Root
class Service extends Base
class Decoy { def run(): Unit = {} }
object App { def caller(service: Service): Unit = service.run() }
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
    assert_eq!(
        route(&member),
        vec![
            (
                0,
                "Service".to_owned(),
                "Base".to_owned(),
                HierarchyRelation::Extends
            ),
            (
                1,
                "Base".to_owned(),
                "Root".to_owned(),
                HierarchyRelation::Extends
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
        r#"class Base { def run(): Unit = {} }
class Service extends Base { override def run(): Unit = {} }
object App { def caller(service: Service): Unit = service.run() }
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

/// A member reached through a trait is its own dispatch bucket, and the hop
/// that mixed the trait in says so. The analyzer indexes trait-ness per
/// declaration, so unlike the Java and Kotlin walks this one is entitled to the
/// distinction; the class hop below it stays `extends`.
#[test]
fn trait_member_is_attributed_at_the_trait_or_interface_tier() {
    let rows = member_candidates(
        r#"trait Greeter { def greet(): Unit = {} }
class Base extends Greeter
class Service extends Base
object App { def caller(service: Service): Unit = service.greet() }
"#,
        "greet",
        1,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Greeter.greet");
    assert_eq!(member.owner.fq_name(), "Greeter");
    assert_eq!(member.hierarchy_depth, 2);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::TraitOrInterface);
    assert_eq!(
        route(&member),
        vec![
            (
                0,
                "Service".to_owned(),
                "Base".to_owned(),
                HierarchyRelation::Extends
            ),
            (
                1,
                "Base".to_owned(),
                "Greeter".to_owned(),
                HierarchyRelation::TraitImpl
            ),
        ]
    );
}

/// The trait bucket's near miss: a member declared on the receiver's own class
/// outranks the same-name trait member, so the trait declaration is never
/// computed and the winner is the direct bucket at depth zero.
#[test]
fn a_direct_member_shadows_a_same_name_trait_member() {
    let rows = member_candidates(
        r#"trait Greeter { def greet(): Unit = {} }
class Service extends Greeter { override def greet(): Unit = {} }
object App { def caller(service: Service): Unit = service.greet() }
"#,
        "greet",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service.greet");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert!(
        !rows.iter().any(|row| fq_name(row) == "Greeter.greet"),
        "the shadowed trait member is never computed: {rows:?}"
    );
}

/// A member reached through a companion object is Scala's static side and takes
/// the `static_or_companion` bucket.
///
/// Depth stays zero, and that is exact rather than a shortcut: Scala names the
/// companion object itself (`Service` in term position is the object `Service$`),
/// so the walk's receiver owner *is* the object and the member is that owner's
/// own. Depth and bucket are independent axes, which is what lets this row say
/// both things at once. The same-name decoy is never reached.
#[test]
fn companion_object_member_is_attributed_at_the_static_or_companion_tier() {
    let rows = member_candidates(
        r#"class Service(val id: Int)
object Service { def create(): Service = new Service(1) }
class Decoy { def create(): Unit = {} }
object App { def caller(): Unit = println(Service.create()) }
"#,
        "create",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service$.create");
    assert_eq!(member.owner.fq_name(), "Service$");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::StaticOrCompanion);
    assert!(member.route.is_empty());
    assert_eq!(
        selected(&rows)[0].tier,
        Some(PrecedenceTier::OwnMember),
        "a member of the receiver's own object declaration is its own member"
    );
    assert!(
        !rows.iter().any(|row| fq_name(row).starts_with("Decoy")),
        "the wrong-owner decoy is never considered: {rows:?}"
    );
}

/// The companion bucket's near miss: an instance member of the class beside the
/// companion is not the static side, and the walk that found it says so.
#[test]
fn an_instance_member_beside_a_companion_stays_the_direct_tier() {
    let rows = member_candidates(
        r#"class Service(val id: Int) { def describe(): String = "s" }
object Service { def describe(): String = "companion" }
object App { def caller(service: Service): Unit = println(service.describe()) }
"#,
        "describe",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service.describe");
    assert_eq!(member.owner.fq_name(), "Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert!(
        !rows.iter().any(|row| fq_name(row) == "Service$.describe"),
        "the companion member is never computed for an instance receiver: {rows:?}"
    );
}

/// An extension method whose declared receiver type is the receiver's own owner
/// is the `extension` bucket at depth zero. The empty route is exact: Scala
/// admits an extension by resolving its declared receiver type and comparing it
/// to the receiver's owner, which is an identity check and not a hierarchy
/// walk, so an admitted extension is always declared on the owner itself. The
/// extension declared for another receiver is never admitted.
#[test]
fn extension_on_the_receivers_own_type_is_attributed_at_depth_zero() {
    let rows = member_candidates(
        r#"class Service
class Decoy
object ServiceOps:
  extension (s: Service) def describe(): Unit = {}

object DecoyOps:
  extension (d: Decoy) def describe(): Unit = {}

object App:
  import ServiceOps.*
  import DecoyOps.*
  def caller(service: Service): Unit = service.describe()
"#,
        "describe",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "ServiceOps$.describe");
    assert_eq!(member.owner.fq_name(), "Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier, MemberDispatchTier::Extension);
    assert!(member.route.is_empty());
    assert!(
        !rows.iter().any(|row| fq_name(row).starts_with("DecoyOps")),
        "the wrong-receiver extension is never admitted: {rows:?}"
    );
}

/// The extension bucket's near miss: a member declared on the receiver's own
/// type outranks a same-name extension, so the extension ladder is never
/// reached and the extension gets no row at all.
#[test]
fn a_declared_member_shadows_a_same_name_extension() {
    let rows = member_candidates(
        r#"class Service:
  def describe(): Unit = {}

object ServiceOps:
  extension (s: Service) def describe(): Unit = {}

object App:
  import ServiceOps.*
  def caller(service: Service): Unit = service.describe()
"#,
        "describe",
        2,
    );
    let (winner, member) = sole_selected(&rows);
    assert_eq!(winner, "Service.describe");
    assert_eq!(member.dispatch_tier, MemberDispatchTier::InherentOrDirect);
    assert!(
        !rows
            .iter()
            .any(|row| fq_name(row).starts_with("ServiceOps")),
        "the extension is never computed: {rows:?}"
    );
}

/// Expected gap (#1477 rule 2): Scala indexes one declaration per overload and
/// overloads share a fq name, while the member-attribution channel is keyed by
/// fq name. Two extensions for different receivers declared in the same object
/// therefore carry one name, of which only one was admitted by the receiver
/// check. Attributing that name would let the admitted overload's owner speak
/// for the other one, so the name stays unattributed. An unattributed candidate
/// is honest; a shared owner here would be a lie.
#[test]
fn an_extension_name_shared_with_another_receivers_overload_is_left_unattributed() {
    let rows = member_candidates(
        r#"class Service
class Decoy
object Ops:
  extension (s: Service) def describe(): Unit = {}
  extension (d: Decoy) def describe(): Unit = {}

object App:
  import Ops.*
  def caller(service: Service): Unit = service.describe()
"#,
        "describe",
        2,
    );
    let selected = selected(&rows);
    assert!(!selected.is_empty(), "{rows:?}");
    for row in &selected {
        assert_eq!(fq_name(row), "Ops$.describe");
        assert!(
            row.member.is_none(),
            "one fq name names both receivers' overloads, so this seam must \
             state absence rather than a shared owner: {rows:?}"
        );
    }
}

/// A member the walk computed and then discarded because it cannot accept the
/// call's argument list is a row, not a silence, and it carries the same owner
/// and depth attribution a winner would have. The reason defers to the callable
/// axis (#1478) rather than claiming a resolution verdict.
#[test]
fn an_arity_rejected_overload_is_recorded_with_its_own_attribution() {
    let rows = member_candidates(
        r#"class Service { def run(first: Int): Unit = {} }
object App { def caller(service: Service): Unit = service.run() }
"#,
        "run",
        1,
    );
    let row = rows
        .iter()
        .find(|row| !row.is_selected() && fq_name(row) == "Service.run")
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
    assert_eq!(row.tier, Some(PrecedenceTier::OwnMember));
}

/// An inherited overload the walk computed and the call-shape filter then
/// discarded keeps the inherited attribution, which is what makes a rejected
/// row usable: the hop distance and the bucket are the ones the walk measured,
/// not defaults.
#[test]
fn an_inherited_arity_loser_keeps_its_inherited_attribution() {
    let rows = member_candidates(
        r#"class Base { def run(first: Int): Unit = {} }
class Service extends Base
object App { def caller(service: Service): Unit = service.run() }
"#,
        "run",
        1,
    );
    let row = rows
        .iter()
        .find(|row| !row.is_selected() && fq_name(row) == "Base.run")
        .unwrap_or_else(|| panic!("the inherited arity loser must be recorded: {rows:?}"));
    let member = row
        .member
        .as_ref()
        .expect("a discarded candidate carries the attribution the walk held");
    assert_eq!(member.owner.fq_name(), "Base");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(
        member.dispatch_tier,
        MemberDispatchTier::InheritedOrPromoted
    );
    assert_eq!(
        route(member),
        vec![(
            0,
            "Service".to_owned(),
            "Base".to_owned(),
            HierarchyRelation::Extends
        )]
    );
    assert_eq!(row.tier, Some(PrecedenceTier::InheritedMember));
}
