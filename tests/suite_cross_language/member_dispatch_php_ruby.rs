//! PHP and Ruby member-dispatch attribution conformance for #1477,
//! Milestone 3.
//!
//! These two languages classify no occurrence roles yet (#1724), so the
//! `occurrences -> candidates_of` pipeline the Java, Rust and TS/Python
//! conformance files use cannot reach a PHP or Ruby member site. The rows are
//! therefore asserted where they are produced: on the production resolution
//! trace itself, which is the same emission the `candidates_of` projection
//! renders once those roles exist.
//!
//! What each fixture pins down is the milestone's rule set: the exact owner the
//! resolver found the member on, the hop distance to that owner, the
//! contiguous route it took, and the language-neutral dispatch bucket -- plus a
//! same-name decoy outside the hierarchy that must never be attributed or
//! selected.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::get_definition::{
    DefinitionLookupRequest, ResolutionTraceResult, TraceCandidate, TraceCandidateRef,
    resolve_definition_batch_with_trace,
};
use brokk_bifrost::{CancellationToken, IAnalyzer, Language, PhpAnalyzer};
use std::sync::Arc;

/// Resolve the reference spelled `member` at the last occurrence of `needle` in
/// `path`, with the trace recording.
fn trace_at(
    analyzer: &dyn IAnalyzer,
    project: &crate::common::BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
    member: &str,
) -> ResolutionTraceResult {
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
    assert!(
        !outcome.definitions.is_empty(),
        "the fixture must resolve: {outcome:?}"
    );
    trace
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

/// The route a candidate reports, rendered as `from -> to` pairs so a test can
/// state the exact hierarchy edges the walk took.
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

fn php_trace(
    files: &[(&str, &str)],
    path: &str,
    needle: &str,
    member: &str,
) -> ResolutionTraceResult {
    let mut project = InlineTestProject::with_language(Language::Php);
    for (name, source) in files {
        project = project.file(*name, *source);
    }
    let project = project.build();
    let analyzer = PhpAnalyzer::from_project(project.project().clone());
    let source = files
        .iter()
        .find(|(name, _)| *name == path)
        .expect("the traced file must be part of the fixture")
        .1;
    trace_at(&analyzer, &project, path, source, needle, member)
}

/// A method inherited through two `extends` hops: the row names the root class
/// as the exact owner, states depth two, and renders the contiguous route the
/// walk took. The same-name decoy outside the hierarchy is never attributed.
#[test]
fn php_inherited_method_is_attributed_with_owner_depth_and_route() {
    let trace = php_trace(
        &[(
            "app.php",
            "<?php\nclass Root { public function run() {} }\nclass Base extends Root {}\nclass Service extends Base {}\nclass Decoy { public function run() {} }\nfunction caller(Service $service) { $service->run(); }\n",
        )],
        "app.php",
        "$service->run()",
        "run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "Root.run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "Root");
    assert_eq!(member.hierarchy_depth, 2);
    assert_eq!(member.dispatch_tier.label(), "inherited_or_promoted");
    assert_eq!(
        route(row),
        vec![
            (
                0,
                "Service".to_owned(),
                "Base".to_owned(),
                "supertype".to_owned()
            ),
            (
                1,
                "Base".to_owned(),
                "Root".to_owned(),
                "supertype".to_owned()
            ),
        ]
    );
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "Decoy.run"),
        "a same-name member outside the receiver's hierarchy is never considered: {:?}",
        trace.candidates
    );
}

/// A direct member outranks the same-name inherited one: the row states the
/// receiver's own class at depth zero with an empty route, and the hidden
/// deeper declaration is never computed, so nothing claims it was considered.
#[test]
fn php_direct_member_precedence_is_attributed_at_depth_zero() {
    let trace = php_trace(
        &[(
            "app.php",
            "<?php\nclass Base { public function run() {} }\nclass Service extends Base { public function run() {} }\nfunction caller(Service $service) { $service->run(); }\n",
        )],
        "app.php",
        "$service->run()",
        "run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "Service.run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier.label(), "inherent_or_direct");
    assert!(member.route.is_empty(), "depth zero has no route to walk");
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "Base.run"),
        "the hidden deeper member is never computed by the production walk: {:?}",
        trace.candidates
    );
}

/// A method a trait composes into the receiver's class: the trait is the exact
/// owner, one hop away, in the trait/interface bucket. The near miss is a trait
/// with the same method that the class does not use.
#[test]
fn php_trait_method_is_attributed_in_the_trait_bucket() {
    let trace = php_trace(
        &[(
            "app.php",
            "<?php\ntrait Runnable { public function run() {} }\ntrait Unused { public function run() {} }\nclass Service { use Runnable; }\nfunction caller(Service $service) { $service->run(); }\n",
        )],
        "app.php",
        "$service->run()",
        "run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "Runnable.run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "Runnable");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(member.dispatch_tier.label(), "trait_or_interface");
    assert_eq!(
        route(row),
        vec![(
            0,
            "Service".to_owned(),
            "Runnable".to_owned(),
            "supertype".to_owned()
        )]
    );
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "Unused.run"),
        "an unused trait with the same method is never considered: {:?}",
        trace.candidates
    );
}

/// An interface method reached through the implementing class: the interface
/// owns it, one hop away, and shares the trait/interface bucket -- the bucket
/// follows the owner's declaration, and the depth axis stays independent.
#[test]
fn php_interface_method_is_attributed_in_the_trait_bucket() {
    let trace = php_trace(
        &[(
            "app.php",
            "<?php\ninterface Runner { public function run(); }\nclass Service implements Runner { }\nfunction caller(Service $service) { $service->run(); }\n",
        )],
        "app.php",
        "$service->run()",
        "run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "Runner.run");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "Runner");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(member.dispatch_tier.label(), "trait_or_interface");
}

/// A `::` access is PHP's static/companion seam, and the row says so whatever
/// the walk found: the inherited class constant keeps its exact owner and hop
/// distance while reporting the static bucket.
#[test]
fn php_static_scope_access_is_attributed_in_the_static_bucket() {
    let trace = php_trace(
        &[(
            "app.php",
            "<?php\nclass Base { const LIMIT = 1; }\nclass Service extends Base {}\nclass Decoy { const LIMIT = 2; }\nfunction caller() { return Service::LIMIT; }\n",
        )],
        "app.php",
        "Service::LIMIT",
        "LIMIT",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "Base.LIMIT");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "Base");
    assert_eq!(member.hierarchy_depth, 1);
    assert_eq!(member.dispatch_tier.label(), "static_or_companion");
    assert_eq!(
        route(row),
        vec![(
            0,
            "Service".to_owned(),
            "Base".to_owned(),
            "supertype".to_owned()
        )]
    );
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "Decoy.LIMIT"),
        "a same-name constant on an unrelated class is never considered: {:?}",
        trace.candidates
    );
}

/// The expected gap: `php_interface_method_declaration_outcome` answers a
/// *declaration* site by walking the enclosing class's supertypes for the
/// interface that declares the same method. That walk pops an undifferentiated
/// stack and keeps no hop distance, so it can name the owner but not the route.
/// An unattributed row is the honest report; a depth invented after the fact
/// would not be.
#[test]
fn php_interface_declaration_site_stays_unattributed() {
    let trace = php_trace(
        &[(
            "app.php",
            "<?php\ninterface Runner { public function run(); }\nclass Service implements Runner { public function run() {} }\n",
        )],
        "app.php",
        "public function run() {}",
        "run",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    assert_eq!(fq_name(selected[0]), "Runner.run");
    assert!(
        selected[0].member.is_none(),
        "the declaration-site seam records no hop distance, so it claims none: {:?}",
        trace.candidates
    );
}

/// A static member declared directly on the named class: the static bucket at
/// depth zero, which is what keeps bucket and depth independent axes.
#[test]
fn php_direct_static_member_is_attributed_at_depth_zero() {
    let trace = php_trace(
        &[(
            "app.php",
            "<?php\nclass Service { public static function build() {} }\nclass Decoy { public static function build() {} }\nfunction caller() { return Service::build(); }\n",
        )],
        "app.php",
        "Service::build()",
        "build",
    );
    let selected = selected(&trace);
    assert_eq!(selected.len(), 1, "{:?}", trace.candidates);
    let row = selected[0];
    assert_eq!(fq_name(row), "Service.build");
    let member = row.member.as_ref().expect("attributed");
    assert_eq!(member.owner.fq_name(), "Service");
    assert_eq!(member.hierarchy_depth, 0);
    assert_eq!(member.dispatch_tier.label(), "static_or_companion");
    assert!(member.route.is_empty());
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| fq_name(row) != "Decoy.build"),
        "{:?}",
        trace.candidates
    );
}
