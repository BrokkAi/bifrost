use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionBinderKind, ResolutionDeclaredTypeRelationKind, ResolutionEngineRuleKind,
    ResolutionGapFact, ResolutionGapKind,
};
use brokk_bifrost_rust::declarations::parse_rust_file;
use brokk_bifrost_test_macros::hardwon;
use tree_sitter::Parser;

use crate::analyzer::resolution::fact_lowering::LoweringGapOrigin;
use crate::analyzer::resolution::fact_lowering::fixture_names::gap_reason_semantic;
use crate::analyzer::resolution::fact_source::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
    ReasonOwnerRow, SelectedDeclarationAccessSource, SelectedTypedFactSource, TypedFactReadOutcome,
    TypedFactRequest,
};
use crate::analyzer::store::Result as StoreResult;

fn without_callable_signatures(typed: LoweredTypedFragment) -> LoweredTypedFragment {
    LoweredTypedFragment::new(
        typed.fragment(),
        typed.language(),
        typed.frontiers().to_vec(),
        typed.transfers().to_vec(),
        typed.intrinsic_seeds().to_vec(),
        typed.projections().to_vec(),
        typed.qualified_routes().to_vec(),
        typed.declaration_types().to_vec(),
        typed.declaration_visibilities().to_vec(),
        typed.member_scopes().to_vec(),
        typed.member_owners().to_vec(),
        typed.deferred_member_owners().to_vec(),
        typed.construction_requirements().to_vec(),
        typed.supertypes().to_vec(),
        typed.property_gaps().to_vec(),
        typed.call_obligations().to_vec(),
        Vec::new(),
    )
}

struct ExactDeclarationAccessSource {
    identity: SemanticId,
    decisions: Box<[(DeclarationAccessRequest, DeclarationAccessDecision)]>,
    reason_owners: Box<[ReasonOwnerRow]>,
    visits: AtomicUsize,
    reason_owner_visits: AtomicUsize,
}

impl ExactDeclarationAccessSource {
    fn new(
        identity: SemanticId,
        decisions: impl Into<Box<[(DeclarationAccessRequest, DeclarationAccessDecision)]>>,
    ) -> Self {
        Self {
            identity,
            decisions: decisions.into(),
            reason_owners: Box::new([]),
            visits: AtomicUsize::new(0),
            reason_owner_visits: AtomicUsize::new(0),
        }
    }

    fn with_reason_owners(mut self, reason_owners: impl Into<Box<[ReasonOwnerRow]>>) -> Self {
        self.reason_owners = reason_owners.into();
        self
    }

    fn decision(&self, request: DeclarationAccessRequest) -> DeclarationAccessDecision {
        self.decisions
            .iter()
            .find_map(|(known, decision)| (*known == request).then_some(*decision))
            .unwrap_or(DeclarationAccessDecision::Unknown)
    }
}

impl SelectedDeclarationAccessSource for ExactDeclarationAccessSource {
    fn identity(&self) -> SemanticId {
        self.identity
    }

    fn visit_access_pages(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        requests: TypedFactRequest<'_, DeclarationAccessRequest>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> StoreResult<TypedFactReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(incomplete_cancelled()));
        }
        self.visits.fetch_add(1, Ordering::Relaxed);
        let rows = requests
            .as_slice()
            .iter()
            .copied()
            .map(|request| DeclarationAccessRow {
                activation_reason: None,
                request,
                decision: self.decision(request),
                visibility_applies: false,
                subclass_access: None,
            })
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return Ok(TypedFactReadOutcome::exhausted(
                ResolutionCompletion::Complete,
            ));
        }
        if !visitor.visit_page(&rows)? {
            return Ok(TypedFactReadOutcome::stopped(
                ResolutionCompletion::Complete,
            ));
        }
        Ok(TypedFactReadOutcome::exhausted(
            ResolutionCompletion::Complete,
        ))
    }

    fn visit_reason_owners(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, ReasonOwnerRow>,
    ) -> StoreResult<TypedFactReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        self.reason_owner_visits.fetch_add(1, Ordering::Relaxed);
        let rows = reasons
            .as_slice()
            .iter()
            .filter_map(|reason| {
                self.reason_owners
                    .iter()
                    .find(|owner| owner.reason == *reason)
                    .copied()
            })
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return Ok(TypedFactReadOutcome::exhausted(
                ResolutionCompletion::Complete,
            ));
        }
        if !visitor.visit_page(&rows)? {
            return Ok(TypedFactReadOutcome::stopped(
                ResolutionCompletion::Complete,
            ));
        }
        Ok(TypedFactReadOutcome::exhausted(
            ResolutionCompletion::Complete,
        ))
    }
}

const PRIVATE_MEMBER_SOURCE: &str = r#"
pub struct Service;

impl Service {
    fn hidden(&self) {}
}

fn use_service(service: Service) {
    service.hidden();
}
"#;

fn private_member_fixture(label: &[u8]) -> (ParsedRustFixture, SemanticId, SemanticId) {
    let fixture = parsed_rust_fixture(PRIVATE_MEMBER_SOURCE, label);
    let (reference, target) = private_member_semantics(&fixture);
    (fixture, reference, target)
}

fn private_member_semantics(fixture: &ParsedRustFixture) -> (SemanticId, SemanticId) {
    (
        callable_reference_named_at(fixture, "service.hidden", "hidden"),
        definition_after(fixture, "impl Service", "hidden"),
    )
}

fn private_member_fixture_with_other_gap(
    label: &[u8],
) -> (ParsedRustFixture, SemanticId, SemanticId, SemanticId) {
    let reference_position = PRIVATE_MEMBER_SOURCE
        .find("service.hidden")
        .expect("Rust private member reference")
        + "service.".len();
    let fixture = parsed_rust_fixture_with_mutation(PRIVATE_MEMBER_SOURCE, label, |facts| {
        let site = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && fixture_site_starts_at(facts, identifier.site, reference_position)
            })
            .expect("Rust private member callable reference")
            .site;
        facts.gaps.push(ResolutionGapFact::new(
            site,
            ResolutionGapKind::UnsupportedImplicitReceiver,
        ));
    });
    let (reference, target) = private_member_semantics(&fixture);
    let site = fixture
        .facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && fixture_site_starts_at(&fixture.facts, identifier.site, reference_position)
        })
        .expect("Rust private member callable reference")
        .site;
    let other_gap = gap_reason_semantic(
        fixture.lexical.fragment(),
        site,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedImplicitReceiver),
    );
    (fixture, reference, target, other_gap)
}

fn fixture_site_starts_at(
    facts: &FileResolutionFacts,
    site: ResolutionSiteId,
    position: usize,
) -> bool {
    facts.sites[site.index()].start_byte == position
}

fn visibility_gap_reason(fixture: &ParsedRustFixture) -> SemanticId {
    let target_position = fixture
        .source
        .find("fn hidden")
        .expect("Rust private member declaration")
        + "fn ".len();
    let target_site = fixture
        .facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && fixture_site_starts_at(&fixture.facts, identifier.site, target_position)
        })
        .expect("Rust private member declaration site")
        .site;
    fixture
        .lexical
        .gaps()
        .iter()
        .find(|gap| {
            gap.site() == target_site
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedVisibility)
        })
        .expect("private member retains exact visibility gap")
        .reason_semantic()
}



#[test]
fn callee_applicability_does_not_contaminate_receiver_construction() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let fixture = parsed_rust_fixture(
        "pub struct Service; impl Service { pub fn make() {} pub fn run(&self) {} pub fn caller(&self) { Service::make(); self.run(); } }",
        b"callee-transfer-ownership",
    );
    let mut receiver_edges = 0;
    for call in &fixture.facts.calls {
        let reason = gap_reason_semantic(
            fixture.typed.fragment(),
            call.callee,
            LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability),
        );
        assert!(
            fixture
                .lexical
                .gaps()
                .iter()
                .any(|gap| gap.reason_semantic() == reason)
        );
        assert!(fixture.typed.call_obligations().iter().any(|row| {
            row.applicability_reason() == reason
                && row
                    .completion()
                    .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))
        }));
        receiver_edges += fixture
            .facts
            .type_transfers
            .iter()
            .filter(|transfer| {
                fixture.facts.type_slots[transfer.input.index()].site == call.callee
                    || fixture.facts.type_slots[transfer.output.index()].site == call.callee
            })
            .count();
        for transfer in fixture.typed.transfers() {
            assert!(
                !transfer
                    .rule()
                    .completion()
                    .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))
            );
        }
    }
    assert!(
        receiver_edges >= 4,
        "fixture must exercise both receiver construction chains"
    );
    for (marker, name) in [("Service::make", "make"), ("self.run", "run")] {
        let reference = callable_reference_named_at(&fixture, marker, name);
        let target = definition_after(&fixture, &format!("pub fn {name}"), name);
        let reverse = fixture
            .service
            .references_to_many(&[target], &CancellationToken::new())
            .unwrap();
        let answer = &reverse.answers()[0];
        assert_eq!(answer.bindings().len(), 1);
        assert_eq!(answer.bindings()[0].reference(), reference);
        assert_eq!(
            answer.answer().completion(),
            &ResolutionCompletion::Complete
        );
    }
}






const RUST_TWO_UNEXPANDED_ITEM_MACROS: &str = r#"pub mod m {
    pub struct Dim(pub i64);
    macro_rules! from_int {
        ($i:ty, $name:ident) => {
            pub fn $name(v: $i) -> Dim {
                Dim(v as i64)
            }
            impl From<$i> for Dim {
                fn from(v: $i) -> Dim {
                    $name(v)
                }
            }
        };
    }
    from_int!(i32, from_i32);
    from_int!(u8, from_u8);
    from_int!(u16, from_u16);
    pub fn bare() {
        unbound_fn();
    }
}
"#;

#[test]
fn transfer_evidence_retains_noncallee_applicability_and_other_callee_gaps() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let mut injected = Vec::new();
    let fixture = parsed_rust_fixture_with_mutation(
        "pub struct Service; impl Service { pub fn run(&self) {} pub fn caller(&self) { self.run(); } }",
        b"callee-transfer-retained-evidence",
        |facts| {
            let callee = facts.calls[0].callee;
            let transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    facts.type_slots[transfer.output.index()].site == callee
                        && facts.type_slots[transfer.input.index()].site != callee
                })
                .expect("receiver construction has a noncallee input site");
            let input_site = facts.type_slots[transfer.input.index()].site;
            injected = vec![
                ResolutionGapFact::new(input_site, ResolutionGapKind::UnsupportedCallApplicability),
                ResolutionGapFact::new(callee, ResolutionGapKind::UnsupportedExpression),
            ];
            for gap in &injected {
                assert!(!facts.gaps.contains(gap));
                facts.gaps.push(gap.clone());
            }
        },
    );
    for gap in injected {
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(gap_reason_semantic(
            fixture.typed.fragment(),
            gap.site,
            LoweringGapOrigin::Extracted(gap.kind),
        ));
        assert!(
            fixture
                .typed
                .transfers()
                .iter()
                .any(|transfer| transfer.rule().completion().contains_reason(reason))
        );
    }
}


#[test]
fn parsed_rust_argument_independent_binding_does_not_require_signature_inventory() {
        let _neutral_rules = crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[brokk_bifrost_core::analyzer::Language::Rust]);
    // The attributed argument keeps the call-site gap on the result frontier.
    let source = "pub fn target(value: i32) {}\npub fn caller() { target(#[cfg(any())] 1); }\n";
    let mut fixture = parsed_rust_fixture_with_mutation(
        source,
        b"rust-argument-independent-no-signature",
        |_| {},
    );
    fixture.typed = without_callable_signatures(fixture.typed);
    fixture.service = PreloadedFactResolutionService::from_lowered_fragments(
        [fixture.lexical.clone()],
        [fixture.typed.clone()],
    );
    let reference = callable_reference_named_at(&fixture, "target(#[cfg", "target");
    let target = definition_after(&fixture, "pub fn target", "target");

    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust signature-independent name binding succeeds");
    assert_eq!(answer.binding().targets(), &[target]);
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete
    );
    assert!(
        answer
            .projected_frontiers()
            .iter()
            .any(|frontier| matches!(frontier.completion(), ResolutionCompletion::Incomplete(_)))
    );
    assert!(matches!(
        answer.completion(),
        ResolutionCompletion::Incomplete(_)
    ));
}



#[test]
fn selected_declaration_access_allowed_discharges_only_visibility_gap() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let (fixture, reference, target, other_gap) =
        private_member_fixture_with_other_gap(b"rust-declaration-access-allowed");
    let policy = ExactDeclarationAccessSource::new(
        SemanticId::for_test(b"rust-declaration-access-allowed-policy"),
        [(
            DeclarationAccessRequest {
                reference,
                definition: target,
            },
            DeclarationAccessDecision::Allowed,
        )],
    );
    let cancellation = CancellationToken::new();
    let mut operation =
        FactResolutionOperation::new(&fixture.service, &fixture.service, &cancellation)
            .with_declaration_access_source(Some(&policy));
    let answer = operation
        .resolve_reference(reference)
        .expect("selected access policy evaluation succeeds");
    assert_eq!(answer.binding().targets(), &[target]);
    assert!(!answer.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(visibility_gap_reason(&fixture))
    ));
    assert!(
        answer
            .binding()
            .completion()
            .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(other_gap))
    );
}

#[test]
#[hardwon("#3773: an active declaration's non-activation gap remains by identity")]
fn selected_active_local_declaration_keeps_its_unsupported_binder_reason() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let source = "pub fn selected() {}\npub fn caller() { fn selected() {} selected(); }\n";
    let fixture = parsed_rust_fixture(source, b"rust-active-local-owned-gap");
    let local_position = source.rfind("fn selected").expect("local function") + "fn ".len();
    let local = definition_named_at(&fixture, local_position);
    let local_site = fixture
        .facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && fixture_site_starts_at(&fixture.facts, identifier.site, local_position)
        })
        .expect("local function declaration site")
        .site;
    let reason = fixture
        .lexical
        .gaps()
        .iter()
        .find(|gap| {
            gap.site() == local_site
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedScopeOrBinder)
        })
        .expect("active local item carries its unsupported binder reason")
        .reason_semantic();
    let reference = callable_reference_named_at(&fixture, "selected();", "selected");
    let policy = ExactDeclarationAccessSource::new(
        SemanticId::for_test(b"rust-active-local-owned-gap-policy"),
        [(
            DeclarationAccessRequest {
                reference,
                definition: local,
            },
            DeclarationAccessDecision::Allowed,
        )],
    )
    .with_reason_owners([ReasonOwnerRow {
        reason,
        definition: local,
    }]);
    let cancellation = CancellationToken::new();
    let mut operation =
        FactResolutionOperation::new(&fixture.service, &fixture.service, &cancellation)
            .with_declaration_access_source(Some(&policy));
    let answer = operation
        .resolve_reference(reference)
        .expect("active local binding resolves with selected access context");

    assert_eq!(answer.binding().targets(), &[local]);
    assert!(
        answer
            .binding()
            .completion()
            .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))
    );
    assert!(policy.reason_owner_visits.load(Ordering::Relaxed) > 0);
}

#[test]
#[hardwon("#3773: refuting one local binder preserves a same-kind sibling reason")]
fn selected_refuted_local_sibling_does_not_discharge_active_binder_reason() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let source = "pub fn selected() {}\npub fn caller() { #[cfg(not(test))] fn selected() {} #[cfg(test)] fn selected() {} selected(); }\n";
    let fixture = parsed_rust_fixture(source, b"rust-refuted-local-sibling-gap");
    let inactive_prefix = "#[cfg(not(test))] fn ";
    let active_prefix = "#[cfg(test)] fn ";
    let inactive_position =
        source.find(inactive_prefix).expect("inactive local") + inactive_prefix.len();
    let active_position = source.find(active_prefix).expect("active local") + active_prefix.len();
    let inactive = definition_named_at(&fixture, inactive_position);
    let active = definition_named_at(&fixture, active_position);
    let site_at = |position| {
        fixture
            .facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && fixture_site_starts_at(&fixture.facts, identifier.site, position)
            })
            .expect("local function declaration site")
            .site
    };
    let reason_at = |site| {
        fixture
            .lexical
            .gaps()
            .iter()
            .find(|gap| {
                gap.site() == site
                    && gap.origin()
                        == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedScopeOrBinder)
            })
            .expect("local item carries its unsupported binder reason")
            .reason_semantic()
    };
    let inactive_reason = reason_at(site_at(inactive_position));
    let active_reason = reason_at(site_at(active_position));
    let reference = callable_reference_named_at(&fixture, "selected();", "selected");
    let policy = ExactDeclarationAccessSource::new(
        SemanticId::for_test(b"rust-refuted-local-sibling-gap-policy"),
        [
            (
                DeclarationAccessRequest {
                    reference,
                    definition: inactive,
                },
                DeclarationAccessDecision::InactiveActivation,
            ),
            (
                DeclarationAccessRequest {
                    reference,
                    definition: active,
                },
                DeclarationAccessDecision::Allowed,
            ),
        ],
    )
    .with_reason_owners([
        ReasonOwnerRow {
            reason: inactive_reason,
            definition: inactive,
        },
        ReasonOwnerRow {
            reason: active_reason,
            definition: active,
        },
    ]);
    let cancellation = CancellationToken::new();
    let mut operation =
        FactResolutionOperation::new(&fixture.service, &fixture.service, &cancellation)
            .with_declaration_access_source(Some(&policy));
    let answer = operation
        .resolve_reference(reference)
        .expect("complementary local declarations resolve with access context");

    assert_eq!(answer.binding().targets(), &[active]);
    assert!(!answer.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(inactive_reason)
    ));
    assert!(answer.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(active_reason)
    ));
    assert!(policy.reason_owner_visits.load(Ordering::Relaxed) > 0);
}

#[test]
fn selected_declaration_access_denied_removes_target_and_witness_before_applicability() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let (fixture, reference, target) = private_member_fixture(b"rust-declaration-access-denied");
    let policy = ExactDeclarationAccessSource::new(
        SemanticId::for_test(b"rust-declaration-access-denied-policy"),
        [(
            DeclarationAccessRequest {
                reference,
                definition: target,
            },
            DeclarationAccessDecision::Denied,
        )],
    );
    let cancellation = CancellationToken::new();
    let mut operation =
        FactResolutionOperation::new(&fixture.service, &fixture.service, &cancellation)
            .with_declaration_access_source(Some(&policy));
    let answer = operation
        .resolve_reference(reference)
        .expect("denied selected access policy evaluation succeeds");
    assert!(answer.binding().targets().is_empty());
    assert!(answer.binding().witnesses().is_empty());
}
#[test]
fn selected_declaration_access_unknown_retains_target_and_visibility_gap() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let (fixture, reference, target) = private_member_fixture(b"rust-declaration-access-unknown");
    let policy = ExactDeclarationAccessSource::new(
        SemanticId::for_test(b"rust-declaration-access-unknown-policy"),
        [],
    );
    let cancellation = CancellationToken::new();
    let mut operation =
        FactResolutionOperation::new(&fixture.service, &fixture.service, &cancellation)
            .with_declaration_access_source(Some(&policy));
    let answer = operation
        .resolve_reference(reference)
        .expect("unknown selected access policy evaluation succeeds");
    assert_eq!(answer.binding().targets(), &[target]);
    assert!(answer.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(visibility_gap_reason(&fixture))
    ));
}

#[test]
fn unrelated_rust_deferred_name_does_not_suppress_parsed_ordinary_callable() {
    let _neutral_rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Rust,
        ]);
    let source = r#"
fn ordinary() {}
struct Service;
impl Service {
    pub fn unrelated(&self) {}
}
fn use_service(service: Service) {
    ordinary();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-inherent-unrelated-name");
    let reference = callable_reference_named_at(&fixture, "    ordinary()", "ordinary");
    let target = definition_after(&fixture, "fn ordinary", "ordinary");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("ordinary Rust callable resolution succeeds");
    assert_eq!(answer.binding().targets(), &[target]);
}












fn assert_argument_independent_binding_keeps_callsite_gap(
    fixture: &ParsedRustFixture,
    reference: SemanticId,
    answer: &FactResolutionAnswer,
) -> SemanticId {
    let obligation = fixture
        .typed
        .call_obligations()
        .iter()
        .find(|obligation| obligation.callee_reference() == reference)
        .expect("Rust call applicability obligation");
    let call = fixture
        .facts
        .calls
        .iter()
        .find(|call| {
            lowered_semantic_at(
                &fixture.lexical,
                call.callee,
                LoweredSemanticRole::Reference,
            ) == reference
        })
        .expect("Rust call fact");
    let callsite_reason = gap_reason_semantic(
        fixture.lexical.fragment(),
        call.call,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability),
    );
    let callee_reason = obligation.applicability_reason();
    let result_slot = obligation.result_slot();

    assert!(obligation.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete
    );
    assert!(!answer.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callee_reason)
    ));
    assert!(!answer.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    let result_frontier = answer
        .projected_frontiers()
        .iter()
        .find(|frontier| frontier.slot() == result_slot)
        .expect("Rust call result frontier");
    assert!(result_frontier.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    assert!(!result_frontier.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callee_reason)
    ));
    assert!(answer.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    assert!(!answer.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callee_reason)
    ));
    result_slot
}
