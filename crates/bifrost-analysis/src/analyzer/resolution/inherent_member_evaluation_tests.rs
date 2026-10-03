use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionBinderKind, ResolutionDeclaredTypeRelationKind, ResolutionEngineRuleKind, ResolutionGapFact,
    ResolutionGapKind,
};
use brokk_bifrost_rust::declarations::parse_rust_file;
use tree_sitter::Parser;

use crate::analyzer::resolution::fact_lowering::LoweringGapOrigin;
use crate::analyzer::resolution::fact_lowering::fixture_names::gap_reason_semantic;
use crate::analyzer::resolution::fact_source::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
    SelectedDeclarationAccessSource, SelectedTypedFactSource, TypedFactReadOutcome,
    TypedFactRequest,
};
use crate::analyzer::store::Result as StoreResult;

struct ParsedRustFixture {
    source: String,
    facts: FileResolutionFacts,
    lexical: LoweredResolutionFragment,
    typed: LoweredTypedFragment,
    service: PreloadedFactResolutionService,
}

fn parsed_rust_fixture(source: &str, label: &[u8]) -> ParsedRustFixture {
    parsed_rust_fixture_with_mutation(source, label, |_| {})
}

fn parsed_rust_fixture_with_mutation(
    source: &str,
    label: &[u8],
    mutate: impl FnOnce(&mut FileResolutionFacts),
) -> ParsedRustFixture {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust grammar");
    let tree = parser.parse(source, None).expect("Rust fixture tree");
    let root = std::env::current_dir()
        .expect("current directory")
        .join("fact-resolution-rust-correctness");
    let file = ProjectFile::new(root, "src/lib.rs");
    let mut facts = parse_rust_file(&file, source, &tree).resolution_facts;
    mutate(&mut facts);
    let fragment = BindingFragmentId::for_test(label);
    let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Rust, &facts).lexical().clone();
    let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Rust, &facts).typed().clone();
    let service =
        PreloadedFactResolutionService::from_lowered_fragments([lexical.clone()], [typed.clone()]);
    ParsedRustFixture {
        source: source.to_owned(),
        facts,
        lexical,
        typed,
        service,
    }
}

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

fn callable_reference_named_at(
    fixture: &ParsedRustFixture,
    marker: &str,
    terminal_name: &str,
) -> SemanticId {
    let position = fixture
        .source
        .find(marker)
        .unwrap_or_else(|| panic!("Rust fixture lacks callable {marker:?}"));
    let name_position = position
        + marker
            .find(terminal_name)
            .expect("call marker contains callable name");
    let site = [ResolutionNamespace::Callable, ResolutionNamespace::Value]
        .into_iter()
        .find_map(|namespace| {
            fixture.facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == namespace
                    && fixture.facts.sites[identifier.site.index()].start_byte == name_position)
                    .then_some(identifier.site)
            })
        })
        .unwrap_or_else(|| panic!("no callable reference at byte {name_position}"));
    lowered_semantic_at(&fixture.lexical, site, LoweredSemanticRole::Reference)
}

fn definition_named_at(fixture: &ParsedRustFixture, position: usize) -> SemanticId {
    let site = fixture
        .facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && fixture.facts.sites[identifier.site.index()].start_byte == position
        })
        .unwrap_or_else(|| panic!("Rust fixture lacks definition at byte {position}"))
        .site;
    lowered_semantic_at(&fixture.lexical, site, LoweredSemanticRole::Definition)
}

fn definition_after(fixture: &ParsedRustFixture, marker: &str, name: &str) -> SemanticId {
    let marker_position = fixture
        .source
        .find(marker)
        .unwrap_or_else(|| panic!("Rust fixture lacks marker {marker:?}"));
    let name_position = fixture.source[marker_position..]
        .find(name)
        .map(|offset| marker_position + offset)
        .unwrap_or_else(|| panic!("Rust fixture lacks definition {name:?}"));
    definition_named_at(fixture, name_position)
}

fn assert_incomplete(answer: &FactResolutionAnswer) {
    assert!(matches!(
        answer.binding().completion(),
        ResolutionCompletion::Incomplete(_)
    ));
}

struct ExactDeclarationAccessSource {
    identity: SemanticId,
    decisions: Box<[(DeclarationAccessRequest, DeclarationAccessDecision)]>,
    visits: AtomicUsize,
}

impl ExactDeclarationAccessSource {
    fn new(
        identity: SemanticId,
        decisions: impl Into<Box<[(DeclarationAccessRequest, DeclarationAccessDecision)]>>,
    ) -> Self {
        Self {
            identity,
            decisions: decisions.into(),
            visits: AtomicUsize::new(0),
        }
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
    let reference = callable_reference_named_at(&fixture, "service.hidden", "hidden");
    let target = definition_after(&fixture, "impl Service", "hidden");
    (fixture, reference, target)
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
        facts.gaps.push(ResolutionGapFact {
            site,
            kind: ResolutionGapKind::UnsupportedImplicitReceiver,
        });
    });
    let reference = callable_reference_named_at(&fixture, "service.hidden", "hidden");
    let target = definition_after(&fixture, "impl Service", "hidden");
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
fn parsed_rust_inherent_impls_union_same_owner_and_reject_other_owner() {
    let source = r#"
pub struct Service;
pub struct Other;

impl Service {
    pub fn run(&self) {}
}

impl Service {
    pub fn run(&self) {}
}

impl Other {
    pub fn run(&self) {}
}

fn use_service(service: Service) {
    service.run();
}

fn use_other(other: Other) {
    other.run();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-inherent-union");
    let service_reference = callable_reference_named_at(&fixture, "service.run", "run");
    let other_reference = callable_reference_named_at(&fixture, "other.run", "run");
    let first = definition_after(&fixture, "impl Service", "run");
    let first_marker = source.find("impl Service").expect("first impl");
    let second_marker = source[first_marker + "impl Service".len()..]
        .find("impl Service")
        .map(|position| first_marker + "impl Service".len() + position)
        .expect("second impl");
    let second = definition_after(&fixture, &source[second_marker..], "run");
    let other = definition_after(&fixture, "impl Other", "run");

    let service_answer = fixture
        .service
        .resolve_reference(service_reference, &CancellationToken::new())
        .expect("Rust inherent member evaluation succeeds");
    let mut expected = [first, second];
    expected.sort_unstable();
    assert_eq!(service_answer.binding().targets(), &expected);
    assert!(!service_answer.binding().targets().contains(&other));

    let other_answer = fixture
        .service
        .resolve_reference(other_reference, &CancellationToken::new())
        .expect("Rust distinct-owner member evaluation succeeds");
    assert_eq!(other_answer.binding().targets(), &[other]);
}

#[test]
fn parsed_rust_static_and_runtime_qualifiers_select_compatible_members() {
    let source = r#"
pub struct Service;

impl Service {
    pub fn make() {}
    pub fn run(&self) {}
}

fn use_static() {
    Service::make();
}

fn use_runtime(service: Service) {
    service.run();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-inherent-qualifiers");
    let static_reference = callable_reference_named_at(&fixture, "Service::make", "make");
    let runtime_reference = callable_reference_named_at(&fixture, "service.run", "run");
    let static_target = definition_after(&fixture, "impl Service", "make");
    let runtime_target = definition_after(&fixture, "impl Service", "run");

    let static_answer = fixture
        .service
        .resolve_reference(static_reference, &CancellationToken::new())
        .expect("Rust static inherent member evaluation succeeds");
    assert_eq!(static_answer.binding().targets(), &[static_target]);

    let runtime_answer = fixture
        .service
        .resolve_reference(runtime_reference, &CancellationToken::new())
        .expect("Rust runtime inherent member evaluation succeeds");
    assert_eq!(runtime_answer.binding().targets(), &[runtime_target]);
}

#[test]
fn parsed_rust_reference_receivers_autoderef_but_raw_pointers_do_not() {
    let source = r#"
pub struct Service;

impl Service {
    pub fn run(&self) {}
}

fn use_borrowed(borrowed: &&Service) {
    borrowed.run();
}

fn use_raw(raw: *const Service) {
    raw.run();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-reference-autoderef");
    let target = definition_after(&fixture, "impl Service", "run");

    let borrowed_reference = callable_reference_named_at(&fixture, "borrowed.run", "run");
    let borrowed = fixture
        .service
        .resolve_reference(borrowed_reference, &CancellationToken::new())
        .expect("Rust borrowed receiver evaluation succeeds");
    assert_eq!(borrowed.binding().targets(), &[target]);
    assert_eq!(
        borrowed.binding().completion(),
        &ResolutionCompletion::Complete
    );

    let raw_reference = callable_reference_named_at(&fixture, "raw.run", "run");
    assert_ne!(borrowed_reference, raw_reference);
    let raw = fixture
        .service
        .resolve_reference(raw_reference, &CancellationToken::new())
        .expect("Rust raw-pointer receiver evaluation succeeds");
    assert!(raw.binding().targets().is_empty());
    assert_incomplete(&raw);
}

#[test]
fn parsed_rust_owning_smart_pointer_receivers_reach_their_payload_members() {
    let source = r#"
pub struct Service;

impl Service {
    pub fn run(&self) {}
}

fn use_boxed(boxed: Box<Service>) {
    boxed.run();
}

fn use_shared(shared: std::sync::Arc<Service>) {
    shared.run();
}

fn use_counted(counted: Rc<Service>) {
    counted.run();
}

fn use_opaque(opaque: Wrapper<Service>) {
    opaque.run();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-smart-pointer-receiver");
    let target = definition_after(&fixture, "impl Service", "run");
    // `Box<T>`, `Arc<T>` and `Rc<T>` dereference to `T`, so a receiver of one
    // of them reaches `T`'s members with no explicit operation.
    for marker in ["boxed.run", "shared.run", "counted.run"] {
        let reference = callable_reference_named_at(&fixture, marker, "run");
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .expect("Rust smart-pointer receiver evaluation succeeds");
        assert_eq!(answer.binding().targets(), &[target], "{marker}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}"
        );
    }
    // An unknown generic head is not transparent. Its substitution stays
    // unproven, so the receiver keeps the head and finds no member.
    let opaque = callable_reference_named_at(&fixture, "opaque.run", "run");
    let answer = fixture
        .service
        .resolve_reference(opaque, &CancellationToken::new())
        .expect("Rust opaque generic receiver evaluation succeeds");
    assert!(answer.binding().targets().is_empty());
    assert_incomplete(&answer);
}

#[test]
fn parsed_rust_generic_impl_projects_nominal_self_receiver() {
    let source = r#"
pub struct Service<T>(T);

impl<T> Service<T> {
    pub fn run(&self) {}
    pub fn call(&self) { self.run(); }
}

fn use_service(service: Service<u32>) {
    service.run();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-generic-impl-self");
    let target = definition_after(&fixture, "impl<T> Service<T>", "run");
    for marker in ["self.run", "service.run"] {
        let reference = callable_reference_named_at(&fixture, marker, "run");
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .expect("Rust generic inherent member evaluation succeeds");
        assert_eq!(answer.binding().targets(), &[target], "{marker}");
    }
}

#[test]
fn parsed_rust_self_qualified_factory_resolves_through_impl_identity() {
    let source = r#"
pub struct Service;

impl Service {
    pub fn factory() -> Self { Self::new() }
    pub fn new() -> Self { Service }
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-self-qualified-factory");
    let reference = callable_reference_named_at(&fixture, "Self::new", "new");
    let target = definition_after(&fixture, "pub fn new", "new");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust Self-qualified factory evaluation succeeds");
    assert_eq!(answer.binding().targets(), &[target]);
    assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete);
}

#[test]
fn parsed_rust_call_initializer_types_its_let_binding() {
    let source = r#"
pub struct Service;

impl Service {
    pub fn new() -> Self { Service }
    pub fn run(&self) {}
}

fn caller() {
    let service = Service::new();
    service.run();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-call-initializer-let-type");
    let reference = callable_reference_named_at(&fixture, "service.run", "run");
    let target = definition_after(&fixture, "pub fn run", "run");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust inferred let receiver evaluation succeeds");
    assert_eq!(answer.binding().targets(), &[target]);
    assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete);
}

#[test]
fn parsed_rust_unwrapped_initializers_reach_the_payload_and_wrapped_ones_do_not() {
    let source = r#"
pub struct Service;
pub struct Failure;

impl Service {
    pub fn run(&self) {}
}

pub fn make() -> Result<Service, Failure> { loop {} }

fn use_expect() {
    let expected = make().expect("service");
    expected.run();
}

fn use_try() {
    let tried = make()?;
    tried.run();
}

fn use_option(opt: Option<Service>) {
    let taken = opt.unwrap();
    taken.run();
}

fn use_wrapped() {
    let wrapped = make();
    wrapped.run();
}
"#;
    // This context-free fixture isolates payload propagation; the public
    // factory needs no selected module-access proof.
    let fixture = parsed_rust_fixture(source, b"rust-unwrap-initializer");
    let target = definition_after(&fixture, "pub fn run", "run");
    // `?`, `.unwrap()` and `.expect(..)` each remove the one unproven layer
    // that the `Option`/`Result` payload encoding adds, so the binding holds
    // the payload and reaches its members.
    for marker in ["expected.run", "tried.run", "taken.run"] {
        let reference = callable_reference_named_at(&fixture, marker, "run");
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .expect("Rust unwrapped receiver evaluation succeeds");
        assert_eq!(answer.binding().targets(), &[target], "{marker}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}"
        );
    }
    // An un-unwrapped `Result` receiver keeps the payload behind that layer.
    // Refusing it is the point: the incumbent's `ConstructorReturn::NeedsUnwrap`
    // refuses the same receiver, and a transparent projection would be a false
    // affirmative.
    let wrapped = callable_reference_named_at(&fixture, "wrapped.run", "run");
    let answer = fixture
        .service
        .resolve_reference(wrapped, &CancellationToken::new())
        .expect("Rust wrapped receiver evaluation succeeds");
    assert!(answer.binding().targets().is_empty());
    assert_incomplete(&answer);
}

#[test]
fn parsed_rust_self_receiver_keeps_owner_frontier_and_current_instance_origin() {
    let source = r#"
pub struct Service;

impl Service {
    pub fn target(&self) {}
    pub fn caller(&self) { self.target(); }
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-inherent-self-receiver");
    let reference = callable_reference_named_at(&fixture, "self.target", "target");
    let reference_site = fixture
        .facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Callable
                && fixture.facts.sites[identifier.site.index()].start_byte
                    == fixture.source.find("self.target").unwrap() + 5
        })
        .expect("self target callable reference");
    assert_eq!(
        fixture.facts.sites[reference_site.site.index()].kind,
        ResolutionSiteKind::MemberReference
    );
    assert_eq!(
        fixture
            .facts
            .callable_receiver_origins
            .iter()
            .find(|origin| origin.reference == reference_site.site)
            .map(|origin| origin.origin),
        Some(ResolutionCallableReceiverOrigin::CurrentInstance)
    );
    let self_declarations = fixture.facts.identifiers.iter().filter(|identifier| {
        identifier.role == ResolutionIdentifierRole::Declaration
            && identifier.namespace == ResolutionNamespace::Value
            && fixture.facts.names[identifier.name.index()].spelling == "self"
    }).collect::<Vec<_>>();
    assert_eq!(self_declarations.len(), 2);
    for declaration in self_declarations {
        assert!(fixture.facts.binders.iter().any(|binder| {
            binder.declaration == declaration.site
                && binder.kind == ResolutionBinderKind::Parameter
        }));
        assert!(fixture.facts.declaration_type_slots.iter().any(|property| {
            property.declaration == declaration.site
                && property.role == DeclarationTypeRole::Parameter
        }));
    }

    let qualifier = reference_site
        .qualifier
        .expect("self member callable retains a receiver qualifier");
    let owner_type = fixture
        .facts
        .declared_type_relations
        .iter()
        .find(|relation| {
            relation.kind == ResolutionDeclaredTypeRelationKind::InherentImplementation
        })
        .map(|relation| relation.subject)
        .expect("inherent impl owner frontier");
    let nominal = fixture.facts.binding_projections.iter().find(|projection| {
        projection.output == owner_type
            && projection.kind == BindingProjectionKind::TargetNominalTypeIdentity
    }).expect("impl owner uses the nominal output");
    let receiver_type = fixture.facts.binding_projections.iter().find(|projection| {
        projection.reference == nominal.reference
            && projection.kind == BindingProjectionKind::TargetTypeIdentity
    }).expect("impl receiver uses the paired payload output").output;
    assert_ne!(owner_type, receiver_type);
    assert!(fixture.facts.type_transfers.iter().any(|transfer| {
        transfer.input == receiver_type
            && transfer.output == qualifier
            && transfer.kind == ResolutionTypeTransferKind::Receiver
            && transfer.indirection_delta == 0
            && transfer.value_transform
                == ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
    }));
    let target = definition_after(&fixture, "pub fn target", "target");
    let forward = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("self member forward evaluation");
    assert_eq!(forward.binding().targets(), &[target]);
    assert_eq!(
        forward.binding().completion(),
        &ResolutionCompletion::Complete
    );
    let reverse = fixture
        .service
        .references_to_many(&[target], &CancellationToken::new())
        .expect("self member reverse evaluation");
    let bindings = reverse.answers()[0].bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].reference(), reference);
    assert_eq!(bindings[0].definitions(), &[target]);
    assert_eq!(bindings[0].completion(), &ResolutionCompletion::Complete);
}

#[test]
fn callee_applicability_does_not_contaminate_receiver_construction() {
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

#[test]
fn transfer_evidence_retains_noncallee_applicability_and_other_callee_gaps() {
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
                ResolutionGapFact {
                    site: input_site,
                    kind: ResolutionGapKind::UnsupportedCallApplicability,
                },
                ResolutionGapFact {
                    site: callee,
                    kind: ResolutionGapKind::UnsupportedExpression,
                },
            ];
            for gap in &injected {
                assert!(!facts.gaps.contains(gap));
                facts.gaps.push(*gap);
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
fn parsed_rust_named_calls_emit_argument_independent_binding_eligibility() {
    let source = r#"
pub fn direct() {}
pub fn generic<T>(value: T) {}
pub fn computed(pair: (fn(),)) {
    pair.0();
}

pub mod nested {
    pub fn qualified() {}
}

pub struct Service;

impl Service {
    pub fn run(&self) {}
}

pub fn caller(service: Service) {
    direct();
    crate::nested::qualified();
    service.run();
    generic::<Service>(service);
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-call-eligibility");
    let mut explicit_type_argument_counts = fixture
        .facts
        .calls
        .iter()
        .map(|call| call.explicit_type_argument_count)
        .collect::<Vec<_>>();
    explicit_type_argument_counts.sort_unstable();
    assert_eq!(explicit_type_argument_counts, vec![0, 0, 0, 1]);
    // One argument-independent-binding row per call. The Rust producer also
    // emits an open-member-surface row per qualified reference, which is a
    // different rule on a different site, so the count is per rule.
    assert_eq!(
        fixture
            .facts
            .engine_rule_eligibilities
            .iter()
            .filter(|eligibility| {
                eligibility.rule == ResolutionEngineRuleKind::ArgumentIndependentBinding
            })
            .count(),
        fixture.facts.calls.len()
    );
    assert!(fixture.facts.calls.iter().all(|call| {
        fixture
            .facts
            .engine_rule_eligibilities
            .iter()
            .any(|eligibility| {
                eligibility.site == call.call
                    && eligibility.rule == ResolutionEngineRuleKind::ArgumentIndependentBinding
            })
    }));
    let generic_call = fixture
        .facts
        .calls
        .iter()
        .find(|call| call.explicit_type_argument_count == 1)
        .expect("generic call retains its explicit type argument count");
    // Every argument list here is exact, so every call publishes the
    // coercion filter's permission beside its argument rows, and none keeps a
    // call-site applicability gap.
    assert!(fixture.facts.calls.iter().all(|call| {
        fixture
            .facts
            .engine_rule_eligibilities
            .iter()
            .any(|eligibility| {
                eligibility.site == call.call
                    && eligibility.rule == ResolutionEngineRuleKind::ArgumentCoercionFilter
            })
    }));
    assert_eq!(
        fixture
            .facts
            .call_arguments
            .iter()
            .filter(|argument| argument.call == generic_call.call)
            .count(),
        1
    );
    assert!(!fixture.facts.gaps.iter().any(|gap| {
        gap.site == generic_call.call && gap.kind == ResolutionGapKind::UnsupportedCallApplicability
    }));
}

#[test]
fn parsed_rust_argument_independent_binding_is_complete_before_result_projection() {
    // An attribute on an argument can remove it, so this call keeps its
    // call-site applicability gap: invocation uncertainty the binding must not
    // absorb.
    let source = "pub fn target(value: i32) {}\npub fn caller() { target(#[cfg(any())] 1); }\n";
    let fixture = parsed_rust_fixture(source, b"rust-argument-independent-binding");
    let reference = callable_reference_named_at(&fixture, "target(#[cfg", "target");
    let target = definition_after(&fixture, "pub fn target", "target");
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
            lowered_semantic_at(&fixture.lexical, call.callee, LoweredSemanticRole::Reference)
                == reference
        })
        .expect("Rust call fact");
    let callsite_reason = gap_reason_semantic(
        fixture.lexical.fragment(),
        call.call,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability),
    );
    let callee_reason = obligation.applicability_reason();
    assert!(obligation.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));

    let point = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust argument-independent point evaluation succeeds");
    assert_eq!(point.binding().targets(), &[target]);
    assert_eq!(
        point.binding().completion(),
        &ResolutionCompletion::Complete
    );
    assert!(!point.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callee_reason)
    ));
    assert!(!point.binding().completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    let result_frontier = point
        .projected_frontiers()
        .iter()
        .find(|frontier| frontier.slot() == obligation.result_slot())
        .expect("Rust call result frontier");
    assert!(result_frontier.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    assert!(!result_frontier.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callee_reason)
    ));
    assert!(point.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    assert!(!point.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callee_reason)
    ));
    assert!(
        point
            .projected_frontiers()
            .iter()
            .any(|frontier| matches!(frontier.completion(), ResolutionCompletion::Incomplete(_)))
    );
    assert!(matches!(
        point.completion(),
        ResolutionCompletion::Incomplete(_)
    ));

    let reverse = fixture
        .service
        .references_to_many(&[target], &CancellationToken::new())
        .expect("Rust argument-independent reverse evaluation succeeds");
    let binding = &reverse.answers()[0].bindings()[0];
    assert_eq!(binding.reference(), reference);
    assert_eq!(binding.definitions(), &[target]);
    assert_eq!(binding.completion(), &ResolutionCompletion::Complete);
}

#[test]
fn parsed_rust_argument_independent_binding_retains_name_ambiguity() {
    let source = concat!(
        "pub fn target(value: i32) {}\n",
        "pub fn target(value: i32) {}\n",
        "pub fn caller() { target(1); }\n",
    );
    let fixture = parsed_rust_fixture(source, b"rust-argument-independent-ambiguity");
    let reference = callable_reference_named_at(&fixture, "target(1)", "target");
    let first_target = definition_after(&fixture, "pub fn target", "target");
    let first_target_position = source.find("pub fn target").expect("first target");
    let second_target_position = source[first_target_position + "pub fn target".len()..]
        .find("pub fn target")
        .map(|offset| first_target_position + "pub fn target".len() + offset)
        .expect("second target");
    let second_target = definition_after(&fixture, &source[second_target_position..], "target");
    let mut expected = [first_target, second_target];
    expected.sort_unstable();
    assert_eq!(expected.len(), 2);

    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust ambiguous argument-independent evaluation succeeds");
    assert_eq!(answer.binding().targets(), expected.as_slice());
}

#[test]
fn parsed_rust_argument_independent_binding_does_not_require_signature_inventory() {
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
fn parsed_rust_argument_independent_binding_closes_missing_name_without_function_target() {
    // The attributed argument keeps the call-site gap on the result frontier.
    let source = "pub fn caller() { missing(#[cfg(any())] 1); }\n";
    let fixture = parsed_rust_fixture(source, b"rust-argument-independent-missing-name");
    let reference = callable_reference_named_at(&fixture, "missing(#[cfg", "missing");
    let obligation = fixture
        .typed
        .call_obligations()
        .iter()
        .find(|obligation| obligation.callee_reference() == reference)
        .expect("Rust missing-name call applicability obligation");
    let call = fixture
        .facts
        .calls
        .iter()
        .find(|call| {
            lowered_semantic_at(&fixture.lexical, call.callee, LoweredSemanticRole::Reference)
                == reference
        })
        .expect("Rust missing-name call fact");
    let callsite_reason = gap_reason_semantic(
        fixture.lexical.fragment(),
        call.call,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability),
    );
    let callee_reason = obligation.applicability_reason();
    assert!(obligation.completion().contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(callsite_reason)
    ));
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust missing callable name evaluation succeeds");
    assert!(answer.binding().targets().is_empty());
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
        .find(|frontier| frontier.slot() == obligation.result_slot())
        .expect("Rust missing-name call result frontier");
    assert!(result_frontier.possible_values().is_empty());
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
    assert!(
        answer
            .projected_frontiers()
            .iter()
            .all(|frontier| frontier.possible_values().is_empty())
    );
}

#[test]
fn parsed_rust_argument_independent_binding_retains_local_value_binder() {
    let source = "pub fn caller() { let local = 1; local(1); }\n";
    let fixture = parsed_rust_fixture(source, b"rust-argument-independent-local-value");
    let reference = callable_reference_named_at(&fixture, "local(1)", "local");
    let local = definition_after(&fixture, "let local", "local");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust local value call evaluation succeeds");
    assert_eq!(answer.binding().targets(), &[local]);
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete
    );
}

#[test]
fn parsed_rust_private_member_keeps_visibility_uncertainty() {
    let source = r#"
pub struct Service;

impl Service {
    fn hidden(&self) {}
}

fn use_service(service: Service) {
    service.hidden();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-inherent-private");
    let reference = callable_reference_named_at(&fixture, "service.hidden", "hidden");
    let target = definition_after(&fixture, "impl Service", "hidden");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust private inherent member evaluation succeeds");
    assert!(answer.binding().targets().contains(&target));
    assert_incomplete(&answer);
}

#[test]
fn selected_declaration_access_allowed_discharges_only_visibility_gap() {
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
fn selected_declaration_access_denied_removes_target_and_witness_before_applicability() {
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
fn selected_declaration_access_exact_pair_is_memoized_across_point_evaluations() {
    let (fixture, reference, target) = private_member_fixture(b"rust-declaration-access-memo");
    let policy = ExactDeclarationAccessSource::new(
        SemanticId::for_test(b"rust-declaration-access-memo-policy"),
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
    let first = operation
        .resolve_reference(reference)
        .expect("first memoized selected access evaluation succeeds");
    let first_visits = policy.visits.load(Ordering::Relaxed);
    assert!(first_visits > 0, "the first resolution evaluates selected access");
    let second = operation
        .resolve_reference(reference)
        .expect("second memoized selected access evaluation succeeds");
    assert_eq!(first.binding().targets(), &[target]);
    assert_eq!(second.binding().targets(), &[target]);
    assert_eq!(policy.visits.load(Ordering::Relaxed), first_visits);
}

#[test]
fn parsed_rust_generic_impl_self_reaches_sibling_nominal_member() {
    let fixture = parsed_rust_fixture(
        r#"
pub struct Wrapper<T> { value: T }
impl<T> Wrapper<T> { pub fn first(&self) { self.second(); } }
impl<T> Wrapper<T> { pub fn second(&self) {} }
"#,
        b"rust-generic-impl-self",
    );
    let reference = callable_reference_named_at(&fixture, "self.second", "second");
    let definition = definition_after(&fixture, "pub fn second", "second");
    let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
    assert_eq!(answer.binding().targets(), &[definition], "{answer:?}");
    assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete, "{answer:?}");
    let reverse = fixture.service.references_to(definition, &CancellationToken::new()).unwrap();
    assert_eq!(reverse.references(), &[reference], "{reverse:?}");
    assert_eq!(reverse.completion(), &ResolutionCompletion::Complete, "{reverse:?}");
}

#[test]
fn parsed_rust_generic_receiver_remains_incomplete() {
    let source = r#"
fn use_generic<T>(value: T) {
    value.run();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-inherent-generic-gap");
    let reference = callable_reference_named_at(&fixture, "value.run", "run");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust generic receiver evaluation succeeds");
    assert!(answer.binding().targets().is_empty());
    assert_incomplete(&answer);
}

#[test]
fn unrelated_rust_deferred_name_does_not_suppress_parsed_ordinary_callable() {
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

#[test]
fn parsed_rust_trait_impl_calls_keep_the_implementing_owner() {
    let source = "pub trait Work { fn work(&self); } pub struct Service; pub struct Other; impl Work for Service { fn work(&self) { self.work(); } } impl Other { pub fn work(&self) {} } fn use_service(service: Service) { service.work(); }";
    let fixture = parsed_rust_fixture(source, b"rust-trait-impl-owner");
    let expected = definition_after(&fixture, "impl Work for Service", "work");
    for marker in ["self.work", "service.work"] {
        let reference = callable_reference_named_at(&fixture, marker, "work");
        let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
        assert_eq!(answer.binding().targets(), &[expected]);
    }
    let contract = definition_after(&fixture, "pub trait Work", "work");
    let reverse = fixture.service.references_to(contract, &CancellationToken::new()).unwrap();
    let caller = callable_reference_named_at(&fixture, "service.work", "work");
    assert!(reverse.references().contains(&caller), "{reverse:?}");

}

#[test]
fn parsed_rust_type_alias_frontiers_preserve_exact_member_owners() {
    let source = r#"
pub struct First;
pub struct Second;
impl First { pub fn new() -> Self { First } pub fn run(&self) {} }
impl Second { pub fn new() -> Self { Second } pub fn run(&self) {} }
pub type Alias = First;
pub type Chain = Alias;
fn outer(value: Chain) { value.run(); Alias::new(); }
fn inner() { type Alias = Second; Alias::new(); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-alias-exact-owners");
    let first_run = definition_after(&fixture, "impl First", "run");
    let first_new = definition_after(&fixture, "impl First", "new");
    let second_new = definition_after(&fixture, "impl Second", "new");
    for (marker, name, expected) in [
        ("value.run", "run", first_run),
        ("value.run(); Alias::new", "new", first_new),
        ("Second; Alias::new", "new", second_new),
    ] {
        let reference = callable_reference_named_at(&fixture, marker, name);
        let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
        assert_eq!(answer.binding().targets(), &[expected], "{marker}: {answer:?}");
        assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete, "{marker}: {answer:?}");
    }
    let reverse = fixture.service.references_to(first_run, &CancellationToken::new()).unwrap();
    assert!(reverse.references().contains(&callable_reference_named_at(&fixture, "value.run", "run")), "{reverse:?}");
}

#[test]
fn parsed_rust_generic_type_alias_preserves_associated_member_owner() {
    let source = r#"
enum EitherWriter<A, B> { A(A), B(B) }
type OptionalWriter<T> = EitherWriter<T, ()>;
impl<T> OptionalWriter<T> {
    fn some(value: T) -> Self { EitherWriter::A(value) }
}
fn make() { let _ = OptionalWriter::some(1usize); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-generic-alias-member-owner");
    let expected = definition_after(&fixture, "impl<T> OptionalWriter<T>", "some");
    let reference = callable_reference_named_at(&fixture, "OptionalWriter::some", "some");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();

    assert_eq!(answer.binding().targets(), &[expected], "{answer:?}");
}

#[test]
fn parsed_rust_type_aliases_preserve_reference_and_pointer_qualifiers() {
    let source = r#"
pub struct Service;
impl Service { pub fn run(&self) {} }
pub type Borrowed = &'static Service;
pub type Raw = *const Service;
fn borrowed(value: Borrowed) { value.run(); }
fn raw(pointer: Raw) { pointer.run(); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-alias-reference-qualifiers");
    let target = definition_after(&fixture, "impl Service", "run");
    let reference = callable_reference_named_at(&fixture, "value.run", "run");
    let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
    assert_eq!(answer.binding().targets(), &[target], "{answer:?}");
    assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete, "{answer:?}");
    let pointer = callable_reference_named_at(&fixture, "pointer.run", "run");
    let answer = fixture.service.resolve_reference(pointer, &CancellationToken::new()).unwrap();
    assert!(answer.binding().targets().is_empty(), "{answer:?}");
    assert_incomplete(&answer);
}

#[test]
fn parsed_rust_associated_types_follow_the_impl_owner() {
    let source = r#"
pub trait Runner { type Output; }
pub struct Service;
pub struct Payload;
impl Payload { pub fn run(&self) {} }
impl Runner for Service {
    type Output = Payload;
    fn own(value: Self::Output) { value.run(); }
}
type Selected = <Service as Runner>::Output;
fn invoke(value: Selected) { value.run(); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-associated-type-owner");
    let expected = definition_after(&fixture, "impl Runner for Service", "Output");
    for marker in ["Self::Output", "<Service as Runner>::Output"] {
        let position = source.find(marker).unwrap() + marker.rfind("Output").unwrap();
        let identifier = fixture.facts.identifiers.iter().find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && fixture.facts.sites[identifier.site.index()].start_byte == position
        }).expect("associated type reference");
        let reference = lowered_semantic_at(&fixture.lexical, identifier.site, LoweredSemanticRole::Reference);
        let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
        assert_eq!(answer.binding().targets(), &[expected], "{marker}: {answer:?}");
        assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete, "{marker}: {answer:?}");
    }
    let method = definition_after(&fixture, "impl Payload", "run");
    let calls = fixture.facts.identifiers.iter().filter(|identifier| {
        identifier.role == ResolutionIdentifierRole::Reference
            && fixture.facts.names[identifier.name.index()].spelling == "run"
    }).map(|identifier| lowered_semantic_at(&fixture.lexical, identifier.site, LoweredSemanticRole::Reference));
    for reference in calls {
        let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
        assert_eq!(answer.binding().targets(), &[method], "{answer:?}");
    }
    let contract = definition_after(&fixture, "pub trait Runner", "Output");
    let reverse = fixture.service.references_to(contract, &CancellationToken::new()).unwrap();
    assert_eq!(reverse.references().len(), 2, "{reverse:?}");
}

#[test]
fn parsed_rust_trait_bound_receivers_select_declarations() {
    let source = r#"
pub trait Store { fn get(&self); }
pub trait Registry { fn get(&self); }
pub struct Concrete;
impl Store for Concrete { fn get(&self) {} }
fn inline<T: Store>(inline_value: &T) { inline_value.get(); }
fn constrained<T>(where_value: &T) where T: Store { where_value.get(); }
fn opaque(opaque_value: &impl Store) { opaque_value.get(); }
fn dynamic(dynamic_value: &dyn Store) { dynamic_value.get(); }
fn both<T: Store + Registry>(both_value: &T) { both_value.get(); }
fn other<T: Registry>(other_value: &T) { other_value.get(); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-trait-bound-receivers");
    let store = definition_after(&fixture, "pub trait Store", "get");
    let registry = definition_after(&fixture, "pub trait Registry", "get");
    for (marker, mut expected) in [
        ("inline_value.get", vec![store]),
        ("where_value.get", vec![store]),
        ("opaque_value.get", vec![store]),
        ("dynamic_value.get", vec![store]),
        ("both_value.get", vec![store, registry]),
        ("other_value.get", vec![registry]),
    ] {
        expected.sort_unstable();
        let reference = callable_reference_named_at(&fixture, marker, "get");
        let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
        assert_eq!(answer.binding().targets(), expected, "{marker}: {answer:?}");
        assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete, "{marker}: {answer:?}");
    }
    let reordered = parsed_rust_fixture_with_mutation(source, b"rust-trait-bound-receivers", |facts| {
        facts.type_transfers.reverse();
    });
    let reference = callable_reference_named_at(&reordered, "both_value.get", "get");
    let reordered_answer = reordered.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
    let reference = callable_reference_named_at(&fixture, "both_value.get", "get");
    let original_answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
    assert_eq!(reordered_answer.binding(), original_answer.binding());
    let implementation = definition_after(&fixture, "impl Store for Concrete", "get");
    assert!(fixture.service.references_to(implementation, &CancellationToken::new()).unwrap().references().is_empty());
    assert_eq!(fixture.service.references_to(store, &CancellationToken::new()).unwrap().references().len(), 5);
}

#[test]
fn parsed_rust_unknown_bound_keeps_an_unproven_reverse_site() {
    let fixture = parsed_rust_fixture(r#"
pub trait Store { fn get(&self); }
fn unknown<T: Missing>(value: &T) { value.get(); }
"#, b"rust-unknown-bound");
    let definition = definition_after(&fixture, "pub trait Store", "get");
    let reference = callable_reference_named_at(&fixture, "value.get", "get");
    let forward = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
    assert!(forward.binding().targets().is_empty(), "{forward:?}");
    assert!(forward.type_bound_receiver);
    let reverse = fixture.service.references_to(definition, &CancellationToken::new()).unwrap();
    assert_eq!(reverse.references(), &[reference]);
    assert!(reverse.witnesses().iter().all(|witness| witness.completion() != &ResolutionCompletion::Complete));
    assert_eq!(reverse.completion(), &ResolutionCompletion::Complete);
}

#[test]
fn parsed_rust_ambiguous_bound_head_is_not_a_proven_union() {
    let fixture = parsed_rust_fixture(r#"
pub trait Store { fn get(&self); }
pub trait Store { fn get(&self); }
fn ambiguous<T: Store>(value: &T) { value.get(); }
"#, b"rust-ambiguous-bound");
    let reference = callable_reference_named_at(&fixture, "value.get", "get");
    let answer = fixture.service.resolve_reference(reference, &CancellationToken::new()).unwrap();
    assert_eq!(answer.binding().targets().len(), 2, "{answer:?}");
    assert!(!answer.type_bound_receiver, "ambiguous lexical alternatives are not independent bounds");
}

/// A call to a generic function whose result is a bare type parameter has an
/// inferred result type, so its result frontier cannot be exact.
#[test]
fn a_generic_call_result_is_not_an_exact_type_parameter() {
    for (source, marker) in [
        (
            "pub fn generic<T>(value: T) -> T { value }\npub fn caller() { generic(1); }\n",
            "generic(1)",
        ),
        (
            "pub fn generic<T>() -> T { loop {} }\npub fn caller() { generic(); }\n",
            "generic()",
        ),
    ] {
        let fixture = parsed_rust_fixture(source, b"rust-generic-call-result");
        let reference = callable_reference_named_at(&fixture, marker, "generic");
        let obligation = fixture
            .typed
            .call_obligations()
            .iter()
            .find(|obligation| obligation.callee_reference() == reference)
            .expect("Rust call applicability obligation");
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .expect("Rust generic call evaluation succeeds");
        let result = answer
            .projected_frontiers()
            .iter()
            .find(|frontier| frontier.slot() == obligation.result_slot())
            .expect("Rust call result frontier");
        // The type parameter names why: its type is inferred.
        let parameter = fixture
            .facts
            .gaps
            .iter()
            .find(|gap| gap.kind == ResolutionGapKind::InferredType)
            .expect("the unbounded type parameter's inferred-type gap")
            .site;
        let inferred = gap_reason_semantic(
            fixture.typed.fragment(),
            parameter,
            LoweringGapOrigin::Extracted(ResolutionGapKind::InferredType),
        );
        assert!(
            result.possible_values().is_empty()
                && result
                    .completion()
                    .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(inferred)),
            "{marker}: the result is not an exact type: {result:?}"
        );
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: the callee still binds exactly: {answer:?}"
        );
    }
}

const RUST_BOUNDED_GENERICS: &str = r#"pub trait Shape { fn area(&self) -> f64; fn name(&self) -> u8; }
pub struct Square;
impl Square { pub fn side(&self) -> f64 { 1.0 } pub fn name(&self) -> u8 { 0 } }
impl Shape for Square { fn area(&self) -> f64 { 1.0 } fn name(&self) -> u8 { 1 } }
pub trait Consume { fn take(self) -> u8; }
impl Consume for Square { fn take(self) -> u8 { 0 } }
impl Square { pub fn take(&self) -> u8 { 1 } }
pub fn pick<T: Shape>(value: T) -> T { value }
pub fn pick_where<T>(value: T) -> T where T: Shape { value }
pub fn identity<T>(value: T) -> T { value }
pub fn make<T: Shape>() -> T { loop {} }
pub fn caller(square: Square, other: Square) {
    let picked = pick(square);
    picked.area();
    picked.side();
    picked.name();
    let chosen = pick_where(other);
    chosen.area();
    let copied = identity(square);
    copied.side();
    make::<Square>().name();
    square.name();
    Square::name(&square);
    square.take();
}
pub fn body<T: Shape>(value: T) { value.area(); value.side(); }
pub fn relay<U: Shape>() -> u8 { make::<U>().name() }
pub fn gather(squares: &[Square]) -> usize { squares.iter().collect::<Vec<_>>().len() }
"#;

fn resolved(fixture: &ParsedRustFixture, marker: &str, name: &str) -> FactResolutionAnswer {
    let reference = callable_reference_named_at(fixture, marker, name);
    fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap()
}

/// A generic call's result is the type its arguments instantiate, not its
/// bound. `pick(square)` is a `Square`: its members are `Square`'s, its
/// inherent `name` outranks the trait's, and `side` resolves instead of staying
/// open. Where no value argument decides the instantiation, an explicit type
/// argument does: `make::<Square>()` is a `Square` too, and `make::<U>()` is a
/// `U`, which reaches its bound's members. A turbofish on a callee the fixture
/// does not index (`collect::<Vec<_>>()`) decides nothing, and the call keeps
/// the reason any unindexed method has. Inside the generic body a value typed
/// by the bound reaches the bound's members, and nothing beyond them is
/// proved.
#[test]
fn a_generic_call_result_follows_the_argument_that_binds_its_type_parameter() {
    let fixture = parsed_rust_fixture(RUST_BOUNDED_GENERICS, b"rust-generic-instantiation");
    let square = definition_after(&fixture, "pub struct Square", "Square");
    let impl_area = definition_after(&fixture, "impl Shape for Square { fn area", "area");
    let side = definition_after(&fixture, "pub fn side", "side");
    let inherent_name = definition_after(&fixture, "pub fn name", "name");
    let trait_area = definition_after(&fixture, "pub trait Shape { fn area", "area");
    let trait_name = definition_after(&fixture, "fn name(&self) -> u8; }", "name");

    let call = resolved(&fixture, "pick(square)", "pick");
    let obligation = fixture
        .typed
        .call_obligations()
        .iter()
        .find(|obligation| {
            obligation.callee_reference() == callable_reference_named_at(&fixture, "pick(square)", "pick")
        })
        .expect("the pick call obligation");
    let result = call
        .projected_frontiers()
        .iter()
        .find(|frontier| frontier.slot() == obligation.result_slot())
        .expect("the pick call result frontier");
    assert_eq!(
        result.possible_values(),
        &[ResolutionSlotValue::runtime(ResolutionTypeRef::new(square, 0), false)],
        "{result:?}"
    );
    assert_eq!(result.completion(), &ResolutionCompletion::Complete, "{result:?}");

    for (marker, name, expected) in [
        ("picked.area", "area", impl_area),
        ("picked.side", "side", side),
        ("picked.name", "name", inherent_name),
        ("chosen.area", "area", impl_area),
        ("copied.side", "side", side),
        ("value.area", "area", trait_area),
    ] {
        let answer = resolved(&fixture, marker, name);
        assert_eq!(answer.binding().targets(), &[expected], "{marker}: {answer:?}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }

    let make = callable_reference_named_at(&fixture, "make::<Square>()", "make");
    let obligation = fixture
        .typed
        .call_obligations()
        .iter()
        .find(|obligation| obligation.callee_reference() == make)
        .expect("the make call obligation");
    assert_eq!(obligation.type_argument_slots().len(), 1, "{obligation:?}");
    let result = resolved(&fixture, "make::<Square>()", "make")
        .projected_frontiers()
        .iter()
        .find(|frontier| frontier.slot() == obligation.result_slot())
        .cloned()
        .expect("the make call result frontier");
    assert_eq!(
        result.possible_values(),
        &[ResolutionSlotValue::runtime(ResolutionTypeRef::new(square, 0), false)],
        "the type argument instantiates the result: {result:?}"
    );
    assert_eq!(result.completion(), &ResolutionCompletion::Complete, "{result:?}");
    for (marker, expected) in [
        ("make::<Square>().name", inherent_name),
        ("make::<U>().name", trait_name),
    ] {
        let answer = resolved(&fixture, marker, "name");
        assert_eq!(answer.binding().targets(), &[expected], "{marker}: {answer:?}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }

    let unindexed = resolved(&fixture, "squares.iter", "iter");
    assert!(unindexed.binding().targets().is_empty(), "{unindexed:?}");
    assert!(
        matches!(unindexed.binding().completion(), ResolutionCompletion::Incomplete(_)),
        "{unindexed:?}"
    );
    for (marker, name) in [("collect::<Vec<_>>()", "collect"), ("collect::<Vec<_>>().len", "len")] {
        let answer = resolved(&fixture, marker, name);
        assert!(answer.binding().targets().is_empty(), "{marker}: {answer:?}");
        assert_eq!(
            answer.binding().completion(),
            unindexed.binding().completion(),
            "{marker}: an unindexed callee keeps its reason, type argument or not: {answer:?}"
        );
    }

    let answer = resolved(&fixture, "value.side", "side");
    assert!(answer.binding().targets().is_empty(), "{answer:?}");
    assert!(
        matches!(answer.binding().completion(), ResolutionCompletion::Incomplete(_)),
        "a member beyond the bound is not a proved absence: {answer:?}"
    );
}

/// An inherent method outranks a trait method of the same type where Rust's
/// lookup does: always for a path, and for a method call when both take their
/// receiver the same way. A by-value trait method beside a by-reference
/// inherent one is probed first for a value receiver, so neither is dropped.
#[test]
fn an_inherent_method_outranks_a_same_form_trait_method() {
    let fixture = parsed_rust_fixture(RUST_BOUNDED_GENERICS, b"rust-inherent-precedence");
    let inherent_name = definition_after(&fixture, "pub fn name", "name");
    for marker in ["square.name", "Square::name(&square)"] {
        let answer = resolved(&fixture, marker, "name");
        assert_eq!(answer.binding().targets(), &[inherent_name], "{marker}: {answer:?}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }
    let mut takes = [
        definition_after(&fixture, "impl Consume for Square { fn take", "take"),
        definition_after(&fixture, "impl Square { pub fn take", "take"),
    ];
    takes.sort_unstable();
    let answer = resolved(&fixture, "square.take", "take");
    assert_eq!(answer.binding().targets(), takes.as_slice(), "{answer:?}");
}

/// The reverse agrees with the forward answers: the calls an argument's type,
/// or an explicit type argument, decides are proven uses of the instantiated
/// type's members, and a type argument that is a type parameter reaches the
/// bound's member. A member beyond the bound is an unproven site.
#[test]
fn instantiated_generic_results_keep_the_reverse_in_step() {
    let fixture = parsed_rust_fixture(RUST_BOUNDED_GENERICS, b"rust-generic-instantiation-reverse");
    let sorted = |markers: &[(&str, &str)]| {
        let mut references = markers
            .iter()
            .map(|(marker, name)| callable_reference_named_at(&fixture, marker, name))
            .collect::<Vec<_>>();
        references.sort_unstable();
        references
    };
    let references = |target: SemanticId| {
        let reverse = fixture
            .service
            .references_to(target, &CancellationToken::new())
            .unwrap();
        let mut references = reverse.references().to_vec();
        references.sort_unstable();
        (references, reverse)
    };

    let (found, reverse) = references(definition_after(&fixture, "pub fn side", "side"));
    assert_eq!(
        found,
        sorted(&[("picked.side", "side"), ("copied.side", "side"), ("value.side", "side")]),
        "{reverse:?}"
    );
    let unproven = callable_reference_named_at(&fixture, "value.side", "side");
    for witness in reverse.witnesses() {
        assert_eq!(
            witness.completion() == &ResolutionCompletion::Complete,
            witness.reference() != unproven,
            "{reverse:?}"
        );
    }

    let (found, reverse) = references(definition_after(&fixture, "pub fn name", "name"));
    assert_eq!(
        found,
        sorted(&[
            ("picked.name", "name"),
            ("make::<Square>().name", "name"),
            ("square.name", "name"),
            ("Square::name(&square)", "name"),
        ]),
        "{reverse:?}"
    );
    assert!(
        reverse
            .witnesses()
            .iter()
            .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
        "every inherent `name` call is proven: {reverse:?}"
    );

    let (found, reverse) =
        references(definition_after(&fixture, "fn name(&self) -> u8; }", "name"));
    assert_eq!(found, sorted(&[("make::<U>().name", "name")]), "{reverse:?}");
    assert!(
        reverse
            .witnesses()
            .iter()
            .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
        "{reverse:?}"
    );
}


const RUST_INSTANTIATION_SOURCES: &str = r#"pub trait Shape { fn area(&self) -> f64; fn name(&self) -> u8; }
pub struct Square;
impl Square {
    pub fn side(&self) -> f64 { 1.0 }
    pub fn name(&self) -> u8 { 0 }
    pub fn echo<T>(&self, value: T) -> T { value }
}
impl Shape for Square { fn area(&self) -> f64 { 1.0 } fn name(&self) -> u8 { 1 } }
pub trait Echo { fn echo_back<T>(&self, value: T) -> T; }
impl Echo for Square { fn echo_back<T>(&self, value: T) -> T { value } }
pub struct Wrapper<W>(W);
impl<W: Shape> Wrapper<W> {
    pub fn make() -> W { loop {} }
    pub fn inner(&self) -> &W { &self.0 }
}
pub fn make<T: Shape>() -> T { loop {} }
pub fn caller(square: Square, other: Square, third: Square, wrapper: Wrapper<Square>) {
    Wrapper::<Square>::make().name();
    let made: Square = make();
    let wrapped: Square = Wrapper::make();
    Square::echo(&square, other).side();
    Echo::echo_back(&square, third).side();
    wrapper.inner().name();
}
"#;

/// The result frontier of the call whose callee is `name` at `marker`.
fn call_result(fixture: &ParsedRustFixture, marker: &str, name: &str) -> TypedFrontierState {
    let callee = callable_reference_named_at(fixture, marker, name);
    let obligation = fixture
        .typed
        .call_obligations()
        .iter()
        .find(|obligation| obligation.callee_reference() == callee)
        .unwrap_or_else(|| panic!("{marker}: no call obligation"));
    resolved(fixture, marker, name)
        .projected_frontiers()
        .iter()
        .find(|frontier| frontier.slot() == obligation.result_slot())
        .cloned()
        .unwrap_or_else(|| panic!("{marker}: no call result frontier"))
}

/// Three more sources decide a generic call's result where no value argument
/// lines up by position: the type arguments written on the path's type
/// segment, which an impl's type parameters take (`Wrapper::<Square>::make()`);
/// the type a `let` annotation expects of its call initializer, after value
/// and type arguments (`let made: Square = make();`); and a method called in
/// path form, whose first argument is the receiver, so its value arguments
/// line up from the second (`Square::echo(&square, other)`, through an
/// inherent method or a trait's).
#[test]
fn type_segments_expected_types_and_path_receivers_decide_generic_results() {
    let fixture = parsed_rust_fixture(RUST_INSTANTIATION_SOURCES, b"rust-instantiation-sources");
    let square = definition_after(&fixture, "pub struct Square", "Square");
    let exact_square = [ResolutionSlotValue::runtime(ResolutionTypeRef::new(square, 0), false)];
    for (marker, name) in [
        ("Wrapper::<Square>::make()", "make"),
        ("make();", "make"),
        ("Wrapper::make();", "make"),
        ("Square::echo(&square, other)", "echo"),
        ("Echo::echo_back(&square, third)", "echo_back"),
    ] {
        let result = call_result(&fixture, marker, name);
        assert_eq!(result.possible_values(), &exact_square, "{marker}: {result:?}");
        assert_eq!(result.completion(), &ResolutionCompletion::Complete, "{marker}: {result:?}");
    }

    let inherent_name = definition_after(&fixture, "pub fn name", "name");
    let side = definition_after(&fixture, "pub fn side", "side");
    for (marker, name, expected) in [
        ("Wrapper::<Square>::make().name", "name", inherent_name),
        ("Square::echo(&square, other).side", "side", side),
        ("Echo::echo_back(&square, third).side", "side", side),
    ] {
        let answer = resolved(&fixture, marker, name);
        assert_eq!(answer.binding().targets(), &[expected], "{marker}: {answer:?}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }

    // A receiver's own type arguments (`wrapper: Wrapper<Square>`) are not
    // modelled, so an impl parameter reached through a method call keeps the
    // bound's surface, and says it is not proven.
    let answer = resolved(&fixture, "wrapper.inner().name", "name");
    assert!(
        matches!(answer.binding().completion(), ResolutionCompletion::Incomplete(_)),
        "{answer:?}"
    );
}

/// The reverse keeps the same deciders: the member calls a type segment or a
/// path-form receiver decides are proven uses of the instantiated type's
/// members. The expected type of a `let` has no reverse reader: the binding
/// takes the annotation itself, so nothing reads the call's result.
#[test]
fn type_segments_and_path_receivers_keep_the_reverse_in_step() {
    let fixture = parsed_rust_fixture(
        RUST_INSTANTIATION_SOURCES,
        b"rust-instantiation-sources-reverse",
    );
    for (definition, expected) in [
        (
            definition_after(&fixture, "pub fn name", "name"),
            vec![("Wrapper::<Square>::make().name", "name")],
        ),
        (
            definition_after(&fixture, "pub fn side", "side"),
            vec![
                ("Square::echo(&square, other).side", "side"),
                ("Echo::echo_back(&square, third).side", "side"),
            ],
        ),
    ] {
        let reverse = fixture
            .service
            .references_to(definition, &CancellationToken::new())
            .unwrap();
        for (marker, name) in expected {
            let reference = callable_reference_named_at(&fixture, marker, name);
            let witness = reverse
                .witnesses()
                .iter()
                .find(|witness| witness.reference() == reference)
                .unwrap_or_else(|| panic!("{marker}: not found: {reverse:?}"));
            assert_eq!(
                witness.completion(),
                &ResolutionCompletion::Complete,
                "{marker}: {reverse:?}"
            );
        }
    }
}

const RUST_UNIT_VALUES: &str = r#"pub struct Square;
impl Square { pub fn side(&self) -> f64 { 1.0 } }
pub struct Pair(u8, u8);
impl Pair { pub fn side(&self) -> f64 { 2.0 } }
pub fn identity<T>(value: T) -> T { value }
pub fn caller() {
    let unit = Square;
    unit.side();
    identity(Square).side();
    let constructor = Pair;
    constructor.side();
}
"#;

/// A unit struct's value item is an instance of it, so a value read binding
/// `Square` is typed `Square` and decides a generic call's instantiation. A
/// tuple struct's value item is its constructor function, which stays
/// untyped rather than passing for an instance.
#[test]
fn a_unit_struct_value_is_an_instance_of_its_struct() {
    let fixture = parsed_rust_fixture(RUST_UNIT_VALUES, b"rust-unit-values");
    let side = definition_after(&fixture, "impl Square { pub fn side", "side");
    for marker in ["unit.side", "identity(Square).side"] {
        let answer = resolved(&fixture, marker, "side");
        assert_eq!(answer.binding().targets(), &[side], "{marker}: {answer:?}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }
    let answer = resolved(&fixture, "constructor.side", "side");
    assert!(answer.binding().targets().is_empty(), "{answer:?}");
    assert!(
        matches!(answer.binding().completion(), ResolutionCompletion::Incomplete(_)),
        "a tuple struct's constructor function is not an instance: {answer:?}"
    );

    let reverse = fixture
        .service
        .references_to(side, &CancellationToken::new())
        .unwrap();
    let mut expected = ["unit.side", "identity(Square).side"]
        .map(|marker| callable_reference_named_at(&fixture, marker, "side"));
    expected.sort_unstable();
    let mut references = reverse.references().to_vec();
    references.sort_unstable();
    assert_eq!(references, expected, "{reverse:?}");
    assert!(
        reverse
            .witnesses()
            .iter()
            .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
        "{reverse:?}"
    );
}


const RUST_ALIASED_TYPE_SEGMENTS: &str = r#"pub struct Square;
impl Square { pub fn side(&self) -> f64 { 1.0 } }
pub struct Circle;
impl Circle { pub fn radius(&self) -> f64 { 1.0 } }
pub struct Pair<P, Q>(P, Q);
impl<A, B> Pair<A, B> { pub fn first() -> A { loop {} } }
pub type Swap<X, Y> = Pair<Y, X>;
pub type Nested<X> = Pair<Vec<X>, X>;
pub fn caller() {
    Pair::<Square, Circle>::first().side();
    Swap::<Square, Circle>::first().side();
    Nested::<Square>::first().side();
}
"#;

/// A path's type segment writes its type's arguments only when it names the
/// type itself. Through an alias it writes the alias's arguments, in the
/// alias's order: `Swap::<Square, Circle>` is `Pair<Circle, Square>`, and
/// `Nested::<Square>` is `Pair<Vec<Square>, Square>`. Neither segment decides
/// `first`, which keeps its undecided result, so neither call's `side` is
/// `Square::side`. Following an alias's parameters through its target is not
/// modelled yet.
#[test]
fn an_aliased_type_segment_does_not_decide_the_aliased_types_parameters() {
    let fixture = parsed_rust_fixture(RUST_ALIASED_TYPE_SEGMENTS, b"rust-aliased-type-segments");
    let square = definition_after(&fixture, "pub struct Square", "Square");
    let direct = call_result(&fixture, "Pair::<Square, Circle>::first()", "first");
    assert_eq!(
        direct.possible_values(),
        &[ResolutionSlotValue::runtime(ResolutionTypeRef::new(square, 0), false)],
        "{direct:?}"
    );
    assert_eq!(direct.completion(), &ResolutionCompletion::Complete, "{direct:?}");
    for marker in ["Swap::<Square, Circle>::first()", "Nested::<Square>::first()"] {
        let result = call_result(&fixture, marker, "first");
        assert!(result.possible_values().is_empty(), "{marker}: {result:?}");
        assert!(
            matches!(result.completion(), ResolutionCompletion::Incomplete(_)),
            "{marker}: {result:?}"
        );
    }

    let side = definition_after(&fixture, "pub fn side", "side");
    let answer = resolved(&fixture, "Pair::<Square, Circle>::first().side", "side");
    assert_eq!(answer.binding().targets(), &[side], "{answer:?}");
    assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete, "{answer:?}");
    for marker in ["Swap::<Square, Circle>::first().side", "Nested::<Square>::first().side"] {
        let answer = resolved(&fixture, marker, "side");
        assert!(answer.binding().targets().is_empty(), "{marker}: {answer:?}");
        assert!(
            matches!(answer.binding().completion(), ResolutionCompletion::Incomplete(_)),
            "{marker}: {answer:?}"
        );
    }

    let reverse = fixture
        .service
        .references_to(side, &CancellationToken::new())
        .unwrap();
    let direct = callable_reference_named_at(&fixture, "Pair::<Square, Circle>::first().side", "side");
    for witness in reverse.witnesses() {
        assert_eq!(
            witness.completion() == &ResolutionCompletion::Complete,
            witness.reference() == direct,
            "only the direct segment's call is a proven use: {reverse:?}"
        );
    }
    assert!(reverse.references().contains(&direct), "{reverse:?}");
}

const RUST_UNNAMEABLE_TRAIT_ITEM: &str = r#"pub struct Service;
impl Display for Service { fn fmt(&self) -> u8 { 0 } }
pub fn caller(service: Service) { service.fmt(); }
"#;

/// An impl item of a trait the rows cannot name (`Display` here names nothing
/// in the fixture) answers alone and complete when the receiver's nameable
/// traits are enumerated and none supplies the method. When the rows cannot
/// place the receiver's traits, another trait could supply it too (E0034), so
/// the item stays the target and the answer says why it is not complete.
#[test]
fn an_unnameable_trait_item_is_complete_only_where_the_nameable_traits_are_enumerated() {
    let fixture = parsed_rust_fixture(RUST_UNNAMEABLE_TRAIT_ITEM, b"rust-unnameable-trait-item");
    let fmt = definition_after(&fixture, "impl Display for Service { fn fmt", "fmt");
    let answer = resolved(&fixture, "service.fmt", "fmt");
    assert_eq!(answer.binding().targets(), &[fmt], "{answer:?}");
    assert_eq!(answer.binding().completion(), &ResolutionCompletion::Complete, "{answer:?}");

    let mut fixture =
        parsed_rust_fixture(RUST_UNNAMEABLE_TRAIT_ITEM, b"rust-unnameable-trait-item-unplaced");
    fixture.service.rust_implemented_traits_unplaced = true;
    let fmt = definition_after(&fixture, "impl Display for Service { fn fmt", "fmt");
    let answer = resolved(&fixture, "service.fmt", "fmt");
    assert_eq!(answer.binding().targets(), &[fmt], "{answer:?}");
    assert!(
        matches!(answer.binding().completion(), ResolutionCompletion::Incomplete(_)),
        "{answer:?}"
    );
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

/// The unexpanded item macros of one scope leave one fallback branch for the
/// scope and one member branch per type, each carrying every invocation's
/// reason, instead of one branch per invocation: every invocation reaches the
/// same names at the same rank, so the copies answered each lookup once per
/// invocation. A bare lookup the scope does not bind still ends incomplete,
/// with each invocation's reason. The macro writes a function beside its impl,
/// so it is an item macro, not an impl-only one (`UnexpandedImplMacro`).
#[test]
fn a_scope_leaves_one_fallback_branch_for_all_its_unexpanded_item_macros() {
    let fixture = parsed_rust_fixture(
        RUST_TWO_UNEXPANDED_ITEM_MACROS,
        b"rust-unexpanded-item-macro-branches",
    );
    let invocations = fixture
        .facts
        .gaps
        .iter()
        .filter(|gap| gap.kind == ResolutionGapKind::UnexpandedItemMacro)
        .count();
    assert_eq!(invocations, 3, "{:?}", fixture.facts.gaps);
    let branches = fixture
        .lexical
        .paths()
        .iter()
        .filter(|(_, path)| {
            path.start().symbols().fixed().is_empty()
                && matches!(
                    path.completion(),
                    ResolutionCompletion::Incomplete(reasons) if reasons.len() == invocations
                )
        })
        .count();
    // One scope fallback and one member branch for `Dim`.
    assert_eq!(branches, 2, "{:?}", fixture.lexical.paths());
    let answer = resolved(&fixture, "unbound_fn()", "unbound_fn");
    assert!(answer.binding().targets().is_empty(), "{answer:?}");
    let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion() else {
        panic!("an unbound name beside unexpanded item macros is incomplete: {answer:?}");
    };
    assert!(reasons.len() >= invocations, "{answer:?}");
}
