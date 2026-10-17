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
    let parsed = parse_rust_file(&file, source, &tree);
    let mut facts = parsed.resolution_facts;
    mutate(&mut facts);
    let fragment = BindingFragmentId::for_test(label);
    let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Rust, &facts)
        .lexical()
        .clone();
    let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Rust, &facts)
        .typed()
        .clone();
    let mut service =
        PreloadedFactResolutionService::from_lowered_fragments([lexical.clone()], [typed.clone()]);
    let source_rows = parsed.source_facts.expect("Rust source declaration rows");
    for &(site, declaration) in &source_rows.native_declaration_sources {
        if source_rows
            .occurrences
            .lexical_declaration(declaration)
            .is_some_and(|row| {
                row.kind == brokk_bifrost_core::analyzer::model::DeclarationKind::Parameter
            })
            && facts.identifiers.iter().any(|identifier| {
                identifier.site == site
                    && identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Type
            })
        {
            service
                .generic_parameter_declaration_metadata
                .insert(lowered_semantic_at(
                    &lexical,
                    site,
                    LoweredSemanticRole::Definition,
                ));
        }
    }
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
        facts.gaps.push(ResolutionGapFact {
            site,
            kind: ResolutionGapKind::UnsupportedImplicitReceiver,
        });
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
#[hardwon("#3828: smart pointer member references lost complete receiver resolution")]
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

fn use_plain(plain: Wrapper) {
    plain.run();
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
    // An unknown generic head is not transparent: the receiver keeps the
    // head and finds no member. Since #3828 the written type argument is a
    // relational row instead of an unsupported-syntax gap, so the generic
    // receiver answers exactly as the same head written without arguments.
    let answer_at = |marker| {
        let reference = callable_reference_named_at(&fixture, marker, "run");
        fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .expect("Rust unresolved-head receiver evaluation succeeds")
    };
    let opaque = answer_at("opaque.run");
    let plain = answer_at("plain.run");
    assert!(opaque.binding().targets().is_empty(), "{opaque:?}");
    assert!(plain.binding().targets().is_empty(), "{plain:?}");
    assert_eq!(
        opaque.binding().completion(),
        plain.binding().completion(),
        "opaque={opaque:?} plain={plain:?}"
    );
}

#[test]
#[hardwon("4b818a2d36c1: Rust unwrap transfers failed to retain the payload for member resolution")]
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
    let self_declarations = fixture
        .facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && identifier.namespace == ResolutionNamespace::Value
                && fixture.facts.names[identifier.name.index()].spelling == "self"
        })
        .collect::<Vec<_>>();
    assert_eq!(self_declarations.len(), 2);
    for declaration in self_declarations {
        assert!(fixture.facts.binders.iter().any(|binder| {
            binder.declaration == declaration.site && binder.kind == ResolutionBinderKind::Parameter
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
    let nominal = fixture
        .facts
        .binding_projections
        .iter()
        .find(|projection| {
            projection.output == owner_type
                && projection.kind == BindingProjectionKind::TargetNominalTypeIdentity
        })
        .expect("impl owner uses the nominal output");
    let receiver_type = fixture
        .facts
        .binding_projections
        .iter()
        .find(|projection| {
            projection.reference == nominal.reference
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        })
        .expect("impl receiver uses the paired payload output")
        .output;
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
#[hardwon("#3746: generic type alias member calls lost their declaration owner")]
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
#[hardwon("#3828: nested generic aliases failed to substitute member call targets")]
fn generic_alias_nested_generic_target_substitutes_for_member_calls() {
    let source = r#"
pub struct Square;
impl Square { pub fn side(&self) {} }
pub struct Circle;
impl Circle { pub fn radius(&self) {} }
pub struct Pair<A, B>(A, B);
impl<A, B> Pair<A, B> { pub fn first() -> A { loop {} } }
pub type Swap<X, Y> = Pair<Y, X>;
pub type Reversed<X, Y> = Swap<X, Y>;
pub struct Wrapper<T>(pub T);
impl<T> Wrapper<Vec<T>> { pub fn only_nested(&self) {} }
pub type Nested<X> = Wrapper<Vec<X>>;
fn caller() {
    Reversed::<Square, Circle>::first().radius();
    let value: Nested<Square> = Wrapper(Vec::new());
    value.only_nested();
}
"#;
    let fixture = parsed_rust_fixture(source, b"rust-generic-alias-substitution");
    let radius = definition_after(&fixture, "impl Circle", "radius");
    let radius_reference = callable_reference_named_at(
        &fixture,
        "Reversed::<Square, Circle>::first().radius()",
        "radius",
    );
    let radius_answer = fixture
        .service
        .resolve_reference(radius_reference, &CancellationToken::new())
        .unwrap();
    assert_eq!(
        radius_answer.binding().targets(),
        &[radius],
        "{radius_answer:?}"
    );
    assert_eq!(
        radius_answer.binding().completion(),
        &ResolutionCompletion::Complete,
        "{radius_answer:?}"
    );

    let nested = definition_after(&fixture, "impl<T> Wrapper<Vec<T>>", "only_nested");
    let nested_reference =
        callable_reference_named_at(&fixture, "value.only_nested()", "only_nested");
    let nested_answer = fixture
        .service
        .resolve_reference(nested_reference, &CancellationToken::new())
        .unwrap();
    assert_eq!(
        nested_answer.binding().targets(),
        &[nested],
        "{nested_answer:?}"
    );
    let reverse = fixture
        .service
        .references_to(nested, &CancellationToken::new())
        .unwrap();
    assert!(
        reverse.references().contains(&nested_reference),
        "{reverse:?}"
    );
}

#[test]
#[hardwon("#3828: recursive generic aliases escaped the structured type frontier")]
fn generic_alias_cycle_stops_at_the_structured_type_frontier() {
    let source = r#"
pub struct Square;
pub type First<T> = Second<T>;
pub type Second<T> = First<T>;
fn caller(value: First<Square>) { value.missing(); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-generic-alias-cycle");
    let reference = callable_reference_named_at(&fixture, "value.missing()", "missing");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();
    assert!(answer.binding().targets().is_empty(), "{answer:?}");
    assert_incomplete(&answer);
}

#[test]
fn parsed_rust_unknown_bound_keeps_an_unproven_reverse_site() {
    let fixture = parsed_rust_fixture(
        r#"
pub trait Store { fn get(&self); }
fn unknown<T: Missing>(value: &T) { value.get(); }
"#,
        b"rust-unknown-bound",
    );
    let definition = definition_after(&fixture, "pub trait Store", "get");
    let reference = callable_reference_named_at(&fixture, "value.get", "get");
    let forward = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();
    assert!(forward.binding().targets().is_empty(), "{forward:?}");
    assert!(forward.type_bound_receiver);
    let reverse = fixture
        .service
        .references_to(definition, &CancellationToken::new())
        .unwrap();
    assert_eq!(reverse.references(), &[reference]);
    assert!(
        reverse
            .witnesses()
            .iter()
            .all(|witness| witness.completion() != &ResolutionCompletion::Complete)
    );
    assert_eq!(reverse.completion(), &ResolutionCompletion::Complete);
}

#[test]
fn parsed_rust_ambiguous_bound_head_is_not_a_proven_union() {
    let fixture = parsed_rust_fixture(
        r#"
pub trait Store { fn get(&self); }
pub trait Store { fn get(&self); }
fn ambiguous<T: Store>(value: &T) { value.get(); }
"#,
        b"rust-ambiguous-bound",
    );
    let reference = callable_reference_named_at(&fixture, "value.get", "get");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();
    assert_eq!(answer.binding().targets().len(), 2, "{answer:?}");
    assert!(
        !answer.type_bound_receiver,
        "ambiguous lexical alternatives are not independent bounds"
    );
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

const RUST_ALIASED_TYPE_SEGMENTS: &str = r#"pub struct Square;
impl Square { pub fn side(&self) -> f64 { 1.0 } }
pub struct Circle;
impl Circle { pub fn radius(&self) -> f64 { 1.0 } }
pub struct Pair<P, Q>(P, Q);
impl<A, B> Pair<A, B> {
    pub fn first() -> A { loop {} }
    pub fn second() -> B { loop {} }
}
pub type Swap<X, Y> = Pair<Y, X>;
pub type Reversed<X, Y> = Swap<X, Y>;
pub type Nested<X> = Pair<Vec<X>, X>;
pub fn caller() {
    Pair::<Square, Circle>::first().side();
    Swap::<Square, Circle>::first().radius();
    Reversed::<Square, Circle>::first().radius();
    Nested::<Square>::second().side();
}
"#;

/// A path's type segment writes its alias's arguments in the alias's order.
/// Substitution follows both a parameter permutation and an alias-of-alias;
/// nested target syntax retains the formal occurrence used by `second`.
#[test]
#[hardwon("#3828: generic alias type arguments were not substituted through nested aliases")]
fn generic_alias_type_segments_substitute_concrete_and_nested_arguments() {
    let fixture = parsed_rust_fixture(RUST_ALIASED_TYPE_SEGMENTS, b"rust-aliased-type-segments");
    let square = definition_after(&fixture, "pub struct Square", "Square");
    let circle = definition_after(&fixture, "pub struct Circle", "Circle");
    for (marker, result, expected) in [
        (
            "Pair::<Square, Circle>::first()",
            call_result(&fixture, "Pair::<Square, Circle>::first()", "first"),
            square,
        ),
        (
            "Swap::<Square, Circle>::first()",
            call_result(&fixture, "Swap::<Square, Circle>::first()", "first"),
            circle,
        ),
        (
            "Reversed::<Square, Circle>::first()",
            call_result(&fixture, "Reversed::<Square, Circle>::first()", "first"),
            circle,
        ),
        (
            "Nested::<Square>::second()",
            call_result(&fixture, "Nested::<Square>::second()", "second"),
            square,
        ),
    ] {
        assert_eq!(
            result.possible_values(),
            &[ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(expected, 0),
                false
            )],
            "{marker}: {result:?}"
        );
        assert_eq!(
            result.completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {result:?}"
        );
    }

    let side = definition_after(&fixture, "pub fn side", "side");
    let radius = definition_after(&fixture, "pub fn radius", "radius");
    for (marker, name, expected) in [
        ("Pair::<Square, Circle>::first().side", "side", side),
        ("Swap::<Square, Circle>::first().radius", "radius", radius),
        (
            "Reversed::<Square, Circle>::first().radius",
            "radius",
            radius,
        ),
        ("Nested::<Square>::second().side", "side", side),
    ] {
        let answer = resolved(&fixture, marker, name);
        assert_eq!(
            answer.binding().targets(),
            &[expected],
            "{marker}: {answer:?}"
        );
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }

    for (target, expected_markers, name) in [
        (
            side,
            vec![
                "Pair::<Square, Circle>::first().side",
                "Nested::<Square>::second().side",
            ],
            "side",
        ),
        (
            radius,
            vec![
                "Swap::<Square, Circle>::first().radius",
                "Reversed::<Square, Circle>::first().radius",
            ],
            "radius",
        ),
    ] {
        let reverse = fixture
            .service
            .references_to(target, &CancellationToken::new())
            .unwrap();
        let mut expected = expected_markers
            .iter()
            .map(|marker| callable_reference_named_at(&fixture, marker, name))
            .collect::<Vec<_>>();
        expected.sort_unstable();
        let mut references = reverse.references().to_vec();
        references.sort_unstable();
        assert_eq!(references, expected, "{reverse:?}");
        assert_eq!(
            reverse.completion(),
            &ResolutionCompletion::Complete,
            "{reverse:?}"
        );
        assert!(
            reverse
                .witnesses()
                .iter()
                .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
            "{reverse:?}"
        );
    }
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
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete,
        "{answer:?}"
    );

    let mut fixture = parsed_rust_fixture(
        RUST_UNNAMEABLE_TRAIT_ITEM,
        b"rust-unnameable-trait-item-unplaced",
    );
    fixture.service.rust_implemented_traits_unplaced = true;
    let fmt = definition_after(&fixture, "impl Display for Service { fn fmt", "fmt");
    let answer = resolved(&fixture, "service.fmt", "fmt");
    assert_eq!(answer.binding().targets(), &[fmt], "{answer:?}");
    assert!(
        matches!(
            answer.binding().completion(),
            ResolutionCompletion::Incomplete(_)
        ),
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
fn parsed_rust_argument_independent_binding_is_complete_before_result_projection() {
    // An attribute on an argument can remove it, so this call keeps its
    // call-site applicability gap: invocation uncertainty the binding must not
    // absorb.
    let source = "pub fn target(value: i32) {}\npub fn caller() { target(#[cfg(any())] 1); }\n";
    let fixture = parsed_rust_fixture(source, b"rust-argument-independent-binding");
    let reference = callable_reference_named_at(&fixture, "target(#[cfg", "target");
    let target = definition_after(&fixture, "pub fn target", "target");

    let point = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust argument-independent point evaluation succeeds");
    assert_argument_independent_binding_keeps_callsite_gap(&fixture, reference, &point);
    assert_eq!(point.binding().targets(), &[target]);
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
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .expect("Rust missing callable name evaluation succeeds");
    let result_slot =
        assert_argument_independent_binding_keeps_callsite_gap(&fixture, reference, &answer);
    assert!(answer.binding().targets().is_empty());
    let result_frontier = answer
        .projected_frontiers()
        .iter()
        .find(|frontier| frontier.slot() == result_slot)
        .expect("Rust missing-name call result frontier");
    assert!(result_frontier.possible_values().is_empty());
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
#[hardwon("#3773: an active declaration's non-activation gap remains by identity")]
fn selected_active_local_declaration_keeps_its_unsupported_binder_reason() {
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
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();
    assert_eq!(answer.binding().targets(), &[definition], "{answer:?}");
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete,
        "{answer:?}"
    );
    let reverse = fixture
        .service
        .references_to(definition, &CancellationToken::new())
        .unwrap();
    assert_eq!(reverse.references(), &[reference], "{reverse:?}");
    assert_eq!(
        reverse.completion(),
        &ResolutionCompletion::Complete,
        "{reverse:?}"
    );
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
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .unwrap();
        assert_eq!(answer.binding().targets(), &[expected]);
    }
    let contract = definition_after(&fixture, "pub trait Work", "work");
    let reverse = fixture
        .service
        .references_to(contract, &CancellationToken::new())
        .unwrap();
    let caller = callable_reference_named_at(&fixture, "service.work", "work");
    assert!(reverse.references().contains(&caller), "{reverse:?}");
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
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();
    assert_eq!(answer.binding().targets(), &[target], "{answer:?}");
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete,
        "{answer:?}"
    );
    let pointer = callable_reference_named_at(&fixture, "pointer.run", "run");
    let answer = fixture
        .service
        .resolve_reference(pointer, &CancellationToken::new())
        .unwrap();
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
        let identifier = fixture
            .facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && fixture.facts.sites[identifier.site.index()].start_byte == position
            })
            .expect("associated type reference");
        let reference = lowered_semantic_at(
            &fixture.lexical,
            identifier.site,
            LoweredSemanticRole::Reference,
        );
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .unwrap();
        assert_eq!(
            answer.binding().targets(),
            &[expected],
            "{marker}: {answer:?}"
        );
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }
    let method = definition_after(&fixture, "impl Payload", "run");
    let calls = fixture
        .facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && fixture.facts.names[identifier.name.index()].spelling == "run"
        })
        .map(|identifier| {
            lowered_semantic_at(
                &fixture.lexical,
                identifier.site,
                LoweredSemanticRole::Reference,
            )
        });
    for reference in calls {
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .unwrap();
        assert_eq!(answer.binding().targets(), &[method], "{answer:?}");
    }
    let contract = definition_after(&fixture, "pub trait Runner", "Output");
    let reverse = fixture
        .service
        .references_to(contract, &CancellationToken::new())
        .unwrap();
    assert_eq!(reverse.references().len(), 2, "{reverse:?}");
}
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
#[test]
#[hardwon("985c255966c6: a same-form trait method outranked the matching inherent method")]
fn an_inherent_method_outranks_a_same_form_trait_method() {
    let fixture = parsed_rust_fixture(RUST_BOUNDED_GENERICS, b"rust-inherent-precedence");
    let inherent_name = definition_after(&fixture, "pub fn name", "name");
    for marker in ["square.name", "Square::name(&square)"] {
        let answer = resolved(&fixture, marker, "name");
        assert_eq!(
            answer.binding().targets(),
            &[inherent_name],
            "{marker}: {answer:?}"
        );
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
        sorted(&[
            ("picked.side", "side"),
            ("copied.side", "side"),
            ("value.side", "side")
        ]),
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

    let (found, reverse) = references(definition_after(
        &fixture,
        "fn name(&self) -> u8; }",
        "name",
    ));
    assert_eq!(
        found,
        sorted(&[("make::<U>().name", "name")]),
        "{reverse:?}"
    );
    assert!(
        reverse
            .witnesses()
            .iter()
            .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
        "{reverse:?}"
    );
}
#[test]
fn type_segments_expected_types_and_path_receivers_decide_generic_results() {
    let fixture = parsed_rust_fixture(RUST_INSTANTIATION_SOURCES, b"rust-instantiation-sources");
    let square = definition_after(&fixture, "pub struct Square", "Square");
    let exact_square = [ResolutionSlotValue::runtime(
        ResolutionTypeRef::new(square, 0),
        false,
    )];
    for (marker, name) in [
        ("Wrapper::<Square>::make()", "make"),
        ("make();", "make"),
        ("Wrapper::make();", "make"),
        ("Square::echo(&square, other)", "echo"),
        ("Echo::echo_back(&square, third)", "echo_back"),
    ] {
        let result = call_result(&fixture, marker, name);
        assert_eq!(
            result.possible_values(),
            &exact_square,
            "{marker}: {result:?}"
        );
        assert_eq!(
            result.completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {result:?}"
        );
    }

    let inherent_name = definition_after(&fixture, "pub fn name", "name");
    let side = definition_after(&fixture, "pub fn side", "side");
    for (marker, name, expected) in [
        ("Wrapper::<Square>::make().name", "name", inherent_name),
        ("Square::echo(&square, other).side", "side", side),
        ("Echo::echo_back(&square, third).side", "side", side),
    ] {
        let answer = resolved(&fixture, marker, name);
        assert_eq!(
            answer.binding().targets(),
            &[expected],
            "{marker}: {answer:?}"
        );
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }

    // Written receiver arguments now instantiate the impl parameter through
    // the existing result-binding machinery.
    let answer = resolved(&fixture, "wrapper.inner().name", "name");
    assert_eq!(answer.binding().targets(), &[inherent_name], "{answer:?}");
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete,
        "{answer:?}"
    );
}
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
#[test]
#[hardwon("955f6461cafc: a unit struct value is an instance of its struct")]
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
        matches!(
            answer.binding().completion(),
            ResolutionCompletion::Incomplete(_)
        ),
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
#[test]
fn a_function_only_item_macro_does_not_open_existing_type_members() {
    let source = r#"
pub trait Runner { type Output; }
pub struct Service;
impl Runner for Service { type Output = u8; }
impl Service { pub fn run(&self) {} }
macro_rules! maker { ($name:ident) => { pub fn $name() -> u8 { 0 } }; }
maker!(generated);
fn invoke(service: Service) { service.run(); }
type Selected = <Service as Runner>::Output;
fn unknown() { generated(); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-function-only-macro-members");
    let run = definition_after(&fixture, "impl Service", "run");
    let answer = resolved(&fixture, "service.run", "run");
    assert_eq!(answer.binding().targets(), &[run], "{answer:?}");
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete,
        "{answer:?}"
    );

    let expected = definition_after(&fixture, "impl Runner for Service", "Output");
    let marker = "<Service as Runner>::Output";
    let position = source.find(marker).unwrap() + marker.rfind("Output").unwrap();
    let identifier = fixture
        .facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && fixture.facts.sites[identifier.site.index()].start_byte == position
        })
        .expect("associated type reference");
    let reference = lowered_semantic_at(
        &fixture.lexical,
        identifier.site,
        LoweredSemanticRole::Reference,
    );
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();
    assert_eq!(answer.binding().targets(), &[expected], "{answer:?}");
    assert_eq!(
        answer.binding().completion(),
        &ResolutionCompletion::Complete,
        "{answer:?}"
    );

    // The generated declaration is still outside declaration replay. Its
    // unresolved lexical lookup must retain the original macro frontier.
    let answer = resolved(&fixture, "generated();", "generated");
    assert!(answer.binding().targets().is_empty(), "{answer:?}");
    assert_incomplete(&answer);
}

#[test]
fn item_macros_with_impl_or_nested_expansion_keep_type_members_open() {
    for expansion in [
        "pub fn generated() {} impl Service { pub fn run(&self) {} }",
        "pub fn generated() { unknown!(); }",
        "#[unknown_attribute] pub fn generated() {}",
        "pub fn generated() { impl Service { pub fn run(&self) {} } }",
        "pub mod more;",
        "use elsewhere::Extension;",
    ] {
        let source = format!(
            "pub struct Service;\n\
             impl Service {{ pub fn run(&self) {{}} }}\n\
             macro_rules! maker {{ () => {{ {expansion} }}; }}\n\
             maker!();\n\
             fn invoke(service: Service) {{ service.run(); }}"
        );
        let fixture = parsed_rust_fixture(&source, b"rust-open-macro-members");
        let run = definition_after(&fixture, "impl Service", "run");
        let answer = resolved(&fixture, "service.run", "run");
        assert_eq!(
            answer.binding().targets(),
            &[run],
            "{expansion}: {answer:?}"
        );
        assert_incomplete(&answer);
    }
}

#[test]
fn a_closed_macro_does_not_hide_another_macro_member_frontier() {
    let source = r#"
pub struct Service;
impl Service { pub fn run(&self) {} }
macro_rules! closed { () => { pub fn generated() {} }; }
macro_rules! open { () => { pub fn other() {} impl Service { pub fn extra(&self) {} } }; }
closed!();
open!();
fn invoke(service: Service) { service.run(); }
"#;
    let fixture = parsed_rust_fixture(source, b"rust-mixed-macro-member-surfaces");
    let run = definition_after(&fixture, "impl Service", "run");
    let answer = resolved(&fixture, "service.run", "run");
    assert_eq!(answer.binding().targets(), &[run], "{answer:?}");
    let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion() else {
        panic!("the other macro can still introduce members: {answer:?}");
    };
    assert_eq!(
        reasons.len(),
        1,
        "only the open macro affects members: {answer:?}"
    );
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
    assert!(
        answer
            .completion()
            .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                callsite_reason
            ))
    );
    assert!(
        !answer
            .completion()
            .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                callee_reason
            ))
    );
    result_slot
}

const RUST_TYPESTATE_BATCH: &str = r#"
pub struct Settings;
pub struct Unmerged;
pub struct Merged;
pub struct BatchConfig<D, S = Unmerged> { pub settings: D, pub state: S }
impl<D> BatchConfig<D, Unmerged> {
    pub fn validate(self) -> Result<BatchConfig<D, Merged>, Error> { loop {} }
    pub fn into_batcher_settings(self) -> Result<Settings, Error> { loop {} }
}
impl<D> BatchConfig<D, Merged> {
    pub fn into_batcher_settings(self) -> Result<Settings, Error> { loop {} }
}
pub struct Error;
pub struct Config { pub batch: BatchConfig<Settings> }
impl Config {
    pub fn run(self) -> Result<Settings, Error> {
        self.batch.validate()?.into_batcher_settings()?
    }
}
"#;

#[test]
fn rust_typestate_receiver_recovers_default_and_unwrapped_result_arguments() {
    let fixture = parsed_rust_fixture(RUST_TYPESTATE_BATCH, b"rust-typestate-receiver-arguments");
    let cancellation = CancellationToken::new();
    let mut session = preloaded_session(&fixture.service, &cancellation);
    let mut hierarchy = HierarchyOperationArena::default();
    let root = callable_reference_named_at(&fixture, "self.batch.validate()", "validate");
    let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, root);
    assert!(evaluation.initialize_root_demands().unwrap());
    for projection in fixture.typed.projections() {
        evaluation.demand_reference(projection.reference());
    }
    for frontier in fixture.typed.frontiers() {
        evaluation.demand_slot(frontier.slot());
    }
    let mut answers = AnswerMap::default();
    let mut states = StateMap::default();
    for _ in 0..64 {
        let round = evaluation
            .evaluate_round(&answers, &states)
            .unwrap()
            .unwrap();
        answers = round.answers;
        states = round.states;
        if round.stable {
            break;
        }
    }
    let settings = definition_after(&fixture, "struct Settings", "Settings");
    let unmerged = definition_after(&fixture, "struct Unmerged", "Unmerged");
    let merged = definition_after(&fixture, "struct Merged", "Merged");
    let target = definition_after(&fixture, "impl<D> BatchConfig<D, Unmerged>", "validate");
    for (marker, name, expected) in [
        (
            "self.batch.validate()",
            "validate",
            vec![Some(settings), Some(unmerged)],
        ),
        (
            "self.batch.validate()?.into_batcher_settings()",
            "into_batcher_settings",
            vec![None, Some(merged)],
        ),
    ] {
        let reference = callable_reference_named_at(&fixture, marker, name);
        let receiver = fixture
            .typed
            .call_obligations()
            .iter()
            .find(|row| row.callee_reference() == reference)
            .unwrap()
            .receiver_slot();
        let recovered = evaluation
            .sparse_receiver_owner_type_arguments_from_receiver(receiver, target, &answers, &states)
            .unwrap()
            .unwrap();
        let SparseReceiverOwnerTypeArguments::Known { arguments, .. } = recovered else {
            panic!("{marker}: {recovered:?}");
        };
        assert_eq!(arguments.len(), expected.len(), "{marker}: {arguments:?}");
        for (argument, expected) in arguments.iter().zip(expected) {
            if let Some(expected) = expected {
                let argument = argument.expect("comparable written argument");
                let identities = fixture
                    .typed
                    .projections()
                    .iter()
                    .filter(|projection| projection.output_slot() == argument.slot)
                    .filter_map(|projection| answers.get(&projection.reference()))
                    .flat_map(|answer| answer.targets())
                    .copied()
                    .collect::<Vec<_>>();
                assert_eq!(identities, [expected], "{marker}: {arguments:?}");
                assert_eq!(
                    (
                        argument.indirection_delta,
                        argument.reference_indirection_delta
                    ),
                    (0, 0)
                );
            } else {
                assert!(
                    argument.is_none()
                        || argument.is_some_and(|argument| states
                            .get(&argument.slot)
                            .and_then(|state| singleton_type_ref(state))
                            .is_some_and(|ty| ty.identity() == settings)),
                    "{marker}: {arguments:?}"
                );
            }
        }
    }
}

#[test]
fn rust_typestate_impl_admission_selects_default_and_merged_methods() {
    let fixture = parsed_rust_fixture(RUST_TYPESTATE_BATCH, b"rust-typestate-impl-admission");
    let subjects = fixture
        .typed
        .deferred_member_owners()
        .iter()
        .map(|row| row.owner_frontier())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        subjects.len(),
        3,
        "each impl owns a distinct candidate subject"
    );
    for method in fixture
        .typed
        .deferred_member_owners()
        .iter()
        .filter(|method| method.definition() != definition_after(&fixture, "impl Config", "run"))
    {
        assert!(
            fixture
                .typed
                .type_arguments()
                .iter()
                .any(|argument| argument.application() == method.owner_frontier()),
            "the candidate frontier owns its written pattern: {method:?}"
        );
    }
    for (marker, name, owner) in [
        (
            "self.batch.validate()",
            "validate",
            "impl<D> BatchConfig<D, Unmerged>",
        ),
        (
            "self.batch.validate()?.into_batcher_settings()",
            "into_batcher_settings",
            "impl<D> BatchConfig<D, Merged>",
        ),
    ] {
        let reference = callable_reference_named_at(&fixture, marker, name);
        let target = definition_after(&fixture, owner, name);
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .unwrap();
        assert_eq!(answer.binding().targets(), [target], "{marker}: {answer:?}");
        assert_eq!(
            answer.binding().completion(),
            &ResolutionCompletion::Complete,
            "{marker}: {answer:?}"
        );
    }
}

#[test]
fn rust_unknown_receiver_argument_keeps_both_impl_candidates() {
    let fixture = parsed_rust_fixture(
        r#"
pub struct X;
pub struct Y;
pub struct P<T> { pub value: T }
impl P<X> { pub fn inspect(&self) {} }
impl P<Y> { pub fn inspect(&self) {} }
pub fn run(value: P<_>) { value.inspect(); }
"#,
        b"rust-unknown-impl-argument",
    );
    let reference = callable_reference_named_at(&fixture, "value.inspect()", "inspect");
    let answer = fixture
        .service
        .resolve_reference(reference, &CancellationToken::new())
        .unwrap();
    let mut expected = vec![
        definition_after(&fixture, "impl P<X>", "inspect"),
        definition_after(&fixture, "impl P<Y>", "inspect"),
    ];
    expected.sort_unstable();
    assert_eq!(answer.binding().targets(), expected, "{answer:?}");
}

#[test]
fn rust_repeated_impl_variable_requires_equal_receiver_arguments() {
    let fixture = parsed_rust_fixture(
        r#"
pub struct X;
pub struct Y;
pub struct Container<T> { pub value: T }
pub struct P<A, B> { pub a: A, pub b: B }
impl<A> P<A, A> { pub fn repeated(&self) {} }
impl<A> P<Container<A>, Container<A>> { pub fn nested(&self) {} }
impl P<&X, Y> { pub fn reference(&self) {} }
pub fn run(equal: P<X, X>, unequal: P<X, Y>, boxed: P<Container<X>, Container<Y>>, pointer: P<*const X, Y>) {
    equal.repeated();
    unequal.repeated();
    boxed.nested();
    pointer.reference();
}
"#,
        b"rust-repeated-impl-variable",
    );
    for (marker, name) in [
        ("equal.repeated()", "repeated"),
        ("unequal.repeated()", "repeated"),
        ("boxed.nested()", "nested"),
        ("pointer.reference()", "reference"),
    ] {
        let reference = callable_reference_named_at(&fixture, marker, name);
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .unwrap();
        if marker == "equal.repeated()" {
            assert_eq!(
                answer.binding().targets(),
                [definition_after(&fixture, "impl<A> P<A, A>", "repeated")],
                "{marker}: {answer:?}"
            );
        } else {
            assert!(
                answer.binding().targets().is_empty(),
                "{marker}: {answer:?}"
            );
        }
    }
}
