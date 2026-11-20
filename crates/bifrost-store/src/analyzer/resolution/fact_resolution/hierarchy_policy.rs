//! Collection and implicit edges share one per-language identity. Split them
//! only when a second consumer needs their lifetimes to vary independently.
use super::*;
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HierarchyPolicyId(pub(crate) u64);
impl HierarchyPolicyId {
    fn hash_extension(self, state: &mut impl Hasher) {
        if self.0 != 0 {
            b"hierarchy-policy".hash(state);
            self.0.hash(state);
        }
    }
}

/// Collection and implicit edges are governed by one immutable per-language identity.
pub(crate) trait HierarchyPolicy: std::fmt::Debug + Sync + std::any::Any {
    fn identity(&self) -> HierarchyPolicyId {
        HierarchyPolicyId(0)
    }
    fn compare_distance(&self, shape: HierarchyLookupShape, new: u32, old: u32) -> Ordering {
        if shape.searches_callable_overload_set() {
            Ordering::Equal
        } else {
            new.cmp(&old)
        }
    }
    fn retain_owner(&self, has_matching_declaration: bool) -> bool {
        has_matching_declaration
    }
    fn direct_hit_stops(&self, shape: HierarchyLookupShape) -> bool {
        !shape.searches_callable_overload_set()
    }
    fn evidence_cutoff(&self, shape: HierarchyLookupShape, nearest: Option<u32>) -> Option<u32> {
        if shape.searches_callable_overload_set() {
            None
        } else {
            nearest
        }
    }
    /// A member-search policy may exclude a known edge role. Unclassified
    /// edges remain open evidence; the shared frame never drops them here.
    fn includes_parent_kind(&self, _kind: Option<ClassifiedSupertypeKind>) -> bool {
        true
    }
    /// The default cannot prove that an owner has no implicit root, so it keeps
    /// the hierarchy open. A policy whose producer emits implicit roots as
    /// ordinary edges selects `ExplicitHierarchyEdges` instead.
    fn edge_provider(&self) -> &'static dyn HierarchyEdgeProvider {
        &CONSERVATIVE_HIERARCHY_EDGES
    }
}
#[derive(Debug)]
pub(crate) struct DefaultHierarchyPolicy {
    // A nonzero-sized singleton has a distinct data address for registry admission.
    _identity: u8,
}
/// The engine's baseline policy (identity 0), used by every owner without a
/// registered policy, including the JVM, Go and Rust. It assumes the producer
/// emits every implicit root as an ordinary edge, as the Java producer does
/// for the implicit `Object` supertype. A language whose implicit root is not
/// emitted must register its own policy and edge provider, as Python does.
/// The baseline stays identity 0 because nonzero identities enter hashed keys.
impl HierarchyPolicy for DefaultHierarchyPolicy {
    fn edge_provider(&self) -> &'static dyn HierarchyEdgeProvider {
        &EXPLICIT_HIERARCHY_EDGES
    }
}
pub(crate) static DEFAULT_HIERARCHY_POLICY: DefaultHierarchyPolicy =
    DefaultHierarchyPolicy { _identity: 0 };

/// Query-local proof from classified written edges, before any default root.
pub(crate) struct NormalizedWrittenParents {
    pub(crate) proved_class_parent: Option<SemanticId>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) next_ordinal: Option<u32>,
}

pub(crate) enum ImplicitBasePreparation {
    Ready(ImplicitBaseRead),
    Reference(ImplicitBaseReference),
}

/// The selected reference and whole-type frontier retain their own authority.
/// No binding or hierarchy walk is performed by provider preparation.
pub(crate) struct ImplicitBaseReference {
    pub(crate) language: Language,
    pub(crate) reference: SemanticId,
    pub(crate) frontier: SemanticId,
    pub(crate) ordinal: u32,
    pub(crate) kind: ClassifiedSupertypeKind,
    pub(crate) provider: HierarchyProviderKey,
    pub(crate) rules:
        Option<&'static brokk_bifrost_core::analyzer::capabilities::ImplicitInterfaceMembers>,
    pub(crate) observations: Box<[HierarchyProviderObservation]>,
    pub(crate) binding_completion: ResolutionCompletion,
    pub(crate) context_completion: ResolutionCompletion,
}

pub(crate) struct ImplicitBaseBinding {
    pub(crate) reference: SemanticId,
    pub(crate) frontier: SemanticId,
}

pub(crate) struct WrittenHierarchyBase<'a> {
    pub(crate) targets: &'a [SemanticId],
    pub(crate) complete: bool,
}

pub(crate) trait HierarchyEdgeProvider: std::fmt::Debug + Sync {
    fn prepare_implicit_base(
        &self,
        owner: SemanticId,
        _written: &NormalizedWrittenParents,
        raw_written: &[WrittenHierarchyBase<'_>],
        source: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBasePreparation>> {
        Ok(self
            .implicit_base(owner, raw_written, source, cancellation)?
            .map(ImplicitBasePreparation::Ready))
    }

    fn base_preservation_rule(&self) -> Option<crate::analyzer::resolution::BasePreservationRule> {
        None
    }

    fn base_preservation_order(&self) -> Option<&'static dyn HierarchyLinearizationPolicy> {
        None
    }

    fn base_preservation_input(
        &self,
        _owner: SemanticId,
        _source: &dyn SelectedTypedFactSource,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<crate::analyzer::resolution::BasePreservationGuard>> {
        Ok(None)
    }

    fn implicit_base(
        &self,
        _owner: SemanticId,
        _written: &[WrittenHierarchyBase<'_>],
        _source: &dyn SelectedTypedFactSource,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBaseRead>> {
        Ok(Some(ImplicitBaseRead {
            guard: None,
            base: None,
            observations: Box::new([]),
            completion: ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(_owner),
            ]),
        }))
    }
}
/// Use when the producer emits implicit roots as ordinary hierarchy edges.
#[derive(Debug)]
pub(crate) struct ExplicitHierarchyEdges;
impl HierarchyEdgeProvider for ExplicitHierarchyEdges {
    fn prepare_implicit_base(
        &self,
        owner: SemanticId,
        written: &NormalizedWrittenParents,
        raw_written: &[WrittenHierarchyBase<'_>],
        source: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBasePreparation>> {
        // Admission already read the immutable selected source header. Other
        // languages retain the existing provider path without a root SQL read.
        let rules = source
            .admitted_owner_language(owner)
            .and_then(|language| source.implicit_root_rules_for_language(language));
        let Some(rules) = rules else {
            return Ok(self
                .implicit_base(owner, raw_written, source, cancellation)?
                .map(ImplicitBasePreparation::Ready));
        };
        let Some(input) = source.selected_implicit_root_input(owner, cancellation)? else {
            return Ok(None);
        };
        let open = |completion: ResolutionCompletion| {
            let provider = HierarchyProviderKey::source(
                owner,
                owner,
                ResolutionNamespace::Type,
                HierarchyProviderAuthority::Boundary(owner),
                HierarchyProviderOperand::SupertypeInventory,
                owner,
                0,
            );
            ImplicitBasePreparation::Ready(ImplicitBaseRead {
                guard: None,
                base: None,
                observations: Box::new([HierarchyProviderObservation {
                    provider,
                    visit: HierarchyProviderVisit::Observed,
                    completion: completion.clone(),
                    inventory_complete: Some(false),
                }]),
                completion,
            })
        };
        let root = match input {
            super::super::SelectedImplicitRootInput::NotProvided => {
                return Ok(Some(open(incomplete(owner))));
            }
            super::super::SelectedImplicitRootInput::Open(completion) => {
                return Ok(Some(open(completion)));
            }
            super::super::SelectedImplicitRootInput::Source(root) => root,
        };
        let context_completion = root.context_completion.combine(&written.completion);
        let kind = match root.owner_kind {
            super::super::NominalParentTargetKind::Class
            | super::super::NominalParentTargetKind::Struct
            | super::super::NominalParentTargetKind::Enum => {
                if context_completion == ResolutionCompletion::Complete {
                    ClassifiedSupertypeKind::ImplicitSuperclass
                } else {
                    ClassifiedSupertypeKind::LookupOnlyRoot
                }
            }
            super::super::NominalParentTargetKind::Interface => {
                ClassifiedSupertypeKind::LookupOnlyRoot
            }
            super::super::NominalParentTargetKind::NonBase
            | super::super::NominalParentTargetKind::Missing
            | super::super::NominalParentTargetKind::Ambiguous
            | super::super::NominalParentTargetKind::Incomplete => {
                return Ok(Some(open(incomplete(owner))));
            }
        };
        let Some(ordinal) = written.next_ordinal else {
            return Ok(Some(open(written.completion.clone())));
        };
        let provider = HierarchyProviderKey::source(
            owner,
            owner,
            ResolutionNamespace::Type,
            HierarchyProviderAuthority::Declaration(owner),
            HierarchyProviderOperand::SupertypeEdge {
                reference: root.reference,
                ordinal,
            },
            root.reference,
            ordinal,
        );
        let observations = Box::new([HierarchyProviderObservation {
            provider: provider.clone(),
            visit: HierarchyProviderVisit::Observed,
            completion: ResolutionCompletion::Complete,
            inventory_complete: Some(true),
        }]);
        Ok(Some(ImplicitBasePreparation::Reference(
            ImplicitBaseReference {
                language: root.language,
                reference: root.reference,
                frontier: root.frontier,
                ordinal,
                kind,
                provider,
                rules: (kind == ClassifiedSupertypeKind::LookupOnlyRoot).then_some(rules),
                observations,
                binding_completion: ResolutionCompletion::Complete,
                context_completion,
            },
        )))
    }

    fn implicit_base(
        &self,
        _owner: SemanticId,
        _written: &[WrittenHierarchyBase<'_>],
        _source: &dyn SelectedTypedFactSource,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBaseRead>> {
        Ok(Some(ImplicitBaseRead {
            guard: None,
            base: None,
            observations: Box::new([]),
            completion: ResolutionCompletion::Complete,
        }))
    }
}
pub(crate) static EXPLICIT_HIERARCHY_EDGES: ExplicitHierarchyEdges = ExplicitHierarchyEdges;
/// Uses the trait's conservative `implicit_base`.
#[derive(Debug)]
struct ConservativeHierarchyEdges;
impl HierarchyEdgeProvider for ConservativeHierarchyEdges {}
static CONSERVATIVE_HIERARCHY_EDGES: ConservativeHierarchyEdges = ConservativeHierarchyEdges;
pub(crate) struct ImplicitBaseRead {
    pub(crate) guard: Option<crate::analyzer::resolution::BasePreservationGuard>,
    pub(crate) base: Option<ImplicitBaseFact>,
    pub(crate) observations: Box<[HierarchyProviderObservation]>,
    pub(crate) completion: ResolutionCompletion,
}
pub(crate) struct ImplicitBaseFact {
    pub(crate) context_completion: ResolutionCompletion,
    pub(crate) binding: Option<ImplicitBaseBinding>,
    pub(crate) rules:
        Option<&'static brokk_bifrost_core::analyzer::capabilities::ImplicitInterfaceMembers>,
    pub(crate) kind: ClassifiedSupertypeKind,
    pub(crate) target: Option<SemanticId>,
    pub(crate) definite: bool,
    pub(crate) external: bool,
    pub(crate) ordinal: u32,
    pub(crate) provider: HierarchyProviderKey,
    pub(crate) occurrence: SemanticId,
}

impl Hash for HierarchyLookupShape {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Keep the exact pre-policy field sequence; zero contributes NO bytes.
        self.lookup.hash(state);
        self.namespace.hash(state);
        self.category.hash(state);
        self.receiver_indirection.hash(state);
        self.candidate_policy.hash(state);
        self.namespace_aliases.hash(state);
        self.policy.hash_extension(state);
        if let Some(HierarchyMemberAdmission::PublicInstanceMethods) = self.admission {
            b"member_admission".hash(state);
            b"public-instance-methods".hash(state);
        }
        if let Some(access) = self.access_context {
            b"candidate-access-context".hash(state);
            access.hash(state);
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct HierarchyOwnerKey {
    pub(super) owner: SemanticId,
    pub(super) policy: HierarchyPolicyId,
}
impl Hash for HierarchyOwnerKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.policy.hash_extension(state);
    }
}
impl From<SemanticId> for HierarchyOwnerKey {
    fn from(owner: SemanticId) -> Self {
        Self {
            owner,
            policy: HierarchyPolicyId(0),
        }
    }
}

impl HierarchyOperationArena {
    pub(super) fn register_policy(
        &mut self,
        policy: &'static dyn HierarchyPolicy,
    ) -> HierarchyPolicyId {
        let id = policy.identity();
        if id == HierarchyPolicyId(0) {
            assert!(
                std::ptr::addr_eq(policy, &DEFAULT_HIERARCHY_POLICY as &dyn HierarchyPolicy),
                "zero identifies only the default policy"
            );
        } else if let Some(previous) = self.policies.insert(id, policy) {
            // Vtables can be duplicated across codegen units. Compare the data
            // address and concrete type for admission only; neither enters a key.
            assert!(
                std::ptr::addr_eq(previous, policy) && previous.type_id() == policy.type_id(),
                "one static policy per identity"
            );
        }
        id
    }
    pub(super) fn policy(&self, id: HierarchyPolicyId) -> &'static dyn HierarchyPolicy {
        if id == HierarchyPolicyId(0) {
            &DEFAULT_HIERARCHY_POLICY
        } else {
            self.policies[&id]
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum HierarchyBaseOrigin {
    Typed(SelectedTypedRowIdentity),
    Implicit {
        provider: HierarchyProviderKey,
        definite: bool,
        external: bool,
    },
}
impl HierarchyBaseOrigin {
    pub(super) fn provider(
        &self,
        key: HierarchyNodeKey,
        operand: HierarchyProviderOperand,
    ) -> HierarchyProviderKey {
        match self {
            Self::Typed(row) => HierarchyProviderKey::new(
                key,
                HierarchyProviderAuthority::Typed(row.clone()),
                operand,
            ),
            Self::Implicit { provider, .. } => provider.with_operand(operand),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12141: a cached creation-hook rejection cannot answer the narrower mro-free question"
    )]
    fn guard_rules_isolate_cached_creation_and_mro_proofs() {
        use crate::analyzer::resolution::{
            BasePreservationGuard, BasePreservationMembers, ClassCreationKind,
            ImplicitBaseAuthority, ImplicitBaseInputs, ImplicitRootObject, QueryObligations,
        };
        use crate::analyzer::store::python_member_rows::{
            PYTHON_BASE_PRESERVATION_RULE as FULL, PYTHON_MRO_ONLY_RULE as MRO,
        };
        for member in ["__init__", "mro"] {
            let subject = SemanticId::for_test("subject");
            let meta = SemanticId::for_test("meta");
            let terminal = hierarchy_global_atom_identity(
                &HierarchyOperationArena::default(),
                FULL.terminal.as_bytes(),
            );
            let mut source = PreloadedFactResolutionService::from_lowered_fragments([], []);
            for owner in [subject, meta] {
                source.base_guard_test_inputs.insert(
                    owner,
                    ImplicitBaseInputs {
                        base_preservation: (owner == subject).then(|| BasePreservationGuard {
                            references: vec![meta],
                            terminal: FULL.terminal,
                            absent_members: FULL.absent_members,
                            enclosing_absent_members: FULL.enclosing_absent_members,
                            completion: ResolutionCompletion::Complete,
                        }),
                        written_inventory_complete: true,
                        written_base_count: 0,
                        creation: ClassCreationKind::Ordinary,
                        root_object: Some(ImplicitRootObject {
                            identity: terminal,
                            occurrence: terminal,
                            authority: ImplicitBaseAuthority::Intrinsic {
                                descriptor: terminal,
                            },
                        }),
                        authority: ImplicitBaseAuthority::Intrinsic { descriptor: owner },
                        completion: ResolutionCompletion::Complete,
                    },
                );
                source.base_guard_test_members.insert(
                    owner,
                    BasePreservationMembers {
                        mutation_receivers: vec![],
                        terminal_mutation_receivers: Some(vec![]),
                        names: if owner == meta {
                            vec![member.into()]
                        } else {
                            vec![]
                        },
                        complete: true,
                    },
                );
            }
            let cancellation = CancellationToken::new();
            let mut session = FactReadSession::from_split_sources(&source, &source, &cancellation);
            let mut arena = HierarchyOperationArena::default();
            let policy = arena.register_policy(
                crate::analyzer::store::resolution_operation::python_hierarchy_policy_for_test(),
            );
            arena.reference_answers.insert(
                meta,
                ClosedQueryValue::new(
                    Arc::new(ResolutionAnswer::new(
                        vec![meta],
                        vec![],
                        ResolutionCompletion::Complete,
                    )),
                    QueryObligations::empty(),
                ),
            );
            let mut evaluation = FactEvaluation::new(&mut session, &mut arena, subject);
            evaluation.hierarchy_policy = policy;
            let mut cursors = HashMap::default();
            let mut aliases = HashMap::default();
            for (rule, admitted) in [
                (FULL, false),
                (MRO, member == "__init__"),
                (FULL, false),
                (MRO, member == "__init__"),
            ] {
                assert_eq!(
                    evaluation
                        .settle_base_preservation_guards(
                            &[subject],
                            Some(rule),
                            &mut cursors,
                            &mut aliases
                        )
                        .unwrap(),
                    Some(vec![])
                );
                assert_eq!(
                    evaluation.base_preservation_proven(subject, rule),
                    admitted,
                    "{member}: {rule:?}"
                );
            }
            assert_eq!(evaluation.hierarchy.base_guard_proofs.len(), 2);
            drop(evaluation);
            let mut operation = FactResolutionOperation::from_session(session);
            operation.hierarchy = arena;
            struct Provider;
            impl demand_scheduler::RootProvider for Provider {
                fn discover(
                    &mut self,
                    _: &demand_scheduler::RelationKey,
                ) -> StoreResult<demand_scheduler::RootDiscovery> {
                    unreachable!("cached reference")
                }
                fn close(
                    &mut self,
                    _: &demand_scheduler::RelationKey,
                    _: &[(demand_scheduler::ReferenceKey, &FactResolutionAnswer)],
                ) -> StoreResult<demand_scheduler::RootClosure> {
                    unreachable!("guard-only demand")
                }
            }
            let request = || demand_scheduler::HierarchyDemandRequest {
                policy:
                    crate::analyzer::store::resolution_operation::python_hierarchy_policy_for_test(),
                order: None,
                root: subject,
                shape: subject,
                language: Language::Python,
            };
            assert_eq!(
                operation
                    .prove_guard_by_demand(request(), MRO, &mut Provider)
                    .unwrap(),
                member == "__init__"
            );
            cancellation.cancel();
            assert!(
                !operation
                    .prove_guard_by_demand(request(), MRO, &mut Provider)
                    .unwrap()
            );
        }
    }

    #[derive(Default)]
    struct Bytes(Vec<u8>);
    impl Hasher for Bytes {
        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
        fn finish(&self) -> u64 {
            unreachable!("capture exact input bytes, not a digest")
        }
    }
    // This is the pre-#5658 shape, deliberately retaining its derived Hash.
    #[derive(Hash)]
    struct OldShape {
        lookup: SemanticId,
        namespace: ResolutionNamespace,
        category: QualifierCategory,
        receiver_indirection: i64,
        candidate_policy: HierarchyCandidatePolicy,
        namespace_aliases: &'static [ResolutionMemberKind],
    }
    #[derive(Hash)]
    struct OldSummaryKey {
        shape: OldShape,
        owner: SemanticId,
    }
    fn bytes(value: &impl Hash) -> Vec<u8> {
        let mut hash = Bytes::default();
        value.hash(&mut hash);
        hash.0
    }
    fn old(shape: HierarchyLookupShape) -> OldShape {
        OldShape {
            lookup: shape.lookup,
            namespace: shape.namespace,
            category: shape.category,
            receiver_indirection: shape.receiver_indirection,
            candidate_policy: shape.candidate_policy,
            namespace_aliases: shape.namespace_aliases,
        }
    }
    #[test]
    fn hierarchy_policy_default_lookup_summary_and_edge_bytes_are_unchanged() {
        for language in [
            Language::CSharp,
            Language::Rust,
            Language::Go,
            Language::Java,
            Language::Kotlin,
            Language::Scala,
        ] {
            for namespace in [
                ResolutionNamespace::Value,
                ResolutionNamespace::Type,
                ResolutionNamespace::Callable,
            ] {
                for category in [QualifierCategory::Type, QualifierCategory::Runtime] {
                    let mut shape = HierarchyLookupShape::new(
                        SemanticId::for_test("key-lookup"),
                        namespace,
                        category,
                        0,
                    );
                    shape.namespace_aliases =
                        super::super::super::fact_source::language_value_member_aliases(language);
                    let owner = SemanticId::for_test("key-owner");
                    for shape in [shape, shape.with_callable_overload_set()] {
                        assert_eq!(
                            bytes(&shape),
                            bytes(&old(shape)),
                            "{language:?} {namespace:?}"
                        );
                        let first = HierarchyLookupShape {
                            access_context: Some(PreparedDeclarationAccessContext {
                                context: DeclarationAccessContext::EnclosingType(owner),
                                reference: SemanticId::for_test("first-caller-site"),
                            }),
                            ..shape
                        };
                        let second = HierarchyLookupShape {
                            access_context: Some(PreparedDeclarationAccessContext {
                                context: DeclarationAccessContext::EnclosingType(owner),
                                reference: SemanticId::for_test("second-caller-site"),
                            }),
                            ..shape
                        };
                        assert_eq!(first, second, "same enclosing type is one context");
                        assert_eq!(bytes(&first), bytes(&second));
                        assert_ne!(bytes(&first), bytes(&shape));
                        let outside = HierarchyLookupShape {
                            access_context: Some(PreparedDeclarationAccessContext {
                                context: DeclarationAccessContext::OutsideType,
                                reference: SemanticId::for_test("outside-caller-site"),
                            }),
                            ..shape
                        };
                        assert_ne!(first, outside);
                        assert_ne!(bytes(&first), bytes(&outside));
                        let summary = HierarchyNodeKey { shape, owner };
                        assert_eq!(
                            bytes(&summary),
                            bytes(&OldSummaryKey {
                                shape: old(shape),
                                owner
                            }),
                            "{language:?} summary"
                        );
                        assert_eq!(
                            bytes(&HierarchyOwnerKey::from(owner)),
                            bytes(&owner),
                            "{language:?} edges"
                        );
                        let constrained = HierarchyLookupShape {
                            admission: Some(HierarchyMemberAdmission::PublicInstanceMethods),
                            ..shape
                        };
                        assert_ne!(bytes(&constrained), bytes(&shape));
                        assert_ne!(
                            bytes(&HierarchyNodeKey {
                                shape: constrained,
                                owner
                            }),
                            bytes(&summary)
                        );
                        let custom = HierarchyLookupShape {
                            policy: HierarchyPolicyId(7),
                            ..shape
                        };
                        assert_ne!(bytes(&custom), bytes(&shape));
                        assert_ne!(
                            bytes(&HierarchyOwnerKey {
                                owner,
                                policy: custom.policy
                            }),
                            bytes(&owner)
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn hierarchy_admission_preserves_absent_canonical_shape_identity() {
        let source = PreloadedFactResolutionService::from_lowered_fragments([], []);
        let cancellation = CancellationToken::new();
        let identities = SelectedContextIdentities::new();
        let lookup = identities.semantic([27; 32]);
        let mut session = FactReadSession::new(&source, &cancellation);
        session.context_identities = Some(identities);
        let arena = HierarchyOperationArena::default();
        for namespace in [
            ResolutionNamespace::Value,
            ResolutionNamespace::Type,
            ResolutionNamespace::Callable,
        ] {
            for category in [QualifierCategory::Type, QualifierCategory::Runtime] {
                let shape = HierarchyLookupShape::new(lookup, namespace, category, 0);
                let mut old = CanonicalHasher::new(b"test-hierarchy-absent-admission:v1");
                old.identity_field("lookup", lookup, |key| session.identity_digest(&arena, key))
                    .unwrap();
                old.field("namespace", namespace.identity_label().as_bytes());
                old.field(
                    "category",
                    match category {
                        QualifierCategory::Type => b"type",
                        QualifierCategory::Runtime => b"runtime",
                    },
                );
                old.field("receiver_indirection", &0_i64.to_le_bytes());
                let mut current = CanonicalHasher::new(b"test-hierarchy-absent-admission:v1");
                hash_hierarchy_shape(&session, &arena, &mut current, shape).unwrap();
                let current = current.finish();
                assert_eq!(
                    old.finish(),
                    current,
                    "absent constraint appends zero canonical bytes"
                );
                let constrained = HierarchyLookupShape {
                    admission: Some(HierarchyMemberAdmission::PublicInstanceMethods),
                    ..shape
                };
                let mut admitted = CanonicalHasher::new(b"test-hierarchy-absent-admission:v1");
                hash_hierarchy_shape(&session, &arena, &mut admitted, constrained).unwrap();
                assert_ne!(
                    current,
                    admitted.finish(),
                    "constrained view has an independent identity"
                );
            }
        }
    }

    #[derive(Debug)]
    struct Exhaustive;
    impl HierarchyPolicy for Exhaustive {
        fn identity(&self) -> HierarchyPolicyId {
            HierarchyPolicyId(7)
        }
        fn compare_distance(&self, _: HierarchyLookupShape, _: u32, _: u32) -> Ordering {
            Ordering::Equal
        }
        fn retain_owner(&self, _: bool) -> bool {
            true
        }
        fn direct_hit_stops(&self, _: HierarchyLookupShape) -> bool {
            false
        }
        fn evidence_cutoff(&self, _: HierarchyLookupShape, _: Option<u32>) -> Option<u32> {
            None
        }
    }
    static EXHAUSTIVE: Exhaustive = Exhaustive;
    #[test]
    fn hierarchy_policy_registry_preserves_default_and_exhaustive_identity() {
        let mut arena = HierarchyOperationArena::default();
        assert_eq!(
            arena.register_policy(&DEFAULT_HIERARCHY_POLICY),
            HierarchyPolicyId(0)
        );
        assert!(arena.policies.is_empty());
        assert_eq!(arena.register_policy(&EXHAUSTIVE), HierarchyPolicyId(7));
        assert_eq!(arena.register_policy(&EXHAUSTIVE), HierarchyPolicyId(7));
        assert!(arena.policy(HierarchyPolicyId(7)).retain_owner(false));
        assert!(!arena.policy(HierarchyPolicyId(0)).retain_owner(false));
    }
    #[test]
    #[should_panic(expected = "one static policy per identity")]
    fn hierarchy_policy_registry_rejects_conflicting_static_policy() {
        #[derive(Debug)]
        struct Different;
        impl HierarchyPolicy for Different {
            fn identity(&self) -> HierarchyPolicyId {
                HierarchyPolicyId(7)
            }
        }
        static DIFFERENT: Different = Different;
        let mut arena = HierarchyOperationArena::default();
        arena.register_policy(&EXHAUSTIVE);
        arena.register_policy(&DIFFERENT);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct BaseGuardKey {
    pub(super) owner: HierarchyOwnerKey,
    pub(super) rule: crate::analyzer::resolution::BasePreservationRule,
}

/// One suspended conditional-input proof. Only the shared driver owns these
/// graph and reference cursors; language sources supply inventories and rules.
pub(super) struct BaseGuardCursor {
    rule: crate::analyzer::resolution::BasePreservationGuard,
    pending: VecDeque<GuardOperand>,
    nodes: HashMap<SemanticId, GuardOwner>,
    roots: Vec<SemanticId>,
    terminal: SemanticId,
    observations: Vec<HierarchyProviderObservation>,
    obligations: super::super::QueryObligations,
    mutation_receivers: HashSet<(GuardRelation, SemanticId)>,
    mutated_owners: HashSet<SemanticId>,
    mutation_targets: HashSet<SemanticId>,
    unknown_mutation: bool,
    unknown_terminal_mutation: bool,
}
#[derive(Debug)]
pub(super) struct BasePreservationProof {
    pub(super) admitted: bool,
    pub(super) observations: Vec<HierarchyProviderObservation>,
}
struct GuardOperand {
    container: Option<SemanticId>,
    reference: SemanticId,
    target: Option<SemanticId>,
    relation: GuardRelation,
}
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum GuardRelation {
    Base,
    Guard,
    Mutation,
    TerminalMutation,
}
#[derive(Default)]
struct GuardOwner {
    bases: Vec<SemanticId>,
    guards: Vec<SemanticId>,
    members: Option<crate::analyzer::resolution::BasePreservationMembers>,
}

impl FactEvaluation<'_, '_> {
    pub(super) fn settle_base_preservation_guards(
        &mut self,
        owners: &[SemanticId],
        supplied_rule: Option<crate::analyzer::resolution::BasePreservationRule>,
        cursors: &mut HashMap<BaseGuardKey, BaseGuardCursor>,
        aliases: &mut HashMap<SemanticId, HierarchyClassAliasWalk>,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        for &subject in owners {
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                self.cancellation_observed = true;
                return Ok(None);
            }
            let edge_provider = self.hierarchy.policy(self.hierarchy_policy).edge_provider();
            let Some(identity) = supplied_rule.or_else(|| edge_provider.base_preservation_rule())
            else {
                continue;
            };
            let proof_key = BaseGuardKey {
                owner: HierarchyOwnerKey {
                    owner: subject,
                    policy: self.hierarchy_policy,
                },
                rule: identity,
            };
            if let Some(proof) = self.hierarchy.base_guard_proofs.get(&proof_key) {
                proof.read(&mut self.query_obligations.node(QueryNode::Hierarchy(subject)));
                continue;
            }
            let mut cursor = if let Some(cursor) = cursors.remove(&proof_key) {
                cursor
            } else {
                let Some(mut rule) = edge_provider.base_preservation_input(
                    subject,
                    self.session.typed_source,
                    self.cancellation,
                )?
                else {
                    continue;
                };
                rule.terminal = identity.terminal;
                rule.absent_members = identity.absent_members;
                rule.enclosing_absent_members = identity.enclosing_absent_members;
                if rule.completion != ResolutionCompletion::Complete || rule.references.is_empty() {
                    self.hierarchy.base_guard_proofs.insert(
                        proof_key,
                        ClosedQueryValue::new(
                            BasePreservationProof {
                                admitted: false,
                                observations: Vec::new(),
                            },
                            self.query_obligations.scope(QueryNode::Hierarchy(subject)),
                        ),
                    );
                    continue;
                }
                if !self.session.charge_scope_steps(rule.references.len()) {
                    self.cancellation_observed = true;
                    return Ok(None);
                }
                BaseGuardCursor {
                    // Start with the subject, so inherited providers participate
                    // in selecting its effective creation guard too.
                    pending: VecDeque::from([GuardOperand {
                        container: None,
                        reference: subject,
                        target: Some(subject),
                        relation: GuardRelation::Base,
                    }]),
                    terminal: hierarchy_global_atom_identity(
                        &*self.hierarchy,
                        rule.terminal.as_bytes(),
                    ),
                    rule,
                    nodes: HashMap::default(),
                    roots: Vec::new(),
                    observations: Vec::new(),
                    obligations: super::super::QueryObligations::empty(),
                    mutation_receivers: HashSet::default(),
                    mutated_owners: HashSet::default(),
                    mutation_targets: HashSet::default(),
                    unknown_mutation: false,
                    unknown_terminal_mutation: false,
                }
            };
            self.query_obligations
                .node(QueryNode::Hierarchy(subject))
                .union(&cursor.obligations);
            let mut rejected = false;
            while let Some(operand) = cursor.pending.front() {
                if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                    self.cancellation_observed = true;
                    return Ok(None);
                }
                let terminal_mutation = matches!(operand.relation, GuardRelation::TerminalMutation);
                let mutation = matches!(
                    operand.relation,
                    GuardRelation::Mutation | GuardRelation::TerminalMutation
                );
                let reference = operand.reference;
                let target = if let Some(target) = operand.target {
                    target
                } else if self
                    .session
                    .typed_source
                    .base_preservation_terminal_reference(
                        reference,
                        cursor.rule.terminal,
                        self.cancellation,
                    )?
                {
                    cursor.terminal
                } else {
                    let mut pending = if !self.hierarchy.reference_ready(reference) {
                        vec![reference]
                    } else {
                        match self.settle_class_aliases(&[reference], aliases)? {
                            Some(pending) => pending,
                            None => return Ok(None),
                        }
                    };
                    if !pending.is_empty() {
                        pending.sort_unstable();
                        pending.dedup();
                        cursors.insert(proof_key, cursor);
                        return Ok(Some(pending));
                    }
                    let mut uncertain = false;
                    for source in std::iter::once(reference).chain(
                        self.hierarchy
                            .alias_source_references
                            .get(&reference)
                            .into_iter()
                            .flatten()
                            .copied(),
                    ) {
                        if !self.session.charge_scope_steps(1) {
                            self.cancellation_observed = true;
                            return Ok(None);
                        }
                        let session = &mut *self.session;
                        let cancellation = self.cancellation;
                        let mut stopped = false;
                        let source_complete =
                            session.typed_source.base_preservation_reference_complete(
                                source,
                                cancellation,
                                &mut || {
                                    let proceed = !cancellation.is_cancelled()
                                        && session.charge_scope_steps(1);
                                    stopped |= !proceed;
                                    proceed
                                },
                            )?;
                        if stopped {
                            self.cancellation_observed = true;
                            return Ok(None);
                        }
                        if !source_complete {
                            uncertain = true;
                            break;
                        }
                    }
                    if uncertain && mutation {
                        if terminal_mutation {
                            cursor.unknown_terminal_mutation = true;
                        } else {
                            cursor.unknown_mutation = true;
                        }
                        cursor.pending.pop_front();
                        continue;
                    }
                    if uncertain {
                        rejected = true;
                        break;
                    }
                    let answer = self
                        .hierarchy
                        .effective_reference_answer(reference, &mut cursor.obligations)
                        .clone();
                    self.query_obligations
                        .node(QueryNode::Hierarchy(subject))
                        .union(&cursor.obligations);
                    if answer.completion() != &ResolutionCompletion::Complete
                        || answer.targets().len() != 1
                    {
                        if mutation {
                            if terminal_mutation {
                                cursor.unknown_terminal_mutation = true;
                            } else {
                                cursor.unknown_mutation = true;
                            }
                            cursor.pending.pop_front();
                            continue;
                        }
                        rejected = true;
                        break;
                    }
                    answer.targets()[0]
                };
                let target = if target == cursor.terminal
                    || self.session.typed_source.base_preservation_terminal_owner(
                        target,
                        cursor.rule.terminal,
                        self.cancellation,
                    )? {
                    cursor.terminal
                } else {
                    target
                };
                let operand = cursor.pending.pop_front().expect("front operand");
                if mutation {
                    if !terminal_mutation {
                        cursor.mutated_owners.insert(target);
                    }
                    cursor.mutation_targets.insert(target);
                }
                match operand.container {
                    None if !mutation => cursor.roots.push(target),
                    None => {}
                    Some(container) => match operand.relation {
                        GuardRelation::Base => cursor
                            .nodes
                            .get_mut(&container)
                            .expect("guard owner")
                            .bases
                            .push(target),
                        GuardRelation::Guard => cursor
                            .nodes
                            .get_mut(&container)
                            .expect("guard owner")
                            .guards
                            .push(target),
                        GuardRelation::Mutation | GuardRelation::TerminalMutation => {
                            unreachable!("mutation is handled before graph edges")
                        }
                    },
                }
                if target == cursor.terminal || cursor.nodes.contains_key(&target) {
                    continue;
                }
                let Some(inputs) = self
                    .session
                    .typed_source
                    .implicit_base_inputs(target, self.cancellation)?
                else {
                    if mutation {
                        if terminal_mutation {
                            cursor.unknown_terminal_mutation = true;
                        } else {
                            cursor.unknown_mutation = true;
                        }
                        continue;
                    }
                    rejected = true;
                    break;
                };
                let completion = inputs
                    .base_preservation
                    .as_ref()
                    .map_or(&inputs.completion, |guard| &guard.completion);
                if !inputs.written_inventory_complete
                    || completion != &ResolutionCompletion::Complete
                {
                    if mutation {
                        if terminal_mutation {
                            cursor.unknown_terminal_mutation = true;
                        } else {
                            cursor.unknown_mutation = true;
                        }
                        continue;
                    }
                    rejected = true;
                    break;
                }
                let mut requested = cursor
                    .rule
                    .absent_members
                    .iter()
                    .chain(cursor.rule.enclosing_absent_members)
                    .copied()
                    .collect::<Vec<_>>();
                requested.sort_unstable();
                requested.dedup();
                let session = &mut *self.session;
                let cancellation = self.cancellation;
                let mut stopped = false;
                let members = session.typed_source.base_preservation_members(
                    target,
                    &requested,
                    cancellation,
                    &mut || {
                        let proceed = !cancellation.is_cancelled() && session.charge_scope_steps(1);
                        stopped |= !proceed;
                        proceed
                    },
                )?;
                if stopped {
                    self.cancellation_observed = true;
                    return Ok(None);
                }
                if members.is_none() && target == subject {
                    // No subject inventory means no closed terminal-binding
                    // mutation input, even when the explicit guard is terminal.
                    rejected = true;
                    break;
                }
                if let Some(members) = &members {
                    if let Some(receivers) = &members.terminal_mutation_receivers {
                        for &reference in receivers {
                            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                                self.cancellation_observed = true;
                                return Ok(None);
                            }
                            if cursor
                                .mutation_receivers
                                .insert((GuardRelation::TerminalMutation, reference))
                            {
                                cursor.pending.push_back(GuardOperand {
                                    container: None,
                                    reference,
                                    target: None,
                                    relation: GuardRelation::TerminalMutation,
                                });
                            }
                        }
                    } else {
                        cursor.unknown_terminal_mutation = true;
                    }
                    for &reference in &members.mutation_receivers {
                        if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                            self.cancellation_observed = true;
                            return Ok(None);
                        }
                        if cursor
                            .mutation_receivers
                            .insert((GuardRelation::Mutation, reference))
                        {
                            cursor.pending.push_back(GuardOperand {
                                container: None,
                                reference,
                                target: None,
                                relation: GuardRelation::Mutation,
                            });
                        }
                    }
                }
                let authority = match inputs.authority {
                    crate::analyzer::resolution::ImplicitBaseAuthority::Selected(row) => {
                        HierarchyProviderAuthority::Typed(row)
                    }
                    crate::analyzer::resolution::ImplicitBaseAuthority::Intrinsic {
                        descriptor,
                    } => HierarchyProviderAuthority::Intrinsic { descriptor },
                };
                cursor.observations.push(HierarchyProviderObservation {
                    provider: HierarchyProviderKey::source(
                        target,
                        target,
                        ResolutionNamespace::Type,
                        authority,
                        HierarchyProviderOperand::SupertypeInventory,
                        target,
                        0,
                    ),
                    visit: HierarchyProviderVisit::Observed,
                    completion: ResolutionCompletion::Complete,
                    inventory_complete: Some(true),
                });
                cursor.nodes.insert(
                    target,
                    GuardOwner {
                        members,
                        ..Default::default()
                    },
                );
                let read = self.session.supertypes_for_definitions(&[target])?;
                let rows = match read {
                    SessionFactRead::Exhausted { rows, evidence, .. } => {
                        let identity = hierarchy_support_read_identity(
                            self.session,
                            self.hierarchy,
                            b"base-preservation-supertypes",
                            &[target],
                        )?;
                        self.observe_hierarchy_support_completion(identity, &evidence);
                        if evidence != ResolutionCompletion::Complete {
                            rejected = true;
                            break;
                        }
                        rows
                    }
                    SessionFactRead::Cancelled(evidence) => {
                        self.observe_cancelled_hierarchy_support_completion(&evidence);
                        return Ok(None);
                    }
                };
                let mut rows = rows;
                rows.sort_by_key(|row| row.get(self.session).row().parent_ordinal());
                if rows.len() != inputs.written_base_count as usize {
                    rejected = true;
                    break;
                }
                for row in rows {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(None);
                    }
                    let row = row.get(self.session).row();
                    let resolved = match row.target() {
                        super::super::LoweredSupertypeTarget::ResolvedIdentity(target) => {
                            Some(*target)
                        }
                        _ => None,
                    };
                    cursor.pending.push_back(GuardOperand {
                        container: Some(target),
                        reference: row.reference(),
                        target: resolved,
                        relation: GuardRelation::Base,
                    });
                }
                if inputs.written_base_count == 0
                    && let Some(root) = inputs.root_object
                {
                    cursor.pending.push_back(GuardOperand {
                        container: Some(target),
                        reference: root.occurrence,
                        target: Some(root.identity),
                        relation: GuardRelation::Base,
                    });
                }
                if let Some(guard) = inputs.base_preservation {
                    if guard.completion != ResolutionCompletion::Complete
                        || guard.terminal != cursor.rule.terminal
                    {
                        rejected = true;
                        break;
                    }
                    for reference in guard.references {
                        if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                            self.cancellation_observed = true;
                            return Ok(None);
                        }
                        cursor.pending.push_back(GuardOperand {
                            container: Some(target),
                            reference,
                            target: None,
                            relation: GuardRelation::Guard,
                        });
                    }
                }
            }
            if !rejected {
                rejected = !self.finish_base_preservation_guard(
                    &mut cursor,
                    edge_provider.base_preservation_order(),
                )?;
            }
            if self.poll_cancelled() || self.cancellation_observed {
                return Ok(None);
            }
            self.hierarchy.base_guard_proofs.insert(
                proof_key,
                ClosedQueryValue::new(
                    BasePreservationProof {
                        admitted: !rejected,
                        observations: cursor.observations,
                    },
                    self.query_obligations.scope(QueryNode::Hierarchy(subject)),
                ),
            );
        }
        Ok(Some(Vec::new()))
    }

    /// A stopped or unfinished proof never admits a caller's narrower question.
    pub(super) fn base_preservation_proven(
        &mut self,
        owner: SemanticId,
        rule: crate::analyzer::resolution::BasePreservationRule,
    ) -> bool {
        if self.poll_cancelled() || self.cancellation_observed {
            return false;
        }
        self.hierarchy
            .base_guard_proofs
            .get(&BaseGuardKey {
                owner: HierarchyOwnerKey {
                    owner,
                    policy: self.hierarchy_policy,
                },
                rule,
            })
            .is_some_and(|proof| {
                proof
                    .read(&mut self.query_obligations.node(QueryNode::Hierarchy(owner)))
                    .admitted
            })
    }

    fn finish_base_preservation_guard(
        &mut self,
        cursor: &mut BaseGuardCursor,
        policy: Option<&'static dyn HierarchyLinearizationPolicy>,
    ) -> StoreResult<bool> {
        let Some(policy) = policy else {
            return Ok(false);
        };
        if cursor.unknown_terminal_mutation {
            return Ok(false);
        }
        // Metaclass dependencies must be well-founded independently of base MROs.
        let mut remaining = HashMap::default();
        let mut parents = HashMap::<SemanticId, Vec<SemanticId>>::default();
        let mut ready = VecDeque::new();
        for (&owner, node) in &cursor.nodes {
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                self.cancellation_observed = true;
                return Ok(false);
            }
            let mut count = 0usize;
            for &base in node.bases.iter().chain(&node.guards) {
                if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                    self.cancellation_observed = true;
                    return Ok(false);
                }
                if base != cursor.terminal {
                    parents.entry(base).or_default().push(owner);
                    count += 1;
                }
            }
            remaining.insert(owner, count);
            if count == 0 {
                ready.push_back(owner);
            }
        }
        let mut completed = Vec::new();
        while let Some(owner) = ready.pop_front() {
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                self.cancellation_observed = true;
                return Ok(false);
            }
            completed.push(owner);
            for parent in parents.get(&owner).into_iter().flatten() {
                let count = remaining.get_mut(parent).expect("guard dependency");
                *count -= 1;
                if *count == 0 {
                    ready.push_back(*parent);
                }
            }
        }
        if completed.len() != cursor.nodes.len() {
            return Ok(false);
        }
        struct GuardSource<'a> {
            cursor: &'a BaseGuardCursor,
        }
        impl SupertypeSource<SemanticId> for GuardSource<'_> {
            fn bases(&mut self, owner: &SemanticId) -> Option<Vec<SemanticId>> {
                if *owner == self.cursor.terminal {
                    Some(Vec::new())
                } else {
                    self.cursor.nodes.get(owner).map(|node| node.bases.clone())
                }
            }
        }
        let mut roots = cursor.roots.clone();
        roots.extend(
            cursor
                .mutation_targets
                .iter()
                .filter(|owner| cursor.nodes.contains_key(owner))
                .copied(),
        );
        for node in cursor.nodes.values() {
            roots.extend(&node.guards);
        }
        roots.sort_unstable();
        roots.dedup();
        let mut orders = HashMap::from_iter([(cursor.terminal, vec![cursor.terminal])]);
        for root in roots {
            let mut source = GuardSource { cursor };
            let mut stopped = false;
            let result = super::hierarchy_linearize::linearize_with_budget(
                &root,
                &mut source,
                policy,
                &mut || {
                    let step =
                        !self.cancellation.is_cancelled() && self.session.charge_scope_steps(1);
                    stopped |= !step;
                    step
                },
            );
            if stopped {
                self.cancellation_observed = true;
            }
            let Ok(order) = result else {
                return Ok(false);
            };
            orders.insert(root, order);
        }
        // Inherited conditional providers must select one most-derived owner.
        let mut effective = HashMap::from_iter([(cursor.terminal, cursor.terminal)]);
        for owner in completed {
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                self.cancellation_observed = true;
                return Ok(false);
            }
            let node = &cursor.nodes[&owner];
            let mut candidates = node.guards.clone();
            candidates.extend(node.bases.iter().map(|base| effective[base]));
            candidates.sort_unstable();
            candidates.dedup();
            if candidates.is_empty() {
                candidates.push(cursor.terminal);
            }
            let mut selected = None;
            for &candidate in &candidates {
                let mut dominates = true;
                for other in &candidates {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(false);
                    }
                    if !orders
                        .get(&candidate)
                        .is_some_and(|order| order.contains(other))
                    {
                        dominates = false;
                        break;
                    }
                }
                if dominates {
                    selected = Some(candidate);
                    break;
                }
            }
            let Some(selected) = selected else {
                return Ok(false);
            };
            effective.insert(owner, selected);
        }
        // A receiver declaration is disjoint only after its class-object
        // creation proof too; a factory result or replacing metaclass is unknown.
        let mut requirements = HashMap::<SemanticId, HashSet<&'static str>>::default();
        let mut pending = VecDeque::new();
        for &subject in cursor.roots.iter().chain(
            cursor
                .mutation_targets
                .iter()
                .filter(|owner| cursor.nodes.contains_key(owner)),
        ) {
            pending.push_back((effective[&subject], cursor.rule.absent_members));
        }
        while let Some((provider, members)) = pending.pop_front() {
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                self.cancellation_observed = true;
                return Ok(false);
            }
            if provider == cursor.terminal {
                continue;
            }
            let Some(order) = orders.get(&provider) else {
                return Ok(false);
            };
            if !order.contains(&cursor.terminal) {
                return Ok(false);
            }
            // Use the shared MRO's prefix, not each base's independent MRO:
            // the terminal and every owner after it are outside this guard.
            for &owner in order.iter().take_while(|owner| **owner != cursor.terminal) {
                if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                    self.cancellation_observed = true;
                    return Ok(false);
                }
                let required = requirements.entry(owner).or_default();
                let prior = required.len();
                required.extend(members);
                if required.len() == prior {
                    continue;
                }
                let node = &cursor.nodes[&owner];
                let Some(inventory) = &node.members else {
                    return Ok(false);
                };
                if !inventory.complete
                    || cursor.unknown_mutation
                    || cursor.mutated_owners.contains(&owner)
                {
                    return Ok(false);
                }
                for name in &inventory.names {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(false);
                    }
                    if required.contains(name.as_str()) {
                        return Ok(false);
                    }
                }
                let header = cursor
                    .observations
                    .iter()
                    .find(|observation| observation.provider.owner == owner)
                    .expect("guard header observation");
                cursor.observations.push(HierarchyProviderObservation {
                    provider: header
                        .provider
                        .with_operand(HierarchyProviderOperand::NamespaceInventory),
                    visit: HierarchyProviderVisit::Observed,
                    completion: ResolutionCompletion::Complete,
                    inventory_complete: Some(true),
                });
                pending.push_back((effective[&owner], cursor.rule.enclosing_absent_members));
            }
        }
        Ok(true)
    }
}
