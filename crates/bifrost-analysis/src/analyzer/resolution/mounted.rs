//! One mounted view of an unmounted blob interior.
//!
//! An interior is produced once per content, under
//! [`BindingFragmentId::unmounted`], and shared by every selection that mounts
//! that content: the cache key is the mount's content digest, and its pages
//! are `Arc`-shared, so a cache read is a pointer clone. What the engine holds
//! is a mounted identity, `(mount ordinal, catalog position)`, and what the
//! interior holds is the same catalog position under the unmounted ordinal.
//! The difference is the mount's ordinal and nothing else.
//!
//! [`Mounted`] is where that difference is applied. It is a forwarding
//! decorator over an unmounted source, implementing both reader traits, and
//! every one of its sixty methods splices the identities that cross it:
//! arguments from the mount's ordinal to the unmounted one, results from the
//! unmounted one back to the mount's. The count of identities one seam call
//! carries is bounded by the call, where the count in a page is not, which is
//! why the splice is here and not over a whole cached page.
//!
//! The two directions are two translations, [`IntoInterior`] and
//! [`OutOfInterior`], and the deep walks they drive are the ones `remount.rs`
//! already writes for a catalog remount. A splice is a remount whose
//! translation is arithmetic instead of a map lookup, so the walks over paths,
//! completions and typed rows are written once and take either.

use std::sync::OnceLock;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::CancellationToken;
use crate::analyzer::store::Result as StoreResult;
use crate::analyzer::store::StoreError;
use crate::hash::HashSet;

use super::batch::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification, BatchReferenceSeed,
    BatchResolutionFragmentSource, CandidatePathIdentity, ReferenceSeed, ReferenceSeedBatch,
    ReferenceSeedReadOutcome, ReverseCandidateGapExclusionPlan, ReverseReferenceSeedRequest,
};
use super::common_fact_lowering::LoweredDeferredMemberOwner;
use super::engine::ResolutionQuery;
use super::fact_source::{
    DeclarationAccessDecision, DeferredMemberOwnerLookupName, FactPageVisitor, FactReadOutcome,
    LoweredRustDeclarationAuthority, LoweredRustReferenceContext, QualifiedRouteSlotLookup,
    RustImplementedTraits, SelectedGapReasonProvenance, SelectedQualifiedRoute,
    SelectedTypeFrontierCompletion, SelectedTypedFactSource, SelectedTypedRow,
    TypedFactPageVisitor, TypedFactReadOutcome, TypedFactRequest,
};
use super::local_identity::{ResolutionIdentityTranslation, SelectedResolutionMountOrdinal};
use super::model::{
    BindingFragmentId, BindingNodeId, PartialPath, PartialPathId, ResolutionCompletion,
    ResolutionIdentityKind, ResolutionIncompleteReason, SemanticId, StackVariableId,
    TypeTransferRule, UNMOUNTED_ORDINAL,
};
use super::remount::{
    remount_binding_projection, remount_call_obligation, remount_callable_signature,
    remount_completion, remount_construction_requirement, remount_declaration_type,
    remount_declaration_visibility, remount_deferred_member_owner, remount_definition_property_gap,
    remount_endpoint, remount_intrinsic_seed, remount_member_owner, remount_member_scope,
    remount_path, remount_site_metadata, remount_supertype, remount_transfer,
    remount_type_transfer_rule, remount_typed_frontier,
};
use super::typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDefinitionPropertyGap, LoweredIntrinsicSeed,
    LoweredMemberOwnerProperty, LoweredMemberScopeProperty, LoweredQualifiedSeededRoute,
    LoweredSupertypeProperty, LoweredTypeComponent, LoweredTypeTransfer, LoweredTypedFrontier,
    LoweredUnderlyingType,
};

/// The token every splice walk runs under.
///
/// A splice translates the identities of one seam call, and a seam call's
/// identities are bounded by the call: one page of rows, one request batch,
/// one path. There is no interruption point inside work that small, and a
/// splice that stopped halfway would hand the engine a value with some of its
/// identities at one ordinal and the rest at another, which is worse than
/// finishing. The walks it reuses take a token because a whole-artifact
/// remount needs one.
fn uncancelled() -> &'static CancellationToken {
    static UNCANCELLED: OnceLock<CancellationToken> = OnceLock::new();
    UNCANCELLED.get_or_init(CancellationToken::default)
}

/// One of the four runtime identities, for the two arithmetic translations
/// below. Each is the same `u64` layout, so the splice is written once.
trait MountedIdentity: Copy {
    fn kind(self) -> ResolutionIdentityKind;
    fn operation_local(number: u64) -> Self;
    fn ordinal(self) -> Option<u32>;
    fn local_key(self) -> Option<u32>;
    fn local(ordinal: u32, local_key: u32) -> Self;
}

macro_rules! mounted_identity {
    ($name:ident) => {
        impl MountedIdentity for $name {
            fn kind(self) -> ResolutionIdentityKind {
                $name::kind(self)
            }

            fn ordinal(self) -> Option<u32> {
                $name::ordinal(self)
            }

            fn local_key(self) -> Option<u32> {
                $name::local_key(self)
            }

            fn local(ordinal: u32, local_key: u32) -> Self {
                $name::local(ordinal, local_key)
            }

            fn operation_local(number: u64) -> Self {
                $name::operation_local(number)
            }
        }
    };
}

mounted_identity!(SemanticId);
mounted_identity!(BindingNodeId);
mounted_identity!(PartialPathId);
mounted_identity!(StackVariableId);

/// The engine's identity as the interior holds it.
///
/// Only this mount's own identities are rewritten. An identity that belongs to
/// no file -- a shared name, a number the operation or the context minted, the
/// universal root -- means the same thing on both sides of the seam and is
/// carried through. An identity of *another* mount is left alone: the interior
/// has no entry at that ordinal, so the question answers negatively, which is
/// exactly what it answered when a mounted identity carried its mount's digest
/// as a prefix. Rewriting it would attribute another blob's key to this one.
#[derive(Debug, Clone, Copy)]
struct IntoInterior {
    ordinal: u32,
}

/// The interior's identity as the engine holds it.
///
/// An interior is produced unmounted, so every local identity it hands back
/// carries [`UNMOUNTED_ORDINAL`] and nothing else may. The assertion is the
/// check that the interior really was produced unmounted; without it an
/// interior produced under some other ordinal would hand the engine identities
/// attributed to the wrong blob and nothing would say so.
#[derive(Debug, Clone, Copy)]
struct OutOfInterior {
    ordinal: u32,
}

impl IntoInterior {
    fn map<T: MountedIdentity + std::fmt::Display>(&self, identity: T) -> T {
        match identity.kind() {
            ResolutionIdentityKind::Local if identity.ordinal() == Some(self.ordinal) => T::local(
                UNMOUNTED_ORDINAL,
                identity.local_key().expect("a local identity has a key"),
            ),
            _ => identity,
        }
    }
}

impl OutOfInterior {
    fn map<T: MountedIdentity + std::fmt::Display>(&self, identity: T) -> T {
        match identity.kind() {
            ResolutionIdentityKind::Local => {
                assert_eq!(
                    identity.ordinal(),
                    Some(UNMOUNTED_ORDINAL),
                    "an interior is produced unmounted, so every local identity it hands \
                     back is unmounted: {identity}"
                );
                T::local(
                    self.ordinal,
                    identity.local_key().expect("a local identity has a key"),
                )
            }
            _ => identity,
        }
    }
}

macro_rules! splice_translation {
    ($name:ident) => {
        impl ResolutionIdentityTranslation for $name {
            fn semantic(&self, semantic: SemanticId) -> SemanticId {
                self.map(semantic)
            }

            fn node(&self, node: BindingNodeId) -> BindingNodeId {
                self.map(node)
            }

            fn path(&self, path: PartialPathId) -> PartialPathId {
                self.map(path)
            }

            fn stack_variable(&self, variable: StackVariableId) -> StackVariableId {
                self.map(variable)
            }

            fn fragment(&self, fragment: BindingFragmentId) -> BindingFragmentId {
                self.fragment_of(fragment)
            }

            /// A reason an operation minted crosses the seam like any other
            /// value: the identity inside it is spliced and the reason keeps
            /// its kind.
            fn operation_local_reason(
                &self,
                reason: &ResolutionIncompleteReason,
            ) -> ResolutionIncompleteReason {
                match reason {
                    ResolutionIncompleteReason::CyclicPrefixDependency(semantic) => {
                        ResolutionIncompleteReason::CyclicPrefixDependency(self.map(*semantic))
                    }
                    ResolutionIncompleteReason::ReceiverBudgetExhausted(semantic) => {
                        ResolutionIncompleteReason::ReceiverBudgetExhausted(self.map(*semantic))
                    }
                    ResolutionIncompleteReason::TimeBudgetExceeded(semantic) => {
                        ResolutionIncompleteReason::TimeBudgetExceeded(self.map(*semantic))
                    }
                    ResolutionIncompleteReason::UnmountedFile { fragment } => {
                        ResolutionIncompleteReason::UnmountedFile {
                            fragment: self.fragment_of(*fragment),
                        }
                    }
                    other => panic!("only an operation-local reason reaches this arm: {other:?}"),
                }
            }
        }
    };
}

impl IntoInterior {
    fn fragment_of(&self, fragment: BindingFragmentId) -> BindingFragmentId {
        if fragment.ordinal() == self.ordinal {
            BindingFragmentId::unmounted()
        } else {
            fragment
        }
    }
}

impl OutOfInterior {
    fn fragment_of(&self, fragment: BindingFragmentId) -> BindingFragmentId {
        assert_eq!(
            fragment.ordinal(),
            UNMOUNTED_ORDINAL,
            "an interior is produced unmounted, so every fragment it names is \
             unmounted: {fragment}"
        );
        BindingFragmentId::at_ordinal(self.ordinal)
    }
}

splice_translation!(IntoInterior);
splice_translation!(OutOfInterior);

/// One value as it compares across two operations.
///
/// An `Operation` identity is a number the operation that minted it gave to a
/// structure it met, so it means nothing outside that operation: two
/// operations meeting the same structures in a different order give them
/// different numbers. A `Local` identity is its mount and its catalog
/// position, a `Shared` name is an interned id, and both mean the same thing
/// in every operation. So a comparison that crosses two operations compares
/// the first as its kind alone and the other two as themselves.
///
/// It is a translation, so it reaches every value the remount walks reach --
/// a completion's reasons, a path's precedence, a typed row -- through the
/// same [`SpliceMount`] the mount seam uses.
#[cfg(any(test, feature = "test-support"))]
pub(crate) struct OperationBlind;

#[cfg(any(test, feature = "test-support"))]
impl OperationBlind {
    fn map<T: MountedIdentity>(&self, identity: T) -> T {
        match identity.kind() {
            ResolutionIdentityKind::Operation => T::operation_local(0),
            _ => identity,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ResolutionIdentityTranslation for OperationBlind {
    fn fragment(&self, fragment: BindingFragmentId) -> BindingFragmentId {
        fragment
    }

    fn semantic(&self, semantic: SemanticId) -> SemanticId {
        self.map(semantic)
    }

    fn node(&self, node: BindingNodeId) -> BindingNodeId {
        self.map(node)
    }

    fn path(&self, path: PartialPathId) -> PartialPathId {
        self.map(path)
    }

    fn stack_variable(&self, variable: StackVariableId) -> StackVariableId {
        self.map(variable)
    }

    fn operation_local_reason(
        &self,
        reason: &ResolutionIncompleteReason,
    ) -> ResolutionIncompleteReason {
        match reason {
            ResolutionIncompleteReason::CyclicPrefixDependency(semantic) => {
                ResolutionIncompleteReason::CyclicPrefixDependency(self.map(*semantic))
            }
            ResolutionIncompleteReason::ReceiverBudgetExhausted(semantic) => {
                ResolutionIncompleteReason::ReceiverBudgetExhausted(self.map(*semantic))
            }
            ResolutionIncompleteReason::TimeBudgetExceeded(semantic) => {
                ResolutionIncompleteReason::TimeBudgetExceeded(self.map(*semantic))
            }
            other => *other,
        }
    }
}

/// One value that crosses the mount seam, in either direction.
///
/// Every implementation is total over the value's identities: a field this
/// trait forgets is a field the engine reads at the wrong ordinal, so each
/// implementation names every field it carries.
pub(crate) trait SpliceMount: Sized {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self;
}

macro_rules! splice_identity {
    ($name:ident, $method:ident) => {
        impl SpliceMount for $name {
            fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
                translation.$method(*self)
            }
        }
    };
}

splice_identity!(SemanticId, semantic);
splice_identity!(BindingNodeId, node);
splice_identity!(PartialPathId, path);
splice_identity!(StackVariableId, stack_variable);

impl SpliceMount for BindingFragmentId {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        translation.fragment(*self)
    }
}

/// One value the engine holds, as the mount's unmounted interior holds it.
///
/// This is the accessor half of the same splice [`Mounted`] applies to the
/// reader seam: `SelectedResolutionAuthority` answers about twenty questions
/// by hand rather than through a trait, and each one splices what it passes
/// down and what it hands back.
pub(crate) fn into_interior<V: SpliceMount>(value: &V, mount: SelectedResolutionMountOrdinal) -> V {
    value.splice(&IntoInterior {
        ordinal: mount.get(),
    })
}

/// One value an unmounted interior handed back, as the engine holds it.
pub(crate) fn out_of_interior<V: SpliceMount>(
    value: &V,
    mount: SelectedResolutionMountOrdinal,
) -> V {
    value.splice(&OutOfInterior {
        ordinal: mount.get(),
    })
}

/// A value whose type carries no runtime identity at all, so a splice of it is
/// itself. Naming them is what keeps a tuple or a row that mixes the two kinds
/// spliceable without a hand-written arm per shape.
macro_rules! splice_is_identity {
    ($($name:ty),* $(,)?) => {
        $(
            impl SpliceMount for $name {
                fn splice<T: ResolutionIdentityTranslation>(&self, _translation: &T) -> Self {
                    self.clone()
                }
            }
        )*
    };
}

splice_is_identity!(
    brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
    brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
    usize,
    i64,
    String,
);

impl<A: SpliceMount, B: SpliceMount, C: SpliceMount> SpliceMount for (A, B, C) {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        (
            self.0.splice(translation),
            self.1.splice(translation),
            self.2.splice(translation),
        )
    }
}

impl<V: SpliceMount> SpliceMount for Option<V> {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        self.as_ref().map(|value| value.splice(translation))
    }
}

impl<V: SpliceMount> SpliceMount for Vec<V> {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        self.iter().map(|value| value.splice(translation)).collect()
    }
}

impl<A: SpliceMount, B: SpliceMount> SpliceMount for (A, B) {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        (self.0.splice(translation), self.1.splice(translation))
    }
}

impl SpliceMount for ResolutionCompletion {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        remount_completion(self, translation, uncancelled())
            .expect("a mount splice runs under an uncancelled token")
    }
}

impl SpliceMount for PartialPath {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        remount_path(self, translation, uncancelled())
            .expect("a mount splice runs under an uncancelled token")
    }
}

impl SpliceMount for ResolutionQuery {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        ResolutionQuery::new(translation.semantic(self.reference()))
    }
}

impl SpliceMount for CandidatePathIdentity {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        CandidatePathIdentity::new(
            translation.fragment(self.fragment()),
            translation.path(self.path()),
        )
    }
}

impl SpliceMount for BatchCandidateMatch {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        BatchCandidateMatch::new(self.candidate().splice(translation), self.request_ordinal())
    }
}

impl SpliceMount for BatchCandidateRequest {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        BatchCandidateRequest::new(
            self.request_ordinal(),
            remount_endpoint(self.endpoint(), translation, uncancelled())
                .expect("a mount splice runs under an uncancelled token"),
        )
    }
}

impl SpliceMount for BatchCandidateCompletionOutcome {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        BatchCandidateCompletionOutcome::new(
            self.branch_completions().len(),
            self.unconditional_completion().splice(translation),
            self.branch_completions()
                .iter()
                .map(|completion| completion.splice(translation)),
        )
    }
}

impl SpliceMount for BatchCandidateOutcome {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        BatchCandidateOutcome::new(
            self.branch_completions().len(),
            self.matches()
                .iter()
                .map(|row| row.splice(translation))
                .collect(),
            self.unconditional_completion().splice(translation),
            self.branch_completions()
                .iter()
                .map(|completion| completion.splice(translation)),
        )
    }
}

impl SpliceMount for BatchDefinitionNode {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        BatchDefinitionNode::new(
            translation.semantic(self.definition()),
            self.node().map(|node| translation.node(node)),
        )
    }
}

impl SpliceMount for BatchEndpointClassification {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        BatchEndpointClassification::new_with_member_scope_owner(
            translation.node(self.node()),
            self.reference().map(|id| translation.semantic(id)),
            self.definition().map(|id| translation.semantic(id)),
            self.member_scope_owner().map(|id| translation.semantic(id)),
        )
        .with_go_definition_namespaces(self.go_definition_namespaces())
    }
}

impl SpliceMount for ReverseReferenceSeedRequest {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        ReverseReferenceSeedRequest::new(
            translation.semantic(self.reference()),
            translation.node(self.expected_node()),
        )
    }
}

impl SpliceMount for ReferenceSeed {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        ReferenceSeed::new_with_site_metadata(
            translation.fragment(self.fragment()),
            self.query().splice(translation),
            translation.node(self.node()),
            self.site_metadata()
                .map(|metadata| remount_site_metadata(metadata, translation)),
            self.completion().splice(translation),
        )
    }
}

impl SpliceMount for BatchReferenceSeed {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        BatchReferenceSeed::new(
            self.request_ordinal(),
            self.query().splice(translation),
            self.seed().map(|seed| seed.splice(translation)),
        )
    }
}

impl SpliceMount for ReferenceSeedReadOutcome {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        if self.is_exhausted() {
            ReferenceSeedReadOutcome::exhausted(
                self.rows()
                    .iter()
                    .map(|row| row.splice(translation))
                    .collect::<Vec<_>>(),
            )
        } else {
            ReferenceSeedReadOutcome::cancelled(self.evidence().splice(translation))
        }
    }
}

impl SpliceMount for ReferenceSeedBatch {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        ReferenceSeedBatch::new(self.seeds().iter().map(|seed| seed.splice(translation)))
    }
}

impl SpliceMount for TypeTransferRule {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        remount_type_transfer_rule(self, translation, uncancelled())
            .expect("a mount splice runs under an uncancelled token")
    }
}

impl SpliceMount for TypedFactReadOutcome {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        let evidence = self.evidence().splice(translation);
        match self.terminal() {
            super::fact_source::TypedFactReadTerminal::Exhausted => {
                TypedFactReadOutcome::exhausted(evidence)
            }
            super::fact_source::TypedFactReadTerminal::Stopped => {
                TypedFactReadOutcome::stopped(evidence)
            }
            super::fact_source::TypedFactReadTerminal::Cancelled => {
                TypedFactReadOutcome::cancelled(evidence)
            }
        }
    }
}

impl SpliceMount for QualifiedRouteSlotLookup {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        QualifiedRouteSlotLookup::new(
            translation.semantic(self.qualifier_slot()),
            translation.semantic(self.lookup()),
        )
    }
}

impl SpliceMount for DeferredMemberOwnerLookupName {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        DeferredMemberOwnerLookupName::new(translation.semantic(self.lookup()))
    }
}

impl SpliceMount for SelectedQualifiedRoute {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        let row = self.row();
        SelectedQualifiedRoute::new(
            translation.fragment(self.fragment()),
            translation.node(self.reference_node()),
            LoweredQualifiedSeededRoute::new_with_source_lookup(
                translation.semantic(row.reference()),
                translation.semantic(row.qualifier_slot()),
                translation.semantic(row.lookup()),
                row.namespace(),
                translation.semantic(row.source_lookup()),
                row.precedence_ordinal(),
                translation.semantic(row.projection_output_slot()),
                row.projection_kind(),
                translation.semantic(row.coarse_gap_reason()),
                row.open_member_surface(),
            ),
        )
    }
}

impl SpliceMount for SelectedGapReasonProvenance {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        SelectedGapReasonProvenance::new(
            translation.fragment(self.fragment()),
            translation.semantic(self.reason()),
            self.source_site(),
            self.origin(),
        )
    }
}

impl SpliceMount for SelectedTypeFrontierCompletion {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        SelectedTypeFrontierCompletion::new(
            translation.fragment(self.fragment()),
            translation.semantic(self.frontier()),
            self.completion().splice(translation),
        )
    }
}

impl SpliceMount for LoweredRustReferenceContext {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        LoweredRustReferenceContext::new(
            translation.semantic(self.reference()),
            self.source_site(),
            self.source_occurrence(),
            self.module_context(),
            self.module_declaration(),
        )
        .with_cfg_condition(self.cfg_condition().clone())
    }
}

impl SpliceMount for LoweredRustDeclarationAuthority {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        LoweredRustDeclarationAuthority::new(
            translation.semantic(self.definition()),
            self.source_site(),
            self.declaration(),
            self.visibility().cloned(),
            self.module_context(),
            self.module_declaration(),
        )
        .with_cfg_condition(self.cfg_condition().clone())
        .with_activation_reason(
            self.activation_reason()
                .map(|reason| translation.semantic(reason)),
        )
    }
}

macro_rules! splice_lowered_row {
    ($name:ty, $helper:ident) => {
        impl SpliceMount for $name {
            fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
                $helper(self, translation)
            }
        }
    };
    ($name:ty, $helper:ident, cancellable) => {
        impl SpliceMount for $name {
            fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
                $helper(self, translation, uncancelled())
                    .expect("a mount splice runs under an uncancelled token")
            }
        }
    };
}

splice_lowered_row!(LoweredTypedFrontier, remount_typed_frontier);
splice_lowered_row!(LoweredBindingProjection, remount_binding_projection);
splice_lowered_row!(LoweredDeclarationTypeProperty, remount_declaration_type);
splice_lowered_row!(
    LoweredDeclarationVisibilityProperty,
    remount_declaration_visibility
);
splice_lowered_row!(LoweredMemberScopeProperty, remount_member_scope);
splice_lowered_row!(LoweredMemberOwnerProperty, remount_member_owner);
splice_lowered_row!(
    LoweredConstructionRequirementProperty,
    remount_construction_requirement
);
splice_lowered_row!(LoweredSupertypeProperty, remount_supertype);
splice_lowered_row!(
    LoweredDefinitionPropertyGap,
    remount_definition_property_gap
);
splice_lowered_row!(LoweredIntrinsicSeed, remount_intrinsic_seed, cancellable);
splice_lowered_row!(LoweredTypeTransfer, remount_transfer, cancellable);
impl SpliceMount for LoweredTypeComponent {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        LoweredTypeComponent::new(
            translation.semantic(self.container()),
            self.constructor(),
            self.kind(),
            translation.semantic(self.component()),
        )
    }
}

impl SpliceMount for LoweredUnderlyingType {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        LoweredUnderlyingType::new(
            translation.semantic(self.definition()),
            translation.semantic(self.slot()),
        )
    }
}
splice_lowered_row!(
    LoweredCallApplicabilityObligation,
    remount_call_obligation,
    cancellable
);
splice_lowered_row!(
    LoweredCallableSignatureProperty,
    remount_callable_signature,
    cancellable
);

impl SpliceMount for LoweredDeferredMemberOwner {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        remount_deferred_member_owner(*self, translation)
    }
}

impl<R: SpliceMount> SpliceMount for SelectedTypedRow<R> {
    fn splice<T: ResolutionIdentityTranslation>(&self, translation: &T) -> Self {
        SelectedTypedRow::new(
            translation.fragment(self.fragment()),
            self.row().splice(translation),
        )
    }
}

/// One mounted reader over an unmounted interior source.
///
/// The ordinal is the only state. Everything else is forwarding. `S` is a
/// pointer to the source rather than the source itself, because what a mount
/// has in hand is the `Arc` the interior cache's page holds: wrapping one
/// costs the ordinal beside the pointer and nothing else.
pub(crate) struct Mounted<S> {
    inner: S,
    ordinal: u32,
}

impl<S> Mounted<S> {
    pub(crate) fn at(inner: S, mount: SelectedResolutionMountOrdinal) -> Self {
        Self {
            inner,
            ordinal: mount.get(),
        }
    }

    pub(crate) const fn mount(&self) -> u32 {
        self.ordinal
    }

    pub(crate) const fn inner(&self) -> &S {
        &self.inner
    }

    const fn interior_translation(&self) -> IntoInterior {
        IntoInterior {
            ordinal: self.ordinal,
        }
    }

    const fn engine_translation(&self) -> OutOfInterior {
        OutOfInterior {
            ordinal: self.ordinal,
        }
    }

    /// One batch of arguments, as the interior holds them.
    fn arguments<V: SpliceMount>(&self, values: &[V]) -> Vec<V> {
        let translation = self.interior_translation();
        values
            .iter()
            .map(|value| value.splice(&translation))
            .collect()
    }

    /// One batch of results, as the engine holds them.
    fn results<V: SpliceMount>(&self, values: &[V]) -> Vec<V> {
        let translation = self.engine_translation();
        values
            .iter()
            .map(|value| value.splice(&translation))
            .collect()
    }

    fn result<V: SpliceMount>(&self, value: &V) -> V {
        value.splice(&self.engine_translation())
    }

    fn argument<V: SpliceMount>(&self, value: &V) -> V {
        value.splice(&self.interior_translation())
    }
}

/// A batch method whose arguments and results are both slices of spliceable
/// values.
macro_rules! spliced_batch {
    ($method:ident ( $argument:ident : &[$argument_type:ty] ) -> $return:ty) => {
        fn $method(
            &self,
            $argument: &[$argument_type],
            cancellation: &CancellationToken,
        ) -> StoreResult<$return> {
            let $argument = self.arguments($argument);
            let outcome = self.inner.$method(&$argument, cancellation)?;
            Ok(self.result(&outcome))
        }
    };
}

/// A method that streams `&[BatchCandidateMatch]` pages through a closure.
macro_rules! spliced_candidate_pages {
    ($method:ident $(, $extra:ident : $extra_type:ty)*) => {
        fn $method(
            &self,
            requests: &[BatchCandidateRequest],
            $($extra: $extra_type,)*
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            let requests = self.arguments(requests);
            let mut splicing = |page: &[BatchCandidateMatch]| visitor(&self.results(page));
            let outcome = self
                .inner
                .$method(&requests, $($extra,)* cancellation, &mut splicing)?;
            Ok(self.result(&outcome))
        }
    };
}

impl<S> BatchResolutionFragmentSource for Mounted<S>
where
    S: std::ops::Deref,
    S::Target: BatchResolutionFragmentSource,
{
    /// The authority names a selection, not an identity, so there is nothing
    /// for this decorator to rebase: the inner source's answer is this one.
    fn selection_authority(&self) -> Option<super::batch::SeedReadAuthority> {
        self.inner.selection_authority()
    }

    fn admits_reverse_reference(&self, reference: SemanticId) -> bool {
        self.inner
            .admits_reverse_reference(self.argument(&reference))
    }

    fn scope_reverse_inventory_completion(
        &self,
        completion: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        let completion = self.argument(completion);
        self.result(&self.inner.scope_reverse_inventory_completion(&completion))
    }

    fn go_lookup_spelling(
        &self,
        reference: SemanticId,
        namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<String>> {
        self.inner
            .go_lookup_spelling(self.argument(&reference), namespace, cancellation)
    }

    fn intern_shared_name_digest(
        &self,
        digest: [u8; 32],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        Ok(self
            .inner
            .intern_shared_name_digest(digest, cancellation)?
            .map(|name| self.result(&name)))
    }

    fn supports_go_universe(&self) -> bool {
        self.inner.supports_go_universe()
    }

    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>> {
        let query = self.argument(&query);
        Ok(self
            .inner
            .reference_seed(query, cancellation)?
            .map(|seed| self.result(&seed)))
    }

    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        let queries = self.arguments(queries);
        let outcome = self.inner.lookup_reference_seeds(&queries, cancellation)?;
        Ok(self.result(&outcome))
    }

    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        let definition = self.argument(&definition);
        Ok(self
            .inner
            .lookup_definition_node(definition, cancellation)?
            .map(|node| self.result(&node)))
    }

    spliced_batch!(lookup_definition_nodes(definitions: &[SemanticId]) -> Vec<BatchDefinitionNode>);

    spliced_batch!(
        issue_reverse_reference_seeds(requests: &[ReverseReferenceSeedRequest])
            -> Vec<ReferenceSeed>
    );

    spliced_batch!(
        classify_endpoint_nodes(nodes: &[BindingNodeId]) -> Vec<BatchEndpointClassification>
    );

    spliced_batch!(
        match_forward_candidates(requests: &[BatchCandidateRequest]) -> BatchCandidateOutcome
    );

    spliced_batch!(
        match_reverse_candidates(requests: &[BatchCandidateRequest]) -> BatchCandidateOutcome
    );

    spliced_batch!(
        hydrate_candidate_paths(candidates: &[CandidatePathIdentity])
            -> Vec<(CandidatePathIdentity, PartialPath)>
    );

    fn visit_reference_seed_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        let mut splicing = |batch: &ReferenceSeedBatch| visitor(&self.result(batch));
        let completion = self.inner.visit_reference_seed_batches(
            maximum_batch_size,
            cancellation,
            &mut splicing,
        )?;
        Ok(self.result(&completion))
    }

    fn visit_reference_seed_batches_in_fragments(
        &self,
        fragments: &HashSet<BindingFragmentId>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        let fragments = fragments
            .iter()
            .map(|fragment| self.argument(fragment))
            .collect::<HashSet<_>>();
        let mut splicing = |batch: &ReferenceSeedBatch| visitor(&self.result(batch));
        let completion = self.inner.visit_reference_seed_batches_in_fragments(
            &fragments,
            maximum_batch_size,
            cancellation,
            &mut splicing,
        )?;
        Ok(self.result(&completion))
    }

    spliced_candidate_pages!(visit_forward_candidate_match_pages);

    spliced_candidate_pages!(
        visit_forward_root_candidate_match_pages,
        mounts: Option<&[SelectedResolutionMountOrdinal]>
    );

    spliced_candidate_pages!(
        visit_forward_candidate_match_pages_limited,
        maximum_page_rows: usize,
        resolution_session: Option<&ResolutionSession>
    );

    spliced_candidate_pages!(visit_reverse_candidate_match_pages);

    spliced_candidate_pages!(
        visit_reverse_root_candidate_match_pages,
        mounts: Option<&[SelectedResolutionMountOrdinal]>
    );

    fn visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
        &self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        if !exclusions.is_empty() {
            return Err(gap_exclusions_do_not_cross_a_mount());
        }
        self.visit_reverse_candidate_match_pages(requests, cancellation, visitor)
    }

    fn visit_reverse_candidate_match_pages_with_gap_exclusions(
        &mut self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
            requests,
            exclusions,
            cancellation,
            visitor,
        )
    }

    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        let source_slot = self.argument(&source_slot);
        let mut splicing = |rule: &TypeTransferRule| visitor(&self.result(rule));
        let completion =
            self.inner
                .visit_type_transfer_rules(source_slot, cancellation, &mut splicing)?;
        Ok(self.result(&completion))
    }
}

/// A gap-exclusion plan is one operation's own value, reused across every raw
/// reverse batch and deliberately not cloneable, so its
/// `(fragment, gap reason)` identities cannot be spliced into an interior's
/// space and back without rewriting the caller's value under it. No source
/// below a mount supports the plan either: the reader trait's own default
/// refuses a nonempty one. This says so in the same place and for the reason
/// that belongs here.
fn gap_exclusions_do_not_cross_a_mount() -> StoreError {
    StoreError::new(
        "a mounted interior source does not support exact reverse candidate gap \
         exclusions: the plan's identities would have to cross the mount seam",
    )
}

/// A typed read keyed on a request batch, streaming rows through the caller's
/// page visitor. Thirty-four of the thirty-nine typed methods are this shape.
macro_rules! spliced_typed_pages {
    ($method:ident, $key:ty, $row:ty) => {
        fn $method(
            &self,
            request: TypedFactRequest<'_, $key>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, $row>,
        ) -> StoreResult<TypedFactReadOutcome> {
            let keys = self.arguments(request.as_slice());
            let maximum_rows = visitor.maximum_rows();
            let mut splicing = |page: &[$row]| visitor.visit_page(&self.results(page));
            let mut inner = TypedFactPageVisitor::with_maximum_rows(&mut splicing, maximum_rows);
            let outcome =
                self.inner
                    .$method(TypedFactRequest::new(&keys), cancellation, &mut inner)?;
            Ok(self.result(&outcome))
        }
    };
}

/// A typed read with no request key: the question is the whole selection.
macro_rules! spliced_typed_inventory {
    ($method:ident, $row:ty) => {
        fn $method(
            &self,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, $row>,
        ) -> StoreResult<TypedFactReadOutcome> {
            let maximum_rows = visitor.maximum_rows();
            let mut splicing = |page: &[$row]| visitor.visit_page(&self.results(page));
            let mut inner = TypedFactPageVisitor::with_maximum_rows(&mut splicing, maximum_rows);
            let outcome = self.inner.$method(cancellation, &mut inner)?;
            Ok(self.result(&outcome))
        }
    };
}

impl<S> SelectedTypedFactSource for Mounted<S>
where
    S: std::ops::Deref,
    S::Target: SelectedTypedFactSource,
{
    fn rust_crate_access(
        &self,
        crate_key: [u8; 32],
        base_blobs: &[(BindingFragmentId, i64)],
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<DeclarationAccessDecision>> {
        let base_blobs = base_blobs
            .iter()
            .map(|&(fragment, blob)| (self.argument(&fragment), blob))
            .collect::<Vec<_>>();
        let reference = reference.map(|row| self.argument(row));
        let definition = definition.map(|row| self.argument(row));
        self.inner.rust_crate_access(
            crate_key,
            &base_blobs,
            reference.as_ref(),
            definition.as_ref(),
        )
    }

    fn rust_crate_set_access(
        &self,
        crate_key: [u8; 32],
        base_blobs: &[(BindingFragmentId, i64)],
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<DeclarationAccessDecision>> {
        let base_blobs = base_blobs
            .iter()
            .map(|&(fragment, blob)| (self.argument(&fragment), blob))
            .collect::<Vec<_>>();
        let reference = reference.map(|row| self.argument(row));
        let definition = definition.map(|row| self.argument(row));
        self.inner.rust_crate_set_access(
            crate_key,
            &base_blobs,
            reference.as_ref(),
            definition.as_ref(),
        )
    }

    spliced_batch!(rust_module_definitions(definitions: &[SemanticId]) -> Vec<SemanticId>);

    fn rust_implemented_traits_nameable_at(
        &self,
        owner: SemanticId,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        Ok(
            match self.inner.rust_implemented_traits_nameable_at(
                self.argument(&owner),
                self.argument(&reference),
                cancellation,
            )? {
                RustImplementedTraits::Traits(traits) => {
                    RustImplementedTraits::Traits(self.results(&traits))
                }
                other => other,
            },
        )
    }

    /// Whether the reference can name this specific Rust trait, independent of its implementor.
    fn rust_trait_nameable_at(
        &self,
        owner: SemanticId,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        Ok(
            match self.inner.rust_trait_nameable_at(
                self.argument(&owner),
                self.argument(&reference),
                cancellation,
            )? {
                RustImplementedTraits::Traits(traits) => {
                    RustImplementedTraits::Traits(self.results(&traits))
                }
                other => other,
            },
        )
    }

    fn rust_impl_item_traits(
        &self,
        member: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        Ok(
            match self
                .inner
                .rust_impl_item_traits(self.argument(&member), cancellation)?
            {
                RustImplementedTraits::Traits(traits) => {
                    RustImplementedTraits::Traits(self.results(&traits))
                }
                other => other,
            },
        )
    }

    fn selection_has_java_semantics(&self) -> bool {
        self.inner.selection_has_java_semantics()
    }

    fn java_access_endpoints(
        &self,
        semantics: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<super::fact_source::JavaAccessEndpoint>>> {
        let semantics = self.arguments(semantics);
        Ok(self
            .inner
            .java_access_endpoints(&semantics, cancellation)?
            .map(|mut rows| {
                for row in &mut rows {
                    row.semantic = self.result(&row.semantic);
                    row.outermost_type = row.outermost_type.map(|owner| self.result(&owner));
                }
                rows
            }))
    }

    fn go_callable_lookups(
        &self,
        lookups: &[(BindingFragmentId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, SemanticId)>>> {
        let lookups = lookups
            .iter()
            .map(|(fragment, lookup)| (self.argument(fragment), self.argument(lookup)))
            .collect::<Vec<_>>();
        Ok(self
            .inner
            .go_callable_lookups(&lookups, cancellation)?
            .map(|rows| {
                rows.into_iter()
                    .map(|(lookup, callable)| (self.result(&lookup), self.result(&callable)))
                    .collect()
            }))
    }

    fn go_member_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<super::fact_source::GoMemberDeclaration>>> {
        let definitions = self.arguments(definitions);
        Ok(self
            .inner
            .go_member_declarations(&definitions, cancellation)?
            .map(|mut rows| {
                for row in &mut rows {
                    row.definition = self.result(&row.definition);
                    if let super::fact_source::GoMemberDeclarationKind::Struct { fields } =
                        &mut row.kind
                    {
                        for field in fields {
                            field.callable_lookup = self.result(&field.callable_lookup);
                            field.field = field.field.map(|id| self.result(&id));
                            field.value_type = field.value_type.map(|id| self.result(&id));
                        }
                    }
                }
                rows
            }))
    }

    fn hierarchy_terminal_nodes(
        &self,
        gaps: &[SelectedGapReasonProvenance],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, BindingNodeId)>>> {
        let gaps = gaps
            .iter()
            .map(|gap| self.argument(gap))
            .collect::<Vec<_>>();
        Ok(self
            .inner
            .hierarchy_terminal_nodes(&gaps, cancellation)?
            .map(|rows| {
                rows.into_iter()
                    .map(|(reason, node)| (self.result(&reason), self.result(&node)))
                    .collect()
            }))
    }

    fn java_inheritance_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<super::fact_source::JavaInheritanceDeclaration>>> {
        let definitions = self.arguments(definitions);
        Ok(self
            .inner
            .java_inheritance_declarations(&definitions, cancellation)?
            .map(|mut rows| {
                for row in &mut rows {
                    row.definition = self.result(&row.definition);
                }
                rows
            }))
    }

    fn rust_supertrait_owners(
        &self,
        owners: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        let owners = owners
            .iter()
            .map(|owner| self.argument(owner))
            .collect::<Vec<_>>();
        Ok(self
            .inner
            .rust_supertrait_owners(&owners, cancellation)?
            .map(|owners| self.results(&owners)))
    }

    fn rust_external_type_identities(
        &self,
        boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        Ok(self
            .inner
            .rust_external_type_identities(self.argument(&boundary), cancellation)?
            .map(|items| self.results(&items)))
    }

    fn rust_external_type_import_path(
        &self,
        boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<String>>> {
        self.inner
            .rust_external_type_import_path(self.argument(&boundary), cancellation)
    }

    fn visit_selected_fragment_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, BindingFragmentId>,
    ) -> StoreResult<FactReadOutcome> {
        let maximum_rows = visitor.maximum_rows();
        let mut splicing = |page: &[BindingFragmentId]| visitor.visit_page(&self.results(page));
        let mut inner = TypedFactPageVisitor::with_maximum_rows(&mut splicing, maximum_rows);
        let outcome = self
            .inner
            .visit_selected_fragment_pages(cancellation, &mut inner)?;
        Ok(self.result(&outcome))
    }

    fn read_selected_reverse_inventory_completion(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<TypedFactReadOutcome> {
        let outcome = self
            .inner
            .read_selected_reverse_inventory_completion(cancellation)?;
        Ok(self.result(&outcome))
    }

    spliced_typed_pages!(
        visit_rust_reference_context_pages,
        SemanticId,
        SelectedTypedRow<LoweredRustReferenceContext>
    );
    spliced_typed_pages!(
        visit_rust_declaration_authority_pages,
        SemanticId,
        SelectedTypedRow<LoweredRustDeclarationAuthority>
    );
    spliced_typed_pages!(
        visit_typed_frontier_pages,
        SemanticId,
        SelectedTypedRow<LoweredTypedFrontier>
    );
    spliced_typed_pages!(
        visit_type_identity_observation_pages_for_references,
        SemanticId,
        SelectedTypedRow<LoweredTypedFrontier>
    );
    spliced_typed_pages!(
        visit_type_frontier_completion_pages,
        SemanticId,
        SelectedTypeFrontierCompletion
    );
    spliced_typed_pages!(
        visit_type_transfer_pages_from_sources,
        SemanticId,
        SelectedTypedRow<LoweredTypeTransfer>
    );
    spliced_typed_pages!(
        visit_type_transfer_pages_to_targets,
        SemanticId,
        SelectedTypedRow<LoweredTypeTransfer>
    );
    spliced_typed_pages!(
        visit_type_component_pages_for_containers,
        SemanticId,
        SelectedTypedRow<LoweredTypeComponent>
    );
    spliced_typed_pages!(
        visit_underlying_type_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredUnderlyingType>
    );
    spliced_typed_pages!(
        visit_intrinsic_seed_pages_for_slots,
        SemanticId,
        SelectedTypedRow<LoweredIntrinsicSeed>
    );
    spliced_typed_pages!(
        visit_intrinsic_seed_pages_for_type_identities,
        SemanticId,
        SelectedTypedRow<LoweredIntrinsicSeed>
    );
    spliced_typed_pages!(
        visit_binding_projection_pages_for_references,
        SemanticId,
        SelectedTypedRow<LoweredBindingProjection>
    );
    spliced_typed_pages!(
        visit_binding_projection_pages_for_outputs,
        SemanticId,
        SelectedTypedRow<LoweredBindingProjection>
    );
    spliced_typed_pages!(
        visit_qualified_route_pages_for_references,
        SemanticId,
        SelectedQualifiedRoute
    );
    spliced_typed_pages!(
        visit_qualified_route_pages_for_slot_lookups,
        QualifiedRouteSlotLookup,
        SelectedQualifiedRoute
    );
    spliced_typed_pages!(
        visit_qualified_route_pages_for_qualifier_slots,
        SemanticId,
        SelectedQualifiedRoute
    );
    spliced_typed_pages!(
        visit_qualified_route_pages_for_lookups,
        SemanticId,
        SelectedQualifiedRoute
    );
    spliced_typed_pages!(
        visit_qualified_route_pages_for_gap_reasons,
        SemanticId,
        SelectedQualifiedRoute
    );

    spliced_typed_inventory!(
        visit_qualified_route_inventory_pages,
        SelectedQualifiedRoute
    );

    spliced_typed_pages!(
        visit_declaration_type_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredDeclarationTypeProperty>
    );
    spliced_typed_pages!(
        visit_declaration_type_pages_for_slots,
        SemanticId,
        SelectedTypedRow<LoweredDeclarationTypeProperty>
    );
    spliced_typed_pages!(
        visit_declaration_visibility_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredDeclarationVisibilityProperty>
    );
    spliced_typed_pages!(
        visit_member_scope_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredMemberScopeProperty>
    );
    spliced_typed_pages!(
        visit_member_scope_pages_for_heads,
        BindingNodeId,
        SelectedTypedRow<LoweredMemberScopeProperty>
    );
    spliced_typed_pages!(
        visit_member_owner_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredMemberOwnerProperty>
    );
    spliced_typed_pages!(
        visit_member_owner_pages_for_owners,
        SemanticId,
        SelectedTypedRow<LoweredMemberOwnerProperty>
    );
    spliced_typed_pages!(
        visit_deferred_member_owner_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredDeferredMemberOwner>
    );
    spliced_typed_pages!(
        visit_deferred_member_owner_pages_for_lookup_names,
        DeferredMemberOwnerLookupName,
        SelectedTypedRow<LoweredDeferredMemberOwner>
    );
    spliced_typed_pages!(
        visit_construction_requirement_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredConstructionRequirementProperty>
    );
    spliced_typed_pages!(
        visit_supertype_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredSupertypeProperty>
    );
    spliced_typed_pages!(
        visit_supertype_pages_for_references,
        SemanticId,
        SelectedTypedRow<LoweredSupertypeProperty>
    );
    spliced_typed_pages!(
        visit_supertype_pages_for_frontiers,
        SemanticId,
        SelectedTypedRow<LoweredSupertypeProperty>
    );
    spliced_typed_pages!(
        visit_definition_property_gap_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredDefinitionPropertyGap>
    );
    spliced_typed_pages!(
        visit_definition_property_gap_pages_for_reasons,
        SemanticId,
        SelectedTypedRow<LoweredDefinitionPropertyGap>
    );
    spliced_typed_pages!(
        visit_call_applicability_pages_for_callee_references,
        SemanticId,
        SelectedTypedRow<LoweredCallApplicabilityObligation>
    );
    spliced_typed_pages!(
        visit_call_applicability_pages_for_gap_reasons,
        SemanticId,
        SelectedTypedRow<LoweredCallApplicabilityObligation>
    );
    spliced_typed_pages!(
        visit_callable_signature_pages_for_definitions,
        SemanticId,
        SelectedTypedRow<LoweredCallableSignatureProperty>
    );
    spliced_typed_pages!(
        visit_gap_reason_provenance_pages_for_reasons,
        SemanticId,
        SelectedGapReasonProvenance
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Method names declared at the top level of one trait body.
    ///
    /// The decorator must forward all sixty. A required method that is not
    /// forwarded fails to compile; a *defaulted* one does not, and its default
    /// body would then run on the decorator, read the inner source through the
    /// decorator's own spliced methods and splice one value twice. This reads
    /// the traits' own source so that case fails a test instead.
    fn declared_methods(source: &str, name: &str) -> Vec<String> {
        let header = format!("pub trait {name} {{");
        let start = source
            .find(&header)
            .unwrap_or_else(|| panic!("trait {name} not found in its own source"))
            + header.len();
        let mut methods = Vec::new();
        let mut ended = false;
        for line in source[start..].lines() {
            if line == "}" {
                ended = true;
                break;
            }
            if let Some(rest) = line.strip_prefix("    fn ") {
                let end = rest
                    .find(['(', '<'])
                    .expect("a trait method declaration names its parameters");
                methods.push(rest[..end].to_string());
            }
        }
        assert!(ended, "trait {name} body is unterminated");
        methods
    }

    /// Method names this module writes an arm for, whether by hand or through
    /// one of its macros.
    fn forwarded_methods(source: &str) -> Vec<String> {
        // A macro invocation names its method on the line after the macro as
        // often as on the same one, so the scan carries the macro's opening
        // line over to the next.
        let mut names = Vec::new();
        let mut expecting = false;
        for line in source.lines() {
            let line = line.trim();
            if expecting {
                expecting = false;
                let end = line
                    .find(['(', '<', ',', ' ', ')', ';'])
                    .unwrap_or(line.len());
                let name = line[..end].to_string();
                if !name.is_empty() {
                    names.push(name);
                }
                continue;
            }
            for prefix in [
                "fn ",
                "spliced_batch!(",
                "spliced_candidate_pages!(",
                "spliced_typed_pages!(",
                "spliced_typed_inventory!(",
            ] {
                let Some(rest) = line.strip_prefix(prefix) else {
                    continue;
                };
                if rest.is_empty() {
                    expecting = true;
                    break;
                }
                let end = rest
                    .find(['(', '<', ',', ' ', ')', ';'])
                    .unwrap_or(rest.len());
                let name = rest[..end].to_string();
                if !name.is_empty() {
                    names.push(name);
                }
                break;
            }
        }
        names
    }

    #[test]
    fn the_decorator_forwards_every_method_of_both_reader_traits() {
        let batch_source = include_str!("batch.rs");
        let batch = declared_methods(batch_source, "BatchResolutionFragmentSource");
        let batch_crlf = batch_source.replace("\r\n", "\n").replace('\n', "\r\n");
        assert_eq!(
            declared_methods(&batch_crlf, "BatchResolutionFragmentSource"),
            batch
        );
        let typed_source = include_str!("fact_source.rs");
        let typed = declared_methods(typed_source, "SelectedTypedFactSource");
        let typed_crlf = typed_source.replace("\r\n", "\n").replace('\n', "\r\n");
        assert_eq!(
            declared_methods(&typed_crlf, "SelectedTypedFactSource"),
            typed
        );
        assert_eq!(batch.len(), 25, "BatchResolutionFragmentSource: {batch:?}");
        assert_eq!(typed.len(), 55, "SelectedTypedFactSource: {typed:?}");

        let forwarded = forwarded_methods(include_str!("mounted.rs"))
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let missing = batch
            .iter()
            .chain(typed.iter())
            .filter(|name| !forwarded.contains(*name))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "Mounted does not forward every reader-seam method: {missing:?}"
        );
    }
}
