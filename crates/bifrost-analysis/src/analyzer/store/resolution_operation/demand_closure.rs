//! Request-local vocabulary for shared root closure (#5658).
//!
//! No frame, cursor, proof or staged context belongs on a retained selection.
//! The migration wrapper is deliberately not installed by a production language.
//! The discovery reader and closer are filled in by the following adoption slices.
#![allow(dead_code)] // Migration seam: production adoption follows the all-halves reader.

use super::demand::{
    DemandLanguage, LanguageClosure, LanguageContextPreparation, LanguagePrefixInputs,
    LanguageRootDiscovery,
};
use super::source_demand::SourceDemandKey;
use super::*;
use crate::analyzer::resolution::{
    DemandClosureDischarges, DemandMemberSelection, DemandMemberSelectionRequest,
    DemandRootUnavailableReason, EndpointSignature, FactResolutionAnswer, LoweredPackageReference,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct HalfId(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct PlacementId(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ContextId(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct EnvironmentId(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ProofId(pub usize);

pub(super) struct RootFrame {
    pub endpoint: EndpointSignature,
    pub source: RootSource,
    pub halves: Box<[SourceHalf]>,
    pub context: Option<ContextId>,
    pub operands: Box<[PrefixOperand]>,
    pub discovery: ResolutionCompletion,
}

pub(super) enum RootSource {
    Positioned(SourceDemandKey),
    Package(LoweredPackageReference),
}

pub(super) struct SourceHalf {
    pub path: SelectedRootPathHalf,
    pub lookup: ResolutionLookupSemanticRecipe,
    pub route: Box<[ResolutionLookupSemanticRecipe]>,
    pub prefix: Option<PrefixKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct PrefixKey {
    pub reference: SemanticId,
    pub environment: EnvironmentId,
}

#[derive(Clone)]
pub(super) struct PrefixOperand {
    pub key: PrefixKey,
    pub source_halves: Box<[HalfId]>,
}

pub(super) struct PrefixAnswer<'a> {
    pub key: PrefixKey,
    pub answer: &'a FactResolutionAnswer,
}
pub(super) struct PrefixAnswers<'a> {
    pub entries: &'a [PrefixAnswer<'a>],
}

pub(super) struct RouteCursor {
    pub half: HalfId,
    pub placement: PlacementId,
    pub location: RouteLocation,
    /// Index into the original route; bridge construction keeps that route intact.
    pub consumed_prefix_segments: usize,
    pub namespace: ResolutionNamespace,
    pub proof: ProofId,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum RouteLocation {
    /// The selected unit and its stored container key. This key comes from
    /// relational rows, never from parsing a rendered source path.
    Container { unit: i64, container: String },
    Owner {
        definition: SemanticId,
        scope: Option<BindingNodeId>,
    },
}

/// Tiers are ordered within one cursor. The walker tries the next tier only
/// when the preceding tier has no result; it never flattens lexical levels.
pub(super) struct RankedEdgeTiers {
    pub tiers: Box<[Box<[RouteCursor]>]>,
}

pub(super) struct ExportCandidate {
    half: SelectedRootPathHalf,
    pub lookup: ResolutionLookupSemanticRecipe,
    pub proof: ProofId,
    pub definition: SemanticId,
}
impl ExportCandidate {
    pub fn new(
        half: SelectedRootPathHalf,
        lookup: ResolutionLookupSemanticRecipe,
        proof: ProofId,
        definition: SemanticId,
    ) -> Self {
        assert!(matches!(half, SelectedRootPathHalf::Export { .. }));
        Self {
            half,
            lookup,
            proof,
            definition,
        }
    }
    pub fn half(&self) -> &SelectedRootPathHalf {
        &self.half
    }
    pub fn authority(&self) -> ExportAuthority {
        let SelectedRootPathHalf::Export {
            identity,
            token,
            demand,
            definition,
            ..
        } = &self.half
        else {
            unreachable!("export candidates are checked at construction");
        };
        ExportAuthority {
            fragment: identity.fragment(),
            token: *token,
            demand: *demand,
            definition: *definition,
        }
    }
}

pub(super) enum CandidateDecision {
    Admit,
    Reject,
    Open(ResolutionCompletion),
}

/// The sealed export authority, independent of the installed path that proved it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ExportAuthority {
    pub fragment: BindingFragmentId,
    pub token: SemanticId,
    pub demand: SemanticId,
    pub definition: BindingNodeId,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum EvidenceOwner {
    Discovery,
    Source(HalfId),
    Placement(HalfId, PlacementId),
    Candidate(HalfId, ExportAuthority),
    Context(ContextId),
}
pub(super) struct Proof {
    pub owner: EvidenceOwner,
    /// AND dependencies. Proofs are appended after their prerequisites.
    pub required: Box<[ProofId]>,
    pub local: ResolutionCompletion,
}
pub(super) struct AuthorityProofs {
    pub owner: EvidenceOwner,
    /// OR alternatives for exactly this authority. Empty never proves absence.
    pub alternatives: Box<[ProofId]>,
}
pub(super) struct ProofFacts {
    pub proofs: Vec<Proof>,
    pub authorities: Vec<AuthorityProofs>,
}

pub(super) struct ClosureFacts<'a> {
    pub prefixes: PrefixAnswers<'a>,
    pub halves: &'a [HalfClosureFacts],
    /// Admitted exports after authority grouping, not raw nominations.
    pub candidates: &'a [ExportCandidate],
    pub context: Option<ContextId>,
    pub evidence: &'a ProofFacts,
}
pub(super) struct HalfClosureFacts {
    pub half: HalfId,
    pub answered_placements: Box<[PlacementId]>,
    pub reached: Box<[RouteLocation]>,
    pub accepted: Box<[ExportAuthority]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BaseEligibility {
    Retain,
    Exclude,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ResultAuthority<'a> {
    Open,
    SelectedTargets(&'a BTreeSet<SemanticId>),
    AuthoritativeEmpty,
}

pub(super) struct ClosurePolicy {
    pub completion: ResolutionCompletion,
    pub base: BaseEligibility,
    // One canonical authority, carried by the existing scheduler discharge type.
    discharges: DemandClosureDischarges,
    pub generated: Box<[GeneratedContinuation]>,
}
impl ClosurePolicy {
    pub fn new(
        completion: ResolutionCompletion,
        base: BaseEligibility,
        discharges: DemandClosureDischarges,
        generated: Box<[GeneratedContinuation]>,
    ) -> Self {
        assert!(
            !discharges.authoritative_empty_result
                || discharges
                    .selected_targets
                    .as_ref()
                    .is_some_and(BTreeSet::is_empty)
        );
        assert!(
            discharges
                .selected_targets
                .as_ref()
                .is_none_or(|targets| !targets.is_empty() || discharges.authoritative_empty_result)
        );
        Self {
            completion,
            base,
            discharges,
            generated,
        }
    }
    pub fn authority(&self) -> ResultAuthority<'_> {
        if self.discharges.authoritative_empty_result {
            ResultAuthority::AuthoritativeEmpty
        } else if let Some(targets) = &self.discharges.selected_targets {
            ResultAuthority::SelectedTargets(targets)
        } else {
            ResultAuthority::Open
        }
    }
    pub fn into_discharges(self) -> DemandClosureDischarges {
        self.discharges
    }
}
pub(super) struct GeneratedContinuation {
    pub candidate: CandidatePathIdentity,
    pub source: SourceDemandKey,
    pub base: BaseEligibility,
}

#[allow(clippy::large_enum_variant)] // Source-owned frames stay inline with the provider root.
pub(super) enum Admission {
    BaseOwned {
        completion: ResolutionCompletion,
        base: BaseEligibility,
    },
    SourceOwned(RootFrame),
    Unavailable {
        reason: DemandRootUnavailableReason,
        completion: ResolutionCompletion,
    },
}
pub(super) enum Read<T> {
    Ready {
        value: T,
        completion: ResolutionCompletion,
    },
    Unavailable {
        reason: DemandRootUnavailableReason,
        completion: ResolutionCompletion,
    },
    Cancelled(ResolutionCompletion),
}
impl<T> Read<T> {
    fn ready(value: T) -> Self {
        Self::Ready {
            value,
            completion: ResolutionCompletion::Complete,
        }
    }
}

pub(super) enum EndpointAdmission {
    Ready,
    Discover,
}
pub(super) enum SourceScope {
    Unrestricted,
    Mounts(Box<[i64]>),
}
pub(super) enum ImportOrigin {
    Named,
    Glob,
}

/// Language decisions only. No hook owns a worklist, registration or publication.
/// Context derivation stages private data; it does not publish candidate cells.
pub(super) trait DemandRules {
    fn describe_source(
        &mut self,
        endpoint: &EndpointSignature,
        halves: Vec<SourceHalf>,
        completion: ResolutionCompletion,
    ) -> Result<Read<Admission>>;
    fn root_starts(
        &mut self,
        frame: &RootFrame,
        half: HalfId,
        answers: &PrefixAnswers<'_>,
        context: Option<&SelectedResolutionContextSet>,
    ) -> Result<Read<Vec<RouteCursor>>>;

    fn admit_endpoint(
        &self,
        endpoint: &EndpointSignature,
        already_published: bool,
    ) -> EndpointAdmission {
        if endpoint.node() != BindingNodeId::universal_root() || already_published {
            EndpointAdmission::Ready
        } else {
            EndpointAdmission::Discover
        }
    }
    fn discovery_scope(&self) -> SourceScope {
        SourceScope::Unrestricted
    }
    fn context_identity(&self, _frame: &RootFrame) -> Option<ContextId> {
        None
    }
    fn derive_context(
        &mut self,
        _key: ContextId,
        _frame: &RootFrame,
    ) -> Result<Read<Option<SelectedResolutionContextSet>>> {
        Ok(Read::ready(None))
    }
    fn prefix_operands(&self, frame: &RootFrame, caller: EnvironmentId) -> Vec<PrefixOperand> {
        frame
            .halves
            .iter()
            .enumerate()
            .filter_map(|(index, half)| {
                let SelectedRootPathHalf::Reference {
                    prefix_reference: Some(reference),
                    ..
                } = &half.path
                else {
                    return None;
                };
                Some(PrefixOperand {
                    key: PrefixKey {
                        reference: *reference,
                        environment: caller,
                    },
                    source_halves: Box::new([HalfId(index)]),
                })
            })
            .collect()
    }
    fn prefix_environment(
        &self,
        _frame: &RootFrame,
        _operand: &PrefixOperand,
        _context: Option<&SelectedResolutionContextSet>,
        caller: EnvironmentId,
    ) -> EnvironmentId {
        caller
    }
    /// An empty default is unsupported route knowledge. The shared walker must
    /// retain an unsupported boundary for residual segments, never prove absence.
    fn route_edges(
        &mut self,
        _frame: &RootFrame,
        _cursor: &RouteCursor,
    ) -> Result<Read<RankedEdgeTiers>> {
        Ok(Read::ready(RankedEdgeTiers {
            tiers: Box::new([]),
        }))
    }
    fn activation(&self, _frame: &RootFrame, _half: HalfId) -> CandidateDecision {
        CandidateDecision::Admit
    }
    fn precedence(&self, origin: ImportOrigin) -> u32 {
        match origin {
            ImportOrigin::Named => 0,
            ImportOrigin::Glob => 1,
        }
    }
    fn admit_candidate(
        &self,
        _frame: &RootFrame,
        _cursor: &RouteCursor,
        _candidate: &ExportCandidate,
    ) -> CandidateDecision {
        CandidateDecision::Admit
    }
    fn closure_policy(
        &self,
        _frame: &RootFrame,
        facts: &ClosureFacts<'_>,
    ) -> Result<Read<ClosurePolicy>> {
        let targets: BTreeSet<_> = facts
            .candidates
            .iter()
            .map(|candidate| candidate.definition)
            .collect();
        let discharges = if targets.is_empty() {
            DemandClosureDischarges::default()
        } else {
            DemandClosureDischarges::default().with_selected_targets(targets)
        };
        Ok(Read::ready(ClosurePolicy::new(
            ResolutionCompletion::Complete,
            BaseEligibility::Retain,
            discharges,
            Box::new([]),
        )))
    }
    fn member_request(
        &self,
        _frame: &RootFrame,
        _answers: &PrefixAnswers<'_>,
    ) -> Result<Read<Option<DemandMemberSelectionRequest>>> {
        Ok(Read::ready(None))
    }
    fn selected_member_exports(
        &mut self,
        _frame: &RootFrame,
        _selection: &DemandMemberSelection,
    ) -> Result<Read<Vec<ExportCandidate>>> {
        unreachable!("selected member exports require a member request")
    }
    /// The reverse pipeline retains incomplete inventory when the selected
    /// unit publishes reexports that these default edges cannot enumerate.
    fn reverse_export_edges(
        &mut self,
        _endpoint: &EndpointSignature,
    ) -> Result<Read<Vec<EndpointSignature>>> {
        Ok(Read::ready(Vec::new()))
    }
}

pub(super) struct SharedDemand<R> {
    pub rules: R,
}
impl<R: DemandRules> DemandLanguage for SharedDemand<R> {
    type RootQuestion = RootFrame;
    type ContextKey = ContextId;
    type ContextData = Option<SelectedResolutionContextSet>;
    fn discover_root(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<RootFrame>> {
        discover_root(&mut self.rules, endpoint)
    }
    fn context_key(&self, frame: &RootFrame) -> Option<ContextId> {
        self.rules.context_identity(frame)
    }
    fn prepare_context(
        &mut self,
        key: &ContextId,
        frame: &RootFrame,
    ) -> Result<LanguageContextPreparation<Self::ContextData>> {
        Ok(match self.rules.derive_context(*key, frame)? {
            Read::Ready { value, completion } => LanguageContextPreparation::Ready {
                data: value,
                completion,
            },
            Read::Unavailable { completion, .. } => {
                LanguageContextPreparation::Unavailable(completion)
            }
            Read::Cancelled(completion) => LanguageContextPreparation::Cancelled(completion),
        })
    }
    fn prefix_inputs(
        &mut self,
        frame: &mut RootFrame,
        context: Option<&Self::ContextData>,
    ) -> Result<LanguagePrefixInputs> {
        prefix_inputs(&mut self.rules, frame, context.and_then(Option::as_ref))
    }
    fn close_root(
        &mut self,
        endpoint: &EndpointSignature,
        frame: &RootFrame,
        context: Option<&Self::ContextData>,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> Result<LanguageClosure> {
        close_root(
            &mut self.rules,
            endpoint,
            frame,
            context.and_then(Option::as_ref),
            inputs,
        )
    }
}

// Intentionally fail loudly if installed early. Missing source rows and missing
// route support must never accidentally certify a base answer or an absence.
fn discover_root<R: DemandRules>(
    _rules: &mut R,
    _endpoint: &EndpointSignature,
) -> Result<LanguageRootDiscovery<RootFrame>> {
    unimplemented!("shared discovery requires the all-halves reader before adoption")
}
fn prefix_inputs<R: DemandRules>(
    _rules: &mut R,
    _frame: &mut RootFrame,
    _context: Option<&SelectedResolutionContextSet>,
) -> Result<LanguagePrefixInputs> {
    unimplemented!("shared prefixes require environment-bearing scheduler inputs before adoption")
}
fn close_root<R: DemandRules>(
    _rules: &mut R,
    _endpoint: &EndpointSignature,
    _frame: &RootFrame,
    _context: Option<&SelectedResolutionContextSet>,
    _inputs: &[(SemanticId, &FactResolutionAnswer)],
) -> Result<LanguageClosure> {
    unimplemented!("shared publication is not installed before differential validation")
}
