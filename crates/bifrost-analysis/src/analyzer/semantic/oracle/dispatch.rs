use crate::analyzer::Language;
use crate::analyzer::semantic::ids::DeclarationLocator;
use crate::analyzer::semantic::ids::DeclarationSegment;
use crate::analyzer::semantic::ids::SemanticLanguage;
use crate::analyzer::semantic::ids::SemanticLocator;
use crate::analyzer::semantic::ir::{
    CallSiteHandle, EvidenceCompleteness, ProcedureKind, ProofStatus, SemanticCallArgument,
};
use crate::analyzer::semantic::oracle::error::OracleContractError;
use crate::analyzer::semantic::oracle::limits::OracleLimits;
use crate::analyzer::semantic::oracle::model::DispatchBoundaryKind;
use crate::analyzer::semantic::oracle::relation::{
    CandidateCoverage, OracleRelationHandle, OracleRelationKind, OracleRelationOwner,
    validate_provenance_identity, validate_provenance_quality, validate_retained_relation_arenas,
};

pub use brokk_bifrost_semantic::analyzer::semantic::oracle::dispatch::*;

/// Declaration/body evidence, conditional on this member being selected. It
/// deliberately excludes the uncertainty about which runtime arm executes.
/// Complete materialization is not a proof about control flow, bindings or
/// effects inside that body; those remain independent consumer obligations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct DispatchFamilyMemberInput {
    declaration: SemanticLocator,
    body: DispatchFamilyMemberBody,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum DispatchFamilyMemberBody {
    Materialized(crate::analyzer::semantic::ProcedureHandle),
    /// Structured declaration modifiers prove this is not an executable arm.
    AbstractDeclaration,
    Unavailable,
}

impl DispatchFamilyMemberInput {
    pub(crate) fn new(
        declaration: SemanticLocator,
        body: DispatchFamilyMemberBody,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    ) -> Self {
        Self {
            declaration,
            body,
            proof,
            completeness,
        }
    }

    pub fn declaration(&self) -> &SemanticLocator {
        &self.declaration
    }
    pub fn body(&self) -> &DispatchFamilyMemberBody {
        &self.body
    }
    pub fn proof(&self) -> &ProofStatus {
        &self.proof
    }
    pub fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }
}

/// Summary applicability is independent of the enumeration of workspace arms.
/// Only the later subject/protocol closure can discharge this remainder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum DispatchFamilyExternalSummaryInput {
    Absent,
    Partial,
    Ambiguous,
    Reviewed,
}

/// An exact external remainder remains named even without a usable summary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct DispatchFamilyExternalRemainder {
    locator: SemanticLocator,
    descriptor: Option<crate::analyzer::resolution::ExternalMemberIdentity>,
    declaration_is_abstract: bool,
    arity: u32,
    has_receiver: bool,
    summary_input: DispatchFamilyExternalSummaryInput,
    bindings: Box<[crate::analyzer::semantic_model::UnmaterializedExternalSummaryCallShapeBinding]>,
}

impl DispatchFamilyExternalRemainder {
    pub(crate) fn new(
        target: &UnmaterializedExternalTarget,
        declaration_is_abstract: bool,
        summary_input: DispatchFamilyExternalSummaryInput,
        mut bindings: Vec<
            crate::analyzer::semantic_model::UnmaterializedExternalSummaryCallShapeBinding,
        >,
    ) -> Self {
        assert!(
            bindings
                .iter()
                .all(|binding| binding.actual_locator() == target.locator())
        );
        if summary_input == DispatchFamilyExternalSummaryInput::Reviewed {
            assert!(
                !bindings.is_empty() && bindings.iter().all(|binding| binding.covers_overrides())
            );
        }
        bindings.sort_by(|left, right| {
            left.model_id()
                .cmp(right.model_id())
                .then_with(|| left.content().cmp(&right.content()))
        });
        Self {
            locator: target.locator().clone(),
            descriptor: target.selected_external_descriptor.clone(),
            declaration_is_abstract,
            arity: target.arity(),
            has_receiver: target.has_receiver(),
            summary_input,
            bindings: bindings.into_boxed_slice(),
        }
    }
    pub fn locator(&self) -> &SemanticLocator {
        &self.locator
    }
    pub fn bindings(
        &self,
    ) -> &[crate::analyzer::semantic_model::UnmaterializedExternalSummaryCallShapeBinding] {
        &self.bindings
    }
    pub fn descriptor(&self) -> Option<&crate::analyzer::resolution::ExternalMemberIdentity> {
        self.descriptor.as_ref()
    }
    pub fn declaration_is_abstract(&self) -> bool {
        self.declaration_is_abstract
    }
    pub fn arity(&self) -> u32 {
        self.arity
    }
    pub fn has_receiver(&self) -> bool {
        self.has_receiver
    }
    pub fn summary_input(&self) -> DispatchFamilyExternalSummaryInput {
        self.summary_input
    }
    fn retained_heap_bytes(&self) -> usize {
        family_locator_heap_bytes(&self.locator)
            + std::mem::size_of_val(self.bindings.as_ref())
            + self
                .bindings
                .iter()
                .map(|binding| {
                    family_locator_heap_bytes(binding.actual_locator())
                        + family_locator_heap_bytes(binding.formal_locator())
                        + binding.model_id().len()
                        + binding.actual_to_formal().map_or(0, std::mem::size_of_val)
                })
                .sum::<usize>()
            + self.descriptor.as_ref().map_or(0, |descriptor| {
                descriptor.owner.provider_id.len()
                    + descriptor.owner.owner_fqn.len()
                    + 4 * std::mem::size_of::<usize>()
            })
    }
}

pub(crate) fn family_locator_heap_bytes(locator: &SemanticLocator) -> usize {
    std::mem::size_of_val(locator.declaration().segments())
        + crate::analyzer::semantic::workspace_oracle::dispatch::semantic_locator_work(locator)
            .owned_text_bytes
}

type FamilyInputReceipt =
    crate::analyzer::workspace_authority::ReplayingMemoEntry<(), crate::analyzer::ReadKey>;

/// Inline bytes of one family receipt, with a target-independent allowance
/// for its cache-charge control block. `AllocationCharge` embeds a platform
/// mutex: `size_of` is 48 bytes on Linux and Windows and 56 on macOS, so
/// charging the receipt's full `size_of` made `owned_text_bytes` (and the
/// resident peak derived from it) host-dependent (#14489). The allowance is
/// the Linux/Windows size, so those targets keep their recorded values and
/// macOS reports the same bytes.
const FAMILY_INPUT_RECEIPT_INLINE_BYTES: usize = std::mem::size_of::<FamilyInputReceipt>()
    - std::mem::size_of::<crate::retention_budget::AllocationCharge>()
    + 48;

/// Complete enumeration, including absence of competing overrides, for one
/// exact call. Only the workspace producer can construct this witness; public
/// candidate and transfer evidence remains unchanged.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct DispatchFamilyMembership {
    call: CallSiteHandle,
    members: Box<[SemanticLocator]>,
    external_remainder: Option<DispatchFamilyExternalRemainder>,
    receipt: std::sync::Arc<FamilyInputReceipt>,
}

impl PartialEq for DispatchFamilyMembership {
    fn eq(&self, other: &Self) -> bool {
        // Receipts are independently refreshed inputs, not published output.
        crate::analyzer::semantic::workspace_oracle::source::dispatch_family_membership_digest(self)
            == crate::analyzer::semantic::workspace_oracle::source::dispatch_family_membership_digest(other)
    }
}
impl Eq for DispatchFamilyMembership {}

impl DispatchFamilyMembership {
    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }
    pub fn members(&self) -> &[SemanticLocator] {
        &self.members
    }
    pub fn external_remainder(&self) -> Option<&DispatchFamilyExternalRemainder> {
        self.external_remainder.as_ref()
    }

    /// Replay through the current owner's capability; no reader or destination
    /// survives with this value.
    pub fn replay(&self, capability: &crate::analyzer::workspace_authority::OwnedMemoCapability) {
        self.receipt.replay(&capability.capability());
    }

    pub fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.retained_heap_bytes()
    }

    fn retained_heap_bytes(&self) -> usize {
        family_members_heap_bytes(&self.members, self.external_remainder.as_ref())
            + family_receipt_bytes(&self.receipt)
    }

    pub fn retained_artifacts(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        census.procedure(self.call.procedure());
    }
}

fn family_members_heap_bytes(
    members: &[SemanticLocator],
    remainder: Option<&DispatchFamilyExternalRemainder>,
) -> usize {
    std::mem::size_of_val(members)
        + members.iter().map(family_locator_heap_bytes).sum::<usize>()
        + remainder.map_or(0, DispatchFamilyExternalRemainder::retained_heap_bytes)
}

fn family_receipt_bytes(receipt: &FamilyInputReceipt) -> usize {
    // Both the entry and its key slice have an Arc allocation header.
    (4 * std::mem::size_of::<usize>() + FAMILY_INPUT_RECEIPT_INLINE_BYTES).saturating_add(
        receipt.retained_read_bytes(|key| {
            let mut heap = crate::analyzer::store::cache_budget::RetainedHeap::default();
            crate::analyzer::store::cache_budget::retained_read_key(&mut heap, key);
            heap.total()
        }),
    )
}

/// Capture producer premises only. Callers record ProcedureDispatch after this
/// returns, so a witness never recursively depends on its own response.
pub(crate) fn capture_dispatch_family(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    resolve: impl FnOnce(
        &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<DispatchResult>,
        crate::analyzer::semantic::SemanticProviderError,
    >,
) -> Result<
    crate::analyzer::semantic::SemanticOutcome<DispatchResult>,
    crate::analyzer::semantic::SemanticProviderError,
> {
    use crate::analyzer::semantic::{SemanticOutcome, SemanticWork};
    let entry = crate::analyzer::workspace_authority::ReplayingMemoEntry::capture(
        &crate::analyzer::workspace_authority::memo_attribution(analyzer),
        || -> Result<_, crate::analyzer::semantic::SemanticProviderError> {
            let outcome = resolve(request)?;
            let mut native_work = SemanticWork::default();
            let outcome = outcome.try_map(|mut dispatch| {
                if let Some(family) = &mut dispatch.family {
                    native_work = family.check_native_inputs(analyzer, request)?;
                }
                Ok::<_, crate::analyzer::semantic::SemanticProviderError>(dispatch)
            })?;
            let work = outcome.work().conservative_add(native_work);
            if request.cancellation.is_cancelled() {
                let partial = match outcome {
                    SemanticOutcome::Complete { value, .. } => Some(value),
                    SemanticOutcome::Ambiguous { candidates, .. } => Some(candidates),
                    SemanticOutcome::Unproven { partial, .. } => Some(partial),
                    SemanticOutcome::Unknown { partial, .. }
                    | SemanticOutcome::Unsupported { partial, .. }
                    | SemanticOutcome::ExceededBudget { partial, .. }
                    | SemanticOutcome::Cancelled { partial, .. } => partial,
                };
                return Ok(SemanticOutcome::Cancelled { partial, work });
            }
            Ok(match outcome {
                SemanticOutcome::Complete { value, .. } => {
                    SemanticOutcome::Complete { value, work }
                }
                SemanticOutcome::Ambiguous { candidates, .. } => {
                    SemanticOutcome::Ambiguous { candidates, work }
                }
                SemanticOutcome::Unknown { partial, .. } => {
                    SemanticOutcome::Unknown { partial, work }
                }
                SemanticOutcome::Unsupported {
                    capability,
                    partial,
                    ..
                } => SemanticOutcome::Unsupported {
                    capability,
                    partial,
                    work,
                },
                SemanticOutcome::Unproven { partial, .. } => {
                    SemanticOutcome::Unproven { partial, work }
                }
                SemanticOutcome::ExceededBudget {
                    partial, exceeded, ..
                } => SemanticOutcome::ExceededBudget {
                    partial,
                    exceeded,
                    work,
                },
                SemanticOutcome::Cancelled { partial, .. } => {
                    SemanticOutcome::Cancelled { partial, work }
                }
            })
        },
    );
    let (outcome, reads) = entry.into_parts();
    let outcome = outcome?;
    let replayable = reads.channels.unattributed_reads == 0
        && !matches!(
            outcome,
            SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. }
        );
    let receipt = std::sync::Arc::new(FamilyInputReceipt::from_parts((), reads));
    let mut added_work = SemanticWork::default();
    let old_work = outcome.work();
    let outcome = outcome.try_map(|mut dispatch| {
        if let Some(family) = &mut dispatch.family {
            let can_seal = replayable && !receipt.execution_dependent();
            if !can_seal && matches!(family.proof, DispatchFamilyProof::Pending { .. }) {
                family.proof = DispatchFamilyProof::Unavailable;
            }
            added_work.owned_text_bytes = family.retained_bytes();
            if matches!(family.proof, DispatchFamilyProof::Pending { .. }) {
                added_work.owned_text_bytes = added_work
                    .owned_text_bytes
                    .saturating_add(family_receipt_bytes(&receipt));
            }
            if let Err(exceeded) = request.budget.admit(added_work) {
                // The raw answer already owns its paid materialization. A
                // refused family/receipt must not discard those may-targets.
                dispatch.family = None;
                return Err(Box::new((exceeded, dispatch)));
            }
            if matches!(family.proof, DispatchFamilyProof::Pending { .. }) {
                let DispatchFamilyProof::Pending {
                    members,
                    external_remainder,
                    native_members,
                } = std::mem::replace(&mut family.proof, DispatchFamilyProof::Unavailable)
                else {
                    unreachable!("the producer just checked its pending inventory")
                };
                assert!(
                    native_members.is_empty(),
                    "owned native premises were discharged before sealing"
                );
                // This construction is private to an owned source lookup's
                // premise capture. A supplied PreparedCallDispatch cannot seal.
                family.proof = DispatchFamilyProof::Complete(DispatchFamilyMembership {
                    call: family.call.clone(),
                    members,
                    external_remainder,
                    receipt: std::sync::Arc::clone(&receipt),
                });
            }
        }
        Ok(dispatch)
    });
    let mut outcome = match outcome {
        Ok(outcome) => outcome,
        Err(refused) => {
            let (exceeded, dispatch) = *refused;
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(dispatch),
                exceeded,
                work: old_work.conservative_add(added_work),
            });
        }
    };
    match &mut outcome {
        SemanticOutcome::Complete { work, .. }
        | SemanticOutcome::Ambiguous { work, .. }
        | SemanticOutcome::Unknown { work, .. }
        | SemanticOutcome::Unsupported { work, .. }
        | SemanticOutcome::Unproven { work, .. }
        | SemanticOutcome::ExceededBudget { work, .. }
        | SemanticOutcome::Cancelled { work, .. } => *work = work.conservative_add(added_work),
    }
    Ok(outcome)
}

/// A published attempt retains unresolved member inputs even when there is no
/// certificate. A missing concrete body never disappears from the inventory.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct DispatchFamilyEvidence {
    call: CallSiteHandle,
    inputs: Box<[DispatchFamilyMemberInput]>,
    proof: DispatchFamilyProof,
}

/// Inventory equality is a pending premise until an owned lookup supplies its
/// immutable receipt. It is deliberately not the public membership witness.
#[derive(Debug, Clone)]
enum DispatchFamilyProof {
    Unavailable,
    Pending {
        members: Box<[SemanticLocator]>,
        external_remainder: Option<DispatchFamilyExternalRemainder>,
        native_members: Box<[crate::analyzer::CodeUnit]>,
    },
    Complete(DispatchFamilyMembership),
}

impl PartialEq for DispatchFamilyEvidence {
    fn eq(&self, other: &Self) -> bool {
        crate::analyzer::semantic::workspace_oracle::source::dispatch_family_premises_digest(Some(
            self,
        )) == crate::analyzer::semantic::workspace_oracle::source::dispatch_family_premises_digest(
            Some(other),
        )
    }
}
impl Eq for DispatchFamilyEvidence {}

impl DispatchFamilyEvidence {
    fn check_native_inputs(
        &mut self,
        analyzer: &dyn crate::analyzer::IAnalyzer,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticWork,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        use crate::analyzer::semantic::{
            SemanticWork,
            workspace_oracle::dispatch::{locator_for_definition, query_virtual_dispatch_family},
        };
        let mut work = SemanticWork::default();
        let DispatchFamilyProof::Pending { native_members, .. } = &mut self.proof else {
            return Ok(work);
        };
        for declaration in std::mem::take(native_members).into_vec() {
            if request.cancellation.is_cancelled() || !request.charge_execution_traversal(1) {
                self.proof = DispatchFamilyProof::Unavailable;
                break;
            }
            let step = SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            };
            request.budget.charge_work(step);
            work = work.conservative_add(step);
            let Some(family) =
                query_virtual_dispatch_family(analyzer, &declaration, request.cancellation)
            else {
                self.proof = DispatchFamilyProof::Unavailable;
                break;
            };
            if family.outcome
                != crate::analyzer::structural::resolution::MemberFamilyOutcome::Proven
            {
                self.proof = DispatchFamilyProof::Unavailable;
                break;
            }
            for member in family.members {
                let locator = locator_for_definition(analyzer, &member)?;
                if self
                    .inputs
                    .binary_search_by(|input| input.declaration.cmp(&locator))
                    .is_err()
                {
                    // Never fill this gap by demanding hidden overrides. The
                    // full native inventory must equal the already staged set.
                    self.proof = DispatchFamilyProof::Unavailable;
                    break;
                }
            }
            if matches!(self.proof, DispatchFamilyProof::Unavailable) {
                break;
            }
        }
        Ok(work)
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }
    pub fn inputs(&self) -> &[DispatchFamilyMemberInput] {
        &self.inputs
    }
    /// Whether every executable arm has a body whose own evidence, apart from
    /// runtime selection, is proven and complete.
    pub fn arms_complete(&self) -> bool {
        self.inputs.iter().all(|input| match &input.body {
            DispatchFamilyMemberBody::AbstractDeclaration => true,
            DispatchFamilyMemberBody::Materialized(_) => {
                matches!(input.proof, ProofStatus::Proven)
                    && matches!(input.completeness, EvidenceCompleteness::Complete)
            }
            DispatchFamilyMemberBody::Unavailable => false,
        })
    }

    /// Whether this sealed family accounts for a dispatch boundary of its own
    /// call: an abstract family declaration has no executable body, and the
    /// open remainder of the target set is the absence that membership proved.
    pub fn discharges(&self, boundary: &DispatchBoundary) -> bool {
        if self.membership().is_none()
            || boundary.partial_cause.is_some()
            || boundary.external_callee_identity.is_some()
            || boundary.unmaterialized_external_target.is_some()
        {
            return false;
        }
        match &boundary.kind {
            DispatchBoundaryKind::Unresolved => boundary.exact_external_target.is_none(),
            // Exact target metadata on this boundary names the same bodiless
            // workspace declaration; it is not an external callee.
            DispatchBoundaryKind::Unmaterialized(locator) => self.inputs.iter().any(|input| {
                matches!(input.body, DispatchFamilyMemberBody::AbstractDeclaration)
                    && &input.declaration == locator
            }),
            _ => false,
        }
    }

    pub fn membership(&self) -> Option<&DispatchFamilyMembership> {
        match &self.proof {
            DispatchFamilyProof::Complete(membership) => Some(membership),
            DispatchFamilyProof::Unavailable | DispatchFamilyProof::Pending { .. } => None,
        }
    }
    pub fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.retained_heap_bytes()
    }

    fn retained_heap_bytes(&self) -> usize {
        std::mem::size_of_val(self.inputs.as_ref())
            + self
                .inputs
                .iter()
                .map(|input| {
                    family_locator_heap_bytes(&input.declaration)
                        + input.proof.retained_heap_bytes()
                        + crate::analyzer::semantic::completeness_reason_bytes(&input.completeness)
                })
                .sum::<usize>()
            + match &self.proof {
                DispatchFamilyProof::Unavailable => 0,
                DispatchFamilyProof::Pending {
                    members,
                    external_remainder,
                    native_members,
                } => {
                    family_members_heap_bytes(members, external_remainder.as_ref())
                        + std::mem::size_of_val(native_members.as_ref())
                }
                DispatchFamilyProof::Complete(membership) => membership.retained_heap_bytes(),
            }
    }

    pub fn retained_artifacts(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        let receipt_bytes = self.membership().map_or(0, |membership| {
            let receipt = &membership.receipt;
            let bytes = family_receipt_bytes(receipt);
            census.allocation(std::sync::Arc::as_ptr(receipt) as usize, bytes);
            bytes
        });
        census.allocation(
            self as *const Self as usize,
            self.retained_bytes() - receipt_bytes,
        );
        census.procedure(self.call.procedure());
        for input in &self.inputs {
            if let DispatchFamilyMemberBody::Materialized(body) = &input.body {
                census.procedure(body);
            }
        }
        if let Some(membership) = self.membership() {
            membership.retained_artifacts(census);
        }
    }
}
/// Structured identity supplied by a language resolver for an external
/// callee whose body is outside the indexed workspace.
///
/// This is deliberately not a semantic procedure target: it carries only the
/// language, owner, and member that the resolver proved. Call-shape facts
/// such as effective arity and receiver binding remain in the resolver's exact
/// external-call proof and are required before an unmaterialized semantic
/// locator can be minted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolverOwnedExternalCalleeIdentity {
    language: Language,
    owner_fqn: Box<str>,
    member: Box<str>,
}

impl ResolverOwnedExternalCalleeIdentity {
    /// Owned owner and member text, for retention accounting.
    #[doc(hidden)]
    pub fn retained_heap_bytes(&self) -> usize {
        let Self {
            language: _,
            owner_fqn,
            member,
        } = self;
        brokk_bifrost_core::allocation_size::allocation_size(owner_fqn.len())
            + brokk_bifrost_core::allocation_size::allocation_size(member.len())
    }

    /// Construct a validated resolver-owned identity. An identity with an
    /// empty owner/member or an unsupported `None` language is not evidence
    /// that can cross the resolver boundary.
    #[doc(hidden)]
    pub fn new(
        language: Language,
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
    ) -> Self {
        let owner_fqn = owner_fqn.into();
        let member = member.into();
        assert!(language != Language::None);
        assert!(!owner_fqn.is_empty());
        assert!(!member.is_empty());
        Self {
            language,
            owner_fqn,
            member,
        }
    }

    pub const fn language(&self) -> Language {
        self.language
    }

    pub fn owner_fqn(&self) -> &str {
        &self.owner_fqn
    }

    pub fn member(&self) -> &str {
        &self.member
    }

    pub(crate) fn matches_unmaterialized_external_target(
        &self,
        target: &UnmaterializedExternalTarget,
    ) -> bool {
        // A direct Python class call keeps its class identity while the
        // initializer target supplies the active constructor formals.
        let exact_callee = self.language == target.language().language()
            && self.owner_fqn.as_ref() == target.owner_fqn()
            && self.member.as_ref() == target.member();
        let python_constructor = self.language == Language::Python
            && target.language().language() == Language::Python
            && target.has_resolver_owned_call_shape()
            && target.has_receiver()
            && target.member() == "__init__"
            && (target.owner_fqn() == format!("{}.{}", self.owner_fqn, self.member)
                || target.python_constructor_class.as_deref()
                    == Some(format!("{}.{}", self.owner_fqn, self.member).as_str()));
        exact_callee || python_constructor
    }
}

/// Why one boundary remains partial despite a proven target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchBoundaryPartialCause {
    ExternalBodyUnavailable,
}

impl DispatchBoundaryPartialCause {
    pub const LABELS: &'static [&'static str] = &["external_body_unavailable"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ExternalBodyUnavailable => "external_body_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchBoundary {
    pub kind: DispatchBoundaryKind,
    /// Resolver-owned owner/member identity for an external callee. This is
    /// intentionally independent of [`ExactExternalCallProof`]: it can name
    /// an external demand even when call-shape evidence is insufficient to
    /// mint a semantic procedure target.
    pub external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
    /// Exact resolver-owned metadata for a named procedure whose body is not
    /// materialized in the workspace. This remains absent when dispatch lacks
    /// any one of the exact artifact, declaration, symbol, receiver, or formal
    /// parameter facts required to bind an external procedure summary.
    pub exact_external_target: Option<ExactExternalProcedureTarget>,
    /// Canonical identity for a fully-qualified external callee that never
    /// materializes to any artifact (a JDK method such as
    /// `java.net.URLDecoder.decode`). It carries the synthetic locator named by
    /// `External(Some(_))` plus the owner FQN, member, arity, and receiver shape
    /// that let an activated authored summary bind by identity (#1978). It is
    /// mutually exclusive with `exact_external_target`.
    pub unmaterialized_external_target: Option<UnmaterializedExternalTarget>,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    /// A typed cause only; a consumer must separately prove its discharge.
    pub partial_cause: Option<DispatchBoundaryPartialCause>,
    pub provenance: Box<[OracleRelationHandle]>,
}

impl DispatchBoundary {
    /// Sufficient borrowed content correspondence; grants no admission authority.
    /// Executable handles retain their exact artifact and interpretation equality.
    #[doc(hidden)]
    fn has_same_content_by(
        &self,
        other: &Self,
        same_relation: &impl Fn(&OracleRelationHandle, &OracleRelationHandle) -> bool,
    ) -> bool {
        let Self {
            kind: l_kind,
            external_callee_identity: l_external_callee_identity,
            exact_external_target: l_exact_external_target,
            unmaterialized_external_target: l_unmaterialized_external_target,
            proof: l_proof,
            completeness: l_completeness,
            partial_cause: l_partial_cause,
            provenance: l_provenance,
        } = self;
        let Self {
            kind: r_kind,
            external_callee_identity: r_external_callee_identity,
            exact_external_target: r_exact_external_target,
            unmaterialized_external_target: r_unmaterialized_external_target,
            proof: r_proof,
            completeness: r_completeness,
            partial_cause: r_partial_cause,
            provenance: r_provenance,
        } = other;

        l_kind == r_kind
            && l_external_callee_identity == r_external_callee_identity
            && l_exact_external_target == r_exact_external_target
            && l_unmaterialized_external_target == r_unmaterialized_external_target
            && l_proof == r_proof
            && l_completeness == r_completeness
            && l_partial_cause == r_partial_cause
            && l_provenance.len() == r_provenance.len()
            && l_provenance
                .iter()
                .zip(r_provenance.iter())
                .all(|(a, b)| same_relation(a, b))
    }
}

impl DispatchBoundary {
    /// Owned metadata only; the caller accounts for this inline boundary.
    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        if let Some(locator) = self.target_locator() {
            census.locator(locator);
        }
        if let Some(identity) = &self.external_callee_identity {
            census.owned_slice(identity.owner_fqn.as_bytes());
            census.owned_slice(identity.member.as_bytes());
        }
        if let Some(target) = &self.exact_external_target {
            target.retained_artifacts(census);
        }
        if let Some(target) = &self.unmaterialized_external_target {
            target.retained_heap(census);
        }
        if let ProofStatus::Unproven(reason) = &self.proof {
            census.owned_slice(reason.as_bytes());
        }
        if let EvidenceCompleteness::Partial(reason) = &self.completeness {
            census.owned_slice(reason.as_bytes());
        }
        if census.owned_slice(&self.provenance) {
            for relation in &self.provenance {
                relation.retained_artifacts(census);
            }
        }
    }

    #[doc(hidden)]
    pub fn target_locator(&self) -> Option<&SemanticLocator> {
        self.kind.target_locator()
    }

    pub fn exact_external_target(&self) -> Option<&ExactExternalProcedureTarget> {
        self.exact_external_target.as_ref()
    }

    /// The canonical identity of a fully-qualified external callee that never
    /// materializes to an artifact, present only when this boundary carries one
    /// (#1978).
    pub fn unmaterialized_external_target(&self) -> Option<&UnmaterializedExternalTarget> {
        self.unmaterialized_external_target.as_ref()
    }

    /// Resolver-owned external owner/member identity, when the external
    /// boundary has one. This never implies an exact semantic procedure.
    pub fn external_callee_identity(&self) -> Option<&ResolverOwnedExternalCalleeIdentity> {
        self.external_callee_identity.as_ref()
    }

    /// Return the receiver shape proved independently of an external body.
    ///
    /// Boundary completeness describes whether the callee body is available.
    /// Receiver shape has separate authority and qualifies only when the
    /// resolver supplied it from an exact declaration owner or explicitly on
    /// an unmaterialized target. Ordinary synthetic targets prove no shape.
    pub fn proven_external_receiver_shape(&self) -> Option<bool> {
        if !matches!(self.proof, ProofStatus::Proven) {
            return None;
        }
        match (
            &self.kind,
            &self.exact_external_target,
            &self.unmaterialized_external_target,
        ) {
            (DispatchBoundaryKind::Unmaterialized(locator), Some(target), None)
                if locator == target.procedure()
                    && target.artifact().language() == SemanticLanguage::Standard(Language::Go) =>
            {
                Some(target.has_receiver())
            }
            (DispatchBoundaryKind::External(Some(locator)), None, Some(target))
                if locator == target.locator() && target.has_resolver_owned_call_shape() =>
            {
                Some(target.has_receiver())
            }
            _ => None,
        }
    }

    /// Validate one retained boundary independently of the dispatch result
    /// that originally sealed it.
    ///
    /// ICFG providers retain boundaries after consuming dispatch candidates,
    /// so this exact-call check is the shared trust boundary for those
    /// provider-owned rows.
    #[doc(hidden)]
    pub fn validate_for_call(&self, call: &CallSiteHandle) -> Result<(), OracleContractError> {
        if self.partial_cause == Some(DispatchBoundaryPartialCause::ExternalBodyUnavailable)
            && (!matches!(self.kind, DispatchBoundaryKind::External(Some(_)))
                || self.unmaterialized_external_target.is_none()
                || self.proof != ProofStatus::Proven
                || !matches!(self.completeness, EvidenceCompleteness::Partial(_)))
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let external_identity_is_valid = match (
            &self.external_callee_identity,
            &self.kind,
            &self.exact_external_target,
            &self.unmaterialized_external_target,
        ) {
            (None, _, _, _) => true,
            (Some(_), DispatchBoundaryKind::External(_), None, None) => true,
            (Some(identity), DispatchBoundaryKind::External(_), None, Some(target)) => {
                identity.matches_unmaterialized_external_target(target)
            }
            _ => false,
        };
        if !external_identity_is_valid {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let exact_target_is_valid = match (
            &self.kind,
            &self.exact_external_target,
            &self.unmaterialized_external_target,
        ) {
            (DispatchBoundaryKind::Unmaterialized(locator), Some(target), None) => {
                locator == target.procedure()
                    && call
                        .procedure()
                        .semantics()
                        .call_site(call.id())
                        .is_some_and(|row| {
                            call_receiver_admits_target(
                                row.receiver.is_some(),
                                target.has_receiver(),
                                target.procedure().language(),
                            )
                        })
            }
            // #1978: a fully-qualified unmaterialized external callee names its
            // synthetic locator through `External(Some(_))` and carries its
            // canonical identity, but never a materialized `exact_external_target`.
            (DispatchBoundaryKind::External(Some(locator)), None, Some(target)) => {
                locator == target.locator()
                    && call
                        .procedure()
                        .semantics()
                        .call_site(call.id())
                        .is_some_and(|row| {
                            // Resolver-owned call shape is authoritative. For
                            // Go, syntax-only lowering can retain a package
                            // qualifier as a receiver; for JS/TS, a direct named
                            // import proves that the package owner is not a
                            // receiver written at the call. Ordinary synthetic
                            // targets still have to match the lowered shape.
                            target.has_resolver_owned_call_shape()
                                || call_receiver_admits_target(
                                    normalized_external_has_receiver(
                                        row.receiver.is_some(),
                                        target.language(),
                                        target.owner_fqn(),
                                        target.normalized_static_owner(),
                                    ),
                                    target.has_receiver(),
                                    target.language(),
                                )
                        })
            }
            (_, None, None) => true,
            _ => false,
        };
        if !exact_target_is_valid {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let owner = OracleRelationOwner::Dispatch(call.clone());
        let Some(first) = self.provenance.first() else {
            return Err(OracleContractError::InvalidRelationIdentity);
        };
        let mut seen = std::collections::HashSet::new();
        if self.provenance.iter().any(|relation| {
            relation.owner() != &owner
                || relation.record().kind() != OracleRelationKind::DispatchBoundary
                || !relation.record().identifies_dispatch_boundary(&self.kind)
                || relation.record().evidence().is_empty()
                || !first.same_arena(relation)
                || !seen.insert(relation.clone())
        }) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        if self.provenance.iter().any(|relation| {
            !relation
                .record()
                .supports_quality(&self.proof, &self.completeness)
        }) {
            return Err(OracleContractError::InvalidRelationQuality);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResult {
    candidates: Box<[DispatchCandidate]>,
    boundaries: Box<[DispatchBoundary]>,
    coverage: CandidateCoverage,
    complete_receiver_hint_refinable: bool,
    resolver_proved_no_callee: bool,
    returned_callable: Option<Box<ReturnedCallableProvenance>>,
    argument_callable: Option<Box<ArgumentCallableProvenance>>,
    stable_package_values: Box<[StablePackageValueProvenance]>,
    member_field_anchor: Option<crate::analyzer::semantic::SourceAnchor>,
    member_receiver_preparation: Option<crate::analyzer::semantic::MemberReceiverPreparation>,
    family: Option<Box<DispatchFamilyEvidence>>,
    receiver_family_open: bool,
}

pub(crate) struct DispatchResultParts {
    pub candidates: Box<[DispatchCandidate]>,
    pub boundaries: Box<[DispatchBoundary]>,
    pub coverage: CandidateCoverage,
    pub family: Option<Box<DispatchFamilyEvidence>>,
}

impl DispatchResult {
    /// Sufficient borrowed content correspondence; grants no admission authority.
    /// Executable handles retain their exact artifact and interpretation equality.
    #[doc(hidden)]
    pub fn has_same_content(&self, other: &Self) -> bool {
        let Self {
            candidates: l_candidates,
            boundaries: l_boundaries,
            coverage: l_coverage,
            complete_receiver_hint_refinable: l_complete_receiver_hint_refinable,
            resolver_proved_no_callee: l_resolver_proved_no_callee,
            returned_callable: l_returned_callable,
            argument_callable: l_argument_callable,
            stable_package_values: l_stable_package_values,
            member_field_anchor: l_member_field_anchor,
            member_receiver_preparation: l_member_receiver_preparation,
            family: l_family,
            receiver_family_open: l_receiver_family_open,
        } = self;
        let Self {
            candidates: r_candidates,
            boundaries: r_boundaries,
            coverage: r_coverage,
            complete_receiver_hint_refinable: r_complete_receiver_hint_refinable,
            resolver_proved_no_callee: r_resolver_proved_no_callee,
            returned_callable: r_returned_callable,
            argument_callable: r_argument_callable,
            stable_package_values: r_stable_package_values,
            member_field_anchor: r_member_field_anchor,
            member_receiver_preparation: r_member_receiver_preparation,
            family: r_family,
            receiver_family_open: r_receiver_family_open,
        } = other;
        let left = self.first_provenance();
        let right = other.first_provenance();
        if !match (left, right) {
            (None, None) => true,
            (Some(a), Some(b)) => a.has_same_arena_content(b),
            _ => false,
        } {
            return false;
        }
        let same_relation = |a: &OracleRelationHandle, b: &OracleRelationHandle| match (left, right)
        {
            (Some(l), Some(r)) => a.same_arena(l) && b.same_arena(r) && a.id() == b.id(),
            _ => false,
        };
        l_candidates.len() == r_candidates.len()
            && l_candidates
                .iter()
                .zip(r_candidates.iter())
                .all(|(a, b)| a.has_same_content_by(b, &same_relation))
            && l_boundaries.len() == r_boundaries.len()
            && l_boundaries
                .iter()
                .zip(r_boundaries.iter())
                .all(|(a, b)| a.has_same_content_by(b, &same_relation))
            && l_coverage == r_coverage
            && l_complete_receiver_hint_refinable == r_complete_receiver_hint_refinable
            && l_resolver_proved_no_callee == r_resolver_proved_no_callee
            && l_returned_callable == r_returned_callable
            && match (l_argument_callable, r_argument_callable) {
                (None, None) => true,
                (Some(a), Some(b)) => a.has_same_content(b),
                _ => false,
            }
            && l_stable_package_values == r_stable_package_values
            && l_member_field_anchor == r_member_field_anchor
            && l_member_receiver_preparation == r_member_receiver_preparation
            // Family premises are published content: compare their digest.
            && l_family == r_family
            && l_receiver_family_open == r_receiver_family_open
    }
}

impl DispatchResult {
    /// Publish a dispatch answer only after every retained arm has resolvable,
    /// call-scoped provenance from one finite relation arena.
    pub fn new(
        call: &CallSiteHandle,
        candidates: Vec<DispatchCandidate>,
        boundaries: Vec<DispatchBoundary>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        let mut boundaries = boundaries;
        for boundary in &mut boundaries {
            let count = boundary
                .exact_external_target()
                .map(|target| target.receiver_adjustments().len())
                .or_else(|| {
                    boundary
                        .unmaterialized_external_target()
                        .map(|target| target.receiver_adjustments.len())
                })
                .unwrap_or(0);
            let limit = crate::analyzer::store::language_support::MAX_EXPLICIT_RECEIVER_STEPS;
            if count > limit {
                return Err(OracleContractError::LimitExceeded {
                    dimension: "receiver_adjustment_steps",
                    limit,
                    attempted: count,
                });
            }
            if let Some(target) = &mut boundary.exact_external_target
                && !target.receiver_adjustments().is_empty()
            {
                target.receiver_adjustment_call =
                    Some(crate::analyzer::semantic_model::receiver_adjustment_call_identity(call));
            }
            if let Some(target) = &mut boundary.unmaterialized_external_target
                && !target.receiver_adjustments.is_empty()
            {
                target.receiver_adjustment_call =
                    Some(crate::analyzer::semantic_model::receiver_adjustment_call_identity(call));
            }
        }
        let mut unique_targets = std::collections::HashSet::new();
        if candidates
            .iter()
            .any(|candidate| !unique_targets.insert(candidate.target.clone()))
        {
            return Err(OracleContractError::DuplicateDispatchTarget);
        }
        if candidates.len() > limits.dispatch_targets() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "dispatch_targets",
                limit: limits.dispatch_targets(),
                attempted: candidates.len(),
            });
        }
        let mut result = Self {
            candidates: candidates.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
            coverage,
            complete_receiver_hint_refinable: false,
            resolver_proved_no_callee: false,
            returned_callable: None,
            argument_callable: None,
            stable_package_values: Box::new([]),
            member_field_anchor: None,
            member_receiver_preparation: None,
            family: None,
            receiver_family_open: false,
        };
        let has_unresolved = result.boundaries.iter().any(|boundary| {
            matches!(
                boundary.kind,
                DispatchBoundaryKind::Unresolved | DispatchBoundaryKind::HierarchyUnenumerated
            )
        });
        let has_truncated = result
            .boundaries
            .iter()
            .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Truncated));
        if (has_unresolved && coverage == CandidateCoverage::Exhaustive)
            || (has_truncated && coverage != CandidateCoverage::Truncated)
        {
            return Err(OracleContractError::InconsistentCoverage);
        }
        result.validate_provenance_for_call(call, false)?;
        validate_retained_relation_arenas(
            result
                .candidates
                .iter()
                .flat_map(|candidate| candidate.provenance.iter())
                .chain(
                    result
                        .boundaries
                        .iter()
                        .flat_map(|boundary| boundary.provenance.iter()),
                ),
            limits,
        )?;
        for candidate in &mut result.candidates {
            candidate.seal();
        }
        Ok(result)
    }

    /// Visit this borrowed payload's owned children; its enclosing owner pays
    /// the inline DispatchResult storage.
    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut impl crate::analyzer::semantic::service::ArtifactRetentionVisitor,
    ) {
        if let Some(family) = &self.family {
            family.retained_artifacts(census);
        }
        if census.owned_slice(&self.candidates) {
            for candidate in self.candidates() {
                candidate.retained_artifacts(census);
            }
        }
        if census.owned_slice(&self.boundaries) {
            for boundary in self.boundaries() {
                boundary.retained_artifacts(census);
            }
        }
        if let Some(returned) = self.returned_callable.as_deref()
            && census.owned_box(returned)
        {
            returned.retained_artifacts(census);
        }
        if let Some(argument) = self.argument_callable.as_deref()
            && census.owned_box(argument)
        {
            argument.retained_artifacts(census);
        }
        if census.owned_slice(&self.stable_package_values) {
            for value in self.stable_package_values() {
                value.retained_artifacts(census);
            }
        }
        // member_field_anchor and member_receiver_preparation are inline IDs
        // and a payload-free enum; coverage and the refinement flags are inline.
    }

    pub fn candidates(&self) -> &[DispatchCandidate] {
        &self.candidates
    }

    pub fn boundaries(&self) -> &[DispatchBoundary] {
        &self.boundaries
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn family(&self) -> Option<&DispatchFamilyEvidence> {
        self.family.as_deref()
    }

    /// The sealed family when this answer's only weakness is runtime
    /// selection among its fully enumerated arms (#11296): every candidate is
    /// one materialized member with complete own evidence, and the family
    /// accounts for every boundary. Each candidate stays an Unproven
    /// may-target; only a consumer that analyzes every arm for one subject
    /// may use this, and it must still reject cancelled or budget-limited
    /// enclosing outcomes.
    #[doc(hidden)]
    pub fn analyzed_family(&self) -> Option<&DispatchFamilyEvidence> {
        let family = self.family.as_deref()?;
        let membership = family.membership()?;
        let bodies = family
            .inputs
            .iter()
            .filter_map(|input| match &input.body {
                DispatchFamilyMemberBody::Materialized(body) => Some(body),
                _ => None,
            })
            .collect::<Vec<_>>();
        (membership.external_remainder().is_none()
            && family.arms_complete()
            && bodies.len() == self.candidates.len()
            && self
                .candidates
                .iter()
                .all(|candidate| bodies.contains(&&candidate.target))
            && self
                .boundaries
                .iter()
                .all(|boundary| family.discharges(boundary)))
        .then_some(family)
    }

    /// The producer supplies the full declaration inventory independently of
    /// materialization. Equality checks both that inventory and every retained
    /// body, so neither a missing member nor a projection cap can seal a subset.
    pub(crate) fn stage_family(
        &mut self,
        call: &CallSiteHandle,
        mut inventory: Vec<SemanticLocator>,
        mut inputs: Vec<DispatchFamilyMemberInput>,
        external_remainder: Option<DispatchFamilyExternalRemainder>,
        native_members: Vec<crate::analyzer::CodeUnit>,
        enumeration_complete: bool,
    ) {
        inventory.sort();
        inventory.dedup();
        inputs.sort_by(|left, right| left.declaration.cmp(&right.declaration));
        let input_inventory = inputs
            .iter()
            .map(|input| input.declaration.clone())
            .collect::<Vec<_>>();
        let mut input_bodies = inputs
            .iter()
            .filter_map(|input| match &input.body {
                DispatchFamilyMemberBody::Materialized(body) => Some(body.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        input_bodies
            .sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        let mut bodies = self
            .candidates
            .iter()
            .map(|candidate| candidate.target().clone())
            .collect::<Vec<_>>();
        bodies.sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        let proof =
            if enumeration_complete && inventory == input_inventory && input_bodies == bodies {
                let members = inputs
                    .iter()
                    .filter(|input| input.body != DispatchFamilyMemberBody::AbstractDeclaration)
                    .map(|input| input.declaration.clone())
                    .collect::<Vec<_>>()
                    .into_boxed_slice();
                DispatchFamilyProof::Pending {
                    members,
                    external_remainder,
                    native_members: native_members.into_boxed_slice(),
                }
            } else {
                DispatchFamilyProof::Unavailable
            };
        self.family = Some(Box::new(DispatchFamilyEvidence {
            call: call.clone(),
            inputs: inputs.into_boxed_slice(),
            proof,
        }));
    }

    pub(crate) fn without_family_authority(mut self) -> Self {
        // Pending family allocations were never admitted by the raw projection.
        // Dropping them keeps the public supplied-lookup seam authority-free.
        self.family = None;
        self
    }

    /// Whether this answer's open workspace-override guard is on a
    /// syntax-derived external receiver arm. A complete, uncertainty-free
    /// receiver hint may replace that arm; independent truncation stays
    /// ineligible for feedback.
    pub const fn complete_receiver_hint_refinable(&self) -> bool {
        self.complete_receiver_hint_refinable
    }

    pub(crate) fn mark_member_field_anchor(
        &mut self,
        anchor: Option<crate::analyzer::semantic::SourceAnchor>,
    ) {
        self.member_field_anchor = anchor;
    }

    pub const fn member_field_anchor(&self) -> Option<crate::analyzer::semantic::SourceAnchor> {
        self.member_field_anchor
    }

    pub(crate) fn mark_member_receiver_preparation(
        &mut self,
        preparation: Option<crate::analyzer::semantic::MemberReceiverPreparation>,
    ) {
        let selected_rust_method = matches!(self.candidates.as_ref(), [candidate]
            if self.coverage == CandidateCoverage::Exhaustive
                && self.boundaries.is_empty()
                && candidate.proof() == &ProofStatus::Proven
                && candidate.completeness() == &EvidenceCompleteness::Complete
                && candidate.receiver_owner_relation()
                    == crate::analyzer::semantic::ReceiverOwnerRelation::Direct
                && candidate.target().artifact().key().language()
                    == SemanticLanguage::Standard(Language::Rust)
                && candidate.target().semantics().kind() == ProcedureKind::Method);
        if self.proven_receiver_shape() != Some(true) && !selected_rust_method {
            return;
        }
        self.member_receiver_preparation = preparation;
        if let (Some(preparation), [candidate]) = (preparation, self.candidates.as_mut()) {
            candidate.mark_member_receiver_preparation(preparation);
        }
    }

    /// A Go interface call passes the value its interface boxes to whichever
    /// method the dynamic type selects. A pointer dynamic type lets that
    /// method write the object the caller's interface refers to, so the
    /// receiver is a reference. This does not depend on the selected
    /// implementation, so it holds while the family is still open.
    pub(crate) fn mark_go_interface_receiver_preparation(
        &mut self,
        preparation: Option<crate::analyzer::semantic::MemberReceiverPreparation>,
    ) {
        debug_assert!(matches!(
            preparation,
            None | Some(crate::analyzer::semantic::MemberReceiverPreparation::Reference)
        ));
        self.member_receiver_preparation = preparation;
        self.receiver_family_open = true;
        if let (Some(preparation), [candidate]) = (preparation, self.candidates.as_mut()) {
            candidate.mark_member_receiver_preparation(preparation);
        }
    }

    pub const fn member_receiver_preparation(
        &self,
    ) -> Option<crate::analyzer::semantic::MemberReceiverPreparation> {
        self.member_receiver_preparation
    }

    /// Whether the receiver preparation describes an open Go interface
    /// family rather than one selected method. It then says only that some
    /// implementation may write the boxed object; it does not prove which
    /// method runs or that the method receives the object by reference.
    pub const fn receiver_family_open(&self) -> bool {
        self.receiver_family_open
    }

    pub(crate) fn mark_complete_receiver_hint_refinable(&mut self) {
        debug_assert!(!self.coverage.is_exhaustive());
        self.complete_receiver_hint_refinable = true;
    }

    /// Whether the resolver proved this call expression names no callable
    /// target at all. A Go call whose callee is a declaration an activated
    /// model publishes, and which positive declaration facts rule out as an
    /// applicable function, is a conversion to a modeled type: there is no
    /// callee, so the empty target set is the complete answer rather than an
    /// unreached one.
    pub const fn resolver_proved_no_callee(&self) -> bool {
        self.resolver_proved_no_callee
    }

    /// The proven callable-result provenance of this answer, when the
    /// invocation's callee was proven to hold exactly one callable a producing
    /// call returned.
    pub fn returned_callable(&self) -> Option<&ReturnedCallableProvenance> {
        self.returned_callable.as_deref()
    }

    /// Exact candidate-specific callback argument proof, when established.
    pub fn argument_callable(&self) -> Option<&ArgumentCallableProvenance> {
        self.argument_callable.as_deref()
    }

    pub(crate) fn mark_argument_callable(&mut self, proof: ArgumentCallableProvenance) {
        assert_eq!(self.coverage, CandidateCoverage::Exhaustive);
        assert_eq!(self.candidates.len(), 1);
        assert_eq!(self.candidates[0].target(), proof.closure());
        assert!(self.argument_callable.is_none());
        self.argument_callable = Some(Box::new(proof));
    }

    /// Record the proof that this invocation's callee holds the exact callable
    /// the named producing call returned.
    pub(crate) fn mark_returned_callable(&mut self, provenance: ReturnedCallableProvenance) {
        debug_assert_eq!(
            self.coverage,
            CandidateCoverage::Exhaustive,
            "a proven returned callable is one complete target set"
        );
        debug_assert_eq!(
            self.candidates.len(),
            1,
            "a proven returned callable names exactly one dispatch target"
        );
        debug_assert!(
            self.returned_callable.is_none(),
            "one dispatch answer carries one returned-callable provenance"
        );
        self.returned_callable = Some(Box::new(provenance));
    }

    /// The proofs behind every candidate this answer reached through a stable
    /// package variable.
    pub fn stable_package_values(&self) -> &[StablePackageValueProvenance] {
        &self.stable_package_values
    }

    /// Record the census proofs for the candidates that dispatch reached
    /// through stable package variables.
    pub(crate) fn mark_stable_package_values(
        &mut self,
        provenance: Vec<StablePackageValueProvenance>,
    ) {
        debug_assert!(
            provenance.iter().all(|proof| self
                .candidates
                .iter()
                .any(|candidate| candidate.target == *proof.initializer())),
            "every stable package value names a retained dispatch candidate"
        );
        self.stable_package_values = provenance.into_boxed_slice();
    }

    pub(crate) fn mark_resolver_proved_no_callee(&mut self) {
        debug_assert_eq!(self.coverage, CandidateCoverage::Exhaustive);
        debug_assert!(
            self.candidates.is_empty() && self.boundaries.is_empty(),
            "a proven no-callee answer retains no dispatch arm"
        );
        self.resolver_proved_no_callee = true;
    }

    /// Return the receiver shape proved by one exhaustive dispatch result.
    ///
    /// A materialized Go target's procedure kind is declaration-owned: Go has
    /// methods and free functions but no static methods, so a complete proven
    /// candidate identifies receiver shape even when the receiver declaration
    /// itself is unnamed and therefore has no formal binding row. A modeled
    /// external target qualifies only when its boundary carries the equivalent
    /// resolver-owned shape. Mixed, partial, non-Go, or open target sets prove
    /// no shape.
    pub fn proven_receiver_shape(&self) -> Option<bool> {
        if self.coverage != CandidateCoverage::Exhaustive {
            return None;
        }
        if self.candidates.is_empty() {
            return match self.boundaries.as_ref() {
                [boundary] => boundary.proven_external_receiver_shape(),
                _ => None,
            };
        }
        if !self.boundaries.is_empty() {
            return None;
        }

        let shape = |candidate: &DispatchCandidate| {
            if !matches!(candidate.proof(), ProofStatus::Proven)
                || !matches!(candidate.completeness(), EvidenceCompleteness::Complete)
                || candidate.target().artifact().key().language()
                    != SemanticLanguage::Standard(Language::Go)
            {
                return None;
            }
            match candidate.target().semantics().kind() {
                ProcedureKind::Method => Some(true),
                ProcedureKind::Function | ProcedureKind::LocalFunction | ProcedureKind::Lambda => {
                    Some(false)
                }
                _ => None,
            }
        };
        let first = shape(self.candidates.first()?)?;
        self.candidates
            .iter()
            .all(|candidate| shape(candidate) == Some(first))
            .then_some(first)
    }

    pub(crate) fn into_parts(self) -> DispatchResultParts {
        DispatchResultParts {
            candidates: self.candidates,
            boundaries: self.boundaries,
            coverage: self.coverage,
            family: self.family,
        }
    }

    pub fn validate_for_call(&self, call: &CallSiteHandle) -> Result<(), OracleContractError> {
        self.validate_provenance_for_call(call, true)
    }

    /// Borrow this result's own provenance arena anchor, if it has relations.
    /// This identifies an owned arena only; it grants no content correspondence
    /// or admission authority for another result or a resealed candidate.
    #[doc(hidden)]
    pub fn relation_anchor(&self) -> Option<&OracleRelationHandle> {
        self.first_provenance()
    }

    fn first_provenance(&self) -> Option<&OracleRelationHandle> {
        self.candidates
            .iter()
            .flat_map(|candidate| candidate.provenance.iter())
            .chain(
                self.boundaries
                    .iter()
                    .flat_map(|boundary| boundary.provenance.iter()),
            )
            .next()
    }

    fn validate_provenance_for_call(
        &self,
        call: &CallSiteHandle,
        require_sealed_candidates: bool,
    ) -> Result<(), OracleContractError> {
        let owner = OracleRelationOwner::Dispatch(call.clone());
        let first = self.first_provenance();
        if require_sealed_candidates
            && self
                .candidates
                .iter()
                .any(|candidate| !candidate.is_sealed())
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let mut seen = std::collections::HashSet::new();
        for (relations, kind, proof, completeness) in self
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.provenance.as_ref(),
                    OracleRelationKind::DispatchCandidate,
                    &candidate.proof,
                    &candidate.completeness,
                )
            })
            .chain(self.boundaries.iter().map(|boundary| {
                (
                    boundary.provenance.as_ref(),
                    OracleRelationKind::DispatchBoundary,
                    &boundary.proof,
                    &boundary.completeness,
                )
            }))
        {
            validate_provenance_identity(relations, &owner, kind, first, &mut seen)?;
            validate_provenance_quality(relations, proof, completeness)?;
        }
        if self.candidates.iter().any(|candidate| {
            candidate.provenance.iter().any(|relation| {
                !relation
                    .record()
                    .identifies_dispatch_candidate(&candidate.target)
            })
        }) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        if self
            .boundaries
            .iter()
            .any(|boundary| boundary.validate_for_call(call).is_err())
        {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        Ok(())
    }
}

pub use crate::analyzer::store::active_models::UnmaterializedExternalTarget;

pub(crate) trait UnmaterializedExternalTargetEngineExt: Sized {
    fn with_selected_python_artifact(
        self,
        proof: &crate::analyzer::usages::get_definition::ExactExternalCallProof,
        arguments: &[SemanticCallArgument],
    ) -> Option<Self>;
}

impl UnmaterializedExternalTargetEngineExt for UnmaterializedExternalTarget {
    fn with_selected_python_artifact(
        mut self,
        proof: &crate::analyzer::usages::get_definition::ExactExternalCallProof,
        arguments: &[SemanticCallArgument],
    ) -> Option<Self> {
        assert!(self.resolver_owned_call_shape);
        assert_eq!(
            self.language(),
            SemanticLanguage::Standard(Language::Python)
        );
        let evidence = proof.python_runtime_artifact()?;
        let slots = proof
            .python_formal_slots()
            .expect("promoted Python proof retains its checked formal slots");
        let formal_parameter_count = u32::try_from(slots.len())
            .expect("checked Python formal slot count fits the summary contract");
        let defaulted_formals = slots
            .iter()
            .map(|slot| slot.default_range.is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let variadic_formals = slots
            .iter()
            .map(|slot| slot.variadic.is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let actual_to_formal = python_actual_to_formal_slots(arguments, slots);
        // Qualify the lookup anchor with checked artifact evidence. Identical
        // import spellings from different installations must coexist in a
        // summary set without sharing its target key.
        let mut artifact_key = b"bifrost.python-runtime-target.v2\0".to_vec();
        for component in [
            evidence.package.as_ref()?.name.as_bytes(),
            evidence.single_raw_sha256()?.as_bytes(),
            proof
                .python_model_manifest_sha256()
                .expect("promoted Python proof retains model applicability")
                .as_bytes(),
        ] {
            artifact_key.extend_from_slice(&(component.len() as u64).to_le_bytes());
            artifact_key.extend_from_slice(component);
        }
        let mut segments = self.locator.declaration().segments().to_vec();
        segments.insert(
            0,
            DeclarationSegment::named(
                crate::analyzer::semantic::ids::DeclarationSegmentKind::Namespace,
                format!(
                    "bifrost.python-artifact.{}",
                    crate::analyzer::canonical_hash::lower_hex_string(
                        &crate::analyzer::canonical_hash::sha256_bytes(&artifact_key)
                    )
                ),
                self.locator.anchor(),
                0,
            )
            .expect("artifact digest namespace is nonempty"),
        );
        self.locator = SemanticLocator::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            DeclarationLocator::new(segments).expect("qualified target preserves declaration"),
            self.locator.role(),
            self.locator.anchor(),
        );
        self.qualify_python_argument_mapping(formal_parameter_count, actual_to_formal.as_deref());
        self.selected_python_artifact = Some(evidence.clone());
        self.selected_python_model_manifest_sha256 =
            proof.python_model_manifest_sha256().map(Into::into);
        self.python_formal_call_shape = Some(PythonFormalCallShape {
            formal_parameter_count,
            defaulted_formals,
            variadic_formals,
            actual_to_formal,
        });
        self.call_arguments = Some(arguments.to_vec().into_boxed_slice());
        Some(self)
    }
}
