use super::super::ids::{
    DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, MemoryLocationId,
    SemanticArtifactKey, SemanticLanguage, SemanticLocator, SemanticRole, SourceAnchor,
    SourcePosition, SourceSpan, WorkspaceMountId, WorkspaceRelativePath,
};
use super::super::ir::{
    CallSiteHandle, CaptureBinding, EvidenceCompleteness, ProcedureHandle, ProcedureKind,
    ProofStatus, SemanticCallArgument, ValueHandle,
};
use super::error::OracleContractError;
use super::limits::OracleLimits;
use super::model::{DispatchBoundaryKind, OracleCallContext};
use super::relation::{
    CandidateCoverage, OracleRelationHandle, OracleRelationKind, OracleRelationOwner,
    collect_candidate_provenance, validate_provenance_identity, validate_provenance_quality,
    validate_retained_relation_arenas,
};
use crate::analyzer::languages::{LanguageSupport, language_support};
use crate::analyzer::semantic_model::SemanticModelActivationEvidence;
use crate::analyzer::usages::UsageHit;
use crate::analyzer::{CallableArity, CodeUnit, Language, SignatureMetadata};
use brokk_bifrost_core::path_utils::path_suffix_key;
use std::borrow::Cow;
use std::path::Path;

/// One materialized workspace target for an exact semantic call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchCandidate {
    pub(crate) target: ProcedureHandle,
    pub(crate) proof: ProofStatus,
    pub(crate) completeness: EvidenceCompleteness,
    pub(crate) native_incomplete_source_reason: Option<Box<str>>,
    pub(crate) provenance: Box<[OracleRelationHandle]>,
    pub(crate) excluded_targets: Box<[ProcedureHandle]>,
    sealed: bool,
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
    /// Construct a validated resolver-owned identity. An identity with an
    /// empty owner/member or an unsupported `None` language is not evidence
    /// that can cross the resolver boundary.
    pub(crate) fn new(
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

impl DispatchCandidate {
    /// Create a draft that becomes a candidate-specific query token only
    /// after validation by [`DispatchResult::new`].
    pub fn new<I>(
        target: ProcedureHandle,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        provenance: I,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleRelationHandle>,
    {
        Ok(Self {
            target,
            proof,
            completeness,
            native_incomplete_source_reason: None,
            provenance: collect_candidate_provenance(provenance, limits)?,
            excluded_targets: Box::new([]),
            sealed: false,
        })
    }

    pub fn target(&self) -> &ProcedureHandle {
        &self.target
    }

    pub fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }

    /// Retain call-binding authority from one incomplete native lookup that
    /// named exactly one source declaration. This only enables
    /// candidate-local rows; the candidate and dispatch remain unproven.
    pub(crate) fn with_unique_incomplete_native_source(mut self, reason: &str) -> Self {
        assert!(
            !self.sealed,
            "dispatch provenance is attached before sealing"
        );
        assert!(matches!(self.proof, ProofStatus::Unproven(_)));
        assert!(matches!(
            self.completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert!(!reason.is_empty(), "native incompleteness has a reason");
        self.proof = ProofStatus::Unproven(reason.into());
        self.completeness = EvidenceCompleteness::Partial(reason.into());
        self.native_incomplete_source_reason = Some(reason.into());
        self
    }

    pub(crate) fn unique_incomplete_native_source_reason(&self) -> Option<&str> {
        self.native_incomplete_source_reason.as_deref()
    }

    pub fn provenance(&self) -> &[OracleRelationHandle] {
        &self.provenance
    }

    /// Resolver candidates that a candidate-specific exact receiver proof
    /// excludes from this call.
    pub fn excluded_targets(&self) -> &[ProcedureHandle] {
        &self.excluded_targets
    }

    fn seal(&mut self) {
        self.sealed = true;
    }

    const fn is_sealed(&self) -> bool {
        self.sealed
    }

    pub(super) fn validate_for_call(
        &self,
        call: &CallSiteHandle,
    ) -> Result<(), OracleContractError> {
        if !self.is_sealed() || self.provenance.is_empty() {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        let owner = OracleRelationOwner::Dispatch(call.clone());
        let first = self.provenance.first();
        let mut seen = std::collections::HashSet::new();
        validate_provenance_identity(
            &self.provenance,
            &owner,
            OracleRelationKind::DispatchCandidate,
            first,
            &mut seen,
        )?;
        if self.provenance.iter().any(|relation| {
            !relation
                .record()
                .identifies_dispatch_candidate(&self.target)
        }) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        validate_provenance_quality(&self.provenance, &self.proof, &self.completeness)?;
        let mut excluded = std::collections::HashSet::new();
        if self.excluded_targets.iter().any(|target| {
            target == &self.target
                || target.artifact().key() != self.target.artifact().key()
                || !excluded.insert(target.durable_key())
        }) {
            return Err(OracleContractError::InvalidRelationIdentity);
        }
        Ok(())
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
    pub provenance: Box<[OracleRelationHandle]>,
}

impl DispatchBoundary {
    pub(crate) fn target_locator(&self) -> Option<&SemanticLocator> {
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
    pub(crate) fn validate_for_call(
        &self,
        call: &CallSiteHandle,
    ) -> Result<(), OracleContractError> {
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

/// Structured resolver output for one exact external procedure target.
///
/// The symbol and boundary shape are retained from analyzer metadata. Receiver
/// shape is derived from the exact declaration owner's structured scope and is
/// corroborated against the lowered call before construction. Clients must not
/// reconstruct either fact from the locator or source text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExactExternalProcedureTarget {
    artifact: SemanticArtifactKey,
    procedure: SemanticLocator,
    symbol: Box<str>,
    has_receiver: bool,
    formal_contract: ExactExternalFormalContract,
}

impl ExactExternalProcedureTarget {
    pub(crate) fn new(
        artifact: SemanticArtifactKey,
        procedure: SemanticLocator,
        symbol: impl Into<Box<str>>,
        has_receiver: bool,
        formal_contract: ExactExternalFormalContract,
    ) -> Option<Self> {
        let symbol = symbol.into();
        (procedure.role() == SemanticRole::Procedure
            && artifact.mount() == procedure.mount()
            && artifact.path() == procedure.path()
            && artifact.language() == procedure.language()
            && !symbol.is_empty())
        .then_some(Self {
            artifact,
            procedure,
            symbol,
            has_receiver,
            formal_contract,
        })
    }

    pub const fn artifact(&self) -> &SemanticArtifactKey {
        &self.artifact
    }

    pub const fn procedure(&self) -> &SemanticLocator {
        &self.procedure
    }

    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    pub const fn has_receiver(&self) -> bool {
        self.has_receiver
    }

    pub fn formal_contract(&self) -> &ExactExternalFormalContract {
        &self.formal_contract
    }

    pub fn parameter_count(&self) -> u32 {
        self.formal_contract.parameter_count()
    }
}

/// Structured formal information selected for an exact external procedure.
///
/// The contract is copied from [`SignatureMetadata`] before the target crosses
/// the semantic boundary. Consumers can therefore bind actual arguments and
/// distinguish overloads without parsing the display symbol or source text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExactExternalFormalContract {
    label: Box<str>,
    parameters: Box<[ExactExternalFormalParameter]>,
    arity: Option<CallableArity>,
}

impl ExactExternalFormalContract {
    pub(crate) fn from_metadata(metadata: &SignatureMetadata) -> Option<Self> {
        let parameter_types = metadata.callable_parameter_types();
        if parameter_types.is_some_and(|types| types.len() != metadata.parameters().len()) {
            return None;
        }
        let arity = metadata.callable_arity();
        let last_index = metadata.parameters().len().saturating_sub(1);
        let parameters = metadata
            .parameters()
            .iter()
            .enumerate()
            .map(|(index, parameter)| ExactExternalFormalParameter {
                label: parameter.label().into(),
                declared_type: parameter_types
                    .and_then(|types| types.get(index))
                    .map(String::as_str)
                    .map(Into::into),
                optional: arity.is_some_and(|arity| index >= arity.required()),
                repeated: arity.is_some_and(|arity| arity.is_repeated() && index == last_index),
            })
            .collect();
        Some(Self {
            label: metadata.label().into(),
            parameters,
            arity,
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn parameters(&self) -> &[ExactExternalFormalParameter] {
        &self.parameters
    }

    pub const fn arity(&self) -> Option<CallableArity> {
        self.arity
    }

    pub fn parameter_count(&self) -> u32 {
        u32::try_from(self.parameters.len())
            .expect("exact external formal parameter count exceeds u32")
    }
}

/// One parameter in an [`ExactExternalFormalContract`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExactExternalFormalParameter {
    label: Box<str>,
    declared_type: Option<Box<str>>,
    optional: bool,
    repeated: bool,
}

impl ExactExternalFormalParameter {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn declared_type(&self) -> Option<&str> {
        self.declared_type.as_deref()
    }

    pub const fn optional(&self) -> bool {
        self.optional
    }

    pub const fn repeated(&self) -> bool {
        self.repeated
    }
}

/// Canonical identity for a fully-qualified external callee that never
/// materializes to a workspace or classpath artifact, yet whose name lets an
/// activated authored procedure summary bind (#1978).
///
/// The match identity is `(language, owner FQN, member, arity, has_receiver)`.
/// Parameter types are unrecoverable for an unmaterialized callee, so same-arity
/// overloads that differ only by parameter type cannot be told apart here. The
/// synthetic `locator` -- and the provenance artifact key derived from it -- is
/// not a real source location; it only anchors the bound summary so the boundary
/// and the summary compare equal. The owner FQN and member are stored verbatim
/// so the summary lookup never has to re-parse the locator. Private call-shape
/// authority is validation evidence; authored summary lookup still uses only
/// the documented match identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnmaterializedExternalTarget {
    owner_fqn: Box<str>,
    member: Box<str>,
    arity: u32,
    has_receiver: bool,
    resolver_owned_call_shape: bool,
    normalized_static_owner: Option<Box<str>>,
    /// Exact JDK artifact selected for the Java source module and verified
    /// against the selected external declaration. Model and dispatch
    /// applicability still require separate proofs.
    selected_jdk_artifact: Option<SemanticModelActivationEvidence>,
    /// Exact PyPI distribution artifact selected for a Python external
    /// declaration by resolver-owned installed-artifact and active-profile
    /// evidence. Model and dispatch applicability still require separate
    /// proofs.
    selected_python_artifact: Option<SemanticModelActivationEvidence>,
    selected_python_model_manifest_sha256: Option<Box<str>>,
    /// Declaration formals from the checked Python defining binding. `arity`
    /// stays the actual call arity used by the locator alias.
    python_formal_call_shape: Option<PythonFormalCallShape>,
    /// Structured actuals from the exact semantic call. Summary formals use
    /// the shared call-binding slot matcher to produce one retained mapping.
    call_arguments: Option<Box<[SemanticCallArgument]>>,
    /// Constructed Python class whose inherited `__init__` this target binds.
    python_constructor_class: Option<Box<str>>,
    locator: SemanticLocator,
    python_formal_locator: Option<SemanticLocator>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PythonFormalCallShape {
    formal_parameter_count: u32,
    defaulted_formals: Box<[bool]>,
    variadic_formals: Box<[bool]>,
    // Formal ordinals for each actual, retained from structured call binding.
    actual_to_formal: Option<Box<[u32]>>,
}

impl PythonFormalCallShape {
    fn accepts_arity(&self, arity: u32) -> bool {
        if self.defaulted_formals.len() != self.formal_parameter_count as usize
            || self.variadic_formals.len() != self.formal_parameter_count as usize
        {
            return false;
        }
        let Some(mapping) = self.actual_to_formal.as_deref() else {
            return false;
        };
        if mapping.len() != arity as usize {
            return false;
        }
        let mut supplied = vec![false; self.formal_parameter_count as usize];
        for formal in mapping {
            let Some(bound) = supplied.get_mut(*formal as usize) else {
                return false;
            };
            if *bound && !self.variadic_formals[*formal as usize] {
                return false;
            }
            *bound = true;
        }
        supplied
            .iter()
            .zip(&self.defaulted_formals)
            .zip(&self.variadic_formals)
            .all(|((supplied, defaulted), variadic)| *supplied || *defaulted || *variadic)
    }
}

fn python_actual_to_formal_slots(
    arguments: &[SemanticCallArgument],
    slots: &[crate::analyzer::lexical_definitions::FormalParameterSlot],
) -> Option<Box<[u32]>> {
    if slots.iter().any(|slot| slot.unique_name().is_none()) {
        return None;
    }
    let layout = crate::analyzer::lexical_definitions::FormalParameterLayout {
        slots: slots.to_vec(),
        python_binding: None,
    };
    crate::analyzer::usages::call_binding::bind_semantic_call_arguments(arguments, &layout)
}

impl UnmaterializedExternalTarget {
    /// Construct a modeled external target from a language adapter's exact
    /// owner/member/receiver proof. The synthetic locator is provenance only;
    /// summary lookup still uses the structured identity carried by the target.
    /// Adapters should add their call-specific arguments when they have them.
    pub fn new_modeled(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        language: SemanticLanguage,
        arity: u32,
        has_receiver: bool,
    ) -> Option<Self> {
        let owner_fqn = owner_fqn.into();
        let member = member.into();
        let anchor = modeled_external_zero_source_anchor();
        let owner_segment =
            DeclarationSegment::named(DeclarationSegmentKind::Type, owner_fqn.clone(), anchor, 0)
                .ok()?;
        let member_kind = if has_receiver {
            DeclarationSegmentKind::Method
        } else {
            DeclarationSegmentKind::Function
        };
        let member_segment =
            DeclarationSegment::named(member_kind, member.clone(), anchor, arity).ok()?;
        let declaration = DeclarationLocator::new(vec![owner_segment, member_segment]).ok()?;
        let declaring_language = match language {
            SemanticLanguage::CppC => SemanticLanguage::Standard(Language::Cpp),
            other => other,
        };
        let locator = SemanticLocator::new(
            unmaterialized_external_mount(),
            unmaterialized_external_path(),
            declaring_language,
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        Some(Self::new_with_normalized_static_owner(
            owner_fqn,
            member,
            arity,
            has_receiver,
            None,
            locator,
        ))
    }

    pub(crate) fn new(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        arity: u32,
        has_receiver: bool,
        locator: SemanticLocator,
    ) -> Self {
        Self::new_with_normalized_static_owner(
            owner_fqn,
            member,
            arity,
            has_receiver,
            None,
            locator,
        )
    }

    pub(crate) fn new_with_normalized_static_owner(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        arity: u32,
        has_receiver: bool,
        normalized_static_owner: Option<Box<str>>,
        locator: SemanticLocator,
    ) -> Self {
        debug_assert_eq!(locator.role(), SemanticRole::Procedure);
        debug_assert!(is_unmaterialized_external_artifact_locator(&locator));
        let owner_fqn = owner_fqn.into();
        debug_assert!(
            normalized_static_owner
                .as_deref()
                .is_none_or(|owner| owner == owner_fqn.as_ref())
        );
        Self {
            owner_fqn,
            member: member.into(),
            arity,
            has_receiver,
            resolver_owned_call_shape: false,
            normalized_static_owner,
            selected_jdk_artifact: None,
            selected_python_artifact: None,
            selected_python_model_manifest_sha256: None,
            python_formal_call_shape: None,
            call_arguments: None,
            python_constructor_class: None,
            python_formal_locator: None,
            locator,
        }
    }

    /// Construct a target whose receiver and arity came from the exact source
    /// resolver rather than syntax-only semantic lowering.
    pub(in crate::analyzer::semantic) fn new_for_resolver_owned_call(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        arity: u32,
        has_receiver: bool,
        selected_jdk_artifact: Option<SemanticModelActivationEvidence>,
        locator: SemanticLocator,
    ) -> Self {
        let mut target = Self::new(owner_fqn, member, arity, has_receiver, locator);
        target.resolver_owned_call_shape = true;
        debug_assert!(
            selected_jdk_artifact.is_none()
                || target.language() == SemanticLanguage::Standard(Language::Java)
        );
        debug_assert!(selected_jdk_artifact.as_ref().is_none_or(|evidence| {
            evidence.language == "java"
                && evidence.ecosystem == "jdk"
                && evidence.artifact_sha256.is_some()
        }));
        target.selected_jdk_artifact = selected_jdk_artifact;
        target
    }

    pub fn selected_jdk_artifact(&self) -> Option<&SemanticModelActivationEvidence> {
        self.selected_jdk_artifact.as_ref()
    }

    pub fn selected_python_artifact(&self) -> Option<&SemanticModelActivationEvidence> {
        self.selected_python_artifact.as_ref()
    }

    pub(crate) fn with_python_constructor_class(
        mut self,
        class_qualified_name: impl Into<Box<str>>,
    ) -> Option<Self> {
        let class_qualified_name = class_qualified_name.into();
        if self.language().language() != Language::Python
            || self.member() != "__init__"
            || !self.has_receiver()
            || class_qualified_name.is_empty()
            || class_qualified_name == self.owner_fqn
        {
            return None;
        }
        self.python_constructor_class = Some(class_qualified_name);
        Some(self)
    }

    /// Carry exact Python distribution selection to a related modeled target
    /// while leaving its call shape to be established independently.
    pub(crate) fn with_python_artifact_selection_from(
        self,
        selected_from: Option<&Self>,
        arguments: &[SemanticCallArgument],
        formals: &[crate::analyzer::lexical_definitions::FormalParameterSlot],
    ) -> Option<Self> {
        let (evidence, manifest) = match selected_from.map(|selected_from| {
            (
                selected_from.selected_python_artifact.as_ref(),
                selected_from
                    .selected_python_model_manifest_sha256
                    .as_deref(),
            )
        }) {
            None => (None, None),
            Some((Some(evidence), Some(manifest))) => (Some(evidence), Some(manifest)),
            Some((None, None)) => (None, None),
            Some(_) => return None,
        };
        self.with_python_artifact_selection_and_call_shape(evidence, manifest, arguments, formals)
    }

    /// Attach artifact evidence selected from an exact active Python model
    /// declaration and bind this related call against that declaration's
    /// formals.
    pub(crate) fn with_python_artifact_selection(
        self,
        evidence: &SemanticModelActivationEvidence,
        manifest: &str,
        arguments: &[SemanticCallArgument],
        formals: &[crate::analyzer::lexical_definitions::FormalParameterSlot],
    ) -> Option<Self> {
        self.with_python_artifact_selection_and_call_shape(
            Some(evidence),
            Some(manifest),
            arguments,
            formals,
        )
    }

    fn with_python_artifact_selection_and_call_shape(
        mut self,
        evidence: Option<&SemanticModelActivationEvidence>,
        manifest: Option<&str>,
        arguments: &[SemanticCallArgument],
        formals: &[crate::analyzer::lexical_definitions::FormalParameterSlot],
    ) -> Option<Self> {
        assert_eq!(
            self.language(),
            SemanticLanguage::Standard(Language::Python)
        );
        let (evidence, manifest) = match (evidence, manifest) {
            (None, None) => (None, None),
            (Some(evidence), Some(manifest)) => {
                if evidence.language != "python"
                    || evidence.ecosystem != "python"
                    || evidence.package.is_none()
                    || evidence.artifact_sha256.is_none()
                    || manifest.is_empty()
                {
                    return None;
                }
                let mut artifact_key = b"bifrost.python-runtime-target.v2\0".to_vec();
                for component in [
                    evidence.package.as_ref()?.name.as_bytes(),
                    evidence.artifact_sha256.as_ref()?.as_bytes(),
                    manifest.as_bytes(),
                ] {
                    artifact_key.extend_from_slice(&(component.len() as u64).to_le_bytes());
                    artifact_key.extend_from_slice(component);
                }
                let mut segments = self.locator.declaration().segments().to_vec();
                segments.insert(
                    0,
                    DeclarationSegment::named(
                        super::super::ids::DeclarationSegmentKind::Namespace,
                        format!(
                            "bifrost.python-artifact.{}",
                            crate::analyzer::canonical_hash::lower_hex_string(
                                &crate::analyzer::canonical_hash::sha256_bytes(&artifact_key)
                            )
                        ),
                        self.locator.anchor(),
                        0,
                    )
                    .ok()?,
                );
                self.locator = SemanticLocator::new(
                    self.locator.mount(),
                    self.locator.path().clone(),
                    self.locator.language(),
                    DeclarationLocator::new(segments).ok()?,
                    self.locator.role(),
                    self.locator.anchor(),
                );
                (Some(evidence.clone()), Some(Box::<str>::from(manifest)))
            }
            _ => return None,
        };
        let formal_parameter_count = u32::try_from(formals.len()).ok()?;
        let defaulted_formals = formals
            .iter()
            .map(|formal| formal.default_range.is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let variadic_formals = formals
            .iter()
            .map(|formal| formal.variadic.is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let actual_to_formal = python_actual_to_formal_slots(arguments, formals);
        self.resolver_owned_call_shape = true;
        self.qualify_python_argument_mapping(formal_parameter_count, actual_to_formal.as_deref());
        self.selected_python_artifact = evidence;
        self.selected_python_model_manifest_sha256 = manifest;
        self.python_formal_call_shape = Some(PythonFormalCallShape {
            formal_parameter_count,
            defaulted_formals,
            variadic_formals,
            actual_to_formal,
        });
        self.call_arguments = Some(arguments.to_vec().into_boxed_slice());
        Some(self)
    }

    /// Copy Python applicability only from an exact call proof that was
    /// promoted with defining-binding and provider evidence.
    pub(in crate::analyzer::semantic) fn with_selected_python_artifact(
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
            evidence.artifact_sha256.as_ref()?.as_bytes(),
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
                super::super::ids::DeclarationSegmentKind::Namespace,
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

    pub(crate) fn with_call_arguments(mut self, arguments: &[SemanticCallArgument]) -> Self {
        self.call_arguments = Some(arguments.to_vec().into_boxed_slice());
        self
    }

    fn qualify_python_argument_mapping(
        &mut self,
        formal_parameter_count: u32,
        actual_to_formal: Option<&[u32]>,
    ) {
        self.python_formal_locator = Some(self.locator.clone());
        if let Some(mapping) = actual_to_formal {
            // Call-specific argument order is part of the target alias, while
            // the shared summary remains anchored to its formal declaration.
            let mut bytes = b"bifrost.python-call-mapping.v1\0".to_vec();
            bytes.extend_from_slice(&formal_parameter_count.to_le_bytes());
            for formal in mapping {
                bytes.extend_from_slice(&formal.to_le_bytes());
            }
            let mut segments = self.locator.declaration().segments().to_vec();
            segments.insert(
                0,
                DeclarationSegment::named(
                    super::super::ids::DeclarationSegmentKind::Namespace,
                    format!(
                        "bifrost.python-call-mapping.{}",
                        crate::analyzer::canonical_hash::lower_hex_string(
                            &crate::analyzer::canonical_hash::sha256_bytes(&bytes)
                        )
                    ),
                    self.locator.anchor(),
                    0,
                )
                .expect("mapping digest namespace is nonempty"),
            );
            self.locator = SemanticLocator::new(
                self.locator.mount(),
                self.locator.path().clone(),
                self.locator.language(),
                DeclarationLocator::new(segments).expect("mapped target preserves declaration"),
                self.locator.role(),
                self.locator.anchor(),
            );
        }
    }

    pub(crate) fn python_formal_parameter_count(&self) -> Option<u32> {
        self.python_formal_call_shape
            .as_ref()
            .map(|shape| shape.formal_parameter_count)
    }

    pub(crate) fn python_formal_call_shape_accepts_arity(&self, arity: u32) -> Option<bool> {
        self.python_formal_call_shape
            .as_ref()
            .map(|shape| shape.accepts_arity(arity))
    }

    pub(crate) fn call_arguments(&self) -> Option<&[SemanticCallArgument]> {
        self.call_arguments.as_deref()
    }

    pub(crate) fn python_actual_to_formal(&self) -> Option<&[u32]> {
        self.python_formal_call_shape
            .as_ref()
            .and_then(|shape| shape.actual_to_formal.as_deref())
    }

    pub(crate) fn python_defaulted_formals(&self) -> Option<&[bool]> {
        self.python_formal_call_shape
            .as_ref()
            .map(|shape| shape.defaulted_formals.as_ref())
    }

    pub(crate) fn formal_summary_locator(&self, arity: u32) -> SemanticLocator {
        let Some(formal) = &self.python_formal_locator else {
            return self.locator_for_arity(arity);
        };
        let mut target = self.clone();
        target.locator = formal.clone();
        target.locator_for_arity(arity)
    }

    pub(crate) fn selected_python_model_manifest_sha256(&self) -> Option<&str> {
        self.selected_python_model_manifest_sha256.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn with_python_model_manifest_for_test(mut self, manifest: &str) -> Self {
        self.selected_python_model_manifest_sha256 = Some(manifest.into());
        self
    }

    #[cfg(test)]
    pub(crate) fn with_selected_python_for_test(
        mut self,
        evidence: SemanticModelActivationEvidence,
    ) -> Self {
        assert_eq!(
            self.language(),
            SemanticLanguage::Standard(Language::Python)
        );
        self.resolver_owned_call_shape = true;
        self.selected_python_artifact = Some(evidence);
        self.python_formal_call_shape = Some(PythonFormalCallShape {
            formal_parameter_count: self.arity,
            defaulted_formals: vec![false; self.arity as usize].into_boxed_slice(),
            variadic_formals: vec![false; self.arity as usize].into_boxed_slice(),
            actual_to_formal: Some((0..self.arity).collect()),
        });
        self
    }

    #[cfg(test)]
    pub(crate) fn with_python_formal_shape_for_test(
        mut self,
        evidence: SemanticModelActivationEvidence,
        formal_parameter_count: u32,
        required_parameter_count: u32,
    ) -> Self {
        assert_eq!(
            self.language(),
            SemanticLanguage::Standard(Language::Python)
        );
        assert!(required_parameter_count <= formal_parameter_count);
        self.resolver_owned_call_shape = true;
        self.selected_python_artifact = Some(evidence);
        self.python_formal_call_shape = Some(PythonFormalCallShape {
            formal_parameter_count,
            defaulted_formals: (0..formal_parameter_count)
                .map(|formal| formal >= required_parameter_count)
                .collect(),
            variadic_formals: vec![false; formal_parameter_count as usize].into_boxed_slice(),
            actual_to_formal: Some((0..self.arity).collect()),
        });
        self
    }

    #[cfg(test)]
    pub(crate) fn with_python_mapping_for_test(mut self, mapping: Option<Vec<u32>>) -> Self {
        let count = self
            .python_formal_parameter_count()
            .expect("test has formal shape");
        self.qualify_python_argument_mapping(count, mapping.as_deref());
        self.python_formal_call_shape
            .as_mut()
            .expect("test has formal shape")
            .actual_to_formal = mapping.map(Vec::into_boxed_slice);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_selected_jdk_for_test(
        mut self,
        evidence: SemanticModelActivationEvidence,
    ) -> Self {
        assert_eq!(self.language(), SemanticLanguage::Standard(Language::Java));
        assert_eq!(evidence.ecosystem, "jdk");
        assert!(evidence.artifact_sha256.is_some());
        self.resolver_owned_call_shape = true;
        self.selected_jdk_artifact = Some(evidence);
        self
    }

    pub fn owner_fqn(&self) -> &str {
        &self.owner_fqn
    }

    pub fn member(&self) -> &str {
        &self.member
    }

    pub const fn arity(&self) -> u32 {
        self.arity
    }

    pub const fn has_receiver(&self) -> bool {
        self.has_receiver
    }

    /// Whether structured language resolution proved that this receiverless
    /// external call is statically selected. A resolver-owned proof has an
    /// exact owner, member, application, and arity, so a receiverless external
    /// callable cannot select an override.
    pub fn resolver_proves_static_call(&self) -> bool {
        if self.has_receiver {
            return false;
        }
        // A receiverless callee the resolver identified through an external
        // declaration and its exact call shape is a free function: nothing
        // dispatches it dynamically. C header functions and Rust external
        // crate functions use this proof; Python and Java also use it for
        // their resolver-owned imported declarations. C# type-qualified calls
        // use the same proof after the declaration overlay establishes that
        // the selected member is static.
        if self.resolver_owned_call_shape
            && matches!(
                self.language(),
                SemanticLanguage::Standard(
                    Language::CSharp
                        | Language::Cpp
                        | Language::Python
                        | Language::Java
                        | Language::Rust,
                )
            )
        {
            return true;
        }
        match self.language() {
            SemanticLanguage::Standard(Language::Java) => self
                .normalized_static_owner
                .as_deref()
                .is_some_and(|owner| owner == self.owner_fqn.as_ref()),
            _ => false,
        }
    }

    pub const fn has_resolver_owned_call_shape(&self) -> bool {
        self.resolver_owned_call_shape
    }

    pub(crate) fn normalized_static_owner(&self) -> Option<&str> {
        self.normalized_static_owner.as_deref()
    }

    pub fn language(&self) -> SemanticLanguage {
        self.locator.language()
    }

    /// The synthetic procedure locator that both the boundary (at solve time) and
    /// the bound summary (at discovery time) name, so the two compare equal.
    pub fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    /// Rebuild this canonical external declaration locator with a different
    /// structured arity. Variadic semantic targets use their total formal
    /// count for the summary's stable declaration identity while retaining the
    /// resolver's actual-arity locators as exact lookup aliases.
    pub fn locator_for_arity(&self, arity: u32) -> SemanticLocator {
        let mut segments = self.locator.declaration().segments().to_vec();
        let last = segments
            .pop()
            .expect("unmaterialized external locator has a member segment");
        debug_assert_eq!(last.name(), Some(self.member()));
        segments.push(
            DeclarationSegment::named(last.kind(), self.member(), last.anchor(), arity)
                .expect("unmaterialized external member name remains non-empty"),
        );
        SemanticLocator::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            DeclarationLocator::new(segments)
                .expect("unmaterialized external declaration remains non-empty"),
            SemanticRole::Procedure,
            self.locator.anchor(),
        )
    }

    /// Build the provenance artifact key that anchors the bound summary. It
    /// reuses the synthetic mount, path, and language of `locator` -- so
    /// `ExternalSummaryTarget::matches(self.locator())` succeeds -- and copies the
    /// caller-analysis validity fields from `template` so the bound summary's
    /// dependency fingerprint matches the active compatibility key.
    pub fn provenance_artifact_key(&self, template: &SemanticArtifactKey) -> SemanticArtifactKey {
        SemanticArtifactKey::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            template.revision(),
            template.adapter().clone(),
            template.ir_version(),
            template.configuration(),
            template.dependencies(),
        )
    }
}

fn modeled_external_zero_source_anchor() -> SourceAnchor {
    let position = SourcePosition::new(0, 0, 0);
    let span = SourceSpan::new(position, position).expect("zero-width sentinel span is ordered");
    SourceAnchor::new(span, 0)
}

/// Normalize the raw IR receiver shape at the external-summary identity
/// boundary.
///
/// Java intentionally retains a value row for every method-invocation object,
/// including a type qualifier. A qualifier is not a semantic receiver, so the
/// exact resolver may prove its canonical owner here. The equality guard keeps
/// that proof target-specific; every other language and every Java value
/// receiver preserves the raw IR shape.
/// Whether a call's receiver shape admits a target's.
///
/// A target that declares a receiver needs one at the call site. A target
/// without one ordinarily forbids one, because a receiver the lowering
/// recorded is evidence the callee was reached through a value, and binding
/// that to a receiver-less target is a mis-resolution worth failing on. Go
/// relies on exactly that: `db.Open()` records `db` as a receiver, and only a
/// resolver-owned package proof may bind it to a package function.
///
/// Python is the exception. Its attribute syntax is uniform, so a recorded
/// receiver distinguishes nothing: `text.maketrans(...)` reaches a static
/// member through an instance and `os.path.join(...)` reaches a module
/// function through its qualifier, and the lowering records a receiver for
/// both.
pub(crate) fn call_receiver_admits_target(
    call_has_receiver: bool,
    target_has_receiver: bool,
    language: SemanticLanguage,
) -> bool {
    if target_has_receiver {
        return call_has_receiver;
    }
    !call_has_receiver || language.language() == Language::Python
}

pub(crate) fn normalized_external_has_receiver(
    raw_has_receiver: bool,
    language: SemanticLanguage,
    owner_fqn: &str,
    normalized_static_owner: Option<&str>,
) -> bool {
    raw_has_receiver
        && !(matches!(language.language(), Language::Java | Language::CSharp)
            && normalized_static_owner.is_some_and(|owner| owner == owner_fqn))
}

/// Stable sentinel mount for synthetic unmaterialized-external identities. The
/// mount and path are provenance only; both the boundary locator and the bound
/// summary artifact key use them, so the two compare equal (#1978).
pub(crate) fn unmaterialized_external_mount() -> WorkspaceMountId {
    WorkspaceMountId::hash_bytes(b"bifrost.unmaterialized-external.mount.v1")
}

/// Stable sentinel provenance path for synthetic unmaterialized externals.
pub(crate) fn unmaterialized_external_path() -> WorkspaceRelativePath {
    WorkspaceRelativePath::new("bifrost-unmaterialized-external")
        .expect("static sentinel path is portable")
}

/// Whether `key` is the synthetic provenance artifact of an unmaterialized
/// external target rather than a real materialized artifact (#1978).
pub fn is_unmaterialized_external_artifact(key: &SemanticArtifactKey) -> bool {
    is_unmaterialized_external_identity(key.mount(), key.path())
}

/// Whether `locator` is one of the structured synthetic procedure identities
/// emitted for an unmaterialized external target (#1978).
pub fn is_unmaterialized_external_artifact_locator(locator: &SemanticLocator) -> bool {
    locator.role() == SemanticRole::Procedure
        && is_unmaterialized_external_identity(locator.mount(), locator.path())
}

fn is_unmaterialized_external_identity(
    mount: WorkspaceMountId,
    path: &WorkspaceRelativePath,
) -> bool {
    mount == unmaterialized_external_mount() && *path == unmaterialized_external_path()
}

/// Split a resolved or authored qualified callee symbol into `(owner FQN,
/// member)`. It strips an optional trailing parameter list, then splits the
/// final dotted segment as the member. It returns `None` when no owner qualifier
/// is present. The parameter types are intentionally discarded: an unmaterialized
/// callee cannot recover them, so the canonical identity never depends on them
/// (#1978). This reads a resolved or authored call-target string, not a
/// `CodeUnit` name accessor, so it does not re-infer declaration structure.
pub fn split_qualified_member(symbol: &str) -> Option<(&str, &str)> {
    let without_parameters = callable_symbol_head(symbol);
    let (owner, member) = without_parameters.rsplit_once('.')?;
    (!owner.is_empty() && !member.is_empty()).then_some((owner.trim(), member.trim()))
}

/// A callee symbol without its optional trailing parameter list. The parameter
/// types never enter a canonical identity, so every reader of an authored or
/// resolved symbol cuts them off the same way (#1978).
fn callable_symbol_head(symbol: &str) -> &str {
    symbol.split_once('(').map_or(symbol, |(head, _tail)| head)
}

/// The owner identity of a module-level declaration: the declaring file's
/// workspace-relative path with its extension removed, rendered slash-canonical
/// (#2610).
///
/// A module-level function in JavaScript, TypeScript, PHP without a namespace,
/// or Ruby has no owner segment in its fully-qualified name and no package, so
/// nothing in the name alone can qualify it. Its module is what does: `src/run`
/// for `src/run.ts`. The rendering reads [`Path`] components rather than the
/// platform path string, so a Windows workspace and a Unix one publish the same
/// owner for the same file, and an authored `path` and a workspace declaration
/// meet on one spelling.
pub fn module_identity_owner(rel_path: &Path) -> Option<String> {
    path_suffix_key(&rel_path.with_extension(""))
}

/// The canonical `(owner, member)` identity one authored procedure target
/// names.
///
/// An authored target carries a `path` beside its `symbol`, and the symbol has
/// two forms. A qualified symbol (`Acme.run`) names its own owner and the path
/// is only provenance. A bare symbol (`run`) is a module-level declaration: the
/// module the `path` names is its owner, so it keys on
/// [`module_identity_owner`] of that path. Both forms produce the same identity
/// the declaration side builds in `modeled_procedure_key`, which is what lets a
/// reviewed summary bind a workspace declaration.
pub fn authored_procedure_target_identity<'a>(
    path: &str,
    symbol: &'a str,
) -> Option<(Cow<'a, str>, &'a str)> {
    if let Some((owner, member)) = split_qualified_member(symbol) {
        return Some((Cow::Borrowed(owner), member));
    }
    let member = callable_symbol_head(symbol).trim();
    if member.is_empty() {
        return None;
    }
    Some((Cow::Owned(module_identity_owner(Path::new(path))?), member))
}

/// Split a *call-site* callee spelling into the canonical dot-joined
/// `(owner FQN, member)` identity, cutting it with the separator `language`
/// writes in source (#2596).
///
/// [`split_qualified_member`] reads a resolved or authored symbol, which is
/// already dot-qualified. A call site instead carries the spelling the source
/// wrote, and Rust writes `std::str::from_utf8` where Java writes
/// `java.net.URLDecoder.decode`. Only the cut is language-specific: the owner
/// is always published dot-joined, because the posting side derives its
/// `(owner, member)` key by dot-splitting the authored summary symbol
/// (`semantic_model::runtime`), and the documented Rust authoring contract is
/// dot-qualified. So `std::str::from_utf8` and an authored
/// `std.str.from_utf8` must both key on owner `std.str`, member `from_utf8`.
///
/// Empty segments are dropped, so a leading path root (`::std::str::from_utf8`)
/// canonicalizes to the same owner as the rootless spelling.
pub fn split_canonical_qualified_callee(
    callee_text: &str,
    language: Language,
) -> Option<(String, String)> {
    let separator =
        language_support(language).map_or(".", LanguageSupport::qualified_call_separator);
    if separator == "." {
        return split_qualified_member(callee_text)
            .map(|(owner, member)| (owner.to_owned(), member.to_owned()));
    }
    let without_parameters = callee_text
        .split_once('(')
        .map_or(callee_text, |(head, _tail)| head);
    let (owner, member) = without_parameters.rsplit_once(separator)?;
    let member = member.trim();
    let owner = owner
        .split(separator)
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    (!owner.is_empty() && !member.is_empty()).then(|| (owner, member.to_owned()))
}

/// Provenance of a callable value that one producing call returned.
///
/// An invocation whose local callee is proven to hold exactly one callable
/// returned by a producing call publishes this row. It names the producing
/// call and callee, the exact closure body the invocation dispatches to, and
/// the environment slots the producing procedure bound into that closure. A
/// consumer can therefore keep the closed-over storage connected across the
/// producing call's normal return without re-deriving which callable the value
/// names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReturnedCallableProvenance {
    producer: CallSiteHandle,
    producer_callee: ProcedureHandle,
    closure: ProcedureHandle,
    captures: Box<[MemoryLocationId]>,
}

impl ReturnedCallableProvenance {
    pub(crate) fn new(
        producer: CallSiteHandle,
        producer_callee: ProcedureHandle,
        closure: ProcedureHandle,
        captures: Box<[MemoryLocationId]>,
    ) -> Self {
        assert_eq!(
            producer.procedure().artifact().key().mount(),
            producer_callee.artifact().key().mount(),
            "a producing call and its callee belong to one workspace mount"
        );
        assert_eq!(
            producer_callee.artifact().key().mount(),
            closure.artifact().key().mount(),
            "a returned closure belongs to its producing procedure's mount"
        );
        Self {
            producer,
            producer_callee,
            closure,
            captures,
        }
    }

    /// The call whose result supplied the callable value.
    pub const fn producer(&self) -> &CallSiteHandle {
        &self.producer
    }

    /// The procedure the producing call resolved to.
    pub const fn producer_callee(&self) -> &ProcedureHandle {
        &self.producer_callee
    }

    /// The local callable body the invocation dispatches to.
    pub const fn closure(&self) -> &ProcedureHandle {
        &self.closure
    }

    /// The closure's environment slots, in the closure's own procedure.
    pub fn captures(&self) -> &[MemoryLocationId] {
        &self.captures
    }
}

/// Exact argument binding and creation behind a during-call closure invocation.
/// The argument association is independent of the optional factory producer
/// that established the actual value's callable identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArgumentCallableProvenance {
    pub(crate) producer: Option<ReturnedCallableProvenance>,
    pub(crate) entering_call: CallSiteHandle,
    pub(crate) caller_context: OracleCallContext,
    pub(crate) callee: ProcedureHandle,
    pub(crate) formal_ordinal: u32,
    pub(crate) actual: ValueHandle,
    pub(crate) creation: ValueHandle,
    pub(crate) closure: ProcedureHandle,
    pub(crate) captures: Box<[MemoryLocationId]>,
    pub(crate) capture_bindings: Box<[CaptureBinding]>,
    pub(crate) binding: Box<[OracleRelationHandle]>,
}

impl ArgumentCallableProvenance {
    /// Exact producing call when the actual came from a factory return.
    /// Creation and capture binding owners remain the producing procedure.
    pub fn producer(&self) -> Option<&ReturnedCallableProvenance> {
        self.producer.as_ref()
    }
    pub fn entering_call(&self) -> &CallSiteHandle {
        &self.entering_call
    }
    pub fn caller_context(&self) -> &OracleCallContext {
        &self.caller_context
    }
    pub fn callee(&self) -> &ProcedureHandle {
        &self.callee
    }
    pub fn formal_ordinal(&self) -> u32 {
        self.formal_ordinal
    }
    pub fn actual(&self) -> &ValueHandle {
        &self.actual
    }
    pub fn creation(&self) -> &ValueHandle {
        &self.creation
    }
    pub fn closure(&self) -> &ProcedureHandle {
        &self.closure
    }
    pub fn captures(&self) -> &[MemoryLocationId] {
        &self.captures
    }
    /// Exact parent-owned environment bindings for this creation. Sources,
    /// points, allocations and evidence are scoped by `creation().procedure()`;
    /// destination slots are scoped by `closure()`. A shared cell remains a
    /// location, never a snapshot of its initializer's value.
    pub fn capture_bindings(&self) -> &[CaptureBinding] {
        &self.capture_bindings
    }

    pub fn binding(&self) -> &[OracleRelationHandle] {
        &self.binding
    }
}

/// Which writers the census behind a [`StablePackageValueProvenance`] sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StablePackageValueScope {
    /// The variable is unexported. Only its own package can name it, and every
    /// file of that package is part of the analyzed workspace.
    Package,
    /// The variable is exported. The census covers the analyzed workspace
    /// only: code outside it that imports the package could still assign the
    /// variable. The proof rests on that closed-world assumption.
    Workspace,
}

/// Provenance of a call through a package variable that is proven to hold its
/// function-literal initializer.
///
/// A Go `var name = func(...) {...}` declares a mutable variable. A call
/// through it dispatches to the literal only because a complete usage census
/// found no assignment, no address-taking, and no other use of the variable:
/// every reference is the callee of a call. This row names the variable, the
/// literal's body, every reference the census found, and the scope in which
/// the census is complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StablePackageValueProvenance {
    variable: CodeUnit,
    initializer: ProcedureHandle,
    references: Box<[UsageHit]>,
    scope: StablePackageValueScope,
}

impl StablePackageValueProvenance {
    pub(crate) fn new(
        variable: CodeUnit,
        initializer: ProcedureHandle,
        references: Box<[UsageHit]>,
        scope: StablePackageValueScope,
    ) -> Self {
        assert!(
            variable.is_field(),
            "a stable package value is a variable declaration"
        );
        assert_eq!(
            initializer.semantics().kind(),
            ProcedureKind::Lambda,
            "a stable package value dispatches to its function-literal initializer"
        );
        Self {
            variable,
            initializer,
            references,
            scope,
        }
    }

    /// The package variable the call names.
    pub const fn variable(&self) -> &CodeUnit {
        &self.variable
    }

    /// The function-literal body the variable holds.
    pub const fn initializer(&self) -> &ProcedureHandle {
        &self.initializer
    }

    /// Every reference the census found; each one is a direct call.
    pub fn references(&self) -> &[UsageHit] {
        &self.references
    }

    /// Where the census is complete.
    pub const fn scope(&self) -> StablePackageValueScope {
        self.scope
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
        };
        let has_unresolved = result
            .boundaries
            .iter()
            .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Unresolved));
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

    pub fn candidates(&self) -> &[DispatchCandidate] {
        &self.candidates
    }

    pub fn boundaries(&self) -> &[DispatchBoundary] {
        &self.boundaries
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    /// Whether this answer's only truncation is the workspace-override guard
    /// on a syntax-derived external receiver arm. A complete, uncertainty-free
    /// receiver hint may replace that arm; every other truncated answer stays
    /// ineligible for feedback.
    pub const fn complete_receiver_hint_refinable(&self) -> bool {
        self.complete_receiver_hint_refinable
    }

    pub(crate) fn mark_complete_receiver_hint_refinable(&mut self) {
        debug_assert_eq!(self.coverage, CandidateCoverage::Truncated);
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

    pub(crate) fn into_parts(
        self,
    ) -> (
        Box<[DispatchCandidate]>,
        Box<[DispatchBoundary]>,
        CandidateCoverage,
    ) {
        (self.candidates, self.boundaries, self.coverage)
    }

    pub fn validate_for_call(&self, call: &CallSiteHandle) -> Result<(), OracleContractError> {
        self.validate_provenance_for_call(call, true)
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

#[cfg(test)]
mod authored_procedure_target_identity_tests {
    use super::authored_procedure_target_identity;
    use brokk_bifrost_test_macros::hardwon;

    /// A qualified symbol names its own owner; the authored path is provenance
    /// and never enters the identity.
    #[test]
    #[hardwon("#2610: module identity overwrote a qualified authored owner")]
    fn a_qualified_symbol_keeps_the_owner_it_spells() {
        let (owner, member) = authored_procedure_target_identity(
            "com/acme/AcmeHttpClient.java",
            "com.acme.AcmeHttpClient.send(java.lang.String)",
        )
        .expect("qualified identity");
        assert_eq!(owner, "com.acme.AcmeHttpClient");
        assert_eq!(member, "send");
    }

    /// A bare symbol is module-level: the module the path names is its owner
    /// (#2610).
    #[test]
    #[hardwon("#2610: bare JavaScript and TypeScript declarations had no summary owner")]
    fn a_bare_symbol_takes_the_module_the_path_names() {
        let (owner, member) =
            authored_procedure_target_identity("src/run.ts", "run").expect("module identity");
        assert_eq!(owner, "src/run");
        assert_eq!(member, "run");
    }
}

#[cfg(test)]
mod python_formal_binding_tests {
    use super::*;
    use crate::analyzer::Range;
    use crate::analyzer::lexical_definitions::{FormalParameterPassingMode, FormalParameterSlot};
    use crate::analyzer::semantic::{ArgumentDomain, ValueId};

    fn slots() -> Vec<FormalParameterSlot> {
        ["first", "second"]
            .into_iter()
            .map(|name| FormalParameterSlot {
                names: vec![name.into()],
                declaration_range: Range {
                    start_byte: 0,
                    end_byte: 0,
                    start_line: 0,
                    end_line: 0,
                },
                receiver: false,
                variadic: None,
                passing_mode: FormalParameterPassingMode::PositionalOrNamed,
                default_range: None,
            })
            .collect()
    }

    #[test]
    fn python_binding_retains_keyword_ordinals_and_rejects_unknown_or_duplicate_names() {
        let slots = slots();
        let first = ValueId::new(0);
        let second = ValueId::new(1);
        assert_eq!(
            python_actual_to_formal_slots(
                &[
                    SemanticCallArgument::keyword(second, "second"),
                    SemanticCallArgument::keyword(first, "first"),
                ],
                &slots
            )
            .as_deref(),
            Some([1, 0].as_slice())
        );
        assert_eq!(
            python_actual_to_formal_slots(
                &[
                    SemanticCallArgument::direct(first, ArgumentDomain::Positional),
                    SemanticCallArgument::keyword(second, "second"),
                ],
                &slots
            )
            .as_deref(),
            Some([0, 1].as_slice())
        );
        assert!(
            python_actual_to_formal_slots(
                &[
                    SemanticCallArgument::keyword(first, "first"),
                    SemanticCallArgument::keyword(second, "first"),
                ],
                &slots
            )
            .is_none()
        );
        assert!(
            python_actual_to_formal_slots(
                &[SemanticCallArgument::keyword(first, "unknown"),],
                &slots
            )
            .is_none()
        );
    }

    #[test]
    fn python_binding_requires_missing_formals_and_preserves_default_omission() {
        let mut slots = slots();
        let actual = SemanticCallArgument::direct(ValueId::new(0), ArgumentDomain::Positional);
        assert!(python_actual_to_formal_slots(std::slice::from_ref(&actual), &slots).is_none());
        slots[1].default_range = Some(slots[1].declaration_range);
        assert_eq!(
            python_actual_to_formal_slots(&[actual], &slots).as_deref(),
            Some([0].as_slice())
        );
    }

    #[test]
    fn python_binding_accepts_declared_positional_and_keyword_rest_formals() {
        let mut formals = slots();
        formals[1].names = vec!["args".into()];
        formals[1].variadic =
            Some(crate::analyzer::lexical_definitions::FormalVariadicKind::Positional);
        formals[1].passing_mode = FormalParameterPassingMode::PositionalOnly;
        let range = formals[0].declaration_range;
        formals.push(FormalParameterSlot {
            names: vec!["flag".into()],
            declaration_range: range,
            receiver: false,
            variadic: None,
            passing_mode: FormalParameterPassingMode::NamedOnly,
            default_range: Some(range),
        });
        formals.push(FormalParameterSlot {
            names: vec!["kwargs".into()],
            declaration_range: range,
            receiver: false,
            variadic: Some(crate::analyzer::lexical_definitions::FormalVariadicKind::Keyword),
            passing_mode: FormalParameterPassingMode::NamedOnly,
            default_range: None,
        });

        let actuals = [
            SemanticCallArgument::direct(ValueId::new(0), ArgumentDomain::Positional),
            SemanticCallArgument::direct(ValueId::new(1), ArgumentDomain::Positional),
            SemanticCallArgument::direct(ValueId::new(2), ArgumentDomain::Positional),
            SemanticCallArgument::keyword(ValueId::new(3), "flag"),
            SemanticCallArgument::keyword(ValueId::new(4), "trace"),
            SemanticCallArgument::keyword(ValueId::new(5), "context"),
        ];
        let mapping = python_actual_to_formal_slots(&actuals, &formals);
        assert_eq!(mapping.as_deref(), Some([0, 1, 1, 2, 3, 3].as_slice()));

        let shape = PythonFormalCallShape {
            formal_parameter_count: 4,
            defaulted_formals: [false, false, true, false].into(),
            variadic_formals: [false, true, false, true].into(),
            actual_to_formal: mapping,
        };
        assert!(shape.accepts_arity(actuals.len() as u32));

        let empty_tails = [
            SemanticCallArgument::direct(ValueId::new(6), ArgumentDomain::Positional),
            SemanticCallArgument::keyword(ValueId::new(7), "flag"),
        ];
        let empty_mapping = python_actual_to_formal_slots(&empty_tails, &formals);
        assert_eq!(empty_mapping.as_deref(), Some([0, 2].as_slice()));
        assert!(
            PythonFormalCallShape {
                actual_to_formal: empty_mapping,
                ..shape.clone()
            }
            .accepts_arity(empty_tails.len() as u32)
        );

        assert!(
            !PythonFormalCallShape {
                actual_to_formal: Some([0, 0, 2, 3, 3, 3].into()),
                ..shape
            }
            .accepts_arity(actuals.len() as u32),
            "repeated actuals are exact only at declared rest formals"
        );
    }
}

#[cfg(test)]
mod split_qualified_member_tests {

    use super::split_qualified_member;

    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#2610: an external summary call with parameters failed to bind its qualified owner and member"
    )]
    fn splits_a_fully_qualified_callee_with_a_parameter_list() {
        assert_eq!(
            split_qualified_member("java.net.URLDecoder.decode(java.lang.String,java.lang.String)"),
            Some(("java.net.URLDecoder", "decode"))
        );
    }

    #[test]
    #[hardwon(
        "#2610: an external summary call without parameters failed to bind its qualified owner and member"
    )]
    fn splits_a_fully_qualified_callee_without_a_parameter_list() {
        assert_eq!(
            split_qualified_member("java.net.URLDecoder.decode"),
            Some(("java.net.URLDecoder", "decode"))
        );
    }

    #[test]
    #[hardwon("#2610: a single-segment owner bypassed the external-summary qualification gate")]
    fn keeps_a_single_segment_owner_so_the_fully_qualified_gate_can_reject_it() {
        // Import-qualified `URLDecoder.decode` still splits, but its owner has no
        // dot; the fully-qualified gate at the call site rejects it.
        assert_eq!(
            split_qualified_member("URLDecoder.decode"),
            Some(("URLDecoder", "decode"))
        );
    }

    #[test]
    #[hardwon("#2610: an unqualified call was admitted as an external summary identity")]
    fn rejects_an_unqualified_callee() {
        assert_eq!(split_qualified_member("decode"), None);
        assert_eq!(split_qualified_member("decode(x)"), None);
    }

    #[test]
    #[hardwon("#2610: parameter text was reconstructed into an external summary identity")]
    fn does_not_reconstruct_parameter_types() {
        // Only the owner and member are recovered; the parameter list is dropped.
        let (owner, member) =
            split_qualified_member("a.b.C.m(int, long)").expect("qualified split");
        assert_eq!(owner, "a.b.C");
        assert_eq!(member, "m");
    }
}

#[cfg(test)]
mod split_canonical_qualified_callee_tests {

    use super::split_canonical_qualified_callee;
    use crate::analyzer::Language;

    /// #2596: a Rust call-site spelling is cut on `::` and published with a
    /// dot-joined owner, which is the exact key an authored `std.str.from_utf8`
    /// summary posts under.

    #[test]
    fn canonicalizes_a_rust_scoped_path_to_the_dotted_authoring_spelling() {
        assert_eq!(
            split_canonical_qualified_callee("std::str::from_utf8", Language::Rust),
            Some(("std.str".to_owned(), "from_utf8".to_owned()))
        );
        // A leading path root is the same identity.
        assert_eq!(
            split_canonical_qualified_callee("::std::str::from_utf8", Language::Rust),
            Some(("std.str".to_owned(), "from_utf8".to_owned()))
        );
    }

    #[test]
    fn keeps_a_single_segment_rust_owner_for_the_callers_gate() {
        assert_eq!(
            split_canonical_qualified_callee("Path::new", Language::Rust),
            Some(("Path".to_owned(), "new".to_owned()))
        );
        assert_eq!(
            split_canonical_qualified_callee("String::from", Language::Rust),
            Some(("String".to_owned(), "from".to_owned()))
        );
    }

    #[test]
    fn rejects_an_unqualified_rust_callee() {
        assert_eq!(
            split_canonical_qualified_callee("from_utf8", Language::Rust),
            None
        );
        assert_eq!(
            split_canonical_qualified_callee("from_utf8(x)", Language::Rust),
            None
        );
    }

    #[test]
    fn canonicalizes_a_cpp_qualified_path_on_the_last_separator() {
        assert_eq!(
            split_canonical_qualified_callee("std::filesystem::exists", Language::Cpp),
            Some(("std.filesystem".to_owned(), "exists".to_owned()))
        );
        assert_eq!(
            split_canonical_qualified_callee("ns::Type::method", Language::Cpp),
            Some(("ns.Type".to_owned(), "method".to_owned()))
        );
        // A global-scope root is the same identity.
        assert_eq!(
            split_canonical_qualified_callee("::ns::Type::method", Language::Cpp),
            Some(("ns.Type".to_owned(), "method".to_owned()))
        );
    }

    #[test]
    fn a_dotted_language_is_unchanged() {
        assert_eq!(
            split_canonical_qualified_callee(
                "java.net.URLDecoder.decode(java.lang.String)",
                Language::Java
            ),
            Some(("java.net.URLDecoder".to_owned(), "decode".to_owned()))
        );
        assert_eq!(
            split_canonical_qualified_callee("std::str::from_utf8", Language::Java),
            None
        );
    }
}
