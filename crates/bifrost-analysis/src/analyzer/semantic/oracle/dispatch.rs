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
    #[doc(hidden)]
    pub fn validate_for_call(&self, call: &CallSiteHandle) -> Result<(), OracleContractError> {
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

    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut crate::analyzer::semantic::service::ArtifactRetentionCensus,
    ) {
        for candidate in self.candidates() {
            candidate.retained_artifacts(census);
        }
        for boundary in self.boundaries() {
            for relation in boundary.provenance.iter() {
                relation.retained_artifacts(census);
            }
        }
        if let Some(returned) = self.returned_callable() {
            returned.retained_artifacts(census);
        }
        if let Some(argument) = self.argument_callable() {
            argument.retained_artifacts(census);
        }
        for value in self.stable_package_values() {
            census.procedure(value.initializer());
        }
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
