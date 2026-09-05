use super::super::ids::{
    DeclarationLocator, DeclarationSegment, SemanticArtifactKey, SemanticLanguage, SemanticLocator,
    SemanticRole, WorkspaceMountId, WorkspaceRelativePath,
};
use super::super::ir::{
    CallSiteHandle, EvidenceCompleteness, ProcedureHandle, ProcedureKind, ProofStatus,
};
use super::error::OracleContractError;
use super::limits::OracleLimits;
use super::model::DispatchBoundaryKind;
use super::relation::{
    CandidateCoverage, OracleRelationHandle, OracleRelationKind, OracleRelationOwner,
    collect_candidate_provenance, validate_retained_relation_arenas,
};
use crate::analyzer::languages::{LanguageSupport, language_support};
use crate::analyzer::{CallableArity, Language, SignatureMetadata};
use brokk_bifrost_core::path_utils::path_suffix_key;
use std::borrow::Cow;
use std::path::Path;

/// One materialized workspace target for an exact semantic call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchCandidate {
    pub(crate) target: ProcedureHandle,
    pub(crate) proof: ProofStatus,
    pub(crate) completeness: EvidenceCompleteness,
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
        self.language == target.language().language()
            && self.owner_fqn.as_ref() == target.owner_fqn()
            && self.member.as_ref() == target.member()
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
        if self.provenance.iter().any(|relation| {
            relation.owner() != &owner
                || relation.record().kind() != OracleRelationKind::DispatchCandidate
                || !relation
                    .record()
                    .identifies_dispatch_candidate(&self.target)
                || relation.record().evidence().is_empty()
                || first.is_some_and(|first| !first.same_arena(relation))
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
                        .is_some_and(|row| row.receiver.is_some() == target.has_receiver())
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
                                || normalized_external_has_receiver(
                                    row.receiver.is_some(),
                                    target.language(),
                                    target.owner_fqn(),
                                    target.normalized_static_owner(),
                                ) == target.has_receiver()
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
    locator: SemanticLocator,
}

impl UnmaterializedExternalTarget {
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
        locator: SemanticLocator,
    ) -> Self {
        let mut target = Self::new(owner_fqn, member, arity, has_receiver, locator);
        target.resolver_owned_call_shape = true;
        target
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
    /// external call is statically selected.
    pub fn resolver_proves_static_call(&self) -> bool {
        if self.has_receiver {
            return false;
        }
        if self.language() == SemanticLanguage::Standard(Language::Python)
            && self.resolver_owned_call_shape
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

    const fn has_resolver_owned_call_shape(&self) -> bool {
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

/// Normalize the raw IR receiver shape at the external-summary identity
/// boundary.
///
/// Java intentionally retains a value row for every method-invocation object,
/// including a type qualifier. A qualifier is not a semantic receiver, so the
/// exact resolver may prove its canonical owner here. The equality guard keeps
/// that proof target-specific; every other language and every Java value
/// receiver preserves the raw IR shape.
pub(crate) fn normalized_external_has_receiver(
    raw_has_receiver: bool,
    language: SemanticLanguage,
    owner_fqn: &str,
    normalized_static_owner: Option<&str>,
) -> bool {
    raw_has_receiver
        && !(language.language() == Language::Java
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResult {
    candidates: Box<[DispatchCandidate]>,
    boundaries: Box<[DispatchBoundary]>,
    coverage: CandidateCoverage,
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
            if relations.is_empty()
                || relations.iter().any(|relation| {
                    relation.owner() != &owner
                        || relation.record().kind() != kind
                        || relation.record().evidence().is_empty()
                        || first.is_some_and(|first| !first.same_arena(relation))
                        || !seen.insert(relation.clone())
                })
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            if relations
                .iter()
                .any(|relation| !relation.record().supports_quality(proof, completeness))
            {
                return Err(OracleContractError::InvalidRelationQuality);
            }
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
mod split_qualified_member_tests {
    use super::split_qualified_member;

    #[test]
    fn splits_a_fully_qualified_callee_with_a_parameter_list() {
        assert_eq!(
            split_qualified_member("java.net.URLDecoder.decode(java.lang.String,java.lang.String)"),
            Some(("java.net.URLDecoder", "decode"))
        );
    }

    #[test]
    fn splits_a_fully_qualified_callee_without_a_parameter_list() {
        assert_eq!(
            split_qualified_member("java.net.URLDecoder.decode"),
            Some(("java.net.URLDecoder", "decode"))
        );
    }

    #[test]
    fn keeps_a_single_segment_owner_so_the_fully_qualified_gate_can_reject_it() {
        // Import-qualified `URLDecoder.decode` still splits, but its owner has no
        // dot; the fully-qualified gate at the call site rejects it.
        assert_eq!(
            split_qualified_member("URLDecoder.decode"),
            Some(("URLDecoder", "decode"))
        );
    }

    #[test]
    fn rejects_an_unqualified_callee() {
        assert_eq!(split_qualified_member("decode"), None);
        assert_eq!(split_qualified_member("decode(x)"), None);
    }

    #[test]
    fn does_not_reconstruct_parameter_types() {
        // Only the owner and member are recovered; the parameter list is dropped.
        let (owner, member) =
            split_qualified_member("a.b.C.m(int, long)").expect("qualified split");
        assert_eq!(owner, "a.b.C");
        assert_eq!(member, "m");
    }
}

#[cfg(test)]
mod authored_procedure_target_identity_tests {
    use super::authored_procedure_target_identity;

    /// A qualified symbol names its own owner; the authored path is provenance
    /// and never enters the identity.
    #[test]
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
    fn a_bare_symbol_takes_the_module_the_path_names() {
        let (owner, member) =
            authored_procedure_target_identity("src/run.ts", "run").expect("module identity");
        assert_eq!(owner, "src/run");
        assert_eq!(member, "run");
    }

    #[test]
    fn a_bare_symbol_drops_its_parameter_list_the_same_way() {
        let (owner, member) = authored_procedure_target_identity("src/run.php", "run(int $count)")
            .expect("module identity");
        assert_eq!(owner, "src/run");
        assert_eq!(member, "run");
    }

    /// Neither half can be empty: an identity nothing names is no identity.
    #[test]
    fn refuses_a_target_with_no_symbol_or_no_path() {
        assert!(authored_procedure_target_identity("src/run.ts", "").is_none());
        assert!(authored_procedure_target_identity("", "run").is_none());
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

    /// A single-segment Rust owner still splits, so the caller's multi-segment
    /// gate is what rejects an unexpanded import or prelude spelling.
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

    /// #2606: C++ writes `::` too, and the cut takes the last separator, so a
    /// nested class or namespace qualification keeps the whole prefix as the
    /// owner instead of splitting at the first separator.
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

    /// A dotted language keeps exactly the dot-only interpretation, so a Rust
    /// spelling is not silently reinterpreted for Java and a Java spelling
    /// keeps its owner verbatim.
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
