use crate::analyzer::semantic::ids::MemoryLocationId;

use crate::analyzer::semantic::ids::SemanticArtifactKey;

use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

use crate::analyzer::semantic::ids::SemanticLocator;

use crate::analyzer::semantic::ids::SemanticRole;

use crate::analyzer::semantic::ids::SourceAnchor;

use crate::analyzer::semantic::ids::SourcePosition;

use crate::analyzer::semantic::ids::SourceSpan;

use crate::analyzer::semantic::ids::WorkspaceMountId;

use crate::analyzer::semantic::ids::WorkspaceRelativePath;

use crate::analyzer::semantic::ir::CallSiteHandle;

use crate::analyzer::semantic::ir::CaptureBinding;

use crate::analyzer::semantic::ir::EvidenceCompleteness;

use crate::analyzer::semantic::ir::ProcedureHandle;

use crate::analyzer::semantic::ir::ProcedureKind;

use crate::analyzer::semantic::ir::ProofStatus;

use crate::analyzer::semantic::ir::SemanticCallArgument;

use crate::analyzer::semantic::ir::ValueHandle;

use crate::analyzer::semantic::oracle::error::OracleContractError;

use crate::analyzer::semantic::oracle::limits::OracleLimits;

use crate::analyzer::semantic::oracle::model::OracleCallContext;

use crate::analyzer::semantic::oracle::relation::OracleRelationHandle;

use crate::analyzer::semantic::oracle::relation::OracleRelationKind;

use crate::analyzer::semantic::oracle::relation::OracleRelationOwner;

use crate::analyzer::semantic::oracle::relation::collect_candidate_provenance;

use crate::analyzer::semantic::oracle::relation::validate_provenance_identity;

use crate::analyzer::semantic::oracle::relation::validate_provenance_quality;

use crate::analyzer::semantic::languages::language_knowledge;

use brokk_bifrost_core::analyzer::usages::model::UsageHit;

use brokk_bifrost_core::analyzer::model::CallableArity;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::SignatureMetadata;
use brokk_bifrost_core::path_utils::path_suffix_key;
use std::borrow::Cow;
use std::path::Path;

/// One materialized workspace target for an exact semantic call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchCandidate {
    #[doc(hidden)]
    pub target: ProcedureHandle,
    #[doc(hidden)]
    pub proof: ProofStatus,
    #[doc(hidden)]
    pub completeness: EvidenceCompleteness,
    pub(crate) native_incomplete_source_reason: Option<Box<str>>,
    #[doc(hidden)]
    pub provenance: Box<[OracleRelationHandle]>,
    #[doc(hidden)]
    pub excluded_targets: Box<[ProcedureHandle]>,
    sealed: bool,
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

    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut crate::analyzer::semantic::service::ArtifactRetentionCensus,
    ) {
        census.procedure(self.target());
        for target in self.excluded_targets() {
            census.procedure(target);
        }
        for relation in self.provenance() {
            relation.retained_artifacts(census);
        }
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
    #[doc(hidden)]
    pub fn with_unique_incomplete_native_source(mut self, reason: &str) -> Self {
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

    #[doc(hidden)]
    pub fn unique_incomplete_native_source_reason(&self) -> Option<&str> {
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

    #[doc(hidden)]
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    #[doc(hidden)]
    pub const fn is_sealed(&self) -> bool {
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
    #[doc(hidden)]
    pub fn new(
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
    #[doc(hidden)]
    pub fn from_metadata(metadata: &SignatureMetadata) -> Option<Self> {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[doc(hidden)]
pub struct PythonFormalCallShape {
    #[doc(hidden)]
    pub formal_parameter_count: u32,
    #[doc(hidden)]
    pub defaulted_formals: Box<[bool]>,
    #[doc(hidden)]
    pub variadic_formals: Box<[bool]>,
    // Formal ordinals for each actual, retained from structured call binding.
    #[doc(hidden)]
    pub actual_to_formal: Option<Box<[u32]>>,
}

impl PythonFormalCallShape {
    #[doc(hidden)]
    pub fn accepts_arity(&self, arity: u32) -> bool {
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

#[doc(hidden)]
pub fn python_actual_to_formal_slots(
    arguments: &[SemanticCallArgument],
    slots: &[crate::analyzer::semantic::lexical_definitions::FormalParameterSlot],
) -> Option<Box<[u32]>> {
    if slots.iter().any(|slot| slot.unique_name().is_none()) {
        return None;
    }
    let layout = crate::analyzer::semantic::lexical_definitions::FormalParameterLayout {
        slots: slots.to_vec(),
        python_binding: None,
    };
    crate::analyzer::semantic::call_binding::bind_semantic_call_arguments(arguments, &layout)
}

#[doc(hidden)]
pub fn modeled_external_zero_source_anchor() -> SourceAnchor {
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
#[doc(hidden)]
pub fn call_receiver_admits_target(
    call_has_receiver: bool,
    target_has_receiver: bool,
    language: SemanticLanguage,
) -> bool {
    if target_has_receiver {
        return call_has_receiver;
    }
    !call_has_receiver || language.language() == Language::Python
}

#[doc(hidden)]
pub fn normalized_external_has_receiver(
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
#[doc(hidden)]
pub fn unmaterialized_external_mount() -> WorkspaceMountId {
    WorkspaceMountId::hash_bytes(b"bifrost.unmaterialized-external.mount.v1")
}

/// Stable sentinel provenance path for synthetic unmaterialized externals.
#[doc(hidden)]
pub fn unmaterialized_external_path() -> WorkspaceRelativePath {
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
    split_owner_member(callable_symbol_head(symbol))
}

/// Split the final dotted segment of a caller-supplied qualified name value,
/// not source text. Both sides must be non-empty and are returned trimmed.
/// Parameter lists remain part of the member spelling for exact-name lookup.
pub fn split_owner_member(head: &str) -> Option<(&str, &str)> {
    let (owner, member) = head.rsplit_once('.')?;
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
        language_knowledge(language).map_or(".", |support| support.qualified_call_separator());
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
    #[doc(hidden)]
    pub fn new(
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
    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut crate::analyzer::semantic::service::ArtifactRetentionCensus,
    ) {
        census.procedure(self.producer().procedure());
        census.procedure(self.producer_callee());
        census.procedure(self.closure());
    }

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
    #[doc(hidden)]
    pub producer: Option<ReturnedCallableProvenance>,
    #[doc(hidden)]
    pub entering_call: CallSiteHandle,
    #[doc(hidden)]
    pub caller_context: OracleCallContext,
    #[doc(hidden)]
    pub callee: ProcedureHandle,
    #[doc(hidden)]
    pub formal_ordinal: u32,
    #[doc(hidden)]
    pub actual: ValueHandle,
    #[doc(hidden)]
    pub creation: ValueHandle,
    #[doc(hidden)]
    pub closure: ProcedureHandle,
    #[doc(hidden)]
    pub captures: Box<[MemoryLocationId]>,
    #[doc(hidden)]
    pub capture_bindings: Box<[CaptureBinding]>,
    #[doc(hidden)]
    pub binding: Box<[OracleRelationHandle]>,
}

impl ArgumentCallableProvenance {
    /// Exact producing call when the actual came from a factory return.
    /// Creation and capture binding owners remain the producing procedure.
    #[doc(hidden)]
    pub fn retained_artifacts(
        &self,
        census: &mut crate::analyzer::semantic::service::ArtifactRetentionCensus,
    ) {
        if let Some(producer) = self.producer() {
            producer.retained_artifacts(census);
        }
        census.context(self.caller_context());
        census.procedure(self.entering_call().procedure());
        census.procedure(self.callee());
        census.procedure(self.closure());
        census.procedure(self.actual().procedure());
        census.procedure(self.creation().procedure());
        for relation in self.binding() {
            relation.retained_artifacts(census);
        }
    }

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
    #[doc(hidden)]
    pub fn new(
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

#[cfg(test)]
mod authored_procedure_target_identity_tests {

    use crate::analyzer::semantic::oracle::dispatch::authored_procedure_target_identity;
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

    use crate::analyzer::semantic::oracle::dispatch::*;

    use brokk_bifrost_core::analyzer::model::Range;

    use crate::analyzer::semantic::lexical_definitions::FormalParameterPassingMode;

    use crate::analyzer::semantic::lexical_definitions::FormalParameterSlot;

    use crate::analyzer::semantic::ArgumentDomain;

    use crate::analyzer::semantic::ValueId;

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
            Some(crate::analyzer::semantic::lexical_definitions::FormalVariadicKind::Positional);
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
            variadic: Some(
                crate::analyzer::semantic::lexical_definitions::FormalVariadicKind::Keyword,
            ),
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

    use crate::analyzer::semantic::oracle::dispatch::split_qualified_member;

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

    use crate::analyzer::semantic::oracle::dispatch::split_canonical_qualified_callee;

    use brokk_bifrost_core::analyzer::model::Language;

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
