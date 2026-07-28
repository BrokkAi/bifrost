//! Stable reusable procedure-summary contracts above query-local tabulation.
//!
//! The summary solver in [`super::summary`] owns run-local fact IDs, worklists,
//! witness relations, and recursive replay. This module deliberately does not
//! expose those values. It defines stable procedure validity, boundary
//! relations, evidence, provenance, and complete-only in-memory publication
//! for clients that can project their query-local results into durable keys.

use std::fmt;
use std::mem::{size_of, size_of_val};

use crate::analyzer::semantic::{
    DeclarationLocator, EvidenceCompleteness, ProofStatus, SemanticArtifactKey, StableDigest,
};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};

use super::{PathQuality, PathQualityFrontier};

pub const SUMMARY_SCHEMA_VERSION: u32 = 1;
pub const MAX_SUMMARY_TRANSFERS: usize = 65_536;
pub const MAX_SUMMARY_EFFECTS: usize = 65_536;
pub const MAX_SUMMARY_RECURSIVE_MEMBERS: usize = 4_096;
pub const MAX_SUMMARY_BOUNDARY_BINDINGS: usize = 65_536;
pub const MAX_SUMMARY_EVIDENCE_REASONS: usize = 64;
pub const MAX_SUMMARY_REASON_BYTES: usize = 1_024;
pub const MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES: usize = 512;
pub const MAX_AMBIGUOUS_SUMMARY_CALLEES: usize = 4_096;
pub const MAX_SUMMARY_DEPENDENCIES: usize = 65_536;
pub const MAX_SUMMARY_EFFECT_REFERENCES: usize = 65_536;
pub const MAX_SUMMARY_COMPOSITION_STEPS: usize = 1_000_000;
pub const DEFAULT_SUMMARY_REPOSITORY_ENTRIES: usize = 16_384;
pub const DEFAULT_SUMMARY_REPOSITORY_BYTES: usize = 64 * 1024 * 1024;

macro_rules! define_summary_digest {
    ($(#[$attribute:meta])* $name:ident) => {
        $(#[$attribute])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(StableDigest);

        impl $name {
            pub const fn from_digest(digest: StableDigest) -> Self {
                Self(digest)
            }

            pub fn hash_bytes(bytes: impl AsRef<[u8]>) -> Self {
                Self(StableDigest::sha256(bytes))
            }

            pub const fn digest(self) -> StableDigest {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

define_summary_digest!(
    /// Versioned execution semantics used to project one reusable summary.
    SummarySemanticsVersion
);
define_summary_digest!(
    /// Context and access-path abstraction selected for one summary family.
    SummaryContextKey
);
define_summary_digest!(
    /// Exceptional, escape, external-call, and unresolved-call behavior.
    SummaryBehaviorKey
);
define_summary_digest!(
    /// Stable identity of one summary-visible semantic event.
    SummaryEventKey
);
define_summary_digest!(
    /// Stable identity of a capture or supported heap/access-path boundary.
    SummaryLocationKey
);
define_summary_digest!(
    /// Content identity of one externally supplied semantic model.
    ExternalSummaryContentHash
);
define_summary_digest!(
    /// Canonical identity of one recursive publication group.
    SummaryRecursiveGroupFingerprint
);
define_summary_digest!(
    /// Exact leftmost procedure key retained by an associative composition.
    SummaryCompositionRootFingerprint
);

/// Non-zero format revision for one reusable summary artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SummarySchemaVersion(u32);

impl SummarySchemaVersion {
    pub const CURRENT: Self = Self(SUMMARY_SCHEMA_VERSION);

    pub fn new(version: u32) -> Result<Self, SummaryValidationError> {
        if version == 0 {
            return Err(SummaryValidationError::ZeroSchemaVersion);
        }
        Ok(Self(version))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Opaque stable identifier supplied by an external model-pack owner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalSummaryModelId(Box<str>);

impl ExternalSummaryModelId {
    pub fn new(value: impl Into<String>) -> Result<Self, SummaryValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SummaryValidationError::EmptyExternalModelId);
        }
        if value.len() > MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES {
            return Err(SummaryValidationError::ExternalModelIdTooLarge {
                actual: value.len(),
                limit: MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES,
            });
        }
        if value.trim() != value || value.chars().any(char::is_control) {
            return Err(SummaryValidationError::InvalidExternalModelId);
        }
        Ok(Self(value.into_boxed_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated provenance for one externally authored or generated summary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalSummaryOrigin {
    model: ExternalSummaryModelId,
    content: ExternalSummaryContentHash,
    contract_version: u32,
}

impl ExternalSummaryOrigin {
    pub fn new(
        model: ExternalSummaryModelId,
        content: ExternalSummaryContentHash,
        contract_version: u32,
    ) -> Result<Self, SummaryValidationError> {
        if contract_version == 0 {
            return Err(SummaryValidationError::ZeroExternalContractVersion);
        }
        Ok(Self {
            model,
            content,
            contract_version,
        })
    }

    pub fn model(&self) -> &ExternalSummaryModelId {
        &self.model
    }

    pub const fn content(&self) -> ExternalSummaryContentHash {
        self.content
    }

    pub const fn contract_version(&self) -> u32 {
        self.contract_version
    }
}

/// Whether a summary came from the exact workspace source or a validated model.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryOrigin {
    Inferred,
    External(ExternalSummaryOrigin),
}

/// Stable procedure validity before its retained dependency closure is applied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcedureSummaryIdentity {
    artifact: SemanticArtifactKey,
    declaration: DeclarationLocator,
    schema: SummarySchemaVersion,
    semantics: SummarySemanticsVersion,
    context: SummaryContextKey,
    behavior: SummaryBehaviorKey,
    origin: SummaryOrigin,
}

impl ProcedureSummaryIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact: SemanticArtifactKey,
        declaration: DeclarationLocator,
        schema: SummarySchemaVersion,
        semantics: SummarySemanticsVersion,
        context: SummaryContextKey,
        behavior: SummaryBehaviorKey,
        origin: SummaryOrigin,
    ) -> Self {
        Self {
            artifact,
            declaration,
            schema,
            semantics,
            context,
            behavior,
            origin,
        }
    }

    pub fn artifact(&self) -> &SemanticArtifactKey {
        &self.artifact
    }

    pub fn declaration(&self) -> &DeclarationLocator {
        &self.declaration
    }

    pub const fn schema(&self) -> SummarySchemaVersion {
        self.schema
    }

    pub const fn semantics(&self) -> SummarySemanticsVersion {
        self.semantics
    }

    pub const fn context(&self) -> SummaryContextKey {
        self.context
    }

    pub const fn behavior(&self) -> SummaryBehaviorKey {
        self.behavior
    }

    pub const fn origin(&self) -> &SummaryOrigin {
        &self.origin
    }

    pub fn fingerprint(&self) -> StableDigest {
        fingerprint_procedure_identity(self)
    }

    /// Conservative retained size of this owned identity and its heap fields.
    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>().saturating_add(identity_heap_bytes(self))
    }
}

/// A retained dependency either names an exact completed summary or an identity
/// that must be supplied by the same recursive publication batch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryDependencyKey {
    Complete(Box<ProcedureSummaryKey>),
    Recursive(Box<ProcedureSummaryIdentity>),
}

impl SummaryDependencyKey {
    pub fn complete(key: ProcedureSummaryKey) -> Self {
        Self::Complete(Box::new(key))
    }

    pub fn recursive(identity: ProcedureSummaryIdentity) -> Self {
        Self::Recursive(Box::new(identity))
    }

    pub fn identity(&self) -> &ProcedureSummaryIdentity {
        match self {
            Self::Complete(key) => key.identity(),
            Self::Recursive(identity) => identity,
        }
    }
}

/// Canonical fingerprint of the exact retained dependency closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SummaryDependencyFingerprint(StableDigest);

impl SummaryDependencyFingerprint {
    fn from_dependencies(dependencies: &[SummaryDependencyKey]) -> Self {
        Self(fingerprint_dependencies(dependencies))
    }

    pub const fn digest(self) -> StableDigest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for SummaryDependencyFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Exact cache lookup identity for one procedure and dependency closure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcedureSummaryKey {
    identity: ProcedureSummaryIdentity,
    dependencies: SummaryDependencyFingerprint,
    recursive_group: Option<SummaryRecursiveGroupKey>,
    composition_root: Option<SummaryCompositionRootFingerprint>,
}

impl ProcedureSummaryKey {
    pub fn try_new(
        identity: ProcedureSummaryIdentity,
        dependencies: &[SummaryDependencyKey],
        recursive_group: Option<SummaryRecursiveGroupKey>,
    ) -> Result<Self, SummaryValidationError> {
        if dependencies.len() > MAX_SUMMARY_DEPENDENCIES {
            return Err(SummaryValidationError::TooManyDependencies {
                actual: dependencies.len(),
                limit: MAX_SUMMARY_DEPENDENCIES,
            });
        }
        Ok(Self {
            identity,
            dependencies: SummaryDependencyFingerprint::from_dependencies(dependencies),
            recursive_group,
            composition_root: None,
        })
    }

    fn try_new_composed(
        identity: ProcedureSummaryIdentity,
        dependencies: &[SummaryDependencyKey],
        recursive_group: Option<SummaryRecursiveGroupKey>,
        composition_root: &ProcedureSummaryKey,
    ) -> Result<Self, SummaryValidationError> {
        let mut key = Self::try_new(identity, dependencies, recursive_group)?;
        key.composition_root = Some(SummaryCompositionRootFingerprint::from_digest(
            composition_root.fingerprint(),
        ));
        Ok(key)
    }

    pub const fn identity(&self) -> &ProcedureSummaryIdentity {
        &self.identity
    }

    pub fn artifact(&self) -> &SemanticArtifactKey {
        self.identity.artifact()
    }

    pub fn declaration(&self) -> &DeclarationLocator {
        self.identity.declaration()
    }

    pub const fn schema(&self) -> SummarySchemaVersion {
        self.identity.schema()
    }

    pub const fn semantics(&self) -> SummarySemanticsVersion {
        self.identity.semantics()
    }

    pub const fn context(&self) -> SummaryContextKey {
        self.identity.context()
    }

    pub const fn behavior(&self) -> SummaryBehaviorKey {
        self.identity.behavior()
    }

    pub const fn origin(&self) -> &SummaryOrigin {
        self.identity.origin()
    }

    pub const fn dependencies(&self) -> SummaryDependencyFingerprint {
        self.dependencies
    }

    pub const fn recursive_group(&self) -> Option<SummaryRecursiveGroupKey> {
        self.recursive_group
    }

    pub const fn composition_root(&self) -> Option<SummaryCompositionRootFingerprint> {
        self.composition_root
    }

    pub fn fingerprint(&self) -> StableDigest {
        let mut bytes = Vec::new();
        push_digest_part(&mut bytes, b"bifrost-procedure-summary-key-v1");
        push_digest_part(&mut bytes, self.identity.fingerprint().as_bytes());
        push_digest_part(&mut bytes, self.dependencies.as_bytes());
        match self.recursive_group {
            Some(group) => {
                push_digest_part(&mut bytes, b"recursive");
                push_digest_part(&mut bytes, group.fingerprint.as_bytes());
                push_digest_part(&mut bytes, &group.member_count.to_le_bytes());
            }
            None => push_digest_part(&mut bytes, b"nonrecursive"),
        }
        match self.composition_root {
            Some(root) => {
                push_digest_part(&mut bytes, b"composed");
                push_digest_part(&mut bytes, root.as_bytes());
            }
            None => push_digest_part(&mut bytes, b"base"),
        }
        StableDigest::sha256(bytes)
    }

    /// Conservative retained size of this owned key, including heap-backed identity fields.
    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>().saturating_add(procedure_key_heap_bytes(self))
    }
}

/// Compact recursive group identity shared by every member summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SummaryRecursiveGroupKey {
    fingerprint: SummaryRecursiveGroupFingerprint,
    member_count: u32,
}

/// One directed dependency edge within a recursive publication group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SummaryRecursiveEdge {
    caller: ProcedureSummaryIdentity,
    callee: ProcedureSummaryIdentity,
}

impl SummaryRecursiveEdge {
    pub fn new(caller: ProcedureSummaryIdentity, callee: ProcedureSummaryIdentity) -> Self {
        Self { caller, callee }
    }

    pub const fn caller(&self) -> &ProcedureSummaryIdentity {
        &self.caller
    }

    pub const fn callee(&self) -> &ProcedureSummaryIdentity {
        &self.callee
    }
}

impl SummaryRecursiveGroupKey {
    pub fn from_closure(
        members: &[ProcedureSummaryIdentity],
        recursive_edges: &[SummaryRecursiveEdge],
        external_dependencies: &[ProcedureSummaryKey],
    ) -> Result<Self, SummaryValidationError> {
        if members.is_empty() {
            return Err(SummaryValidationError::EmptyRecursiveGroup);
        }
        if members.len() > MAX_SUMMARY_RECURSIVE_MEMBERS {
            return Err(SummaryValidationError::TooManyRecursiveMembers {
                actual: members.len(),
                limit: MAX_SUMMARY_RECURSIVE_MEMBERS,
            });
        }
        let mut members = members.to_vec();
        members.sort_unstable();
        members.dedup();
        if recursive_edges.len() > MAX_SUMMARY_DEPENDENCIES {
            return Err(SummaryValidationError::TooManyDependencies {
                actual: recursive_edges.len(),
                limit: MAX_SUMMARY_DEPENDENCIES,
            });
        }
        let mut recursive_edges = recursive_edges.to_vec();
        recursive_edges.sort_unstable();
        recursive_edges.dedup();
        if recursive_edges.iter().any(|edge| {
            members.binary_search(edge.caller()).is_err()
                || members.binary_search(edge.callee()).is_err()
        }) {
            return Err(SummaryValidationError::RecursiveEdgeOutsideGroup);
        }
        if external_dependencies.len() > MAX_SUMMARY_DEPENDENCIES {
            return Err(SummaryValidationError::TooManyDependencies {
                actual: external_dependencies.len(),
                limit: MAX_SUMMARY_DEPENDENCIES,
            });
        }
        let mut external_dependencies = external_dependencies.to_vec();
        external_dependencies.sort_unstable();
        external_dependencies.dedup();
        if members.len() > u32::MAX as usize {
            return Err(SummaryValidationError::TooManyRecursiveMembers {
                actual: members.len(),
                limit: u32::MAX as usize,
            });
        }
        let mut bytes = Vec::new();
        push_digest_part(&mut bytes, b"bifrost-summary-recursive-group-v1");
        for member in &members {
            push_digest_part(&mut bytes, b"member");
            push_digest_part(&mut bytes, member.fingerprint().as_bytes());
        }
        for edge in &recursive_edges {
            push_digest_part(&mut bytes, b"edge");
            push_digest_part(&mut bytes, edge.caller().fingerprint().as_bytes());
            push_digest_part(&mut bytes, edge.callee().fingerprint().as_bytes());
        }
        for dependency in &external_dependencies {
            push_digest_part(&mut bytes, b"external");
            push_digest_part(&mut bytes, dependency.fingerprint().as_bytes());
        }
        Ok(Self {
            fingerprint: SummaryRecursiveGroupFingerprint::from_digest(StableDigest::sha256(bytes)),
            member_count: members.len() as u32,
        })
    }

    pub const fn fingerprint(self) -> SummaryRecursiveGroupFingerprint {
        self.fingerprint
    }

    pub const fn member_count(self) -> u32 {
        self.member_count
    }
}

/// Stable procedure-boundary slots. Dense semantic IDs never enter this type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryPort {
    Receiver,
    Parameter(u32),
    NormalReturn,
    ExceptionalReturn,
    Capture(SummaryLocationKey),
    Heap(SummaryLocationKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryExitKind {
    Normal,
    Exceptional,
}

/// One typed normal or exceptional procedure output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SummaryExit {
    kind: SummaryExitKind,
    port: SummaryPort,
}

impl SummaryExit {
    pub fn try_new(
        kind: SummaryExitKind,
        port: SummaryPort,
    ) -> Result<Self, SummaryValidationError> {
        if matches!(
            (kind, &port),
            (SummaryExitKind::Normal, SummaryPort::ExceptionalReturn)
                | (SummaryExitKind::Exceptional, SummaryPort::NormalReturn)
        ) {
            return Err(SummaryValidationError::IncompatibleExitPort);
        }
        Ok(Self { kind, port })
    }

    pub const fn kind(&self) -> SummaryExitKind {
        self.kind
    }

    pub fn port(&self) -> &SummaryPort {
        &self.port
    }
}

/// One concrete quality alternative and the reasons for its weak axes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryEvidenceAlternative {
    quality: PathQuality,
    unproven_reasons: Box<[Box<str>]>,
    incomplete_reasons: Box<[Box<str>]>,
}

impl SummaryEvidenceAlternative {
    pub const fn quality(&self) -> PathQuality {
        self.quality
    }

    pub fn unproven_reasons(&self) -> &[Box<str>] {
        &self.unproven_reasons
    }

    pub fn incomplete_reasons(&self) -> &[Box<str>] {
        &self.incomplete_reasons
    }
}

/// Nondominated proof/completeness alternatives for one reusable row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryEvidence {
    alternatives: Box<[SummaryEvidenceAlternative]>,
}

impl Default for SummaryEvidence {
    fn default() -> Self {
        Self::proven_complete()
    }
}

impl SummaryEvidence {
    pub fn try_new(
        unproven_reasons: Vec<String>,
        incomplete_reasons: Vec<String>,
    ) -> Result<Self, SummaryValidationError> {
        let unproven_reasons = canonicalize_reason_strings(unproven_reasons)?;
        let incomplete_reasons = canonicalize_reason_strings(incomplete_reasons)?;
        let quality = quality_from_reasons(&unproven_reasons, &incomplete_reasons);
        Ok(Self {
            alternatives: vec![SummaryEvidenceAlternative {
                quality,
                unproven_reasons,
                incomplete_reasons,
            }]
            .into_boxed_slice(),
        })
    }

    pub fn from_semantic(
        proof: &ProofStatus,
        completeness: &EvidenceCompleteness,
    ) -> Result<Self, SummaryValidationError> {
        let unproven = match proof {
            ProofStatus::Proven => Vec::new(),
            ProofStatus::Unproven(reason) => vec![reason.to_string()],
        };
        let incomplete = match completeness {
            EvidenceCompleteness::Complete => Vec::new(),
            EvidenceCompleteness::Partial(reason) => vec![reason.to_string()],
        };
        Self::try_new(unproven, incomplete)
    }

    pub fn proven_complete() -> Self {
        Self {
            alternatives: vec![SummaryEvidenceAlternative {
                quality: PathQuality::PROVEN_COMPLETE,
                unproven_reasons: Box::default(),
                incomplete_reasons: Box::default(),
            }]
            .into_boxed_slice(),
        }
    }

    pub fn is_proven(&self) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| alternative.quality.is_proven())
    }

    pub fn is_complete(&self) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| alternative.quality.is_complete())
    }

    pub fn alternatives(&self) -> &[SummaryEvidenceAlternative] {
        &self.alternatives
    }

    pub fn join(&self, other: &Self) -> Result<Self, SummaryValidationError> {
        let mut alternatives = self.alternatives.to_vec();
        alternatives.extend_from_slice(&other.alternatives);
        Self::from_alternatives(alternatives)
    }

    pub fn conjoin(&self, other: &Self) -> Result<Self, SummaryValidationError> {
        let mut alternatives = Vec::new();
        for left in &self.alternatives {
            for right in &other.alternatives {
                alternatives.push(SummaryEvidenceAlternative {
                    quality: left.quality.conjoin(right.quality),
                    unproven_reasons: merge_reason_slices(
                        &left.unproven_reasons,
                        &right.unproven_reasons,
                    )?,
                    incomplete_reasons: merge_reason_slices(
                        &left.incomplete_reasons,
                        &right.incomplete_reasons,
                    )?,
                });
            }
        }
        Self::from_alternatives(alternatives)
    }

    fn from_alternatives(
        alternatives: Vec<SummaryEvidenceAlternative>,
    ) -> Result<Self, SummaryValidationError> {
        Ok(Self {
            alternatives: canonicalize_evidence_alternatives(alternatives)?,
        })
    }
}

/// One stable input-to-exit relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryTransfer {
    input: SummaryPort,
    exit: SummaryExit,
    evidence: SummaryEvidence,
}

impl SummaryTransfer {
    pub fn try_new(
        input: SummaryPort,
        exit: SummaryExit,
        evidence: SummaryEvidence,
    ) -> Result<Self, SummaryValidationError> {
        if matches!(
            input,
            SummaryPort::NormalReturn | SummaryPort::ExceptionalReturn
        ) {
            return Err(SummaryValidationError::InvalidTransferInputPort);
        }
        Ok(Self {
            input,
            exit,
            evidence,
        })
    }

    pub fn input(&self) -> &SummaryPort {
        &self.input
    }

    pub fn exit(&self) -> &SummaryExit {
        &self.exit
    }

    pub fn evidence(&self) -> &SummaryEvidence {
        &self.evidence
    }
}

/// Stable identity of one summary-visible semantic effect.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryEffectKey {
    Allocation {
        event: SummaryEventKey,
        output: SummaryPort,
    },
    Call {
        event: SummaryEventKey,
        callee: Box<SummaryDependencyKey>,
    },
    Escape {
        event: SummaryEventKey,
        input: SummaryPort,
    },
    UnknownCall {
        event: SummaryEventKey,
        input: SummaryPort,
    },
    /// A source-backed dispatch boundary whose affected input cannot be
    /// represented as a stable procedure port. Its evidence retains the
    /// boundary's proof and completeness without fabricating a heap location.
    UnknownCallBoundary { event: SummaryEventKey },
    AmbiguousCall {
        event: SummaryEventKey,
        input: SummaryPort,
        candidates: Box<[SummaryDependencyKey]>,
    },
}

impl SummaryEffectKey {
    pub fn ambiguous_call(
        event: SummaryEventKey,
        input: SummaryPort,
        mut candidates: Vec<SummaryDependencyKey>,
    ) -> Result<Self, SummaryValidationError> {
        candidates.sort_unstable();
        candidates.dedup();
        if candidates.is_empty() {
            return Err(SummaryValidationError::EmptyAmbiguousCallees);
        }
        if candidates.len() > MAX_AMBIGUOUS_SUMMARY_CALLEES {
            return Err(SummaryValidationError::TooManyAmbiguousCallees {
                actual: candidates.len(),
                limit: MAX_AMBIGUOUS_SUMMARY_CALLEES,
            });
        }
        Ok(Self::AmbiguousCall {
            event,
            input,
            candidates: candidates.into_boxed_slice(),
        })
    }
}

/// One effect plus its proof and completeness evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SummaryEffect {
    key: SummaryEffectKey,
    evidence: SummaryEvidence,
}

impl SummaryEffect {
    pub fn new(key: SummaryEffectKey, evidence: SummaryEvidence) -> Self {
        Self { key, evidence }
    }

    pub fn key(&self) -> &SummaryEffectKey {
        &self.key
    }

    pub fn evidence(&self) -> &SummaryEvidence {
        &self.evidence
    }
}

/// Why a current summary is not eligible for complete reuse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryIncompleteReason {
    Cancelled,
    BudgetExceeded(Box<str>),
    SemanticGap(Box<str>),
    DependencyIncomplete(SummaryDependencyFingerprint),
    ExternalModelIncomplete(ExternalSummaryContentHash),
}

impl SummaryIncompleteReason {
    fn validate(&self) -> Result<(), SummaryValidationError> {
        match self {
            Self::BudgetExceeded(reason) | Self::SemanticGap(reason) => validate_reason(reason),
            Self::Cancelled | Self::DependencyIncomplete(_) | Self::ExternalModelIncomplete(_) => {
                Ok(())
            }
        }
    }
}

/// Completeness of the entire reusable artifact, independent of proof strength.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SummaryCompleteness {
    Complete,
    Partial(Box<[SummaryIncompleteReason]>),
}

impl SummaryCompleteness {
    pub fn partial(
        mut reasons: Vec<SummaryIncompleteReason>,
    ) -> Result<Self, SummaryValidationError> {
        for reason in &reasons {
            reason.validate()?;
        }
        reasons.sort_unstable();
        reasons.dedup();
        if reasons.is_empty() {
            return Err(SummaryValidationError::EmptyIncompleteReasons);
        }
        if reasons.len() > MAX_SUMMARY_EVIDENCE_REASONS {
            return Err(SummaryValidationError::TooManyEvidenceReasons {
                actual: reasons.len(),
                limit: MAX_SUMMARY_EVIDENCE_REASONS,
            });
        }
        Ok(Self::Partial(reasons.into_boxed_slice()))
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn reasons(&self) -> &[SummaryIncompleteReason] {
        match self {
            Self::Complete => &[],
            Self::Partial(reasons) => reasons,
        }
    }

    fn validate(&self) -> Result<(), SummaryValidationError> {
        match self {
            Self::Complete => Ok(()),
            Self::Partial(reasons) => {
                let normalized = Self::partial(reasons.to_vec())?;
                if &normalized != self {
                    return Err(SummaryValidationError::NonCanonicalIncompleteReasons);
                }
                Ok(())
            }
        }
    }

    fn join_alternatives(&self, other: &Self) -> Result<Self, SummaryValidationError> {
        if self.is_complete() || other.is_complete() {
            return Ok(Self::Complete);
        }
        let mut reasons = self.reasons().to_vec();
        reasons.extend_from_slice(other.reasons());
        Self::partial(reasons)
    }

    fn conjoin(&self, other: &Self) -> Result<Self, SummaryValidationError> {
        match (self, other) {
            (Self::Complete, Self::Complete) => Ok(Self::Complete),
            _ => {
                let mut reasons = self.reasons().to_vec();
                reasons.extend_from_slice(other.reasons());
                Self::partial(reasons)
            }
        }
    }
}

/// Stable reusable semantic effects for one exact procedure validity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticProcedureSummary {
    key: ProcedureSummaryKey,
    composition_root: ProcedureSummaryKey,
    recursive_topology: Box<[SummaryRecursiveEdge]>,
    transfers: Box<[SummaryTransfer]>,
    effects: Box<[SummaryEffect]>,
    dependencies: Box<[SummaryDependencyKey]>,
    completeness: SummaryCompleteness,
}

impl SemanticProcedureSummary {
    pub fn try_new(
        key: ProcedureSummaryKey,
        transfers: Vec<SummaryTransfer>,
        effects: Vec<SummaryEffect>,
        dependencies: Vec<SummaryDependencyKey>,
        completeness: SummaryCompleteness,
    ) -> Result<Self, SummaryValidationError> {
        let recursive_topology = recursive_edges_for_dependencies(key.identity(), &dependencies);
        Self::try_new_with_root(
            key.clone(),
            key,
            recursive_topology,
            transfers,
            effects,
            dependencies,
            completeness,
        )
    }

    fn try_new_with_root(
        key: ProcedureSummaryKey,
        composition_root: ProcedureSummaryKey,
        recursive_topology: Vec<SummaryRecursiveEdge>,
        transfers: Vec<SummaryTransfer>,
        effects: Vec<SummaryEffect>,
        dependencies: Vec<SummaryDependencyKey>,
        completeness: SummaryCompleteness,
    ) -> Result<Self, SummaryValidationError> {
        if transfers.len() > MAX_SUMMARY_TRANSFERS {
            return Err(SummaryValidationError::TooManyTransfers {
                actual: transfers.len(),
                limit: MAX_SUMMARY_TRANSFERS,
            });
        }
        if effects.len() > MAX_SUMMARY_EFFECTS {
            return Err(SummaryValidationError::TooManyEffects {
                actual: effects.len(),
                limit: MAX_SUMMARY_EFFECTS,
            });
        }
        validate_raw_effect_reference_bound(&effects)?;
        completeness.validate()?;
        if key.identity() != composition_root.identity() {
            return Err(SummaryValidationError::CompositionRootIdentityMismatch);
        }
        let expected_root = (key != composition_root).then(|| {
            SummaryCompositionRootFingerprint::from_digest(composition_root.fingerprint())
        });
        if key.composition_root() != expected_root {
            return Err(SummaryValidationError::CompositionRootFingerprintMismatch);
        }

        let transfers = canonicalize_transfers(transfers)?;
        let effects = canonicalize_effects(effects)?;
        let dependencies = canonicalize_dependencies(dependencies)?;
        let recursive_topology =
            canonicalize_recursive_topology(recursive_topology, key.identity(), &dependencies)?;
        if key.dependencies() != SummaryDependencyFingerprint::from_dependencies(&dependencies) {
            return Err(SummaryValidationError::DependencyFingerprintMismatch);
        }
        validate_effect_dependencies(&effects, &dependencies)?;
        if key.recursive_group().is_none()
            && dependencies
                .iter()
                .any(|dependency| matches!(dependency, SummaryDependencyKey::Recursive(_)))
        {
            return Err(SummaryValidationError::RecursiveDependencyWithoutGroup);
        }
        if completeness.is_complete() && transfers.iter().any(|row| !row.evidence.is_complete()) {
            return Err(SummaryValidationError::CompleteSummaryHasIncompleteTransfer);
        }
        if completeness.is_complete()
            && effects.iter().any(|row| {
                !row.evidence.is_complete()
                    && !matches!(row.key, SummaryEffectKey::UnknownCallBoundary { .. })
            })
        {
            return Err(SummaryValidationError::CompleteSummaryHasIncompleteEffect);
        }

        Ok(Self {
            key,
            composition_root,
            recursive_topology,
            transfers,
            effects,
            dependencies,
            completeness,
        })
    }

    pub fn key(&self) -> &ProcedureSummaryKey {
        &self.key
    }

    /// The original procedure key represented by this composition's leftmost stage.
    pub fn composition_root(&self) -> &ProcedureSummaryKey {
        &self.composition_root
    }

    pub fn recursive_topology(&self) -> &[SummaryRecursiveEdge] {
        &self.recursive_topology
    }

    pub const fn origin(&self) -> &SummaryOrigin {
        self.key.origin()
    }

    pub fn transfers(&self) -> &[SummaryTransfer] {
        &self.transfers
    }

    pub fn effects(&self) -> &[SummaryEffect] {
        &self.effects
    }

    pub fn dependencies(&self) -> &[SummaryDependencyKey] {
        &self.dependencies
    }

    pub const fn recursive_group(&self) -> Option<SummaryRecursiveGroupKey> {
        self.key.recursive_group()
    }

    pub const fn completeness(&self) -> &SummaryCompleteness {
        &self.completeness
    }

    /// Conservative retained heap estimate including the repository's cloned map key.
    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(size_of::<ProcedureSummaryKey>())
            .saturating_add(procedure_key_heap_bytes(&self.key).saturating_mul(2))
            .saturating_add(size_of::<ProcedureSummaryKey>())
            .saturating_add(procedure_key_heap_bytes(&self.composition_root))
            .saturating_add(size_of_val(self.recursive_topology()))
            .saturating_add(
                self.recursive_topology
                    .iter()
                    .map(recursive_edge_heap_bytes)
                    .fold(0_usize, usize::saturating_add),
            )
            .saturating_add(size_of_val(self.transfers()))
            .saturating_add(
                self.transfers
                    .iter()
                    .map(|row| evidence_heap_bytes(&row.evidence))
                    .fold(0_usize, usize::saturating_add),
            )
            .saturating_add(size_of_val(self.effects()))
            .saturating_add(
                self.effects
                    .iter()
                    .map(effect_heap_bytes)
                    .fold(0_usize, usize::saturating_add),
            )
            .saturating_add(size_of_val(self.dependencies()))
            .saturating_add(
                self.dependencies
                    .iter()
                    .map(dependency_heap_bytes)
                    .fold(0_usize, usize::saturating_add),
            )
            .saturating_add(completeness_heap_bytes(&self.completeness))
    }

    /// Join alternative effects for the same exact summary identity.
    pub fn join(&self, other: &Self) -> Result<Self, SummaryCompositionError> {
        if self.key != other.key {
            return Err(SummaryCompositionError::KeyMismatch);
        }
        if self.dependencies != other.dependencies {
            return Err(SummaryCompositionError::DependencyMismatch);
        }
        if self.composition_root != other.composition_root {
            return Err(SummaryCompositionError::CompositionRootMismatch);
        }
        if self.recursive_topology != other.recursive_topology {
            return Err(SummaryCompositionError::RecursiveTopologyMismatch);
        }

        let mut transfers = self.transfers.to_vec();
        transfers.extend_from_slice(&other.transfers);
        let mut effects = self.effects.to_vec();
        effects.extend_from_slice(&other.effects);
        let transfers =
            canonicalize_transfers(transfers).map_err(SummaryCompositionError::InvalidResult)?;
        let effects =
            canonicalize_effects(effects).map_err(SummaryCompositionError::InvalidResult)?;
        Self::try_new_with_root(
            self.key.clone(),
            self.composition_root.clone(),
            self.recursive_topology.to_vec(),
            transfers.into_vec(),
            effects.into_vec(),
            self.dependencies.to_vec(),
            self.completeness
                .join_alternatives(&other.completeness)
                .map_err(SummaryCompositionError::InvalidResult)?,
        )
        .map_err(SummaryCompositionError::InvalidResult)
    }

    /// Compose `next` after this summary under an explicit boundary map.
    pub fn compose(
        &self,
        next: &Self,
        call_event: SummaryEventKey,
        boundaries: &SummaryBoundaryMap,
    ) -> Result<Self, SummaryCompositionError> {
        if !summary_families_compatible(self.key.identity(), next.key.identity()) {
            return Err(SummaryCompositionError::IncompatibleSummaryFamilies);
        }

        let (transfers, invocation_evidence) =
            compose_summary_transfers(&self.transfers, &next.transfers, boundaries)?;
        let mut effects = self.effects.to_vec();
        let mut dependencies = self.dependencies.to_vec();
        let invoked = invocation_evidence.is_some();
        let completeness = if let Some(invocation_evidence) = invocation_evidence {
            let next_dependency = if self.key.recursive_group().is_some()
                && self.key.recursive_group() == next.key.recursive_group()
            {
                SummaryDependencyKey::recursive(next.composition_root.identity().clone())
            } else {
                SummaryDependencyKey::complete(next.composition_root.clone())
            };
            dependencies.push(next_dependency.clone());
            dependencies.extend_from_slice(&next.dependencies);
            effects.push(SummaryEffect::new(
                SummaryEffectKey::Call {
                    event: call_event,
                    callee: Box::new(next_dependency),
                },
                invocation_evidence.clone(),
            ));
            for effect in &next.effects {
                effects.push(SummaryEffect::new(
                    effect.key.clone(),
                    invocation_evidence
                        .conjoin(&effect.evidence)
                        .map_err(SummaryCompositionError::InvalidResult)?,
                ));
            }
            self.completeness
                .conjoin(&next.completeness)
                .map_err(SummaryCompositionError::InvalidResult)?
        } else {
            self.completeness.clone()
        };
        let effects =
            canonicalize_effects(effects).map_err(SummaryCompositionError::InvalidResult)?;
        let dependencies = canonicalize_dependencies(dependencies)
            .map_err(SummaryCompositionError::InvalidResult)?;
        let mut recursive_topology = self.recursive_topology.to_vec();
        if invoked
            && self.key.recursive_group().is_some()
            && self.key.recursive_group() == next.key.recursive_group()
        {
            recursive_topology.push(SummaryRecursiveEdge::new(
                self.key.identity().clone(),
                next.composition_root.identity().clone(),
            ));
        }
        let output_key = ProcedureSummaryKey::try_new_composed(
            self.key.identity().clone(),
            &dependencies,
            self.key.recursive_group(),
            &self.composition_root,
        )
        .map_err(SummaryCompositionError::InvalidResult)?;
        Self::try_new_with_root(
            output_key,
            self.composition_root.clone(),
            recursive_topology,
            transfers.into_vec(),
            effects.into_vec(),
            dependencies.into_vec(),
            completeness,
        )
        .map_err(SummaryCompositionError::InvalidResult)
    }
}

/// Explicit connection from one relation's normal output to the next input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SummaryBoundaryBinding {
    output: SummaryPort,
    input: SummaryPort,
}

impl SummaryBoundaryBinding {
    pub fn try_new(
        output: SummaryPort,
        input: SummaryPort,
    ) -> Result<Self, SummaryValidationError> {
        if output == SummaryPort::ExceptionalReturn {
            return Err(SummaryValidationError::InvalidBoundaryOutputPort);
        }
        if matches!(
            input,
            SummaryPort::NormalReturn | SummaryPort::ExceptionalReturn
        ) {
            return Err(SummaryValidationError::InvalidBoundaryInputPort);
        }
        Ok(Self { output, input })
    }

    pub fn output(&self) -> &SummaryPort {
        &self.output
    }

    pub fn input(&self) -> &SummaryPort {
        &self.input
    }
}

/// Canonical finite map required to compose two stable boundary relations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryBoundaryMap(Box<[SummaryBoundaryBinding]>);

impl SummaryBoundaryMap {
    pub fn try_new(
        mut bindings: Vec<SummaryBoundaryBinding>,
    ) -> Result<Self, SummaryValidationError> {
        bindings.sort_unstable();
        bindings.dedup();
        if bindings.is_empty() {
            return Err(SummaryValidationError::EmptyBoundaryMap);
        }
        if bindings.len() > MAX_SUMMARY_BOUNDARY_BINDINGS {
            return Err(SummaryValidationError::TooManyBoundaryBindings {
                actual: bindings.len(),
                limit: MAX_SUMMARY_BOUNDARY_BINDINGS,
            });
        }
        Ok(Self(bindings.into_boxed_slice()))
    }

    pub fn bindings(&self) -> &[SummaryBoundaryBinding] {
        &self.0
    }
}

/// Compose two canonical relations using only explicitly supplied bindings.
///
/// Exceptional exits from `first` remain exits of the composition. Normal
/// exits continue only when `boundaries` maps them to an input in `second`.
fn compose_summary_transfers(
    first: &[SummaryTransfer],
    second: &[SummaryTransfer],
    boundaries: &SummaryBoundaryMap,
) -> Result<(Box<[SummaryTransfer]>, Option<SummaryEvidence>), SummaryCompositionError> {
    if first.len() > MAX_SUMMARY_TRANSFERS || second.len() > MAX_SUMMARY_TRANSFERS {
        return Err(SummaryCompositionError::TooManyComposedTransfers {
            limit: MAX_SUMMARY_TRANSFERS,
        });
    }
    let ProductiveContinuations {
        rows: continuations,
        invocation_outputs,
        mut work,
    } = productive_continuations(second, boundaries)?;
    let mut composed: HashMap<(SummaryPort, SummaryExit), SummaryEvidence> =
        map_with_capacity(first.len().min(MAX_SUMMARY_TRANSFERS));
    let mut invocation_evidence: Option<SummaryEvidence> = None;
    for left in first {
        if left.exit.kind == SummaryExitKind::Exceptional {
            work = checked_composition_work(work, 1)?;
            insert_composed_transfer(&mut composed, left.clone())?;
            continue;
        }
        if invocation_outputs.contains(&left.exit.port) {
            invocation_evidence = Some(match invocation_evidence {
                Some(existing) => existing
                    .join(&left.evidence)
                    .map_err(SummaryCompositionError::InvalidResult)?,
                None => left.evidence.clone(),
            });
        }
        let Some(rows) = continuations.get(&left.exit.port) else {
            continue;
        };
        work = checked_composition_work(work, rows.len())?;
        for right in rows {
            let transfer = SummaryTransfer::try_new(
                left.input.clone(),
                right.exit.clone(),
                left.evidence
                    .conjoin(&right.evidence)
                    .map_err(SummaryCompositionError::InvalidResult)?,
            )
            .map_err(SummaryCompositionError::InvalidResult)?;
            insert_composed_transfer(&mut composed, transfer)?;
        }
    }
    let rows = composed
        .into_iter()
        .map(|((input, exit), evidence)| SummaryTransfer {
            input,
            exit,
            evidence,
        })
        .collect();
    Ok((
        canonicalize_transfers(rows).map_err(SummaryCompositionError::InvalidResult)?,
        invocation_evidence,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryPublicationOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryRepositoryLimits {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for SummaryRepositoryLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_SUMMARY_REPOSITORY_ENTRIES,
            max_bytes: DEFAULT_SUMMARY_REPOSITORY_BYTES,
        }
    }
}

/// Complete in-memory summaries with preflighted atomic SCC publication.
#[derive(Debug)]
pub struct CompleteSummaryRepository {
    entries: HashMap<ProcedureSummaryKey, SemanticProcedureSummary>,
    retained_bytes: usize,
    limits: SummaryRepositoryLimits,
}

impl Default for CompleteSummaryRepository {
    fn default() -> Self {
        Self::with_limits(SummaryRepositoryLimits::default())
    }
}

impl CompleteSummaryRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: SummaryRepositoryLimits) -> Self {
        Self {
            entries: HashMap::default(),
            retained_bytes: 0,
            limits,
        }
    }

    pub fn get(&self, key: &ProcedureSummaryKey) -> Option<&SemanticProcedureSummary> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub const fn limits(&self) -> SummaryRepositoryLimits {
        self.limits
    }

    /// Drop every retained revision so an owner can rotate repository generations.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.retained_bytes = 0;
    }

    pub fn publish(
        &mut self,
        summary: SemanticProcedureSummary,
    ) -> Result<SummaryPublicationOutcome, SummaryPublicationError> {
        validate_publishable(&summary)?;
        if summary.recursive_group().is_some() {
            return Err(SummaryPublicationError::RequiresAtomicScc);
        }
        self.validate_dependencies(&summary, &[])?;
        self.publish_preflighted(summary)
    }

    pub fn publish_scc(
        &mut self,
        summaries: Vec<SemanticProcedureSummary>,
    ) -> Result<SummaryPublicationOutcome, SummaryPublicationError> {
        let summary_refs = summaries.iter().collect::<Vec<_>>();
        let validated = validate_recursive_summary_batch(&summary_refs)?;
        for summary in &summaries {
            self.validate_dependencies(summary, &validated.identities)?;
        }

        let mut inserted = false;
        let mut added_entries = 0_usize;
        let mut added_bytes = 0_usize;
        for summary in &summaries {
            if let Some(existing) = self.entries.get(&summary.key) {
                if existing != summary {
                    return Err(SummaryPublicationError::ConflictingEntry);
                }
            } else {
                inserted = true;
                added_entries = added_entries.saturating_add(1);
                added_bytes = added_bytes.saturating_add(summary.retained_bytes());
            }
        }
        self.preflight_capacity(added_entries, added_bytes)?;
        for summary in summaries {
            if !self.entries.contains_key(&summary.key) {
                self.retained_bytes = self.retained_bytes.saturating_add(summary.retained_bytes());
                self.entries.insert(summary.key.clone(), summary);
            }
        }
        Ok(if inserted {
            SummaryPublicationOutcome::Inserted
        } else {
            SummaryPublicationOutcome::AlreadyPresent
        })
    }

    fn publish_preflighted(
        &mut self,
        summary: SemanticProcedureSummary,
    ) -> Result<SummaryPublicationOutcome, SummaryPublicationError> {
        match self.entries.get(&summary.key) {
            Some(existing) if existing == &summary => Ok(SummaryPublicationOutcome::AlreadyPresent),
            Some(_) => Err(SummaryPublicationError::ConflictingEntry),
            None => {
                self.preflight_capacity(1, summary.retained_bytes())?;
                self.retained_bytes = self.retained_bytes.saturating_add(summary.retained_bytes());
                self.entries.insert(summary.key.clone(), summary);
                Ok(SummaryPublicationOutcome::Inserted)
            }
        }
    }

    fn validate_dependencies(
        &self,
        summary: &SemanticProcedureSummary,
        batch_identities: &[ProcedureSummaryIdentity],
    ) -> Result<(), SummaryPublicationError> {
        for dependency in &summary.dependencies {
            match dependency {
                SummaryDependencyKey::Complete(key) => {
                    if batch_identities.binary_search(key.identity()).is_ok() {
                        return Err(SummaryPublicationError::InternalDependencyMustBeRecursive);
                    }
                    if self.entries.contains_key(key) {
                        continue;
                    }
                    return Err(SummaryPublicationError::MissingDependency);
                }
                SummaryDependencyKey::Recursive(identity) => {
                    if batch_identities.binary_search(identity).is_err() {
                        return Err(SummaryPublicationError::MissingRecursiveDependency);
                    }
                }
            }
        }
        Ok(())
    }

    fn preflight_capacity(
        &self,
        added_entries: usize,
        added_bytes: usize,
    ) -> Result<(), SummaryPublicationError> {
        let entries = self.entries.len().saturating_add(added_entries);
        let bytes = self.retained_bytes.saturating_add(added_bytes);
        if entries > self.limits.max_entries || bytes > self.limits.max_bytes {
            return Err(SummaryPublicationError::CapacityExceeded {
                entries,
                entry_limit: self.limits.max_entries,
                bytes,
                byte_limit: self.limits.max_bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryValidationError {
    ZeroSchemaVersion,
    EmptyExternalModelId,
    InvalidExternalModelId,
    ExternalModelIdTooLarge { actual: usize, limit: usize },
    ZeroExternalContractVersion,
    EmptyEvidenceReason,
    EvidenceReasonTooLarge { actual: usize, limit: usize },
    TooManyEvidenceReasons { actual: usize, limit: usize },
    IncompatibleExitPort,
    InvalidTransferInputPort,
    InvalidBoundaryOutputPort,
    InvalidBoundaryInputPort,
    EmptyIncompleteReasons,
    NonCanonicalIncompleteReasons,
    TooManyTransfers { actual: usize, limit: usize },
    TooManyEffects { actual: usize, limit: usize },
    CompleteSummaryHasIncompleteTransfer,
    CompleteSummaryHasIncompleteEffect,
    EmptyRecursiveGroup,
    TooManyRecursiveMembers { actual: usize, limit: usize },
    RecursiveEdgeOutsideGroup,
    TooManyDependencies { actual: usize, limit: usize },
    DependencyFingerprintMismatch,
    CompositionRootIdentityMismatch,
    CompositionRootFingerprintMismatch,
    EffectDependenciesMismatch,
    RecursiveDependencyWithoutGroup,
    RecursiveTopologyDependencyMismatch,
    TooManyEffectReferences { actual: usize, limit: usize },
    EmptyBoundaryMap,
    TooManyBoundaryBindings { actual: usize, limit: usize },
    EmptyAmbiguousCallees,
    TooManyAmbiguousCallees { actual: usize, limit: usize },
}

impl fmt::Display for SummaryValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSchemaVersion => formatter.write_str("summary schema version must be non-zero"),
            Self::EmptyExternalModelId => formatter.write_str("external summary model ID must not be empty"),
            Self::InvalidExternalModelId => formatter.write_str("external summary model ID must not contain surrounding whitespace or control characters"),
            Self::ExternalModelIdTooLarge { actual, limit } => write!(formatter, "external summary model ID uses {actual} bytes, limit is {limit}"),
            Self::ZeroExternalContractVersion => formatter.write_str("external summary contract version must be non-zero"),
            Self::EmptyEvidenceReason => formatter.write_str("summary evidence reason must not be empty"),
            Self::EvidenceReasonTooLarge { actual, limit } => write!(formatter, "summary evidence reason uses {actual} bytes, limit is {limit}"),
            Self::TooManyEvidenceReasons { actual, limit } => write!(formatter, "summary has {actual} evidence reasons, limit is {limit}"),
            Self::IncompatibleExitPort => formatter.write_str("summary exit kind is incompatible with its return port"),
            Self::InvalidTransferInputPort => formatter.write_str("summary transfer inputs cannot be return ports"),
            Self::InvalidBoundaryOutputPort => formatter.write_str("exceptional returns cannot continue through a normal summary boundary"),
            Self::InvalidBoundaryInputPort => formatter.write_str("summary boundary inputs cannot be return ports"),
            Self::EmptyIncompleteReasons => formatter.write_str("a partial summary requires at least one incomplete reason"),
            Self::NonCanonicalIncompleteReasons => formatter.write_str("partial summary reasons must be sorted and unique"),
            Self::TooManyTransfers { actual, limit } => write!(formatter, "summary has {actual} transfers, limit is {limit}"),
            Self::TooManyEffects { actual, limit } => write!(formatter, "summary has {actual} effects, limit is {limit}"),
            Self::CompleteSummaryHasIncompleteTransfer => formatter.write_str("a complete summary cannot contain an incomplete transfer"),
            Self::CompleteSummaryHasIncompleteEffect => formatter.write_str("a complete summary cannot contain an incomplete effect"),
            Self::EmptyRecursiveGroup => formatter.write_str("a recursive summary group must not be empty"),
            Self::TooManyRecursiveMembers { actual, limit } => write!(formatter, "summary recursive group has {actual} members, limit is {limit}"),
            Self::RecursiveEdgeOutsideGroup => formatter.write_str("summary recursive edges must connect members of the declared group"),
            Self::TooManyDependencies { actual, limit } => write!(formatter, "summary has {actual} retained dependencies, limit is {limit}"),
            Self::DependencyFingerprintMismatch => formatter.write_str("summary dependency keys do not match the cache-key fingerprint"),
            Self::CompositionRootIdentityMismatch => formatter.write_str("a composed summary must retain the leftmost procedure identity"),
            Self::CompositionRootFingerprintMismatch => formatter.write_str("a composed summary key must include its exact leftmost procedure key"),
            Self::EffectDependenciesMismatch => formatter.write_str("summary call effects do not exactly match its retained dependency closure"),
            Self::RecursiveDependencyWithoutGroup => formatter.write_str("recursive dependencies require an atomic recursive group"),
            Self::RecursiveTopologyDependencyMismatch => formatter.write_str("recursive topology edges must originate at the summary owner and name retained recursive dependencies"),
            Self::TooManyEffectReferences { actual, limit } => write!(formatter, "summary effects retain {actual} dependency references, limit is {limit}"),
            Self::EmptyBoundaryMap => formatter.write_str("summary composition requires at least one explicit boundary binding"),
            Self::TooManyBoundaryBindings { actual, limit } => write!(formatter, "summary boundary map has {actual} bindings, limit is {limit}"),
            Self::EmptyAmbiguousCallees => formatter.write_str("an ambiguous-call effect requires at least one candidate"),
            Self::TooManyAmbiguousCallees { actual, limit } => write!(formatter, "ambiguous-call effect has {actual} candidates, limit is {limit}"),
        }
    }
}

impl std::error::Error for SummaryValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryCompositionError {
    KeyMismatch,
    RecursiveGroupMismatch,
    DependencyMismatch,
    CompositionRootMismatch,
    RecursiveTopologyMismatch,
    OutputIdentityMismatch,
    IncompatibleSummaryFamilies,
    TooManyComposedTransfers { limit: usize },
    CompositionWorkExceeded { limit: usize },
    InvalidResult(SummaryValidationError),
}

impl fmt::Display for SummaryCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMismatch => {
                formatter.write_str("cannot join summaries with different validity keys")
            }
            Self::RecursiveGroupMismatch => {
                formatter.write_str("cannot join summaries with different recursive groups")
            }
            Self::DependencyMismatch => {
                formatter.write_str("cannot join summaries with different dependency closures")
            }
            Self::CompositionRootMismatch => {
                formatter.write_str("cannot join summaries with different composition roots")
            }
            Self::RecursiveTopologyMismatch => {
                formatter.write_str("cannot join summaries with different recursive topology")
            }
            Self::OutputIdentityMismatch => {
                formatter.write_str("composed output must retain the first summary's identity")
            }
            Self::IncompatibleSummaryFamilies => formatter.write_str(
                "summary composition requires matching schema, semantics, context, and behavior",
            ),
            Self::TooManyComposedTransfers { limit } => write!(
                formatter,
                "summary composition exceeded the {limit}-transfer limit"
            ),
            Self::CompositionWorkExceeded { limit } => write!(
                formatter,
                "summary composition exceeded the {limit}-step work limit"
            ),
            Self::InvalidResult(error) => write!(formatter, "composed summary is invalid: {error}"),
        }
    }
}

impl std::error::Error for SummaryCompositionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidResult(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryPublicationError {
    InvalidSummary(SummaryValidationError),
    IncompleteSummary,
    RequiresAtomicScc,
    EmptyScc,
    TooManySccMembers {
        actual: usize,
        limit: usize,
    },
    TooManySccDependencies {
        actual: usize,
        limit: usize,
    },
    DuplicateSccMember,
    DuplicateSccIdentity,
    SccMembershipMismatch,
    SccNotStronglyConnected,
    InternalDependencyMustBeRecursive,
    MissingDependency,
    MissingRecursiveDependency,
    MissingDeclaredRecursiveEdge,
    ConflictingEntry,
    CapacityExceeded {
        entries: usize,
        entry_limit: usize,
        bytes: usize,
        byte_limit: usize,
    },
}

impl fmt::Display for SummaryPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSummary(error) => write!(formatter, "invalid summary batch: {error}"),
            Self::IncompleteSummary => {
                formatter.write_str("only complete summaries may be published for reuse")
            }
            Self::RequiresAtomicScc => {
                formatter.write_str("a recursive summary must be published with its complete SCC")
            }
            Self::EmptyScc => formatter.write_str("an SCC publication batch must not be empty"),
            Self::TooManySccMembers { actual, limit } => write!(
                formatter,
                "SCC publication has {actual} members, limit is {limit}"
            ),
            Self::TooManySccDependencies { actual, limit } => write!(
                formatter,
                "SCC publication has {actual} aggregate dependencies, limit is {limit}"
            ),
            Self::DuplicateSccMember => {
                formatter.write_str("SCC publication contains a duplicate procedure key")
            }
            Self::DuplicateSccIdentity => {
                formatter.write_str("SCC publication contains duplicate procedure identities")
            }
            Self::SccMembershipMismatch => formatter.write_str(
                "SCC publication does not exactly match every member's declared recursive group",
            ),
            Self::SccNotStronglyConnected => {
                formatter.write_str("recursive publication dependencies are not strongly connected")
            }
            Self::InternalDependencyMustBeRecursive => formatter.write_str(
                "dependencies on members of the same publication batch must be recursive",
            ),
            Self::MissingDependency => formatter
                .write_str("summary publication requires every exact dependency to be published"),
            Self::MissingRecursiveDependency => formatter.write_str(
                "recursive summary publication references an identity outside its atomic batch",
            ),
            Self::MissingDeclaredRecursiveEdge => formatter.write_str(
                "declared recursive topology is not represented by the source member's dependencies",
            ),
            Self::ConflictingEntry => formatter
                .write_str("a different complete summary is already published under this key"),
            Self::CapacityExceeded {
                entries,
                entry_limit,
                bytes,
                byte_limit,
            } => write!(
                formatter,
                "summary repository capacity exceeded: {entries}/{entry_limit} entries and {bytes}/{byte_limit} bytes"
            ),
        }
    }
}

impl std::error::Error for SummaryPublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSummary(error) => Some(error),
            _ => None,
        }
    }
}

fn canonicalize_reason_strings(
    reasons: Vec<String>,
) -> Result<Box<[Box<str>]>, SummaryValidationError> {
    if reasons.len() > MAX_SUMMARY_EVIDENCE_REASONS {
        return Err(SummaryValidationError::TooManyEvidenceReasons {
            actual: reasons.len(),
            limit: MAX_SUMMARY_EVIDENCE_REASONS,
        });
    }
    let mut reasons: Vec<Box<str>> = reasons.into_iter().map(String::into_boxed_str).collect();
    for reason in &reasons {
        validate_reason(reason)?;
    }
    reasons.sort_unstable();
    reasons.dedup();
    Ok(reasons.into_boxed_slice())
}

fn validate_reason(reason: &str) -> Result<(), SummaryValidationError> {
    if reason.is_empty() {
        return Err(SummaryValidationError::EmptyEvidenceReason);
    }
    if reason.len() > MAX_SUMMARY_REASON_BYTES {
        return Err(SummaryValidationError::EvidenceReasonTooLarge {
            actual: reason.len(),
            limit: MAX_SUMMARY_REASON_BYTES,
        });
    }
    Ok(())
}

fn merge_reason_slices(
    left: &[Box<str>],
    right: &[Box<str>],
) -> Result<Box<[Box<str>]>, SummaryValidationError> {
    let mut reasons = Vec::with_capacity(left.len().saturating_add(right.len()));
    reasons.extend_from_slice(left);
    reasons.extend_from_slice(right);
    reasons.sort_unstable();
    reasons.dedup();
    if reasons.len() > MAX_SUMMARY_EVIDENCE_REASONS {
        return Err(SummaryValidationError::TooManyEvidenceReasons {
            actual: reasons.len(),
            limit: MAX_SUMMARY_EVIDENCE_REASONS,
        });
    }
    Ok(reasons.into_boxed_slice())
}

fn quality_from_reasons(
    unproven_reasons: &[Box<str>],
    incomplete_reasons: &[Box<str>],
) -> PathQuality {
    match (unproven_reasons.is_empty(), incomplete_reasons.is_empty()) {
        (true, true) => PathQuality::PROVEN_COMPLETE,
        (true, false) => PathQuality::PROVEN_PARTIAL,
        (false, true) => PathQuality::UNPROVEN_COMPLETE,
        (false, false) => PathQuality::UNPROVEN_PARTIAL,
    }
}

fn canonicalize_evidence_alternatives(
    alternatives: Vec<SummaryEvidenceAlternative>,
) -> Result<Box<[SummaryEvidenceAlternative]>, SummaryValidationError> {
    let mut by_quality: [Option<SummaryEvidenceAlternative>; 4] = std::array::from_fn(|_| None);
    for alternative in alternatives {
        let slot = &mut by_quality[alternative.quality.ordinal()];
        if let Some(existing) = slot {
            existing.unproven_reasons =
                merge_reason_slices(&existing.unproven_reasons, &alternative.unproven_reasons)?;
            existing.incomplete_reasons = merge_reason_slices(
                &existing.incomplete_reasons,
                &alternative.incomplete_reasons,
            )?;
        } else {
            *slot = Some(alternative);
        }
    }

    let mut frontier = PathQualityFrontier::default();
    for alternative in by_quality.iter().flatten() {
        frontier.insert(alternative.quality);
    }
    let canonical = PathQuality::ALL
        .into_iter()
        .filter(|quality| frontier.contains(*quality))
        .filter_map(|quality| by_quality[quality.ordinal()].take())
        .collect::<Vec<_>>();
    debug_assert!(!canonical.is_empty());
    Ok(canonical.into_boxed_slice())
}

fn canonicalize_transfers(
    mut transfers: Vec<SummaryTransfer>,
) -> Result<Box<[SummaryTransfer]>, SummaryValidationError> {
    transfers.sort_unstable_by(|left, right| {
        (&left.input, &left.exit).cmp(&(&right.input, &right.exit))
    });
    let mut canonical: Vec<SummaryTransfer> = Vec::with_capacity(transfers.len());
    for transfer in transfers {
        match canonical.last_mut() {
            Some(existing)
                if existing.input == transfer.input && existing.exit == transfer.exit =>
            {
                existing.evidence = existing.evidence.join(&transfer.evidence)?;
            }
            _ => canonical.push(transfer),
        }
    }
    Ok(canonical.into_boxed_slice())
}

fn validate_raw_effect_reference_bound(
    effects: &[SummaryEffect],
) -> Result<(), SummaryValidationError> {
    let mut references = 0_usize;
    for effect in effects {
        references = references.saturating_add(effect_reference_count(effect.key()));
        if references > MAX_SUMMARY_EFFECT_REFERENCES {
            return Err(SummaryValidationError::TooManyEffectReferences {
                actual: references,
                limit: MAX_SUMMARY_EFFECT_REFERENCES,
            });
        }
    }
    Ok(())
}

fn canonicalize_effects(
    mut effects: Vec<SummaryEffect>,
) -> Result<Box<[SummaryEffect]>, SummaryValidationError> {
    for effect in &mut effects {
        if let SummaryEffectKey::AmbiguousCall { candidates, .. } = &mut effect.key {
            let mut normalized = candidates.to_vec();
            normalized.sort_unstable();
            normalized.dedup();
            if normalized.is_empty() {
                return Err(SummaryValidationError::EmptyAmbiguousCallees);
            }
            if normalized.len() > MAX_AMBIGUOUS_SUMMARY_CALLEES {
                return Err(SummaryValidationError::TooManyAmbiguousCallees {
                    actual: normalized.len(),
                    limit: MAX_AMBIGUOUS_SUMMARY_CALLEES,
                });
            }
            *candidates = normalized.into_boxed_slice();
        }
    }
    effects.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    let mut canonical: Vec<SummaryEffect> = Vec::with_capacity(effects.len());
    for effect in effects {
        match canonical.last_mut() {
            Some(existing) if existing.key == effect.key => {
                existing.evidence = existing.evidence.join(&effect.evidence)?;
            }
            _ => canonical.push(effect),
        }
    }
    let references = canonical
        .iter()
        .map(|effect| effect_reference_count(&effect.key))
        .fold(0_usize, usize::saturating_add);
    if references > MAX_SUMMARY_EFFECT_REFERENCES {
        return Err(SummaryValidationError::TooManyEffectReferences {
            actual: references,
            limit: MAX_SUMMARY_EFFECT_REFERENCES,
        });
    }
    Ok(canonical.into_boxed_slice())
}

fn canonicalize_dependencies(
    mut dependencies: Vec<SummaryDependencyKey>,
) -> Result<Box<[SummaryDependencyKey]>, SummaryValidationError> {
    dependencies.sort_unstable();
    dependencies.dedup();
    if dependencies.len() > MAX_SUMMARY_DEPENDENCIES {
        return Err(SummaryValidationError::TooManyDependencies {
            actual: dependencies.len(),
            limit: MAX_SUMMARY_DEPENDENCIES,
        });
    }
    Ok(dependencies.into_boxed_slice())
}

fn recursive_edges_for_dependencies(
    caller: &ProcedureSummaryIdentity,
    dependencies: &[SummaryDependencyKey],
) -> Vec<SummaryRecursiveEdge> {
    dependencies
        .iter()
        .filter_map(|dependency| match dependency {
            SummaryDependencyKey::Recursive(callee) => Some(SummaryRecursiveEdge::new(
                caller.clone(),
                (**callee).clone(),
            )),
            SummaryDependencyKey::Complete(_) => None,
        })
        .collect()
}

fn canonicalize_recursive_topology(
    mut topology: Vec<SummaryRecursiveEdge>,
    owner: &ProcedureSummaryIdentity,
    dependencies: &[SummaryDependencyKey],
) -> Result<Box<[SummaryRecursiveEdge]>, SummaryValidationError> {
    if topology.len() > MAX_SUMMARY_DEPENDENCIES {
        return Err(SummaryValidationError::TooManyDependencies {
            actual: topology.len(),
            limit: MAX_SUMMARY_DEPENDENCIES,
        });
    }
    topology.sort_unstable();
    topology.dedup();
    for edge in &topology {
        if edge.caller() != owner
            || !dependencies.iter().any(|dependency| {
                matches!(dependency, SummaryDependencyKey::Recursive(callee) if callee.as_ref() == edge.callee())
            })
        {
            return Err(SummaryValidationError::RecursiveTopologyDependencyMismatch);
        }
    }
    Ok(topology.into_boxed_slice())
}

fn validate_effect_dependencies(
    effects: &[SummaryEffect],
    dependencies: &[SummaryDependencyKey],
) -> Result<(), SummaryValidationError> {
    let mut referenced = Vec::new();
    for effect in effects {
        match &effect.key {
            SummaryEffectKey::Call { callee, .. } => referenced.push((**callee).clone()),
            SummaryEffectKey::AmbiguousCall { candidates, .. } => {
                referenced.extend_from_slice(candidates)
            }
            SummaryEffectKey::Allocation { .. }
            | SummaryEffectKey::Escape { .. }
            | SummaryEffectKey::UnknownCall { .. }
            | SummaryEffectKey::UnknownCallBoundary { .. } => {}
        }
    }
    referenced.sort_unstable();
    referenced.dedup();
    if referenced.as_slice() != dependencies {
        return Err(SummaryValidationError::EffectDependenciesMismatch);
    }
    Ok(())
}

struct ProductiveContinuations<'summary> {
    rows: HashMap<SummaryPort, Vec<&'summary SummaryTransfer>>,
    invocation_outputs: HashSet<SummaryPort>,
    work: usize,
}

fn productive_continuations<'summary>(
    second: &'summary [SummaryTransfer],
    boundaries: &SummaryBoundaryMap,
) -> Result<ProductiveContinuations<'summary>, SummaryCompositionError> {
    let mut second_by_input: HashMap<SummaryPort, Vec<&SummaryTransfer>> =
        map_with_capacity(second.len());
    for row in second {
        second_by_input
            .entry(row.input.clone())
            .or_default()
            .push(row);
    }
    let mut continuations: HashMap<SummaryPort, Vec<&SummaryTransfer>> =
        map_with_capacity(boundaries.bindings().len());
    let mut invocation_outputs: HashSet<SummaryPort> =
        set_with_capacity(boundaries.bindings().len());
    let mut work = 0_usize;
    for binding in boundaries.bindings() {
        work = checked_composition_work(work, 1)?;
        invocation_outputs.insert(binding.output.clone());
        if let Some(rows) = second_by_input.get(&binding.input) {
            work = checked_composition_work(work, rows.len())?;
            continuations
                .entry(binding.output.clone())
                .or_default()
                .extend(rows.iter().copied());
        }
    }
    Ok(ProductiveContinuations {
        rows: continuations,
        invocation_outputs,
        work,
    })
}

fn checked_composition_work(
    current: usize,
    added: usize,
) -> Result<usize, SummaryCompositionError> {
    let work = current.saturating_add(added);
    if work > MAX_SUMMARY_COMPOSITION_STEPS {
        return Err(SummaryCompositionError::CompositionWorkExceeded {
            limit: MAX_SUMMARY_COMPOSITION_STEPS,
        });
    }
    Ok(work)
}

fn insert_composed_transfer(
    composed: &mut HashMap<(SummaryPort, SummaryExit), SummaryEvidence>,
    transfer: SummaryTransfer,
) -> Result<(), SummaryCompositionError> {
    let key = (transfer.input, transfer.exit);
    if let Some(existing) = composed.get_mut(&key) {
        *existing = existing
            .join(&transfer.evidence)
            .map_err(SummaryCompositionError::InvalidResult)?;
        return Ok(());
    }
    if composed.len() == MAX_SUMMARY_TRANSFERS {
        return Err(SummaryCompositionError::TooManyComposedTransfers {
            limit: MAX_SUMMARY_TRANSFERS,
        });
    }
    composed.insert(key, transfer.evidence);
    Ok(())
}

fn summary_families_compatible(
    left: &ProcedureSummaryIdentity,
    right: &ProcedureSummaryIdentity,
) -> bool {
    left.schema == right.schema
        && left.semantics == right.semantics
        && left.context == right.context
        && left.behavior == right.behavior
}

fn effect_reference_count(effect: &SummaryEffectKey) -> usize {
    match effect {
        SummaryEffectKey::Call { .. } => 1,
        SummaryEffectKey::AmbiguousCall { candidates, .. } => candidates.len(),
        SummaryEffectKey::Allocation { .. }
        | SummaryEffectKey::Escape { .. }
        | SummaryEffectKey::UnknownCall { .. }
        | SummaryEffectKey::UnknownCallBoundary { .. } => 0,
    }
}

fn procedure_key_heap_bytes(key: &ProcedureSummaryKey) -> usize {
    identity_heap_bytes(key.identity())
}

fn identity_heap_bytes(identity: &ProcedureSummaryIdentity) -> usize {
    let declaration = identity.declaration().segments();
    let declaration_names = declaration
        .iter()
        .filter_map(|segment| segment.name())
        .map(str::len)
        .fold(0_usize, usize::saturating_add);
    let external_model = match identity.origin() {
        SummaryOrigin::Inferred => 0,
        SummaryOrigin::External(origin) => origin.model().as_str().len(),
    };
    identity
        .artifact()
        .path()
        .as_str()
        .len()
        .saturating_add(size_of_val(declaration))
        .saturating_add(declaration_names)
        .saturating_add(external_model)
}

fn dependency_heap_bytes(dependency: &SummaryDependencyKey) -> usize {
    match dependency {
        SummaryDependencyKey::Complete(key) => {
            size_of::<ProcedureSummaryKey>().saturating_add(procedure_key_heap_bytes(key))
        }
        SummaryDependencyKey::Recursive(identity) => {
            size_of::<ProcedureSummaryIdentity>().saturating_add(identity_heap_bytes(identity))
        }
    }
}

fn recursive_edge_heap_bytes(edge: &SummaryRecursiveEdge) -> usize {
    identity_heap_bytes(edge.caller()).saturating_add(identity_heap_bytes(edge.callee()))
}

fn evidence_heap_bytes(evidence: &SummaryEvidence) -> usize {
    size_of_val(evidence.alternatives()).saturating_add(
        evidence
            .alternatives()
            .iter()
            .map(|alternative| {
                size_of_val(alternative.unproven_reasons())
                    .saturating_add(
                        alternative
                            .unproven_reasons()
                            .iter()
                            .map(|reason| reason.len())
                            .fold(0_usize, usize::saturating_add),
                    )
                    .saturating_add(size_of_val(alternative.incomplete_reasons()))
                    .saturating_add(
                        alternative
                            .incomplete_reasons()
                            .iter()
                            .map(|reason| reason.len())
                            .fold(0_usize, usize::saturating_add),
                    )
            })
            .fold(0_usize, usize::saturating_add),
    )
}

fn effect_heap_bytes(effect: &SummaryEffect) -> usize {
    let key_bytes = match effect.key() {
        SummaryEffectKey::Call { callee, .. } => dependency_heap_bytes(callee),
        SummaryEffectKey::AmbiguousCall { candidates, .. } => size_of_val(candidates.as_ref())
            .saturating_add(
                candidates
                    .iter()
                    .map(dependency_heap_bytes)
                    .fold(0_usize, usize::saturating_add),
            ),
        SummaryEffectKey::Allocation { .. }
        | SummaryEffectKey::Escape { .. }
        | SummaryEffectKey::UnknownCall { .. }
        | SummaryEffectKey::UnknownCallBoundary { .. } => 0,
    };
    key_bytes.saturating_add(evidence_heap_bytes(effect.evidence()))
}

fn completeness_heap_bytes(completeness: &SummaryCompleteness) -> usize {
    let SummaryCompleteness::Partial(reasons) = completeness else {
        return 0;
    };
    size_of_val(reasons.as_ref()).saturating_add(
        reasons
            .iter()
            .map(|reason| match reason {
                SummaryIncompleteReason::BudgetExceeded(reason)
                | SummaryIncompleteReason::SemanticGap(reason) => reason.len(),
                SummaryIncompleteReason::Cancelled
                | SummaryIncompleteReason::DependencyIncomplete(_)
                | SummaryIncompleteReason::ExternalModelIncomplete(_) => 0,
            })
            .fold(0_usize, usize::saturating_add),
    )
}

fn fingerprint_dependencies(dependencies: &[SummaryDependencyKey]) -> StableDigest {
    let mut dependencies = dependencies.to_vec();
    dependencies.sort_unstable();
    dependencies.dedup();
    let mut bytes = Vec::new();
    push_digest_part(&mut bytes, b"bifrost-summary-dependencies-v1");
    for dependency in dependencies {
        match dependency {
            SummaryDependencyKey::Complete(key) => {
                push_digest_part(&mut bytes, b"complete");
                push_digest_part(&mut bytes, key.fingerprint().as_bytes());
            }
            SummaryDependencyKey::Recursive(identity) => {
                push_digest_part(&mut bytes, b"recursive");
                push_digest_part(&mut bytes, identity.fingerprint().as_bytes());
            }
        }
    }
    StableDigest::sha256(bytes)
}

fn fingerprint_procedure_identity(identity: &ProcedureSummaryIdentity) -> StableDigest {
    let mut bytes = Vec::new();
    push_digest_part(&mut bytes, b"bifrost-procedure-summary-identity-v1");
    let artifact = identity.artifact.fingerprint();
    push_digest_part(&mut bytes, artifact.as_bytes());
    for segment in identity.declaration.segments() {
        push_digest_part(&mut bytes, segment.kind().stable_label().as_bytes());
        match segment.name() {
            Some(name) => {
                push_digest_part(&mut bytes, b"named");
                push_digest_part(&mut bytes, name.as_bytes());
            }
            None => push_digest_part(&mut bytes, b"anonymous"),
        }
        let anchor = segment.anchor();
        let span = anchor.span();
        let start = span.start();
        let end = span.end();
        for value in [
            start.byte_offset(),
            start.line(),
            start.byte_column(),
            end.byte_offset(),
            end.line(),
            end.byte_column(),
            anchor.occurrence(),
            segment.sibling_ordinal(),
        ] {
            push_digest_part(&mut bytes, &value.to_le_bytes());
        }
    }
    push_digest_part(&mut bytes, &identity.schema.get().to_le_bytes());
    push_digest_part(&mut bytes, identity.semantics.as_bytes());
    push_digest_part(&mut bytes, identity.context.as_bytes());
    push_digest_part(&mut bytes, identity.behavior.as_bytes());
    match &identity.origin {
        SummaryOrigin::Inferred => push_digest_part(&mut bytes, b"inferred"),
        SummaryOrigin::External(origin) => {
            push_digest_part(&mut bytes, b"external");
            push_digest_part(&mut bytes, origin.model.as_str().as_bytes());
            push_digest_part(&mut bytes, origin.content.as_bytes());
            push_digest_part(&mut bytes, &origin.contract_version.to_le_bytes());
        }
    }
    StableDigest::sha256(bytes)
}

fn push_digest_part(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}

pub(crate) struct ValidatedRecursiveSummaryBatch {
    pub(crate) group: SummaryRecursiveGroupKey,
    identities: Vec<ProcedureSummaryIdentity>,
}

pub(crate) fn validate_recursive_summary_batch(
    summaries: &[&SemanticProcedureSummary],
) -> Result<ValidatedRecursiveSummaryBatch, SummaryPublicationError> {
    if summaries.is_empty() {
        return Err(SummaryPublicationError::EmptyScc);
    }
    if summaries.len() > MAX_SUMMARY_RECURSIVE_MEMBERS {
        return Err(SummaryPublicationError::TooManySccMembers {
            actual: summaries.len(),
            limit: MAX_SUMMARY_RECURSIVE_MEMBERS,
        });
    }
    for summary in summaries {
        validate_publishable(summary)?;
    }
    let batch_dependencies = summaries.iter().fold(0_usize, |total, summary| {
        total.saturating_add(summary.dependencies.len())
    });
    if batch_dependencies > MAX_SUMMARY_DEPENDENCIES {
        return Err(SummaryPublicationError::TooManySccDependencies {
            actual: batch_dependencies,
            limit: MAX_SUMMARY_DEPENDENCIES,
        });
    }

    let mut batch_keys = summaries
        .iter()
        .map(|summary| summary.key.clone())
        .collect::<Vec<_>>();
    batch_keys.sort_unstable();
    let original_len = batch_keys.len();
    batch_keys.dedup();
    if batch_keys.len() != original_len {
        return Err(SummaryPublicationError::DuplicateSccMember);
    }
    let mut identities = summaries
        .iter()
        .map(|summary| summary.key.identity().clone())
        .collect::<Vec<_>>();
    identities.sort_unstable();
    identities.dedup();
    if identities.len() != summaries.len() {
        return Err(SummaryPublicationError::DuplicateSccIdentity);
    }
    let mut external_dependencies = Vec::new();
    let mut recursive_edges = Vec::new();
    for summary in summaries {
        recursive_edges.extend_from_slice(summary.recursive_topology());
        for dependency in &summary.dependencies {
            match dependency {
                SummaryDependencyKey::Complete(key) => {
                    if identities.binary_search(key.identity()).is_ok() {
                        return Err(SummaryPublicationError::InternalDependencyMustBeRecursive);
                    }
                    external_dependencies.push((**key).clone());
                }
                SummaryDependencyKey::Recursive(_) => {}
            }
        }
    }
    external_dependencies.sort_unstable();
    external_dependencies.dedup();
    recursive_edges.sort_unstable();
    recursive_edges.dedup();
    let group = SummaryRecursiveGroupKey::from_closure(
        &identities,
        &recursive_edges,
        &external_dependencies,
    )
    .map_err(SummaryPublicationError::InvalidSummary)?;
    if summaries
        .iter()
        .any(|summary| summary.recursive_group() != Some(group))
    {
        return Err(SummaryPublicationError::SccMembershipMismatch);
    }
    validate_recursive_topology(summaries, &identities, &recursive_edges)?;
    Ok(ValidatedRecursiveSummaryBatch { group, identities })
}

fn validate_recursive_topology(
    summaries: &[&SemanticProcedureSummary],
    identities: &[ProcedureSummaryIdentity],
    recursive_edges: &[SummaryRecursiveEdge],
) -> Result<(), SummaryPublicationError> {
    let mut forward = vec![Vec::new(); identities.len()];
    let mut reverse = vec![Vec::new(); identities.len()];
    let mut declared = vec![HashSet::default(); identities.len()];
    for summary in summaries {
        let source = identities
            .binary_search(summary.key.identity())
            .expect("batch identities are derived from the summaries");
        for dependency in &summary.dependencies {
            let SummaryDependencyKey::Recursive(target) = dependency else {
                continue;
            };
            let target = identities
                .binary_search(target)
                .map_err(|_| SummaryPublicationError::MissingRecursiveDependency)?;
            declared[source].insert(target);
        }
    }
    for edge in recursive_edges {
        let source = identities
            .binary_search(edge.caller())
            .map_err(|_| SummaryPublicationError::MissingRecursiveDependency)?;
        let target = identities
            .binary_search(edge.callee())
            .map_err(|_| SummaryPublicationError::MissingRecursiveDependency)?;
        if !declared[source].contains(&target) {
            return Err(SummaryPublicationError::MissingDeclaredRecursiveEdge);
        }
        forward[source].push(target);
        reverse[target].push(source);
    }
    if identities.len() == 1 && !forward[0].contains(&0) {
        return Err(SummaryPublicationError::SccNotStronglyConnected);
    }
    if !iterative_reaches_every_member(&forward) || !iterative_reaches_every_member(&reverse) {
        return Err(SummaryPublicationError::SccNotStronglyConnected);
    }
    Ok(())
}

fn iterative_reaches_every_member(edges: &[Vec<usize>]) -> bool {
    let mut visited = vec![false; edges.len()];
    let mut stack = vec![0_usize];
    while let Some(node) = stack.pop() {
        if visited[node] {
            continue;
        }
        visited[node] = true;
        stack.extend(edges[node].iter().copied().filter(|next| !visited[*next]));
    }
    visited.into_iter().all(|reached| reached)
}

fn validate_publishable(summary: &SemanticProcedureSummary) -> Result<(), SummaryPublicationError> {
    if !summary.completeness.is_complete() {
        return Err(SummaryPublicationError::IncompleteSummary);
    }
    Ok(())
}
