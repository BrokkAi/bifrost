//! Semantic correspondence between two workspace revisions (#2450 slice 1).
//!
//! Bifrost can already describe *a* diff: `crate::diff_analysis` resolves two
//! Git endpoints, materializes both images, and reports which symbols were
//! edited, introduced, deleted or moved. What it cannot do is state, as a value
//! a later stage can consume, *which entity on one side is which entity on the
//! other*, how confident that claim is, and what evidence earned it. Every
//! answer it produces is a presentation record: `MovedSymbol` carries an
//! optional similarity score and nothing else about why the pairing exists, and
//! a pairing it refuses simply disappears into `deleted` plus `introduced`.
//!
//! This module is the canonical relation those records should eventually be
//! derived from. It has three parts:
//!
//! - The revision pin ([`RevisionPin`]): what two revisions were compared, over
//!   what scope, with what completeness on each side. A correspondence claim is
//!   only meaningful against the pin that produced it, so the pin travels with
//!   the relation rather than beside it.
//! - The correspondence vocabulary ([`CorrespondenceEvidence`],
//!   [`CorrespondenceKind`], [`CorrespondenceCertainty`],
//!   [`CorrespondencePair`], [`UnresolvedEntity`]): one-to-zero, one-to-one and
//!   one-to-many mappings with the evidence tier that earned each pair.
//! - The declaration-grained producer, in [`declarations`].
//!
//! # Identity discipline
//!
//! Every identity here is a [`StableDigest`] over domain-separated,
//! length-delimited fields, and the ingredients are the ones the repository
//! already settled on rather than new ones:
//!
//! - The stable semantic identity of a declaration is the recipe behind
//!   `brokk_bifrost_policy::finding_identity::StableSemanticIdentity`: an
//!   adapter namespace (the language), a workspace-relative path, the
//!   `analyzer_declaration_id` derivation, and a `kind:qualified_name` semantic
//!   key. The occurrence ordinal that separates two same-named declarations in
//!   one file is the same ordinal `PolicyFindingId::from_match_anchor` and
//!   `stable_semantic_id` ("semantic-node-v2") both fold in.
//! - The content identity is the SHA-256 of the declaration's exact source
//!   slice -- the `selected_source_sha256` of a strong match anchor.
//!
//! Two prohibitions follow the Milestone E (#2449) schema in
//! [`crate::analyzer::invalidation`] and are not negotiable here:
//!
//! - No absolute path enters an identity. #2529 settled that two byte-equal
//!   checkouts at different directories must compare equal, so paths are
//!   [`WorkspaceRelativePath`] and nothing else.
//! - No workspace generation, snapshot handle, run-local index or source
//!   coordinate enters an identity. An entity's position in the entity table is
//!   an [`EntityIndex`], which is a handle into *this* relation and is never
//!   hashed as identity -- only the digests are.
//!
//! # Evidence tiers
//!
//! A pair carries exactly one [`CorrespondenceEvidence`], the strongest tier it
//! earned, and the tiers are strictly ordered (see [`CorrespondenceTier`]):
//!
//! 1. [`CorrespondenceTier::StableSemanticIdentity`] -- the same declaration in
//!    the same place under the same name. Exact.
//! 2. [`CorrespondenceTier::ContentIdentity`] -- byte-equal source slices. Exact
//!    about the bytes; it says nothing about the name, which is what makes it
//!    the move/rename tier.
//! 3. [`CorrespondenceTier::OwnerSignatureIdentity`] -- the same owner, name and
//!    signature with a different body. This is the "modified candidate" tier: it
//!    is the only tier that admits a changed body, and it admits it only because
//!    the declaration's own contract is byte-equal.
//! 4. [`CorrespondenceTier::BodySimilarity`] -- structured body similarity. No
//!    producer in this slice emits it; see the contract below.
//!
//! Precedence is absolute, not a score: a base entity that earned tier 1 never
//! looks at tier 2, so a declaration that stayed put is never confused with its
//! own duplicate elsewhere in the tree.
//!
//! Tier 1 names the declaration's signature, and that is what makes it safe on
//! an overload set: two same-named methods differ in their identity by their
//! parameters rather than by their position in the file, so inserting an
//! overload above another cannot silently re-point an exact claim. The stated
//! cost is a declaration whose own signature changed in place: it earns no tier
//! -- not 1, whose identity it broke; not 2, because its body moved with it;
//! not 3, whose contract it broke -- and is reported
//! [`UnresolvedReason::NoCandidate`] on both sides. That is the honest answer
//! from these four tiers, and a change-fact family for signature evolution is
//! deliberately out of this slice: mispairing two overloads exactly would be a
//! fabricated winner, while an unresolved signature change is a gap a later
//! tier can close.
//!
//! # Ambiguity is retained, never resolved
//!
//! When several counterparts are equally plausible at the winning tier, every
//! one of them is kept as its own pair and every one is marked
//! [`CorrespondenceCertainty::Ambiguous`]. There is deliberately no tie-break:
//! two byte-identical declarations offer no evidence about which became which,
//! and a rule that picked the lexicographically first one would be reporting a
//! sort order as a fact. A consumer that needs one answer must either bring more
//! evidence or say it does not know.
//!
//! The same rule governs the bounds. When an entity has more equally plausible
//! candidates than [`CorrespondenceLimits::max_candidates_per_entity`], the
//! whole group is dropped and the entity is reported unresolved with
//! [`UnresolvedReason::CandidateLimitExceeded`] -- retaining a prefix of the
//! group would be exactly the fabricated winner this schema exists to prevent.
//!
//! # The #1907 body-similarity move-classification contract
//!
//! `crate::diff_analysis::pair_endpoints` already classifies moves by body
//! similarity, and this slice does not change its behavior. What follows states
//! its contract so that tier 4 has a definition before it has a producer. The
//! citations are the current implementation.
//!
//! Body similarity **may** classify a move only when all of the following hold:
//!
//! - Every exact tier has already failed for both endpoints. In `pair_endpoints`
//!   this is structural: rule 3 scores only the leftovers of rule 1 (identity of
//!   fqn/kind/language) and rule 2 (the Git-reported rename bucket, which
//!   additionally requires exactly one candidate on each side).
//! - Both bodies are non-trivial. `body_token_signature` returns `None` for a
//!   body of fewer than two non-blank lines, and a `None` signature never
//!   participates.
//! - The score clears `BODY_MOVE_SIMILARITY_THRESHOLD` (0.40 on the
//!   diff-local-IDF-weighted bag Jaccard of `body_similarity`), tuned on the
//!   RefactoringMiner oracle rather than chosen.
//! - The assignment is one-to-one: a preimage and a postimage each take part in
//!   at most one similarity pair.
//!
//! The result **must stay ambiguous** -- that is, a producer of tier-4 evidence
//! must emit [`CorrespondenceCertainty::Ambiguous`] and retain every candidate,
//! rather than publish a winner -- in each of these cases:
//!
//! - Two or more candidates reach the same score for one entity. `pair_endpoints`
//!   resolves this today by sorting on descending score and breaking ties on
//!   fqn, then taking greedily; that tie-break is a determinism device, not
//!   evidence, and the canonical relation must not restate it as a fact.
//! - The pairing is not mutually best. Greedy assignment can hand a preimage to
//!   a postimage that had a better claimant which was itself already taken, so
//!   "accepted by the greedy walk" is weaker than "these two are each other's
//!   best match".
//! - The rule did not run at all. Past `FUZZY_PAIRING_CANDIDATE_CAP`
//!   (250,000 preimage x postimage products) the whole rule is skipped for the
//!   diff, and `within_fuzzy_weight_ratio` skips individual pairs whose bag
//!   weights differ by more than 3x. Absence of a similarity pair is therefore
//!   never evidence of absence of a move; it maps to
//!   [`UnresolvedReason::CandidateLimitExceeded`] or to a partial acquisition,
//!   not to [`UnresolvedReason::NoCandidate`].
//!
//! A tier-4 pair is a candidate for review. It is never proof that the two
//! declarations are the same declaration, and no consumer may promote it to one.
//!
//! # Not in this slice
//!
//! No history replay, no change-fact families beyond move/rename/modify, and no
//! policy surface. The configuration and model axes of [`RevisionPin`] exist and
//! are [`PinnedIdentity::Unknown`]; each field's doc comment names what fills it.

pub mod declarations;

use std::fmt;

use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::semantic::{SEMANTIC_IR_SCHEMA_VERSION, StableDigest, WorkspaceRelativePath};

/// The revision of this schema itself.
///
/// It enters [`RevisionPin::analyzer_schema`], so a relation produced by an
/// older schema can never be compared with one produced by a newer schema by
/// accident.
pub const CORRESPONDENCE_SCHEMA_VERSION: u32 = 1;

const ANALYZER_SCHEMA_DOMAIN: &[u8] = b"bifrost.correspondence.analyzer-schema.v1";
const REVISION_PIN_DOMAIN: &[u8] = b"bifrost.correspondence.revision-pin.v1";

/// A Git object name: the lowercase hex spelling of a commit or tree id.
///
/// Validated on construction because it is an identity ingredient: a
/// mixed-case or truncated spelling of the same object would produce a
/// different pin digest for the same comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectName(Box<str>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectNameError {
    /// Not a SHA-1 (40) or SHA-256 (64) hex spelling.
    Length { bytes: usize },
    /// A byte outside `0-9a-f`. Uppercase is rejected rather than folded: two
    /// spellings of one object must not produce two identities.
    NotLowercaseHex,
}

impl fmt::Display for ObjectNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { bytes } => write!(
                formatter,
                "a git object name is 40 or 64 hex digits, not {bytes}"
            ),
            Self::NotLowercaseHex => {
                formatter.write_str("a git object name must be lowercase hexadecimal")
            }
        }
    }
}

impl std::error::Error for ObjectNameError {}

impl ObjectName {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ObjectNameError> {
        let value = value.as_ref();
        if !matches!(value.len(), 40 | 64) {
            return Err(ObjectNameError::Length { bytes: value.len() });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ObjectNameError::NotLowercaseHex);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One end of a comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RevisionEndpoint {
    /// A commit. Immutable: its tree cannot change under the comparison.
    Commit(ObjectName),
    /// A bare tree. Immutable for the same reason.
    Tree(ObjectName),
    /// The live working tree. Not immutable: two reads may disagree, so a
    /// relation with this endpoint states a claim about one moment only.
    WorkingTree,
}

impl RevisionEndpoint {
    pub const LABELS: &'static [&'static str] = &["commit", "tree", "working_tree"];

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Commit(_) => "commit",
            Self::Tree(_) => "tree",
            Self::WorkingTree => "working_tree",
        }
    }

    pub const fn is_immutable(&self) -> bool {
        !matches!(self, Self::WorkingTree)
    }

    pub fn object_name(&self) -> Option<&ObjectName> {
        match self {
            Self::Commit(name) | Self::Tree(name) => Some(name),
            Self::WorkingTree => None,
        }
    }
}

impl fmt::Display for RevisionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commit(name) => write!(formatter, "commit:{name}"),
            Self::Tree(name) => write!(formatter, "tree:{name}"),
            Self::WorkingTree => formatter.write_str("working_tree"),
        }
    }
}

/// What part of one revision a side was asked to acquire.
///
/// An empty `roots` list is the general case of "no restriction": the whole
/// workspace. Both lists are sorted and deduplicated on construction so two
/// callers that named the same scope in different orders produce the same pin.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceScope {
    roots: Vec<WorkspaceRelativePath>,
    exclusions: Vec<WorkspaceRelativePath>,
}

impl WorkspaceScope {
    /// Everything in the revision.
    pub fn whole_workspace() -> Self {
        Self::default()
    }

    pub fn new(
        roots: impl IntoIterator<Item = WorkspaceRelativePath>,
        exclusions: impl IntoIterator<Item = WorkspaceRelativePath>,
    ) -> Self {
        let mut roots: Vec<_> = roots.into_iter().collect();
        roots.sort();
        roots.dedup();
        let mut exclusions: Vec<_> = exclusions.into_iter().collect();
        exclusions.sort();
        exclusions.dedup();
        Self { roots, exclusions }
    }

    pub fn roots(&self) -> &[WorkspaceRelativePath] {
        &self.roots
    }

    pub fn exclusions(&self) -> &[WorkspaceRelativePath] {
        &self.exclusions
    }

    /// Whether `path` is inside this scope.
    ///
    /// Containment is compared by path component, not by string prefix, so
    /// `src/ab` is not inside `src/a`. `WorkspaceRelativePath` is already
    /// slash-canonical, and `Path::starts_with` treats `/` as a separator on
    /// every supported target, so this is the same answer on Windows and Unix.
    pub fn contains(&self, path: &WorkspaceRelativePath) -> bool {
        let inside_a_root = self.roots.is_empty()
            || self
                .roots
                .iter()
                .any(|root| path.as_path().starts_with(root.as_path()));
        inside_a_root
            && !self
                .exclusions
                .iter()
                .any(|excluded| path.as_path().starts_with(excluded.as_path()))
    }

    fn hash_into(&self, hasher: &mut CanonicalHasher) {
        hasher.sequence("roots", &self.roots, |hasher, root| {
            hasher.value(root.as_str().as_bytes());
        });
        hasher.sequence("exclusions", &self.exclusions, |hasher, excluded| {
            hasher.value(excluded.as_str().as_bytes());
        });
    }
}

/// Something in scope that a side could not acquire.
///
/// Every variant names what was missed and why, so the gap is readable without
/// the reader holding the producer's context. A gap is not an error: it is the
/// reason the side's [`AcquisitionCompleteness`] is
/// [`AcquisitionCompleteness::Partial`], which is what stops a consumer from
/// reading a missing correspondence as a proved absence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AcquisitionGap {
    /// The file's bytes could not be read, so no declaration in it has a
    /// content identity.
    SourceUnreadable { path: WorkspaceRelativePath },
    /// A declaration in this file reported no source range, or a range that is
    /// not a character boundary of the file it names.
    DeclarationSliceUnavailable { path: WorkspaceRelativePath },
    /// The side stopped acquiring at [`CorrespondenceLimits::max_entities_per_side`].
    EntityLimitExceeded { limit: usize },
}

impl AcquisitionGap {
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::SourceUnreadable { .. } => "source_unreadable",
            Self::DeclarationSliceUnavailable { .. } => "declaration_slice_unavailable",
            Self::EntityLimitExceeded { .. } => "entity_limit_exceeded",
        }
    }
}

impl fmt::Display for AcquisitionGap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceUnreadable { path } => {
                write!(formatter, "source of {} could not be read", path.as_str())
            }
            Self::DeclarationSliceUnavailable { path } => write!(
                formatter,
                "a declaration in {} has no usable source slice",
                path.as_str()
            ),
            Self::EntityLimitExceeded { limit } => {
                write!(formatter, "acquisition stopped at {limit} entities")
            }
        }
    }
}

/// Whether one side of the pin acquired everything its scope named.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AcquisitionCompleteness {
    Complete,
    #[default]
    Partial,
}

impl AcquisitionCompleteness {
    pub const LABELS: &'static [&'static str] = &["complete", "partial"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    /// The meet of two markers: partial wins.
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Complete, Self::Complete) => Self::Complete,
            _ => Self::Partial,
        }
    }
}

/// One side of a [`RevisionPin`]: what was compared, over what scope, and how
/// completely it was acquired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionSide {
    endpoint: RevisionEndpoint,
    scope: WorkspaceScope,
    gaps: Vec<AcquisitionGap>,
}

impl RevisionSide {
    pub fn new(endpoint: RevisionEndpoint, scope: WorkspaceScope) -> Self {
        Self {
            endpoint,
            scope,
            gaps: Vec::new(),
        }
    }

    /// Record something the side could not acquire. Gaps are kept sorted and
    /// deduplicated so two runs that hit the same gaps in different orders
    /// produce the same pin digest.
    pub fn record_gap(&mut self, gap: AcquisitionGap) {
        match self.gaps.binary_search(&gap) {
            Ok(_) => {}
            Err(position) => self.gaps.insert(position, gap),
        }
    }

    pub const fn endpoint(&self) -> &RevisionEndpoint {
        &self.endpoint
    }

    pub const fn scope(&self) -> &WorkspaceScope {
        &self.scope
    }

    pub fn gaps(&self) -> &[AcquisitionGap] {
        &self.gaps
    }

    /// Completeness is derived from the gap list rather than stored beside it,
    /// so the two can never disagree.
    pub fn completeness(&self) -> AcquisitionCompleteness {
        if self.gaps.is_empty() {
            AcquisitionCompleteness::Complete
        } else {
            AcquisitionCompleteness::Partial
        }
    }

    fn hash_into(&self, hasher: &mut CanonicalHasher, name: &str) {
        hasher.field("side", name.as_bytes());
        hasher.field("endpoint_kind", self.endpoint.label().as_bytes());
        hasher.field(
            "endpoint_object",
            self.endpoint
                .object_name()
                .map_or(b"".as_slice(), |name| name.as_str().as_bytes()),
        );
        self.scope.hash_into(hasher);
        hasher.sequence("gaps", &self.gaps, |hasher, gap| {
            hasher.value(gap.stable_label().as_bytes());
            hasher.value(gap.to_string().as_bytes());
        });
    }
}

/// An identity axis of the pin that a later slice fills.
///
/// [`Self::Unknown`] is a statement, not a placeholder: it says the axis was
/// not pinned, so a consumer that needs it must not assume the two sides agreed
/// on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PinnedIdentity {
    #[default]
    Unknown,
    Pinned(StableDigest),
}

impl PinnedIdentity {
    pub const fn digest(self) -> Option<StableDigest> {
        match self {
            Self::Unknown => None,
            Self::Pinned(digest) => Some(digest),
        }
    }

    fn hash_into(self, hasher: &mut CanonicalHasher, name: &str) {
        match self {
            Self::Unknown => hasher.field(name, b"unknown"),
            Self::Pinned(digest) => hasher.field(name, digest.as_bytes()),
        }
    }
}

/// What two revisions a correspondence relation is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionPin {
    base: RevisionSide,
    target: RevisionSide,
    analyzer_schema: StableDigest,
    configuration: PinnedIdentity,
    model: PinnedIdentity,
}

impl RevisionPin {
    /// Pin two sides under the current analyzer schema.
    ///
    /// The configuration and model axes start [`PinnedIdentity::Unknown`]; see
    /// [`Self::with_configuration`] and [`Self::with_model`].
    pub fn new(base: RevisionSide, target: RevisionSide) -> Self {
        Self {
            base,
            target,
            analyzer_schema: analyzer_schema_identity(),
            configuration: PinnedIdentity::Unknown,
            model: PinnedIdentity::Unknown,
        }
    }

    /// Pin the analyzer configuration both sides ran under.
    ///
    /// Left [`PinnedIdentity::Unknown`] by every producer in this slice. The
    /// value that belongs here is the `ConfigurationFingerprint` a semantic
    /// artifact key already carries, which is derived from `AnalyzerConfig`;
    /// wiring it needs the config to reach the correspondence producer, which
    /// is a change to the callers rather than to this schema.
    pub const fn with_configuration(mut self, configuration: PinnedIdentity) -> Self {
        self.configuration = configuration;
        self
    }

    /// Pin the external semantic-model knowledge both sides ran under.
    ///
    /// Left [`PinnedIdentity::Unknown`] by every producer in this slice. The
    /// value that belongs here is the identity of the activated semantic-pack
    /// set (`crate::analyzer::semantic_model`), because activating a different
    /// pack can change what a declaration means without changing a byte of the
    /// workspace.
    pub const fn with_model(mut self, model: PinnedIdentity) -> Self {
        self.model = model;
        self
    }

    pub const fn base(&self) -> &RevisionSide {
        &self.base
    }

    pub const fn target(&self) -> &RevisionSide {
        &self.target
    }

    pub const fn analyzer_schema(&self) -> StableDigest {
        self.analyzer_schema
    }

    pub const fn configuration(&self) -> PinnedIdentity {
        self.configuration
    }

    pub const fn model(&self) -> PinnedIdentity {
        self.model
    }

    /// Whether both endpoints are immutable, which is what an exact
    /// correspondence over two trees requires.
    pub const fn is_immutable(&self) -> bool {
        self.base.endpoint.is_immutable() && self.target.endpoint.is_immutable()
    }

    pub fn completeness(&self) -> AcquisitionCompleteness {
        self.base.completeness().meet(self.target.completeness())
    }

    /// The deterministic identity of this pin.
    pub fn digest(&self) -> StableDigest {
        let mut hasher = CanonicalHasher::new(REVISION_PIN_DOMAIN);
        self.base.hash_into(&mut hasher, "base");
        self.target.hash_into(&mut hasher, "target");
        hasher.field("analyzer_schema", self.analyzer_schema.as_bytes());
        self.configuration.hash_into(&mut hasher, "configuration");
        self.model.hash_into(&mut hasher, "model");
        StableDigest::from_array(hasher.finish())
    }
}

/// The schema identity every pin produced by this build carries.
///
/// It names this schema's own version and the semantic IR schema version,
/// because a change to either can change which entities exist and therefore
/// which correspondences are derivable. It deliberately names no package
/// version: a packaging-only release must not rotate a comparison key.
fn analyzer_schema_identity() -> StableDigest {
    let mut hasher = CanonicalHasher::new(ANALYZER_SCHEMA_DOMAIN);
    hasher.field(
        "correspondence_schema",
        &CORRESPONDENCE_SCHEMA_VERSION.to_be_bytes(),
    );
    hasher.field(
        "semantic_ir_schema",
        &SEMANTIC_IR_SCHEMA_VERSION.to_be_bytes(),
    );
    StableDigest::from_array(hasher.finish())
}

/// How strong the evidence behind one pair is. Declared strongest first, so the
/// derived ordering compares strength directly: `StableSemanticIdentity` is the
/// least element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CorrespondenceTier {
    StableSemanticIdentity,
    ContentIdentity,
    OwnerSignatureIdentity,
    BodySimilarity,
}

impl CorrespondenceTier {
    pub const LABELS: &'static [&'static str] = &[
        "stable_semantic_identity",
        "content_identity",
        "owner_signature_identity",
        "body_similarity",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::StableSemanticIdentity => "stable_semantic_identity",
            Self::ContentIdentity => "content_identity",
            Self::OwnerSignatureIdentity => "owner_signature_identity",
            Self::BodySimilarity => "body_similarity",
        }
    }

    /// Whether this tier is exact. An exact tier compares identities that are
    /// equal or not equal; an inexact one compares a score against a threshold.
    pub const fn is_exact(self) -> bool {
        !matches!(self, Self::BodySimilarity)
    }
}

/// What earned one pair, and the identity that did it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CorrespondenceEvidence {
    /// Both entities carry the same stable semantic identity: same language,
    /// workspace-relative path, kind, qualified name and occurrence ordinal.
    StableSemanticIdentity { identity: StableDigest },
    /// Both entities have byte-equal source slices, in the same language and of
    /// the same kind.
    ContentIdentity { identity: StableDigest },
    /// Both entities have the same owner, terminal name, kind and signature.
    /// This is the only exact tier that admits a changed body.
    OwnerSignatureIdentity { identity: StableDigest },
    /// A structured body-similarity score, in thousandths so the evidence
    /// hashes deterministically -- a float has no canonical byte form worth
    /// putting in an identity. No producer in this slice emits this variant;
    /// the contract one must obey is in the module documentation.
    BodySimilarity { score_per_mille: u16 },
}

impl CorrespondenceEvidence {
    pub const fn tier(&self) -> CorrespondenceTier {
        match self {
            Self::StableSemanticIdentity { .. } => CorrespondenceTier::StableSemanticIdentity,
            Self::ContentIdentity { .. } => CorrespondenceTier::ContentIdentity,
            Self::OwnerSignatureIdentity { .. } => CorrespondenceTier::OwnerSignatureIdentity,
            Self::BodySimilarity { .. } => CorrespondenceTier::BodySimilarity,
        }
    }

    fn hash_into(&self, hasher: &mut CanonicalHasher) {
        hasher.field("tier", self.tier().label().as_bytes());
        match self {
            Self::StableSemanticIdentity { identity }
            | Self::ContentIdentity { identity }
            | Self::OwnerSignatureIdentity { identity } => {
                hasher.field("identity", identity.as_bytes());
            }
            Self::BodySimilarity { score_per_mille } => {
                hasher.field("score_per_mille", &score_per_mille.to_be_bytes());
            }
        }
    }
}

/// What the pair says happened to the entity.
///
/// The three cases are decided by the evidence and the entity's owner path, not
/// by a heuristic: byte-equal content in the same place is unchanged, byte-equal
/// content elsewhere is a move, and an equal contract with a different body is a
/// modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CorrespondenceKind {
    /// Same content, same owner path and name.
    Unchanged,
    /// Same content, different owner path or qualified name.
    Moved,
    /// Same contract, different body.
    ModifiedCandidate,
}

impl CorrespondenceKind {
    pub const LABELS: &'static [&'static str] = &["unchanged", "moved", "modified_candidate"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Moved => "moved",
            Self::ModifiedCandidate => "modified_candidate",
        }
    }
}

/// Whether this pair is the only plausible reading of its evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CorrespondenceCertainty {
    /// One entity on each side earned this evidence, and neither has another
    /// counterpart at this tier.
    Unique,
    /// Several mappings are equally plausible at this tier. Every one of them
    /// is a retained pair; `alternatives` counts the *other* pairs that claim
    /// the same base entity or the same target entity, so a reader knows how
    /// wide the ambiguity is without walking the relation.
    Ambiguous { alternatives: u32 },
}

impl CorrespondenceCertainty {
    pub const LABELS: &'static [&'static str] = &["unique", "ambiguous"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Unique => "unique",
            Self::Ambiguous { .. } => "ambiguous",
        }
    }

    pub const fn is_ambiguous(self) -> bool {
        matches!(self, Self::Ambiguous { .. })
    }
}

/// A handle into one side's entity table of one relation.
///
/// It is a position, not an identity: it is never hashed and never compared
/// across relations. The identity of an entity is its digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityIndex(u32);

impl EntityIndex {
    pub fn new(index: usize) -> Self {
        Self(u32::try_from(index).expect("entity tables are bounded well below u32::MAX"))
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for EntityIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// One retained mapping from a base entity to a target entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrespondencePair {
    pub base: EntityIndex,
    pub target: EntityIndex,
    pub kind: CorrespondenceKind,
    pub evidence: CorrespondenceEvidence,
    pub certainty: CorrespondenceCertainty,
}

impl CorrespondencePair {
    pub(crate) fn hash_into(&self, hasher: &mut CanonicalHasher) {
        hasher.field("base", &self.base.0.to_be_bytes());
        hasher.field("target", &self.target.0.to_be_bytes());
        hasher.field("kind", self.kind.label().as_bytes());
        self.evidence.hash_into(hasher);
        hasher.field("certainty", self.certainty.label().as_bytes());
        if let CorrespondenceCertainty::Ambiguous { alternatives } = self.certainty {
            hasher.field("alternatives", &alternatives.to_be_bytes());
        }
    }
}

/// Why one entity has no retained pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnresolvedReason {
    /// No counterpart earned any evidence tier with this entity.
    ///
    /// On the target side this means no retained pair names it, which also
    /// covers the case where its only possible claimant earned a stronger tier
    /// against a different target.
    NoCandidate,
    /// More equally plausible candidates than the limit allows. The group is
    /// dropped whole: retaining a prefix of it would publish a sort order as a
    /// finding.
    CandidateLimitExceeded { candidates: usize, limit: usize },
    /// The relation reached [`CorrespondenceLimits::max_pairs`] before this
    /// entity was resolved. Its correspondence is unknown, not absent.
    PairLimitExceeded { limit: usize },
}

impl UnresolvedReason {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::NoCandidate => "no_candidate",
            Self::CandidateLimitExceeded { .. } => "candidate_limit_exceeded",
            Self::PairLimitExceeded { .. } => "pair_limit_exceeded",
        }
    }

    /// Whether this reason is a bound binding rather than an answer about the
    /// code. A consumer must not read one of these as "there is no counterpart".
    pub const fn is_bound(self) -> bool {
        !matches!(self, Self::NoCandidate)
    }
}

impl fmt::Display for UnresolvedReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidate => formatter.write_str("no counterpart earned any evidence tier"),
            Self::CandidateLimitExceeded { candidates, limit } => write!(
                formatter,
                "{candidates} equally plausible candidates exceed the limit of {limit}"
            ),
            Self::PairLimitExceeded { limit } => {
                write!(formatter, "the relation reached its limit of {limit} pairs")
            }
        }
    }
}

/// One entity with no retained pair, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnresolvedEntity {
    pub entity: EntityIndex,
    pub reason: UnresolvedReason,
}

impl UnresolvedEntity {
    pub(crate) fn hash_into(&self, hasher: &mut CanonicalHasher) {
        hasher.field("entity", &self.entity.0.to_be_bytes());
        hasher.field("reason", self.reason.stable_label().as_bytes());
        match self.reason {
            UnresolvedReason::NoCandidate => {}
            UnresolvedReason::CandidateLimitExceeded { candidates, limit } => {
                hasher.field("candidates", &(candidates as u64).to_be_bytes());
                hasher.field("limit", &(limit as u64).to_be_bytes());
            }
            UnresolvedReason::PairLimitExceeded { limit } => {
                hasher.field("limit", &(limit as u64).to_be_bytes());
            }
        }
    }
}

/// What a correspondence derivation is willing to spend, and to publish.
///
/// The limits are part of the relation because a relation derived under a
/// different bound is a different claim: an entity dropped for
/// [`UnresolvedReason::CandidateLimitExceeded`] under a limit of 4 might have
/// been resolvable under a limit of 64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrespondenceLimits {
    /// The most declarations one side will acquire. Past it the side records
    /// [`AcquisitionGap::EntityLimitExceeded`] and stops.
    pub max_entities_per_side: usize,
    /// The most equally plausible counterparts one entity may have and still
    /// produce pairs.
    pub max_candidates_per_entity: usize,
    /// The most pairs the whole relation will retain.
    pub max_pairs: usize,
}

impl Default for CorrespondenceLimits {
    /// Sized so an ordinary repository revision fits and a pathological one
    /// stops: the entity bound is roughly a large monorepo's declaration count,
    /// the candidate bound is far above any honest ambiguity group (a duplicate
    /// group of 17 is a generated tree, not a refactor), and the pair bound
    /// keeps the retained relation proportional to the entity tables.
    fn default() -> Self {
        Self {
            max_entities_per_side: 200_000,
            max_candidates_per_entity: 16,
            max_pairs: 400_000,
        }
    }
}

impl CorrespondenceLimits {
    pub(crate) fn hash_into(&self, hasher: &mut CanonicalHasher) {
        hasher.field(
            "max_entities_per_side",
            &(self.max_entities_per_side as u64).to_be_bytes(),
        );
        hasher.field(
            "max_candidates_per_entity",
            &(self.max_candidates_per_entity as u64).to_be_bytes(),
        );
        hasher.field("max_pairs", &(self.max_pairs as u64).to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> WorkspaceRelativePath {
        WorkspaceRelativePath::new(value).expect("portable test path")
    }

    #[test]
    fn scope_containment_compares_components_not_string_prefixes() {
        let scope = WorkspaceScope::new([path("src/a")], [path("src/a/generated")]);
        assert!(scope.contains(&path("src/a/main.rs")));
        assert!(
            !scope.contains(&path("src/ab/main.rs")),
            "`src/ab` is not inside `src/a`"
        );
        assert!(!scope.contains(&path("src/a/generated/api.rs")));
        assert!(WorkspaceScope::whole_workspace().contains(&path("anything/at/all.rs")));
    }

    #[test]
    fn a_pin_digest_depends_on_every_axis_and_not_on_gap_order() {
        let base = RevisionSide::new(
            RevisionEndpoint::Commit(ObjectName::new("a".repeat(40)).unwrap()),
            WorkspaceScope::whole_workspace(),
        );
        let target = RevisionSide::new(
            RevisionEndpoint::Commit(ObjectName::new("b".repeat(40)).unwrap()),
            WorkspaceScope::whole_workspace(),
        );
        let pin = RevisionPin::new(base.clone(), target.clone());
        assert!(pin.is_immutable());
        assert_eq!(pin.completeness(), AcquisitionCompleteness::Complete);
        assert_eq!(pin.configuration(), PinnedIdentity::Unknown);
        assert_eq!(pin.model(), PinnedIdentity::Unknown);

        let mut forward = base.clone();
        forward.record_gap(AcquisitionGap::SourceUnreadable { path: path("a.rs") });
        forward.record_gap(AcquisitionGap::EntityLimitExceeded { limit: 4 });
        let mut backward = base;
        backward.record_gap(AcquisitionGap::EntityLimitExceeded { limit: 4 });
        backward.record_gap(AcquisitionGap::SourceUnreadable { path: path("a.rs") });
        assert_eq!(
            RevisionPin::new(forward.clone(), target.clone()).digest(),
            RevisionPin::new(backward, target.clone()).digest(),
            "gap insertion order must not reach the digest"
        );
        assert_eq!(
            RevisionPin::new(forward, target.clone()).completeness(),
            AcquisitionCompleteness::Partial
        );

        let configured = pin
            .clone()
            .with_configuration(PinnedIdentity::Pinned(StableDigest::sha256(b"config")));
        assert_ne!(pin.digest(), configured.digest());
        assert_ne!(
            configured.digest(),
            configured
                .clone()
                .with_model(PinnedIdentity::Pinned(StableDigest::sha256(b"model")))
                .digest()
        );

        let swapped = RevisionPin::new(
            RevisionSide::new(
                RevisionEndpoint::Commit(ObjectName::new("b".repeat(40)).unwrap()),
                WorkspaceScope::whole_workspace(),
            ),
            RevisionSide::new(
                RevisionEndpoint::Commit(ObjectName::new("a".repeat(40)).unwrap()),
                WorkspaceScope::whole_workspace(),
            ),
        );
        assert_ne!(pin.digest(), swapped.digest(), "the pin is directional");
    }

    #[test]
    fn an_object_name_is_lowercase_hex_of_a_known_width() {
        assert!(ObjectName::new("0".repeat(40)).is_ok());
        assert!(ObjectName::new("0".repeat(64)).is_ok());
        assert_eq!(
            ObjectName::new("A".repeat(40)).unwrap_err(),
            ObjectNameError::NotLowercaseHex
        );
        assert_eq!(
            ObjectName::new("0".repeat(39)).unwrap_err(),
            ObjectNameError::Length { bytes: 39 }
        );
    }

    #[test]
    fn tier_order_is_strongest_first() {
        assert!(CorrespondenceTier::StableSemanticIdentity < CorrespondenceTier::ContentIdentity);
        assert!(CorrespondenceTier::ContentIdentity < CorrespondenceTier::OwnerSignatureIdentity);
        assert!(CorrespondenceTier::OwnerSignatureIdentity < CorrespondenceTier::BodySimilarity);
        assert!(CorrespondenceTier::OwnerSignatureIdentity.is_exact());
        assert!(!CorrespondenceTier::BodySimilarity.is_exact());
    }
}
