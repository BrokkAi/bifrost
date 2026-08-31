//! Declaration-grained correspondence over two revisions.
//!
//! This is the first producer of the schema in the parent module. It answers
//! one question exactly: for every declaration the base revision holds, which
//! declaration of the target revision is it, and on what evidence.
//!
//! The four decisions the producer makes, in the order it makes them:
//!
//! - Same content in the same place under the same name is
//!   [`CorrespondenceKind::Unchanged`].
//! - Same content somewhere else, or under another name, is
//!   [`CorrespondenceKind::Moved`].
//! - The same owner, name, kind and signature with a different body is
//!   [`CorrespondenceKind::ModifiedCandidate`].
//! - Content duplicated on both sides is every one of those pairs, each marked
//!   [`CorrespondenceCertainty::Ambiguous`]. There is no winner.
//!
//! Nothing here parses source text. The entity table is built from the
//! analyzer's own declaration surface -- `IAnalyzer::all_declarations`, its
//! ranges and its signatures -- and the owner of a declaration comes from the
//! structured `FqName` segments the extractor recorded, never from splitting a
//! rendered name (#2111).

use std::collections::HashMap;
use std::path::Path;

use super::{
    AcquisitionCompleteness, AcquisitionGap, CorrespondenceCertainty, CorrespondenceEvidence,
    CorrespondenceKind, CorrespondenceLimits, CorrespondencePair, EntityIndex, ObjectName,
    RevisionEndpoint, RevisionPin, RevisionSide, UnresolvedEntity, UnresolvedReason,
    WorkspaceScope,
};
use crate::analyzer::canonical_hash::{CanonicalHasher, sha256_bytes};
use crate::analyzer::semantic::{StableDigest, WorkspaceRelativePath};
use crate::analyzer::{CodeUnit, IAnalyzer};

const DECLARATION_IDENTITY_DOMAIN: &[u8] = b"bifrost.correspondence.declaration-identity.v1";
const DECLARATION_CONTENT_DOMAIN: &[u8] = b"bifrost.correspondence.declaration-content.v1";
const DECLARATION_CONTRACT_DOMAIN: &[u8] = b"bifrost.correspondence.declaration-contract.v1";
const RELATION_DOMAIN: &[u8] = b"bifrost.correspondence.declaration-relation.v1";

/// One declaration of one revision, reduced to the three identities the
/// evidence tiers compare.
///
/// The descriptive fields are kept beside the digests so a diagnostic can name
/// the declaration without a second lookup; they are not what makes two
/// entities correspond.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationEntity {
    path: WorkspaceRelativePath,
    language: Box<str>,
    kind: Box<str>,
    qualified_name: Box<str>,
    terminal_name: Box<str>,
    signature: Box<str>,
    occurrence_ordinal: u32,
    stable_semantic_identity: StableDigest,
    content_identity: StableDigest,
    owner_signature_identity: StableDigest,
}

impl DeclarationEntity {
    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub fn language(&self) -> &str {
        &self.language
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn qualified_name(&self) -> &str {
        &self.qualified_name
    }

    pub fn terminal_name(&self) -> &str {
        &self.terminal_name
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Which same-named declaration of this file this is, in document order.
    ///
    /// Overloads are the reason this exists: without it two same-named methods
    /// in one file would carry the same stable semantic identity, and the
    /// strongest tier would pair them arbitrarily. It is the same ordinal
    /// `PolicyFindingId::from_match_anchor` folds into a strong match anchor.
    pub const fn occurrence_ordinal(&self) -> u32 {
        self.occurrence_ordinal
    }

    /// Tier 1: language, workspace-relative path, `kind:qualified_name`, and the
    /// occurrence ordinal.
    pub const fn stable_semantic_identity(&self) -> StableDigest {
        self.stable_semantic_identity
    }

    /// Tier 2: the SHA-256 of the declaration's exact source slice, separated
    /// by language and kind.
    pub const fn content_identity(&self) -> StableDigest {
        self.content_identity
    }

    /// Tier 3: language, owner segments, kind, terminal name and signature --
    /// everything about the declaration's contract except where it lives and
    /// what its body says.
    pub const fn owner_signature_identity(&self) -> StableDigest {
        self.owner_signature_identity
    }

    fn hash_into(&self, hasher: &mut CanonicalHasher) {
        hasher.field("stable", self.stable_semantic_identity.as_bytes());
        hasher.field("content", self.content_identity.as_bytes());
        hasher.field("contract", self.owner_signature_identity.as_bytes());
    }
}

/// One acquired side: the pin side describing it, plus its entity table in
/// deterministic order.
#[derive(Debug, Clone)]
pub struct DeclarationImage {
    side: RevisionSide,
    entities: Vec<DeclarationEntity>,
}

impl DeclarationImage {
    pub const fn side(&self) -> &RevisionSide {
        &self.side
    }

    pub fn entities(&self) -> &[DeclarationEntity] {
        &self.entities
    }
}

/// The bounded derivation of a declaration correspondence.
///
/// The limits are stated once, on the builder, so the acquisition and the
/// matching cannot be run under two different bounds and produce a relation
/// whose own limits do not describe it.
#[derive(Debug, Clone, Copy)]
pub struct DeclarationCorrespondenceBuilder {
    limits: CorrespondenceLimits,
}

impl Default for DeclarationCorrespondenceBuilder {
    fn default() -> Self {
        Self::new(CorrespondenceLimits::default())
    }
}

impl DeclarationCorrespondenceBuilder {
    pub const fn new(limits: CorrespondenceLimits) -> Self {
        Self { limits }
    }

    pub const fn limits(&self) -> CorrespondenceLimits {
        self.limits
    }

    /// Read one revision's declarations through `analyzer`.
    ///
    /// The traversal is flat: `all_declarations` yields every declaration the
    /// analyzer holds, so there is no tree to recurse over. Each file's bytes
    /// are read at most once regardless of how many declarations it holds.
    pub fn acquire(
        &self,
        analyzer: &dyn IAnalyzer,
        endpoint: RevisionEndpoint,
        scope: WorkspaceScope,
    ) -> DeclarationImage {
        let mut side = RevisionSide::new(endpoint, scope);
        let mut acquired: Vec<AcquiredDeclaration> = Vec::new();
        let mut file_text: HashMap<std::path::PathBuf, Option<String>> = HashMap::new();

        for unit in analyzer.all_declarations() {
            if unit.is_synthetic() {
                continue;
            }
            let Ok(path) = WorkspaceRelativePath::try_from_path(unit.source().rel_path()) else {
                // A path that is not portable cannot carry a portable identity,
                // and every identity in this schema is portable by contract.
                continue;
            };
            if !side.scope().contains(&path) {
                continue;
            }
            if acquired.len() >= self.limits.max_entities_per_side {
                side.record_gap(AcquisitionGap::EntityLimitExceeded {
                    limit: self.limits.max_entities_per_side,
                });
                break;
            }
            // The declaration's own extent. `ranges` may report several for one
            // declaration (a C++ definition and its declaration); the earliest
            // is the one every other diff surface already uses.
            let Some(range) = analyzer
                .ranges(&unit)
                .iter()
                .copied()
                .min_by_key(|range| (range.start_line, range.start_byte))
            else {
                side.record_gap(AcquisitionGap::DeclarationSliceUnavailable { path });
                continue;
            };
            let text = file_text
                .entry(unit.source().abs_path())
                .or_insert_with(|| unit.source().read_to_string().ok());
            let Some(text) = text.as_deref() else {
                side.record_gap(AcquisitionGap::SourceUnreadable { path });
                continue;
            };
            let Some(slice) = text.get(range.start_byte..range.end_byte) else {
                side.record_gap(AcquisitionGap::DeclarationSliceUnavailable { path });
                continue;
            };
            acquired.push(AcquiredDeclaration {
                path,
                language: unit.source().declaration_language().config_label(),
                kind: unit.kind().display_lowercase(),
                qualified_name: unit.fq_name(),
                terminal_name: unit.terminal_name().to_string(),
                owner_segments: owner_segments(&unit),
                signature: analyzer
                    .signatures(&unit)
                    .first()
                    .map(String::as_str)
                    .or_else(|| unit.signature())
                    .unwrap_or_default()
                    .to_string(),
                start_byte: range.start_byte,
                end_byte: range.end_byte,
                content_sha256: sha256_bytes(slice.as_bytes()),
            });
        }

        // Document order within a file decides the occurrence ordinal, and the
        // whole table is ordered so two runs over the same revision produce the
        // same entity indices.
        acquired.sort_by(|left, right| {
            (
                &left.path,
                left.start_byte,
                left.end_byte,
                left.kind,
                &left.qualified_name,
            )
                .cmp(&(
                    &right.path,
                    right.start_byte,
                    right.end_byte,
                    right.kind,
                    &right.qualified_name,
                ))
        });

        // The ordinal separates declarations that agree on everything the
        // identity names, which is why it is assigned per full identity group
        // rather than per name: two overloads differ by signature and must not
        // be told apart by their position in the file.
        let mut ordinals: HashMap<(&WorkspaceRelativePath, &str, &str, &str), u32> = HashMap::new();
        let mut entities = Vec::with_capacity(acquired.len());
        for declaration in &acquired {
            let ordinal = ordinals
                .entry((
                    &declaration.path,
                    declaration.kind,
                    declaration.qualified_name.as_str(),
                    declaration.signature.as_str(),
                ))
                .or_insert(0);
            entities.push(declaration.entity(*ordinal));
            *ordinal += 1;
        }

        DeclarationImage { side, entities }
    }

    /// Correspond two acquired images.
    pub fn build(
        &self,
        base: DeclarationImage,
        target: DeclarationImage,
    ) -> DeclarationCorrespondence {
        let pin = RevisionPin::new(base.side, target.side);
        let base_entities = base.entities;
        let target_entities = target.entities;

        let by_stable = index_by(
            &target_entities,
            DeclarationEntity::stable_semantic_identity,
        );
        let by_content = index_by(&target_entities, DeclarationEntity::content_identity);
        let by_contract = index_by(
            &target_entities,
            DeclarationEntity::owner_signature_identity,
        );

        // Pass one: the winning tier and candidate set of every base entity.
        let mut selections: Vec<Option<Selection>> = Vec::with_capacity(base_entities.len());
        let mut base_unresolved: Vec<UnresolvedEntity> = Vec::new();
        let mut target_bound_reason: HashMap<u32, UnresolvedReason> = HashMap::new();
        for (index, entity) in base_entities.iter().enumerate() {
            let selected = [
                (
                    Tier::Stable,
                    entity.stable_semantic_identity,
                    by_stable.get(&entity.stable_semantic_identity),
                ),
                (
                    Tier::Content,
                    entity.content_identity,
                    by_content.get(&entity.content_identity),
                ),
                (
                    Tier::Contract,
                    entity.owner_signature_identity,
                    by_contract.get(&entity.owner_signature_identity),
                ),
            ]
            .into_iter()
            .find_map(|(tier, identity, candidates)| {
                candidates.map(|candidates| (tier, identity, candidates))
            });
            let Some((tier, identity, candidates)) = selected else {
                selections.push(None);
                base_unresolved.push(UnresolvedEntity {
                    entity: EntityIndex::new(index),
                    reason: UnresolvedReason::NoCandidate,
                });
                continue;
            };
            if candidates.len() > self.limits.max_candidates_per_entity {
                let reason = UnresolvedReason::CandidateLimitExceeded {
                    candidates: candidates.len(),
                    limit: self.limits.max_candidates_per_entity,
                };
                for candidate in candidates {
                    target_bound_reason.entry(*candidate).or_insert(reason);
                }
                selections.push(None);
                base_unresolved.push(UnresolvedEntity {
                    entity: EntityIndex::new(index),
                    reason,
                });
                continue;
            }
            selections.push(Some(Selection {
                tier,
                identity,
                candidates: candidates.clone(),
            }));
        }

        // Pass two: how many base entities claim each target entity. A target
        // claimed twice is as ambiguous as a base with two candidates, and
        // neither direction may be resolved by picking.
        let mut claims: HashMap<u32, u32> = HashMap::new();
        for selection in selections.iter().flatten() {
            for candidate in &selection.candidates {
                *claims.entry(*candidate).or_default() += 1;
            }
        }

        // Pass three: emit. Base order is the deterministic entity order, and
        // each candidate list is already ascending, so the pair list is sorted
        // by `(base, target)` without a final sort.
        let mut pairs: Vec<CorrespondencePair> = Vec::new();
        let mut claimed: Vec<bool> = vec![false; target_entities.len()];
        for (index, selection) in selections.iter().enumerate() {
            let Some(selection) = selection else {
                continue;
            };
            if pairs.len() + selection.candidates.len() > self.limits.max_pairs {
                let reason = UnresolvedReason::PairLimitExceeded {
                    limit: self.limits.max_pairs,
                };
                for candidate in &selection.candidates {
                    target_bound_reason.entry(*candidate).or_insert(reason);
                }
                base_unresolved.push(UnresolvedEntity {
                    entity: EntityIndex::new(index),
                    reason,
                });
                continue;
            }
            let base_entity = &base_entities[index];
            for candidate in &selection.candidates {
                let target_entity = &target_entities[*candidate as usize];
                let peers = claims.get(candidate).copied().unwrap_or(1) - 1;
                let alternatives = peers + (selection.candidates.len() as u32 - 1);
                pairs.push(CorrespondencePair {
                    base: EntityIndex::new(index),
                    target: EntityIndex::new(*candidate as usize),
                    kind: selection.tier.classify(base_entity, target_entity),
                    evidence: selection.tier.evidence(selection.identity),
                    certainty: if alternatives == 0 {
                        CorrespondenceCertainty::Unique
                    } else {
                        CorrespondenceCertainty::Ambiguous { alternatives }
                    },
                });
                claimed[*candidate as usize] = true;
            }
        }
        base_unresolved.sort();

        let target_unresolved = claimed
            .iter()
            .enumerate()
            .filter(|(_, claimed)| !**claimed)
            .map(|(index, _)| UnresolvedEntity {
                entity: EntityIndex::new(index),
                reason: target_bound_reason
                    .get(&(index as u32))
                    .copied()
                    .unwrap_or(UnresolvedReason::NoCandidate),
            })
            .collect();

        DeclarationCorrespondence {
            pin,
            limits: self.limits,
            base_entities,
            target_entities,
            pairs,
            base_unresolved,
            target_unresolved,
        }
    }
}

/// The correspondence between two revisions' declarations.
#[derive(Debug, Clone)]
pub struct DeclarationCorrespondence {
    pin: RevisionPin,
    limits: CorrespondenceLimits,
    base_entities: Vec<DeclarationEntity>,
    target_entities: Vec<DeclarationEntity>,
    pairs: Vec<CorrespondencePair>,
    base_unresolved: Vec<UnresolvedEntity>,
    target_unresolved: Vec<UnresolvedEntity>,
}

impl DeclarationCorrespondence {
    pub const fn pin(&self) -> &RevisionPin {
        &self.pin
    }

    pub const fn limits(&self) -> CorrespondenceLimits {
        self.limits
    }

    pub fn base_entities(&self) -> &[DeclarationEntity] {
        &self.base_entities
    }

    pub fn target_entities(&self) -> &[DeclarationEntity] {
        &self.target_entities
    }

    /// Every retained pair, ordered by `(base, target)`.
    pub fn pairs(&self) -> &[CorrespondencePair] {
        &self.pairs
    }

    /// Base entities with no retained pair, ordered by entity index.
    pub fn base_unresolved(&self) -> &[UnresolvedEntity] {
        &self.base_unresolved
    }

    /// Target entities no retained pair names, ordered by entity index.
    pub fn target_unresolved(&self) -> &[UnresolvedEntity] {
        &self.target_unresolved
    }

    pub fn base_entity(&self, entity: EntityIndex) -> &DeclarationEntity {
        &self.base_entities[entity.index()]
    }

    pub fn target_entity(&self, entity: EntityIndex) -> &DeclarationEntity {
        &self.target_entities[entity.index()]
    }

    /// Every mapping of one base entity. More than one means the correspondence
    /// is ambiguous and all of them were retained.
    pub fn pairs_for_base(&self, entity: EntityIndex) -> impl Iterator<Item = &CorrespondencePair> {
        self.pairs.iter().filter(move |pair| pair.base == entity)
    }

    /// Partial when either side's acquisition was partial or any entity was
    /// left unresolved by a bound rather than by the code.
    pub fn completeness(&self) -> AcquisitionCompleteness {
        let bounded = self
            .base_unresolved
            .iter()
            .chain(&self.target_unresolved)
            .any(|unresolved| unresolved.reason.is_bound());
        if bounded {
            AcquisitionCompleteness::Partial
        } else {
            self.pin.completeness()
        }
    }

    /// The deterministic identity of this whole relation.
    pub fn digest(&self) -> StableDigest {
        let mut hasher = CanonicalHasher::new(RELATION_DOMAIN);
        hasher.field("pin", self.pin.digest().as_bytes());
        self.limits.hash_into(&mut hasher);
        hasher.sequence("base_entities", &self.base_entities, |hasher, entity| {
            entity.hash_into(hasher);
        });
        hasher.sequence(
            "target_entities",
            &self.target_entities,
            |hasher, entity| {
                entity.hash_into(hasher);
            },
        );
        hasher.sequence("pairs", &self.pairs, |hasher, pair| pair.hash_into(hasher));
        hasher.sequence(
            "base_unresolved",
            &self.base_unresolved,
            |hasher, unresolved| unresolved.hash_into(hasher),
        );
        hasher.sequence(
            "target_unresolved",
            &self.target_unresolved,
            |hasher, unresolved| unresolved.hash_into(hasher),
        );
        StableDigest::from_array(hasher.finish())
    }
}

/// Correspond the declarations of two committed revisions of one workspace.
///
/// Both endpoints are immutable by construction: each revision is exported to a
/// private temporary directory and analyzed there, so nothing the working tree
/// does during the comparison can change either side.
///
/// Both exports read and write the repository's shared content-addressed
/// analyzer cache, exactly as the `blast_radius` and `analyze_diff` revision
/// images do. A comparison of two revisions parses only the blobs the cache has
/// never seen, and the blobs the two revisions share are parsed once between
/// them; both sides' work warms every later consumer, including the live
/// worktree analyzer. The cache is opened from `workspace_root`, never from an
/// export directory: an export is a self-deleting temp tree with no repository
/// to resolve a cache location from.
pub fn correspond_revisions(
    workspace_root: &Path,
    base_revision: &str,
    target_revision: &str,
    limits: CorrespondenceLimits,
) -> Result<DeclarationCorrespondence, String> {
    let builder = DeclarationCorrespondenceBuilder::new(limits);
    let base_export = crate::diff_analysis::export_revision(workspace_root, base_revision)?;
    let target_export = crate::diff_analysis::export_revision(workspace_root, target_revision)?;
    // Opening is strict. A cache that exists but will not open is reported
    // rather than worked around: the silent alternative re-parses every blob of
    // both revisions on every request, which is a performance failure worth
    // naming.
    let cache = crate::analyzer::SharedAnalyzerCache::open(workspace_root)
        .map_err(|error| error.to_string())?;
    let base_analyzer =
        crate::diff_analysis::build_revision_analyzer(base_export.image(), Some(&cache))?;
    let target_analyzer =
        crate::diff_analysis::build_revision_analyzer(target_export.image(), Some(&cache))?;
    let base = builder.acquire(
        base_analyzer.analyzer(),
        commit_endpoint(base_export.commit_id())?,
        WorkspaceScope::whole_workspace(),
    );
    let target = builder.acquire(
        target_analyzer.analyzer(),
        commit_endpoint(target_export.commit_id())?,
        WorkspaceScope::whole_workspace(),
    );
    Ok(builder.build(base, target))
}

fn commit_endpoint(commit_id: &str) -> Result<RevisionEndpoint, String> {
    ObjectName::new(commit_id)
        .map(RevisionEndpoint::Commit)
        .map_err(|error| format!("commit `{commit_id}` is not a usable object name: {error}"))
}

/// One declaration read off the analyzer, before ordinals are assigned.
struct AcquiredDeclaration {
    path: WorkspaceRelativePath,
    language: &'static str,
    kind: &'static str,
    qualified_name: String,
    terminal_name: String,
    owner_segments: Vec<String>,
    signature: String,
    start_byte: usize,
    end_byte: usize,
    content_sha256: [u8; 32],
}

impl AcquiredDeclaration {
    fn entity(&self, occurrence_ordinal: u32) -> DeclarationEntity {
        let mut identity = CanonicalHasher::new(DECLARATION_IDENTITY_DOMAIN);
        identity.field("namespace", self.language.as_bytes());
        identity.field("path", self.path.as_str().as_bytes());
        identity.field("derivation", b"analyzer_declaration_id");
        identity.field("kind", self.kind.as_bytes());
        identity.field("qualified_name", self.qualified_name.as_bytes());
        identity.field("signature", self.signature.as_bytes());
        identity.field("occurrence_ordinal", &occurrence_ordinal.to_be_bytes());

        let mut content = CanonicalHasher::new(DECLARATION_CONTENT_DOMAIN);
        content.field("namespace", self.language.as_bytes());
        content.field("kind", self.kind.as_bytes());
        content.field("source_slice_sha256", &self.content_sha256);

        let mut contract = CanonicalHasher::new(DECLARATION_CONTRACT_DOMAIN);
        contract.field("namespace", self.language.as_bytes());
        contract.sequence("owner", &self.owner_segments, |hasher, segment| {
            hasher.value(segment.as_bytes());
        });
        contract.field("kind", self.kind.as_bytes());
        contract.field("terminal_name", self.terminal_name.as_bytes());
        contract.field("signature", self.signature.as_bytes());

        DeclarationEntity {
            path: self.path.clone(),
            language: self.language.into(),
            kind: self.kind.into(),
            qualified_name: self.qualified_name.as_str().into(),
            terminal_name: self.terminal_name.as_str().into(),
            signature: self.signature.as_str().into(),
            occurrence_ordinal,
            stable_semantic_identity: StableDigest::from_array(identity.finish()),
            content_identity: StableDigest::from_array(content.finish()),
            owner_signature_identity: StableDigest::from_array(contract.finish()),
        }
    }
}

/// The structured owner chain of a declaration: its qualified-name segments
/// root to leaf, without the leaf.
///
/// Read from the extractor's recorded segments rather than by splitting the
/// rendered name, which cannot be split back reliably: a segment may itself
/// contain `.`, `/` or `::` (#2111).
fn owner_segments(unit: &CodeUnit) -> Vec<String> {
    let mut segments = unit.fq_segment_texts();
    segments.pop();
    segments
}

/// The tier a base entity won on, kept separate from
/// [`CorrespondenceEvidence`] so the classification and the published evidence
/// are derived from one decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Stable,
    Content,
    Contract,
}

impl Tier {
    const fn evidence(self, identity: StableDigest) -> CorrespondenceEvidence {
        match self {
            Self::Stable => CorrespondenceEvidence::StableSemanticIdentity { identity },
            Self::Content => CorrespondenceEvidence::ContentIdentity { identity },
            Self::Contract => CorrespondenceEvidence::OwnerSignatureIdentity { identity },
        }
    }

    fn classify(self, base: &DeclarationEntity, target: &DeclarationEntity) -> CorrespondenceKind {
        match self {
            // Same place, same name, same contract: whether it changed is what
            // the content says.
            Self::Stable => {
                if base.content_identity == target.content_identity {
                    CorrespondenceKind::Unchanged
                } else {
                    CorrespondenceKind::ModifiedCandidate
                }
            }
            // Byte-equal content. Whether that is a move is decided by
            // comparing where the two declarations live, not by inferring it
            // from tier 1 having failed: tier 1 also fails for two byte-equal
            // duplicates that share a file, and neither of those moved.
            Self::Content => {
                if base.path == target.path
                    && base.kind == target.kind
                    && base.qualified_name == target.qualified_name
                    && base.signature == target.signature
                {
                    CorrespondenceKind::Unchanged
                } else {
                    CorrespondenceKind::Moved
                }
            }
            // An equal contract reached only because the content differs, since
            // equal content would have been claimed a tier earlier.
            Self::Contract => CorrespondenceKind::ModifiedCandidate,
        }
    }
}

struct Selection {
    tier: Tier,
    identity: StableDigest,
    candidates: Vec<u32>,
}

/// Index one side's entities by one identity. Candidate lists come out in
/// ascending entity order because the entities are visited in that order.
fn index_by(
    entities: &[DeclarationEntity],
    identity: impl Fn(&DeclarationEntity) -> StableDigest,
) -> HashMap<StableDigest, Vec<u32>> {
    let mut index: HashMap<StableDigest, Vec<u32>> = HashMap::new();
    for (position, entity) in entities.iter().enumerate() {
        index
            .entry(identity(entity))
            .or_default()
            .push(u32::try_from(position).expect("entity tables are bounded well below u32::MAX"));
    }
    index
}

#[cfg(test)]
mod tests {
    use super::{CorrespondenceLimits, correspond_revisions};
    use crate::gitblob::test_repo;
    use std::fs;
    use std::path::Path;

    /// A two-commit Go module whose second commit edits one function body and
    /// leaves the other file untouched, so the two revisions share a blob and
    /// differ in one.
    fn two_revision_repo(root: &Path) -> (String, String) {
        let repo = test_repo::init_repo(root);
        fs::write(root.join("go.mod"), "module repro\n\ngo 1.21\n").unwrap();
        fs::write(
            root.join("kept.go"),
            "package repro\n\nfunc Kept() int { return 1 }\n",
        )
        .unwrap();
        fs::write(
            root.join("edited.go"),
            "package repro\n\nfunc Edited() int { return 1 }\n",
        )
        .unwrap();
        let base = test_repo::commit_all(&repo, "base");
        fs::write(
            root.join("edited.go"),
            "package repro\n\nfunc Edited() int { return 2 }\n",
        )
        .unwrap();
        let head = test_repo::commit_all(&repo, "target");
        (base.to_string(), head.to_string())
    }

    fn cache_row_count(root: &Path, table: &str) -> i64 {
        rusqlite::Connection::open(crate::analyzer::store::analyzer_db_path(root))
            .expect("open the shared analyzer cache")
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count cache rows")
    }

    /// Both revision exports read and write the repository's shared cache, so a
    /// repeated comparison of the same pair parses nothing, and neither export
    /// directory leaves a workspace projection row behind.
    #[test]
    fn repeated_correspondence_parses_nothing_the_second_time() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (base, head) = two_revision_repo(root);

        let cold = correspond_revisions(root, &base, &head, CorrespondenceLimits::default())
            .expect("cold correspondence");
        let after_cold = cache_row_count(root, "blobs");
        let warm = correspond_revisions(root, &base, &head, CorrespondenceLimits::default())
            .expect("warm correspondence");
        let after_warm = cache_row_count(root, "blobs");

        assert_eq!(
            cold.digest(),
            warm.digest(),
            "a warm comparison must answer exactly like the cold one"
        );
        assert!(
            after_cold > 0,
            "a cold comparison publishes both revisions' parsed blobs"
        );
        assert_eq!(
            after_cold, after_warm,
            "a warm comparison must publish no new blobs"
        );
        // Every workspace identity this comparison could have published names an
        // export directory that no longer exists.
        assert_eq!(0, cache_row_count(root, "workspace_heads"));
        assert_eq!(0, cache_row_count(root, "workspace_revisions"));
        assert_eq!(0, cache_row_count(root, "workspace_file_versions"));
    }

    /// A comparison that cannot open the repository's shared cache is a hard
    /// error, not a silently slower ephemeral rebuild of both revisions. This
    /// is the same contract `an_immutable_request_fails_when_the_shared_cache_cannot_be_opened`
    /// pins for `blast_radius`; the equality this test used to assert is
    /// covered by `repeated_correspondence_parses_nothing_the_second_time`.
    #[test]
    fn a_comparison_fails_when_the_shared_cache_cannot_be_opened() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (base, head) = two_revision_repo(root);

        // Occupying the cache file's path with a directory is the portable way
        // to make the store refuse to open, which is what a read-only cache
        // location does in production.
        let db_path = crate::analyzer::store::analyzer_db_path(root);
        fs::create_dir_all(&db_path).expect("block the cache path");

        let error = correspond_revisions(root, &base, &head, CorrespondenceLimits::default())
            .expect_err("a blocked shared cache must fail the comparison, not downgrade it");
        assert!(
            error.contains(&db_path.display().to_string()),
            "the error must name the cache it could not open: {error}"
        );

        fs::remove_dir(&db_path).expect("unblock the cache path");
        correspond_revisions(root, &base, &head, CorrespondenceLimits::default())
            .expect("persisted correspondence");
        assert!(
            cache_row_count(root, "blobs") > 0,
            "the unblocked run must have used the shared cache"
        );
    }
}
