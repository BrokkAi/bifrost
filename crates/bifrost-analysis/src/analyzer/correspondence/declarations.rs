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

use super::{
    AcquisitionCompleteness, AcquisitionGap, CorrespondenceCertainty, CorrespondenceEvidence,
    CorrespondenceKind, CorrespondenceLimits, CorrespondencePair, EntityIndex, RevisionEndpoint,
    RevisionPin, RevisionSide, UnresolvedEntity, UnresolvedReason, WorkspaceScope,
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
mod digest_properties {
    use super::super::RevisionEndpoint;
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn acquisition_bounds_only_count_eligible_declarations() {
        use crate::analyzer::{
            CodeUnitIndex, CodeUnitType, DeclarationInfo, Language, Project, ProjectFile, Range,
            TestProject,
        };
        use std::collections::BTreeSet;
        struct ParsedDeclarations {
            project: TestProject,
            units: Vec<(CodeUnit, Range)>,
        }
        impl CodeUnitIndex for ParsedDeclarations {
            fn project(&self) -> &dyn Project {
                &self.project
            }
            fn languages(&self) -> BTreeSet<Language> {
                BTreeSet::from([Language::Python])
            }
            fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
                Box::new(self.units.iter().map(|(unit, _)| unit.clone()))
            }
            fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
                self.units
                    .iter()
                    .filter(|(candidate, _)| candidate == unit)
                    .map(|(_, range)| *range)
                    .collect()
            }
            fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
                unimplemented!()
            }
            fn enclosing_code_unit(&self, _: &ProjectFile, _: &Range) -> Option<CodeUnit> {
                unimplemented!()
            }
            fn enclosing_code_unit_for_lines(
                &self,
                _: &ProjectFile,
                _: usize,
                _: usize,
            ) -> Option<CodeUnit> {
                unimplemented!()
            }
            fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
                unimplemented!()
            }
            fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
                unimplemented!()
            }
            fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
                unimplemented!()
            }
        }
        impl IAnalyzer for ParsedDeclarations {
            fn update(&self, _: &BTreeSet<ProjectFile>) -> Self {
                unimplemented!()
            }
            fn update_all(&self) -> Self {
                unimplemented!()
            }
            fn is_access_expression(&self, _: &ProjectFile, _: usize, _: usize) -> bool {
                unimplemented!()
            }
            fn find_nearest_declaration(
                &self,
                _: &ProjectFile,
                _: usize,
                _: usize,
                _: &str,
            ) -> Option<DeclarationInfo> {
                unimplemented!()
            }
        }
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        for count in [0, 1, 3, 4] {
            let temp = tempfile::tempdir().unwrap();
            let mut analyzer = ParsedDeclarations {
                project: TestProject::new(temp.path(), Language::Python),
                units: vec![],
            };
            let source = (0..count)
                .map(|i| format!("def f{i}(): pass\n"))
                .collect::<String>();
            for (path, source) in [
                ("src/example.py", source.as_str()),
                ("excluded.py", "def skipped(): pass\n"),
            ] {
                let file = ProjectFile::new(temp.path(), path);
                file.write(source).unwrap();
                let tree = parser.parse(source, None).unwrap();
                let mut cursor = tree.root_node().walk();
                for declaration in tree.root_node().named_children(&mut cursor) {
                    assert_eq!(declaration.kind(), "function_definition");
                    let name = declaration.child_by_field_name("name").unwrap();
                    let unit = CodeUnit::new(
                        file.clone(),
                        CodeUnitType::Function,
                        "",
                        &source[name.byte_range()],
                    );
                    let range = brokk_bifrost_core::analyzer::tree_walk::node_range(declaration);
                    analyzer.units.push((unit.with_synthetic(true), range));
                    analyzer.units.push((unit, range));
                }
            }
            let scope = WorkspaceScope::new([WorkspaceRelativePath::new("src").unwrap()], []);
            for limit in [0, 1, 3] {
                let builder = DeclarationCorrespondenceBuilder::new(CorrespondenceLimits {
                    max_entities_per_side: limit,
                    ..CorrespondenceLimits::default()
                });
                let image =
                    builder.acquire(&analyzer, RevisionEndpoint::WorkingTree, scope.clone());
                assert_eq!(
                    image.entities.len(),
                    count.min(limit),
                    "count={count}, limit={limit}"
                );
                assert_eq!(
                    image.side.completeness(),
                    if count > limit {
                        AcquisitionCompleteness::Partial
                    } else {
                        AcquisitionCompleteness::Complete
                    }
                );
                assert_eq!(
                    image.side.gaps,
                    if count > limit {
                        vec![AcquisitionGap::EntityLimitExceeded { limit }]
                    } else {
                        vec![]
                    }
                );
            }
        }
    }

    fn image(names: &[&str]) -> DeclarationImage {
        DeclarationImage {
            side: RevisionSide::new(
                RevisionEndpoint::WorkingTree,
                WorkspaceScope::whole_workspace(),
            ),
            entities: names
                .iter()
                .map(|name| {
                    AcquiredDeclaration {
                        path: WorkspaceRelativePath::new(format!("{name}.rb")).unwrap(),
                        language: "ruby",
                        kind: "function",
                        qualified_name: (*name).to_owned(),
                        terminal_name: (*name).to_owned(),
                        owner_segments: Vec::new(),
                        signature: String::new(),
                        start_byte: 0,
                        end_byte: name.len(),
                        content_sha256: sha256_bytes(name.as_bytes()),
                    }
                    .entity(0)
                })
                .collect(),
        }
    }

    use super::super::tests::{Frames, expected_pin};

    fn acquired(path: &str, owner: &[&str], body: &[u8]) -> AcquiredDeclaration {
        use sha2::{Digest, Sha256};
        AcquiredDeclaration {
            path: WorkspaceRelativePath::new(path).unwrap(),
            language: "ruby",
            kind: "function",
            qualified_name: format!("{}.f", owner.join(".")),
            terminal_name: "f".into(),
            owner_segments: owner.iter().map(|s| (*s).into()).collect(),
            signature: "f(x)".into(),
            start_byte: 0,
            end_byte: body.len(),
            content_sha256: Sha256::digest(body).into(),
        }
    }

    fn expected_entity(declaration: &AcquiredDeclaration, ordinal: u32) -> [StableDigest; 3] {
        let mut stable = Frames::new("bifrost.correspondence.declaration-identity.v1");
        stable.field("namespace", declaration.language);
        stable.field("path", declaration.path.as_str());
        stable.field("derivation", "analyzer_declaration_id");
        stable.field("kind", declaration.kind);
        stable.field("qualified_name", &declaration.qualified_name);
        stable.field("signature", &declaration.signature);
        stable.field("occurrence_ordinal", ordinal.to_be_bytes());
        let mut content = Frames::new("bifrost.correspondence.declaration-content.v1");
        content.field("namespace", declaration.language);
        content.field("kind", declaration.kind);
        content.field("source_slice_sha256", declaration.content_sha256);
        let mut contract = Frames::new("bifrost.correspondence.declaration-contract.v1");
        contract.field("namespace", declaration.language);
        contract.sequence("owner", declaration.owner_segments.len());
        for segment in &declaration.owner_segments {
            contract.atom(segment);
        }
        contract.field("kind", declaration.kind);
        contract.field("terminal_name", &declaration.terminal_name);
        contract.field("signature", &declaration.signature);
        [stable.digest(), content.digest(), contract.digest()]
    }

    #[test]
    fn declaration_and_relation_v1_known_answer_vectors() {
        let declarations = [
            acquired("old.rb", &["outer.with.dot", "A"], b"old"),
            acquired("new.rb", &["outer.with.dot", "A"], b"new"),
        ];
        let mut entities = Vec::new();
        let mut expected = Vec::new();
        for declaration in &declarations {
            for ordinal in [0, 1] {
                let entity = declaration.entity(ordinal);
                let digests = expected_entity(declaration, ordinal);
                assert_eq!(
                    [
                        entity.stable_semantic_identity(),
                        entity.content_identity(),
                        entity.owner_signature_identity()
                    ],
                    digests
                );
                assert_eq!(entity.occurrence_ordinal(), ordinal);
                entities.push(entity);
                expected.push(digests);
            }
        }
        // Whole relation vectors cover unequal sides, repeated occurrences,
        // every evidence tier and public ambiguous claims with 1 or 2 peers.
        for (tier, evidence) in [
            (
                "stable_semantic_identity",
                CorrespondenceEvidence::StableSemanticIdentity {
                    identity: expected[0][0],
                },
            ),
            (
                "content_identity",
                CorrespondenceEvidence::ContentIdentity {
                    identity: expected[0][1],
                },
            ),
            (
                "owner_signature_identity",
                CorrespondenceEvidence::OwnerSignatureIdentity {
                    identity: expected[0][2],
                },
            ),
            (
                "body_similarity",
                CorrespondenceEvidence::BodySimilarity {
                    score_per_mille: 731,
                },
            ),
        ] {
            for alternatives in [0u32, 1, 2] {
                let relation = DeclarationCorrespondence {
                    pin: RevisionPin::new(image(&[]).side, image(&[]).side),
                    limits: CorrespondenceLimits {
                        max_entities_per_side: 19,
                        max_candidates_per_entity: 5,
                        max_pairs: 23,
                    },
                    base_entities: entities[..2].to_vec(),
                    target_entities: entities[2..].to_vec(),
                    pairs: vec![CorrespondencePair {
                        base: EntityIndex::new(0),
                        target: EntityIndex::new(1),
                        kind: CorrespondenceKind::ModifiedCandidate,
                        evidence,
                        certainty: if alternatives == 0 {
                            CorrespondenceCertainty::Unique
                        } else {
                            CorrespondenceCertainty::Ambiguous { alternatives }
                        },
                    }],
                    base_unresolved: vec![],
                    target_unresolved: vec![],
                };
                let mut frames = Frames::new("bifrost.correspondence.declaration-relation.v1");
                frames.field("pin", expected_pin(&relation.pin).as_bytes());
                for (label, value) in [
                    ("max_entities_per_side", 19u64),
                    ("max_candidates_per_entity", 5),
                    ("max_pairs", 23),
                ] {
                    frames.field(label, value.to_be_bytes());
                }
                for (label, digests) in [
                    ("base_entities", &expected[..2]),
                    ("target_entities", &expected[2..]),
                ] {
                    frames.sequence(label, digests.len());
                    for entity in digests {
                        for (name, digest) in
                            ["stable", "content", "contract"].into_iter().zip(entity)
                        {
                            frames.field(name, digest.as_bytes());
                        }
                    }
                }
                frames.sequence("pairs", 1);
                frames.field("base", 0u32.to_be_bytes());
                frames.field("target", 1u32.to_be_bytes());
                frames.field("kind", "modified_candidate");
                frames.field("tier", tier);
                if tier == "body_similarity" {
                    frames.field("score_per_mille", 731u16.to_be_bytes());
                } else {
                    let index = match tier {
                        "stable_semantic_identity" => 0,
                        "content_identity" => 1,
                        _ => 2,
                    };
                    frames.field("identity", expected[0][index].as_bytes());
                }
                frames.field(
                    "certainty",
                    if alternatives == 0 {
                        "unique"
                    } else {
                        "ambiguous"
                    },
                );
                if alternatives > 0 {
                    frames.field("alternatives", alternatives.to_be_bytes());
                }
                frames.sequence("base_unresolved", 0);
                frames.sequence("target_unresolved", 0);
                assert_eq!(
                    relation.digest(),
                    frames.digest(),
                    "{tier}, alternatives={alternatives}"
                );
            }
        }
    }

    #[test]
    fn ambiguity_groups_fit_exact_pair_and_default_candidate_bounds() {
        let base = DeclarationImage {
            side: image(&[]).side,
            entities: vec![acquired("old.rb", &["A"], b"same").entity(0)],
        };
        for count in [2, 16, 17] {
            let target = DeclarationImage {
                side: image(&[]).side,
                entities: (0..count)
                    .map(|i| acquired(&format!("copy{i}.rb"), &["A"], b"same").entity(0))
                    .collect(),
            };
            for max_pairs in [count - 1, count, count + 1] {
                let relation = DeclarationCorrespondenceBuilder::new(CorrespondenceLimits {
                    max_pairs,
                    ..CorrespondenceLimits::default()
                })
                .build(base.clone(), target.clone());
                let fits = count <= 16 && count <= max_pairs;
                assert_eq!(
                    relation.pairs.len(),
                    if fits { count } else { 0 },
                    "{count} candidates, {max_pairs} pairs"
                );
                assert_eq!(
                    relation.completeness(),
                    if fits {
                        AcquisitionCompleteness::Complete
                    } else {
                        AcquisitionCompleteness::Partial
                    }
                );
                if fits {
                    assert!(relation.base_unresolved.is_empty());
                    assert!(relation.target_unresolved.is_empty());
                    for (i, pair) in relation.pairs.iter().enumerate() {
                        assert_eq!(pair.target, EntityIndex::new(i));
                        assert_eq!(pair.kind, CorrespondenceKind::Moved);
                        assert_eq!(
                            pair.certainty,
                            CorrespondenceCertainty::Ambiguous {
                                alternatives: count as u32 - 1
                            }
                        );
                    }
                } else {
                    let reason = if count > 16 {
                        UnresolvedReason::CandidateLimitExceeded {
                            candidates: count,
                            limit: 16,
                        }
                    } else {
                        UnresolvedReason::PairLimitExceeded { limit: max_pairs }
                    };
                    assert_eq!(
                        relation.base_unresolved,
                        vec![UnresolvedEntity {
                            entity: EntityIndex::new(0),
                            reason
                        }]
                    );
                    assert_eq!(
                        relation.target_unresolved,
                        (0..count)
                            .map(|i| UnresolvedEntity {
                                entity: EntityIndex::new(i),
                                reason
                            })
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn owner_contracts_preserve_structured_segments_and_immediate_owner() {
        use crate::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
        use crate::analyzer::{CodeUnitType, ProjectFile};
        let root = std::env::current_dir().unwrap();
        let mut before = Vec::new();
        let mut after = Vec::new();
        for (path, owners, body, output) in [
            ("old.rb", ["A", "B"], b"old".as_slice(), &mut before),
            ("new.rb", ["A", "C"], b"new".as_slice(), &mut after),
        ] {
            for owner in owners {
                let mut fq = FqName::new();
                for (text, kind) in [
                    ("outer.with::punctuation", SegmentKind::Package),
                    (owner, SegmentKind::Type),
                    ("f", SegmentKind::Member),
                ] {
                    fq.push(segment_interner().intern(text, kind));
                }
                let unit = CodeUnit::from_fq(
                    ProjectFile::new(&root, path),
                    CodeUnitType::Function,
                    fq,
                    1,
                    None,
                    false,
                );
                let segments = owner_segments(&unit);
                assert_eq!(segments, ["outer.with::punctuation", owner]);
                let refs = segments.iter().map(String::as_str).collect::<Vec<_>>();
                output.push(acquired(path, &refs, body).entity(0));
            }
        }
        let relation = DeclarationCorrespondenceBuilder::default().build(
            DeclarationImage {
                side: image(&[]).side,
                entities: before,
            },
            DeclarationImage {
                side: image(&[]).side,
                entities: after,
            },
        );
        assert_eq!(relation.pairs.len(), 1);
        assert_eq!(relation.pairs[0].base, EntityIndex::new(0));
        assert_eq!(relation.pairs[0].target, EntityIndex::new(0));
        assert!(matches!(
            relation.pairs[0].evidence,
            CorrespondenceEvidence::OwnerSignatureIdentity { .. }
        ));
        assert_eq!(
            relation.base_unresolved,
            vec![UnresolvedEntity {
                entity: EntityIndex::new(1),
                reason: UnresolvedReason::NoCandidate
            }]
        );
        assert_eq!(relation.target_unresolved, relation.base_unresolved);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn relation_digest_distinguishes_unresolved_claims_and_preserves_equal_entity_order(
            index in 3usize..1000,
            candidates in 2usize..1000,
            limit in 1usize..1000,
            pair_limit in 1usize..1000,
            reverse_base in any::<bool>(),
            reverse_target in any::<bool>(),
        ) {
            let builder = DeclarationCorrespondenceBuilder::default();
            let base = image(&["shared", "old", "old"]);
            let target = image(&["shared", "new", "new"]);
            let relation = builder.build(base.clone(), target.clone());
            prop_assert_eq!(relation.pairs.len(), 1);
            prop_assert_eq!(relation.base_unresolved.len(), 2);
            prop_assert_eq!(relation.target_unresolved.len(), 2);

            // Equal entity occurrences are indistinguishable. Their acquisition
            // order must not become part of a relation's identity.
            let mut reordered_base = base;
            let mut reordered_target = target;
            if reverse_base { reordered_base.entities[1..].reverse(); }
            if reverse_target { reordered_target.entities[1..].reverse(); }
            prop_assert_eq!(relation.digest(), builder.build(reordered_base, reordered_target).digest());

            // Isolate each published unresolved field on each side, independently
            // of the matching algorithm that originally produced the fixture.
            for target_side in [false, true] {
                for reason in [
                    UnresolvedReason::NoCandidate,
                    UnresolvedReason::CandidateLimitExceeded { candidates, limit },
                    UnresolvedReason::PairLimitExceeded { limit: pair_limit },
                ] {
                    let mut claim = relation.clone();
                    let unresolved = if target_side { &mut claim.target_unresolved } else { &mut claim.base_unresolved };
                    unresolved[0].reason = reason;
                    let digest = claim.digest();
                    let mut changed = claim.clone();
                    let unresolved = if target_side { &mut changed.target_unresolved } else { &mut changed.base_unresolved };
                    unresolved[0].entity = EntityIndex::new(index);
                    prop_assert_ne!(digest, changed.digest());

                    for replacement in [
                        UnresolvedReason::NoCandidate,
                        UnresolvedReason::CandidateLimitExceeded { candidates, limit },
                        UnresolvedReason::CandidateLimitExceeded { candidates: candidates + 1, limit },
                        UnresolvedReason::CandidateLimitExceeded { candidates, limit: limit + 1 },
                        UnresolvedReason::PairLimitExceeded { limit: pair_limit },
                        UnresolvedReason::PairLimitExceeded { limit: pair_limit + 1 },
                    ] {
                        if replacement == reason { continue; }
                        let mut changed = claim.clone();
                        let unresolved = if target_side { &mut changed.target_unresolved } else { &mut changed.base_unresolved };
                        unresolved[0].reason = replacement;
                        prop_assert_ne!(digest, changed.digest());
                    }
                }
            }
        }
    }
}
