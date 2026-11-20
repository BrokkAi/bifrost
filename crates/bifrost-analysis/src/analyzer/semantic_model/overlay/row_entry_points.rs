//! Group-local composition over catalog rows and selected decoded inputs.

use super::*;
use crate::analyzer::store::active_models::FamilyRows;
use crate::analyzer::store::cache_budget::StoreCacheBudget;
use crate::analyzer::store::model_catalog::semantic_catalog_question;
use crate::analyzer::store::semantic_composition::{
    ComposedGroupCacheKey, CompositionDiscoveryCacheKey, CompositionLookup,
    RequestSourceAnchorsKey, SearchCandidate, SearchCandidateStream, SearchGroup,
    SemanticOverlayBuildIdentity,
};
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::{
    CatalogError, statements as questions,
};
use brokk_bifrost_semantic::analyzer::semantic_model::runtime::FamilyOpen;
use composition::{CompositionGroupKey, RowCompositionReads};
use rusqlite::named_params;

#[derive(Default)]
struct BackingKeyMemo {
    entries: std::collections::HashMap<
        (Option<String>, SemanticOverlayBuildIdentity),
        ([u8; 32], crate::analyzer::common::QueryCacheBuildReceipt),
    >,
    #[cfg(test)]
    fills: usize,
}

fn backing_key_memo(
    owner: &crate::analyzer::store::model_catalog::RequestRowReader,
) -> &std::sync::Mutex<BackingKeyMemo> {
    owner
        .derivation_extension
        .get_or_init(|| Arc::new(std::sync::Mutex::new(BackingKeyMemo::default())))
        .downcast_ref::<std::sync::Mutex<BackingKeyMemo>>()
        .expect("reader extension is the backing key memo")
}

/// Activation-owner reads remain for overlay construction and eager anchors,
/// release-bundle verification, and census-proven JVM-free consumers including
/// C# type-forward boundaries. A JVM question must not use this helper without
/// review of the #9559 routing plan.
pub(super) fn activation_owner_question<T>(
    reads: &RowCompositionReads<'_>,
    statement: &str,
    key: impl std::fmt::Debug,
    answer: Result<T, CatalogError>,
) -> T {
    let answer = semantic_catalog_question(statement, key, answer).unwrap_or_else(|open| {
        panic!("{statement}: unselected overlay reads run on the activation owner, which owns no JVM-family shards (#9559): {open:?}")
    });
    if let Some(open) = reads.open_part() {
        panic!(
            "{statement}: unselected overlay reads run on the activation owner, which owns no JVM-family shards (#9559): {open:?}"
        );
    }
    answer
}

/// [`activation_owner_question`] for a whole-activation enumeration.
pub(super) fn activation_owner_rows<R>(statement: &str, rows: FamilyRows<R>) -> R {
    if let Some(open) = rows.jvm_open {
        panic!(
            "{statement}: unselected overlay reads run on the activation owner, which owns no JVM-family shards (#9559): {open:?}"
        );
    }
    rows.rows
}

/// The open JVM-family part one request-time lookup saw. A lookup that saw one
/// answers with possible candidates only and retains nothing it computed.
#[derive(Default)]
pub(super) struct LookupOpen(std::cell::Cell<Option<FamilyOpen>>);

impl LookupOpen {
    fn note(&self, open: Option<FamilyOpen>) {
        if self.0.get().is_none() || open.is_some_and(FamilyOpen::is_cancellation) {
            self.0.set(open);
        }
    }

    pub(super) fn get(&self) -> Option<FamilyOpen> {
        self.0.get()
    }
}

/// Rewrite a batch while retaining endpoint failures only on sets that use them.
pub(super) fn rewrite_standalone_relation_sets(
    sets: &[HashSet<String>],
    relations: Vec<SemanticModelRelation>,
    opens: &[&LookupOpen],
    mut endpoint: impl FnMut(
        &str,
        &str,
    ) -> Result<
        (
            crate::analyzer::store::semantic_composition::RepresentativeIdentity,
            composition::OriginRewrites,
        ),
        FamilyOpen,
    >,
) -> Vec<Vec<SemanticModelRelation>> {
    assert_eq!(sets.len(), opens.len());
    let mut endpoints = HashMap::default();
    for relation in &relations {
        let family = brokk_bifrost_core::analyzer::model::semantic_pack_realm(
            &relation.provenance.activation.matched_evidence.language,
        );
        for id in [&relation.from, &relation.to] {
            endpoints
                .entry((family, id))
                .or_insert_with(|| endpoint(family, id));
        }
    }
    let mut by_source = HashMap::<&str, Vec<usize>>::default();
    for (index, relation) in relations.iter().enumerate() {
        by_source
            .entry(semantic_relation_source_key(relation).0)
            .or_default()
            .push(index);
    }
    sets.iter()
        .zip(opens)
        .map(|(origins, open)| {
            let mut selected_indices = origins
                .iter()
                .filter_map(|origin| by_source.get(origin.as_str()))
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            selected_indices.sort_unstable();
            let selected = selected_indices
                .into_iter()
                .map(|index| relations[index].clone())
                .collect::<Vec<_>>();
            let mut replacements = HashMap::default();
            let mut composed_owners = HashSet::default();
            let mut origin_identities = composition::OriginRewrites::default();
            let mut seen = HashSet::default();
            let mut failed = false;
            for relation in &selected {
                let family = brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                    &relation.provenance.activation.matched_evidence.language,
                );
                for id in [&relation.from, &relation.to] {
                    if !seen.insert((family, id)) {
                        continue;
                    }
                    match &endpoints[&(family, id)] {
                        Err(part) => {
                            open.note(Some(*part));
                            failed = true;
                        }
                        Ok((representative, origins)) => {
                            for (pack, ids) in origins {
                                origin_identities.entry(pack.clone()).or_default().extend(
                                    ids.iter()
                                        .map(|(id, identity)| (id.clone(), identity.clone())),
                                );
                            }
                            if representative.composed {
                                composed_owners.insert((family.to_owned(), id.clone()));
                            }
                            replacements.extend(representative.replacements.iter().map(
                                |(id, replacement)| {
                                    ((family.to_owned(), id.clone()), replacement.clone())
                                },
                            ));
                        }
                    }
                }
            }
            if failed {
                return Vec::new();
            }
            composition::rewrite_relations(
                selected.into_iter().enumerate().collect(),
                &replacements,
                &composed_owners,
                &origin_identities,
            )
            .into_iter()
            .map(|(_, relation)| relation)
            .collect()
        })
        .collect()
}

/// A request-time lookup question. Unscoped reads keep the rows of every owner
/// that answered and record an open JVM part; a scoped read that is open as a
/// whole contributes nothing.
fn lookup_question<T: Default>(
    open: &LookupOpen,
    reads: &RowCompositionReads<'_>,
    statement: &str,
    key: impl std::fmt::Debug,
    answer: Result<T, CatalogError>,
) -> T {
    let answer = semantic_catalog_question(statement, key, answer);
    open.note(reads.open_part());
    answer.unwrap_or_else(|family_open| {
        open.note(Some(family_open));
        T::default()
    })
}

/// Groups looked up for one step of a request, kept until it ends so that a
/// cache eviction in between cannot make the step compose one again.
#[derive(Default)]
struct HeldGroups(HashMap<CompositionGroupKey, GroupLookup>);

impl HeldGroups {
    /// Look up the groups of `keys` not held yet, in chunks.
    fn fill(&mut self, overlay: &RowOverlay, keys: impl IntoIterator<Item = CompositionGroupKey>) {
        let mut missing = keys
            .into_iter()
            .filter(|key| !self.0.contains_key(key))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        for chunk in missing.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
            // This lookup's own aggregate is unused: each answer keeps its part.
            let scratch = LookupOpen::default();
            for (key, lookup) in chunk.iter().zip(overlay.lookup_groups(chunk, &scratch)) {
                self.0.insert(key.clone(), lookup);
            }
        }
    }
}

/// What discovery found for one raw record ID: the keys of the groups holding
/// it, symbols whose owner is missing, and the open part its lookup saw.
pub(super) struct IdDiscovery {
    keys: Vec<CompositionGroupKey>,
    orphans: Vec<Arc<SemanticModelSymbol>>,
    open: Option<FamilyOpen>,
}

/// A composed group held by its asker: retained by the cache or owned by the
/// request. Cloning shares the group.
pub(super) type HeldGroup = crate::retention_budget::BudgetedValue<composition::ComposedGroup>;

/// One key's group lookup: its group, if composed, and the open part it saw.
#[derive(Clone)]
pub(super) struct GroupLookup {
    group: Option<HeldGroup>,
    open: Option<FamilyOpen>,
}

/// The rows of one request-time lookup and the open part it saw, if any.
pub(super) type LookupRows = (Vec<Arc<SemanticModelSymbol>>, Option<FamilyOpen>);

#[derive(Debug)]
pub(super) struct OwnerQualification {
    pub(super) addresses: HashSet<(String, i64, i64)>,
    pub(super) guarded: bool,
    pub(super) name: String,
}

pub(super) fn reduce_owner_qualification_row(
    qualifications: &mut HashMap<(String, String), OwnerQualification>,
    row: &crate::analyzer::store::model_catalog::OwnedCatalogRow<'_>,
) -> rusqlite::Result<()> {
    let id: String = row.get("record_id")?;
    let language: String = row.get("language")?;
    let address = (
        row.get("source_db")?,
        row.get("shard_key")?,
        row.get("record_key")?,
    );
    let guarded: bool = row.get("guarded")?;
    let name: String = row.get("owner_name")?;
    let group = qualifications
        .entry((
            brokk_bifrost_core::analyzer::model::semantic_pack_realm(&language).to_owned(),
            id,
        ))
        .or_insert_with(|| OwnerQualification {
            addresses: HashSet::default(),
            guarded: false,
            name,
        });
    group.addresses.insert(address);
    group.guarded |= guarded;
    Ok(())
}

fn attach_search_spelling(
    group: &mut SearchGroup,
    owner: Option<&str>,
    qualified: &str,
    spelling: &str,
) {
    group.standalone.insert(spelling.to_owned());
    group.standalone.insert(qualified.to_owned());
    if let Some(owner) = owner {
        group.standalone.insert(format!("{owner}.{spelling}"));
        group.members.insert(spelling.to_owned());
    }
}

/// Groups composed together per projection. A chunk's records are the working
/// set held while it composes, so this bounds memory; each chunk costs a few
/// set statements, so it also bounds the statement count to a few per chunk.
const SEARCH_COMPOSE_CHUNK_GROUPS: usize = 256;

fn debug_assert_search_spellings(candidates: &SearchGroup, symbols: &[SemanticModelSymbol]) {
    #[cfg(debug_assertions)]
    {
        let spellings = candidates.spellings().collect::<HashSet<_>>();
        debug_assert!(
            symbols.iter().all(|symbol| std::iter::once(&symbol.name)
                .chain(std::iter::once(&symbol.qualified_name))
                .chain(&symbol.aliases)
                .all(|spelling| spellings.contains(spelling.as_str()))),
            "incomplete search spellings for {:?}: {:?}",
            candidates.key,
            symbols
        );
    }
    #[cfg(not(debug_assertions))]
    let _ = (candidates, symbols);
}

#[derive(Debug, Clone)]
pub(super) struct RowOverlay {
    pub(super) active: Arc<ResolvedActiveSemanticModels>,
    pub(super) cache: Option<StoreCacheBudget>,
    pub(super) build_identity: SemanticOverlayBuildIdentity,
    anchors: locations::SourceLocationInputs,
    generated: Vec<SemanticModelSymbol>,
    generated_relations: Vec<SemanticModelRelation>,
}

/// Full backing identity: canonical scope plus frozen build and reader binding.
pub(super) struct EffectiveSearchInputs {
    scope: composition::CompositionScopeIdentity,
    build: crate::analyzer::store::semantic_composition::SemanticOverlayBuildIdentity,
    binding: Option<crate::analyzer::store::model_catalog::ReaderBinding>,
}

impl EffectiveSearchInputs {
    pub(super) fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(serde_json::to_vec(&self.scope).expect("scope identity serializes"));
        digest.update(self.build.0);
        digest.update([u8::from(self.binding.is_some())]);
        if let Some(binding) = self.binding {
            digest.update(binding.0);
        }
        digest.finalize().into()
    }
}

impl RowOverlay {
    /// Every row-path access, including a fresh child capture, observes this set.
    pub(super) fn active(&self) -> &Arc<ResolvedActiveSemanticModels> {
        crate::analyzer::i_analyzer::record_request_row_selection_read(
            crate::analyzer::ReadKey::Models(crate::analyzer::semantic::ids::StableDigest::sha256(
                self.active.active_model_set_hash(),
            )),
        );
        &self.active
    }

    /// The declared type names of `language`, read scoped to it. A JVM-family
    /// language is answered by its owner, so it is Open when a real request
    /// owner cannot answer; any other language's rows all belong to the
    /// activation owner, and reading them never binds a request owner.
    pub(super) fn declaration_type_names(
        &self,
        language: &str,
    ) -> Result<Vec<(String, String)>, SemanticModelOverlayBuildError> {
        let records = if brokk_bifrost_core::analyzer::model::JVM_SEMANTIC_PACK_LANGUAGES
            .contains(&language)
        {
            let reads =
                RowCompositionReads::new(self.active(), &self.generated, &self.generated_relations);
            selected_question(
                "ALL_TYPES",
                "active-set",
                reads
                    .for_language(language)
                    .types(questions::ALL_TYPES, &[]),
            )?
        } else {
            let reads = RowCompositionReads::activation_only(
                self.active(),
                &self.generated,
                &self.generated_relations,
            );
            selected_question(
                "ALL_TYPES",
                "active-set",
                reads.types(questions::ALL_TYPES, &[]),
            )?
        };
        Ok(records
            .into_iter()
            .filter(|r| r.record.type_kind != crate::analyzer::semantic_model::TypeKind::Module)
            .map(|r| (r.shard.manifest.language.clone(), r.record.name.clone()))
            .collect())
    }

    /// These are activation-lifetime originals, not evictable cache entries.
    /// Estimate each fact exactly as the eager overlay does, and include spare
    /// vector capacity and the anchor map's owned keys and values.
    pub(super) fn retained_owned_input_bytes(&self) -> [usize; 3] {
        [
            self.anchors.retained_bytes_lower_bound(),
            std::mem::size_of_val(&self.generated)
                .saturating_add(
                    (self.generated.capacity() - self.generated.len())
                        .saturating_mul(std::mem::size_of::<SemanticModelSymbol>()),
                )
                .saturating_add(
                    self.generated
                        .iter()
                        .map(symbol_retained_bytes)
                        .fold(0usize, usize::saturating_add),
                ),
            std::mem::size_of_val(&self.generated_relations)
                .saturating_add(
                    (self.generated_relations.capacity() - self.generated_relations.len())
                        .saturating_mul(std::mem::size_of::<SemanticModelRelation>()),
                )
                .saturating_add(
                    self.generated_relations
                        .iter()
                        .map(relation_retained_bytes)
                        .fold(0usize, usize::saturating_add),
                ),
        ]
    }

    pub(super) fn new(
        analyzer: &dyn IAnalyzer,
        active: &Arc<ResolvedActiveSemanticModels>,
        generated: Vec<SemanticModelSymbol>,
        generated_relations: Vec<SemanticModelRelation>,
        cache: Option<StoreCacheBudget>,
        eager_symbols: &[SemanticModelSymbol],
    ) -> Self {
        let mut result = Self {
            active: Arc::clone(active),
            cache,
            build_identity: SemanticOverlayBuildIdentity([0; 32]),
            anchors: locations::SourceLocationInputs::default(),
            generated,
            generated_relations,
        };
        // Construction can itself run inside an otherwise empty capture.
        result.active();
        let authored = if active.shards.iter().any(|shard| shard.decoded.is_none()) {
            let reads = RowCompositionReads::activation_only(
                active,
                &result.generated,
                &result.generated_relations,
            );
            activation_owner_question(
                &reads,
                "SOURCE_TYPES/SOURCE_MEMBERS",
                active.active_model_set_hash(),
                reads.activation_source_anchors(analyzer),
            )
        } else {
            locations::SourceAnchors::default()
        };
        result.anchors = locations::SourceLocationInputs::new(authored, active, eager_symbols);
        let mut digest =
            crate::analyzer::semantic::LengthDelimitedDigest::new(b"semantic-overlay-build-v1");
        digest.push(active.active_model_set_hash().as_bytes());
        // The semantic active-set digest deliberately ignores presentation
        // provenance. Cached groups retain it, including the explanation
        // reason and the selected publication's source ID and order.
        for shard in &active.shards {
            digest.push(shard.manifest.content_sha256.as_bytes());
            digest.push(
                format!(
                    "{:?}",
                    (
                        &shard.descriptor,
                        &shard.selectors,
                        shard.row_store,
                        shard.has_callable_values,
                        shard.source_kind,
                        &shard.source_id,
                        &shard.matched_evidence,
                        &shard.matching_evidence,
                        shard.evidence_rank,
                        shard.source_rank,
                        shard.approximation
                    )
                )
                .as_bytes(),
            );
            digest.push(format!("{:?}", activated_record_provenance(active, shard, "")).as_bytes());
        }

        // Symbol Debug preserves the existing input projection, including scope,
        // signature and ordering fields absent from the public serialized shape.
        // Code-derived callable groups are omitted. This key is local to this
        // executable and never a persisted format.
        digest.push(format!("{:?}", result.generated).as_bytes());
        digest.push(format!("{:?}", result.generated_relations).as_bytes());
        digest.push(result.anchors.digest().as_bytes());
        result.build_identity = SemanticOverlayBuildIdentity(*digest.finish().as_bytes());
        result
    }

    /// A group composed through its language's owner. A group whose read is
    /// open as a whole contributes nothing; a partial one is not cached.
    /// A composed group depends only on its key: `compose_group` scopes its
    /// reads to the key's language whatever scope the lookup that reached it
    /// had, so scoped and unscoped lookups share the cached group. The cached
    /// group is shared, not copied: a caller that changes one clones it itself.
    fn lookup_group(&self, key: &CompositionGroupKey, open: &LookupOpen) -> Option<HeldGroup> {
        self.lookup_groups(std::slice::from_ref(key), open)
            .pop()
            .expect("one key, one answer")
            .group
    }

    /// The groups of `keys`, as if `lookup_group` ran on each in order with the
    /// same `open`, but the missing ones composed together: one projection per
    /// language per chunk of `SEARCH_COMPOSE_CHUNK_GROUPS` groups. A group's
    /// content and its retained size depend only on its key, so composing it in
    /// a chunk or alone gives the same group. The answers hold their groups, so
    /// the cache may evict one without the caller composing it again.
    fn lookup_groups(&self, keys: &[CompositionGroupKey], open: &LookupOpen) -> Vec<GroupLookup> {
        enum Probe {
            Open(FamilyOpen),
            Hit(HeldGroup),
            Miss(ComposedGroupCacheKey),
        }
        struct Language<'a> {
            anchors: locations::SourceAnchorView<'a>,
            open: Option<FamilyOpen>,
            retention: Option<Option<crate::analyzer::store::model_catalog::ReaderBinding>>,
        }
        let mut languages: HashMap<&str, Language<'_>> = HashMap::default();
        let mut probes = Vec::with_capacity(keys.len());
        for key in keys {
            let language = languages.entry(key.language.as_str()).or_insert_with(|| {
                // Only this language's own anchor part decides here: an open
                // part seen earlier in the same lookup must not drop a group
                // that reads none.
                let anchor_open = LookupOpen::default();
                let anchors = self.anchor_view_scoped(&anchor_open, Some(&key.language));
                Language {
                    anchors,
                    open: anchor_open.get(),
                    retention: self.jvm_retention(Some(&key.language)),
                }
            });
            if let Some(part) = language.open {
                probes.push(Probe::Open(part));
                continue;
            }
            // An open JVM owner has no retention binding, so its key would equal
            // the key of a request without a request source; never share it.
            let cache = self.cache.as_ref().filter(|_| language.retention.is_some());
            let cache_key = ComposedGroupCacheKey {
                // An open owner never caches. A None binding means no request
                // source: the reads are activation-owned and covered by `build`.
                // Otherwise the binding hashes this request's own selection
                // answer, so two selections that cannot be replayed share an
                // entry only when their answers are equal.
                jvm_binding: language.retention.flatten(),
                build: self.build_identity,
                selection_digest: None,
                group: key.clone(),
            };
            match cache.and_then(|cache| cache.composed_group(&cache_key)) {
                Some(hit) => probes.push(Probe::Hit(
                    crate::retention_budget::BudgetedValue::Retained(hit),
                )),
                None => probes.push(Probe::Miss(cache_key)),
            }
        }
        // The loader has no cancellation branch: it either returns a complete
        // group or an error. Callers check cancellation before using this answer.
        let reads = self.reads();
        let mut composed: Vec<Option<Result<composition::ComposedGroup, FamilyOpen>>> =
            (0..keys.len()).map(|_| None).collect();
        let mut missing = HashMap::<&str, Vec<usize>>::default();
        for (position, probe) in probes.iter().enumerate() {
            if matches!(probe, Probe::Miss(_)) {
                missing
                    .entry(keys[position].language.as_str())
                    .or_default()
                    .push(position);
            }
        }
        let mut missing = missing.into_iter().collect::<Vec<_>>();
        missing.sort_unstable();
        for (language, positions) in missing {
            for chunk in positions.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
                let chunk_keys = chunk.iter().map(|&p| keys[p].clone()).collect::<Vec<_>>();
                let anchors = &languages[language].anchors;
                match semantic_catalog_question(
                    "GROUP_OWNER_IDS/MEMBER_IDS_BY_OWNERS/OVERLAY_RELATIONS_FROM",
                    &chunk_keys,
                    reads.compose_groups(anchors, language, &chunk_keys),
                ) {
                    Ok(groups) => {
                        for (&position, group) in chunk.iter().zip(groups) {
                            composed[position] = Some(Ok(group));
                        }
                    }
                    Err(family_open) => {
                        for &position in chunk {
                            composed[position] = Some(Err(family_open));
                        }
                    }
                }
            }
        }
        let reads_open = reads.open_part();
        keys.iter()
            .zip(probes)
            .zip(composed)
            .map(|((key, probe), composed)| match probe {
                Probe::Open(part) => {
                    open.note(Some(part));
                    GroupLookup {
                        group: None,
                        open: Some(part),
                    }
                }
                Probe::Hit(group) => GroupLookup {
                    group: Some(group),
                    open: None,
                },
                Probe::Miss(cache_key) => match composed.expect("every missing key composes") {
                    Err(part) => {
                        open.note(Some(part));
                        GroupLookup {
                            group: None,
                            open: Some(part),
                        }
                    }
                    Ok(group) => {
                        open.note(reads_open);
                        let cache = self
                            .cache
                            .as_ref()
                            .filter(|_| languages[key.language.as_str()].retention.is_some());
                        let group = match cache {
                            Some(cache) if reads_open.is_none() && open.get().is_none() => {
                                cache.insert_composed_group(cache_key, group)
                            }
                            _ => crate::retention_budget::BudgetedValue::request_only(group),
                        };
                        GroupLookup {
                            group: Some(group),
                            open: reads_open,
                        }
                    }
                },
            })
            .collect()
    }

    fn selected_reads<'a>(
        &'a self,
        language: &'a str,
        selection: &'a ModelProviderSelection,
        defining_owner: Option<&'a SemanticModelProvenance>,
        cancellation: &'a crate::CancellationToken,
    ) -> Box<dyn composition::GroupInput + 'a> {
        if crate::analyzer::Language::from_config_label(language)
            .and_then(brokk_bifrost_semantic::analyzer::semantic::languages::language_knowledge)
            .is_some_and(|knowledge| knowledge.models_compose_from_catalog_rows())
        {
            let mut reads = self.reads();
            reads.cancellation = Some(cancellation.clone());
            reads.selection = Some(selection);
            reads.defining_owner = defining_owner;
            Box::new(reads.for_language(language))
        } else {
            Box::new(composition::SelectedDecodedReads {
                language,
                active: self.active(),
                selection,
                defining_owner,
                generated: &self.generated,
                generated_relations: &self.generated_relations,
                cancellation,
            })
        }
    }

    pub(super) fn selected_symbols(
        &self,
        symbol: &ModelSymbolRef,
        selection: &ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Vec<SemanticModelSymbol>, SemanticModelOverlayBuildError> {
        let Some(shard) = self.active().shards.iter().find(|shard| {
            shard.manifest.pack_id == symbol.provider.pack_id
                && shard.manifest.version == symbol.provider.pack_version
                && shard.manifest.semantic_sha256 == symbol.provider.pack_digest
        }) else {
            return Ok(Vec::new());
        };
        Ok(self
            .selected_groups(
                &shard.manifest.language,
                &TypeRef::Declared {
                    id: symbol.symbol_id.clone(),
                    arguments: Vec::new(),
                    nullable: false,
                },
                selection,
                cancellation,
            )?
            .into_iter()
            .flatten()
            .collect())
    }

    /// Read one spelling through its exact selected provider before ordinary
    /// cross-pack composition can suppress colliding package versions.
    pub(super) fn selected_rust_symbols_named(
        &self,
        path: &str,
        provider: &ModelProvider,
        cancellation: Option<&crate::CancellationToken>,
    ) -> Result<Vec<SemanticModelSymbol>, SemanticModelOverlayBuildError> {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        let open = LookupOpen::default();
        let rust_realm = Some(brokk_bifrost_core::analyzer::model::semantic_pack_realm(
            "rust",
        ));
        let mut ids = self.candidate_ids(
            &open,
            "TYPE_SPELLINGS",
            questions::TYPE_SPELLINGS,
            path,
            named_params! { ":name": path },
            rust_realm,
        );
        if let Some((owner, member)) = selected_rust_member_path(path) {
            ids.extend(self.candidate_ids(
                &open,
                "MEMBERS_QUALIFIED",
                questions::MEMBERS_QUALIFIED,
                path,
                named_params! { ":owner_name": owner, ":member": member },
                rust_realm,
            ));
        }
        ids.extend(self.candidate_ids(
            &open,
            "MEMBER_ALIASES",
            questions::MEMBER_ALIASES,
            path,
            named_params! { ":name": path },
            rust_realm,
        ));
        if open.get().is_some() {
            return Err(open.get().expect("checked open").into());
        }
        ids.sort_unstable();
        ids.dedup();
        let selection = ModelProviderSelection::new([provider.clone()]);
        let default_cancellation = crate::CancellationToken::default();
        let cancellation = cancellation.unwrap_or(&default_cancellation);
        let mut symbols = Vec::new();
        for id in ids {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            symbols.extend(self.selected_symbols(
                &ModelSymbolRef {
                    provider: provider.clone(),
                    symbol_id: id,
                },
                &selection,
                cancellation,
            )?);
        }
        symbols.retain(|symbol| {
            symbol.qualified_name == path || symbol.aliases.iter().any(|alias| alias == path)
        });
        symbols.sort_by_cached_key(composition::owned_symbol_source_key);
        symbols.dedup_by(|a, b| a == b);
        Ok(symbols)
    }

    /// One selected alias group is the cache unit, including its defining facets.
    pub(super) fn selected_groups(
        &self,
        language: &str,
        reference: &TypeRef,
        selection: &ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Vec<Vec<SemanticModelSymbol>>, SemanticModelOverlayBuildError> {
        let anchor_open = LookupOpen::default();
        let anchors = self.anchor_view_scoped(&anchor_open, Some(language));
        if let Some(open) = anchor_open.get() {
            return Err(open.into());
        }
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        let retention = self.jvm_retention(Some(language));
        let cache = self.cache.as_ref().filter(|_| retention.is_some());
        let input = self.selected_reads(language, selection, None, cancellation);
        let reads = composition::GroupProjection::new(input.as_ref());
        let selected_lookup = match reference {
            TypeRef::Declared { id, .. } => CompositionLookup::SelectedId {
                language: language.to_owned(),
                id: id.clone(),
            },
            TypeRef::Named { name, .. } => CompositionLookup::SelectedName {
                language: language.to_owned(),
                name: name.clone(),
            },
            _ => return Ok(Vec::new()),
        };
        let lookup = CompositionDiscoveryCacheKey {
            // As in `lookup_groups`: an open owner never caches, and a binding
            // hashes this request's own selection answer.
            jvm_binding: retention.flatten(),
            build: self.build_identity,
            selection_digest: Some(selection.digest()),
            realm: None,
            lookup: selected_lookup,
        };
        let keys = cache.and_then(|cache| cache.composition_discovery(&lookup));
        let keys = match keys {
            Some(keys) => crate::retention_budget::BudgetedValue::Retained(keys),
            None => {
                let symbols = match reference {
                    TypeRef::Declared { id, .. } => selected_question(
                        "TYPES_BY_ID/MEMBERS_BY_ID",
                        reference,
                        reads.symbols_with_id(&anchors, id),
                    )?,
                    TypeRef::Named { name, .. } => {
                        let records = selected_question(
                            "TYPES_BY_NAME",
                            reference,
                            input.all_types_named(name),
                        )?;
                        let mut symbols = Vec::new();
                        for record in records {
                            check_selected_cancellation(cancellation)?;
                            symbols.extend(selected_question(
                                "TYPES_BY_ID",
                                &record.record.id,
                                reads.owner_symbols(&anchors, &record.record.id),
                            )?);
                        }
                        symbols
                    }
                    _ => unreachable!("selected group references are names or declaration IDs"),
                };
                let mut keys = Vec::new();
                for symbol in symbols.into_iter().filter(|s| s.language == language) {
                    check_selected_cancellation(cancellation)?;
                    let owners = if let Some(owner) = symbol.owner_id {
                        selected_question(
                            "TYPES_BY_ID",
                            &owner,
                            reads.owner_symbols(&anchors, &owner),
                        )?
                    } else {
                        vec![symbol]
                    };
                    for owner in owners {
                        check_selected_cancellation(cancellation)?;
                        let seed = CompositionGroupKey {
                            language: owner.language,
                            module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                            identity: owner.qualified_name,
                        };
                        let owners = selected_question(
                            "GROUP_OWNERS",
                            &seed,
                            reads.group_owners(&anchors, &seed),
                        )?;
                        keys.push(composition::group_key(&owners.iter().collect::<Vec<_>>()));
                    }
                }
                keys.sort_unstable();
                keys.dedup();
                if cancellation.is_cancelled() {
                    return Err(SemanticModelOverlayBuildError::Cancelled);
                }
                match cache {
                    Some(cache) => cache.insert_composition_discovery(lookup, keys),
                    None => crate::retention_budget::BudgetedValue::request_only(keys),
                }
            }
        };
        let mut symbols = Vec::new();
        for key in keys.iter() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let cache_key = ComposedGroupCacheKey {
                jvm_binding: self.retention_binding(Some(&key.language)),
                build: self.build_identity,
                selection_digest: Some(selection.digest()),
                group: key.clone(),
            };
            let cached = cache.and_then(|cache| cache.composed_group(&cache_key));
            let group = match cached {
                Some(group) => crate::retention_budget::BudgetedValue::Retained(group),
                None => {
                    let owners =
                        selected_question("GROUP_OWNERS", key, reads.group_owners(&anchors, key))?;
                    let mut facets = HashSet::default();
                    let mut groups = Vec::new();
                    // Partition before the shared kernel: both representative and
                    // endpoint reads see at most one extracted defining provider.
                    // Selected curated contributors remain available to every facet.
                    let has_extracted = owners.iter().any(|s| s.provenance.extraction.is_some());
                    for owner in owners
                        .iter()
                        .filter(|s| !has_extracted || s.provenance.extraction.is_some())
                    {
                        let provider = ModelProvider::from(&owner.provenance);
                        let input = self.selected_reads(
                            language,
                            selection,
                            Some(&owner.provenance),
                            cancellation,
                        );
                        let facet_reads = composition::GroupProjection::new(input.as_ref());
                        let seed = CompositionGroupKey {
                            language: owner.language.clone(),
                            module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                            identity: owner.qualified_name.clone(),
                        };
                        let facet_owners = selected_question(
                            "GROUP_OWNERS",
                            &seed,
                            facet_reads.group_owners(&anchors, &seed),
                        )?;
                        let facet_key =
                            composition::group_key(&facet_owners.iter().collect::<Vec<_>>());
                        if facets.insert((provider.clone(), facet_key.clone())) {
                            groups.push(selected_question(
                                "SELECTED_GROUP",
                                &facet_key,
                                facet_reads.compose_group(&anchors, &facet_key),
                            )?);
                        }
                    }
                    let mut groups = groups.into_iter();
                    let mut group = groups.next().expect("discovered group has an owner");
                    for other in groups {
                        check_selected_cancellation(cancellation)?;
                        let offset = group.symbols.len();
                        group
                            .source_indices
                            .extend(other.source_indices.into_iter().map(|i| i + offset));
                        group.symbols.extend(other.symbols);
                        group.relations.extend(other.relations);
                        group.diagnostics.extend(other.diagnostics);
                    }
                    self.augment_selected_group(
                        &key.language,
                        &mut group.symbols,
                        selection,
                        cancellation,
                    )?;
                    check_selected_cancellation(cancellation)?;
                    match cache {
                        Some(cache) => cache.insert_composed_group(cache_key, group),
                        None => crate::retention_budget::BudgetedValue::request_only(group),
                    }
                }
            };
            symbols.push(group.symbols.clone());
        }
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        Ok(symbols)
    }

    fn augment_selected_group(
        &self,
        language: &str,
        symbols: &mut Vec<SemanticModelSymbol>,
        selection: &ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<(), SemanticModelOverlayBuildError> {
        let anchor_open = LookupOpen::default();
        let anchors = self.anchor_view_scoped(&anchor_open, Some(language));
        if let Some(open) = anchor_open.get() {
            return Err(open.into());
        }
        let hook =
            brokk_bifrost_semantic::analyzer::semantic_model::overlay::model_composition_language(
                language,
            );
        let original = symbols.len();
        let input = self.selected_reads(language, selection, None, cancellation);
        let reads = composition::GroupProjection::new(input.as_ref());
        let mut seen = symbols
            .iter()
            .map(|s| (ModelProvider::from(&s.provenance), s.id.clone()))
            .collect::<HashSet<_>>();
        let mut cursor = 0;
        // Materialize only the structured embedding inputs of this request.
        // The shared Go algorithm below owns provider-first resolution, shadowing,
        // DeclaringSite matching, promotion marks and members_state.
        while cursor < symbols.len() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let dependencies = hook
                .group_dependencies(&symbols[cursor])
                .cloned()
                .collect::<Vec<_>>();
            cursor += 1;
            for dependency in dependencies {
                if cancellation.is_cancelled() {
                    return Err(SemanticModelOverlayBuildError::Cancelled);
                }
                let mut reference = &dependency;
                while let TypeRef::Pointer { element } = reference {
                    reference = element;
                }
                let targets = match reference {
                    TypeRef::Declared { id, .. } => selected_question(
                        "GO_EMBEDDED_OWNER_ID",
                        id,
                        reads.owner_symbols(&anchors, id),
                    )?,
                    TypeRef::Named { name, .. } => {
                        let records = selected_question(
                            "GO_EMBEDDED_OWNER_NAME",
                            name,
                            input.all_types_named(name),
                        )?;
                        let mut targets = Vec::new();
                        for record in records {
                            check_selected_cancellation(cancellation)?;
                            targets.extend(selected_question(
                                "GO_EMBEDDED_OWNER_ID",
                                &record.record.id,
                                reads.owner_symbols(&anchors, &record.record.id),
                            )?);
                        }
                        targets
                    }
                    _ => Vec::new(),
                };
                for target in targets {
                    let key = CompositionGroupKey {
                        language: target.language.clone(),
                        module_namespace: target.kind == SemanticModelSymbolKind::Module,
                        identity: target.qualified_name.clone(),
                    };
                    let group = selected_question(
                        "GO_EMBEDDED_GROUP",
                        &key,
                        reads.group_symbols(&anchors, &key),
                    )?;
                    for symbol in group {
                        if seen.insert((ModelProvider::from(&symbol.provenance), symbol.id.clone()))
                        {
                            symbols.push(symbol);
                        }
                    }
                }
            }
        }
        hook.augment_group(symbols, &mut Vec::new(), cancellation)?;
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        // The embedded closure dies here; only the requested alias group is cached.
        symbols.truncate(original);
        // Do not retain the embedding closure's allocation in a group cache entry.
        symbols.shrink_to_fit();
        Ok(())
    }

    fn discovered(
        &self,
        lookup: &CompositionLookup,
        realm: Option<&str>,
    ) -> Option<crate::retention_budget::Retained<Vec<CompositionGroupKey>>> {
        // A scoped lookup reads only its family, so its JVM state is its
        // realm's: a Python lookup never binds the JVM owner to cache.
        let binding = self.jvm_retention(realm.or(lookup_language(lookup)))?;
        self.cache.as_ref().and_then(|cache| {
            cache.composition_discovery(&CompositionDiscoveryCacheKey {
                jvm_binding: binding,
                build: self.build_identity,
                selection_digest: None,
                realm: realm.map(str::to_owned),
                lookup: lookup.clone(),
            })
        })
    }
    fn retain_discovery(
        &self,
        lookup: CompositionLookup,
        mut groups: Vec<CompositionGroupKey>,
        realm: Option<&str>,
    ) {
        let Some(binding) = self.jvm_retention(realm.or(lookup_language(&lookup))) else {
            return;
        };
        groups.sort_unstable();
        groups.dedup();
        if let Some(cache) = &self.cache {
            drop(cache.insert_composition_discovery(
                CompositionDiscoveryCacheKey {
                    jvm_binding: binding,
                    build: self.build_identity,
                    selection_digest: None,
                    realm: realm.map(str::to_owned),
                    lookup,
                },
                groups,
            ));
        }
    }
    fn retention_binding(
        &self,
        language: Option<&str>,
    ) -> Option<crate::analyzer::store::model_catalog::ReaderBinding> {
        if language.is_some_and(|language| {
            brokk_bifrost_core::analyzer::model::semantic_pack_realm(language) != "jvm"
        }) {
            return None;
        }
        self.active().question_row_owners(None).jvm_binding
    }

    /// The JVM owner's retention state for a question scoped to `language`
    /// (None: any language), read once: `None` when the JVM part is open, so
    /// nothing is cached, otherwise the binding that keys retention. A question
    /// scoped to a non-JVM language never consults the JVM request owner, so
    /// it is never open for it and has no binding; binding the owner there
    /// would record a JVM read the question never makes.
    fn jvm_retention(
        &self,
        language: Option<&str>,
    ) -> Option<Option<crate::analyzer::store::model_catalog::ReaderBinding>> {
        if language.is_some_and(|language| {
            brokk_bifrost_core::analyzer::model::semantic_pack_realm(language) != "jvm"
        }) {
            return Some(None);
        }
        let owners = self.active().question_row_owners(None);
        owners.jvm_open.is_none().then_some(owners.jvm_binding)
    }

    /// Derive on every access; no alias retains a budgeted backing.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn effective_search_inputs(
        &self,
        key: &crate::analyzer::store::semantic_composition::SearchCandidateKey,
    ) -> EffectiveSearchInputs {
        // Binding discovery records its reads for this asking request, even on hits.
        self.active().question_row_owners(key.realm.as_deref());
        EffectiveSearchInputs {
            scope: self
                .reads_for_realm(key.realm.as_deref())
                .for_search()
                .expect("test search selection")
                .canonical_identity(),
            build: key.build,
            binding: key.jvm_binding,
        }
    }

    #[cfg(test)]
    pub(super) fn backing_key_fills(
        owner: &crate::analyzer::store::model_catalog::RequestRowReader,
    ) -> usize {
        backing_key_memo(owner).lock().unwrap().fills
    }

    pub(super) fn memoized_search_digest(
        &self,
        owner: &crate::analyzer::store::model_catalog::RequestRowReader,
        realm: Option<&str>,
    ) -> Option<[u8; 32]> {
        self.memoized_search_digest_with_scope(owner, realm, || {
            Some(
                self.search_reads_for_realm(realm, None)?
                    .canonical_identity(),
            )
        })
    }

    fn memoized_search_digest_with_scope(
        &self,
        owner: &crate::analyzer::store::model_catalog::RequestRowReader,
        realm: Option<&str>,
        scope: impl FnOnce() -> Option<composition::CompositionScopeIdentity>,
    ) -> Option<[u8; 32]> {
        let mut memo = backing_key_memo(owner)
            .lock()
            .expect("backing key memo poisoned");
        let key = (realm.map(str::to_owned), self.build_identity);
        if let Some((digest, receipt)) = memo.entries.get(&key) {
            receipt.replay();
            return Some(*digest);
        }
        #[cfg(test)]
        {
            memo.fills += 1;
        }
        let (digest, receipt) = crate::analyzer::common::capture_current_query_cache_build(|| {
            self.active().question_row_owners(realm);
            Some(
                EffectiveSearchInputs {
                    scope: scope()?,
                    build: self.build_identity,
                    binding: Some(owner.binding),
                }
                .digest(),
            )
        });
        let digest = digest?;
        if receipt.request_memo_admissible() {
            memo.entries.insert(key, (digest, receipt));
        }
        Some(digest)
    }

    fn search_reads_for_realm(
        &self,
        realm: Option<&str>,
        cancellation: Option<&crate::CancellationToken>,
    ) -> Option<RowCompositionReads<'_>> {
        let mut reads = self.reads_for_realm(realm);
        if let Some(cancellation) = cancellation {
            reads.cancellation = Some(cancellation.clone());
        }
        semantic_catalog_question(
            "search fill relevance",
            self.active().active_model_set_hash(),
            reads.for_search(),
        )
        .ok()
    }

    fn reads_for_realm<'a>(&'a self, realm: Option<&str>) -> RowCompositionReads<'a> {
        let reads = self.reads().with_anchors(&self.anchors);
        match realm {
            Some(realm) => reads.for_realm(realm),
            None => reads,
        }
    }

    fn reads(&self) -> RowCompositionReads<'_> {
        RowCompositionReads::new(self.active(), &self.generated, &self.generated_relations)
    }

    fn anchor_view(&self, open: &LookupOpen) -> locations::SourceAnchorView<'_> {
        self.anchor_view_scoped(open, None)
    }

    fn anchor_view_scoped(
        &self,
        open: &LookupOpen,
        language: Option<&str>,
    ) -> locations::SourceAnchorView<'_> {
        self.anchor_view_with_reads(
            open,
            &self.reads_for_realm(
                language.map(brokk_bifrost_core::analyzer::model::semantic_pack_realm),
            ),
        )
    }

    fn anchor_view_with_reads<'a>(
        &self,
        open: &LookupOpen,
        reads: &RowCompositionReads<'a>,
    ) -> locations::SourceAnchorView<'a> {
        let request = if reads.includes_request_owner()
            && self
                .active()
                .shards
                .iter()
                .any(|shard| shard.decoded.is_none() && shard.request_owned())
        {
            let owners = self.active().question_row_owners(None);
            let key = owners.jvm_binding.map(|binding| RequestSourceAnchorsKey {
                build: self.build_identity,
                binding,
            });
            if let Some(value) = self.active().request_source().and_then(|source| {
                let owner = source.jvm_reader(self.active()).ok()?;
                let cache = &self.cache.as_ref()?.composed_search_inputs;
                [None, Some("jvm")].into_iter().find_map(|realm| {
                    cache.get_ready(
                        &self.memoized_search_digest(&owner, realm)?,
                        &crate::CancellationToken::new(),
                    )
                })
            }) {
                value
                    .receipt
                    .as_any()
                    .downcast_ref::<crate::analyzer::common::QueryCacheBuildReceipt>()
                    .expect("search input receipt")
                    .replay();
                return locations::SourceAnchorView {
                    activation: reads.anchors().expect("overlay selection carries anchors"),
                    request: Some(locations::RequestAnchors::Search(value)),
                };
            }
            if let Some(hit) = key.as_ref().and_then(|key| {
                self.cache
                    .as_ref()
                    .and_then(|cache| cache.request_source_anchors(key))
            }) {
                Some(crate::retention_budget::BudgetedValue::Retained(hit))
            } else {
                let answer = semantic_catalog_question(
                    "SOURCE_TYPES/SOURCE_MEMBERS",
                    self.build_identity,
                    reads.request_source_anchors(),
                );
                match answer {
                    Ok(anchors) => {
                        debug_assert!(!self.anchors.overlaps(&anchors));
                        Some(match (key, &self.cache) {
                            (Some(key), Some(cache)) => {
                                cache.insert_request_source_anchors(key, anchors)
                            }
                            _ => crate::retention_budget::BudgetedValue::request_only(anchors),
                        })
                    }
                    Err(family_open) => {
                        open.note(Some(family_open));
                        None
                    }
                }
            }
        } else {
            None
        };
        locations::SourceAnchorView {
            activation: reads.anchors().expect("overlay selection carries anchors"),
            request: request.map(locations::RequestAnchors::Standalone),
        }
    }

    pub(super) fn row_language(&self, language: &str) -> bool {
        self.active()
            .shards
            .iter()
            .any(|shard| shard.decoded.is_none() && shard.manifest.language == language)
    }

    pub(super) fn mark_identity_conflicts(&self, symbols: &mut [SemanticModelSymbol]) {
        let anchors = locations::SourceAnchorView {
            activation: &self.anchors,
            request: None,
        };
        let reads = RowCompositionReads::activation_only(
            self.active(),
            &self.generated,
            &self.generated_relations,
        );
        let ids = symbols.iter().map(|s| s.id.clone()).collect::<HashSet<_>>();
        for id in ids {
            let mut all = activation_owner_question(
                &reads,
                "TYPES_BY_ID/MEMBERS_BY_ID",
                &id,
                reads.symbols_with_id(&anchors, &id),
            );
            let matches = symbols
                .iter()
                .enumerate()
                .filter(|(_, s)| s.id == id)
                .filter_map(|(index, s)| {
                    all.iter()
                        .position(|other| other.provenance == s.provenance)
                        .map(|other| (index, other))
                })
                .collect::<Vec<_>>();
            mark_symbol_identity_conflicts(&mut all);
            for (index, other) in matches {
                symbols[index].provenance.ambiguous = all[other].provenance.ambiguous;
            }
        }
    }

    fn discover_ids(
        &self,
        ids: &[String],
        open: &LookupOpen,
        realm: Option<&str>,
    ) -> (HashSet<CompositionGroupKey>, Vec<Arc<SemanticModelSymbol>>) {
        let mut keys = HashSet::default();
        let mut orphans = Vec::new();
        for found in self.discover_each(ids, open, realm) {
            keys.extend(found.keys);
            orphans.extend(found.orphans);
            open.note(found.open);
        }
        (keys, orphans)
    }

    /// The group keys and orphan symbols of each raw record ID, in order. An ID
    /// answered by the retained discovery needs no read; the rest are found
    /// together: their records and owners as set reads, then their owners'
    /// alias groups, instead of a point read per ID. Each answer's `open` is the
    /// open part its own lookup saw.
    fn discover_each(
        &self,
        ids: &[String],
        open: &LookupOpen,
        realm: Option<&str>,
    ) -> Vec<IdDiscovery> {
        let reads = self.reads_for_realm(realm);
        let anchors = self.anchor_view_with_reads(open, &reads);
        let mut answers = ids
            .iter()
            .map(|_| None)
            .collect::<Vec<Option<IdDiscovery>>>();
        let mut missing = Vec::new();
        for (position, id) in ids.iter().enumerate() {
            match self.discovered(&CompositionLookup::RecordId(id.clone()), realm) {
                Some(groups) => {
                    answers[position] = Some(IdDiscovery {
                        keys: groups.to_vec(),
                        orphans: Vec::new(),
                        open: None,
                    })
                }
                None => missing.push(position),
            }
        }
        if !missing.is_empty() {
            let missing_ids = missing.iter().map(|&p| ids[p].clone()).collect::<Vec<_>>();
            let found = self.discover_each_with_reads(&missing_ids, open.get(), &reads, &anchors);
            for (position, found) in missing.into_iter().zip(found) {
                if found.orphans.is_empty() && found.open.is_none() {
                    self.retain_discovery(
                        CompositionLookup::RecordId(ids[position].clone()),
                        found.keys.clone(),
                        realm,
                    );
                }
                answers[position] = Some(found);
            }
        }
        answers
            .into_iter()
            .map(|answer| answer.expect("every ID is answered"))
            .collect()
    }

    /// The keys and orphans of `ids` together, found with the caller's reads.
    fn discover_ids_with_reads(
        &self,
        ids: &[String],
        open: &LookupOpen,
        reads: &RowCompositionReads<'_>,
        anchors: &locations::SourceAnchorView<'_>,
    ) -> (HashSet<CompositionGroupKey>, Vec<Arc<SemanticModelSymbol>>) {
        let mut keys = HashSet::default();
        let mut orphans = Vec::new();
        for found in self.discover_each_with_reads(ids, open.get(), reads, anchors) {
            keys.extend(found.keys);
            orphans.extend(found.orphans);
            open.note(found.open);
        }
        (keys, orphans)
    }

    /// [`Self::discover_each`] for IDs the discovery has not retained. `base` is
    /// the open part already seen, which every ID shares.
    fn discover_each_with_reads(
        &self,
        ids: &[String],
        base: Option<FamilyOpen>,
        reads: &RowCompositionReads<'_>,
        anchors: &locations::SourceAnchorView<'_>,
    ) -> Vec<IdDiscovery> {
        let projection = reads.projection();
        let shared = LookupOpen::default();
        shared.note(base);
        lookup_question(
            &shared,
            reads,
            "TYPES_BY_IDS/MEMBERS_BY_IDS",
            ids,
            projection.hydrate_ids(ids),
        );
        let opens = ids
            .iter()
            .map(|_| {
                let open = LookupOpen::default();
                open.note(shared.get());
                open
            })
            .collect::<Vec<_>>();
        let mut symbols_by_id = Vec::with_capacity(ids.len());
        for (id, open) in ids.iter().zip(&opens) {
            let mut symbols = lookup_question(
                open,
                reads,
                "TYPES_BY_ID/MEMBERS_BY_ID",
                id,
                projection.symbols_with_id(anchors, id),
            );
            mark_symbol_identity_conflicts(&mut symbols);
            symbols.retain(|s| self.row_language(&s.language));
            symbols_by_id.push(symbols);
        }
        let mut owner_ids = symbols_by_id
            .iter()
            .flatten()
            .filter_map(|s| s.owner_id.clone())
            .collect::<Vec<_>>();
        owner_ids.sort_unstable();
        owner_ids.dedup();
        lookup_question(
            &shared,
            reads,
            "TYPES_BY_IDS/MEMBERS_BY_IDS",
            &owner_ids,
            projection.hydrate_ids(&owner_ids),
        );
        let mut orphans_by_id = Vec::with_capacity(ids.len());
        let mut seeds_by_id = Vec::with_capacity(ids.len());
        for ((symbols, open), id) in symbols_by_id.into_iter().zip(&opens).zip(ids) {
            let mut orphans = Vec::new();
            let mut seeds = Vec::new();
            for mut symbol in symbols {
                let owners = if let Some(owner) = &symbol.owner_id {
                    lookup_question(
                        open,
                        reads,
                        "TYPES_BY_ID",
                        owner,
                        projection.symbols_with_id(anchors, owner),
                    )
                    .into_iter()
                    .filter(|s| s.owner_id.is_none() && s.language == symbol.language)
                    .collect::<Vec<_>>()
                } else {
                    vec![symbol.clone()]
                };
                if owners.is_empty() {
                    composition::freeze_symbol_order(std::slice::from_mut(&mut symbol));
                    orphans.push(Arc::new(symbol));
                }
                seeds.extend(owners.into_iter().map(|owner| CompositionGroupKey {
                    language: owner.language,
                    module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                    identity: owner.qualified_name,
                }));
            }
            debug_assert!(!id.is_empty());
            orphans_by_id.push(orphans);
            seeds_by_id.push(seeds);
        }
        let canonical = self.canonical_group_keys(
            seeds_by_id.iter().flatten().cloned().collect(),
            reads,
            anchors,
        );
        ids.iter()
            .zip(opens)
            .zip(orphans_by_id)
            .zip(seeds_by_id)
            .map(|(((_, open), orphans), seeds)| {
                let mut keys = Vec::with_capacity(seeds.len());
                for seed in seeds {
                    let (key, part) = &canonical[&seed];
                    open.note(*part);
                    keys.push(key.clone());
                }
                keys.sort_unstable();
                keys.dedup();
                IdDiscovery {
                    keys,
                    orphans,
                    open: open.get(),
                }
            })
            .collect()
    }

    /// The canonical key of each seed's alias group, with the open part its
    /// language saw. A seed whose language read is open stands for itself.
    fn canonical_group_keys(
        &self,
        seeds: HashSet<CompositionGroupKey>,
        reads: &RowCompositionReads<'_>,
        anchors: &locations::SourceAnchorView<'_>,
    ) -> HashMap<CompositionGroupKey, (CompositionGroupKey, Option<FamilyOpen>)> {
        let mut by_language = HashMap::<&str, Vec<CompositionGroupKey>>::default();
        for seed in &seeds {
            by_language
                .entry(&seed.language)
                .or_default()
                .push(seed.clone());
        }
        let mut canonical = HashMap::default();
        for (language, mut seeds) in by_language {
            seeds.sort_unstable();
            let open = LookupOpen::default();
            let keys = lookup_question(
                &open,
                reads,
                "GROUP_OWNERS",
                &seeds,
                reads.group_keys_of(anchors, language, &seeds),
            );
            for (index, seed) in seeds.into_iter().enumerate() {
                let key = keys.get(index).cloned().unwrap_or_else(|| {
                    debug_assert!(open.get().is_some());
                    seed.clone()
                });
                canonical.insert(seed, (key, open.get()));
            }
        }
        canonical
    }

    /// Copy the symbols of the keys' composed groups that `keep` accepts,
    /// after `result`'s own symbols that it accepts. Groups are shared, so
    /// filtering before the copy keeps an ID lookup from cloning whole groups.
    fn project_groups(
        &self,
        keys: impl IntoIterator<Item = CompositionGroupKey>,
        mut result: Vec<Arc<SemanticModelSymbol>>,
        open: &LookupOpen,
        keep: impl Fn(&SemanticModelSymbol) -> bool,
    ) -> Vec<Arc<SemanticModelSymbol>> {
        result.retain(|symbol| keep(symbol));
        let mut keys = keys.into_iter().collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        for chunk in keys.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
            // The chunk's groups are held while their symbols are copied out.
            for lookup in self.lookup_groups(chunk, open) {
                if let Some(group) = lookup.group {
                    result.extend(
                        group
                            .symbols
                            .iter()
                            .filter(|symbol| keep(symbol))
                            .cloned()
                            .map(Arc::new),
                    );
                }
            }
        }
        result.sort_by_cached_key(|symbol| composition::owned_symbol_source_key(symbol));
        result
    }
    pub(super) fn indexed_inputs(
        &self,
        realm: Option<&str>,
    ) -> Option<
        crate::retention_budget::BudgetedValue<
            crate::analyzer::store::semantic_composition::ComposedSearchInputs,
        >,
    > {
        if realm.is_some_and(|realm| realm != "jvm") {
            return None;
        }
        let source = self.active().request_source()?;
        if source.reads_through_activation() {
            return None;
        }
        let owner = source.jvm_reader(self.active()).ok()?;
        let value = self.cache.as_ref()?.composed_search_inputs.get_ready(
            &self.memoized_search_digest(&owner, realm)?,
            &crate::CancellationToken::new(),
        )?;
        value
            .receipt
            .as_any()
            .downcast_ref::<crate::analyzer::common::QueryCacheBuildReceipt>()
            .expect("search input receipt")
            .replay();
        Some(value)
    }

    fn indexed_symbols(
        &self,
        lookup: &CompositionLookup,
        realm: Option<&str>,
    ) -> Option<LookupRows> {
        let value = self.indexed_inputs(realm)?;
        let rows = value
            .indexed_symbols(lookup)?
            .into_iter()
            .map(|symbol| Arc::new(symbol.clone()))
            .collect::<Vec<_>>();
        Some((rows, None))
    }

    fn symbols_for_lookup(
        &self,
        lookup: CompositionLookup,
        ids: impl FnOnce(&LookupOpen) -> Vec<String>,
        realm: Option<&str>,
    ) -> LookupRows {
        if let Some(rows) = self.indexed_symbols(&lookup, realm) {
            return rows;
        }
        let open = LookupOpen::default();
        if let Some(keys) = self.discovered(&lookup, realm) {
            let rows = self.project_groups(keys.iter().cloned(), Vec::new(), &open, |_| true);
            return (rows, open.get());
        }
        let (keys, orphans) = self.discover_ids(&ids(&open), &open, realm);
        // A lookup that saw an open part is incomplete and is not retained.
        if orphans.is_empty() && open.get().is_none() {
            self.retain_discovery(lookup, keys.iter().cloned().collect(), realm);
        }
        let rows = self.project_groups(keys, orphans, &open, |_| true);
        (rows, open.get())
    }

    fn candidate_ids(
        &self,
        open: &LookupOpen,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        params: &[(&str, &dyn rusqlite::ToSql)],
        realm: Option<&str>,
    ) -> Vec<String> {
        self.candidate_ids_with_reads(
            &self.reads_for_realm(realm),
            open,
            statement_name,
            statement,
            key,
            params,
        )
    }

    fn candidate_ids_with_reads(
        &self,
        reads: &RowCompositionReads<'_>,
        open: &LookupOpen,
        statement_name: &str,
        statement: &str,
        key: impl std::fmt::Debug,
        params: &[(&str, &dyn rusqlite::ToSql)],
    ) -> Vec<String> {
        lookup_question(
            open,
            reads,
            statement_name,
            key,
            reads.raw_rows_for_overlay(statement, params, &self.active().shards, |row| {
                row.get::<_, String>("record_id")
            }),
        )
        .into_iter()
        .filter(|r| self.row_language(&r.shard.manifest.language))
        .map(|r| Arc::unwrap_or_clone(r.record))
        .collect()
    }

    pub(super) fn symbols_named(&self, name: &str) -> LookupRows {
        self.symbols_named_scoped(name, None)
    }

    pub(super) fn symbols_named_scoped(&self, name: &str, realm: Option<&str>) -> LookupRows {
        let (rows, open) = self.symbols_for_lookup(
            CompositionLookup::Name(name.to_owned()),
            |open| {
                let reads = self.reads_for_realm(realm);
                let mut ids = Vec::new();
                for (label, sql) in [
                    ("TYPE_SPELLINGS", questions::TYPE_SPELLINGS),
                    ("MEMBER_SPELLINGS", questions::MEMBER_SPELLINGS),
                    ("MEMBER_ALIASES", questions::MEMBER_ALIASES),
                ] {
                    ids.extend(self.candidate_ids_with_reads(
                        &reads,
                        open,
                        label,
                        sql,
                        name,
                        named_params! { ":name": name },
                    ));
                }
                // One indexed equality probe per dot boundary. Joining the
                // boundaries through `json_extract` instead kept SQLite from
                // seeking the name and owner indexes, so every dotted lookup
                // scanned the catalog (#10397).
                for (owner, member) in
                    crate::analyzer::semantic::oracle::dispatch::owner_member_splits(name)
                {
                    for (label, sql) in [
                        ("MEMBERS_QUALIFIED", questions::MEMBERS_QUALIFIED),
                        (
                            "MEMBERS_ALIAS_QUALIFIED",
                            questions::MEMBERS_ALIAS_QUALIFIED,
                        ),
                    ] {
                        ids.extend(self.candidate_ids_with_reads(
                            &reads,
                            open,
                            label,
                            sql,
                            (owner, member),
                            named_params! { ":owner_name": owner, ":member": member },
                        ));
                    }
                    ids.extend(self.candidate_ids_with_reads(
                        &reads,
                        open,
                        "MEMBERS_BY_OWNER_NAME",
                        questions::MEMBERS_BY_OWNER_NAME,
                        (owner, member),
                        named_params! { ":owner": owner, ":name": member },
                    ));
                }
                ids.extend(
                    self.generated
                        .iter()
                        .filter(|s| {
                            s.name == name
                                || s.qualified_name == name
                                || s.aliases.iter().any(|a| a == name)
                        })
                        .map(|s| s.id.clone()),
                );
                ids.sort_unstable();
                ids.dedup();
                ids
            },
            realm,
        );
        let rows = rows
            .into_iter()
            .filter(|s| {
                s.name == name || s.qualified_name == name || s.aliases.iter().any(|a| a == name)
            })
            .collect();
        (rows, open)
    }

    pub(super) fn members_of(&self, owner: &str) -> LookupRows {
        self.members_of_scoped(owner, None)
    }

    pub(super) fn members_of_scoped(&self, owner: &str, realm: Option<&str>) -> LookupRows {
        let (rows, open) = self.symbols_for_lookup(CompositionLookup::MembersOf(owner.to_owned()),|open| {
        let mut ids = self.candidate_ids(open, "MEMBERS_BY_OWNERS", questions::MEMBERS_BY_OWNERS, owner,
            named_params! { ":owner_ids": serde_json::to_string(&[owner]).expect("owner IDs serialize") }, realm);
        ids.push(owner.to_owned());
        ids.extend(
            self.generated
                .iter()
                .filter(|s| s.owner_id.as_deref() == Some(owner))
                .map(|s| s.id.clone()),
        );
        ids.sort_unstable();
        ids.dedup();
            ids
        }, realm);
        let rows = rows
            .into_iter()
            .filter(|s| s.owner_id.as_deref() == Some(owner))
            .collect();
        (rows, open)
    }

    pub(super) fn symbols_at_uri(&self, uri: &str) -> LookupRows {
        let (rows, open) = self.symbols_for_lookup(
            CompositionLookup::Uri(uri.to_owned()),
            |_| {
                let mut ids = self
                    .generated
                    .iter()
                    .filter(|s| {
                        matches!(&s.location,
            SemanticModelLocation::Model(location) if location.uri == uri)
                    })
                    .map(|s| s.id.clone())
                    .collect::<Vec<_>>();
                if let Some(id) = crate::analyzer::store::model_provenance::model_uri_record_id(uri)
                {
                    ids.push(id);
                }
                ids.sort_unstable();
                ids.dedup();
                ids
            },
            None,
        );
        let rows = rows
            .into_iter()
            .filter(|s| {
                matches!(&s.location,
            SemanticModelLocation::Model(location) if location.uri == uri)
            })
            .collect();
        (rows, open)
    }

    pub(super) fn source_bindings_unchanged(
        &self,
        analyzer: &dyn IAnalyzer,
        changed: &brokk_bifrost_core::analyzer::changed_paths::ChangedPaths,
    ) -> bool {
        // An incomplete definition lookup cannot certify an unchanged fallback.
        // Refusing carry leaves the next generation Pending for its normal warm.
        matches!(
            crate::analyzer::i_analyzer::complete_independent_answer(analyzer, || {
                self.anchors.bindings_unchanged(
                    analyzer,
                    &self.active,
                    &self.generated,
                    &self.generated_relations,
                    changed,
                )
            }),
            Ok(Ok(true))
        )
    }

    /// Whether `touches` accepts any workspace path this row overlay was
    /// authored from: the activation anchors, the generated symbols and the
    /// request owner's carried-source anchors. The scan is complete. When the
    /// request anchors cannot be read (an open family, cancellation or a
    /// budget stop) the answer is `true`, so a caller proving that no authored
    /// path changed never proves it from a partial view.
    pub(super) fn any_authored_path(&self, mut touches: impl FnMut(&str) -> bool) -> bool {
        let open = LookupOpen::default();
        let anchors = self.anchor_view(&open);
        open.get().is_some()
            || self.generated.iter().any(|symbol| {
                matches!(&symbol.location,
                    SemanticModelLocation::Authored(anchor) if touches(&anchor.path))
            })
            || anchors.authored_paths().any(touches)
    }

    pub(super) fn symbols_at_authored_path(&self, path: &str) -> LookupRows {
        let (rows, open) = self.symbols_for_lookup(
            CompositionLookup::AuthoredPath(path.to_owned()),
            |open| {
                let anchors = self.anchor_view(open);
                let mut ids = anchors.ids_at_path(path);
                ids.extend(
                    self.generated
                        .iter()
                        .filter(|s| {
                            matches!(&s.location,
            SemanticModelLocation::Authored(anchor) if anchor.path == path)
                        })
                        .map(|s| s.id.clone()),
                );
                ids.sort_unstable();
                ids.dedup();
                ids
            },
            None,
        );
        let rows = rows
            .into_iter()
            .filter(|s| {
                matches!(&s.location,
            SemanticModelLocation::Authored(anchor) if anchor.path == path)
            })
            .collect();
        (rows, open)
    }

    pub(super) fn symbols_with_id(&self, id: &str) -> LookupRows {
        self.symbols_with_id_scoped(id, None)
    }

    pub(super) fn symbols_with_id_scoped(&self, id: &str, realm: Option<&str>) -> LookupRows {
        if let Some(rows) = self.indexed_symbols(&CompositionLookup::RecordId(id.to_owned()), realm)
        {
            return rows;
        }
        let open = LookupOpen::default();
        let (keys, orphans) = self.discover_ids(&[id.to_owned()], &open, realm);
        // Only symbols that name `id` are answers; select them before copying
        // them out of the shared groups. The sort in project_groups is stable,
        // so the answer and its order equal filtering after the copy.
        let rows = self.project_groups(keys, orphans, &open, |s| {
            s.id == id || s.semantic_contributors.iter().any(|c| c.record_id == id)
        });
        (rows, open.get())
    }
}

fn selected_rust_member_path(path: &str) -> Option<(String, String)> {
    RustQualifiedPath::parse(path).and_then(|path| {
        path.parent_and_member()
            .map(|(owner, member)| (owner, member.to_owned()))
    })
}

#[cfg(test)]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10258: selected Rust row lookups reject malformed trailing path segments"
)]
fn selected_rust_member_path_rejects_trailing_dot() {
    assert_eq!(selected_rust_member_path("sqlx.Pool."), None);
    assert_eq!(
        selected_rust_member_path("sqlx.Pool.query"),
        Some(("sqlx.Pool".into(), "query".into()))
    );
}

// Full scalar buffer: record/owner/language, physical source/shard/record keys,
// pre-composition qualified name, spelling and semantic pack digest. No JSON
// record bodies are retained while the catalog cursor is released.

impl RowOverlay {
    fn candidate_buffer(
        &self,
        cancellation: Option<&crate::CancellationToken>,
        reads: &RowCompositionReads<'_>,
    ) -> Option<Vec<SearchCandidate>> {
        let shards = self.active().shards.iter().filter(|s| reads.selects_active_shard(s)).map(|s| {
            let identity = s.row_store.expect("row shard has catalog identity");
            let source = match identity.database {
                crate::analyzer::store::active_models::CatalogShardDatabase::Durable => "durable",
                crate::analyzer::store::active_models::CatalogShardDatabase::Session => "session",
            };
            (source, identity.shard_key, &s.manifest.semantic_sha256)
        }).filter(|(source, key, _)| reads.selects_shard(source, *key)).map(|(source, key, digest)| {
            serde_json::json!({"source_db":source,"shard_key":key,"digest":digest})
        }).collect::<Vec<_>>();
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        let mut candidates: Vec<SearchCandidate> = Vec::new();
        semantic_catalog_question("SEARCH_ORDERED_CANDIDATES", self.active().active_model_set_hash(),
            reads.visit_owned_rows(questions::SEARCH_ORDERED_CANDIDATES,
                named_params! { ":owner_names": "[]", ":shards":serde_json::to_string(&shards).expect("shard identities serialize") },
                cancellation,
                |row| {
                    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) { return Ok(false); }
                    candidates.push((row.get("record_id")?,row.get("owner_id")?,row.get("language")?,row.get("source_db")?,row.get("shard_key")?,row.get("record_key")?,row.get("qualified_name")?,row.get("spelling")?,row.get("pack_digest")?,row.get("record_name")?,row.get("row_kind")?));
                    Ok(true)
                })).ok()?;
        if reads.open_part().is_some() {
            return None;
        }
        let shard_order = self
            .active()
            .shards
            .iter()
            .filter_map(|shard| {
                let identity = shard.row_store?;
                let source = match identity.database {
                    crate::analyzer::store::active_models::CatalogShardDatabase::Durable => {
                        "durable"
                    }
                    crate::analyzer::store::active_models::CatalogShardDatabase::Session => {
                        "session"
                    }
                };
                Some((
                    (source, identity.shard_key),
                    (
                        shard.manifest.pack_id.as_str(),
                        shard.descriptor.shard_id.as_str(),
                        shard.manifest.semantic_sha256.as_str(),
                    ),
                ))
            })
            .collect::<HashMap<_, _>>();
        candidates.sort_by(|a, b| {
            let a_order = shard_order
                .get(&(a.3.as_str(), a.4))
                .expect("candidate has active shard");
            let b_order = shard_order
                .get(&(b.3.as_str(), b.4))
                .expect("candidate has active shard");
            (&a.6, &a.0, &a.8, a_order, &a.3, a.4, &a.10, a.5)
                .cmp(&(&b.6, &b.0, &b.8, b_order, &b.3, b.4, &b.10, b.5))
        });
        // Candidate rows deduplicate by table-qualified address and spelling, preserving aliases.
        let mut seen = HashSet::default();
        candidates.retain(|row| {
            seen.insert((row.3.clone(), row.4, row.10.clone(), row.5, row.7.clone()))
        });
        Some(candidates)
    }

    fn candidate_inputs_with_reads<'a>(
        &'a self,
        cancellation: Option<&crate::CancellationToken>,
        reads: &RowCompositionReads<'a>,
    ) -> Option<(Vec<SearchCandidate>, Vec<&'a SemanticModelSymbol>)> {
        let has_candidates = self.active().shards.iter().any(|s| {
            reads.selects_active_shard(s)
                && s.descriptor.payload_kind
                    == crate::analyzer::semantic_model::PayloadKind::DeclarationFacts
        }) || reads
            .generated
            .iter()
            .any(|s| self.row_language(&s.language) && reads.accepts_language(&s.language));
        if !has_candidates {
            return Some((Vec::new(), Vec::new()));
        }
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        let candidates = self.candidate_buffer(cancellation, reads)?;
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        Some((
            candidates,
            reads
                .generated
                .iter()
                .filter(|s| self.row_language(&s.language) && reads.accepts_language(&s.language))
                .collect(),
        ))
    }

    fn candidate_inputs<'a>(
        &'a self,
        cancellation: Option<&crate::CancellationToken>,
        realm: Option<&str>,
    ) -> Option<(Vec<SearchCandidate>, Vec<&'a SemanticModelSymbol>)> {
        self.candidate_inputs_with_reads(
            cancellation,
            &self.reads_for_realm(realm).for_row_candidates(),
        )
    }

    /// Composition spellings come from the group's owner-identity x member
    /// spelling product, standalone names/aliases, and raw-owner-ID x member
    /// spelling product. Ranked qualification chooses an owner identity or the
    /// raw ID, so its preserved pre-composition QName is already in this set.
    /// Generated facts supply their precomputed spellings without hydration.
    /// Curated duplicate removal transfers these spellings, never inventing
    /// another one. The debug guard checks this on every composed candidate.
    /// Raw facets conservatively close aliases before ranking and guards;
    /// only matched closures enter the existing ranked projection and final
    /// matcher. Complete scalar streams share the store retention budget;
    /// cancellation never publishes a partial stream.
    fn build_search_candidates(
        &self,
        candidates: &[SearchCandidate],
        generated: &[&SemanticModelSymbol],
        cancellation: Option<&crate::CancellationToken>,
        reads: &RowCompositionReads<'_>,
    ) -> Option<SearchCandidateStream> {
        struct Owner {
            id: String,
            language: String,
            module: bool,
            pack_digest: Option<String>,
            identities: HashSet<String>,
            standalone: HashSet<String>,
        }
        let mut owners = Vec::<Owner>::new();
        let mut addresses = HashMap::default();
        let pack_digests = self
            .active()
            .shards
            .iter()
            .map(|shard| {
                (
                    shard.manifest.content_sha256.as_str(),
                    shard.manifest.semantic_sha256.as_str(),
                )
            })
            .collect::<HashMap<_, _>>();
        semantic_catalog_question(
            "SEARCH_TYPES",
            self.active().active_model_set_hash(),
            reads.visit_owned_rows(
                questions::SEARCH_TYPE_IDENTITIES,
                &[],
                cancellation,
                |row| {
                    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                        return Ok(false);
                    }
                    let language: String = row.get("language")?;
                    if !self.row_language(&language) {
                        return Ok(true);
                    }
                    let address = (
                        row.get::<_, String>("source_db")?,
                        row.get::<_, i64>("shard_key")?,
                        row.get::<_, i64>("record_key")?,
                    );
                    let index = if let Some(&index) = addresses.get(&address) {
                        index
                    } else {
                        let index = owners.len();
                        owners.push(Owner {
                            id: row.get("record_id")?,
                            language,
                            module: row.get::<_, String>("namespace")? == "module",
                            pack_digest: Some(
                                pack_digests[row.get::<_, String>("manifest_digest")?.as_str()]
                                    .to_owned(),
                            ),
                            identities: HashSet::default(),
                            standalone: HashSet::default(),
                        });
                        addresses.insert(address, index);
                        index
                    };
                    let spelling: String = row.get("spelling")?;
                    owners[index].standalone.insert(spelling.clone());
                    if row.get::<_, bool>("identity_name")? {
                        owners[index].identities.insert(spelling);
                    }
                    Ok(true)
                },
            ),
        )
        .ok()?;
        if reads.open_part().is_some() {
            return None;
        }
        for symbol in generated.iter().copied().filter(|s| s.owner_id.is_none()) {
            let identities = std::iter::once(symbol.qualified_name.clone())
                .chain(symbol.aliases.iter().cloned())
                .collect::<HashSet<_>>();
            let mut standalone = identities.clone();
            standalone.insert(symbol.name.clone());
            owners.push(Owner {
                id: symbol.id.clone(),
                language: symbol.language.clone(),
                module: symbol.kind == SemanticModelSymbolKind::Module,
                pack_digest: None,
                identities,
                standalone,
            });
        }
        let closures = composition::identity_groups(
            owners.len(),
            owners.iter().enumerate().flat_map(|(index, owner)| {
                owner
                    .identities
                    .iter()
                    .map(move |name| (index, owner.language.as_str(), owner.module, name.as_str()))
            }),
            cancellation,
        )?;
        let mut by_owner = HashMap::<(String, String), Vec<usize>>::default();
        let mut groups = Vec::new();
        let mut seeds_by_group = Vec::new();
        let mut single_contributors = Vec::new();
        let generated_owners = generated
            .iter()
            .map(|s| (s.language.as_str(), s.owner_id.as_deref().unwrap_or(&s.id)))
            .collect::<HashSet<_>>();
        let owner_ids = owners.iter().map(|o| &o.id).collect::<Vec<_>>();
        let mut owner_qualifications = HashMap::default();
        let mut qualification_rows = HashMap::default();
        semantic_catalog_question(
            "SEARCH_OWNER_QUALIFICATIONS", self.active().active_model_set_hash(),
            reads.visit_owned_rows(
                questions::SEARCH_OWNER_QUALIFICATIONS,
                named_params! { ":ids": serde_json::to_string(&owner_ids).expect("owner IDs serialize") },
                cancellation,
                |row| {
                    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) { return Ok(false); }
                    reduce_owner_qualification_row(&mut qualification_rows, row)?;
                    Ok(true)
                },
            ),
        ).ok()?;
        if reads.open_part().is_some() {
            return None;
        }
        for (id, qualification) in qualification_rows {
            owner_qualifications.insert(
                id,
                (qualification.addresses.len() == 1 && !qualification.guarded)
                    .then_some(qualification.name),
            );
        }
        for closure in closures {
            let first = &owners[closure[0]];
            single_contributors.push(
                (closure.len() == 1
                    && !generated_owners.contains(&(first.language.as_str(), first.id.as_str())))
                .then(|| first.pack_digest.clone())
                .flatten(),
            );
            let identities = closure
                .iter()
                .flat_map(|&i| owners[i].identities.iter().cloned())
                .collect::<HashSet<_>>();
            let key = CompositionGroupKey {
                language: first.language.clone(),
                module_namespace: first.module,
                identity: identities.iter().min().expect("owner has identity").clone(),
            };
            let mut standalone = HashSet::default();
            let mut seeds = Vec::new();
            for index in closure {
                let owner = &owners[index];
                let seed = (owner.language.clone(), owner.id.clone());
                by_owner.entry(seed.clone()).or_default().push(groups.len());
                seeds.push(seed);
                standalone.extend(owner.standalone.iter().cloned());
            }
            groups.push(SearchGroup {
                key,
                identities,
                standalone,
                members: HashSet::default(),
            });
            seeds_by_group.push(seeds);
        }
        let mut orphans = Vec::new();
        let spellings = candidates
            .iter()
            .map(|c| {
                (
                    c.0.as_str(),
                    c.1.as_deref(),
                    c.2.as_str(),
                    c.6.as_str(),
                    c.7.as_str(),
                )
            })
            .chain(generated.iter().flat_map(|s| {
                std::iter::once(s.name.as_str())
                    .chain(s.aliases.iter().map(String::as_str))
                    .map(move |name| {
                        (
                            s.id.as_str(),
                            s.owner_id.as_deref(),
                            s.language.as_str(),
                            s.qualified_name.as_str(),
                            name,
                        )
                    })
            }));
        for (id, owner, language, qualified, spelling) in spellings {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return None;
            }
            let seed = (language.to_owned(), owner.unwrap_or(id).to_owned());
            if let Some(indices) = by_owner.get(&seed) {
                for &index in indices {
                    let group = &mut groups[index];
                    attach_search_spelling(group, owner, qualified, spelling);
                }
            } else {
                let mut spellings = vec![spelling.to_owned(), qualified.to_owned()];
                spellings.extend(owner.map(|owner| format!("{owner}.{spelling}")));
                orphans.push((seed, spellings));
            }
        }
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        Some(SearchCandidateStream {
            candidates: candidates.to_vec(),
            groups,
            seeds_by_group,
            single_contributors,
            owner_qualifications,
            orphans,
        })
    }

    fn search_candidates(
        &self,
        cancellation: Option<&crate::CancellationToken>,
        realm: Option<&str>,
    ) -> Option<crate::retention_budget::BudgetedValue<SearchCandidateStream>> {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        // A stream belongs to its family and, when JVM rows contribute,
        // to the request owner binding it read through.
        let binding = self.jvm_retention(realm)?;
        let key = crate::analyzer::store::semantic_composition::SearchCandidateKey {
            realm: realm.map(str::to_owned),
            build: self.build_identity,
            jvm_binding: binding,
        };
        if let Some(value) = self
            .cache
            .as_ref()
            .and_then(|cache| cache.search_candidates(key.clone()))
        {
            return Some(crate::retention_budget::BudgetedValue::Retained(value));
        }
        let (candidates, generated) = self.candidate_inputs(cancellation, realm)?;
        let value = self.build_search_candidates(
            &candidates,
            &generated,
            cancellation,
            &self.reads_for_realm(realm),
        )?;
        Some(match &self.cache {
            Some(cache) => cache.insert_search_candidates(key, value),
            None => crate::retention_budget::BudgetedValue::request_only(value),
        })
    }

    fn candidate_groups(
        &self,
        cancellation: Option<&crate::CancellationToken>,
    ) -> (Vec<SearchGroup>, Vec<Arc<SemanticModelSymbol>>, bool) {
        let Some((candidates, generated)) = self.candidate_inputs(cancellation, None) else {
            return (Vec::new(), Vec::new(), false);
        };
        self.project_candidate_groups(candidates, generated, cancellation, None)
    }

    fn project_candidate_groups(
        &self,
        candidates: Vec<SearchCandidate>,
        generated: Vec<&SemanticModelSymbol>,
        cancellation: Option<&crate::CancellationToken>,
        realm: Option<&str>,
    ) -> (Vec<SearchGroup>, Vec<Arc<SemanticModelSymbol>>, bool) {
        let anchor_open = LookupOpen::default();
        let anchors = self.anchor_view_scoped(&anchor_open, realm);
        let mut reads = self.reads_for_realm(realm);
        reads.cancellation = cancellation.cloned().or(reads.cancellation);
        self.project_candidate_groups_with_anchors(
            candidates,
            generated,
            cancellation,
            &reads,
            &anchor_open,
            &anchors,
        )
    }

    fn project_candidate_groups_with_anchors(
        &self,
        candidates: Vec<SearchCandidate>,
        generated: Vec<&SemanticModelSymbol>,
        cancellation: Option<&crate::CancellationToken>,
        reads: &RowCompositionReads<'_>,
        anchor_open: &LookupOpen,
        anchors: &locations::SourceAnchorView<'_>,
    ) -> (Vec<SearchGroup>, Vec<Arc<SemanticModelSymbol>>, bool) {
        let mut keys_by_owner = HashMap::default();
        let mut groups = HashMap::<CompositionGroupKey, SearchGroup>::default();
        let mut orphans = Vec::new();
        let seeds = candidates
            .iter()
            .map(|c| (c.0.as_str(), c.1.as_deref(), c.2.as_str()))
            .chain(
                generated
                    .iter()
                    .copied()
                    .map(|s| (s.id.as_str(), s.owner_id.as_deref(), s.language.as_str())),
            );
        let seeds = seeds.collect::<Vec<_>>();
        let mut ids = seeds
            .iter()
            .map(|(id, owner, _)| owner.unwrap_or(id).to_string())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        let projection = reads.projection();
        lookup_question(
            anchor_open,
            reads,
            "SEARCH_SEEDS",
            &ids,
            projection.hydrate_ids(&ids),
        );
        let mut languages = seeds
            .iter()
            .map(|(_, _, language)| *language)
            .collect::<Vec<_>>();
        languages.sort_unstable();
        languages.dedup();
        let scoped = languages
            .iter()
            .map(|language| reads.for_language(language))
            .collect::<Vec<_>>();
        let projections = scoped
            .iter()
            .map(|reads| reads.projection())
            .collect::<Vec<_>>();
        for (index, language) in languages.iter().enumerate() {
            let mut language_ids = seeds
                .iter()
                .filter(|(_, _, lang)| lang == language)
                .map(|(id, owner, _)| owner.unwrap_or(id).to_string())
                .collect::<Vec<_>>();
            language_ids.sort_unstable();
            language_ids.dedup();
            lookup_question(
                anchor_open,
                reads,
                "SEARCH_GROUPS",
                &language_ids,
                projections[index].prepare_groups(anchors, &language_ids),
            );
        }
        for (id, owner, language) in seeds {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (Vec::new(), orphans, false);
            }
            let seed = owner.unwrap_or(id);
            let owner_key = (language.to_owned(), seed.to_owned());
            if let std::collections::hash_map::Entry::Vacant(entry) =
                keys_by_owner.entry(owner_key.clone())
            {
                let mut owners = lookup_question(
                    anchor_open,
                    reads,
                    "TYPES_BY_ID",
                    seed,
                    projection.owner_symbols(anchors, seed),
                );
                owners.extend(
                    self.generated
                        .iter()
                        .filter(|s| s.owner_id.is_none() && s.id == seed)
                        .cloned(),
                );
                owners.retain(|s| s.language == language);
                let mut keys = Vec::new();
                for owner in owners {
                    let key = CompositionGroupKey {
                        language: owner.language,
                        module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                        identity: owner.qualified_name,
                    };
                    let owners = lookup_question(
                        anchor_open,
                        reads,
                        "GROUP_OWNERS",
                        &key,
                        projections[languages
                            .binary_search(&key.language.as_str())
                            .expect("seed language")]
                        .group_owners(anchors, &key),
                    );
                    if owners.is_empty() && anchor_open.get().is_some() {
                        return (Vec::new(), Vec::new(), false);
                    }
                    let key = composition::group_key(&owners.iter().collect::<Vec<_>>());
                    groups.entry(key.clone()).or_insert_with(|| {
                        let identities = owners
                            .iter()
                            .flat_map(|s| {
                                std::iter::once(s.qualified_name.clone())
                                    .chain(s.aliases.iter().cloned())
                            })
                            .collect::<HashSet<_>>();
                        let mut standalone = identities.clone();
                        standalone.extend(owners.iter().map(|s| s.name.clone()));
                        SearchGroup {
                            key: key.clone(),
                            identities,
                            standalone,
                            members: HashSet::default(),
                        }
                    });
                    keys.push(key);
                }
                keys.sort_unstable();
                keys.dedup();
                entry.insert(keys);
            }
            if keys_by_owner[&owner_key].is_empty() {
                let (keys, found) =
                    self.discover_ids_with_reads(&[id.to_owned()], anchor_open, reads, anchors);
                orphans.extend(found);
                for key in keys {
                    // Only the symbols are kept, so no relations are read.
                    let group = lookup_question(
                        anchor_open,
                        reads,
                        "COMPOSE_GROUP",
                        &key,
                        reads
                            .compose_groups_symbols(anchors, std::slice::from_ref(&key))
                            .map(|mut groups| groups.pop()),
                    );
                    if let Some(group) = group {
                        orphans.extend(group.symbols.into_iter().map(Arc::new));
                    }
                }
            }
        }
        for (id, owner, language, _, _, _, qualified_name, spelling, _, _, _) in &candidates {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (Vec::new(), orphans, false);
            }
            for key in &keys_by_owner[&(language.clone(), owner.as_ref().unwrap_or(id).clone())] {
                let group = groups.get_mut(key).expect("discovered group");
                attach_search_spelling(group, owner.as_deref(), qualified_name, spelling);
            }
        }
        for symbol in generated {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (Vec::new(), orphans, false);
            }
            for key in &keys_by_owner[&(
                symbol.language.clone(),
                symbol.owner_id.as_ref().unwrap_or(&symbol.id).clone(),
            )] {
                let group = groups.get_mut(key).expect("generated group discovered");
                for spelling in std::iter::once(&symbol.name).chain(&symbol.aliases) {
                    attach_search_spelling(
                        group,
                        symbol.owner_id.as_deref(),
                        &symbol.qualified_name,
                        spelling,
                    );
                }
            }
        }
        let mut groups = groups.into_values().collect::<Vec<_>>();
        groups.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        (
            groups,
            orphans,
            !cancellation.is_some_and(crate::CancellationToken::is_cancelled)
                && anchor_open.get().is_none(),
        )
    }

    fn compose_candidate_group(
        &self,
        candidates: SearchGroup,
        open: &LookupOpen,
    ) -> Option<HeldGroup> {
        let group = self.lookup_group(&candidates.key, open)?;
        if open.get().is_some() {
            return Some(group);
        }
        debug_assert_search_spellings(&candidates, &group.symbols);
        Some(group)
    }

    /// Enumerate complete groups through the shared store retention budget.
    pub(super) fn groups(
        &self,
        cancellation: Option<&crate::CancellationToken>,
    ) -> (Vec<HeldGroup>, Vec<Arc<SemanticModelSymbol>>, bool) {
        let (candidates, orphans, complete) = self.candidate_groups(cancellation);
        let mut groups = Vec::new();
        let open = LookupOpen::default();
        for candidate in candidates {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (groups, orphans, false);
            }
            if let Some(group) = self.compose_candidate_group(candidate, &open) {
                groups.push(group);
            }
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (groups, orphans, false);
            }
        }
        (groups, orphans, complete && open.get().is_none())
    }

    #[cfg(test)]
    pub(super) fn search_symbols(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
        realm: Option<&str>,
    ) -> (Vec<Arc<SemanticModelSymbol>>, bool) {
        self.with_search_symbols(patterns, cancellation, realm, |records, complete| {
            (
                records
                    .into_iter()
                    .map(|symbol| symbol.to_shared())
                    .collect(),
                complete,
            )
        })
    }

    pub(super) fn with_search_symbols<T>(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
        realm: Option<&str>,
        consume: impl FnOnce(Vec<SearchSymbolRef<'_>>, bool) -> T,
    ) -> T {
        use brokk_bifrost_core::budgeted_value_cache::BudgetedValueAcquisition;
        // Non-JVM searches keep their demand-shaped hydration path.
        if realm.is_some_and(|realm| realm != "jvm")
            || self
                .active()
                .request_source()
                .is_none_or(|source| source.reads_through_activation())
        {
            let (records, complete) = self.search_symbols_uncached(patterns, cancellation, realm);
            return consume(
                records.iter().map(SearchSymbolRef::Shared).collect(),
                complete,
            );
        }
        let source = self
            .active()
            .request_source()
            .expect("checked request source");
        let (owner, binding_receipt) =
            crate::analyzer::common::capture_current_query_cache_build(|| {
                source.jvm_reader(self.active())
            });
        let owner = match owner {
            Ok(owner) => owner,
            Err(_) => return consume(Vec::new(), false),
        };
        let key = crate::analyzer::store::semantic_composition::SearchCandidateKey {
            realm: realm.map(str::to_owned),
            build: self.build_identity,
            jvm_binding: Some(owner.binding),
        };
        let default_cancellation = crate::CancellationToken::new();
        let cancellation = cancellation.unwrap_or(&default_cancellation);
        let reads = std::cell::OnceCell::new();
        let frozen;
        let acquisition = self.cache.as_ref().and_then(|cache| {
            Some(
                cache
                    .composed_search_inputs
                    .acquire(
                        &self.memoized_search_digest_with_scope(&owner, realm, || {
                            if reads.get().is_none() {
                                reads
                                    .set(self.search_reads_for_realm(realm, Some(cancellation))?)
                                    .ok()
                                    .expect("empty selection cell");
                            }
                            Some(
                                reads
                                    .get()
                                    .expect("resolved selection")
                                    .canonical_identity(),
                            )
                        })?,
                        cancellation,
                    )
                    .0,
            )
        });
        let value = match acquisition {
            Some(BudgetedValueAcquisition::Cached { value }) => value,
            Some(BudgetedValueAcquisition::Cancelled | BudgetedValueAcquisition::Rejected) => {
                return consume(Vec::new(), false);
            }
            acquisition => {
                frozen = {
                    let mut result = self.clone();
                    #[derive(Clone)]
                    struct FrozenSource(
                        crate::analyzer::store::model_catalog::RequestRowReader,
                        bool,
                        Arc<crate::analyzer::common::QueryCacheBuildReceipt>,
                    );
                    impl std::fmt::Debug for FrozenSource {
                        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            f.debug_tuple("FrozenSource")
                                .field(&self.0.binding)
                                .finish()
                        }
                    }
                    impl crate::analyzer::store::model_catalog::RequestRowReaderSource for FrozenSource {
                        fn reads_through_activation(&self) -> bool {
                            self.1
                        }
                        fn jvm_reader(
                            &self,
                            _: &ResolvedActiveSemanticModels,
                        ) -> Result<
                            crate::analyzer::store::model_catalog::RequestRowReader,
                            FamilyOpen,
                        > {
                            self.2.replay();
                            Ok(self.0.clone())
                        }
                    }
                    result.active = Arc::new(self.active().with_frozen_request_source(Arc::new(
                        FrozenSource(
                            owner,
                            source.reads_through_activation(),
                            Arc::new(binding_receipt),
                        ),
                    )));
                    // Capture every fill read, including composition discovery. Do
                    // not consume receipt-less entries from older partial caches.
                    result.cache = None;
                    result
                };
                let Some(mut reads) = reads
                    .into_inner()
                    .or_else(|| self.search_reads_for_realm(realm, Some(cancellation)))
                else {
                    return consume(Vec::new(), false);
                };
                reads.cancellation = Some(cancellation.clone());
                reads.active = &frozen.active;
                let Some(value) = Self::fill_search_inputs(&frozen, &reads, cancellation) else {
                    return consume(Vec::new(), false);
                };
                if brokk_bifrost_core::profiling::enabled() {
                    use crate::retention_budget::RetainedBytes;
                    eprintln!(
                        "search inputs filled realm={:?}: records={} groups={} entry_bytes={} index_bytes={}",
                        key.realm,
                        value.records.len(),
                        value.groups.len(),
                        value.retained_bytes(),
                        value.index.retained_bytes()
                    );
                }
                match acquisition {
                    Some(BudgetedValueAcquisition::Leader { permit }) => {
                        let receipt = value
                            .receipt
                            .as_any()
                            .downcast_ref::<crate::analyzer::common::QueryCacheBuildReceipt>()
                            .expect("search inputs carry an analyzer receipt");
                        if receipt.is_complete() {
                            permit.publish_complete(value)
                        } else {
                            // Refusing dependency reuse does not invalidate
                            // this request's complete catalog answer.
                            permit.publish_request_owned(value)
                        }
                    }
                    None => crate::retention_budget::BudgetedValue::request_only(value),
                    _ => unreachable!("handled acquisition"),
                }
            }
        };
        value
            .receipt
            .as_any()
            .downcast_ref::<crate::analyzer::common::QueryCacheBuildReceipt>()
            .expect("search inputs carry an analyzer receipt")
            .replay();
        let mut records = value
            .records
            .iter()
            .chain(value.groups.iter().flatten())
            .take_while(|_| !cancellation.is_cancelled())
            .filter(|symbol| {
                std::iter::once(&symbol.name)
                    .chain(std::iter::once(&symbol.qualified_name))
                    .chain(&symbol.aliases)
                    .any(|name| patterns.is_match(name))
            })
            .collect::<Vec<_>>();
        records.sort_by_cached_key(|symbol| composition::owned_symbol_source_key(symbol));
        records.dedup_by(|a, b| a == b);
        consume(
            records.into_iter().map(SearchSymbolRef::Borrowed).collect(),
            !cancellation.is_cancelled(),
        )
    }

    /// All inputs are fixed by SearchCandidateKey: frozen overlay build,
    /// activation selection and the reader bound to its certificate identity.
    fn fill_search_inputs(
        frozen: &Self,
        reads: &RowCompositionReads<'_>,
        cancellation: &crate::CancellationToken,
    ) -> Option<crate::analyzer::store::semantic_composition::ComposedSearchInputs> {
        let (result, receipt) = crate::analyzer::common::capture_current_query_cache_build(|| {
            let open = LookupOpen::default();
            let anchors = frozen.anchor_view_with_reads(&open, reads);
            let (candidates, generated) =
                frozen.candidate_inputs_with_reads(Some(cancellation), reads)?;
            let stream = frozen.build_search_candidates(
                &candidates,
                &generated,
                Some(cancellation),
                reads,
            )?;
            let mut single = HashSet::default();
            for (seeds, contributor) in stream
                .seeds_by_group
                .iter()
                .zip(&stream.single_contributors)
            {
                if let Some(digest) = contributor {
                    single.extend(seeds.iter().map(|(language, owner)| {
                        (language.clone(), owner.clone(), digest.clone())
                    }));
                }
            }
            let single_candidates = candidates
                .iter()
                .filter(|c| {
                    single.contains(&(
                        c.2.clone(),
                        c.1.as_ref().unwrap_or(&c.0).clone(),
                        c.8.clone(),
                    ))
                })
                .collect::<Vec<_>>();
            let mut ids = single_candidates
                .iter()
                .map(|c| c.0.clone())
                .collect::<Vec<_>>();
            ids.sort_unstable();
            ids.dedup();
            let mut owner_names = stream.owner_qualifications.clone();
            // An owner whose raw ID has several records needs its qualification
            // read exceptionally. Read those with set questions per chunk.
            let mut unqualified = owner_names
                .iter()
                .filter(|(_, qualification)| qualification.is_none())
                .map(|(owner, _)| owner.clone())
                .collect::<Vec<_>>();
            unqualified.sort_unstable();
            for chunk in unqualified.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
                if cancellation.is_cancelled() {
                    return None;
                }
                let qualifications = lookup_question(
                    &open,
                    reads,
                    "TYPES_BY_IDS",
                    chunk,
                    reads.owner_qualifications(chunk),
                );
                for (owner, qualification) in chunk.iter().zip(qualifications) {
                    owner_names.insert(owner.clone(), qualification);
                }
            }
            let mut records = lookup_question(
                &open,
                reads,
                "TYPES_BY_IDS/MEMBERS_BY_IDS",
                &ids,
                reads.search_symbols(&anchors, &ids, owner_names),
            );
            let single_records = single_candidates
                .iter()
                .map(|c| (c.8.clone(), c.0.clone(), c.1.clone()))
                .collect::<HashSet<_>>();
            records.retain(|symbol| {
                single_records.contains(&(
                    symbol.provenance.pack_digest.clone(),
                    symbol.id.clone(),
                    symbol.owner_id.clone(),
                ))
            });
            let multi = candidates
                .into_iter()
                .filter(|c| {
                    !single.contains(&(
                        c.2.clone(),
                        c.1.as_ref().unwrap_or(&c.0).clone(),
                        c.8.clone(),
                    ))
                })
                .collect();
            let (groups, orphans, complete) = frozen.project_candidate_groups_with_anchors(
                multi,
                generated,
                Some(cancellation),
                reads,
                &open,
                &anchors,
            );
            records.extend(orphans.into_iter().map(|symbol| (*symbol).clone()));
            let mut composed = Vec::new();
            // Search reads only symbols: no relations, no endpoint
            // representatives. The anchor inventory was captured above, so
            // reusing it avoids reading it again for every chunk.
            for chunk in groups.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
                if cancellation.is_cancelled() {
                    return None;
                }
                let keys = chunk
                    .iter()
                    .map(|candidate| candidate.key.clone())
                    .collect::<Vec<_>>();
                let symbols = match semantic_catalog_question(
                    "GROUP_OWNER_IDS/MEMBER_IDS_BY_OWNERS",
                    &keys,
                    reads.compose_groups_symbols(&anchors, &keys),
                ) {
                    Ok(symbols) => symbols,
                    Err(part) => {
                        open.note(Some(part));
                        return None;
                    }
                };
                open.note(reads.open_part());
                composed.extend(symbols.into_iter().map(|group| group.symbols));
                if cancellation.is_cancelled() {
                    return None;
                }
            }
            let groups = composed;
            (complete && open.get().is_none() && !cancellation.is_cancelled()).then(|| {
                (
                    stream,
                    records,
                    groups,
                    anchors
                        .request
                        .as_ref()
                        .map(|a| (**a).clone())
                        .unwrap_or_default(),
                )
            })
        });
        let (mut stream, records, groups, anchors) = result?;
        stream.candidates = stream.candidates.into_boxed_slice().into_vec();
        stream.groups = stream.groups.into_boxed_slice().into_vec();
        stream.single_contributors = stream.single_contributors.into_boxed_slice().into_vec();
        for seeds in &mut stream.seeds_by_group {
            *seeds = std::mem::take(seeds).into_boxed_slice().into_vec();
        }
        stream.seeds_by_group = stream.seeds_by_group.into_boxed_slice().into_vec();
        for (_, spellings) in &mut stream.orphans {
            *spellings = std::mem::take(spellings).into_boxed_slice().into_vec();
        }
        stream.orphans = stream.orphans.into_boxed_slice().into_vec();
        // The caller publishes a receipt with request-pinned inputs as
        // request-owned, so only other execution dependences stop the fill.
        if receipt.has_unpinned_execution_dependences()
            || !receipt.stable_reasons().is_empty()
            || cancellation.is_cancelled()
        {
            return None;
        }
        let index = crate::analyzer::store::semantic_composition::SearchSymbolIndex::build(
            &records, &groups,
        );
        Some(
            crate::analyzer::store::semantic_composition::ComposedSearchInputs {
                index,
                stream,
                records: records.into_boxed_slice().into_vec(),
                groups: groups.into_boxed_slice().into_vec(),
                anchors,
                receipt: Box::new(receipt),
            },
        )
    }

    fn search_symbols_uncached(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
        realm: Option<&str>,
    ) -> (Vec<Arc<SemanticModelSymbol>>, bool) {
        let anchor_open = LookupOpen::default();
        let anchors = self.anchor_view_scoped(&anchor_open, realm);
        let Some(stream) = self.search_candidates(cancellation, realm) else {
            return (Vec::new(), false);
        };
        let mut single = HashSet::default();
        let mut matched = HashSet::default();
        let mut composed_identities = HashSet::default();
        for ((group, seeds), contributor) in stream
            .groups
            .iter()
            .zip(&stream.seeds_by_group)
            .zip(&stream.single_contributors)
        {
            if let Some(digest) = contributor {
                for (language, owner) in seeds {
                    single.insert((language.clone(), owner.clone(), digest.clone()));
                }
                continue;
            }
            let matches = group
                .spellings()
                .take_while(|_| !cancellation.is_some_and(crate::CancellationToken::is_cancelled))
                .any(|spelling| patterns.is_match(&spelling));
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (Vec::new(), false);
            }
            if matches {
                matched.extend(seeds.iter().cloned());
                composed_identities.extend(group.identities.iter().map(|name| {
                    (
                        group.key.language.clone(),
                        group.key.module_namespace,
                        name.clone(),
                    )
                }));
            }
        }

        for (seed, spellings) in &stream.orphans {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (Vec::new(), false);
            }
            if spellings.iter().any(|s| patterns.is_match(s)) {
                matched.insert(seed.clone());
            }
        }

        // A single contributor cannot add or remove spellings. Match its
        // records before hydration, using the same exceptional qualification
        // question as group projection. Only matching IDs and their same-ID
        // conflict contributors are decoded; no group is composed or admitted.
        let reads = self.reads_for_realm(realm);
        let mut owner_names = HashMap::default();
        let mut single_records = HashSet::default();
        let mut ids = HashSet::default();
        for candidate in &stream.candidates {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (Vec::new(), false);
            }
            let (id, owner, language, _, _, _, _, spelling, digest, name, _) = candidate;
            if !single.contains(&(
                language.clone(),
                owner.as_ref().unwrap_or(id).clone(),
                digest.clone(),
            )) {
                continue;
            }
            let qualified = if let Some(owner) = owner {
                let qualified_owner = owner_names
                    .entry((
                        brokk_bifrost_core::analyzer::model::semantic_pack_realm(language)
                            .to_owned(),
                        owner.clone(),
                    ))
                    .or_insert_with(|| {
                        stream
                            .owner_qualifications
                            .get(&(
                                brokk_bifrost_core::analyzer::model::semantic_pack_realm(language)
                                    .to_owned(),
                                owner.clone(),
                            ))
                            .cloned()
                            .flatten()
                            .or_else(|| {
                                lookup_question(
                                    &anchor_open,
                                    &reads,
                                    "TYPES_BY_ID",
                                    owner,
                                    reads.owner_qualification(
                                        brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                                            language,
                                        ),
                                        owner,
                                    ),
                                )
                            })
                    });
                Some(format!(
                    "{}.{}",
                    qualified_owner.as_deref().unwrap_or(owner),
                    name
                ))
            } else {
                None
            };
            if patterns.is_match(spelling)
                || qualified
                    .as_ref()
                    .is_some_and(|name| patterns.is_match(name))
            {
                ids.insert(id.clone());
                single_records.insert((digest.clone(), id.clone(), owner.clone(), name.clone()));
            }
        }
        let mut ids = ids.into_iter().collect::<Vec<_>>();
        ids.sort_unstable();
        let mut records = if ids.is_empty() {
            Vec::new()
        } else {
            lookup_question(
                &anchor_open,
                &reads,
                "TYPES_BY_IDS/MEMBERS_BY_IDS",
                &ids,
                reads.search_symbols(&anchors, &ids, owner_names),
            )
            .into_iter()
            .filter(|symbol| {
                single_records.contains(&(
                    symbol.provenance.pack_digest.clone(),
                    symbol.id.clone(),
                    symbol.owner_id.clone(),
                    if symbol.owner_id.is_some() {
                        symbol.name.clone()
                    } else {
                        symbol.qualified_name.clone()
                    },
                ))
            })
            .map(Arc::new)
            .collect()
        };
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            // Records hydrated without the request anchors carry fallback
            // locations, so a cancelled prefix is returned only when they read.
            if anchor_open.get().is_some() {
                return (Vec::new(), false);
            }
            return (records, false);
        }

        let inputs = stream
            .candidates
            .iter()
            .filter(|c| matched.contains(&(c.2.clone(), c.1.as_ref().unwrap_or(&c.0).clone())))
            .cloned()
            .collect();
        let generated = self
            .generated
            .iter()
            .filter(|s| {
                self.row_language(&s.language)
                    && matched.contains(&(
                        s.language.clone(),
                        s.owner_id.as_ref().unwrap_or(&s.id).clone(),
                    ))
            })
            .collect();
        let (candidates, orphans, mut complete) =
            self.project_candidate_groups(inputs, generated, cancellation, realm);
        records.extend(orphans);
        // A pack-local raw ID can also discover a different single-owner
        // closure. Only the matching multi/generated closures need compose.
        let selected = candidates
            .into_iter()
            .filter(|candidate| {
                composed_identities.contains(&(
                    candidate.key.language.clone(),
                    candidate.key.module_namespace,
                    candidate.key.identity.clone(),
                )) && candidate
                    .spellings()
                    .any(|spelling| patterns.is_match(&spelling))
            })
            .collect::<Vec<_>>();
        // Search keeps only symbols, so it composes them alone and in chunks,
        // through the same symbol merge the fill uses.
        for chunk in selected.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            let keys = chunk
                .iter()
                .map(|candidate| candidate.key.clone())
                .collect::<Vec<_>>();
            let groups = lookup_question(
                &anchor_open,
                &reads,
                "GROUP_OWNER_IDS/MEMBER_IDS_BY_OWNERS",
                &keys,
                reads.compose_groups_symbols(&anchors, &keys),
            );
            for (candidate, group) in chunk.iter().zip(groups) {
                debug_assert_search_spellings(candidate, &group.symbols);
                records.extend(group.symbols.into_iter().map(Arc::new));
            }
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
        }
        // An open part (the source anchors or a group's composition) leaves
        // the records unverified: their locations or composition may be wrong,
        // so none is returned. A cancelled search keeps what it found.
        if anchor_open.get().is_some()
            || (!complete && !cancellation.is_some_and(crate::CancellationToken::is_cancelled))
        {
            return (Vec::new(), false);
        }
        records.sort_by_cached_key(|symbol| composition::owned_symbol_source_key(symbol));
        records.dedup_by(|a, b| a == b);
        (records, complete)
    }

    pub(super) fn symbols(
        &self,
        cancellation: Option<&crate::CancellationToken>,
    ) -> (Vec<Arc<SemanticModelSymbol>>, bool) {
        let (groups, mut records, complete) = self.groups(cancellation);
        records.extend(
            groups
                .iter()
                .flat_map(|g| g.symbols.iter().cloned())
                .map(Arc::new),
        );
        records.sort_by_cached_key(|symbol| composition::owned_symbol_source_key(symbol));
        records.dedup_by(|a, b| a == b);
        (records, complete)
    }

    pub(super) fn diagnostics(&self) -> Vec<Arc<SemanticModelCompositionDiagnostic>> {
        let (groups, _, complete) = self.groups(None);
        assert!(
            complete,
            "whole-overlay diagnostic enumeration is activation-owner only; an open JVM part must not reach it"
        );
        let mut diagnostics = groups
            .iter()
            .flat_map(|g| g.diagnostics.iter().cloned())
            .collect::<Vec<_>>();
        composition::normalize_diagnostics(&mut diagnostics);
        diagnostics.into_iter().map(Arc::new).collect()
    }
}

impl RowOverlay {
    fn rewritten_standalone_relations(
        &self,
        origins: &HashSet<String>,
        open: &LookupOpen,
        realm: Option<&str>,
    ) -> Vec<SemanticModelRelation> {
        self.rewritten_standalone_relation_sets(
            std::slice::from_ref(origins),
            std::slice::from_ref(&open),
            realm,
        )
        .pop()
        .expect("one origin set")
    }

    fn rewritten_standalone_relation_sets(
        &self,
        sets: &[HashSet<String>],
        opens: &[&LookupOpen],
        realm: Option<&str>,
    ) -> Vec<Vec<SemanticModelRelation>> {
        let origins = sets.iter().flatten().cloned().collect::<HashSet<_>>();
        if origins.is_empty() {
            return sets.iter().map(|_| Vec::new()).collect();
        }
        let batch_open = LookupOpen::default();
        let anchors = self.anchor_view_scoped(&batch_open, realm);
        let reads = self.reads_for_realm(realm);
        let mut relations = lookup_question(
            &batch_open,
            &reads,
            "RELATIONS_FROM/TYPES_BY_ID",
            &origins,
            reads.relations_for_origins(&anchors, &origins),
        );
        // An unavailable batch read affects every origin it read, but never
        // a set with no standalone origin. Endpoint failures below are local.
        for (set, open) in sets.iter().zip(opens) {
            if !set.is_empty() {
                open.note(batch_open.get());
            }
        }
        composition::freeze_relation_order(relations.iter_mut());
        rewrite_standalone_relation_sets(sets, relations, opens, |family, id| {
            // A reader's open part is sticky. Each endpoint needs a fresh
            // reader so its failure cannot mark a different endpoint open.
            let endpoint_reads = self.reads_for_realm(realm);
            let answer = semantic_catalog_question(
                "GROUP_OWNERS",
                id,
                endpoint_reads.endpoint_representatives(&anchors, family, id),
            );
            match (answer, endpoint_reads.open_part()) {
                (Ok(answer), None) => Ok(answer),
                (Err(part), _) | (_, Some(part)) => Err(part),
            }
        })
    }

    /// Whole-overlay enumeration reports any incomplete owner read.
    /// Request-time relation queries use relations_from and relations_to.
    pub(super) fn relations(&self) -> (Vec<Arc<SemanticModelRelation>>, bool) {
        let anchor_open = LookupOpen::default();
        let anchors = self.anchor_view(&anchor_open);
        if anchor_open.get().is_some() {
            return (Vec::new(), false);
        }
        let (groups, _, complete) = self.groups(None);
        if !complete {
            return (Vec::new(), false);
        }
        let mut records = groups
            .iter()
            .flat_map(|g| g.relations.iter().map(|(_, r)| r.clone()))
            .collect::<Vec<_>>();
        let reads = self.reads();
        let mut origins = lookup_question(
            &anchor_open,
            &reads,
            "RELATION_ORIGINS",
            (),
            reads.scalar_question(questions::RELATION_ORIGINS, &[], |row| {
                row.get::<_, String>(0)
            }),
        );
        origins.extend(self.generated_relations.iter().map(|r| r.from.clone()));
        origins.sort();
        origins.dedup();
        let mut standalone = HashSet::default();
        for id in origins {
            let owners = lookup_question(
                &anchor_open,
                &reads,
                "TYPES_BY_ID",
                &id,
                reads.owner_symbols(&anchors, &id),
            );
            if owners.is_empty()
                && !self
                    .generated
                    .iter()
                    .any(|s| s.owner_id.is_none() && s.id == id)
            {
                standalone.insert(id);
            }
        }
        records.extend(self.rewritten_standalone_relations(&standalone, &anchor_open, None));
        if anchor_open.get().is_some() {
            return (Vec::new(), false);
        }
        records.sort_by(composition::relation_source_order);
        (records.into_iter().map(Arc::new).collect(), true)
    }

    pub(super) fn relations_from(
        &self,
        id: &str,
    ) -> (Vec<Arc<SemanticModelRelation>>, Option<FamilyOpen>) {
        self.relations_from_scoped(id, None)
    }

    pub(super) fn relations_from_scoped(
        &self,
        id: &str,
        realm: Option<&str>,
    ) -> (Vec<Arc<SemanticModelRelation>>, Option<FamilyOpen>) {
        self.relations_from_many(&[id.to_owned()], realm)
            .pop()
            .expect("one ID, one answer")
    }

    /// `relations_from_scoped` of each ID, in order, found together: chunks of
    /// `SEARCH_COMPOSE_CHUNK_GROUPS` IDs share their discovery reads and their
    /// group composition (one projection per language per chunk). One ID is a
    /// chunk of one, so this is the only algorithm. The chunk's groups are held
    /// until its relations are copied out, so the cache cannot make a chunk
    /// compose a group twice; no more than one chunk's groups are held.
    pub(super) fn relations_from_many(
        &self,
        ids: &[String],
        realm: Option<&str>,
    ) -> Vec<(Vec<Arc<SemanticModelRelation>>, Option<FamilyOpen>)> {
        let active = self.active();
        if !active.shards.iter().any(|shard| {
            composition::admits_row_relation(shard, &shard.manifest.semantic_sha256)
                && realm.is_none_or(|realm| {
                    brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                        &shard.manifest.language,
                    ) == realm
                })
        }) {
            return ids.iter().map(|_| (Vec::new(), None)).collect();
        }
        let opens = ids
            .iter()
            .map(|_| LookupOpen::default())
            .collect::<Vec<_>>();
        let mut records = Vec::with_capacity(ids.len());
        let mut standalone_sets = Vec::with_capacity(ids.len());
        for (chunk, chunk_opens) in ids
            .chunks(SEARCH_COMPOSE_CHUNK_GROUPS)
            .zip(opens.chunks(SEARCH_COMPOSE_CHUNK_GROUPS))
        {
            let mut held = HeldGroups::default();
            let origins = self.raw_ids_held(chunk, chunk_opens, &mut held, realm);
            let (owned, standalone) =
                self.owned_relations_for_origin_sets(&origins, chunk_opens, &held, realm);
            records.extend(owned);
            standalone_sets.extend(standalone);
            // Only copied relation rows and origin IDs survive this chunk.
        }
        let standalone = self.rewritten_standalone_relation_sets(
            &standalone_sets,
            &opens.iter().collect::<Vec<_>>(),
            realm,
        );
        ids.iter()
            .zip(records)
            .zip(standalone)
            .zip(opens)
            .map(|(((id, mut records), standalone), open)| {
                records.extend(standalone);
                records.sort_by(composition::relation_source_order);
                (
                    records
                        .into_iter()
                        .filter(|r| r.from == *id)
                        .map(Arc::new)
                        .collect(),
                    open.get(),
                )
            })
            .collect()
    }

    /// The raw record IDs of the symbols `symbols_with_id_scoped` finds for
    /// each ID, in order, and the ID itself: the origins of its relations. Each
    /// ID's own open part is noted in `opens`. The groups composed on the way
    /// stay in `held`.
    fn raw_ids_held(
        &self,
        ids: &[String],
        opens: &[LookupOpen],
        held: &mut HeldGroups,
        realm: Option<&str>,
    ) -> Vec<HashSet<String>> {
        let mut raw_ids = ids
            .iter()
            .map(|id| HashSet::from_iter([id.clone()]))
            .collect::<Vec<HashSet<String>>>();
        let mut pending = Vec::new();
        for (position, id) in ids.iter().enumerate() {
            match self.indexed_symbols(&CompositionLookup::RecordId(id.clone()), realm) {
                Some((indexed, part)) => {
                    opens[position].note(part);
                    for symbol in indexed {
                        raw_ids[position].insert(symbol.id.clone());
                        raw_ids[position].extend(
                            symbol
                                .semantic_contributors
                                .iter()
                                .map(|p| p.record_id.clone()),
                        );
                    }
                }
                None => pending.push(position),
            }
        }
        if pending.is_empty() {
            return raw_ids;
        }
        let shared = LookupOpen::default();
        let pending_ids = pending.iter().map(|&p| ids[p].clone()).collect::<Vec<_>>();
        let found = self.discover_each(&pending_ids, &shared, realm);
        held.fill(
            self,
            found.iter().flat_map(|found| found.keys.iter().cloned()),
        );
        for (position, found) in pending.into_iter().zip(found) {
            let id = &ids[position];
            let open = &opens[position];
            open.note(shared.get());
            open.note(found.open);
            let orphans = found.orphans.iter().map(|s| &**s);
            let held_symbols = found.keys.iter().flat_map(|key| {
                let lookup = &held.0[key];
                open.note(lookup.open);
                lookup.group.iter().flat_map(|group| group.symbols.iter())
            });
            for symbol in orphans.chain(held_symbols).filter(|s| {
                s.id == *id || s.semantic_contributors.iter().any(|c| c.record_id == *id)
            }) {
                raw_ids[position].insert(symbol.id.clone());
                raw_ids[position].extend(
                    symbol
                        .semantic_contributors
                        .iter()
                        .map(|p| p.record_id.clone()),
                );
            }
        }
        raw_ids
    }

    pub(super) fn relations_to(
        &self,
        id: &str,
    ) -> (Vec<Arc<SemanticModelRelation>>, Option<FamilyOpen>) {
        self.relations_to_scoped(id, None)
    }

    pub(super) fn relations_to_scoped(
        &self,
        id: &str,
        realm: Option<&str>,
    ) -> (Vec<Arc<SemanticModelRelation>>, Option<FamilyOpen>) {
        let reads = self.reads_for_realm(realm);
        let open = LookupOpen::default();
        let mut raw_targets = HashSet::from_iter([id.to_owned()]);
        let (symbols, part) = self.symbols_with_id_scoped(id, realm);
        open.note(part);
        for symbol in symbols {
            raw_targets.insert(symbol.id.clone());
            raw_targets.extend(
                symbol
                    .semantic_contributors
                    .iter()
                    .map(|p| p.record_id.clone()),
            );
        }
        let mut raw_targets = raw_targets.into_iter().collect::<Vec<_>>();
        raw_targets.sort_unstable();
        let mut origins = lookup_question(&open,&reads, "OVERLAY_RELATIONS_TO",id,reads.raw_rows_for_overlay(questions::OVERLAY_RELATIONS_TO,
            named_params! { ":raw_targets":serde_json::to_string(&raw_targets).expect("targets serialize") }, &self.active().shards,|row|row.get::<_,String>("from_id")))
            .into_iter().map(|r|Arc::unwrap_or_clone(r.record)).collect::<HashSet<_>>();
        origins.extend(
            self.generated_relations
                .iter()
                .filter(|r| raw_targets.contains(&r.to))
                .map(|r| r.from.clone()),
        );
        let opens = [open];
        let records = self
            .relations_for_origin_sets(&[origins], &opens, &HeldGroups::default(), realm)
            .pop()
            .expect("one set, one answer")
            .into_iter()
            .filter(|r| r.to == id)
            .collect();
        (records, opens[0].get())
    }

    /// The relations whose source is one of each set's origin IDs, in order.
    /// An origin is mapped to the groups holding it through the retained
    /// discovery of its record ID, the map `symbols_with_id_scoped` uses, so a
    /// repeated origin reads nothing; origins not yet discovered are found
    /// together. An origin that no group holds as an owner has only standalone
    /// relations. Groups are composed in chunks and dropped after their
    /// relations are copied out, unless the caller already holds them.
    fn relations_for_origin_sets(
        &self,
        sets: &[HashSet<String>],
        opens: &[LookupOpen],
        held: &HeldGroups,
        realm: Option<&str>,
    ) -> Vec<Vec<Arc<SemanticModelRelation>>> {
        let (records, standalone_sets) =
            self.owned_relations_for_origin_sets(sets, opens, held, realm);
        let standalone = self.rewritten_standalone_relation_sets(
            &standalone_sets,
            &opens.iter().collect::<Vec<_>>(),
            realm,
        );
        records
            .into_iter()
            .zip(standalone)
            .map(|(mut records, standalone)| {
                records.extend(standalone);
                records.sort_by(composition::relation_source_order);
                records.into_iter().map(Arc::new).collect()
            })
            .collect()
    }

    /// Copy group rows out while the caller holds only one discovery chunk.
    fn owned_relations_for_origin_sets(
        &self,
        sets: &[HashSet<String>],
        opens: &[LookupOpen],
        held: &HeldGroups,
        realm: Option<&str>,
    ) -> (Vec<Vec<SemanticModelRelation>>, Vec<HashSet<String>>) {
        // A scoped lookup composes only its family's owners. The row owners
        // are read through the scoped reads already; a generated owner, or a
        // group key, of another family would compose through that family's
        // owner (for a JVM one, binding the JVM request owner).
        let in_realm = |language: &str| {
            realm.is_none_or(|realm| {
                brokk_bifrost_core::analyzer::model::semantic_pack_realm(language) == realm
            })
        };
        let mut origins = sets.iter().flatten().cloned().collect::<Vec<_>>();
        origins.sort_unstable();
        origins.dedup();
        let scratch = LookupOpen::default();
        let mut discovered = HashMap::<String, IdDiscovery>::default();
        for chunk in origins.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
            discovered.extend(
                chunk
                    .iter()
                    .cloned()
                    .zip(self.discover_each(chunk, &scratch, realm)),
            );
        }
        // Generated owners are not in the catalog rows: each is its own seed.
        let reads = self.reads_for_realm(realm);
        let anchors = self.anchor_view_scoped(&scratch, realm);
        let generated = origins
            .iter()
            .map(|id| {
                self.generated
                    .iter()
                    .filter(|s| s.owner_id.is_none() && &s.id == id && in_realm(&s.language))
                    .map(|s| CompositionGroupKey {
                        language: s.language.clone(),
                        module_namespace: s.kind == SemanticModelSymbolKind::Module,
                        identity: s.qualified_name.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let canonical = self.canonical_group_keys(
            generated.iter().flatten().cloned().collect(),
            &reads,
            &anchors,
        );
        let generated = origins
            .iter()
            .zip(generated)
            .filter(|(_, seeds)| !seeds.is_empty())
            .map(|(id, seeds)| (id.as_str(), seeds))
            .collect::<HashMap<_, _>>();
        let mut keys_to_sets = HashMap::<CompositionGroupKey, Vec<usize>>::default();
        let mut owned = sets
            .iter()
            .map(|_| HashSet::<String>::default())
            .collect::<Vec<_>>();
        for (position, set) in sets.iter().enumerate() {
            for origin in set {
                let found = &discovered[origin];
                opens[position].note(scratch.get());
                opens[position].note(found.open);
                let mut generated_keys = Vec::new();
                for seed in generated.get(origin.as_str()).into_iter().flatten() {
                    let (key, part) = &canonical[seed];
                    opens[position].note(*part);
                    generated_keys.push(key);
                }
                if !generated_keys.is_empty() {
                    owned[position].insert(origin.clone());
                }
                for key in found.keys.iter().chain(generated_keys) {
                    let sets = keys_to_sets.entry(key.clone()).or_default();
                    if !sets.contains(&position) {
                        sets.push(position);
                    }
                }
            }
        }
        let mut keys = keys_to_sets.keys().cloned().collect::<Vec<_>>();
        keys.sort_unstable();
        let mut records = sets.iter().map(|_| Vec::new()).collect::<Vec<_>>();
        for chunk in keys.chunks(SEARCH_COMPOSE_CHUNK_GROUPS) {
            let mut looked_up = HeldGroups::default();
            looked_up.fill(
                self,
                chunk
                    .iter()
                    .filter(|key| !held.0.contains_key(*key))
                    .cloned(),
            );
            for key in chunk {
                let lookup = held.0.get(key).unwrap_or_else(|| &looked_up.0[key]);
                for &position in &keys_to_sets[key] {
                    opens[position].note(lookup.open);
                    let Some(group) = &lookup.group else {
                        continue;
                    };
                    let origins = &sets[position];
                    for symbol in group.symbols.iter().filter(|s| s.owner_id.is_none()) {
                        for raw in std::iter::once(&symbol.id)
                            .chain(symbol.semantic_contributors.iter().map(|c| &c.record_id))
                        {
                            if let Some(origin) = origins.get(raw) {
                                owned[position].insert(origin.clone());
                            }
                        }
                    }
                    records[position].extend(
                        group
                            .relations
                            .iter()
                            .map(|(_, r)| r)
                            .filter(|r| origins.contains(semantic_relation_source_key(r).0))
                            .cloned(),
                    );
                }
            }
        }
        let standalone_sets = sets
            .iter()
            .zip(&owned)
            .map(|(origins, owned)| origins.difference(owned).cloned().collect::<HashSet<_>>())
            .collect::<Vec<_>>();
        (records, standalone_sets)
    }
}

impl RowOverlay {
    pub(super) fn has_generated_functions(&self, language: &str) -> bool {
        self.generated
            .iter()
            .any(|s| s.language == language && s.is_rule_generated_function())
    }
}

impl RowOverlay {
    fn contract_records<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
    ) -> Vec<(Arc<ActiveSemanticModelShard>, Arc<T>)> {
        let reads = self.reads();
        let rows = activation_owner_question(
            &reads,
            name,
            self.active().active_model_set_hash(),
            reads.raw_rows_for_overlay(statement, bindings, &self.active().shards, |row| {
                let json: String = row.get("record_json")?;
                let record: T = serde_json::from_str(&json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        row.column_index("record_json").expect("record column"),
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok((row.get::<_, i64>("record_key")?, Arc::new(record)))
            }),
        );
        let mut records = rows
            .into_iter()
            .filter_map(|r| {
                let index = self
                    .active()
                    .shards
                    .iter()
                    .position(|s| Arc::ptr_eq(&s.metadata, &r.shard))
                    .expect("row belongs to publication");
                self.active().shards[index]
                    .decoded
                    .is_none()
                    .then(|| ((index, r.record.0), Arc::clone(&r.record.1)))
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|(index, _)| *index);
        records
            .into_iter()
            .map(|((index, _), r)| (Arc::clone(&self.active().shards[index]), r))
            .collect()
    }

    pub(super) fn merge_contracts<T>(
        &self,
        decoded: Vec<Arc<T>>,
        rows: Vec<Arc<T>>,
        provenance_of: impl Fn(&T) -> &SemanticModelProvenance,
    ) -> Vec<Arc<T>> {
        let order = |record: &Arc<T>| {
            let p = provenance_of(record);
            self.active()
                .shards
                .iter()
                .position(|s| {
                    s.manifest.semantic_sha256 == p.pack_digest
                        && s.source_id == p.activation.source_id
                        && source_kind(s.source_kind) == p.activation.source_kind
                })
                .expect("contract belongs to active publication")
        };
        crate::analyzer::store::active_models::merge_ordered_semantic_results(
            decoded,
            rows,
            |a, b| order(a).cmp(&order(b)),
        )
    }

    pub(super) fn collection_flows(
        &self,
        name: &str,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
    ) -> Vec<Arc<CollectionFlowContract>> {
        self.contract_records::<crate::analyzer::semantic_model::CollectionFlowFact>(
            name, statement, bindings,
        )
        .into_iter()
        .map(|(shard, flow)| {
            Arc::new(CollectionFlowContract {
                provenance: provenance(
                    self.active(),
                    &shard,
                    &flow.callable,
                    &model_location(&shard, "collection-flow", &flow.callable),
                    None,
                    false,
                ),
                callable: flow.callable.clone(),
                payload: flow.payload.clone(),
                coverage: flow.coverage,
            })
        })
        .collect()
    }

    pub(super) fn refinements(
        &self,
        ids: &[String],
    ) -> Vec<Arc<ConditionalTypeRefinementContract>> {
        self.contract_records::<crate::analyzer::semantic_model::ConditionalTypeRefinementFact>(
            "CONDITIONAL_REFINEMENTS",
            questions::CONDITIONAL_REFINEMENTS,
            named_params! { ":callable_ids":serde_json::to_string(ids).expect("IDs serialize") },
        )
        .into_iter()
        .map(|(shard, fact)| {
            Arc::new(ConditionalTypeRefinementContract {
                provenance: provenance(
                    self.active(),
                    &shard,
                    &fact.payload.callable,
                    &model_location(
                        &shard,
                        "conditional-type-refinement",
                        &fact.payload.callable,
                    ),
                    None,
                    false,
                ),
                payload: fact.payload.clone(),
                coverage: fact.coverage,
            })
        })
        .collect()
    }

    pub(super) fn deferred_yields(
        &self,
        name: &str,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
    ) -> Vec<Arc<DeferredYieldContract>> {
        self.contract_records::<crate::analyzer::semantic_model::DeferredYieldFact>(
            name, statement, bindings,
        )
        .into_iter()
        .map(|(shard, fact)| {
            Arc::new(DeferredYieldContract {
                provenance: provenance(
                    self.active(),
                    &shard,
                    &fact.factory,
                    &model_location(&shard, "deferred-yield", &fact.factory),
                    None,
                    false,
                ),
                factory: fact.factory.clone(),
                resume: fact.resume.clone(),
                handle_type: fact.handle_type.clone(),
                payload: fact.payload.clone(),
                coverage: fact.coverage,
            })
        })
        .collect()
    }

    pub(super) fn runtime_values(&self) -> Vec<Arc<RuntimeValueContracts>> {
        activation_owner_rows("RUNTIME_VALUES", self.active().runtime_values())
            .into_iter()
            .filter(|(_, shard)| shard.decoded.is_none())
            .map(|(payload, shard)| {
                Arc::new(RuntimeValueContracts {
                    provenance: Arc::new(provenance(
                        self.active(),
                        &shard,
                        "runtime-values",
                        &model_location(&shard, "runtime-values", "runtime-values"),
                        None,
                        false,
                    )),
                    payload,
                })
            })
            .collect()
    }
}

impl RowOverlay {
    pub(super) fn runtime_exposures(
        &self,
        binding: &str,
        language: &str,
    ) -> Vec<(Arc<RuntimeGlobalExposure>, Arc<SemanticModelProvenance>)> {
        let reads = self.reads();
        let records = activation_owner_question(
            &reads,
            "RUNTIME_EXPOSURES",
            (binding, language),
            reads.raw_rows_for_overlay(
                questions::RUNTIME_EXPOSURES,
                named_params! { ":binding":binding },
                &self.active().shards,
                |row| {
                    let json: String = row.get("exposure_json")?;
                    let exposure: RuntimeGlobalExposure =
                        serde_json::from_str(&json).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                row.column_index("exposure_json").expect("exposure column"),
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                    Ok((row.get::<_, i64>("exposure_ordinal")?, Arc::new(exposure)))
                },
            ),
        );
        let mut result = records
            .into_iter()
            .filter_map(|r| {
                let index = self
                    .active()
                    .shards
                    .iter()
                    .position(|s| Arc::ptr_eq(&s.metadata, &r.shard))
                    .expect("selected exposure metadata");
                let shard = &self.active().shards[index];
                (shard.decoded.is_none() && r.record.1.languages.iter().any(|l| l == language))
                    .then(|| {
                        (
                            (index, r.record.0),
                            Arc::clone(&r.record.1),
                            Arc::new(provenance(
                                self.active(),
                                shard,
                                "runtime-values",
                                &model_location(shard, "runtime-values", "runtime-values"),
                                None,
                                false,
                            )),
                        )
                    })
            })
            .collect::<Vec<_>>();
        result.sort_by_key(|(key, _, _)| *key);
        result
            .into_iter()
            .map(|(_, exposure, provenance)| (exposure, provenance))
            .collect()
    }
}

fn check_selected_cancellation(
    cancellation: &crate::CancellationToken,
) -> Result<(), SemanticModelOverlayBuildError> {
    if cancellation.is_cancelled() {
        return Err(SemanticModelOverlayBuildError::Cancelled);
    }
    Ok(())
}

fn selected_question<T>(
    question: &'static str,
    key: impl std::fmt::Debug,
    result: Result<T, CatalogError>,
) -> Result<T, SemanticModelOverlayBuildError> {
    match result {
        Err(CatalogError::Cancelled) => Err(SemanticModelOverlayBuildError::Cancelled),
        Err(CatalogError::FamilyOpen(open)) => Err(open.into()),
        result => semantic_catalog_question(question, key, result).map_err(Into::into),
    }
}

/// The language a composition lookup is scoped to, or None for an unscoped one.
fn lookup_language(lookup: &CompositionLookup) -> Option<&str> {
    match lookup {
        CompositionLookup::SelectedId { language, .. }
        | CompositionLookup::SelectedName { language, .. } => Some(language.as_str()),
        CompositionLookup::OwnerIdentity(key) => Some(key.language.as_str()),
        _ => None,
    }
}
