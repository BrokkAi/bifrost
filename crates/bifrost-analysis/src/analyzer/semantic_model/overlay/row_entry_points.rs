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
struct LookupOpen(std::cell::Cell<Option<FamilyOpen>>);

impl LookupOpen {
    fn note(&self, open: Option<FamilyOpen>) {
        if self.0.get().is_none() || open.is_some_and(FamilyOpen::is_cancellation) {
            self.0.set(open);
        }
    }

    fn get(&self) -> Option<FamilyOpen> {
        self.0.get()
    }

    /// An activation-owner path ends here: see [`activation_owner_question`].
    fn assert_activation_owner(&self, statement: &str) {
        if let Some(open) = self.get() {
            panic!(
                "{statement}: unselected overlay reads run on the activation owner, which owns no JVM-family shards (#9559): {open:?}"
            );
        }
    }
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

#[derive(Debug, Clone)]
pub(super) struct RowOverlay {
    pub(super) active: Arc<ResolvedActiveSemanticModels>,
    pub(super) cache: Option<StoreCacheBudget>,
    build_identity: SemanticOverlayBuildIdentity,
    anchors: locations::SourceAnchors,
    generated: Vec<SemanticModelSymbol>,
    generated_relations: Vec<SemanticModelRelation>,
}

impl RowOverlay {
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
                RowCompositionReads::new(&self.active, &self.generated, &self.generated_relations);
            selected_question(
                "ALL_TYPES",
                "active-set",
                reads
                    .for_language(language)
                    .types(questions::ALL_TYPES, &[]),
            )?
        } else {
            let reads = RowCompositionReads::activation_only(
                &self.active,
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
            anchors: locations::SourceAnchors::default(),
            generated,
            generated_relations,
        };
        if active.shards.iter().any(|shard| shard.decoded.is_none()) {
            let reads = RowCompositionReads::activation_only(
                active,
                &result.generated,
                &result.generated_relations,
            );
            result.anchors = activation_owner_question(
                &reads,
                "SOURCE_TYPES/SOURCE_MEMBERS",
                active.active_model_set_hash(),
                reads.activation_source_anchors(analyzer),
            );
        }
        for symbol in eager_symbols
            .iter()
            .filter(|s| matches!(s.location, SemanticModelLocation::Authored(_)))
        {
            result.anchors.insert_symbol(
                if symbol.owner_id.is_none() {
                    "type"
                } else {
                    "member"
                },
                symbol.clone(),
            );
        }
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
                        shard.approximate
                    )
                )
                .as_bytes(),
            );
            digest.push(format!("{:?}", activated_record_provenance(active, shard, "")).as_bytes());
        }

        // Derived Debug includes scope, signature and ordering fields which the
        // public serialized symbol shape deliberately omits. This key is local
        // to this executable and never a persisted format.
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
    /// had, so scoped and unscoped lookups share the cached group.
    fn lookup_group(
        &self,
        key: &CompositionGroupKey,
        open: &LookupOpen,
    ) -> Option<composition::ComposedGroup> {
        // Only this group's own anchor part decides here: an open part seen
        // earlier in the same lookup must not drop a group that reads none.
        let anchor_open = LookupOpen::default();
        let anchors = self.anchor_view_scoped(&anchor_open, Some(&key.language));
        if let Some(part) = anchor_open.get() {
            open.note(Some(part));
            return None;
        }
        // An open JVM owner has no retention binding, so its key would equal
        // the key of a request without a request source; never share it.
        let retention = self.jvm_retention(Some(&key.language));
        let cache = self.cache.as_ref().filter(|_| retention.is_some());
        let cache_key = ComposedGroupCacheKey {
            jvm_binding: retention.flatten(),
            build: self.build_identity,
            selection_digest: None,
            group: key.clone(),
        };
        if let Some(value) = cache.and_then(|cache| cache.composed_group(&cache_key)) {
            return Some((*value).clone());
        }
        // The loader has no cancellation branch: it either returns a complete
        // group or an error. Callers check cancellation before using this answer.
        let reads = self.reads();
        let group = match semantic_catalog_question(
            "GROUP_OWNER_IDS/MEMBER_IDS_BY_OWNERS/OVERLAY_RELATIONS_FROM",
            key,
            reads.compose_group(&anchors, key),
        ) {
            Ok(group) => group,
            Err(family_open) => {
                open.note(Some(family_open));
                return None;
            }
        };
        if let Some(part) = reads.open_part() {
            open.note(Some(part));
            return Some(group);
        }
        if open.get().is_some() {
            return Some(group);
        }
        if let Some(cache) = cache {
            drop(cache.insert_composed_group(cache_key, group.clone()));
        }
        Some(group)
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
            reads.cancellation = Some(cancellation);
            reads.selection = Some(selection);
            reads.defining_owner = defining_owner;
            Box::new(reads.for_language(language))
        } else {
            Box::new(composition::SelectedDecodedReads {
                language,
                active: &self.active,
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
        let Some(shard) = self.active.shards.iter().find(|shard| {
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
        symbols.sort_by(composition::symbol_source_order);
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
    fn owner_group_key(
        &self,
        key: &CompositionGroupKey,
        open: &LookupOpen,
        realm: Option<&str>,
    ) -> CompositionGroupKey {
        let anchors = self.anchor_view_scoped(open, Some(&key.language));
        let lookup = CompositionLookup::OwnerIdentity(key.clone());
        if let Some(groups) = self.discovered(&lookup, realm) {
            return groups[0].clone();
        }
        let reads = self.reads_for_realm(realm);
        let owners = lookup_question(
            open,
            &reads,
            "GROUP_OWNERS",
            key,
            reads.group_owners(&anchors, key),
        );
        if owners.is_empty() && open.get().is_some() {
            return key.clone();
        }
        let canonical = composition::group_key(&owners.iter().collect::<Vec<_>>());
        if open.get().is_none() {
            self.retain_discovery(lookup, vec![canonical.clone()], realm);
        }
        canonical
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
        self.active.question_row_owners(None).jvm_binding
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
        let owners = self.active.question_row_owners(None);
        owners.jvm_open.is_none().then_some(owners.jvm_binding)
    }

    fn reads_for_realm<'a>(&'a self, realm: Option<&'a str>) -> RowCompositionReads<'a> {
        let reads = self.reads();
        match realm {
            Some(realm) => reads.for_realm(realm),
            None => reads,
        }
    }

    fn reads(&self) -> RowCompositionReads<'_> {
        RowCompositionReads::new(&self.active, &self.generated, &self.generated_relations)
    }

    fn anchor_view(&self, open: &LookupOpen) -> locations::SourceAnchorView<'_> {
        self.anchor_view_scoped(open, None)
    }

    fn anchor_view_scoped(
        &self,
        open: &LookupOpen,
        language: Option<&str>,
    ) -> locations::SourceAnchorView<'_> {
        let request = if !language.is_some_and(|language| {
            brokk_bifrost_core::analyzer::model::semantic_pack_realm(language) != "jvm"
        }) && self
            .active
            .shards
            .iter()
            .any(|shard| shard.decoded.is_none() && shard.request_owned())
        {
            let owners = self.active.question_row_owners(None);
            let key = owners.jvm_binding.map(|binding| RequestSourceAnchorsKey {
                build: self.build_identity,
                binding,
            });
            if let Some(hit) = key.as_ref().and_then(|key| {
                self.cache
                    .as_ref()
                    .and_then(|cache| cache.request_source_anchors(key))
            }) {
                Some(crate::retention_budget::BudgetedValue::Retained(hit))
            } else {
                let reads = self.reads();
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
            activation: &self.anchors,
            request,
        }
    }

    pub(super) fn row_language(&self, language: &str) -> bool {
        self.active
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
            &self.active,
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
        let anchors = self.anchor_view_scoped(open, realm);
        let reads = self.reads_for_realm(realm);
        let mut keys = HashSet::default();
        let mut result = Vec::new();
        for id in ids {
            let lookup = CompositionLookup::RecordId(id.clone());
            if let Some(groups) = self.discovered(&lookup, realm) {
                keys.extend(groups.iter().cloned());
                continue;
            }
            let mut id_keys = HashSet::default();
            let mut has_orphan = false;
            let mut symbols = lookup_question(
                open,
                &reads,
                "TYPES_BY_ID/MEMBERS_BY_ID",
                id,
                reads.symbols_with_id(&anchors, id),
            );
            mark_symbol_identity_conflicts(&mut symbols);
            for mut symbol in symbols
                .into_iter()
                .filter(|s| self.row_language(&s.language))
            {
                let owners = if let Some(owner) = &symbol.owner_id {
                    lookup_question(
                        open,
                        &reads,
                        "TYPES_BY_ID",
                        owner,
                        reads.symbols_with_id(&anchors, owner),
                    )
                    .into_iter()
                    .filter(|s| s.owner_id.is_none() && s.language == symbol.language)
                    .collect::<Vec<_>>()
                } else {
                    vec![symbol.clone()]
                };
                if owners.is_empty() {
                    has_orphan = true;
                    composition::freeze_symbol_order(std::slice::from_mut(&mut symbol));
                    result.push(Arc::new(symbol));
                }
                for owner in owners {
                    let key = CompositionGroupKey {
                        language: owner.language,
                        module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                        identity: owner.qualified_name,
                    };
                    id_keys.insert(self.owner_group_key(&key, open, realm));
                }
            }
            // A discovery that saw an open part is incomplete and is not retained.
            if !has_orphan && open.get().is_none() {
                self.retain_discovery(lookup, id_keys.iter().cloned().collect(), realm);
            }
            keys.extend(id_keys);
        }
        (keys, result)
    }

    fn project_groups(
        &self,
        keys: impl IntoIterator<Item = CompositionGroupKey>,
        mut result: Vec<Arc<SemanticModelSymbol>>,
        open: &LookupOpen,
    ) -> Vec<Arc<SemanticModelSymbol>> {
        for key in keys {
            if let Some(group) = self.lookup_group(&key, open) {
                result.extend(group.symbols.into_iter().map(Arc::new));
            }
        }
        result.sort_by(|a, b| composition::symbol_source_order(a, b));
        result
    }
    fn symbols_for_ids(
        &self,
        ids: &[String],
        open: &LookupOpen,
        realm: Option<&str>,
    ) -> Vec<Arc<SemanticModelSymbol>> {
        let (keys, orphans) = self.discover_ids(ids, open, realm);
        self.project_groups(keys, orphans, open)
    }
    fn symbols_for_lookup(
        &self,
        lookup: CompositionLookup,
        ids: impl FnOnce(&LookupOpen) -> Vec<String>,
        realm: Option<&str>,
    ) -> LookupRows {
        let open = LookupOpen::default();
        if let Some(keys) = self.discovered(&lookup, realm) {
            let rows = self.project_groups(keys.iter().cloned(), Vec::new(), &open);
            return (rows, open.get());
        }
        let (keys, orphans) = self.discover_ids(&ids(&open), &open, realm);
        // A lookup that saw an open part is incomplete and is not retained.
        if orphans.is_empty() && open.get().is_none() {
            self.retain_discovery(lookup, keys.iter().cloned().collect(), realm);
        }
        let rows = self.project_groups(keys, orphans, &open);
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
        let reads = self.reads_for_realm(realm);
        lookup_question(
            open,
            &reads,
            statement_name,
            key,
            reads.raw_rows_for_overlay(statement, params, &self.active.shards, |row| {
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
                let mut ids = Vec::new();
                for (label, sql) in [
                    ("TYPE_SPELLINGS", questions::TYPE_SPELLINGS),
                    ("MEMBER_SPELLINGS", questions::MEMBER_SPELLINGS),
                    ("MEMBER_ALIASES", questions::MEMBER_ALIASES),
                ] {
                    ids.extend(self.candidate_ids(
                        open,
                        label,
                        sql,
                        name,
                        named_params! { ":name": name },
                        realm,
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
                        ids.extend(self.candidate_ids(
                            open,
                            label,
                            sql,
                            (owner, member),
                            named_params! { ":owner_name": owner, ":member": member },
                            realm,
                        ));
                    }
                    ids.extend(self.candidate_ids(
                        open,
                        "MEMBERS_BY_OWNER_NAME",
                        questions::MEMBERS_BY_OWNER_NAME,
                        (owner, member),
                        named_params! { ":owner": owner, ":name": member },
                        realm,
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
        let open = LookupOpen::default();
        let rows = self
            .symbols_for_ids(&[id.to_owned()], &open, realm)
            .into_iter()
            .filter(|s| s.id == id || s.semantic_contributors.iter().any(|c| c.record_id == id))
            .collect();
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
        realm: Option<&str>,
    ) -> Option<Vec<SearchCandidate>> {
        let reads = self.reads_for_realm(realm);
        let shards = self.active.shards.iter().filter(|s| s.decoded.is_none() && realm.is_none_or(|realm| brokk_bifrost_core::analyzer::model::semantic_pack_realm(&s.manifest.language) == realm)).map(|s| {
            let identity = s.row_store.expect("row shard has catalog identity");
            let source = match identity.database {
                crate::analyzer::store::active_models::CatalogShardDatabase::Durable => "durable",
                crate::analyzer::store::active_models::CatalogShardDatabase::Session => "session",
            };
            serde_json::json!({"source_db":source,"shard_key":identity.shard_key,"digest":s.manifest.semantic_sha256})
        }).collect::<Vec<_>>();
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        let mut candidates: Vec<SearchCandidate> = Vec::new();
        semantic_catalog_question("SEARCH_ORDERED_CANDIDATES", self.active.active_model_set_hash(),
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
            .active
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

    fn candidate_inputs<'a>(
        &'a self,
        cancellation: Option<&crate::CancellationToken>,
        realm: Option<&str>,
    ) -> Option<(Vec<SearchCandidate>, Vec<&'a SemanticModelSymbol>)> {
        let has_candidates = self.active.shards.iter().any(|s| {
            realm.is_none_or(|realm| {
                brokk_bifrost_core::analyzer::model::semantic_pack_realm(&s.manifest.language)
                    == realm
            }) && s.decoded.is_none()
                && s.descriptor.payload_kind
                    == crate::analyzer::semantic_model::PayloadKind::DeclarationFacts
        }) || self.generated.iter().any(|s| {
            self.row_language(&s.language)
                && realm.is_none_or(|realm| {
                    brokk_bifrost_core::analyzer::model::semantic_pack_realm(&s.language) == realm
                })
        });
        if !has_candidates {
            return Some((Vec::new(), Vec::new()));
        }
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        let candidates = self.candidate_buffer(cancellation, realm)?;
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        Some((
            candidates,
            self.generated
                .iter()
                .filter(|s| {
                    self.row_language(&s.language)
                        && realm.is_none_or(|realm| {
                            brokk_bifrost_core::analyzer::model::semantic_pack_realm(&s.language)
                                == realm
                        })
                })
                .collect(),
        ))
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
        realm: Option<&str>,
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
            .active
            .shards
            .iter()
            .map(|shard| {
                (
                    shard.manifest.content_sha256.as_str(),
                    shard.manifest.semantic_sha256.as_str(),
                )
            })
            .collect::<HashMap<_, _>>();
        let reads = self.reads_for_realm(realm);
        semantic_catalog_question(
            "SEARCH_TYPES",
            self.active.active_model_set_hash(),
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
        let reads = self.reads_for_realm(realm);
        semantic_catalog_question(
            "SEARCH_OWNER_QUALIFICATIONS", self.active.active_model_set_hash(),
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
        let value = self.build_search_candidates(&candidates, &generated, cancellation, realm)?;
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
        let reads = self.reads_for_realm(realm);
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
                    &anchor_open,
                    &reads,
                    "TYPES_BY_ID",
                    seed,
                    reads.owner_symbols(&anchors, seed),
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
                        &anchor_open,
                        &reads,
                        "GROUP_OWNERS",
                        &key,
                        reads.group_owners(&anchors, &key),
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
                orphans.extend(self.symbols_for_ids(&[id.to_owned()], &anchor_open, realm));
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
    ) -> Option<composition::ComposedGroup> {
        let group = self.lookup_group(&candidates.key, open)?;
        if open.get().is_some() {
            return Some(group);
        }
        #[cfg(debug_assertions)]
        {
            let spellings = candidates.spellings().collect::<HashSet<_>>();
            debug_assert!(
                group
                    .symbols
                    .iter()
                    .all(|symbol| std::iter::once(&symbol.name)
                        .chain(std::iter::once(&symbol.qualified_name))
                        .chain(&symbol.aliases)
                        .all(|spelling| spellings.contains(spelling.as_str()))),
                "incomplete search spellings for {:?}: {:?}",
                candidates.key,
                group.symbols
            );
        }
        Some(group)
    }

    /// Enumerate complete groups through the shared store retention budget.
    pub(super) fn groups(
        &self,
        cancellation: Option<&crate::CancellationToken>,
    ) -> (
        Vec<composition::ComposedGroup>,
        Vec<Arc<SemanticModelSymbol>>,
        bool,
    ) {
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

    pub(super) fn search_symbols(
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
        for candidate in candidates {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            // A pack-local raw ID can also discover a different single-owner
            // closure. Only the matching multi/generated closures need compose.
            if composed_identities.contains(&(
                candidate.key.language.clone(),
                candidate.key.module_namespace,
                candidate.key.identity.clone(),
            )) && candidate
                .spellings()
                .any(|spelling| patterns.is_match(&spelling))
                && let Some(group) = self.compose_candidate_group(candidate, &anchor_open)
            {
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
        records.sort_by(|a, b| composition::symbol_source_order(a, b));
        records.dedup_by(|a, b| a == b);
        (records, complete)
    }

    pub(super) fn symbols(
        &self,
        cancellation: Option<&crate::CancellationToken>,
    ) -> (Vec<Arc<SemanticModelSymbol>>, bool) {
        let (groups, mut records, complete) = self.groups(cancellation);
        records.extend(groups.into_iter().flat_map(|g| g.symbols).map(Arc::new));
        records.sort_by(|a, b| composition::symbol_source_order(a, b));
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
            .into_iter()
            .flat_map(|g| g.diagnostics)
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
        let anchors = self.anchor_view_scoped(open, realm);
        let reads = self.reads_for_realm(realm);
        let mut relations = lookup_question(
            open,
            &reads,
            "RELATIONS_FROM/TYPES_BY_ID",
            origins,
            reads.relations_for_origins(&anchors, origins),
        );
        composition::freeze_relation_order(relations.iter_mut());
        let mut replacements = HashMap::default();
        let mut composed_owners = HashSet::default();
        let mut origin_identities = composition::OriginRewrites::default();
        for (family, id) in relations
            .iter()
            .flat_map(|r| {
                let family = brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                    &r.provenance.activation.matched_evidence.language,
                );
                [(family, &r.from), (family, &r.to)]
            })
            .collect::<HashSet<_>>()
        {
            let answer = semantic_catalog_question(
                "GROUP_OWNERS",
                id,
                reads.endpoint_representatives(&anchors, family, id),
            );
            open.note(reads.open_part());
            let (representative, origins) = match answer {
                Ok(answer) => answer,
                Err(part) => {
                    open.note(Some(part));
                    return Vec::new();
                }
            };
            for (pack, ids) in origins {
                origin_identities.entry(pack).or_default().extend(ids);
            }
            if representative.composed {
                composed_owners.insert((family.to_owned(), id.clone()));
            }
            replacements.extend(
                representative
                    .replacements
                    .into_iter()
                    .map(|(id, replacement)| ((family.to_owned(), id), replacement)),
            );
        }
        composition::rewrite_relations(
            relations.into_iter().enumerate().collect(),
            &replacements,
            &composed_owners,
            &origin_identities,
        )
        .into_iter()
        .map(|(_, r)| r)
        .collect()
    }

    fn row_relation(&self, relation: &SemanticModelRelation) -> bool {
        self.active.shards.iter().any(|s| {
            s.decoded.is_none() && s.manifest.semantic_sha256 == relation.provenance.pack_digest
        })
    }

    /// Activation-owner enumeration; conformance is its only production caller.
    /// Request-time relation queries use relations_from and relations_to.
    pub(super) fn relations(&self) -> Vec<Arc<SemanticModelRelation>> {
        let anchor_open = LookupOpen::default();
        let anchors = self.anchor_view(&anchor_open);
        anchor_open.assert_activation_owner("SOURCE_TYPES/SOURCE_MEMBERS");
        let (groups, _, complete) = self.groups(None);
        assert!(
            complete,
            "whole-overlay relation enumeration is activation-owner only; an open JVM part must not reach it"
        );
        let mut records = groups
            .into_iter()
            .flat_map(|g| g.relations.into_iter().map(|(_, r)| r))
            .collect::<Vec<_>>();
        let reads = self.reads();
        let mut origins = activation_owner_question(
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
            let owners = activation_owner_question(
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
        anchor_open.assert_activation_owner("RELATIONS");
        records.retain(|r| self.row_relation(r));
        records.sort_by(composition::relation_source_order);
        records.into_iter().map(Arc::new).collect()
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
        let reads = self.reads_for_realm(realm);
        let open = LookupOpen::default();
        let mut raw_ids = HashSet::from_iter([id.to_owned()]);
        let (symbols, part) = self.symbols_with_id_scoped(id, realm);
        open.note(part);
        for symbol in symbols {
            raw_ids.insert(symbol.id.clone());
            raw_ids.extend(
                symbol
                    .semantic_contributors
                    .iter()
                    .map(|p| p.record_id.clone()),
            );
        }
        let records = self
            .relations_for_origins(&reads, raw_ids, &open, realm)
            .into_iter()
            .filter(|r| r.from == id)
            .collect();
        (records, open.get())
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
            named_params! { ":raw_targets":serde_json::to_string(&raw_targets).expect("targets serialize") }, &self.active.shards,|row|row.get::<_,String>("from_id")))
            .into_iter().map(|r|Arc::unwrap_or_clone(r.record)).collect::<HashSet<_>>();
        origins.extend(
            self.generated_relations
                .iter()
                .filter(|r| raw_targets.contains(&r.to))
                .map(|r| r.from.clone()),
        );
        let records = self
            .relations_for_origins(&reads, origins, &open, realm)
            .into_iter()
            .filter(|r| r.to == id)
            .collect();
        (records, open.get())
    }

    fn relations_for_origins(
        &self,
        reads: &RowCompositionReads<'_>,
        origins: HashSet<String>,
        open: &LookupOpen,
        realm: Option<&str>,
    ) -> Vec<Arc<SemanticModelRelation>> {
        let anchors = self.anchor_view_scoped(open, realm);
        // A scoped lookup composes only its family's owners. The row owners
        // are read through the scoped reads already; a generated owner, or a
        // group key, of another family would compose through that family's
        // owner (for a JVM one, binding the JVM request owner).
        let in_realm = |language: &str| {
            realm.is_none_or(|realm| {
                brokk_bifrost_core::analyzer::model::semantic_pack_realm(language) == realm
            })
        };
        let mut keys = HashSet::default();
        let mut standalone = HashSet::default();
        for id in &origins {
            let mut owners = lookup_question(
                open,
                reads,
                "TYPES_BY_ID",
                id,
                reads.owner_symbols(&anchors, id),
            );
            owners.extend(
                self.generated
                    .iter()
                    .filter(|s| s.owner_id.is_none() && &s.id == id && in_realm(&s.language))
                    .cloned(),
            );
            owners.retain(|owner| in_realm(&owner.language));
            owners.sort_by(composition::symbol_source_order);
            if owners.is_empty() {
                standalone.insert(id.clone());
            }
            for owner in owners {
                let key = CompositionGroupKey {
                    language: owner.language.clone(),
                    module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                    identity: owner.qualified_name.clone(),
                };
                keys.insert(self.owner_group_key(&key, open, realm));
            }
        }
        let mut records = self.rewritten_standalone_relations(&standalone, open, realm);
        for key in keys {
            let Some(group) = self.lookup_group(&key, open) else {
                continue;
            };
            records.extend(
                group
                    .relations
                    .into_iter()
                    .map(|(_, r)| r)
                    .filter(|r| origins.contains(semantic_relation_source_key(r).0)),
            );
        }
        records.retain(|r| self.row_relation(r));
        records.sort_by(composition::relation_source_order);
        records.into_iter().map(Arc::new).collect()
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
            self.active.active_model_set_hash(),
            reads.raw_rows_for_overlay(statement, bindings, &self.active.shards, |row| {
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
                    .active
                    .shards
                    .iter()
                    .position(|s| Arc::ptr_eq(&s.metadata, &r.shard))
                    .expect("row belongs to publication");
                self.active.shards[index]
                    .decoded
                    .is_none()
                    .then(|| ((index, r.record.0), Arc::clone(&r.record.1)))
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|(index, _)| *index);
        records
            .into_iter()
            .map(|((index, _), r)| (Arc::clone(&self.active.shards[index]), r))
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
            self.active
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
                    &self.active,
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
                    &self.active,
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
                    &self.active,
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
        activation_owner_rows("RUNTIME_VALUES", self.active.runtime_values())
            .into_iter()
            .filter(|(_, shard)| shard.decoded.is_none())
            .map(|(payload, shard)| {
                Arc::new(RuntimeValueContracts {
                    provenance: Arc::new(provenance(
                        &self.active,
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
                &self.active.shards,
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
                    .active
                    .shards
                    .iter()
                    .position(|s| Arc::ptr_eq(&s.metadata, &r.shard))
                    .expect("selected exposure metadata");
                let shard = &self.active.shards[index];
                (shard.decoded.is_none() && r.record.1.languages.iter().any(|l| l == language))
                    .then(|| {
                        (
                            (index, r.record.0),
                            Arc::clone(&r.record.1),
                            Arc::new(provenance(
                                &self.active,
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
