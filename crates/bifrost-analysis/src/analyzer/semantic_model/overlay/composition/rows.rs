//! Query-local catalog reads for one composition group. No decoded payloads.

use super::*;
use crate::analyzer::store::active_models::resolve_records;
use crate::analyzer::store::model_catalog::CatalogRowReader;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements as questions;
use brokk_bifrost_semantic::analyzer::semantic_model::runtime::FamilyOpen;
use rusqlite::{ToSql, named_params};
use std::cell::{Cell, OnceCell};

/// Admit only relations owned by an active row-backed pack.
pub(in crate::analyzer::semantic_model::overlay) fn admits_row_relation(
    shard: &ActiveSemanticModelShard,
    digest: &str,
) -> bool {
    shard.decoded.is_none() && shard.manifest.semantic_sha256 == digest
}

/// Connection-only outside reads; generated symbols belong to this overlay
/// build, and are included by the group loader and keyed identity checks.
pub struct RowCompositionReads<'a> {
    pub selection: Option<&'a ModelProviderSelection>,
    pub defining_owner: Option<&'a SemanticModelProvenance>,
    pub active: &'a ResolvedActiveSemanticModels,
    pub activation: Arc<dyn CatalogRowReader + Send + Sync>,
    jvm: OnceCell<Result<Arc<dyn CatalogRowReader + Send + Sync>, FamilyOpen>>,
    pub generated: &'a [SemanticModelSymbol],
    pub generated_relations: &'a [SemanticModelRelation],
    activation_only: bool,
    anchors: Option<&'a locations::SourceAnchors>,
    scope: Option<CompositionScope>,
    search_generated_relations: Option<Vec<usize>>,
    open: Cell<Option<FamilyOpen>>,
    pub(in crate::analyzer::semantic_model::overlay) cancellation: Option<crate::CancellationToken>,
}

pub(in crate::analyzer::semantic_model::overlay) const SEARCH_OWNER_IDS_FOR_GROUPS: &str = "WITH requested AS MATERIALIZED (SELECT CAST(key AS INTEGER) AS position, value FROM json_each(:groups)),
             selected_names AS MATERIALIZED (
             SELECT 'durable' AS source_db,n.shard_key,n.record_key,q.position
             FROM requested q CROSS JOIN main.catalog_declaration_names n INDEXED BY catalog_declaration_names_lookup
             ON n.name=json_extract(q.value,'$[2]') AND n.language=json_extract(q.value,'$[0]')
             AND n.namespace=json_extract(q.value,'$[1]') AND n.identity_name=1
             UNION ALL
             SELECT 'session' AS source_db,n.shard_key,n.record_key,q.position
             FROM requested q CROSS JOIN session.catalog_declaration_names n INDEXED BY catalog_declaration_names_lookup
             ON n.name=json_extract(q.value,'$[2]') AND n.language=json_extract(q.value,'$[0]')
             AND n.namespace=json_extract(q.value,'$[1]') AND n.identity_name=1)
             SELECT t.source_db,t.shard_key,t.record_key,t.record_id,n.position
             FROM selected_names n CROSS JOIN active_catalog_declaration_types t
             ON t.source_db=n.source_db AND t.shard_key=n.shard_key AND t.record_key=n.record_key";

type OwnerQualifications = std::cell::RefCell<HashMap<(Option<String>, String), Option<String>>>;

/// Resolved SQL and generated-fact selection for one composition read.
///
/// This value contains no realm. Callers resolve a language or realm once;
/// readers then consume only these explicit inputs. It is request-local and
/// does not retain a catalog reader or a cache entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::analyzer::semantic_model::overlay) struct CompositionScope {
    languages: Vec<String>,
    shard_keys: String,
    shard_selection: Vec<(String, i64)>,
    request_owner: bool,
}

impl CompositionScope {
    fn accepts(&self, language: &str) -> bool {
        self.languages
            .binary_search_by(|candidate| candidate.as_str().cmp(language))
            .is_ok()
    }
}

/// Canonical, process-local inputs selected by a composition scope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(in crate::analyzer::semantic_model::overlay) struct CompositionScopeIdentity {
    shards: Vec<(String, i64, String, bool)>,
    // The build identity pins generated contents; this selects their languages.
    generated_languages: Vec<String>,
    // Positions are relative to the immutable generated facts pinned by the build.
    generated_relations: Vec<usize>,
    request_owner: bool,
    generated_contents: Vec<String>,
    relation_contents: Vec<String>,
    anchors: Option<String>,
}

impl<'a> RowCompositionReads<'a> {
    pub(in crate::analyzer::semantic_model::overlay) fn canonical_identity(
        &self,
    ) -> CompositionScopeIdentity {
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        let selected: Option<HashSet<(String, i64)>> = self.scope.as_ref().map(|scope| {
            serde_json::from_str(&scope.shard_keys).expect("scope contains SQL shard keys")
        });
        let mut shards = self
            .active
            .shards
            .iter()
            .filter_map(|shard| {
                let id = shard.row_store?;
                let database = match id.database {
                    CatalogShardDatabase::Durable => "durable",
                    CatalogShardDatabase::Session => "session",
                }
                .to_owned();
                if selected
                    .as_ref()
                    .is_some_and(|keys| !keys.contains(&(database.clone(), id.shard_key)))
                {
                    return None;
                }
                Some((
                    database,
                    id.shard_key,
                    shard.manifest.semantic_sha256.clone(),
                    self.includes_request_owner() && shard.request_owned(),
                ))
            })
            .collect::<Vec<_>>();
        shards.sort_unstable();
        let mut generated_languages = self
            .generated_symbols()
            .map(|symbol| symbol.language.clone())
            .collect::<Vec<_>>();
        generated_languages.sort_unstable();
        generated_languages.dedup();
        CompositionScopeIdentity {
            shards,
            generated_languages,
            generated_relations: self
                .selected_generated_edges()
                .map(|(index, _)| index)
                .collect(),
            request_owner: self.includes_request_owner(),
            generated_contents: self
                .generated_symbols()
                .map(|symbol| format!("{symbol:?}"))
                .collect(),
            relation_contents: self
                .generated_edges()
                .map(|relation| format!("{relation:?}"))
                .collect(),
            anchors: self.anchors.map(locations::SourceAnchors::digest),
        }
    }

    /// Select the row candidate stream without applying search-fill relevance.
    /// Enumeration uses this selection and retains its own readers for hydration.
    pub(in crate::analyzer::semantic_model::overlay) fn for_row_candidates(mut self) -> Self {
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        let mut keys = self
            .active
            .shards
            .iter()
            .filter(|shard| {
                admits_row_relation(shard, &shard.manifest.semantic_sha256)
                    && self.accepts_language(&shard.manifest.language)
                    && self.selects_active_shard(shard)
            })
            .map(|shard| {
                let id = shard.row_store.expect("selected row shard has identity");
                let source = match id.database {
                    CatalogShardDatabase::Durable => "durable",
                    CatalogShardDatabase::Session => "session",
                };
                (source.to_owned(), id.shard_key)
            })
            .collect::<Vec<_>>();
        keys.sort_unstable();
        let mut languages = self
            .active
            .shards
            .iter()
            .map(|shard| shard.manifest.language.clone())
            .chain(self.generated.iter().map(|symbol| symbol.language.clone()))
            .filter(|language| self.accepts_language(language))
            .collect::<Vec<_>>();
        languages.sort_unstable();
        languages.dedup();
        self.scope = Some(CompositionScope {
            shard_keys: serde_json::to_string(&keys).expect("shard identities serialize"),
            shard_selection: keys,
            languages,
            request_owner: self.includes_request_owner(),
        });
        self
    }

    /// Resolve relevance once, before either the backing key or fill is used.
    /// Nested language reads intersect this same physical shard selection.
    pub(in crate::analyzer::semantic_model::overlay) fn for_search(mut self) -> ReadResult<Self> {
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::search_fill_relevance_statement;
        check_composition_cancellation(self.cancellation.as_ref())?;
        self = self.for_row_candidates();
        let default_cancellation = crate::CancellationToken::new();
        let cancellation = self.cancellation.as_ref().unwrap_or(&default_cancellation);
        let statement = search_fill_relevance_statement();
        let mut cache = self
            .active
            .search_fill_relevance
            .lock()
            .expect("search relevance mutex poisoned");
        let mut keys = Vec::new();
        for shard in &self.active.shards {
            check_composition_cancellation(Some(cancellation))?;
            let Some(id) = shard.row_store else { continue };
            let source = match id.database {
                CatalogShardDatabase::Durable => "durable",
                CatalogShardDatabase::Session => "session",
            };
            if !self.selects_shard(source, id.shard_key) {
                continue;
            }
            let relevant = if let Some(bit) = cache.get(&shard.descriptor.semantic_sha256) {
                *bit
            } else {
                let reader: &dyn CatalogRowReader = if self.active.activation_owns(shard) {
                    self.activation.as_ref()
                } else {
                    self.jvm_reader()?
                        .ok_or_else(|| {
                            CatalogError::FamilyOpen(
                                self.open_part()
                                    .expect("unavailable unscoped owner records its open part"),
                            )
                        })?
                        .as_ref()
                };
                let rows = reader.owned_rows(
                    &statement,
                    named_params! { ":source_db": source, ":shard_key": id.shard_key },
                    cancellation,
                )?;
                check_composition_cancellation(Some(cancellation))?;
                assert_eq!(rows.rows.len(), 1, "relevance query returns one scalar");
                let bit = rows
                    .iter()
                    .next()
                    .expect("one relevance row")
                    .get::<_, bool>("relevant")
                    .map_err(|error| CatalogError::sqlite("read search fill relevance", error))?;
                cache.insert(shard.descriptor.semantic_sha256.clone(), bit);
                bit
            };
            if relevant {
                keys.push((source, id.shard_key));
            }
        }
        let languages = self
            .scope
            .as_ref()
            .expect("candidate scope selected")
            .languages
            .clone();
        keys.sort_unstable();
        // Decoded generated relations belong to the eager overlay. Select the
        // row overlay's generated relation positions once, independently of
        // physical row relevance (rule-only shards have no declaration rows).
        self.search_generated_relations = Some(
            self.selected_generated_edges()
                .filter(|(_, relation)| {
                    self.active.shards.iter().any(|shard| {
                        shard.decoded.is_none()
                            && shard.manifest.semantic_sha256 == relation.provenance.pack_digest
                    })
                })
                .map(|(index, _)| index)
                .collect(),
        );
        self.scope = Some(CompositionScope {
            shard_selection: keys
                .iter()
                .map(|(source, key)| ((*source).to_owned(), *key))
                .collect(),
            languages,
            shard_keys: serde_json::to_string(&keys).expect("shard identities serialize"),
            request_owner: self.includes_request_owner(),
        });
        Ok(self)
    }

    pub(in crate::analyzer::semantic_model::overlay) fn selects_active_shard(
        &self,
        shard: &crate::analyzer::store::active_models::ActiveSemanticModelShard,
    ) -> bool {
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        shard.row_store.is_some_and(|id| {
            let source = match id.database {
                CatalogShardDatabase::Durable => "durable",
                CatalogShardDatabase::Session => "session",
            };
            self.selects_shard(source, id.shard_key)
        })
    }

    pub(in crate::analyzer::semantic_model::overlay) fn selects_shard(
        &self,
        source: &str,
        key: i64,
    ) -> bool {
        self.scope.as_ref().is_none_or(|scope| {
            scope
                .shard_selection
                .binary_search_by(|(database, shard)| {
                    database.as_str().cmp(source).then_with(|| shard.cmp(&key))
                })
                .is_ok()
        })
    }

    pub(in crate::analyzer::semantic_model::overlay) fn with_anchors(
        mut self,
        anchors: &'a locations::SourceAnchors,
    ) -> Self {
        self.anchors = Some(anchors);
        self
    }

    pub(in crate::analyzer::semantic_model::overlay) fn anchors(
        &self,
    ) -> Option<&'a locations::SourceAnchors> {
        self.anchors
    }

    fn admits_provenance(&self, provenance: &SemanticModelProvenance) -> bool {
        let provider = ModelProvider::from(provenance);
        self.selection
            .is_none_or(|selection| selection.contains(&provider))
            && super::admits_defining_owner(
                self.defining_owner,
                &provider,
                provenance.extraction.as_ref(),
            )
    }

    pub fn new(
        active: &'a ResolvedActiveSemanticModels,
        generated: &'a [SemanticModelSymbol],
        generated_relations: &'a [SemanticModelRelation],
    ) -> Self {
        Self {
            selection: None,
            defining_owner: None,
            active,
            activation: active
                .source_reader
                .as_ref()
                .expect("row-backed set has activation reader")
                .clone(),
            jvm: OnceCell::new(),
            generated,
            generated_relations,
            activation_only: false,
            anchors: None,
            scope: None,
            search_generated_relations: None,
            open: Cell::new(None),
            cancellation: crate::analyzer::i_analyzer::current_query_cancellation(),
        }
    }

    /// Build-time composition reads only activation-owned rows and never opens a request reader.
    pub fn activation_only(
        active: &'a ResolvedActiveSemanticModels,
        generated: &'a [SemanticModelSymbol],
        generated_relations: &'a [SemanticModelRelation],
    ) -> Self {
        let mut reads = Self::new_without_request(active, generated, generated_relations);
        reads.activation_only = true;
        reads
    }

    fn new_without_request(
        active: &'a ResolvedActiveSemanticModels,
        generated: &'a [SemanticModelSymbol],
        generated_relations: &'a [SemanticModelRelation],
    ) -> Self {
        let activation = active
            .source_reader
            .as_ref()
            .expect("row-backed set has activation reader")
            .clone();
        Self {
            selection: None,
            defining_owner: None,
            active,
            activation: activation.clone(),
            jvm: OnceCell::new(),
            generated,
            generated_relations,
            activation_only: true,
            anchors: None,
            scope: None,
            search_generated_relations: None,
            open: Cell::new(None),
            cancellation: crate::analyzer::i_analyzer::current_query_cancellation(),
        }
    }

    /// Scope every outside read before decoding. The reader's full metadata
    /// slice still matches its immutable active views; SQL selects only this
    /// language's physical shard identities, as established by their manifests.
    pub(in crate::analyzer::semantic_model::overlay) fn for_language<'b>(
        &self,
        language: &str,
    ) -> RowCompositionReads<'b>
    where
        'a: 'b,
    {
        self.for_scope(
            Some(language),
            brokk_bifrost_core::analyzer::model::semantic_pack_realm(language),
        )
    }

    pub(in crate::analyzer::semantic_model::overlay) fn for_realm<'b>(
        &self,
        realm: &str,
    ) -> RowCompositionReads<'b>
    where
        'a: 'b,
    {
        self.for_scope(None, realm)
    }

    fn composition_scope(&self, language: Option<&str>, realm: &str) -> CompositionScope {
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        let mut languages = self
            .active
            .shards
            .iter()
            .map(|shard| shard.manifest.language.as_str())
            .chain(self.generated.iter().map(|symbol| symbol.language.as_str()))
            .filter(|candidate| {
                language.map_or_else(
                    || brokk_bifrost_core::analyzer::model::semantic_pack_realm(candidate) == realm,
                    |language| *candidate == language,
                )
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        languages.sort_unstable();
        let mut shards = self
            .active
            .shards
            .iter()
            .filter(|shard| {
                if self.activation_only && !self.active.activation_owns(shard) {
                    return false;
                }
                let provider = ModelProvider {
                    pack_id: shard.manifest.pack_id.clone(),
                    pack_version: shard.manifest.version.clone(),
                    pack_digest: shard.manifest.semantic_sha256.clone(),
                };
                language.map_or_else(
                    || {
                        brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                            &shard.manifest.language,
                        ) == realm
                    },
                    |language| shard.manifest.language == language,
                ) && self
                    .selection
                    .is_none_or(|selection| selection.contains(&provider))
                    && super::admits_defining_owner(
                        self.defining_owner,
                        &provider,
                        shard.extraction(),
                    )
            })
            .map(|shard| {
                shard
                    .row_store
                    .expect("catalog group shard has row identity")
            })
            .map(|identity| {
                (
                    match identity.database {
                        CatalogShardDatabase::Durable => "durable",
                        CatalogShardDatabase::Session => "session",
                    },
                    identity.shard_key,
                )
            })
            .filter(|(source, key)| self.selects_shard(source, *key))
            .collect::<Vec<_>>();
        shards.sort_unstable();
        CompositionScope {
            shard_selection: shards
                .iter()
                .map(|(source, key)| ((*source).to_owned(), *key))
                .collect(),
            languages,
            shard_keys: serde_json::to_string(&shards).expect("shard identities serialize"),
            request_owner: realm == "jvm",
        }
    }

    fn for_scope<'b>(&self, language: Option<&str>, realm: &str) -> RowCompositionReads<'b>
    where
        'a: 'b,
    {
        self.for_composition_scope(self.composition_scope(language, realm))
    }

    pub(in crate::analyzer::semantic_model::overlay) fn for_composition_scope<'b>(
        &self,
        scope: CompositionScope,
    ) -> RowCompositionReads<'b>
    where
        'a: 'b,
    {
        RowCompositionReads {
            selection: self.selection,
            defining_owner: self.defining_owner,
            active: self.active,
            activation: Arc::clone(&self.activation),
            jvm: self.jvm.clone(),
            generated: self.generated,
            generated_relations: self.generated_relations,
            activation_only: self.activation_only,
            anchors: self.anchors,
            cancellation: self.cancellation.clone(),
            scope: Some(scope),
            search_generated_relations: self.search_generated_relations.clone(),
            open: Cell::new(None),
        }
    }

    pub fn open_part(&self) -> Option<FamilyOpen> {
        self.open.get()
    }

    /// The JVM owner, bound on the first read that can return JVM rows: an
    /// unscoped read or one scoped to a JVM-realm language. A read scoped to
    /// another language never binds it. The bind happens even when the
    /// activation holds no request-owned shard, because binding is also how
    /// the request's JVM selection is checked against the activation: a
    /// request that selects shards the activation lacks answers Open.
    fn jvm_reader(&self) -> ReadResult<Option<&Arc<dyn CatalogRowReader + Send + Sync>>> {
        if self.activation_only
            || self
                .scope
                .as_ref()
                .is_some_and(|scope| !scope.request_owner)
        {
            return Ok(None);
        }
        match self.jvm.get_or_init(|| {
            self.active
                .request_source()
                .map(|source| source.jvm_reader(self.active).map(|owner| owner.reader))
                .unwrap_or_else(|| Ok(Arc::clone(&self.activation)))
        }) {
            Ok(reader) => Ok(Some(reader)),
            Err(open) if self.scope.is_none() => {
                self.open.set(Some(
                    self.open
                        .get()
                        .map_or(*open, |previous| previous.merge(*open)),
                ));
                Ok(None)
            }
            Err(open) => Err(CatalogError::FamilyOpen(*open)),
        }
    }

    /// The distinct JVM owner's part of a statement. For an unscoped read its
    /// failure is recorded as the open part and the other owners' rows stand,
    /// exactly as when binding the owner fails (see `jvm_reader`): the open
    /// part then marks every record a candidate. A read scoped to the JVM
    /// family fails as a whole.
    fn jvm_owner_part<T>(&self, result: ReadResult<T>) -> ReadResult<Option<T>> {
        let open = match result {
            Ok(value) => return Ok(Some(value)),
            Err(error) if self.scope.is_some() => return Err(error),
            Err(CatalogError::FamilyOpen(open)) => open,
            Err(CatalogError::Cancelled) => FamilyOpen::jvm_cancelled(),
            Err(error) => return Err(error),
        };
        self.open.set(Some(
            self.open
                .get()
                .map_or(open, |previous| previous.merge(open)),
        ));
        Ok(None)
    }

    fn generated_symbols(&self) -> impl Iterator<Item = &SemanticModelSymbol> {
        self.generated.iter().filter(|symbol| {
            self.admits_provenance(&symbol.provenance)
                && self
                    .scope
                    .as_ref()
                    .is_none_or(|scope| scope.accepts(&symbol.language))
        })
    }

    pub(in crate::analyzer::semantic_model::overlay) fn accepts_language(
        &self,
        language: &str,
    ) -> bool {
        self.scope
            .as_ref()
            .is_none_or(|scope| scope.accepts(language))
    }

    pub(in crate::analyzer::semantic_model::overlay) fn includes_request_owner(&self) -> bool {
        !self.activation_only && self.scope.as_ref().is_none_or(|scope| scope.request_owner)
    }

    fn generated_edges(&self) -> impl Iterator<Item = &SemanticModelRelation> {
        self.selected_generated_edges()
            .map(|(_, relation)| relation)
    }

    fn selected_generated_edges(&self) -> impl Iterator<Item = (usize, &SemanticModelRelation)> {
        self.generated_relations
            .iter()
            .enumerate()
            .filter(|(index, relation)| {
                self.search_generated_relations
                    .as_ref()
                    .is_none_or(|selected| selected.binary_search(index).is_ok())
                    && self.admits_provenance(&relation.provenance)
                    && self.scope.as_ref().is_none_or(|scope| {
                        self.active.shards.iter().any(|shard| {
                            scope.accepts(&shard.manifest.language)
                                && shard.manifest.semantic_sha256 == relation.provenance.pack_digest
                        })
                    })
            })
    }

    pub(in crate::analyzer::semantic_model::overlay) fn raw_rows_for_overlay<T>(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
        _shards: &[Arc<crate::analyzer::store::active_models::ActiveSemanticModelShard>],
        decode: impl Fn(
            &crate::analyzer::store::model_catalog::OwnedCatalogRow<'_>,
        ) -> rusqlite::Result<T>,
    ) -> ReadResult<Vec<crate::analyzer::store::model_catalog::CatalogRawRecord<T>>> {
        self.raw_rows(statement, params, decode)
    }

    fn has_activation_shards(&self) -> bool {
        self.active
            .shards
            .iter()
            .any(|shard| self.active.activation_owns(shard))
    }

    pub(in crate::analyzer::semantic_model::overlay) fn scalar_question<T>(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
        mut decode: impl FnMut(
            &crate::analyzer::store::model_catalog::OwnedCatalogRow<'_>,
        ) -> rusqlite::Result<T>,
    ) -> ReadResult<Vec<T>> {
        let mut rows = if self.has_activation_shards() {
            (self.activation.as_ref() as &dyn CatalogRowReader).scalar_question(
                statement,
                params,
                &mut decode,
            )?
        } else {
            Vec::new()
        };
        if let Some(jvm) = self.jvm_reader()?
            && Arc::as_ptr(jvm) as *const () != Arc::as_ptr(&self.activation) as *const ()
            && let Some(request_rows) = self.jvm_owner_part(
                (jvm.as_ref() as &dyn CatalogRowReader).scalar_question(statement, params, decode),
            )?
        {
            rows.extend(request_rows);
        }
        Ok(rows)
    }

    pub(in crate::analyzer::semantic_model::overlay) fn visit_owned_rows(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
        cancellation: Option<&crate::CancellationToken>,
        mut visit: impl FnMut(
            &crate::analyzer::store::model_catalog::OwnedCatalogRow<'_>,
        ) -> rusqlite::Result<bool>,
    ) -> ReadResult<()> {
        check_composition_cancellation(cancellation)?;
        let scoped_statement = self
            .scope
            .as_ref()
            .map(|_| scoped_catalog_statement(statement));
        let mut scoped_params = params.to_vec();
        if let Some(scope) = &self.scope {
            scoped_params.push((":composition_shards", &scope.shard_keys));
        }
        let statement = scoped_statement.as_deref().unwrap_or(statement);
        let params = scoped_params.as_slice();
        if self.has_activation_shards() {
            (self.activation.as_ref() as &dyn CatalogRowReader).visit_owned_rows(
                statement,
                params,
                cancellation,
                &mut visit,
            )?;
        }
        if let Some(jvm) = self.jvm_reader()?
            && Arc::as_ptr(jvm) as *const () != Arc::as_ptr(&self.activation) as *const ()
        {
            self.jvm_owner_part((jvm.as_ref() as &dyn CatalogRowReader).visit_owned_rows(
                statement,
                params,
                cancellation,
                visit,
            ))?;
        }
        Ok(())
    }

    fn raw_rows<T>(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
        decode: impl Fn(
            &crate::analyzer::store::model_catalog::OwnedCatalogRow<'_>,
        ) -> rusqlite::Result<T>,
    ) -> ReadResult<Vec<crate::analyzer::store::model_catalog::CatalogRawRecord<T>>> {
        check_composition_cancellation(self.cancellation.as_ref())?;
        let scoped_statement = self
            .scope
            .as_ref()
            .map(|_| scoped_catalog_statement(statement));
        let mut scoped_params = params.to_vec();
        if let Some(scope) = &self.scope {
            scoped_params.push((":composition_shards", &scope.shard_keys));
        }
        let statement = scoped_statement.as_deref().unwrap_or(statement);
        let params = scoped_params.as_slice();
        let jvm = if self
            .scope
            .as_ref()
            .is_some_and(|scope| !scope.request_owner)
        {
            None
        } else {
            self.jvm_reader()?
        };
        let distinct = jvm.is_some_and(|reader| {
            Arc::as_ptr(reader) as *const () != Arc::as_ptr(&self.activation) as *const ()
        });
        // An owner-scoped source read puts one reader in both slots. Read it
        // once even for request-only shards; distinct and placeholder readers
        // still skip an activation connection that owns no shards.
        let mut rows = if self.has_activation_shards()
            || (jvm.is_some()
                && !distinct
                && self
                    .active
                    .shards
                    .iter()
                    .any(|shard| !self.active.activation_owns(shard)))
        {
            (self.activation.as_ref() as &dyn CatalogRowReader).raw_rows(
                statement,
                params,
                &self.active.shards,
                &decode,
            )?
        } else {
            Vec::new()
        };
        if distinct
            && let Some(request_rows) =
                self.jvm_owner_part(
                    (jvm.expect("distinct reader exists").as_ref() as &dyn CatalogRowReader)
                        .raw_rows(statement, params, &self.active.shards, decode),
                )?
        {
            rows.extend(request_rows);
        }
        Ok(rows)
    }

    fn records<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<T>>> {
        self.ordered_records(statement, params, |row| {
            let json: String = row.get("record_json")?;
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    row.column_index("record_json").expect("record JSON column"),
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
    }

    fn ordered_records<T>(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
        decode: impl Fn(
            &crate::analyzer::store::model_catalog::OwnedCatalogRow<'_>,
        ) -> rusqlite::Result<T>,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<T>>> {
        let mut rows = self
            .raw_rows(statement, params, |row| {
                Ok((row.get::<_, i64>("record_key")?, Arc::new(decode(row)?)))
            })?
            .into_iter()
            .map(|row| {
                let index = self
                    .active
                    .shards
                    .iter()
                    .position(|shard| Arc::ptr_eq(&shard.metadata, &row.shard))
                    .expect("selected row metadata");
                (
                    index,
                    row.record.0,
                    ActivatedSemanticModelRecord {
                        shard: Arc::clone(&self.active.shards[index]),
                        record: Arc::clone(&row.record.1),
                    },
                )
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            crate::analyzer::store::active_models::shard_record_order_key(
                &self.active.shards[left.0],
                left.1,
            )
            .cmp(
                &crate::analyzer::store::active_models::shard_record_order_key(
                    &self.active.shards[right.0],
                    right.1,
                ),
            )
        });
        rows.dedup_by(|left, right| {
            let left = crate::analyzer::store::active_models::shard_record_order_key(
                &self.active.shards[left.0],
                left.1,
            );
            let right = crate::analyzer::store::active_models::shard_record_order_key(
                &self.active.shards[right.0],
                right.1,
            );
            (left.3, left.4, left.5) == (right.3, right.4, right.5)
        });
        Ok(rows.into_iter().map(|(_, _, record)| record).collect())
    }

    pub(in crate::analyzer::semantic_model::overlay) fn types(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(self
            .records::<TypeFact>(statement, params)?
            .into_iter()
            .filter(|r| !r.shard.guard_excludes(r.record.guard.as_ref()))
            .collect())
    }

    fn members(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        Ok(self
            .records::<MemberFact>(statement, params)?
            .into_iter()
            .filter(|r| !r.shard.guard_excludes(r.record.guard.as_ref()))
            .collect())
    }

    /// Source-locator dependency candidates, including records whose published
    /// location fell back to a model URI. Equality and subtree range questions
    /// seek the catalog path indexes; no locator inventory is scanned.
    pub(in crate::analyzer::semantic_model::overlay) fn source_bindings_unchanged(
        &self,
        comparison: &locations::SourceAnchorComparison<'_>,
        paths: &[locations::LocatorPathQuery],
    ) -> ReadResult<bool> {
        let mut ids = std::collections::BTreeSet::new();
        for path in paths {
            let params = named_params! {
                ":ancestors": &path.ancestors_json,
                ":descendant_start": &path.descendant_start,
                ":descendant_end": &path.descendant_end,
            };
            ids.extend(
                self.types(questions::SOURCE_TYPES_TOUCHING_PATH, params)?
                    .into_iter()
                    .filter(|record| {
                        record.shard.decoded.is_none() && !record.shard.request_owned()
                    })
                    .map(|record| record.record.id.clone()),
            );
            ids.extend(
                self.members(questions::SOURCE_MEMBERS_TOUCHING_PATH, params)?
                    .into_iter()
                    .filter(|record| {
                        record.shard.decoded.is_none() && !record.shard.request_owned()
                    })
                    .map(|record| record.record.id.clone()),
            );
        }
        if ids.is_empty() {
            return Ok(self.open_part().is_none());
        }
        let ids = ids.into_iter().collect::<Vec<_>>();
        let projection = self.projection();
        projection.hydrate_ids(&ids)?;
        for id in ids {
            projection.symbols_with_id(comparison, &id)?;
            if !comparison.unchanged.get() {
                return Ok(false);
            }
        }
        Ok(self.open_part().is_none())
    }

    /// The activation owner's anchors, converted through the live analyzer:
    /// workspace declarations first, then the pack's carried sources.
    pub(crate) fn activation_source_anchors(
        &self,
        analyzer: &dyn IAnalyzer,
    ) -> ReadResult<locations::SourceAnchors> {
        self.owned_source_anchors(&self.activation, analyzer, |shard| !shard.request_owned())
    }

    /// The request owner's anchors. An external pack's record anchors only to
    /// a source the pack carries, never to a workspace declaration that shares
    /// its entry path and name, so no analyzer is needed.
    pub(crate) fn request_source_anchors(&self) -> ReadResult<locations::SourceAnchors> {
        let Some(reader) = self.jvm_reader()? else {
            if let Some(open) = self.open_part() {
                return Err(CatalogError::FamilyOpen(open));
            }
            return Ok(locations::SourceAnchors::default());
        };
        self.owned_source_anchors(reader, &locations::CarriedSourceLocations, |shard| {
            shard.request_owned()
        })
    }

    fn owned_source_anchors(
        &self,
        reader: &Arc<dyn CatalogRowReader + Send + Sync>,
        resolver: &(impl locations::SemanticModelLocations + ?Sized),
        owns: impl Fn(&crate::analyzer::store::active_models::ActiveSemanticModelShard) -> bool,
    ) -> ReadResult<locations::SourceAnchors> {
        // Read only the owning connection. Both may expose the same active
        // catalog views today, but the request owner will bind its own snapshot.
        let owner = RowCompositionReads {
            selection: self.selection,
            defining_owner: self.defining_owner,
            active: self.active,
            activation: Arc::clone(reader),
            jvm: OnceCell::from(Ok(Arc::clone(reader))),
            generated: self.generated,
            generated_relations: self.generated_relations,
            activation_only: self.activation_only,
            anchors: self.anchors,
            scope: self.scope.clone(),
            search_generated_relations: self.search_generated_relations.clone(),
            open: Cell::new(None),
            cancellation: self.cancellation.clone(),
        };
        let mut anchors = locations::SourceAnchors::default();
        let owners = owner
            .types(questions::SOURCE_TYPES, &[])?
            .into_iter()
            .filter(|r| r.shard.decoded.is_none() && owns(&r.shard))
            .map(|r| r.record.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let members = owner
            .members(questions::SOURCE_MEMBERS, &[])?
            .into_iter()
            .filter(|r| r.shard.decoded.is_none() && owns(&r.shard))
            .map(|r| r.record.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let projection = owner.projection();
        let ids = owners.union(&members).cloned().collect::<Vec<_>>();
        projection.hydrate_ids(&ids)?;
        for id in owners {
            for symbol in projection.owner_symbols(resolver, &id)? {
                if self.active.shards.iter().any(|shard| {
                    owns(shard) && shard.manifest.semantic_sha256 == symbol.provenance.pack_digest
                }) {
                    anchors.insert_symbol("type", symbol);
                }
            }
        }
        for id in members {
            for symbol in projection.member_symbols(resolver, &id)? {
                if self.active.shards.iter().any(|shard| {
                    owns(shard) && shard.manifest.semantic_sha256 == symbol.provenance.pack_digest
                }) {
                    anchors.insert_symbol("member", symbol);
                }
            }
        }
        Ok(anchors)
    }

    pub(in crate::analyzer::semantic_model::overlay) fn projection(&self) -> GroupProjection<'_> {
        GroupProjection::new(self)
    }
    pub(crate) fn owner_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        self.projection().owner_symbols(analyzer, id)
    }
    /// Every active symbol with this raw ID participates, across namespaces and
    /// languages. Exact JDK facets retain the shared whole-set exception.
    pub(crate) fn symbols_with_id(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        self.projection().symbols_with_id(analyzer, id)
    }
    pub(crate) fn owner_qualification(&self, realm: &str, id: &str) -> ReadResult<Option<String>> {
        self.projection().owner_qualification(Some(realm), id)
    }

    /// `owner_qualification` for many owners, in order. The owners' records are
    /// read with one set question before any is qualified, instead of one point
    /// read each. The caller bounds the number of owners per call.
    pub(in crate::analyzer::semantic_model::overlay) fn owner_qualifications(
        &self,
        owners: &[(String, String)],
    ) -> ReadResult<Vec<Option<String>>> {
        let projection = self.projection();
        let mut ids = owners.iter().map(|(_, id)| id.clone()).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        projection.hydrate_ids(&ids)?;
        owners
            .iter()
            .map(|(realm, id)| projection.owner_qualification(Some(realm), id))
            .collect()
    }

    /// Project only matched raw IDs. The two batch reads also supply every
    /// same-ID contributor for the existing selection and identity-conflict
    /// rules. Ordinary qualification comes from scalar rows; exceptional
    /// qualification is the same shared keyed read used by group projection.
    pub(crate) fn search_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        ids: &[String],
        owner_names: HashMap<(String, String), Option<String>>,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let projection = self.projection();
        *projection.owner_names.borrow_mut() = owner_names
            .into_iter()
            .map(|((realm, id), name)| ((Some(realm), id), name))
            .collect();
        let ids_json = serde_json::to_string(ids).expect("record IDs serialize");
        let mut types: HashMap<String, TypeRecords> =
            ids.iter().map(|id| (id.clone(), Vec::new())).collect();
        let mut members: HashMap<String, MemberRecords> =
            ids.iter().map(|id| (id.clone(), Vec::new())).collect();
        for record in self.types(questions::TYPES_BY_IDS, named_params! { ":ids": &ids_json })? {
            types
                .get_mut(&record.record.id)
                .expect("requested type ID")
                .push(record);
        }
        for record in self.members(
            questions::MEMBERS_BY_IDS,
            named_params! { ":ids": &ids_json },
        )? {
            members
                .get_mut(&record.record.id)
                .expect("requested member ID")
                .push(record);
        }
        *projection.types_by_id.borrow_mut() = types;
        *projection.members_by_id.borrow_mut() = members;
        let mut symbols = Vec::new();
        for id in ids {
            let mut same_id = projection.symbols_with_id(analyzer, id)?;
            mark_symbol_identity_conflicts(&mut same_id);
            symbols.extend(same_id);
        }
        freeze_symbol_order(&mut symbols);
        Ok(symbols)
    }
    pub fn group_owners(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        self.for_language(&key.language)
            .projection()
            .group_owners(analyzer, key)
    }
    pub fn group_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        self.for_language(&key.language)
            .projection()
            .group_symbols(analyzer, key)
    }
    pub(in crate::analyzer::semantic_model::overlay) fn endpoint_representatives(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        realm: &str,
        id: &str,
    ) -> ReadResult<(RepresentativeIdentity, OriginRewrites)> {
        self.projection()
            .endpoint_representatives(analyzer, None, realm, id)
    }
    pub fn group_relations(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        symbols: &[SemanticModelSymbol],
    ) -> ReadResult<Vec<SemanticModelRelation>> {
        let Some(symbol) = symbols.first() else {
            return Ok(Vec::new());
        };
        self.for_language(&symbol.language)
            .projection()
            .group_relations(analyzer, symbols)
    }
    pub(crate) fn relations_for_origins(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        ids: &HashSet<String>,
    ) -> ReadResult<Vec<SemanticModelRelation>> {
        let projection = self.projection();
        projection.hydrate_ids(&ids.iter().cloned().collect::<Vec<_>>())?;
        projection.relations_for_origins(analyzer, ids)
    }
    pub fn compose_group(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<ComposedGroup> {
        let mut composed =
            self.compose_groups(analyzer, &key.language, std::slice::from_ref(key))?;
        Ok(composed.pop().expect("one key, one group"))
    }

    /// The canonical key of the alias group of each seed, in order. The seeds
    /// are of `language`; one projection closes their spellings as set reads.
    pub(in crate::analyzer::semantic_model::overlay) fn group_keys_of(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        language: &str,
        seeds: &[CompositionGroupKey],
    ) -> ReadResult<Vec<CompositionGroupKey>> {
        let reads = self.for_language(language);
        let projection = reads.projection();
        projection.prepare_group_names(analyzer, seeds)?;
        seeds
            .iter()
            .map(|seed| {
                let owners = projection.group_owners(analyzer, seed)?;
                Ok(group_key(&owners.iter().collect::<Vec<_>>()))
            })
            .collect()
    }

    /// Whole groups of one language, composed together with one projection
    /// that is dropped before this returns, so the working set is the chunk.
    pub(in crate::analyzer::semantic_model::overlay) fn compose_groups(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        language: &str,
        keys: &[CompositionGroupKey],
    ) -> ReadResult<Vec<ComposedGroup>> {
        debug_assert!(keys.iter().all(|key| key.language == language));
        self.for_language(language)
            .projection()
            .compose_groups(analyzer, keys)
    }

    /// The symbols of every key's group, in key order. Each language of the
    /// chunk has one projection, prepared with set reads for all its groups and
    /// dropped before this returns, so the working set is the chunk.
    pub(in crate::analyzer::semantic_model::overlay) fn compose_groups_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        keys: &[CompositionGroupKey],
    ) -> ReadResult<Vec<ComposedSymbols>> {
        let mut languages = keys.iter().map(|key| &key.language).collect::<Vec<_>>();
        languages.sort_unstable();
        languages.dedup();
        let mut composed = (0..keys.len()).map(|_| None).collect::<Vec<_>>();
        for language in languages {
            let reads = self.for_language(language);
            let projection = reads.projection();
            let positions = (0..keys.len())
                .filter(|&position| keys[position].language == *language)
                .collect::<Vec<_>>();
            let group_keys = positions
                .iter()
                .map(|&position| keys[position].clone())
                .collect::<Vec<_>>();
            projection.prepare_group_keys(analyzer, &group_keys)?;
            for position in positions {
                composed[position] =
                    Some(projection.compose_group_symbols(analyzer, &keys[position])?);
            }
        }
        Ok(composed
            .into_iter()
            .map(|group| group.expect("every key has a language"))
            .collect())
    }
}

impl CompositionReads for RowCompositionReads<'_> {
    fn all_type_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        self.types(questions::TYPES_BY_ID, named_params! { ":id": id })
    }
    fn types_named(&self, name: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(resolve_records(FamilyRows::complete(self.types(
            questions::TYPES_BY_IDENTITY_NAME,
            named_params! { ":name": name },
        )?))
        .records)
    }
    fn all_member_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        self.members(questions::MEMBERS_BY_ID, named_params! { ":id": id })
    }
    fn procedure_summaries_for_member(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
    ) -> ReadResult<Vec<Arc<CompiledProcedureSummary>>> {
        let realm = brokk_bifrost_core::analyzer::model::semantic_pack_realm(key.language);
        let owners = procedure_owner_names(self.all_types_named(key.owner)?, key);
        let records = self.records::<CompiledProcedureSummary>(questions::SUMMARY_MEMBER, named_params! { ":realm": realm, ":owners": serde_json::to_string(&owners).expect("owner IDs serialize"), ":member": key.member, ":receiver": key.has_receiver })?;
        select_procedure_summaries(records, &owners, key)
    }
}

type TypeRecords = Vec<ActivatedSemanticModelRecord<TypeFact>>;
type MemberRecords = Vec<ActivatedSemanticModelRecord<MemberFact>>;
type SummaryQuestion = (String, String, String, bool, u32);

/// The shared group driver asks structured questions of either input backing.
pub(in crate::analyzer::semantic_model::overlay) trait GroupInput:
    CompositionReads
{
    fn for_language<'a>(&'a self, language: &'a str) -> Box<dyn GroupInput + 'a>;
    fn cancellation(&self) -> Option<&crate::CancellationToken>;
    fn provider_selection(&self) -> Option<&ModelProviderSelection>;
    fn defining_owner(&self) -> Option<&SemanticModelProvenance>;

    fn active(&self) -> &ResolvedActiveSemanticModels;
    /// Decoded inputs retain their own relations; row inputs admit only their backing.
    fn admits_relation(&self, shard: &ActiveSemanticModelShard, digest: &str) -> bool {
        shard.manifest.semantic_sha256 == digest
    }
    fn all_types_named(&self, name: &str) -> ReadResult<TypeRecords>;
    fn owner_ids_named(&self, key: &CompositionGroupKey, name: &str) -> ReadResult<Vec<String>>;
    fn member_ids_by_owners(&self, owners: &[&String]) -> ReadResult<Vec<String>>;
    fn owner_ids_for_groups(&self, keys: &[CompositionGroupKey]) -> ReadResult<Vec<Vec<String>>> {
        keys.iter()
            .map(|key| self.owner_ids_named(key, &key.identity))
            .collect()
    }
    fn types_by_ids(&self, ids: &[String]) -> ReadResult<TypeRecords> {
        let mut records = Vec::new();
        for id in ids {
            records.extend(self.all_type_records_with_id(id)?);
        }
        Ok(records)
    }
    fn members_by_ids(&self, ids: &[String]) -> ReadResult<MemberRecords> {
        let mut records = Vec::new();
        for id in ids {
            records.extend(self.all_member_records_with_id(id)?);
        }
        Ok(records)
    }
    fn relation_records_from(
        &self,
        ids: &HashSet<String>,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<RelationFact>>>;
    fn generated_symbols(&self) -> Box<dyn Iterator<Item = &SemanticModelSymbol> + '_>;
    fn generated_relations(&self) -> Box<dyn Iterator<Item = &SemanticModelRelation> + '_>;
}

impl GroupInput for RowCompositionReads<'_> {
    fn admits_relation(&self, shard: &ActiveSemanticModelShard, digest: &str) -> bool {
        admits_row_relation(shard, digest)
    }

    fn cancellation(&self) -> Option<&crate::CancellationToken> {
        self.cancellation.as_ref()
    }
    fn for_language<'a>(&'a self, language: &'a str) -> Box<dyn GroupInput + 'a> {
        Box::new(RowCompositionReads::for_language(self, language))
    }
    fn provider_selection(&self) -> Option<&ModelProviderSelection> {
        self.selection
    }
    fn defining_owner(&self) -> Option<&SemanticModelProvenance> {
        self.defining_owner
    }
    fn active(&self) -> &ResolvedActiveSemanticModels {
        self.active
    }
    fn all_types_named(&self, name: &str) -> ReadResult<TypeRecords> {
        self.types(
            questions::TYPES_BY_IDENTITY_NAME,
            named_params! { ":name": name },
        )
    }
    fn owner_ids_named(&self, key: &CompositionGroupKey, name: &str) -> ReadResult<Vec<String>> {
        Ok(self
            .raw_rows(
                questions::GROUP_OWNER_IDS,
                named_params! { ":name":name, ":language":key.language,
                ":namespace": if key.module_namespace { "module" } else { "type" } },
                |row| row.get::<_, String>("record_id"),
            )?
            .into_iter()
            .map(|row| Arc::unwrap_or_clone(row.record))
            .collect())
    }
    fn member_ids_by_owners(&self, owners: &[&String]) -> ReadResult<Vec<String>> {
        Ok(self.raw_rows(questions::MEMBER_IDS_BY_OWNERS,
            named_params! { ":owner_ids": serde_json::to_string(owners).expect("owner IDs serialize") },
            |row| row.get::<_, String>("record_id"))?
            .into_iter().map(|row| Arc::unwrap_or_clone(row.record)).collect())
    }
    fn owner_ids_for_groups(&self, keys: &[CompositionGroupKey]) -> ReadResult<Vec<Vec<String>>> {
        let values = keys
            .iter()
            .map(|key| {
                (
                    &key.language,
                    if key.module_namespace {
                        "module"
                    } else {
                        "type"
                    },
                    &key.identity,
                )
            })
            .collect::<Vec<_>>();
        let rows = self.raw_rows(
            SEARCH_OWNER_IDS_FOR_GROUPS,
            named_params! { ":groups": serde_json::to_string(&values).expect("group questions serialize") },
            |row| Ok((row.get::<_, usize>("position")?, row.get::<_, String>("record_id")?)),
        )?;
        let mut answers = vec![Vec::new(); keys.len()];
        for row in rows {
            answers[row.record.0].push(row.record.1.clone());
        }
        Ok(answers)
    }
    fn types_by_ids(&self, ids: &[String]) -> ReadResult<TypeRecords> {
        self.types(
            questions::TYPES_BY_IDS,
            named_params! { ":ids": serde_json::to_string(ids).expect("IDs serialize") },
        )
    }
    fn members_by_ids(&self, ids: &[String]) -> ReadResult<MemberRecords> {
        self.members(
            questions::MEMBERS_BY_IDS,
            named_params! { ":ids": serde_json::to_string(ids).expect("IDs serialize") },
        )
    }
    fn relation_records_from(
        &self,
        ids: &HashSet<String>,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<RelationFact>>> {
        let mut relation_ids = HashSet::default();
        let mut origins = ids.iter().collect::<Vec<_>>();
        origins.sort_unstable();
        // Bound the request payload while retaining same-ID records from all
        // origins for the family ranking below.
        for origins in origins.chunks(256) {
            check_composition_cancellation(self.cancellation.as_ref())?;
            for record in self.raw_rows(
                questions::OVERLAY_RELATIONS_FROM,
                named_params! { ":owner_ids": serde_json::to_string(origins).expect("origin IDs serialize") },
                |row| {
                    Ok((
                        row.get::<_, String>("origin")?,
                        row.get::<_, String>("record_id")?,
                    ))
                },
            )? {
                if record.record.0 == "relation_fact" {
                    relation_ids.insert(record.record.1.clone());
                }
            }
        }
        let mut relation_ids = relation_ids.into_iter().collect::<Vec<_>>();
        relation_ids.sort_unstable();
        let mut result = Vec::new();
        for id in relation_ids {
            check_composition_cancellation(self.cancellation.as_ref())?;
            result.extend(self.ordered_records(
                questions::RELATIONS_BY_ID,
                named_params! { ":id": id },
                |row| {
                    let kind: String = row.get("relation_kind")?;
                    let relation_kind = serde_json::from_value(serde_json::Value::String(kind))
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                row.column_index("relation_kind")
                                    .expect("relation kind column"),
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                    Ok(RelationFact {
                        id: row.get("record_id")?,
                        from: row.get("from_id")?,
                        to: row.get("to_id")?,
                        relation_kind,
                    })
                },
            )?);
        }
        Ok(result)
    }
    fn generated_symbols(&self) -> Box<dyn Iterator<Item = &SemanticModelSymbol> + '_> {
        Box::new(RowCompositionReads::generated_symbols(self))
    }
    fn generated_relations(&self) -> Box<dyn Iterator<Item = &SemanticModelRelation> + '_> {
        Box::new(self.generated_edges())
    }
}

/// Results reused only while answering this projection. A composed group, or a
/// chunk of groups composed together, creates one of these on its stack and
/// drops it before returning, so its working set is that group or chunk. No raw
/// records or qualifications are shared with another request or an earlier
/// chunk.
pub(in crate::analyzer::semantic_model::overlay) struct GroupProjection<'query> {
    reads: &'query dyn GroupInput,
    types_by_id: std::cell::RefCell<HashMap<String, TypeRecords>>,
    types_by_name: std::cell::RefCell<HashMap<String, TypeRecords>>,
    members_by_id: std::cell::RefCell<HashMap<String, MemberRecords>>,
    /// Member record IDs of an owner whose members were read as a set. An owner
    /// in `owners_with_members` is complete here, with an empty list when it
    /// has none.
    members_by_owner: std::cell::RefCell<HashMap<String, Vec<String>>>,
    owners_with_members: std::cell::RefCell<HashSet<String>>,
    owner_names: OwnerQualifications,
    group_names: std::cell::RefCell<HashMap<CompositionGroupKey, Vec<String>>>,
    summaries: std::cell::RefCell<HashMap<SummaryQuestion, Vec<Arc<CompiledProcedureSummary>>>>,
    /// Origins whose relation records were read as a set, so a group's
    /// relations answer from here. Every record of a relation ID is kept, as
    /// the family ranking needs all of them; `relation_ids_by_origin` names the
    /// IDs one origin takes part in.
    relation_origins: std::cell::RefCell<HashSet<String>>,
    relation_records:
        std::cell::RefCell<HashMap<String, Vec<ActivatedSemanticModelRecord<RelationFact>>>>,
    relation_ids_by_origin: std::cell::RefCell<HashMap<String, Vec<String>>>,
}

impl<'query> GroupProjection<'query> {
    fn poll(&self) -> ReadResult<()> {
        check_composition_cancellation(self.reads.cancellation())
    }

    pub(in crate::analyzer::semantic_model::overlay) fn new(reads: &'query dyn GroupInput) -> Self {
        if let Some(ledger) = crate::analyzer::i_analyzer::innermost_read_ledger() {
            debug_assert!(
                ledger.keys().contains(&crate::analyzer::ReadKey::Models(
                    crate::analyzer::semantic::StableDigest::sha256(
                        reads.active().active_model_set_hash()
                    ),
                )),
                "composition memo hits require the selected model publication key"
            );
        }

        Self {
            reads,
            types_by_id: Default::default(),
            types_by_name: Default::default(),
            members_by_id: Default::default(),
            members_by_owner: Default::default(),
            owners_with_members: Default::default(),
            owner_names: Default::default(),
            group_names: Default::default(),
            summaries: Default::default(),
            relation_origins: Default::default(),
            relation_records: Default::default(),
            relation_ids_by_origin: Default::default(),
        }
    }

    /// Hydrate selected IDs and every contributing member's owner together.
    /// Empty entries preserve absence; all same-ID contributors remain visible.
    /// An ID this projection already read keeps its entry: the projection is
    /// request-local, so that entry is the complete answer.
    pub(in crate::analyzer::semantic_model::overlay) fn hydrate_ids(
        &self,
        ids: &[String],
    ) -> ReadResult<()> {
        self.poll()?;
        let mut owners = ids.to_vec();
        let mut unread = Vec::new();
        {
            let cached = self.members_by_id.borrow();
            for id in ids {
                match cached.get(id) {
                    Some(records) => owners.extend(records.iter().map(|r| r.record.owner.clone())),
                    None => unread.push(id.clone()),
                }
            }
        }
        let mut members: HashMap<String, MemberRecords> =
            unread.iter().map(|id| (id.clone(), Vec::new())).collect();
        if !unread.is_empty() {
            for record in self.reads.members_by_ids(&unread)? {
                self.poll()?;
                owners.push(record.record.owner.clone());
                members
                    .get_mut(&record.record.id)
                    .expect("requested member")
                    .push(record);
            }
        }
        owners.sort_unstable();
        owners.dedup();
        owners.retain(|id| !self.types_by_id.borrow().contains_key(id));
        let mut types: HashMap<String, TypeRecords> =
            owners.iter().map(|id| (id.clone(), Vec::new())).collect();
        if !owners.is_empty() {
            for record in self.reads.types_by_ids(&owners)? {
                self.poll()?;
                types
                    .get_mut(&record.record.id)
                    .expect("requested owner")
                    .push(record);
            }
        }
        self.members_by_id.borrow_mut().extend(members);
        self.types_by_id.borrow_mut().extend(types);
        Ok(())
    }

    /// The member record IDs whose records have one of these owners. Owners not
    /// yet read are read together with one set question; their members are
    /// hydrated with it, so later per-ID reads are cache hits.
    fn member_ids_of_owners(&self, owners: &HashSet<String>) -> ReadResult<Vec<String>> {
        let mut missing = {
            let read = self.owners_with_members.borrow();
            owners
                .iter()
                .filter(|owner| !read.contains(*owner))
                .collect::<Vec<_>>()
        };
        if !missing.is_empty() {
            missing.sort_unstable();
            let mut ids = self.reads.member_ids_by_owners(&missing)?;
            ids.sort_unstable();
            ids.dedup();
            // The owners are hydrated with their members: a caller looks for a
            // member under the owner's ID too.
            let mut hydrated = ids.clone();
            hydrated.extend(missing.iter().map(|owner| (*owner).clone()));
            self.hydrate_ids(&hydrated)?;
            let mut by_owner = self.members_by_owner.borrow_mut();
            let cached = self.members_by_id.borrow();
            for id in &ids {
                for record in &cached[id] {
                    if missing.binary_search(&&record.record.owner).is_ok() {
                        by_owner
                            .entry(record.record.owner.clone())
                            .or_default()
                            .push(id.clone());
                    }
                }
            }
            self.owners_with_members
                .borrow_mut()
                .extend(missing.into_iter().cloned());
        }
        let by_owner = self.members_by_owner.borrow();
        let mut ids = owners
            .iter()
            .flat_map(|owner| by_owner.get(owner).into_iter().flatten().cloned())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// Close all selected owner spellings in batches before projecting groups.
    /// A frontier is one set question, including names with no contributors.
    pub(in crate::analyzer::semantic_model::overlay) fn prepare_groups(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        ids: &[String],
    ) -> ReadResult<()> {
        self.hydrate_ids(ids)?;
        let mut pending = Vec::new();
        for id in ids {
            pending.extend(self.owner_symbols(analyzer, id)?);
        }
        pending.extend(
            self.reads
                .generated_symbols()
                .filter(|s| s.owner_id.is_none() && ids.contains(&s.id))
                .cloned(),
        );
        self.close_group_names(analyzer, pending, HashSet::default())
    }

    /// Close every owner spelling the groups of `keys` reach, in set reads. The
    /// groups' `group_owners` then answer from this projection's caches.
    pub(in crate::analyzer::semantic_model::overlay) fn prepare_group_names(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        keys: &[CompositionGroupKey],
    ) -> ReadResult<()> {
        self.poll()?;
        let questions = keys
            .iter()
            .filter(|key| !self.group_names.borrow().contains_key(*key))
            .cloned()
            .collect();
        self.close_group_names(analyzer, Vec::new(), questions)
    }

    /// Prepare whole groups from their keys: close every owner spelling the
    /// groups reach, then read the members of all their owners together. The
    /// groups' `group_symbols` then answer from this projection's caches.
    pub(in crate::analyzer::semantic_model::overlay) fn prepare_group_keys(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        keys: &[CompositionGroupKey],
    ) -> ReadResult<()> {
        self.prepare_group_names(analyzer, keys)?;
        let owners = self
            .group_names
            .borrow()
            .values()
            .flatten()
            .cloned()
            .collect::<HashSet<_>>();
        self.member_ids_of_owners(&owners)?;
        Ok(())
    }

    /// Read the relation records of every origin not yet read, together: the
    /// origins' set read, then each relation ID's records. A group's
    /// `relations_for_origins` answers from here, so a chunk of groups reads its
    /// relations once. Every record of a relation ID is kept, because the
    /// family ranking needs all of them, whichever origin reached the ID.
    pub(in crate::analyzer::semantic_model::overlay) fn prepare_relation_origins(
        &self,
        origins: &HashSet<String>,
    ) -> ReadResult<()> {
        let missing = {
            let read = self.relation_origins.borrow();
            origins
                .iter()
                .filter(|origin| !read.contains(*origin))
                .cloned()
                .collect::<HashSet<_>>()
        };
        if missing.is_empty() {
            return Ok(());
        }
        let mut by_id: HashMap<String, Vec<ActivatedSemanticModelRecord<RelationFact>>> =
            HashMap::default();
        for record in self
            .reads
            .relation_records_from(&missing)?
            .into_iter()
            .filter(|record| {
                self.reads
                    .admits_relation(&record.shard, &record.shard.manifest.semantic_sha256)
            })
        {
            self.poll()?;
            by_id
                .entry(record.record.id.clone())
                .or_default()
                .push(record);
        }
        let mut by_origin = self.relation_ids_by_origin.borrow_mut();
        for (id, records) in &by_id {
            for record in records {
                let ids = by_origin.entry(record.record.from.clone()).or_default();
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
        }
        self.relation_records.borrow_mut().extend(by_id);
        self.relation_origins.borrow_mut().extend(missing);
        Ok(())
    }

    /// Follow owner spellings from `pending` owners and the `seeded` name
    /// questions until no new name is reached. Each frontier is one set read.
    fn close_group_names(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        mut pending: Vec<SemanticModelSymbol>,
        mut seeded: HashSet<CompositionGroupKey>,
    ) -> ReadResult<()> {
        loop {
            self.poll()?;
            let mut questions = std::mem::take(&mut seeded);
            for owner in pending.drain(..) {
                self.poll()?;
                for name in std::iter::once(owner.qualified_name).chain(owner.aliases) {
                    let key = CompositionGroupKey {
                        language: owner.language.clone(),
                        module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                        identity: name,
                    };
                    if !self.group_names.borrow().contains_key(&key) {
                        questions.insert(key);
                    }
                }
            }
            if questions.is_empty() {
                break;
            }
            // Generated owners join only a reached canonical/alias name.
            // Their other spellings then extend the next frontier.
            for owner in self
                .reads
                .generated_symbols()
                .filter(|s| s.owner_id.is_none())
            {
                self.poll()?;
                if std::iter::once(&owner.qualified_name)
                    .chain(&owner.aliases)
                    .any(|name| {
                        questions.contains(&CompositionGroupKey {
                            language: owner.language.clone(),
                            module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                            identity: name.clone(),
                        })
                    })
                {
                    pending.push(owner.clone());
                }
            }
            let mut questions = questions.into_iter().collect::<Vec<_>>();
            questions.sort_unstable();
            let answers = self.reads.owner_ids_for_groups(&questions)?;
            let mut ids = Vec::new();
            for (key, answer) in questions.into_iter().zip(answers) {
                ids.extend(answer.iter().cloned());
                self.group_names.borrow_mut().insert(key, answer);
            }
            ids.sort_unstable();
            ids.dedup();
            self.hydrate_ids(&ids)?;
            for id in ids {
                pending.extend(self.owner_symbols(analyzer, &id)?);
            }
        }
        Ok(())
    }

    fn owner_qualification(&self, realm: Option<&str>, id: &str) -> ReadResult<Option<String>> {
        if let Some(name) = self
            .owner_names
            .borrow()
            .get(&(realm.map(str::to_owned), id.to_owned()))
        {
            return Ok(name.clone());
        }
        let records = self
            .all_type_records_with_id(id)?
            .into_iter()
            .filter(|record| {
                realm.is_none_or(|realm| {
                    brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                        &record.shard.manifest.language,
                    ) == realm
                })
            })
            .collect::<Vec<_>>();
        let matched = with_artifact_declarations(
            resolve_records(FamilyRows::complete(records.clone())),
            records.into_iter(),
        );
        let name = qualified_owner_name(&matched).map(str::to_owned);
        self.owner_names
            .borrow_mut()
            .insert((realm.map(str::to_owned), id.to_owned()), name.clone());
        Ok(name)
    }

    fn owner_ids_named(&self, key: &CompositionGroupKey, name: &str) -> ReadResult<Vec<String>> {
        let question = CompositionGroupKey {
            identity: name.to_owned(),
            ..key.clone()
        };
        if let Some(ids) = self.group_names.borrow().get(&question) {
            return Ok(ids.clone());
        }
        let ids = self.reads.owner_ids_named(key, name)?;
        self.group_names.borrow_mut().insert(question, ids.clone());
        Ok(ids)
    }
}

impl CompositionReads for GroupProjection<'_> {
    fn all_type_records_with_id(&self, id: &str) -> ReadResult<TypeRecords> {
        if let Some(records) = self.types_by_id.borrow().get(id) {
            return Ok(records.clone());
        }
        let records = self.reads.all_type_records_with_id(id)?;
        self.types_by_id
            .borrow_mut()
            .insert(id.to_owned(), records.clone());
        Ok(records)
    }
    fn types_named(&self, name: &str) -> ReadResult<TypeRecords> {
        if let Some(records) = self.types_by_name.borrow().get(name) {
            return Ok(resolve_records(FamilyRows::complete(records.clone())).records);
        }
        let records = self.reads.all_types_named(name)?;
        self.types_by_name
            .borrow_mut()
            .insert(name.to_owned(), records.clone());
        Ok(resolve_records(FamilyRows::complete(records)).records)
    }
    fn all_member_records_with_id(&self, id: &str) -> ReadResult<MemberRecords> {
        if let Some(records) = self.members_by_id.borrow().get(id) {
            return Ok(records.clone());
        }
        let records = self.reads.all_member_records_with_id(id)?;
        self.members_by_id
            .borrow_mut()
            .insert(id.to_owned(), records.clone());
        Ok(records)
    }
    fn procedure_summaries_for_member(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
    ) -> ReadResult<Vec<Arc<CompiledProcedureSummary>>> {
        let question = (
            key.language.to_owned(),
            key.owner.to_owned(),
            key.member.to_owned(),
            key.has_receiver,
            key.parameter_count,
        );
        if let Some(records) = self.summaries.borrow().get(&question) {
            return Ok(records.clone());
        }
        let records = self.reads.procedure_summaries_for_member(key)?;
        self.summaries
            .borrow_mut()
            .insert(question, records.clone());
        Ok(records)
    }
}

impl GroupProjection<'_> {
    fn declaration_families<T: Eq + Clone>(
        &self,
        records: Vec<ActivatedSemanticModelRecord<T>>,
    ) -> Vec<SemanticModelMatch<T>> {
        // Discovery must not lose a defining provider through evidence ranking
        // or equal-value deduplication. Actual facets already have their owner
        // scope: extracted facets keep curated contribution ranking; authored
        // facets see only their own defining provider.
        if self.reads.provider_selection().is_none() || self.reads.defining_owner().is_some() {
            return matches_by_family(with_artifact_declarations(
                resolve_records(FamilyRows::complete(records.clone())),
                records.into_iter(),
            ))
            .into_iter()
            .map(|(_, matched)| matched)
            .collect();
        }
        let mut positions = HashMap::default();
        let mut families: Vec<Vec<ActivatedSemanticModelRecord<T>>> = Vec::new();
        for record in records {
            let provider = ModelProvider {
                pack_id: record.shard.manifest.pack_id.clone(),
                pack_version: record.shard.manifest.version.clone(),
                pack_digest: record.shard.manifest.semantic_sha256.clone(),
            };
            let index = positions.entry(provider).or_insert_with(|| {
                families.push(Vec::new());
                families.len() - 1
            });
            families[*index].push(record);
        }
        families
            .into_iter()
            .flat_map(|records| {
                matches_by_family(with_artifact_declarations(
                    resolve_records(FamilyRows::complete(records.clone())),
                    records.into_iter(),
                ))
                .into_iter()
                .map(|(_, matched)| matched)
            })
            .collect()
    }

    pub(in crate::analyzer::semantic_model::overlay) fn owner_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let records = self.all_type_records_with_id(id)?;
        let mut result = Vec::new();
        for matched in self.declaration_families(records) {
            self.poll()?;
            let ambiguous = type_declaration_records_conflict(&matched);
            for (index, activated) in matched.records.iter().enumerate() {
                self.poll()?;
                if matched.records[..index].iter().any(|earlier| {
                    earlier.record.runtime_bases != activated.record.runtime_bases
                        && type_declarations_equivalent(&earlier.record, &activated.record)
                }) {
                    continue;
                }
                result.push(type_symbol(
                    analyzer,
                    self.reads.active(),
                    &activated.shard,
                    &activated.record,
                    ambiguous,
                ));
            }
        }
        Ok(result)
    }

    fn member_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let records = self.all_member_records_with_id(id)?;
        let mut result = Vec::new();
        for matched in self.declaration_families(records) {
            self.poll()?;
            let ambiguous = declaration_records_conflict(&matched);
            for activated in matched.records {
                self.poll()?;
                let owner = self.owner_qualification(
                    Some(brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                        &activated.shard.manifest.language,
                    )),
                    &activated.record.owner,
                )?;
                result.push(member_symbol(
                    analyzer,
                    self.reads.active(),
                    &activated.shard,
                    &activated.record,
                    owner.as_deref(),
                    ambiguous,
                ));
            }
        }
        Ok(result)
    }

    pub(in crate::analyzer::semantic_model::overlay) fn symbols_with_id(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let mut symbols = self.owner_symbols(analyzer, id)?;
        symbols.extend(self.member_symbols(analyzer, id)?);
        symbols.extend(
            self.reads
                .generated_symbols()
                .filter(|s| s.id == id)
                .cloned(),
        );
        Ok(symbols)
    }

    /// Close canonical/alias spellings iteratively, including generated owners
    /// from this build. Terminal simple names are deliberately not group edges.
    pub(in crate::analyzer::semantic_model::overlay) fn group_owners(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let mut pending = vec![key.identity.clone()];
        let mut visited = HashSet::default();
        let mut owners = Vec::new();
        let mut seen = HashSet::default();
        while let Some(name) = pending.pop() {
            self.poll()?;
            if !visited.insert(name.clone()) {
                continue;
            }
            let ids = self.owner_ids_named(key, &name)?;
            let mut candidates = Vec::new();
            for id in ids {
                self.poll()?;
                candidates.extend(self.owner_symbols(analyzer, &id)?);
            }
            candidates.extend(
                self.reads
                    .generated_symbols()
                    .filter(|s| {
                        s.owner_id.is_none()
                            && s.language == key.language
                            && (s.kind == SemanticModelSymbolKind::Module) == key.module_namespace
                            && (s.qualified_name == name || s.aliases.contains(&name))
                    })
                    .cloned(),
            );
            for symbol in candidates {
                self.poll()?;
                if symbol.language != key.language
                    || (symbol.qualified_name != name && !symbol.aliases.contains(&name))
                    || (symbol.kind == SemanticModelSymbolKind::Module) != key.module_namespace
                {
                    continue;
                }
                let identity = (
                    symbol.id.clone(),
                    symbol.provenance.pack_digest.clone(),
                    serde_json::to_string(&symbol.location).expect("location serializes"),
                );
                if !seen.insert(identity) {
                    continue;
                }
                pending.push(symbol.qualified_name.clone());
                pending.extend(symbol.aliases.iter().cloned());
                owners.push(symbol);
            }
        }
        owners.sort_by_cached_key(owned_symbol_source_key);
        Ok(owners)
    }

    pub(in crate::analyzer::semantic_model::overlay) fn group_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let owners = self.group_owners(analyzer, key)?;
        let owner_ids = owners.iter().map(|s| s.id.clone()).collect::<HashSet<_>>();
        let member_ids = self.member_ids_of_owners(&owner_ids)?;
        let mut ids = member_ids.clone();
        ids.extend(owner_ids.iter().cloned());
        ids.extend(
            self.reads
                .generated_symbols()
                .filter(|s| s.owner_id.as_ref().is_some_and(|id| owner_ids.contains(id)))
                .map(|s| s.id.clone()),
        );
        ids.sort_unstable();
        ids.dedup();
        self.hydrate_ids(&ids)?;
        let mut symbols = owners;
        for id in member_ids {
            self.poll()?;
            symbols.extend(
                self.member_symbols(analyzer, &id)?
                    .into_iter()
                    .filter(|s| s.owner_id.as_ref().is_some_and(|id| owner_ids.contains(id))),
            );
        }
        symbols.extend(
            self.reads
                .generated_symbols()
                .filter(|s| s.owner_id.as_ref().is_some_and(|id| owner_ids.contains(id)))
                .cloned(),
        );
        symbols.sort_by_cached_key(owned_symbol_source_key);
        let mut ids = symbols.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            self.poll()?;
            let mut all = self.symbols_with_id(analyzer, &id)?;
            let matching = symbols
                .iter()
                .enumerate()
                .filter(|(_, s)| s.id == id)
                .filter_map(|(index, symbol)| {
                    all.iter()
                        .position(|s| s.provenance == symbol.provenance)
                        .map(|other| (index, other))
                })
                .collect::<Vec<_>>();
            mark_symbol_identity_conflicts(&mut all);
            for (index, other) in matching {
                self.poll()?;
                symbols[index].provenance.ambiguous = all[other].provenance.ambiguous;
            }
        }
        Ok(symbols)
    }
}

impl GroupProjection<'_> {
    /// Resolve only owner identity at a relation endpoint. No other group's
    /// members are composed, so cross-group edges cannot recurse composition.
    /// `own_language` is the language this projection reads; owners of it are
    /// resolved from this projection's memos, owners of any other language of
    /// the realm through a projection of theirs.
    fn endpoint_representatives(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        own_language: Option<&str>,
        realm: &str,
        id: &str,
    ) -> ReadResult<(RepresentativeIdentity, OriginRewrites)> {
        let mut keys = HashSet::default();
        let mut groups = Vec::new();
        let mut owners = self.owner_symbols(analyzer, id)?;
        owners.extend(
            self.reads
                .generated_symbols()
                .filter(|s| s.id == id && s.owner_id.is_none())
                .cloned(),
        );
        for owner in owners.into_iter().filter(|owner| {
            brokk_bifrost_core::analyzer::model::semantic_pack_realm(&owner.language) == realm
        }) {
            self.poll()?;
            let key = CompositionGroupKey {
                language: owner.language,
                module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                identity: owner.qualified_name,
            };
            let owners = if own_language == Some(key.language.as_str()) {
                self.group_owners(analyzer, &key)?
            } else {
                let reads = self.reads.for_language(&key.language);
                GroupProjection::new(reads.as_ref()).group_owners(analyzer, &key)?
            };
            let key = group_key(&owners.iter().collect::<Vec<_>>());
            if keys.insert(key) {
                groups.push(owners);
            }
        }
        groups.sort_by_cached_key(|group| owned_symbol_source_key(&group[0]));
        let mut result = RepresentativeIdentity {
            representative_id: None,
            replacements: Vec::new(),
            composed: false,
            disagreement: false,
        };
        let mut origins = OriginRewrites::default();
        for owners in groups {
            self.poll()?;
            let owners_refs = owners.iter().collect::<Vec<_>>();
            let representative = if own_language == Some(owners[0].language.as_str()) {
                representative_identity(&owners_refs, self)?
            } else {
                let reads = self.reads.for_language(&owners[0].language);
                representative_identity(&owners_refs, reads.as_ref())?
            };
            record_origin_identities(
                &mut origins,
                &owners.iter().collect::<Vec<_>>(),
                &representative,
            );
            result.composed |= representative.composed;
            if representative.representative_id.is_some() {
                result.representative_id = representative.representative_id.clone();
            }
            result.disagreement |= representative.disagreement;
            result.replacements.extend(representative.replacements);
        }
        Ok((result, origins))
    }

    fn group_relations(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        symbols: &[SemanticModelSymbol],
    ) -> ReadResult<Vec<SemanticModelRelation>> {
        let ids = symbols
            .iter()
            .filter(|s| s.owner_id.is_none())
            .map(|s| s.id.clone())
            .collect::<HashSet<_>>();
        self.relations_for_origins(analyzer, &ids)
    }

    fn relations_for_origins(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        ids: &HashSet<String>,
    ) -> ReadResult<Vec<SemanticModelRelation>> {
        let mut relations = Vec::new();
        for id in ids {
            self.poll()?;
            for owner in self.owner_symbols(analyzer, id)? {
                let ambiguous = owner.provenance.ambiguous;
                for record in self
                    .all_type_records_with_id(&owner.id)?
                    .into_iter()
                    .filter(|r| {
                        self.reads
                            .admits_relation(&r.shard, &owner.provenance.pack_digest)
                    })
                {
                    relations.extend(record.record.hierarchy.iter().map(|hierarchy| {
                        hierarchy_relation(
                            self.reads.active(),
                            &record.shard,
                            &owner.id,
                            hierarchy,
                            ambiguous,
                        )
                    }));
                }
            }
        }
        self.prepare_relation_origins(ids)?;
        // A relation takes part when one of its records starts at an origin;
        // all its records rank together, then only those from an origin stay.
        let mut relation_ids = {
            let by_origin = self.relation_ids_by_origin.borrow();
            ids.iter()
                .filter_map(|id| by_origin.get(id))
                .flatten()
                .cloned()
                .collect::<Vec<_>>()
        };
        relation_ids.sort_unstable();
        relation_ids.dedup();
        for relation_id in relation_ids {
            self.poll()?;
            let records = self.relation_records.borrow()[&relation_id].clone();
            for (_, matched) in matches_by_family(resolve_records(FamilyRows::complete(records))) {
                let ambiguous = matched.disposition == SemanticModelMatchDisposition::Conflict;
                relations.extend(
                    matched
                        .records
                        .iter()
                        .filter(|r| ids.contains(&r.record.from))
                        .map(|r| relation(self.reads.active(), &r.shard, &r.record, ambiguous)),
                );
            }
        }
        relations.extend(
            self.reads
                .generated_relations()
                .filter(|r| {
                    ids.contains(&r.from)
                        && self.reads.active().shards.iter().any(|shard| {
                            self.reads.admits_relation(shard, &r.provenance.pack_digest)
                        })
                })
                .cloned(),
        );
        relations.sort_by(relation_source_order);
        Ok(relations)
    }

    fn ordered_group_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let mut symbols = self.group_symbols(analyzer, key)?;
        freeze_symbol_order(&mut symbols);
        debug_assert_group_backing(&symbols, self.reads.active());
        Ok(symbols)
    }

    /// The group's merged symbols and nothing else: no relations and no
    /// endpoint representatives, which cannot change a symbol. This is the
    /// symbol half of `compose_group`, through the same `compose_symbols`.
    pub(in crate::analyzer::semantic_model::overlay) fn compose_group_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<ComposedSymbols> {
        compose_symbols(self.ordered_group_symbols(analyzer, key)?, self)
    }

    /// The row driver asks only for this group and the identity of endpoints.
    /// It never composes a neighboring group to rewrite an edge.
    pub(in crate::analyzer::semantic_model::overlay) fn compose_group(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<ComposedGroup> {
        let draft = self.draft_group(analyzer, key)?;
        self.finish_group(analyzer, &key.language, draft)
    }

    /// Whole groups composed together, all of this projection's language: the
    /// reads that `compose_group` makes per group are made once for the chunk
    /// (names, members, relations and endpoint owners as set reads), then each
    /// group is composed from this projection's memos by the same
    /// `draft_group`/`finish_group`. A group's content depends only on its key,
    /// never on the other keys of the chunk.
    pub(in crate::analyzer::semantic_model::overlay) fn compose_groups(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        keys: &[CompositionGroupKey],
    ) -> ReadResult<Vec<ComposedGroup>> {
        self.prepare_group_keys(analyzer, keys)?;
        let mut origins = HashSet::default();
        for key in keys {
            self.poll()?;
            origins.extend(
                self.group_owners(analyzer, key)?
                    .into_iter()
                    .map(|owner| owner.id),
            );
        }
        self.prepare_relation_origins(&origins)?;
        let mut drafts = Vec::with_capacity(keys.len());
        for key in keys {
            drafts.push(self.draft_group(analyzer, key)?);
        }
        let mut endpoints = drafts
            .iter()
            .flat_map(|draft| draft.endpoints.iter().map(|(_, id)| id.clone()))
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.dedup();
        self.prepare_groups(analyzer, &endpoints)?;
        keys.iter()
            .zip(drafts)
            .map(|(key, draft)| self.finish_group(analyzer, &key.language, draft))
            .collect()
    }

    /// A group's symbols, its own relations, and the endpoints those relations
    /// and owners name: everything `finish_group` needs to rewrite them.
    fn draft_group(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<GroupDraft> {
        let symbols = self.ordered_group_symbols(analyzer, key)?;
        let mut relations = self.group_relations(analyzer, &symbols)?;
        let origins = symbols
            .iter()
            .filter(|s| s.owner_id.is_none())
            .map(|s| (s.provenance.pack_digest.as_str(), s.id.as_str()))
            .collect::<HashSet<_>>();
        relations
            .retain(|r| origins.contains(&(r.provenance.pack_digest.as_str(), r.from.as_str())));
        freeze_relation_order(relations.iter_mut());
        let mut endpoints = symbols
            .iter()
            .filter(|s| s.owner_id.is_none())
            .map(|s| {
                (
                    brokk_bifrost_core::analyzer::model::semantic_pack_realm(&s.language)
                        .to_owned(),
                    s.id.clone(),
                )
            })
            .collect::<HashSet<_>>();
        endpoints.extend(relations.iter().flat_map(|r| {
            let family = brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                &r.provenance.activation.matched_evidence.language,
            )
            .to_owned();
            [(family.clone(), r.from.clone()), (family, r.to.clone())]
        }));
        Ok(GroupDraft {
            symbols,
            relations,
            endpoints,
        })
    }

    /// Resolve the draft's endpoints and compose. `language` is the language
    /// this projection reads, whose memos serve the endpoints of that language.
    fn finish_group(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        language: &str,
        draft: GroupDraft,
    ) -> ReadResult<ComposedGroup> {
        let GroupDraft {
            symbols,
            relations,
            endpoints,
        } = draft;
        let mut replacements = HashMap::default();
        let mut composed_owners = HashSet::default();
        let mut origin_identities = OriginRewrites::default();
        for (realm, id) in endpoints {
            self.poll()?;
            let (representative, origins) =
                self.endpoint_representatives(analyzer, Some(language), &realm, &id)?;
            for (pack, ids) in origins {
                self.poll()?;
                origin_identities.entry(pack).or_default().extend(ids);
            }
            if representative.composed {
                composed_owners.insert((realm.clone(), id.clone()));
            }
            if let Some((_, replacement)) = representative
                .replacements
                .into_iter()
                .rev()
                .find(|(raw, _)| raw == &id)
            {
                replacements.insert((realm.clone(), id.clone()), replacement);
            }
        }
        compose(
            symbols,
            relations.into_iter().enumerate().collect(),
            self,
            &replacements,
            &composed_owners,
            &origin_identities,
        )
    }
}

/// One group before its endpoints are resolved.
struct GroupDraft {
    symbols: Vec<SemanticModelSymbol>,
    relations: Vec<SemanticModelRelation>,
    endpoints: HashSet<(String, String)>,
}

// The uncorrelated list is evaluated once per statement. A join to json_each
// instead reparses the entire shard list for every returned catalog record.
fn scoped_catalog_statement(statement: &str) -> String {
    format!(
        "SELECT composition_row.* FROM ({}) AS composition_row
         WHERE (composition_row.source_db, composition_row.shard_key) IN
         (SELECT json_extract(value,'$[0]'), json_extract(value,'$[1]')
          FROM json_each(:composition_shards))",
        statement.trim_end().trim_end_matches(';')
    )
}

#[cfg(test)]
mod scope_cost_tests {
    use super::scoped_catalog_statement;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::{Connection, StatementStatus, named_params};

    #[test]
    #[hardwon("#9559: scoped JVM reads reparsed every shard for every catalog row")]
    fn shard_membership_work_is_additive() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE records(source_db TEXT, shard_key INTEGER);
             WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000)
             INSERT INTO records SELECT 'session',x FROM n;",
            )
            .unwrap();
        let shards =
            serde_json::to_string(&(1..=1000).map(|key| ("session", key)).collect::<Vec<_>>())
                .unwrap();
        let sql = scoped_catalog_statement("SELECT * FROM records;");
        let mut statement = connection.prepare(&sql).unwrap();
        let count = statement
            .query_map(named_params! { ":composition_shards": shards }, |_| Ok(()))
            .unwrap()
            .count();
        assert_eq!(count, 1000);
        let steps = statement.get_status(StatementStatus::VmStep);
        assert!(
            steps < 100_000,
            "membership must not multiply rows by shards: {steps}"
        );
    }
}
