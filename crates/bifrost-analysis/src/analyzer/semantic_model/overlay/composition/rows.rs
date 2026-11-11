//! Query-local catalog reads for one composition group. No decoded payloads.

use super::*;
use crate::analyzer::store::active_models::resolve_records;
use crate::analyzer::store::model_catalog::CatalogRowReader;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements as questions;
use brokk_bifrost_semantic::analyzer::semantic_model::runtime::FamilyOpen;
use rusqlite::{ToSql, named_params};
use std::cell::{Cell, OnceCell};

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
    scope: Option<LanguageScope<'a>>,
    open: Cell<Option<FamilyOpen>>,
    pub(in crate::analyzer::semantic_model::overlay) cancellation:
        Option<&'a crate::CancellationToken>,
}

type OwnerQualifications = std::cell::RefCell<HashMap<(Option<String>, String), Option<String>>>;

struct LanguageScope<'a> {
    language: Option<&'a str>,
    realm: &'a str,
    shard_keys: String,
}

impl LanguageScope<'_> {
    fn accepts(&self, language: &str) -> bool {
        self.language.map_or_else(
            || brokk_bifrost_core::analyzer::model::semantic_pack_realm(language) == self.realm,
            |selected| selected == language,
        )
    }
}

impl<'a> RowCompositionReads<'a> {
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
            scope: None,
            open: Cell::new(None),
            cancellation: None,
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
            scope: None,
            open: Cell::new(None),
            cancellation: None,
        }
    }

    /// Scope every outside read before decoding. The reader's full metadata
    /// slice still matches its immutable active views; SQL selects only this
    /// language's physical shard identities, as established by their manifests.
    pub(in crate::analyzer::semantic_model::overlay) fn for_language<'b>(
        &self,
        language: &'b str,
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
        realm: &'b str,
    ) -> RowCompositionReads<'b>
    where
        'a: 'b,
    {
        self.for_scope(None, realm)
    }

    fn for_scope<'b>(&self, language: Option<&'b str>, realm: &'b str) -> RowCompositionReads<'b>
    where
        'a: 'b,
    {
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        let shards = self
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
            .collect::<Vec<_>>();
        RowCompositionReads {
            selection: self.selection,
            defining_owner: self.defining_owner,
            active: self.active,
            activation: Arc::clone(&self.activation),
            jvm: self.jvm.clone(),
            generated: self.generated,
            generated_relations: self.generated_relations,
            activation_only: self.activation_only,
            cancellation: self.cancellation,
            scope: Some(LanguageScope {
                language,
                realm,
                shard_keys: serde_json::to_string(&shards).expect("shard identities serialize"),
            }),
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
                .is_some_and(|scope| scope.realm != "jvm")
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

    fn generated_edges(&self) -> impl Iterator<Item = &SemanticModelRelation> {
        self.generated_relations.iter().filter(|relation| {
            self.admits_provenance(&relation.provenance)
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
        check_composition_cancellation(self.cancellation)?;
        let scoped_statement = self.scope.as_ref().map(|_| {
            format!(
                "SELECT composition_row.* FROM ({}) AS composition_row
                 JOIN json_each(:composition_shards) AS selected_shard
                 ON composition_row.source_db=json_extract(selected_shard.value,'$[0]')
                 AND composition_row.shard_key=json_extract(selected_shard.value,'$[1]')",
                statement.trim_end().trim_end_matches(';')
            )
        });
        let mut scoped_params = params.to_vec();
        if let Some(scope) = &self.scope {
            scoped_params.push((":composition_shards", &scope.shard_keys));
        }
        let statement = scoped_statement.as_deref().unwrap_or(statement);
        let params = scoped_params.as_slice();
        let jvm = if self
            .scope
            .as_ref()
            .is_some_and(|scope| scope.realm != "jvm")
        {
            None
        } else {
            self.jvm_reader()?
        };
        let distinct = jvm.is_some_and(|reader| {
            Arc::as_ptr(reader) as *const () != Arc::as_ptr(&self.activation) as *const ()
        });
        let mut rows = if self.has_activation_shards() {
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
            scope: None,
            open: Cell::new(None),
            cancellation: self.cancellation,
        };
        let mut anchors = locations::SourceAnchors::default();
        let owners = owner
            .types(questions::SOURCE_TYPES, &[])?
            .into_iter()
            .filter(|r| r.shard.decoded.is_none() && owns(&r.shard))
            .map(|r| r.record.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for id in owners {
            for symbol in owner.owner_symbols(resolver, &id)? {
                if self.active.shards.iter().any(|shard| {
                    owns(shard) && shard.manifest.semantic_sha256 == symbol.provenance.pack_digest
                }) {
                    anchors.insert_symbol("type", symbol);
                }
            }
        }
        let members = owner
            .members(questions::SOURCE_MEMBERS, &[])?
            .into_iter()
            .filter(|r| r.shard.decoded.is_none() && owns(&r.shard))
            .map(|r| r.record.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for id in members {
            for symbol in owner.member_symbols(resolver, &id)? {
                if self.active.shards.iter().any(|shard| {
                    owns(shard) && shard.manifest.semantic_sha256 == symbol.provenance.pack_digest
                }) {
                    anchors.insert_symbol("member", symbol);
                }
            }
        }
        Ok(anchors)
    }

    fn projection(&self) -> GroupProjection<'_> {
        GroupProjection::new(self)
    }
    pub(crate) fn owner_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        self.projection().owner_symbols(analyzer, id)
    }
    fn member_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        self.projection().member_symbols(analyzer, id)
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
            .endpoint_representatives(analyzer, realm, id)
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
        self.projection().relations_for_origins(analyzer, ids)
    }
    pub fn compose_group(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<ComposedGroup> {
        self.for_language(&key.language)
            .projection()
            .compose_group(analyzer, key)
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
    fn all_types_named(&self, name: &str) -> ReadResult<TypeRecords>;
    fn owner_ids_named(&self, key: &CompositionGroupKey, name: &str) -> ReadResult<Vec<String>>;
    fn member_ids_by_owners(&self, owners: &[&String]) -> ReadResult<Vec<String>>;
    fn relation_records_from(
        &self,
        ids: &HashSet<String>,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<RelationFact>>>;
    fn generated_symbols(&self) -> Box<dyn Iterator<Item = &SemanticModelSymbol> + '_>;
    fn generated_relations(&self) -> Box<dyn Iterator<Item = &SemanticModelRelation> + '_>;
}

impl GroupInput for RowCompositionReads<'_> {
    fn cancellation(&self) -> Option<&crate::CancellationToken> {
        self.cancellation
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
    fn relation_records_from(
        &self,
        ids: &HashSet<String>,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<RelationFact>>> {
        let mut relation_ids = HashSet::default();
        for id in ids {
            check_composition_cancellation(self.cancellation)?;
            for record in self.raw_rows(
                questions::RELATIONS_FROM,
                named_params! { ":id": id },
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
            check_composition_cancellation(self.cancellation)?;
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

/// Results reused only while answering this projection. A composed group
/// creates one of these on its stack and drops it before returning. No raw
/// records or qualifications are shared with another group or request.
pub(in crate::analyzer::semantic_model::overlay) struct GroupProjection<'query> {
    reads: &'query dyn GroupInput,
    types_by_id: std::cell::RefCell<HashMap<String, TypeRecords>>,
    types_by_name: std::cell::RefCell<HashMap<String, TypeRecords>>,
    members_by_id: std::cell::RefCell<HashMap<String, MemberRecords>>,
    owner_names: OwnerQualifications,
    group_names: std::cell::RefCell<HashMap<CompositionGroupKey, Vec<String>>>,
    summaries: std::cell::RefCell<HashMap<SummaryQuestion, Vec<Arc<CompiledProcedureSummary>>>>,
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
            owner_names: Default::default(),
            group_names: Default::default(),
            summaries: Default::default(),
        }
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
        owners.sort_by(symbol_source_order);
        Ok(owners)
    }

    pub(in crate::analyzer::semantic_model::overlay) fn group_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let owners = self.group_owners(analyzer, key)?;
        let owner_ids = owners.iter().map(|s| s.id.clone()).collect::<HashSet<_>>();
        let mut ordered_owner_ids = owner_ids.iter().collect::<Vec<_>>();
        ordered_owner_ids.sort_unstable();
        let mut member_ids = self.reads.member_ids_by_owners(&ordered_owner_ids)?;
        member_ids.sort_unstable();
        member_ids.dedup();
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
        symbols.sort_by(symbol_source_order);
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
    fn endpoint_representatives(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
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
            let reads = self.reads.for_language(&key.language);
            let owners = GroupProjection::new(reads.as_ref()).group_owners(analyzer, &key)?;
            let key = group_key(&owners.iter().collect::<Vec<_>>());
            if keys.insert(key) {
                groups.push(owners);
            }
        }
        groups.sort_by(|a, b| symbol_source_order(&a[0], &b[0]));
        let mut result = RepresentativeIdentity {
            representative_id: None,
            replacements: Vec::new(),
            composed: false,
            disagreement: false,
        };
        let mut origins = OriginRewrites::default();
        for owners in groups {
            self.poll()?;
            let reads = self.reads.for_language(&owners[0].language);
            let representative =
                representative_identity(&owners.iter().collect::<Vec<_>>(), reads.as_ref())?;
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
                    .filter(|r| r.shard.manifest.semantic_sha256 == owner.provenance.pack_digest)
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
        let records = self.reads.relation_records_from(ids)?;
        let mut by_id: HashMap<String, Vec<_>> = HashMap::default();
        for record in records {
            self.poll()?;
            by_id
                .entry(record.record.id.clone())
                .or_default()
                .push(record);
        }
        for records in by_id.into_values() {
            self.poll()?;
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
                .filter(|r| ids.contains(&r.from))
                .cloned(),
        );
        relations.sort_by(relation_source_order);
        Ok(relations)
    }

    /// The row driver asks only for this group and the identity of endpoints.
    /// It never composes a neighboring group to rewrite an edge.
    pub(in crate::analyzer::semantic_model::overlay) fn compose_group(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<ComposedGroup> {
        let mut symbols = self.group_symbols(analyzer, key)?;
        freeze_symbol_order(&mut symbols);
        debug_assert_group_backing(&symbols, self.reads.active());
        let mut relations = self.group_relations(analyzer, &symbols)?;
        let origins = symbols
            .iter()
            .filter(|s| s.owner_id.is_none())
            .map(|s| (s.provenance.pack_digest.as_str(), s.id.as_str()))
            .collect::<HashSet<_>>();
        relations
            .retain(|r| origins.contains(&(r.provenance.pack_digest.as_str(), r.from.as_str())));
        freeze_relation_order(relations.iter_mut());
        let mut replacements = HashMap::default();
        let mut composed_owners = HashSet::default();
        let mut origin_identities = OriginRewrites::default();
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
        for (realm, id) in endpoints {
            self.poll()?;
            let (representative, origins) = self.endpoint_representatives(analyzer, &realm, &id)?;
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
