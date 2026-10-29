//! Query-local catalog reads for one composition group. No decoded payloads.

use super::*;
use crate::analyzer::store::active_models::resolve_records;
use crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements as questions;
use rusqlite::{ToSql, named_params};

/// Connection-only outside reads; generated symbols belong to this overlay
/// build, and are included by the group loader and keyed identity checks.
pub struct RowCompositionReads<'a> {
    pub selection: Option<&'a ModelProviderSelection>,
    pub defining_owner: Option<&'a SemanticModelProvenance>,
    pub active: &'a ResolvedActiveSemanticModels,
    pub reader: &'a CatalogRuntimeSourceReader,
    pub generated: &'a [SemanticModelSymbol],
    pub generated_relations: &'a [SemanticModelRelation],
    scope: Option<LanguageScope<'a>>,
    pub(in crate::analyzer::semantic_model::overlay) cancellation:
        Option<&'a crate::CancellationToken>,
}

struct LanguageScope<'a> {
    language: &'a str,
    shard_keys: String,
}

impl<'a> RowCompositionReads<'a> {
    fn admits_provenance(&self, provenance: &SemanticModelProvenance) -> bool {
        let provider = ModelProvider::from(provenance);
        self.selection
            .is_none_or(|selection| selection.contains(&provider))
            && self.defining_owner.is_none_or(|defining| {
                (defining.extraction.is_some() && provenance.extraction.is_none())
                    || ModelProvider::from(defining) == provider
            })
    }

    pub fn new(
        active: &'a ResolvedActiveSemanticModels,
        reader: &'a CatalogRuntimeSourceReader,
        generated: &'a [SemanticModelSymbol],
        generated_relations: &'a [SemanticModelRelation],
    ) -> Self {
        Self {
            selection: None,
            defining_owner: None,
            active,
            reader,
            generated,
            generated_relations,
            scope: None,
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
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        let shards = self
            .active
            .shards
            .iter()
            .filter(|shard| {
                let provider = ModelProvider {
                    pack_id: shard.manifest.pack_id.clone(),
                    pack_version: shard.manifest.version.clone(),
                    pack_digest: shard.manifest.semantic_sha256.clone(),
                };
                shard.manifest.language == language
                    && self
                        .selection
                        .is_none_or(|selection| selection.contains(&provider))
                    && self.defining_owner.is_none_or(|defining| {
                        (defining.extraction.is_some() && shard.manifest.extraction.is_none())
                            || ModelProvider::from(defining) == provider
                    })
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
            reader: self.reader,
            generated: self.generated,
            generated_relations: self.generated_relations,
            cancellation: self.cancellation,
            scope: Some(LanguageScope {
                language,
                shard_keys: serde_json::to_string(&shards).expect("shard identities serialize"),
            }),
        }
    }

    fn generated_symbols(&self) -> impl Iterator<Item = &SemanticModelSymbol> {
        self.generated.iter().filter(|symbol| {
            self.admits_provenance(&symbol.provenance)
                && self
                    .scope
                    .as_ref()
                    .is_none_or(|scope| symbol.language == scope.language)
        })
    }

    fn generated_edges(&self) -> impl Iterator<Item = &SemanticModelRelation> {
        self.generated_relations.iter().filter(|relation| {
            self.admits_provenance(&relation.provenance)
                && self.scope.as_ref().is_none_or(|scope| {
                    self.active.shards.iter().any(|shard| {
                        shard.manifest.language == scope.language
                            && shard.manifest.semantic_sha256 == relation.provenance.pack_digest
                    })
                })
        })
    }

    fn raw_rows<T>(
        &self,
        statement: &str,
        params: &[(&str, &dyn ToSql)],
        decode: impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> ReadResult<Vec<crate::analyzer::store::model_catalog::CatalogRawRecord<T>>> {
        check_composition_cancellation(self.cancellation)?;
        let Some(scope) = &self.scope else {
            return self
                .reader
                .raw_rows(statement, params, &self.active.shards, decode);
        };
        let statement = format!(
            "SELECT composition_row.* FROM ({}) AS composition_row
             JOIN json_each(:composition_shards) AS selected_shard
             ON composition_row.source_db=json_extract(selected_shard.value,'$[0]')
             AND composition_row.shard_key=json_extract(selected_shard.value,'$[1]')",
            statement.trim_end().trim_end_matches(';')
        );
        let mut params = params.to_vec();
        params.push((":composition_shards", &scope.shard_keys));
        self.reader
            .raw_rows(&statement, params.as_slice(), &self.active.shards, decode)
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
                    row.as_ref()
                        .column_index("record_json")
                        .expect("record JSON column"),
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
        decode: impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
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
        rows.sort_by_key(|(shard, record, _)| (*shard, *record));
        rows.dedup_by_key(|(shard, record, _)| (*shard, *record));
        Ok(rows.into_iter().map(|(_, _, record)| record).collect())
    }

    fn types(
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

    pub(crate) fn source_anchors(
        &self,
        analyzer: &dyn IAnalyzer,
    ) -> ReadResult<locations::SourceAnchors> {
        let mut anchors = locations::SourceAnchors::default();
        let owners = self
            .types(questions::SOURCE_TYPES, &[])?
            .into_iter()
            .filter(|r| r.shard.decoded.is_none())
            .map(|r| r.record.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for id in owners {
            for symbol in self.owner_symbols(analyzer, &id)? {
                anchors.insert_symbol("type", symbol);
            }
        }
        let members = self
            .members(questions::SOURCE_MEMBERS, &[])?
            .into_iter()
            .filter(|r| r.shard.decoded.is_none())
            .map(|r| r.record.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for id in members {
            for symbol in self.member_symbols(analyzer, &id)? {
                anchors.insert_symbol("member", symbol);
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
    pub(crate) fn owner_qualification(&self, id: &str) -> ReadResult<Option<String>> {
        self.projection().owner_qualification(id)
    }

    /// Project only matched raw IDs. The two batch reads also supply every
    /// same-ID contributor for the existing selection and identity-conflict
    /// rules. Ordinary qualification comes from scalar rows; exceptional
    /// qualification is the same shared keyed read used by group projection.
    pub(crate) fn search_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        ids: &[String],
        owner_names: HashMap<String, Option<String>>,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let projection = self.projection();
        *projection.owner_names.borrow_mut() = owner_names;
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
        id: &str,
    ) -> ReadResult<(RepresentativeIdentity, OriginRewrites)> {
        self.projection().endpoint_representatives(analyzer, id)
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
    fn types_with_id(&self, id: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(resolve_records(self.all_type_records_with_id(id)?).records)
    }
    fn types_named(&self, name: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(resolve_records(self.types(
            questions::TYPES_BY_IDENTITY_NAME,
            named_params! { ":name": name },
        )?)
        .records)
    }
    fn all_member_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        self.members(questions::MEMBERS_BY_ID, named_params! { ":id": id })
    }
    fn members_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        Ok(resolve_records(self.all_member_records_with_id(id)?).records)
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
                                row.as_ref()
                                    .column_index("relation_kind")
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
    owner_names: std::cell::RefCell<HashMap<String, Option<String>>>,
    group_names: std::cell::RefCell<HashMap<CompositionGroupKey, Vec<String>>>,
    summaries: std::cell::RefCell<HashMap<SummaryQuestion, Vec<Arc<CompiledProcedureSummary>>>>,
}

impl<'query> GroupProjection<'query> {
    fn poll(&self) -> ReadResult<()> {
        check_composition_cancellation(self.reads.cancellation())
    }

    pub(in crate::analyzer::semantic_model::overlay) fn new(reads: &'query dyn GroupInput) -> Self {
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

    fn owner_qualification(&self, id: &str) -> ReadResult<Option<String>> {
        if let Some(name) = self.owner_names.borrow().get(id) {
            return Ok(name.clone());
        }
        let records = self.all_type_records_with_id(id)?;
        let matched =
            with_artifact_declarations(resolve_records(records.clone()), records.into_iter());
        let name = qualified_owner_name(&matched).map(str::to_owned);
        self.owner_names
            .borrow_mut()
            .insert(id.to_owned(), name.clone());
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
    fn types_with_id(&self, id: &str) -> ReadResult<TypeRecords> {
        Ok(resolve_records(self.all_type_records_with_id(id)?).records)
    }
    fn types_named(&self, name: &str) -> ReadResult<TypeRecords> {
        if let Some(records) = self.types_by_name.borrow().get(name) {
            return Ok(resolve_records(records.clone()).records);
        }
        let records = self.reads.all_types_named(name)?;
        self.types_by_name
            .borrow_mut()
            .insert(name.to_owned(), records.clone());
        Ok(resolve_records(records).records)
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
    fn members_with_id(&self, id: &str) -> ReadResult<MemberRecords> {
        Ok(resolve_records(self.all_member_records_with_id(id)?).records)
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
            return vec![with_artifact_declarations(
                resolve_records(records.clone()),
                records.into_iter(),
            )];
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
            .map(|records| {
                with_artifact_declarations(resolve_records(records.clone()), records.into_iter())
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
                let owner = self.owner_qualification(&activated.record.owner)?;
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
        for owner in owners {
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
            let matched = resolve_records(records);
            let ambiguous = matched.disposition == SemanticModelMatchDisposition::Conflict;
            relations.extend(
                matched
                    .records
                    .iter()
                    .filter(|r| ids.contains(&r.record.from))
                    .map(|r| relation(self.reads.active(), &r.shard, &r.record, ambiguous)),
            );
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
            .map(|s| s.id.clone())
            .collect::<HashSet<_>>();
        endpoints.extend(
            relations
                .iter()
                .flat_map(|r| [r.from.clone(), r.to.clone()]),
        );
        for id in endpoints {
            self.poll()?;
            let (representative, origins) = self.endpoint_representatives(analyzer, &id)?;
            for (pack, ids) in origins {
                self.poll()?;
                origin_identities.entry(pack).or_default().extend(ids);
            }
            if representative.composed {
                composed_owners.insert(id.clone());
            }
            if let Some((_, replacement)) = representative
                .replacements
                .into_iter()
                .rev()
                .find(|(raw, _)| raw == &id)
            {
                replacements.insert(id.clone(), replacement);
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
