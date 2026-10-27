//! Query-local catalog reads for one composition group. No decoded payloads.

use super::*;
use crate::analyzer::semantic::oracle::dispatch::authored_procedure_target_identity;
use crate::analyzer::store::active_models::{resolve_procedure_records, resolve_records};
use crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements as questions;
use brokk_bifrost_semantic::analyzer::semantic_model::runtime::{
    ProcedureSummaryAcceptance, procedure_claims_agree, procedure_summary_minimum_actual_count,
};
use rusqlite::named_params;

/// Connection-only outside reads; generated symbols belong to this overlay
/// build, and are included by the group loader and keyed identity checks.
pub struct RowCompositionReads<'a> {
    pub active: &'a ResolvedActiveSemanticModels,
    pub reader: &'a CatalogRuntimeSourceReader,
    pub generated: &'a [SemanticModelSymbol],
    pub generated_relations: &'a [SemanticModelRelation],
}

impl RowCompositionReads<'_> {
    fn records<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        params: impl rusqlite::Params,
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
        params: impl rusqlite::Params,
        decode: impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<T>>> {
        let mut rows = self
            .reader
            .raw_rows(statement, params, &self.active.shards, |row| {
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
        params: impl rusqlite::Params,
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
        params: impl rusqlite::Params,
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
            .types(questions::SOURCE_TYPES, [])?
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
            .members(questions::SOURCE_MEMBERS, [])?
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

    fn projection(&self) -> GroupProjection<'_, '_> {
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
        self.projection().group_owners(analyzer, key)
    }
    pub fn group_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        self.projection().group_symbols(analyzer, key)
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
        self.projection().group_relations(analyzer, symbols)
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
        self.projection().compose_group(analyzer, key)
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
        let mut owners = HashSet::default();
        for declaration in self.types(
            questions::TYPES_BY_IDENTITY_NAME,
            named_params! { ":name": key.owner },
        )? {
            if declaration.shard.manifest.extraction.is_some()
                && brokk_bifrost_core::analyzer::model::semantic_pack_realm(
                    &declaration.shard.manifest.language,
                ) == realm
            {
                owners.insert(declaration.record.name.clone());
                owners.extend(declaration.record.aliases.iter().cloned());
            }
        }
        owners.remove(key.owner);
        let mut owners = owners.into_iter().collect::<Vec<_>>();
        owners.sort_unstable();
        owners.push(key.owner.to_owned());
        let records = self.records::<CompiledProcedureSummary>(questions::SUMMARY_MEMBER, named_params! { ":realm": realm, ":owners": serde_json::to_string(&owners).expect("owner IDs serialize"), ":member": key.member, ":receiver": key.has_receiver })?;
        let mut candidates = Vec::new();
        for (index, record) in records.iter().enumerate() {
            let target = &record.record.target;
            let (owner, _) = authored_procedure_target_identity(&target.path, &target.symbol)
                .expect("member question has target identity");
            let owner = owners
                .iter()
                .position(|name| name == &owner)
                .expect("question restricts owners");
            if !target.variadic && target.parameter_count == key.parameter_count {
                candidates.push(((0, 0, 0, owner, index), record.clone()));
            }
            let minimum = procedure_summary_minimum_actual_count(target);
            if target.variadic && minimum <= key.parameter_count {
                candidates.push(((1, minimum, 0, owner, index), record.clone()));
            }
            if !target.formals.is_empty() && target.formals.iter().any(|f| f.optional) {
                let minimum = u32::try_from(target.formals.iter().filter(|f| !f.optional).count())
                    .expect("validated formal count");
                if minimum <= key.parameter_count && target.parameter_count >= key.parameter_count {
                    candidates.push((
                        (2, minimum, target.parameter_count, owner, index),
                        record.clone(),
                    ));
                }
            }
        }
        candidates.sort_by_key(|(order, _)| *order);
        Ok(resolve_procedure_records(
            candidates.into_iter().map(|(_, r)| r),
            procedure_claims_agree,
            |_, _| ProcedureSummaryAcceptance::Accept(None),
        )
        .records
        .into_iter()
        .map(|r| r.record)
        .collect())
    }
}

type TypeRecords = Vec<ActivatedSemanticModelRecord<TypeFact>>;
type MemberRecords = Vec<ActivatedSemanticModelRecord<MemberFact>>;
type SummaryQuestion = (String, String, String, bool, u32);

/// Results reused only while answering this projection. A composed group
/// creates one of these on its stack and drops it before returning. No raw
/// records or qualifications are shared with another group or request.
struct GroupProjection<'query, 'models> {
    reads: &'query RowCompositionReads<'models>,
    types_by_id: std::cell::RefCell<HashMap<String, TypeRecords>>,
    types_by_name: std::cell::RefCell<HashMap<String, TypeRecords>>,
    members_by_id: std::cell::RefCell<HashMap<String, MemberRecords>>,
    owner_names: std::cell::RefCell<HashMap<String, Option<String>>>,
    group_names: std::cell::RefCell<HashMap<CompositionGroupKey, Vec<String>>>,
    summaries: std::cell::RefCell<HashMap<SummaryQuestion, Vec<Arc<CompiledProcedureSummary>>>>,
}

impl<'query, 'models> std::ops::Deref for GroupProjection<'query, 'models> {
    type Target = RowCompositionReads<'models>;
    fn deref(&self) -> &Self::Target {
        self.reads
    }
}

impl<'query, 'models> GroupProjection<'query, 'models> {
    fn new(reads: &'query RowCompositionReads<'models>) -> Self {
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
        let namespace = if key.module_namespace {
            "module"
        } else {
            "type"
        };
        let rows = self.reader.raw_rows(
            questions::GROUP_OWNER_IDS,
            named_params! { ":name":name,":language":key.language,":namespace":namespace },
            &self.active.shards,
            |row| row.get::<_, String>("record_id"),
        )?;
        let ids = rows
            .into_iter()
            .map(|row| Arc::unwrap_or_clone(row.record))
            .collect::<Vec<_>>();
        self.group_names.borrow_mut().insert(question, ids.clone());
        Ok(ids)
    }
}

impl CompositionReads for GroupProjection<'_, '_> {
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
        let records = self.reads.types(
            questions::TYPES_BY_IDENTITY_NAME,
            named_params! { ":name":name },
        )?;
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

impl GroupProjection<'_, '_> {
    fn owner_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let records = self.all_type_records_with_id(id)?;
        let matched =
            with_artifact_declarations(resolve_records(records.clone()), records.into_iter());
        let ambiguous = type_declaration_records_conflict(&matched);
        let mut result = Vec::new();
        for (index, activated) in matched.records.iter().enumerate() {
            if matched.records[..index].iter().any(|earlier| {
                earlier.record.runtime_bases != activated.record.runtime_bases
                    && type_declarations_equivalent(&earlier.record, &activated.record)
            }) {
                continue;
            }
            result.push(type_symbol(
                analyzer,
                self.active,
                &activated.shard,
                &activated.record,
                ambiguous,
            ));
        }
        Ok(result)
    }

    fn member_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let records = self.all_member_records_with_id(id)?;
        let matched =
            with_artifact_declarations(resolve_records(records.clone()), records.into_iter());
        let ambiguous = declaration_records_conflict(&matched);
        let mut result = Vec::new();
        for activated in matched.records {
            let owner = self.owner_qualification(&activated.record.owner)?;
            result.push(member_symbol(
                analyzer,
                self.active,
                &activated.shard,
                &activated.record,
                owner.as_deref(),
                ambiguous,
            ));
        }
        Ok(result)
    }

    fn symbols_with_id(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        id: &str,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let mut symbols = self.owner_symbols(analyzer, id)?;
        symbols.extend(self.member_symbols(analyzer, id)?);
        symbols.extend(self.generated.iter().filter(|s| s.id == id).cloned());
        Ok(symbols)
    }

    /// Close canonical/alias spellings iteratively, including generated owners
    /// from this build. Terminal simple names are deliberately not group edges.
    fn group_owners(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let mut pending = vec![key.identity.clone()];
        let mut visited = HashSet::default();
        let mut owners = Vec::new();
        let mut seen = HashSet::default();
        while let Some(name) = pending.pop() {
            if !visited.insert(name.clone()) {
                continue;
            }
            let ids = self.owner_ids_named(key, &name)?;
            let mut candidates = Vec::new();
            for id in ids {
                candidates.extend(self.owner_symbols(analyzer, &id)?);
            }
            candidates.extend(
                self.generated
                    .iter()
                    .filter(|s| {
                        s.owner_id.is_none()
                            && s.language == key.language
                            && (s.kind == SemanticModelSymbolKind::Module) == key.module_namespace
                            && (s.qualified_name == name || s.aliases.contains(&name))
                    })
                    .cloned(),
            );
            for symbol in candidates {
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

    fn group_symbols(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<Vec<SemanticModelSymbol>> {
        let owners = self.group_owners(analyzer, key)?;
        let owner_ids = owners.iter().map(|s| s.id.clone()).collect::<HashSet<_>>();
        let mut ordered_owner_ids = owner_ids.iter().collect::<Vec<_>>();
        ordered_owner_ids.sort_unstable();
        let members=self.reader.raw_rows(questions::MEMBER_IDS_BY_OWNERS,named_params! { ":owner_ids":serde_json::to_string(&ordered_owner_ids).expect("owner IDs serialize") },&self.active.shards,|row|row.get::<_,String>("record_id"))?;
        let mut member_ids = members
            .iter()
            .map(|r| r.record.as_str())
            .collect::<Vec<_>>();
        member_ids.sort_unstable();
        member_ids.dedup();
        let mut symbols = owners;
        for id in member_ids {
            symbols.extend(
                self.member_symbols(analyzer, id)?
                    .into_iter()
                    .filter(|s| s.owner_id.as_ref().is_some_and(|id| owner_ids.contains(id))),
            );
        }
        symbols.extend(
            self.generated
                .iter()
                .filter(|s| s.owner_id.as_ref().is_some_and(|id| owner_ids.contains(id)))
                .cloned(),
        );
        symbols.sort_by(symbol_source_order);
        let mut ids = symbols.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
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
                symbols[index].provenance.ambiguous = all[other].provenance.ambiguous;
            }
        }
        Ok(symbols)
    }
}

impl GroupProjection<'_, '_> {
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
            self.generated
                .iter()
                .filter(|s| s.id == id && s.owner_id.is_none())
                .cloned(),
        );
        for owner in owners {
            let key = CompositionGroupKey {
                language: owner.language,
                module_namespace: owner.kind == SemanticModelSymbolKind::Module,
                identity: owner.qualified_name,
            };
            let owners = self.group_owners(analyzer, &key)?;
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
            let representative = representative_identity(&owners.iter().collect::<Vec<_>>(), self)?;
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
            for owner in self.owner_symbols(analyzer, id)? {
                let ambiguous = owner.provenance.ambiguous;
                for record in self
                    .all_type_records_with_id(&owner.id)?
                    .into_iter()
                    .filter(|r| r.shard.manifest.semantic_sha256 == owner.provenance.pack_digest)
                {
                    relations.extend(record.record.hierarchy.iter().map(|hierarchy| {
                        hierarchy_relation(
                            self.active,
                            &record.shard,
                            &owner.id,
                            hierarchy,
                            ambiguous,
                        )
                    }));
                }
            }
        }
        let mut relation_ids = HashSet::default();
        for id in ids {
            for record in self.reader.raw_rows(
                questions::RELATIONS_FROM,
                named_params! { ":id": id },
                &self.active.shards,
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
        for id in relation_ids {
            let records = self.ordered_records::<RelationFact>(
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
            )?;
            let matched = resolve_records(records);
            let ambiguous = matched.disposition == SemanticModelMatchDisposition::Conflict;
            relations.extend(
                matched
                    .records
                    .iter()
                    .filter(|r| ids.contains(&r.record.from))
                    .map(|r| relation(self.active, &r.shard, &r.record, ambiguous)),
            );
        }
        relations.extend(
            self.generated_relations
                .iter()
                .filter(|r| ids.contains(&r.from))
                .cloned(),
        );
        relations.sort_by(relation_source_order);
        Ok(relations)
    }

    /// The row driver asks only for this group and the identity of endpoints.
    /// It never composes a neighboring group to rewrite an edge.
    fn compose_group(
        &self,
        analyzer: &(impl SemanticModelLocations + ?Sized),
        key: &CompositionGroupKey,
    ) -> ReadResult<ComposedGroup> {
        let mut symbols = self.group_symbols(analyzer, key)?;
        freeze_symbol_order(&mut symbols);
        debug_assert_group_backing(&symbols, self.active);
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
            let (representative, origins) = self.endpoint_representatives(analyzer, &id)?;
            for (pack, ids) in origins {
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
