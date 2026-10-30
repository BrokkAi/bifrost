//! Selected decoded-shard input for the shared group projection and kernel.

use super::*;
use crate::analyzer::semantic_model::ArtifactExtraction;
use crate::analyzer::store::active_models::resolve_records;

pub(in crate::analyzer::semantic_model::overlay) struct SelectedDecodedReads<'a> {
    pub language: &'a str,
    pub active: &'a ResolvedActiveSemanticModels,
    pub selection: &'a ModelProviderSelection,
    pub defining_owner: Option<&'a SemanticModelProvenance>,
    pub generated: &'a [SemanticModelSymbol],
    pub generated_relations: &'a [SemanticModelRelation],
    pub cancellation: &'a crate::CancellationToken,
}

impl SelectedDecodedReads<'_> {
    fn admits_shard(&self, shard: &ActiveSemanticModelShard) -> bool {
        let provider = ModelProvider {
            pack_id: shard.manifest.pack_id.clone(),
            pack_version: shard.manifest.version.clone(),
            pack_digest: shard.manifest.semantic_sha256.clone(),
        };
        shard.manifest.language == self.language
            && self.admits_provider(&provider, shard.manifest.extraction.as_ref())
    }

    fn shards(&self) -> impl Iterator<Item = &Arc<ActiveSemanticModelShard>> {
        self.active
            .shards
            .iter()
            .filter(|shard| self.admits_shard(shard))
    }

    fn admits_provenance(&self, provenance: &SemanticModelProvenance) -> bool {
        let provider = ModelProvider::from(provenance);
        self.active.shards.iter().any(|shard| {
            shard.manifest.language == self.language
                && shard.manifest.semantic_sha256 == provenance.pack_digest
        }) && self.admits_provider(&provider, provenance.extraction.as_ref())
    }

    fn admits_provider(
        &self,
        provider: &ModelProvider,
        extraction: Option<&ArtifactExtraction>,
    ) -> bool {
        self.selection.contains(provider)
            && super::admits_defining_owner(self.defining_owner, provider, extraction)
    }
}

impl CompositionReads for SelectedDecodedReads<'_> {
    fn all_type_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(self
            .active
            .decoded_type_records_with_id(id)
            .filter(|r| self.admits_shard(&r.shard))
            .collect())
    }
    fn types_named(&self, name: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(resolve_records(self.all_types_named(name)?).records)
    }
    fn all_member_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        Ok(self
            .active
            .decoded_member_records_with_id(id)
            .filter(|r| self.admits_shard(&r.shard))
            .collect())
    }
    fn procedure_summaries_for_member(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
    ) -> ReadResult<Vec<Arc<CompiledProcedureSummary>>> {
        let realm = brokk_bifrost_core::analyzer::model::semantic_pack_realm(key.language);
        let owners = procedure_owner_names(self.all_types_named(key.owner)?, key);
        let mut records = Vec::new();
        for shard in self.shards() {
            check_composition_cancellation(Some(self.cancellation))?;
            if brokk_bifrost_core::analyzer::model::semantic_pack_realm(&shard.manifest.language)
                != realm
            {
                continue;
            }
            for record in shard
                .decoded
                .as_ref()
                .into_iter()
                .filter_map(|decoded| decoded.payload().procedure_summaries())
                .flatten()
            {
                check_composition_cancellation(Some(self.cancellation))?;
                let (owner, member) = crate::analyzer::semantic::oracle::dispatch::authored_procedure_target_identity(
                    &record.target.path, &record.target.symbol).expect("validated procedure target");
                if owners.iter().any(|name| name == owner.as_ref())
                    && member == key.member
                    && record.target.has_receiver == key.has_receiver
                {
                    records.push(ActivatedSemanticModelRecord {
                        shard: Arc::clone(shard),
                        record: Arc::clone(record),
                    });
                }
            }
        }
        select_procedure_summaries(records, &owners, key)
    }
}

impl GroupInput for SelectedDecodedReads<'_> {
    fn cancellation(&self) -> Option<&crate::CancellationToken> {
        Some(self.cancellation)
    }
    fn for_language<'a>(&'a self, language: &'a str) -> Box<dyn GroupInput + 'a> {
        Box::new(SelectedDecodedReads {
            language,
            active: self.active,
            selection: self.selection,
            defining_owner: self.defining_owner,
            generated: self.generated,
            generated_relations: self.generated_relations,
            cancellation: self.cancellation,
        })
    }
    fn provider_selection(&self) -> Option<&ModelProviderSelection> {
        Some(self.selection)
    }
    fn defining_owner(&self) -> Option<&SemanticModelProvenance> {
        self.defining_owner
    }
    fn active(&self) -> &ResolvedActiveSemanticModels {
        self.active
    }
    fn all_types_named(
        &self,
        name: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(self
            .active
            .decoded_type_records_named(name)
            .filter(|r| self.admits_shard(&r.shard))
            .collect())
    }
    fn owner_ids_named(&self, key: &CompositionGroupKey, name: &str) -> ReadResult<Vec<String>> {
        Ok(self
            .all_types_named(name)?
            .into_iter()
            .filter(|record| {
                record.shard.manifest.language == key.language
                    && (record.record.type_kind
                        == crate::analyzer::semantic_model::TypeKind::Module)
                        == key.module_namespace
            })
            .map(|record| record.record.id.clone())
            .collect())
    }
    fn member_ids_by_owners(&self, owners: &[&String]) -> ReadResult<Vec<String>> {
        let mut ids = Vec::new();
        for owner in owners {
            check_composition_cancellation(Some(self.cancellation))?;
            for id in self.active.decoded_member_ids_by_owner(owner) {
                check_composition_cancellation(Some(self.cancellation))?;
                if self.active.decoded_member_records_with_id(&id).any(|r| {
                    self.admits_shard(&r.shard)
                        && owners.iter().any(|owner| **owner == r.record.owner)
                }) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    fn relation_records_from(
        &self,
        ids: &HashSet<String>,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<RelationFact>>> {
        let mut relation_ids = HashSet::default();
        for id in ids {
            check_composition_cancellation(Some(self.cancellation))?;
            relation_ids.extend(
                self.active
                    .decoded_relation_records_from(id)
                    .map(|r| r.record.id.clone()),
            );
        }
        let mut records = Vec::new();
        for id in relation_ids {
            check_composition_cancellation(Some(self.cancellation))?;
            records.extend(
                self.active
                    .decoded_relation_records_with_id(&id)
                    .filter(|r| self.admits_shard(&r.shard)),
            );
        }
        Ok(records)
    }

    fn generated_symbols(&self) -> Box<dyn Iterator<Item = &SemanticModelSymbol> + '_> {
        Box::new(
            self.generated
                .iter()
                .filter(|s| self.admits_provenance(&s.provenance)),
        )
    }
    fn generated_relations(&self) -> Box<dyn Iterator<Item = &SemanticModelRelation> + '_> {
        Box::new(
            self.generated_relations
                .iter()
                .filter(|r| self.admits_provenance(&r.provenance)),
        )
    }
}
