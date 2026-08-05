use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use semver::{Version, VersionReq};
use sha2::{Digest, Sha256};

use super::{
    ActivationSelector, CatalogCoordinate, CatalogMiss, CatalogPackSourceKind,
    CompiledPackManifest, CompiledProcedureSummary, CompiledShard, GeneratorRule, MemberFact,
    PayloadKind, RelationFact, RuleTrigger, SemanticModelOverlay, SemanticModelOverlayBuildError,
    SemanticPackCatalog, SemanticPackSelectorQuery, TypeFact,
};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::is_lower_sha256;
use crate::analyzer::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};
use crate::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
};
use crate::analyzer::{IAnalyzer, Language};
use crate::hash::{HashMap, map_with_capacity};

pub const SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticModelActivationEvidence {
    pub language: String,
    pub ecosystem: String,
    pub package: Option<CatalogCoordinate>,
    pub module: Option<CatalogCoordinate>,
    pub toolchain: Option<CatalogCoordinate>,
    pub target: Option<String>,
    pub configuration: Option<String>,
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticModelControlScope {
    User,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticModelControlAction {
    Enable,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticModelPackSelector {
    pub pack_id: String,
    pub version: Option<VersionReq>,
    pub manifest_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticModelActivationControl {
    pub scope: SemanticModelControlScope,
    pub action: SemanticModelControlAction,
    pub selector: SemanticModelPackSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticModelRuntimeLimits {
    pub max_evidence_rows: usize,
    pub max_controls: usize,
    pub max_catalog_candidates: usize,
    pub max_loaded_shards: usize,
    pub max_records: usize,
    pub max_index_entries: usize,
    pub max_working_bytes: u64,
    pub max_retained_bytes: u64,
    pub max_explanations: usize,
}

impl Default for SemanticModelRuntimeLimits {
    fn default() -> Self {
        Self {
            max_evidence_rows: 4_096,
            max_controls: 4_096,
            max_catalog_candidates: 65_536,
            max_loaded_shards: 16_384,
            max_records: 4_000_000,
            max_index_entries: 16_000_000,
            max_working_bytes: 1 << 30,
            max_retained_bytes: 1 << 30,
            max_explanations: 65_536,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SemanticModelActivationRequest {
    pub bifrost_version: Version,
    pub evidence: Vec<SemanticModelActivationEvidence>,
    pub controls: Vec<SemanticModelActivationControl>,
    pub limits: SemanticModelRuntimeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticModelActivationStatus {
    Active,
    Disabled,
    Incompatible,
    ReviewRequired,
    Shadowed,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticModelActivationExplanation {
    pub manifest_digest: String,
    pub pack_id: Option<String>,
    pub shard_id: String,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub status: SemanticModelActivationStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticModelActivationReport {
    pub explanations: Vec<SemanticModelActivationExplanation>,
    pub suppressed_explanations: usize,
    pub catalog_candidates: usize,
    pub loaded_shards: usize,
    pub loaded_records: usize,
    pub index_entries: usize,
    pub working_bytes: u64,
    pub retained_bytes: u64,
}

#[derive(Debug)]
pub struct ActiveSemanticModelShard {
    pub manifest: CompiledPackManifest,
    pub shard: CompiledShard,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub matched_evidence: SemanticModelActivationEvidence,
    evidence_rank: EvidenceRank,
    source_rank: u8,
}

#[derive(Debug)]
pub struct ResolvedActiveSemanticModels {
    active_model_set_hash: String,
    shards: Vec<ActiveSemanticModelShard>,
    indexes: MatcherIndexes,
    report: SemanticModelActivationReport,
}

impl ResolvedActiveSemanticModels {
    pub fn active_model_set_hash(&self) -> &str {
        &self.active_model_set_hash
    }

    pub fn shards(&self) -> &[ActiveSemanticModelShard] {
        &self.shards
    }

    pub fn activation_report(&self) -> &SemanticModelActivationReport {
        &self.report
    }

    pub fn retained_bytes(&self) -> u64 {
        self.report.retained_bytes
    }

    pub fn types_with_id(&self, id: &str) -> SemanticModelMatch<'_, TypeFact> {
        self.type_match(self.indexes.types_by_id.get(id))
    }

    pub fn types_named(&self, name: &str) -> SemanticModelMatch<'_, TypeFact> {
        self.type_match(self.indexes.types_by_name.get(name))
    }

    pub fn members_with_id(&self, id: &str) -> SemanticModelMatch<'_, MemberFact> {
        self.member_match(self.indexes.members_by_id.get(id))
    }

    pub fn members_named(&self, owner: &str, name: &str) -> SemanticModelMatch<'_, MemberFact> {
        self.member_match(
            self.indexes
                .members_by_owner_name
                .get(owner)
                .and_then(|names| names.get(name)),
        )
    }

    pub fn relations_with_id(&self, id: &str) -> SemanticModelMatch<'_, RelationFact> {
        self.relation_match(self.indexes.relations_by_id.get(id))
    }

    pub fn relations_from(&self, from: &str) -> SemanticModelMatch<'_, RelationFact> {
        self.relation_match(self.indexes.relations_by_from.get(from))
    }

    pub fn relations_to(&self, to: &str) -> SemanticModelMatch<'_, RelationFact> {
        self.relation_match(self.indexes.relations_by_to.get(to))
    }

    pub fn rules_for(&self, trigger: RuleTriggerKey<'_>) -> SemanticModelMatch<'_, GeneratorRule> {
        let posting = match trigger {
            RuleTriggerKey::LanguageConstruct(value) => {
                self.indexes.rules_by_language_construct.get(value)
            }
            RuleTriggerKey::Annotation(value) => self.indexes.rules_by_annotation.get(value),
            RuleTriggerKey::MacroInvocation(value) => self.indexes.rules_by_macro.get(value),
            RuleTriggerKey::GeneratorInvocation(value) => {
                self.indexes.rules_by_generator.get(value)
            }
            RuleTriggerKey::ResolvedOwner(value) => self.indexes.rules_by_owner.get(value),
            RuleTriggerKey::ResolvedCall { owner, name } => self
                .indexes
                .rules_by_call
                .get(owner)
                .and_then(|names| names.get(name)),
        };
        self.rule_match(posting)
    }

    pub fn rules_with_id(&self, id: &str) -> SemanticModelMatch<'_, GeneratorRule> {
        self.rule_match(self.indexes.rules_by_id.get(id))
    }

    pub fn procedure_summaries_for(
        &self,
        target: ProcedureSummaryTargetKey<'_>,
    ) -> ProcedureSummaryMatch<'_> {
        let posting = self
            .indexes
            .procedure_summaries_by_target
            .get(target.language)
            .and_then(|paths| paths.get(target.path))
            .and_then(|symbols| symbols.get(target.symbol))
            .and_then(|shapes| shapes.get(&(target.has_receiver, target.parameter_count)));
        resolve_procedure_posting(&self.shards, posting)
    }

    fn type_match(&self, posting: Option<&Vec<RecordAddress>>) -> SemanticModelMatch<'_, TypeFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .shard
                .payload()
                .declaration_facts()
                .and_then(|(types, _, _)| types.get(record))
        })
    }

    fn member_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<'_, MemberFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .shard
                .payload()
                .declaration_facts()
                .and_then(|(_, members, _)| members.get(record))
        })
    }

    fn relation_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<'_, RelationFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .shard
                .payload()
                .declaration_facts()
                .and_then(|(_, _, relations)| relations.get(record))
        })
    }

    fn rule_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<'_, GeneratorRule> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard.shard.payload().generator_rules()?.get(record)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelMatchDisposition {
    Empty,
    Unique,
    Conflict,
}

#[derive(Debug)]
pub struct SemanticModelMatch<'a, T> {
    pub records: Vec<ActivatedSemanticModelRecord<'a, T>>,
    pub disposition: SemanticModelMatchDisposition,
    pub candidates_examined: usize,
    pub fallback_candidates_examined: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ActivatedSemanticModelRecord<'a, T> {
    pub record: &'a T,
    pub shard: &'a ActiveSemanticModelShard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureSummaryTargetKey<'a> {
    pub language: &'a str,
    pub path: &'a str,
    pub symbol: &'a str,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

impl<'a> ProcedureSummaryTargetKey<'a> {
    pub fn new(
        language: &'a str,
        path: &'a str,
        symbol: &'a str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> Self {
        Self {
            language,
            path,
            symbol,
            has_receiver,
            parameter_count,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ActivatedProcedureSummary<'a> {
    pub record: &'a CompiledProcedureSummary,
    pub shard: &'a ActiveSemanticModelShard,
    pub payload: &'a [CompiledProcedureSummary],
}

impl<'a> ActivatedProcedureSummary<'a> {
    pub fn summary_with_id(&self, id: &str) -> Option<&'a CompiledProcedureSummary> {
        self.payload.iter().find(|summary| summary.id == id)
    }
}

#[derive(Debug)]
pub struct ProcedureSummaryMatch<'a> {
    pub records: Vec<ActivatedProcedureSummary<'a>>,
    pub disposition: SemanticModelMatchDisposition,
    pub candidates_examined: usize,
    pub fallback_candidates_examined: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTriggerKey<'a> {
    LanguageConstruct(&'a str),
    Annotation(&'a str),
    MacroInvocation(&'a str),
    GeneratorInvocation(&'a str),
    ResolvedOwner(&'a str),
    ResolvedCall { owner: &'a str, name: &'a str },
}

#[derive(Debug, Clone, Copy)]
struct RecordAddress {
    shard: u32,
    record: u32,
}

type ProcedureSummaryTargetPostings =
    HashMap<String, HashMap<String, HashMap<String, HashMap<(bool, u32), Vec<RecordAddress>>>>>;

#[derive(Debug, Default)]
struct MatcherIndexes {
    types_by_id: HashMap<String, Vec<RecordAddress>>,
    types_by_name: HashMap<String, Vec<RecordAddress>>,
    members_by_id: HashMap<String, Vec<RecordAddress>>,
    members_by_owner_name: HashMap<String, HashMap<String, Vec<RecordAddress>>>,
    relations_by_id: HashMap<String, Vec<RecordAddress>>,
    relations_by_from: HashMap<String, Vec<RecordAddress>>,
    relations_by_to: HashMap<String, Vec<RecordAddress>>,
    rules_by_id: HashMap<String, Vec<RecordAddress>>,
    rules_by_language_construct: HashMap<String, Vec<RecordAddress>>,
    rules_by_annotation: HashMap<String, Vec<RecordAddress>>,
    rules_by_macro: HashMap<String, Vec<RecordAddress>>,
    rules_by_generator: HashMap<String, Vec<RecordAddress>>,
    rules_by_owner: HashMap<String, Vec<RecordAddress>>,
    rules_by_call: HashMap<String, HashMap<String, Vec<RecordAddress>>>,
    procedure_summaries_by_target: ProcedureSummaryTargetPostings,
}

impl MatcherIndexes {
    fn build(
        active: &[CandidateSelection],
        limits: SemanticModelRuntimeLimits,
        cancellation: &CancellationToken,
        report: &mut SemanticModelActivationReport,
    ) -> Result<Self, String> {
        let mut indexes = Self {
            types_by_id: map_with_capacity(active.len()),
            types_by_name: map_with_capacity(active.len()),
            members_by_id: map_with_capacity(active.len()),
            members_by_owner_name: map_with_capacity(active.len()),
            relations_by_id: map_with_capacity(active.len()),
            relations_by_from: map_with_capacity(active.len()),
            relations_by_to: map_with_capacity(active.len()),
            rules_by_id: map_with_capacity(active.len()),
            rules_by_language_construct: map_with_capacity(active.len()),
            rules_by_annotation: map_with_capacity(active.len()),
            rules_by_macro: map_with_capacity(active.len()),
            rules_by_generator: map_with_capacity(active.len()),
            rules_by_owner: map_with_capacity(active.len()),
            rules_by_call: map_with_capacity(active.len()),
            procedure_summaries_by_target: map_with_capacity(active.len()),
        };
        let mut entries = 0usize;
        let mut working_bytes = 0u64;
        let mut records_visited = 0usize;

        for (shard_index, selection) in active.iter().enumerate() {
            let shard = u32::try_from(shard_index)
                .map_err(|_| "semantic-model shard address exceeds u32".to_owned())?;
            if let Some((types, members, relations)) =
                selection.active.shard.payload().declaration_facts()
            {
                for (record_index, fact) in types.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard, record_index)?;
                    insert_posting(
                        &mut indexes.types_by_id,
                        fact.id.clone(),
                        fact.id.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    insert_posting(
                        &mut indexes.types_by_name,
                        fact.name.clone(),
                        fact.name.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    for alias in &fact.aliases {
                        insert_posting(
                            &mut indexes.types_by_name,
                            alias.clone(),
                            alias.len(),
                            address,
                            &mut entries,
                            &mut working_bytes,
                            limits,
                        )?;
                    }
                }
                for (record_index, fact) in members.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard, record_index)?;
                    insert_posting(
                        &mut indexes.members_by_id,
                        fact.id.clone(),
                        fact.id.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    insert_member_name(
                        &mut indexes.members_by_owner_name,
                        fact,
                        &fact.name,
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    for alias in &fact.aliases {
                        insert_member_name(
                            &mut indexes.members_by_owner_name,
                            fact,
                            alias,
                            address,
                            &mut entries,
                            &mut working_bytes,
                            limits,
                        )?;
                    }
                }
                for (record_index, fact) in relations.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard, record_index)?;
                    for (map, key) in [
                        (&mut indexes.relations_by_id, &fact.id),
                        (&mut indexes.relations_by_from, &fact.from),
                        (&mut indexes.relations_by_to, &fact.to),
                    ] {
                        insert_posting(
                            map,
                            key.clone(),
                            key.len(),
                            address,
                            &mut entries,
                            &mut working_bytes,
                            limits,
                        )?;
                    }
                }
            }
            if let Some(rules) = selection.active.shard.payload().generator_rules() {
                for (record_index, rule) in rules.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard, record_index)?;
                    insert_posting(
                        &mut indexes.rules_by_id,
                        rule.id.clone(),
                        rule.id.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    insert_rule_trigger(
                        &mut indexes,
                        &rule.trigger,
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                }
            }
            if let Some(summaries) = selection.active.shard.payload().procedure_summaries() {
                for (record_index, summary) in summaries.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard, record_index)?;
                    let key_bytes = selection
                        .active
                        .manifest
                        .language
                        .len()
                        .saturating_add(summary.target.path.len())
                        .saturating_add(summary.target.symbol.len())
                        .saturating_add(size_of::<bool>())
                        .saturating_add(size_of::<u32>());
                    let paths = indexes
                        .procedure_summaries_by_target
                        .entry(selection.active.manifest.language.clone())
                        .or_default();
                    let symbols = paths.entry(summary.target.path.clone()).or_default();
                    let shapes = symbols.entry(summary.target.symbol.clone()).or_default();
                    insert_posting(
                        shapes,
                        (summary.target.has_receiver, summary.target.parameter_count),
                        key_bytes,
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                }
            }
        }

        let shard_bytes = active
            .iter()
            .try_fold(0u64, |total, selection| {
                total.checked_add(
                    selection
                        .active
                        .manifest
                        .shards
                        .iter()
                        .find(|descriptor| {
                            descriptor.shard_id == selection.active.shard.shard_id()
                        })?
                        .raw_size,
                )
            })
            .ok_or_else(|| "semantic-model retained-byte accounting overflowed".to_owned())?;
        let retained_bytes = working_bytes
            .checked_add(shard_bytes)
            .ok_or_else(|| "semantic-model retained-byte accounting overflowed".to_owned())?;
        if retained_bytes > limits.max_retained_bytes {
            return Err("semantic-model retained-byte budget exceeded".to_owned());
        }
        report.index_entries = entries;
        report.working_bytes = working_bytes;
        report.retained_bytes = retained_bytes;
        Ok(indexes)
    }
}

fn record_address(shard: u32, record: usize) -> Result<RecordAddress, String> {
    Ok(RecordAddress {
        shard,
        record: u32::try_from(record)
            .map_err(|_| "semantic-model record address exceeds u32".to_owned())?,
    })
}

fn poll_matcher_cancellation(
    cancellation: &CancellationToken,
    records_visited: usize,
) -> Result<(), String> {
    if records_visited.is_multiple_of(1_024) && cancellation.is_cancelled() {
        return Err("semantic-model matcher construction cancelled".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_posting<K: Eq + std::hash::Hash>(
    map: &mut HashMap<K, Vec<RecordAddress>>,
    key: K,
    key_bytes: usize,
    address: RecordAddress,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    *entries = entries
        .checked_add(1)
        .ok_or_else(|| "semantic-model index-entry accounting overflowed".to_owned())?;
    if *entries > limits.max_index_entries {
        return Err("semantic-model index-entry budget exceeded".to_owned());
    }
    *working_bytes = working_bytes
        .checked_add((key_bytes + size_of::<RecordAddress>() + 32) as u64)
        .ok_or_else(|| "semantic-model working-byte accounting overflowed".to_owned())?;
    if *working_bytes > limits.max_working_bytes {
        return Err("semantic-model working-byte budget exceeded".to_owned());
    }
    map.entry(key).or_default().push(address);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_member_name(
    map: &mut HashMap<String, HashMap<String, Vec<RecordAddress>>>,
    fact: &MemberFact,
    name: &str,
    address: RecordAddress,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    let names = map.entry(fact.owner.clone()).or_default();
    insert_posting(
        names,
        name.to_owned(),
        fact.owner.len() + name.len(),
        address,
        entries,
        working_bytes,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_rule_trigger(
    indexes: &mut MatcherIndexes,
    trigger: &RuleTrigger,
    address: RecordAddress,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    let (map, value) = match trigger {
        RuleTrigger::LanguageConstruct { construct } => {
            (&mut indexes.rules_by_language_construct, construct)
        }
        RuleTrigger::Annotation { name } => (&mut indexes.rules_by_annotation, name),
        RuleTrigger::AnnotatedField { annotation, .. } => {
            (&mut indexes.rules_by_annotation, annotation)
        }
        RuleTrigger::MacroInvocation { name } => (&mut indexes.rules_by_macro, name),
        RuleTrigger::GeneratorInvocation { name } => (&mut indexes.rules_by_generator, name),
        RuleTrigger::ResolvedOwner { owner } => (&mut indexes.rules_by_owner, owner),
        RuleTrigger::ResolvedCall { owner, name } => {
            let names = indexes.rules_by_call.entry(owner.clone()).or_default();
            return insert_posting(
                names,
                name.clone(),
                owner.len() + name.len(),
                address,
                entries,
                working_bytes,
                limits,
            );
        }
    };
    insert_posting(
        map,
        value.clone(),
        value.len(),
        address,
        entries,
        working_bytes,
        limits,
    )
}

fn resolve_posting<'a, T: Eq, F>(
    shards: &'a [ActiveSemanticModelShard],
    posting: Option<&Vec<RecordAddress>>,
    mut resolve: F,
) -> SemanticModelMatch<'a, T>
where
    F: FnMut(&'a ActiveSemanticModelShard, usize) -> Option<&'a T>,
{
    let Some(posting) = posting else {
        return SemanticModelMatch {
            records: Vec::new(),
            disposition: SemanticModelMatchDisposition::Empty,
            candidates_examined: 0,
            fallback_candidates_examined: 0,
        };
    };
    let best_rank = posting
        .iter()
        .map(|address| {
            let shard = &shards[address.shard as usize];
            (shard.evidence_rank, shard.source_rank)
        })
        .max()
        .expect("non-empty semantic-model posting");
    let mut records = Vec::new();
    for address in posting {
        let shard = &shards[address.shard as usize];
        if (shard.evidence_rank, shard.source_rank) != best_rank {
            continue;
        }
        let record = resolve(shard, address.record as usize)
            .expect("semantic-model index address must resolve to its record kind");
        if !records
            .iter()
            .any(|candidate: &ActivatedSemanticModelRecord<'_, T>| candidate.record == record)
        {
            records.push(ActivatedSemanticModelRecord { record, shard });
        }
    }
    SemanticModelMatch {
        disposition: if records.len() == 1 {
            SemanticModelMatchDisposition::Unique
        } else {
            SemanticModelMatchDisposition::Conflict
        },
        records,
        candidates_examined: posting.len(),
        fallback_candidates_examined: 0,
    }
}

fn resolve_procedure_posting<'a>(
    shards: &'a [ActiveSemanticModelShard],
    posting: Option<&Vec<RecordAddress>>,
) -> ProcedureSummaryMatch<'a> {
    let Some(posting) = posting else {
        return ProcedureSummaryMatch {
            records: Vec::new(),
            disposition: SemanticModelMatchDisposition::Empty,
            candidates_examined: 0,
            fallback_candidates_examined: 0,
        };
    };
    let best_rank = posting
        .iter()
        .map(|address| {
            let shard = &shards[address.shard as usize];
            (shard.evidence_rank, shard.source_rank)
        })
        .max()
        .expect("non-empty procedure-summary posting");
    let mut records = Vec::<ActivatedProcedureSummary<'a>>::new();
    for address in posting {
        let shard = &shards[address.shard as usize];
        if (shard.evidence_rank, shard.source_rank) != best_rank {
            continue;
        }
        let payload = shard
            .shard
            .payload()
            .procedure_summaries()
            .expect("procedure-summary index address must resolve to its payload kind");
        let record = payload
            .get(address.record as usize)
            .expect("procedure-summary index address must resolve to its record");
        if records
            .iter()
            .any(|candidate| candidate.record == record && candidate.payload == payload)
        {
            continue;
        }
        records.push(ActivatedProcedureSummary {
            record,
            shard,
            payload,
        });
    }
    ProcedureSummaryMatch {
        disposition: if records.len() == 1 {
            SemanticModelMatchDisposition::Unique
        } else {
            SemanticModelMatchDisposition::Conflict
        },
        records,
        candidates_examined: posting.len(),
        fallback_candidates_examined: 0,
    }
}

#[derive(Debug)]
pub enum SemanticModelResolutionOutcome {
    Ready(ResolvedActiveSemanticModels),
    Incomplete {
        usable: Option<ResolvedActiveSemanticModels>,
        report: SemanticModelActivationReport,
    },
    Cancelled(SemanticModelActivationReport),
    Unavailable(SemanticModelActivationReport),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelRuntimeLifecycle {
    Cached,
    Built,
    Uncached,
}

#[derive(Debug)]
pub enum SemanticModelRuntimeOutcome {
    Ready {
        active: Arc<ResolvedActiveSemanticModels>,
        lifecycle: SemanticModelRuntimeLifecycle,
    },
    Incomplete {
        usable: Option<Arc<ResolvedActiveSemanticModels>>,
        report: SemanticModelActivationReport,
    },
    Cancelled(SemanticModelActivationReport),
    Unavailable(SemanticModelActivationReport),
}

impl SemanticModelRuntimeOutcome {
    /// Convert an existing activation result into diagnostic suppression
    /// reasons. This method performs no activation, discovery, or package I/O.
    pub fn semantic_diagnostic_incomplete_reasons(
        &self,
    ) -> Vec<crate::analyzer::SemanticDiagnosticIncompleteReason> {
        use crate::analyzer::SemanticDiagnosticIncompleteReason;

        match self {
            Self::Ready { .. } => Vec::new(),
            Self::Incomplete { report, .. } => {
                vec![SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                    detail: format!("incomplete activation: {report:?}"),
                }]
            }
            Self::Cancelled(_) => vec![SemanticDiagnosticIncompleteReason::Cancelled],
            Self::Unavailable(report) => {
                vec![SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                    detail: format!("unavailable activation: {report:?}"),
                }]
            }
        }
    }
}

pub(crate) struct SemanticModelRuntimeCache {
    values: CompleteValueCache<String, ResolvedActiveSemanticModels>,
    published: Mutex<PublishedSemanticModelState>,
}

#[derive(Default)]
struct PublishedSemanticModelState {
    overlay: Option<PublishedSemanticModelOverlay>,
    dependency_evidence: HashMap<Language, Arc<super::DependencyDiscoveryEvidence>>,
}

struct PublishedSemanticModelOverlay {
    active: Arc<ResolvedActiveSemanticModels>,
    overlay: Arc<SemanticModelOverlay>,
}

#[derive(Clone, Copy)]
pub struct SemanticModelActivationPersistence<'a> {
    pub scope_id: &'a str,
    pub store: &'a AnalyzerStore,
}

impl Default for SemanticModelRuntimeCache {
    fn default() -> Self {
        Self::new(1)
    }
}

impl SemanticModelRuntimeCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            values: CompleteValueCache::<String, ResolvedActiveSemanticModels>::new(
                max_retained_bytes,
                |_, active| u32::try_from(active.retained_bytes()).unwrap_or(u32::MAX),
            ),
            published: Mutex::new(PublishedSemanticModelState::default()),
        }
    }

    /// Retain one discovery run's evidence for every language its ecosystem serves.
    /// Production hosts use the atomic activation method instead.
    #[cfg(test)]
    pub(crate) fn retain_dependency_discovery_evidence(
        &self,
        languages: &[Language],
        evidence: super::DependencyDiscoveryEvidence,
    ) {
        let evidence = Arc::new(evidence);
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        for language in languages {
            published
                .dependency_evidence
                .insert(*language, Arc::clone(&evidence));
        }
    }

    pub(crate) fn dependency_discovery_evidence(
        &self,
        language: Language,
    ) -> Option<Arc<super::DependencyDiscoveryEvidence>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .dependency_evidence
            .get(&language)
            .cloned()
    }

    pub(crate) fn invalidate_dependency_pack_state(&self, languages: &[Language]) -> bool {
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let mut evidence_changed = false;
        for language in languages {
            evidence_changed |= published.dependency_evidence.remove(language).is_some();
        }
        let overlay_changed = published.overlay.take().is_some();
        evidence_changed || overlay_changed
    }

    pub(crate) fn overlay(&self) -> Option<Arc<SemanticModelOverlay>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .overlay
            .as_ref()
            .map(|published| Arc::clone(&published.overlay))
    }

    fn publish_overlay(
        &self,
        analyzer: &dyn IAnalyzer,
        active: &Arc<ResolvedActiveSemanticModels>,
        dependency_evidence: Option<&[(Box<[Language]>, super::DependencyDiscoveryEvidence)]>,
        cancellation: &CancellationToken,
        max_combined_retained_bytes: u64,
    ) -> Result<Arc<SemanticModelOverlay>, SemanticModelOverlayBuildError> {
        {
            let published = self
                .published
                .lock()
                .expect("semantic-model publication mutex poisoned");
            if dependency_evidence.is_none()
                && let Some(overlay) = published.overlay.as_ref()
                && Arc::ptr_eq(&overlay.active, active)
            {
                return Ok(Arc::clone(&overlay.overlay));
            }
        }
        let overlay = Arc::new(SemanticModelOverlay::build(
            analyzer,
            active,
            cancellation,
            max_combined_retained_bytes,
        )?);
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        if dependency_evidence.is_none()
            && let Some(current) = published.overlay.as_ref()
            && Arc::ptr_eq(&current.active, active)
        {
            return Ok(Arc::clone(&current.overlay));
        }
        if let Some(evidence) = dependency_evidence {
            for (languages, value) in evidence {
                let value = Arc::new(value.clone());
                for language in languages {
                    published
                        .dependency_evidence
                        .insert(*language, Arc::clone(&value));
                }
            }
        }
        published.overlay = Some(PublishedSemanticModelOverlay {
            active: Arc::clone(active),
            overlay: Arc::clone(&overlay),
        });
        Ok(overlay)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EvidenceRank {
    Language,
    NamedCoordinate,
    VersionedCoordinate,
    ExactArtifact,
}

#[derive(Debug)]
struct CandidateSelection {
    active: ActiveSemanticModelShard,
    semantic_sha256: String,
    payload_kind: PayloadKind,
    evidence_rank: EvidenceRank,
    source_rank: u8,
}

pub fn resolve_active_semantic_models(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelResolutionOutcome {
    let mut report = SemanticModelActivationReport::default();
    let evidence = match validate_and_canonicalize_request(request) {
        Ok(evidence) => evidence,
        Err(reason) => {
            push_request_explanation(&mut report, request.limits, reason);
            return SemanticModelResolutionOutcome::Unavailable(report);
        }
    };
    if cancellation.is_cancelled() {
        return SemanticModelResolutionOutcome::Cancelled(report);
    }

    let mut candidates = BTreeMap::new();
    for row in &evidence {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = evidence_query(row, request.bifrost_version.clone());
        let discovered = match catalog.candidates(&query) {
            Ok(discovered) => discovered,
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("catalog candidate discovery failed: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        for candidate in discovered {
            let key = (
                candidate.manifest_digest().to_owned(),
                candidate.shard_id().to_owned(),
                candidate.source_kind(),
                candidate.source_id().to_owned(),
            );
            candidates.entry(key).or_insert(candidate);
            if candidates.len() > request.limits.max_catalog_candidates {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    "semantic-model catalog candidate budget exceeded".to_owned(),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        }
    }
    let mut language_ecosystems = evidence
        .iter()
        .map(|row| (row.language.clone(), row.ecosystem.clone()))
        .collect::<Vec<_>>();
    language_ecosystems.sort();
    language_ecosystems.dedup();
    for (language, ecosystem) in language_ecosystems {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = SemanticPackSelectorQuery {
            language,
            ecosystem,
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: request.bifrost_version.clone(),
        };
        let discovered = match catalog.candidates_bounded(
            &query,
            request.limits.max_catalog_candidates.saturating_add(1),
        ) {
            Ok(discovered) => discovered,
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("catalog candidate evaluation failed: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        for candidate in discovered {
            let key = (
                candidate.manifest_digest().to_owned(),
                candidate.shard_id().to_owned(),
                candidate.source_kind(),
                candidate.source_id().to_owned(),
            );
            candidates.entry(key).or_insert(candidate);
            if candidates.len() > request.limits.max_catalog_candidates {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    "semantic-model catalog candidate budget exceeded".to_owned(),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        }
    }
    report.catalog_candidates = candidates.len();

    let mut selected = Vec::<CandidateSelection>::new();
    let mut incomplete = false;
    for candidate in candidates.into_values() {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let loaded = match catalog.load(&candidate) {
            Ok(loaded) => loaded,
            Err(miss) => {
                incomplete = true;
                push_explanation(
                    &mut report,
                    request.limits,
                    SemanticModelActivationExplanation {
                        manifest_digest: candidate.manifest_digest().to_owned(),
                        pack_id: None,
                        shard_id: candidate.shard_id().to_owned(),
                        source_kind: candidate.source_kind(),
                        source_id: candidate.source_id().to_owned(),
                        status: SemanticModelActivationStatus::Unavailable,
                        reason: catalog_miss_reason(&miss),
                    },
                );
                continue;
            }
        };
        report.loaded_shards = report.loaded_shards.saturating_add(1);
        report.loaded_records = report
            .loaded_records
            .saturating_add(loaded.shard.record_count());
        if report.loaded_shards > request.limits.max_loaded_shards
            || report.loaded_records > request.limits.max_records
        {
            push_request_explanation(
                &mut report,
                request.limits,
                "semantic-model decoded shard budget exceeded".to_owned(),
            );
            return SemanticModelResolutionOutcome::Unavailable(report);
        }

        let Some((evidence_rank, matched_evidence)) = strict_activation_match(
            &loaded.manifest,
            &loaded.shard,
            &evidence,
            &request.bifrost_version,
        ) else {
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::Incompatible,
                "complete activation evidence does not satisfy the manifest and shard selector",
            );
            continue;
        };
        let control = match effective_control(&loaded.manifest, &request.controls) {
            Ok(control) => control,
            Err(reason) => {
                push_loaded_explanation(
                    &mut report,
                    request.limits,
                    &loaded,
                    SemanticModelActivationStatus::Conflict,
                    &reason,
                );
                incomplete = true;
                continue;
            }
        };
        if control == Some(SemanticModelControlAction::Disable) {
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::Disabled,
                "a compatible activation control disables this pack",
            );
            continue;
        }
        if loaded.shard.safety().review_required
            && control != Some(SemanticModelControlAction::Enable)
        {
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::ReviewRequired,
                "the pack requires an explicit compatible enable control",
            );
            continue;
        }

        let descriptor = candidate.descriptor();
        selected.push(CandidateSelection {
            semantic_sha256: descriptor.semantic_sha256.clone(),
            payload_kind: descriptor.payload_kind,
            evidence_rank,
            source_rank: source_rank(loaded.source_kind),
            active: ActiveSemanticModelShard {
                manifest: loaded.manifest,
                shard: loaded.shard,
                source_kind: loaded.source_kind,
                source_id: loaded.source_id,
                matched_evidence,
                evidence_rank,
                source_rank: source_rank(loaded.source_kind),
            },
        });
    }

    selected.sort_by(compare_selection);
    let mut active = Vec::new();
    let mut by_semantic_shard = BTreeMap::<(String, PayloadKind), usize>::new();
    for selection in selected.into_iter().rev() {
        let key = (selection.semantic_sha256.clone(), selection.payload_kind);
        if let Some(&winner) = by_semantic_shard.get(&key) {
            let active_winner: &CandidateSelection = &active[winner];
            push_explanation(
                &mut report,
                request.limits,
                SemanticModelActivationExplanation {
                    manifest_digest: selection.active.manifest.content_sha256.clone(),
                    pack_id: Some(selection.active.manifest.pack_id.clone()),
                    shard_id: selection.active.shard.shard_id().to_owned(),
                    source_kind: selection.active.source_kind,
                    source_id: selection.active.source_id.clone(),
                    status: SemanticModelActivationStatus::Shadowed,
                    reason: format!(
                        "equivalent semantic shard is supplied by higher-precedence source {}",
                        active_winner.active.source_id
                    ),
                },
            );
            continue;
        }
        by_semantic_shard.insert(key, active.len());
        active.push(selection);
    }
    active.sort_by(|left, right| {
        left.active
            .manifest
            .pack_id
            .cmp(&right.active.manifest.pack_id)
            .then_with(|| {
                left.active
                    .shard
                    .shard_id()
                    .cmp(right.active.shard.shard_id())
            })
            .then_with(|| left.semantic_sha256.cmp(&right.semantic_sha256))
    });

    for selection in &active {
        push_explanation(
            &mut report,
            request.limits,
            SemanticModelActivationExplanation {
                manifest_digest: selection.active.manifest.content_sha256.clone(),
                pack_id: Some(selection.active.manifest.pack_id.clone()),
                shard_id: selection.active.shard.shard_id().to_owned(),
                source_kind: selection.active.source_kind,
                source_id: selection.active.source_id.clone(),
                status: SemanticModelActivationStatus::Active,
                reason: "strict activation evidence and controls selected this shard".to_owned(),
            },
        );
    }
    report.explanations.sort_by(|left, right| {
        left.manifest_digest
            .cmp(&right.manifest_digest)
            .then_with(|| left.shard_id.cmp(&right.shard_id))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source_id.cmp(&right.source_id))
            .then_with(|| left.status.cmp(&right.status))
    });

    let active_model_set_hash = active_model_set_hash(&active);
    let indexes = match MatcherIndexes::build(&active, request.limits, cancellation, &mut report) {
        Ok(indexes) => indexes,
        Err(reason) => {
            push_request_explanation(&mut report, request.limits, reason);
            return if cancellation.is_cancelled() {
                SemanticModelResolutionOutcome::Cancelled(report)
            } else {
                SemanticModelResolutionOutcome::Unavailable(report)
            };
        }
    };
    let resolved = ResolvedActiveSemanticModels {
        active_model_set_hash,
        shards: active
            .into_iter()
            .map(|selection| selection.active)
            .collect(),
        indexes,
        report: report.clone(),
    };
    if incomplete {
        SemanticModelResolutionOutcome::Incomplete {
            usable: (!resolved.shards.is_empty()).then_some(resolved),
            report,
        }
    } else {
        SemanticModelResolutionOutcome::Ready(resolved)
    }
}

pub fn acquire_active_semantic_models(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    acquire_active_semantic_models_with_evidence(
        analyzer,
        catalog,
        persistence,
        request,
        None,
        cancellation,
    )
}

/// Acquire and atomically publish one generation's overlay and discovery evidence.
/// A failed acquisition leaves the previously complete publication unchanged.
pub fn acquire_active_semantic_models_with_evidence(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    dependency_evidence: Option<&[(Box<[Language]>, super::DependencyDiscoveryEvidence)]>,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    let request_key = match runtime_request_key(request) {
        Ok(key) => key,
        Err(reason) => {
            let mut report = SemanticModelActivationReport::default();
            push_request_explanation(&mut report, request.limits, reason);
            return SemanticModelRuntimeOutcome::Unavailable(report);
        }
    };
    if let Some(persistence) = persistence
        && let Err(error) =
            catalog.reconcile_workspace_active_set(persistence.scope_id, persistence.store)
    {
        return catalog_lifecycle_error(request.limits, "reconcile", error);
    }
    let catalog_identity = match catalog.cache_identity() {
        Ok(identity) => identity,
        Err(error) => return catalog_lifecycle_error(request.limits, "identify", error),
    };
    let key = format!(
        "{request_key}:{}:{}",
        catalog_identity.mutation_generation, catalog_identity.sqlite_data_version
    );
    let generations = analyzer.snapshot_source_generations();
    let Some(caches) = analyzer.snapshot_caches() else {
        let outcome = resolve_active_semantic_models(catalog, request, cancellation);
        if !analyzer.snapshot_generations_match(&generations) {
            return stale_generation_outcome(request.limits);
        }
        if let SemanticModelResolutionOutcome::Ready(active) = &outcome
            && let Err(error) = publish_active_models(catalog, persistence, active)
        {
            return catalog_lifecycle_error(request.limits, "publish", error);
        }
        return runtime_outcome(outcome, SemanticModelRuntimeLifecycle::Uncached);
    };
    let (acquisition, _) = caches.semantic_models().values.acquire(&key, cancellation);
    match acquisition {
        CompleteValueAcquisition::Cached { value } => {
            if !analyzer.snapshot_generations_match(&generations) {
                return stale_generation_outcome(request.limits);
            }
            if let Err(error) = publish_active_models(catalog, persistence, &value) {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            if let Err(error) = caches.semantic_models().publish_overlay(
                analyzer,
                &value,
                dependency_evidence,
                cancellation,
                request.limits.max_retained_bytes,
            ) {
                return overlay_build_outcome(&value, error, request.limits);
            }
            SemanticModelRuntimeOutcome::Ready {
                active: value,
                lifecycle: SemanticModelRuntimeLifecycle::Cached,
            }
        }
        CompleteValueAcquisition::Leader { permit } => {
            let outcome = resolve_active_semantic_models(catalog, request, cancellation);
            let SemanticModelResolutionOutcome::Ready(active) = outcome else {
                return runtime_outcome(outcome, SemanticModelRuntimeLifecycle::Built);
            };
            if !analyzer.snapshot_generations_match(&generations) {
                return stale_generation_outcome(request.limits);
            }
            let active = Arc::new(active);
            if let Err(error) = publish_active_models(catalog, persistence, &active) {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            if let Err(error) = caches.semantic_models().publish_overlay(
                analyzer,
                &active,
                dependency_evidence,
                cancellation,
                request.limits.max_retained_bytes,
            ) {
                return overlay_build_outcome(&active, error, request.limits);
            }
            permit.publish_complete(Arc::clone(&active));
            SemanticModelRuntimeOutcome::Ready {
                active,
                lifecycle: SemanticModelRuntimeLifecycle::Built,
            }
        }
        CompleteValueAcquisition::Cancelled => {
            SemanticModelRuntimeOutcome::Cancelled(SemanticModelActivationReport::default())
        }
        CompleteValueAcquisition::Rejected => {
            unreachable!("semantic-model runtime cache never publishes deterministic rejections")
        }
    }
}

fn overlay_build_outcome(
    active: &ResolvedActiveSemanticModels,
    error: SemanticModelOverlayBuildError,
    limits: SemanticModelRuntimeLimits,
) -> SemanticModelRuntimeOutcome {
    let mut report = active.activation_report().clone();
    match error {
        SemanticModelOverlayBuildError::Cancelled => SemanticModelRuntimeOutcome::Cancelled(report),
        SemanticModelOverlayBuildError::RetainedBytesExceeded => {
            push_request_explanation(
                &mut report,
                limits,
                "semantic-model overlay exceeds the combined retained-byte budget".to_string(),
            );
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
        SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded => {
            push_request_explanation(
                &mut report,
                limits,
                "semantic-model Go promotion or interface traversal exceeds its bounded work limit"
                    .to_string(),
            );
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
    }
}

fn publish_active_models(
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    active: &ResolvedActiveSemanticModels,
) -> Result<(), super::CatalogError> {
    let Some(persistence) = persistence else {
        return Ok(());
    };
    let mut members = active
        .shards
        .iter()
        .map(|shard| SemanticPackActiveReference {
            manifest_digest: shard.manifest.content_sha256.clone(),
            source_kind: activation_source_kind(shard.source_kind),
            source_id: shard.source_id.clone(),
            workspace_produced: shard.source_kind == CatalogPackSourceKind::WorkspaceProduced,
        })
        .collect::<Vec<_>>();
    members.sort();
    members.dedup();
    catalog
        .replace_workspace_active_set(persistence.scope_id, persistence.store, &members)
        .map(|_| ())
}

fn activation_source_kind(kind: CatalogPackSourceKind) -> SemanticPackActivationSourceKind {
    match kind {
        CatalogPackSourceKind::Installed => SemanticPackActivationSourceKind::Installed,
        CatalogPackSourceKind::Generated => SemanticPackActivationSourceKind::Generated,
        CatalogPackSourceKind::PreShipped => SemanticPackActivationSourceKind::PreShipped,
        CatalogPackSourceKind::WorkspaceProduced => {
            SemanticPackActivationSourceKind::WorkspaceProduced
        }
        CatalogPackSourceKind::Embedded => SemanticPackActivationSourceKind::Embedded,
        CatalogPackSourceKind::EphemeralWorkspace => {
            SemanticPackActivationSourceKind::EphemeralWorkspace
        }
    }
}

fn catalog_lifecycle_error(
    limits: SemanticModelRuntimeLimits,
    operation: &str,
    error: super::CatalogError,
) -> SemanticModelRuntimeOutcome {
    let mut report = SemanticModelActivationReport::default();
    push_request_explanation(
        &mut report,
        limits,
        format!("semantic-model active-set {operation} failed: {error}"),
    );
    SemanticModelRuntimeOutcome::Unavailable(report)
}

fn runtime_outcome(
    outcome: SemanticModelResolutionOutcome,
    lifecycle: SemanticModelRuntimeLifecycle,
) -> SemanticModelRuntimeOutcome {
    match outcome {
        SemanticModelResolutionOutcome::Ready(active) => SemanticModelRuntimeOutcome::Ready {
            active: Arc::new(active),
            lifecycle,
        },
        SemanticModelResolutionOutcome::Incomplete { usable, report } => {
            SemanticModelRuntimeOutcome::Incomplete {
                usable: usable.map(Arc::new),
                report,
            }
        }
        SemanticModelResolutionOutcome::Cancelled(report) => {
            SemanticModelRuntimeOutcome::Cancelled(report)
        }
        SemanticModelResolutionOutcome::Unavailable(report) => {
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
    }
}

fn stale_generation_outcome(limits: SemanticModelRuntimeLimits) -> SemanticModelRuntimeOutcome {
    let mut report = SemanticModelActivationReport::default();
    push_request_explanation(
        &mut report,
        limits,
        "analyzer generation changed during semantic-model activation".to_owned(),
    );
    SemanticModelRuntimeOutcome::Unavailable(report)
}

fn runtime_request_key(request: &SemanticModelActivationRequest) -> Result<String, String> {
    let evidence = validate_and_canonicalize_request(request)?;
    let mut controls = request
        .controls
        .iter()
        .map(|control| {
            let mut hasher = Sha256::new();
            hasher.update([match control.scope {
                SemanticModelControlScope::User => 0,
                SemanticModelControlScope::Workspace => 1,
            }]);
            hasher.update([match control.action {
                SemanticModelControlAction::Enable => 0,
                SemanticModelControlAction::Disable => 1,
            }]);
            hash_key_part(&mut hasher, &control.selector.pack_id);
            hash_optional_key_part(
                &mut hasher,
                control
                    .selector
                    .version
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
            );
            hash_optional_key_part(&mut hasher, control.selector.manifest_digest.as_deref());
            hasher.finalize().to_vec()
        })
        .collect::<Vec<_>>();
    controls.sort_unstable();
    controls.dedup();
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.semantic-model.runtime-request.v1\0");
    hash_key_part(&mut hasher, &request.bifrost_version.to_string());
    for row in evidence {
        hash_key_part(&mut hasher, &row.language);
        hash_key_part(&mut hasher, &row.ecosystem);
        hash_optional_coordinate(&mut hasher, row.package.as_ref());
        hash_optional_coordinate(&mut hasher, row.module.as_ref());
        hash_optional_coordinate(&mut hasher, row.toolchain.as_ref());
        hash_optional_key_part(&mut hasher, row.target.as_deref());
        hash_optional_key_part(&mut hasher, row.configuration.as_deref());
        hash_optional_key_part(&mut hasher, row.artifact_sha256.as_deref());
    }
    for control in controls {
        hasher.update((control.len() as u64).to_be_bytes());
        hasher.update(control);
    }
    for limit in [
        request.limits.max_evidence_rows as u64,
        request.limits.max_controls as u64,
        request.limits.max_catalog_candidates as u64,
        request.limits.max_loaded_shards as u64,
        request.limits.max_records as u64,
        request.limits.max_index_entries as u64,
        request.limits.max_working_bytes,
        request.limits.max_retained_bytes,
        request.limits.max_explanations as u64,
    ] {
        hasher.update(limit.to_be_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_key_part(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_optional_key_part(hasher: &mut Sha256, value: Option<&str>) {
    hasher.update([u8::from(value.is_some())]);
    if let Some(value) = value {
        hash_key_part(hasher, value);
    }
}

fn hash_optional_coordinate(hasher: &mut Sha256, coordinate: Option<&CatalogCoordinate>) {
    hasher.update([u8::from(coordinate.is_some())]);
    if let Some(coordinate) = coordinate {
        hash_key_part(hasher, &coordinate.name);
        hash_optional_key_part(
            hasher,
            coordinate
                .version
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
        );
    }
}

fn validate_and_canonicalize_request(
    request: &SemanticModelActivationRequest,
) -> Result<Vec<SemanticModelActivationEvidence>, String> {
    if request.evidence.len() > request.limits.max_evidence_rows {
        return Err("semantic-model activation evidence budget exceeded".to_owned());
    }
    if request.controls.len() > request.limits.max_controls {
        return Err("semantic-model activation control budget exceeded".to_owned());
    }
    let mut evidence = request.evidence.clone();
    for row in &evidence {
        if row.language.is_empty() || row.ecosystem.is_empty() {
            return Err("activation evidence language and ecosystem must not be empty".to_owned());
        }
        if row
            .artifact_sha256
            .as_deref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        {
            return Err("activation evidence artifact digest must be lowercase SHA-256".to_owned());
        }
    }
    for control in &request.controls {
        if control.selector.pack_id.is_empty() {
            return Err("semantic-model control pack ID must not be empty".to_owned());
        }
        if control
            .selector
            .manifest_digest
            .as_deref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        {
            return Err(
                "semantic-model control manifest digest must be lowercase SHA-256".to_owned(),
            );
        }
    }
    let mut control_actions = BTreeMap::new();
    for control in &request.controls {
        let key = (
            control.scope,
            control.selector.pack_id.as_str(),
            control.selector.version.as_ref().map(ToString::to_string),
            control.selector.manifest_digest.as_deref(),
        );
        if control_actions
            .insert(key, control.action)
            .is_some_and(|previous| previous != control.action)
        {
            return Err("equally specific activation controls conflict".to_owned());
        }
    }
    evidence.sort();
    evidence.dedup();
    Ok(evidence)
}

fn evidence_query(
    evidence: &SemanticModelActivationEvidence,
    bifrost_version: Version,
) -> SemanticPackSelectorQuery {
    SemanticPackSelectorQuery {
        language: evidence.language.clone(),
        ecosystem: evidence.ecosystem.clone(),
        package: evidence.package.clone(),
        module: evidence.module.clone(),
        toolchain: evidence.toolchain.clone(),
        target: evidence.target.clone(),
        configuration: evidence.configuration.clone(),
        artifact_sha256: evidence.artifact_sha256.clone(),
        bifrost_version,
    }
}

fn strict_activation_match(
    manifest: &CompiledPackManifest,
    shard: &CompiledShard,
    evidence: &[SemanticModelActivationEvidence],
    bifrost_version: &Version,
) -> Option<(EvidenceRank, SemanticModelActivationEvidence)> {
    let bifrost = VersionReq::parse(&manifest.compatibility.bifrost).ok()?;
    if !bifrost.matches(bifrost_version) {
        return None;
    }
    if !manifest.compatibility.toolchains.iter().all(|constraint| {
        let Ok(requirement) = VersionReq::parse(&constraint.requirement) else {
            return false;
        };
        evidence.iter().any(|row| {
            row.language == manifest.language
                && row.ecosystem == manifest.ecosystem
                && row.toolchain.as_ref().is_some_and(|toolchain| {
                    toolchain.name == constraint.name
                        && toolchain
                            .version
                            .as_ref()
                            .is_some_and(|version| requirement.matches(version))
                })
        })
    }) {
        return None;
    }
    shard
        .activation()
        .iter()
        .flat_map(|selector| {
            evidence
                .iter()
                .filter(move |row| {
                    row.language == manifest.language
                        && row.ecosystem == manifest.ecosystem
                        && strict_selector_matches(selector, row)
                })
                .map(|row| (selector_rank(selector), row.clone()))
        })
        .max()
}

fn strict_selector_matches(
    selector: &ActivationSelector,
    evidence: &SemanticModelActivationEvidence,
) -> bool {
    strict_coordinate_matches(selector.package.as_ref(), evidence.package.as_ref())
        && strict_coordinate_matches(selector.module.as_ref(), evidence.module.as_ref())
        && strict_coordinate_matches(selector.toolchain.as_ref(), evidence.toolchain.as_ref())
        && (selector.targets.is_empty()
            || evidence
                .target
                .as_ref()
                .is_some_and(|target| selector.targets.contains(target)))
        && (selector.configurations.is_empty()
            || evidence
                .configuration
                .as_ref()
                .is_some_and(|configuration| selector.configurations.contains(configuration)))
        && selector
            .artifact_sha256
            .as_ref()
            .is_none_or(|expected| evidence.artifact_sha256.as_ref() == Some(expected))
}

fn strict_coordinate_matches(
    selector: Option<&super::NameSelector>,
    evidence: Option<&CatalogCoordinate>,
) -> bool {
    match (selector, evidence) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(selector), Some(evidence)) if selector.name != evidence.name => false,
        (Some(selector), Some(evidence)) => match (&selector.version, &evidence.version) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(requirement), Some(version)) => {
                VersionReq::parse(requirement).is_ok_and(|requirement| requirement.matches(version))
            }
        },
    }
}

fn selector_rank(selector: &ActivationSelector) -> EvidenceRank {
    if selector.artifact_sha256.is_some() {
        EvidenceRank::ExactArtifact
    } else if [&selector.package, &selector.module, &selector.toolchain]
        .into_iter()
        .flatten()
        .any(|coordinate| coordinate.version.is_some())
    {
        EvidenceRank::VersionedCoordinate
    } else if selector.package.is_some()
        || selector.module.is_some()
        || selector.toolchain.is_some()
    {
        EvidenceRank::NamedCoordinate
    } else {
        EvidenceRank::Language
    }
}

fn effective_control(
    manifest: &CompiledPackManifest,
    controls: &[SemanticModelActivationControl],
) -> Result<Option<SemanticModelControlAction>, String> {
    let pack_version = Version::parse(&manifest.version)
        .map_err(|error| format!("compiled pack version is invalid: {error}"))?;
    let mut matched = controls
        .iter()
        .filter(|control| {
            control.selector.pack_id == manifest.pack_id
                && control
                    .selector
                    .version
                    .as_ref()
                    .is_none_or(|requirement| requirement.matches(&pack_version))
                && control
                    .selector
                    .manifest_digest
                    .as_ref()
                    .is_none_or(|digest| digest == &manifest.content_sha256)
        })
        .map(|control| {
            let scope = match control.scope {
                SemanticModelControlScope::User => 0,
                SemanticModelControlScope::Workspace => 1,
            };
            let specificity = u8::from(control.selector.version.is_some())
                + 2 * u8::from(control.selector.manifest_digest.is_some());
            (scope, specificity, control.action)
        })
        .collect::<Vec<_>>();
    matched.sort();
    let Some(&(scope, specificity, action)) = matched.last() else {
        return Ok(None);
    };
    if matched
        .iter()
        .rev()
        .take_while(|(other_scope, other_specificity, _)| {
            *other_scope == scope && *other_specificity == specificity
        })
        .any(|(_, _, other_action)| *other_action != action)
    {
        return Err("equally specific activation controls conflict".to_owned());
    }
    Ok(Some(action))
}

fn compare_selection(left: &CandidateSelection, right: &CandidateSelection) -> Ordering {
    left.evidence_rank
        .cmp(&right.evidence_rank)
        .then_with(|| left.source_rank.cmp(&right.source_rank))
        .then_with(|| left.semantic_sha256.cmp(&right.semantic_sha256))
        .then_with(|| {
            left.active
                .manifest
                .content_sha256
                .cmp(&right.active.manifest.content_sha256)
        })
        .then_with(|| left.active.source_id.cmp(&right.active.source_id))
}

fn source_rank(kind: CatalogPackSourceKind) -> u8 {
    match kind {
        CatalogPackSourceKind::Embedded => 0,
        CatalogPackSourceKind::PreShipped => 1,
        CatalogPackSourceKind::Installed => 2,
        CatalogPackSourceKind::Generated => 3,
        CatalogPackSourceKind::WorkspaceProduced => 4,
        CatalogPackSourceKind::EphemeralWorkspace => 5,
    }
}

fn active_model_set_hash(active: &[CandidateSelection]) -> String {
    let mut rows = active
        .iter()
        .map(|selection| {
            (
                selection.semantic_sha256.as_str(),
                match selection.payload_kind {
                    PayloadKind::DeclarationFacts => 0u8,
                    PayloadKind::GeneratorRules => 1u8,
                    PayloadKind::ProcedureSummaries => 2u8,
                },
            )
        })
        .collect::<Vec<_>>();
    rows.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.semantic-model.active-set.v1\0");
    hasher.update(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION.to_be_bytes());
    hasher.update((rows.len() as u64).to_be_bytes());
    for (digest, kind) in rows {
        hasher.update((digest.len() as u64).to_be_bytes());
        hasher.update(digest.as_bytes());
        hasher.update([kind]);
    }
    format!("{:x}", hasher.finalize())
}

fn catalog_miss_reason(miss: &CatalogMiss) -> String {
    match miss {
        CatalogMiss::NotFound => "catalog candidate disappeared before verified load".to_owned(),
        CatalogMiss::Quarantined { reason } | CatalogMiss::Incompatible { reason } => {
            reason.clone()
        }
    }
}

fn push_request_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    reason: String,
) {
    push_explanation(
        report,
        limits,
        SemanticModelActivationExplanation {
            manifest_digest: String::new(),
            pack_id: None,
            shard_id: String::new(),
            source_kind: CatalogPackSourceKind::Embedded,
            source_id: String::new(),
            status: SemanticModelActivationStatus::Unavailable,
            reason,
        },
    );
}

fn push_loaded_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    loaded: &super::LoadedCatalogShard,
    status: SemanticModelActivationStatus,
    reason: &str,
) {
    push_explanation(
        report,
        limits,
        SemanticModelActivationExplanation {
            manifest_digest: loaded.manifest.content_sha256.clone(),
            pack_id: Some(loaded.manifest.pack_id.clone()),
            shard_id: loaded.shard.shard_id().to_owned(),
            source_kind: loaded.source_kind,
            source_id: loaded.source_id.clone(),
            status,
            reason: reason.to_owned(),
        },
    );
}

fn push_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    explanation: SemanticModelActivationExplanation,
) {
    if report.explanations.len() < limits.max_explanations {
        report.explanations.push(explanation);
    } else {
        report.suppressed_explanations = report.suppressed_explanations.saturating_add(1);
    }
}

#[cfg(test)]
mod semantic_diagnostic_runtime_tests {
    use super::*;
    use crate::analyzer::SemanticDiagnosticIncompleteReason;

    #[test]
    fn runtime_outcomes_map_to_shared_suppression_reasons() {
        let report = SemanticModelActivationReport::default();
        assert_eq!(
            SemanticModelRuntimeOutcome::Cancelled(report.clone())
                .semantic_diagnostic_incomplete_reasons(),
            vec![SemanticDiagnosticIncompleteReason::Cancelled]
        );

        let incomplete = SemanticModelRuntimeOutcome::Incomplete {
            usable: None,
            report: report.clone(),
        }
        .semantic_diagnostic_incomplete_reasons();
        assert!(matches!(
            incomplete.as_slice(),
            [SemanticDiagnosticIncompleteReason::RuntimeUnavailable { detail }]
                if detail.starts_with("incomplete activation:")
        ));

        let unavailable = SemanticModelRuntimeOutcome::Unavailable(report)
            .semantic_diagnostic_incomplete_reasons();
        assert!(matches!(
            unavailable.as_slice(),
            [SemanticDiagnosticIncompleteReason::RuntimeUnavailable { detail }]
                if detail.starts_with("unavailable activation:")
        ));
    }
}
