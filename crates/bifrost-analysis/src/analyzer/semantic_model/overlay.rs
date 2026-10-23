// Preserve explicit engine visibility when an overlay shadows a public glob.
#![allow(hidden_glob_reexports)]

pub use crate::analyzer::store::model_provenance::{
    activated_record_provenance, model_location, origin, provenance, provenance_with_visits,
    source_kind,
};

pub use brokk_bifrost_semantic::analyzer::semantic_model::overlay::*;
pub(crate) mod java_functional;
#[doc(hidden)]
pub mod java_hierarchy;
use crate::analyzer::dependency_support::dependency_locator_path as locator_path;
use crate::analyzer::semantic_model::ActivePackExtractionGap;
use crate::analyzer::semantic_model::ActiveSemanticModelShard;
use crate::analyzer::semantic_model::CaptureBinding;
use crate::analyzer::semantic_model::CaptureProjection;
use crate::analyzer::semantic_model::CaptureSource;
use crate::analyzer::semantic_model::Completeness;
use crate::analyzer::semantic_model::EmittedDeclaration;
use crate::analyzer::semantic_model::GeneratorRule;
use crate::analyzer::semantic_model::HierarchyFact;
use crate::analyzer::semantic_model::HierarchyKind;
use crate::analyzer::semantic_model::ImplicitOperation;
use crate::analyzer::semantic_model::Locator;
use crate::analyzer::semantic_model::MemberFact;
use crate::analyzer::semantic_model::ParameterPassingMode;
use crate::analyzer::semantic_model::RelationFact;
use crate::analyzer::semantic_model::ResolvedActiveSemanticModels;
use crate::analyzer::semantic_model::RuleEmission;
use crate::analyzer::semantic_model::RuleTrigger;
use crate::analyzer::semantic_model::RuntimeGlobalExposure;
use crate::analyzer::semantic_model::SemanticModelMatch;
use crate::analyzer::semantic_model::SemanticModelMatchDisposition;
use crate::analyzer::semantic_model::TypeFact;
use crate::analyzer::semantic_model::TypeRef;
use crate::analyzer::semantic_model::Visibility;
use crate::analyzer::structural::{FileFacts, NormalizedKind, Role};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

#[derive(Debug)]
pub struct SemanticModelOverlay {
    active_model_set_hash: String,
    extraction_gaps: Vec<ActivePackExtractionGap>,
    extraction_gap_by_declaration: HashMap<String, usize>,
    /// The manifest languages of the active shards that carry declaration
    /// facts, deduplicated. An overlay can be built entirely from
    /// generator-rule packs (e.g. `bifrost.scala.case-class`), and such an
    /// overlay declares no API surface at all: its existence must not license
    /// an absence proof (#2678). Only a language listed here has a published
    /// declaration surface to prove a miss against.
    declaration_surface_languages: Vec<String>,
    /// The languages a declaration shard claims a *complete* surface for. A
    /// narrow reviewed pack publishes a surface without claiming to enumerate
    /// the language's declarations, so a consumer that needs exhaustive
    /// coverage must ask for this list instead.
    complete_declaration_surface_languages: Vec<String>,
    symbols: Vec<SemanticModelSymbol>,
    generated_function_languages: HashSet<String>,
    relations: Vec<SemanticModelRelation>,
    java_hierarchy: HashMap<String, (Vec<String>, Vec<HierarchyFact>)>,
    symbols_by_id: HashMap<String, Vec<usize>>,
    symbols_by_name: HashMap<String, Vec<usize>>,
    symbols_by_uri: HashMap<String, Vec<usize>>,
    symbols_by_authored_path: HashMap<String, Vec<usize>>,
    symbols_by_owner: HashMap<String, Vec<usize>>,
    relations_from: HashMap<String, Vec<usize>>,
    relations_to: HashMap<String, Vec<usize>>,
    runtime_values: Vec<RuntimeValueContracts>,
    collection_flows: Vec<CollectionFlowContract>,
    collection_flows_by_callable: HashMap<String, Vec<usize>>,
    conditional_type_refinements: Vec<ConditionalTypeRefinementContract>,
    conditional_types_by_callable: HashMap<String, Vec<usize>>,
    deferred_yields: Vec<DeferredYieldContract>,
    deferred_yields_by_scope: HashMap<(String, String, String), Vec<usize>>,
}

impl SemanticModelOverlay {
    #[doc(hidden)]
    pub fn build(
        analyzer: &dyn IAnalyzer,
        active: &ResolvedActiveSemanticModels,
        cancellation: &crate::CancellationToken,
        max_combined_retained_bytes: u64,
    ) -> Result<Self, SemanticModelOverlayBuildError> {
        // A repository can match no configured semantic-model shard. Do not
        // traverse a large analyzer to derive facts for an empty model set.
        if active.shards().is_empty() {
            return Ok(Self {
                active_model_set_hash: active.active_model_set_hash().to_string(),
                extraction_gaps: active.extraction_gaps().to_vec(),
                extraction_gap_by_declaration: extraction_gap_index(active.extraction_gaps()),
                declaration_surface_languages: Vec::new(),
                complete_declaration_surface_languages: Vec::new(),
                symbols: Vec::new(),
                generated_function_languages: HashSet::default(),
                relations: Vec::new(),
                java_hierarchy: HashMap::default(),
                symbols_by_id: HashMap::default(),
                symbols_by_name: HashMap::default(),
                symbols_by_uri: HashMap::default(),
                symbols_by_authored_path: HashMap::default(),
                symbols_by_owner: HashMap::default(),
                relations_from: HashMap::default(),
                relations_to: HashMap::default(),
                runtime_values: Vec::new(),
                collection_flows: Vec::new(),
                collection_flows_by_callable: HashMap::default(),
                conditional_type_refinements: Vec::new(),
                conditional_types_by_callable: HashMap::default(),
                deferred_yields: Vec::new(),
                deferred_yields_by_scope: HashMap::default(),
            });
        }
        let mut type_ids = Vec::new();
        let mut member_ids = Vec::new();
        let mut relation_ids = Vec::new();
        let mut runtime_values = Vec::new();
        let mut collection_flows = Vec::new();
        let mut conditional_type_refinements = Vec::new();
        let mut deferred_yields = Vec::new();
        let mut declaration_surface_languages: Vec<String> = Vec::new();
        let mut complete_declaration_surface_languages: Vec<String> = Vec::new();
        for shard in active.shards() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            if let Some(payload) = shard.shard.runtime_values() {
                runtime_values.push(RuntimeValueContracts {
                    provenance: provenance(
                        active,
                        shard,
                        "runtime-values",
                        &model_location(shard, "runtime-values", "runtime-values"),
                        None,
                        false,
                    ),
                    payload: payload.clone(),
                });
            }
            if let Some(payload) = shard.shard.collection_flows() {
                for flow in &payload.flows {
                    collection_flows.push(CollectionFlowContract {
                        provenance: provenance(
                            active,
                            shard,
                            &flow.callable,
                            &model_location(shard, "collection-flow", &flow.callable),
                            None,
                            false,
                        ),
                        callable: flow.callable.clone(),
                        payload: flow.payload.clone(),
                        coverage: flow.coverage,
                    });
                }
            }
            if let Some(payload) = shard.shard.conditional_type_refinements() {
                for fact in &payload.refinements {
                    conditional_type_refinements.push(ConditionalTypeRefinementContract {
                        provenance: provenance(
                            active,
                            shard,
                            &fact.payload.callable,
                            &model_location(
                                shard,
                                "conditional-type-refinement",
                                &fact.payload.callable,
                            ),
                            None,
                            false,
                        ),
                        payload: fact.payload.clone(),
                        coverage: fact.coverage,
                    });
                }
            }
            if let Some(payload) = shard.shard.deferred_yields() {
                for contract in &payload.yields {
                    deferred_yields.push(DeferredYieldContract {
                        provenance: provenance(
                            active,
                            shard,
                            &contract.factory,
                            &model_location(shard, "deferred-yield", &contract.factory),
                            None,
                            false,
                        ),
                        factory: contract.factory.clone(),
                        resume: contract.resume.clone(),
                        handle_type: contract.handle_type.clone(),
                        payload: contract.payload.clone(),
                        coverage: contract.coverage,
                    });
                }
            }
            if shard.shard.payload().declaration_facts().is_some() {
                if !declaration_surface_languages.contains(&shard.manifest.language) {
                    declaration_surface_languages.push(shard.manifest.language.clone());
                }
                if shard.manifest.completeness == Completeness::Complete
                    && !complete_declaration_surface_languages.contains(&shard.manifest.language)
                {
                    complete_declaration_surface_languages.push(shard.manifest.language.clone());
                }
            }
            if let Some((types, members, relations)) = shard.shard.payload().declaration_facts() {
                // A guarded record the pinned activation coordinates exclude
                // is not in the matcher indexes, so collecting its identity
                // here would only resolve to nothing (#1899).
                type_ids.extend(
                    types
                        .iter()
                        .filter(|record| !shard.guard_excludes(record.guard.as_ref()))
                        .map(|record| record.id.clone()),
                );
                member_ids.extend(
                    members
                        .iter()
                        .filter(|record| !shard.guard_excludes(record.guard.as_ref()))
                        .map(|record| record.id.clone()),
                );
                relation_ids.extend(relations.iter().map(|record| record.id.clone()));
            }
        }
        type_ids.sort_unstable();
        type_ids.dedup();
        member_ids.sort_unstable();
        member_ids.dedup();
        relation_ids.sort_unstable();
        relation_ids.dedup();

        let mut symbols = Vec::new();
        let mut hierarchy_relations = Vec::new();
        let mut java_hierarchy = HashMap::default();
        let mut qualified_types = HashMap::default();
        for id in type_ids {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let matched = active.types_with_id(&id);
            let ambiguous = type_declaration_records_conflict(&matched);
            for (index, activated) in matched.records.iter().enumerate() {
                // Runtime claims are adjudicated by the ancestry consumer. Do
                // not manufacture duplicate declaration identities from them.
                // Raw active records remain available with their provenance.
                if matched.records[..index].iter().any(|earlier| {
                    earlier.record.runtime_bases != activated.record.runtime_bases
                        && type_declarations_equivalent(earlier.record, activated.record)
                }) {
                    continue;
                }
                let symbol = type_symbol(
                    analyzer,
                    active,
                    activated.shard,
                    activated.record,
                    ambiguous,
                );
                if symbol.language == "java" && !ambiguous {
                    java_hierarchy.insert(
                        symbol.id.clone(),
                        (
                            activated.record.type_parameters.clone(),
                            activated.record.hierarchy.clone(),
                        ),
                    );
                }
                if !ambiguous {
                    qualified_types.insert(symbol.id.clone(), symbol.qualified_name.clone());
                }
                hierarchy_relations.extend(activated.record.hierarchy.iter().map(|hierarchy| {
                    hierarchy_relation(
                        active,
                        activated.shard,
                        &activated.record.id,
                        hierarchy,
                        ambiguous,
                    )
                }));
                symbols.push(symbol);
            }
        }
        for id in member_ids {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let matched = active.members_with_id(&id);
            let ambiguous = declaration_records_conflict(&matched);
            for activated in matched.records {
                symbols.push(member_symbol(
                    analyzer,
                    active,
                    activated.shard,
                    activated.record,
                    qualified_types
                        .get(&activated.record.owner)
                        .map(String::as_str),
                    ambiguous,
                ));
            }
        }
        let generated = generated_overlay_facts(analyzer, active, cancellation)?;
        symbols.extend(generated.symbols);
        mark_symbol_identity_conflicts(&mut symbols);
        augment_go_overlay_surface(&mut symbols, &mut hierarchy_relations, cancellation)?;
        mark_symbol_identity_conflicts(&mut symbols);
        symbols.sort_by(|left, right| {
            left.qualified_name
                .cmp(&right.qualified_name)
                .then_with(|| left.id.cmp(&right.id))
                .then_with(|| {
                    left.provenance
                        .pack_digest
                        .cmp(&right.provenance.pack_digest)
                })
        });

        let mut relations = hierarchy_relations;
        relations.extend(generated.relations);
        for id in relation_ids {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let matched = active.relations_with_id(&id);
            let ambiguous = matched.disposition == SemanticModelMatchDisposition::Conflict;
            for activated in matched.records {
                relations.push(relation(
                    active,
                    activated.shard,
                    activated.record,
                    ambiguous,
                ));
            }
        }
        relations.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| {
                    left.declaration_ordinal
                        .is_some()
                        .cmp(&right.declaration_ordinal.is_some())
                })
                .then_with(|| left.declaration_ordinal.cmp(&right.declaration_ordinal))
                .then_with(|| left.to.cmp(&right.to))
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut collection_flows_by_callable = HashMap::default();
        for (index, flow) in collection_flows.iter().enumerate() {
            collection_flows_by_callable
                .entry(flow.callable.clone())
                .or_insert_with(Vec::new)
                .push(index);
        }
        let mut conditional_types_by_callable = HashMap::default();
        for (index, fact) in conditional_type_refinements.iter().enumerate() {
            conditional_types_by_callable
                .entry(fact.payload.callable.clone())
                .or_insert_with(Vec::new)
                .push(index);
        }
        let mut deferred_yields_by_scope = HashMap::default();
        for (index, contract) in deferred_yields.iter().enumerate() {
            deferred_yields_by_scope
                .entry((
                    contract.factory.clone(),
                    contract.resume.clone(),
                    contract.handle_type.clone(),
                ))
                .or_insert_with(Vec::new)
                .push(index);
        }
        let mut overlay = Self {
            active_model_set_hash: active.active_model_set_hash().to_string(),
            extraction_gaps: active.extraction_gaps().to_vec(),
            extraction_gap_by_declaration: extraction_gap_index(active.extraction_gaps()),
            declaration_surface_languages,
            complete_declaration_surface_languages,
            generated_function_languages: symbols
                .iter()
                .filter(|s| s.is_rule_generated_function())
                .map(|s| s.language.clone())
                .collect(),
            symbols,
            relations,
            java_hierarchy,
            symbols_by_id: HashMap::default(),
            symbols_by_name: HashMap::default(),
            symbols_by_uri: HashMap::default(),
            symbols_by_authored_path: HashMap::default(),
            symbols_by_owner: HashMap::default(),
            relations_from: HashMap::default(),
            relations_to: HashMap::default(),
            runtime_values,
            collection_flows,
            collection_flows_by_callable,
            conditional_type_refinements,
            conditional_types_by_callable,
            deferred_yields,
            deferred_yields_by_scope,
        };
        overlay.rebuild_indexes(cancellation)?;
        if active
            .retained_bytes()
            .saturating_add(overlay.retained_bytes_lower_bound())
            > max_combined_retained_bytes
        {
            return Err(SemanticModelOverlayBuildError::RetainedBytesExceeded);
        }
        Ok(overlay)
    }

    pub fn active_model_set_hash(&self) -> &str {
        &self.active_model_set_hash
    }

    /// Whether any active shard publishes declaration facts for `language`.
    ///
    /// An overlay built only from generator-rule packs declares no API
    /// surface, so nothing can be proved absent against it (#2678). Absence
    /// gates must ask this instead of treating the overlay's existence as a
    /// published surface.
    pub fn publishes_declaration_surface_for(&self, language: &str) -> bool {
        self.declaration_surface_languages
            .iter()
            .any(|surface| surface == language)
    }

    /// Whether an activated declaration shard claims a complete surface for
    /// this language. A reviewed pack that models a handful of members
    /// publishes a surface but claims no such coverage, so a consumer that
    /// needs an exhaustive relation must not read the weaker predicate.
    pub fn publishes_complete_declaration_surface_for(&self, language: &str) -> bool {
        self.complete_declaration_surface_languages
            .iter()
            .any(|surface| surface == language)
    }

    pub fn gapped(&self, declaration: &str) -> Option<&ActivePackExtractionGap> {
        self.extraction_gap_by_declaration
            .get(declaration)
            .map(|index| &self.extraction_gaps[*index])
    }

    pub fn gapped_member_surface(
        &self,
        owner: &str,
        member: &str,
    ) -> Option<&ActivePackExtractionGap> {
        let declaration = format!("{owner}.{member}");
        self.gapped(&declaration).or_else(|| self.gapped(owner))
    }

    #[doc(hidden)]
    pub fn has_generated_functions(&self, language: &str) -> bool {
        self.generated_function_languages.contains(language)
    }

    pub fn symbols(&self) -> &[SemanticModelSymbol] {
        &self.symbols
    }

    pub fn relations(&self) -> &[SemanticModelRelation] {
        &self.relations
    }

    /// Runtime-value contracts retained from the same immutable active-model
    /// publication as declaration symbols. Callers must inspect each record's
    /// typed coverage and activation evidence before claiming an exact read.
    pub fn runtime_value_contracts(&self) -> &[RuntimeValueContracts] {
        &self.runtime_values
    }

    pub fn collection_flow_contracts(&self) -> &[CollectionFlowContract] {
        &self.collection_flows
    }

    pub fn collection_flows_for(
        &self,
        callable: &str,
    ) -> SemanticModelOverlayMatch<'_, CollectionFlowContract> {
        self.collection_flow_match(self.collection_flows_by_callable.get(callable))
    }

    #[doc(hidden)]
    pub fn unique_complete_collection_flow(
        &self,
        callable: &str,
    ) -> Option<&CollectionFlowContract> {
        let flows = self.collection_flows_for(callable);
        if flows.disposition != SemanticModelOverlayDisposition::Unique {
            return None;
        }
        let [flow] = flows.records.as_slice() else {
            return None;
        };
        flow.is_complete().then_some(flow)
    }

    /// Local declaration IDs are meaningful only within the publishing pack.
    pub fn conditional_type_refinements_for<'a>(
        &'a self,
        callable: &'a SemanticModelSymbol,
    ) -> impl Iterator<Item = &'a ConditionalTypeRefinementContract> + 'a {
        self.conditional_types_by_callable
            .get(&callable.id)
            .into_iter()
            .flatten()
            .map(|index| &self.conditional_type_refinements[*index])
            .filter(|fact| {
                fact.provenance.pack_digest == callable.provenance.pack_digest
                    && fact.provenance.pack_id == callable.provenance.pack_id
                    && fact.provenance.activation == callable.provenance.activation
            })
    }

    pub fn deferred_yield_contracts(&self) -> &[DeferredYieldContract] {
        &self.deferred_yields
    }

    pub fn deferred_yields_for(
        &self,
        factory: &str,
        resume: &str,
        handle_type: &str,
    ) -> SemanticModelOverlayMatch<'_, DeferredYieldContract> {
        self.deferred_yield_match(self.deferred_yields_by_scope.get(&(
            factory.to_owned(),
            resume.to_owned(),
            handle_type.to_owned(),
        )))
    }

    pub fn deferred_yields_for_factory(
        &self,
        factory: &str,
    ) -> SemanticModelOverlayMatch<'_, DeferredYieldContract> {
        let mut records = self
            .deferred_yields
            .iter()
            .filter(|contract| contract.factory == factory)
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            (&left.resume, &left.handle_type).cmp(&(&right.resume, &right.handle_type))
        });
        let disposition = match records.len() {
            0 => SemanticModelOverlayDisposition::Empty,
            1 => SemanticModelOverlayDisposition::Unique,
            _ => SemanticModelOverlayDisposition::Conflict,
        };
        SemanticModelOverlayMatch {
            records,
            disposition,
        }
    }

    pub fn runtime_exposures(
        &self,
        binding_name: &str,
        language: &str,
    ) -> Vec<(&RuntimeGlobalExposure, &SemanticModelProvenance)> {
        self.runtime_values
            .iter()
            .flat_map(|contracts| {
                contracts
                    .exposures()
                    .iter()
                    .filter(move |exposure| {
                        exposure.binding_name == binding_name
                            && exposure
                                .languages
                                .iter()
                                .any(|candidate| candidate == language)
                    })
                    .map(move |exposure| (exposure, &contracts.provenance))
            })
            .collect()
    }

    pub fn symbols_with_id(&self, id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_id.get(id))
    }

    pub fn symbols_named(&self, name: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_name.get(name))
    }

    /// Streaming access to existing unique postings. Callers with a query
    /// ledger charge each candidate before retaining or selecting it.
    pub(crate) fn symbol_candidates_named<'a>(
        &'a self,
        name: &str,
    ) -> impl Iterator<Item = &'a SemanticModelSymbol> + 'a {
        self.symbols_by_name
            .get(name)
            .into_iter()
            .flatten()
            .map(move |index| &self.symbols[*index])
    }

    #[doc(hidden)]
    pub fn symbol_candidates_with_id<'a>(
        &'a self,
        id: &str,
    ) -> impl Iterator<Item = &'a SemanticModelSymbol> + 'a {
        self.symbols_by_id
            .get(id)
            .into_iter()
            .flatten()
            .map(move |index| &self.symbols[*index])
    }

    #[doc(hidden)]
    pub fn visible_public_symbol(
        &self,
        qualified_name: &str,
        language: &str,
    ) -> Option<&SemanticModelSymbol> {
        let matched = self.symbols_named(qualified_name);
        let symbol = (matched.disposition == SemanticModelOverlayDisposition::Unique)
            .then(|| matched.records.first().copied())
            .flatten()?;
        Self::symbol_is_visible_public(symbol, language).then_some(symbol)
    }

    #[doc(hidden)]
    pub fn symbol_is_visible_public(symbol: &SemanticModelSymbol, language: &str) -> bool {
        symbol.language == language && symbol.visibility == Visibility::Public
    }

    pub fn symbols_at_uri(&self, uri: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_uri.get(uri))
    }

    pub fn symbols_at_authored_path(
        &self,
        path: &str,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_authored_path.get(path))
    }

    pub fn members_of(&self, owner_id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_owner.get(owner_id))
    }

    /// Return owner members with this exact symbol name and their disposition.
    pub fn members_named(
        &self,
        owner_id: &str,
        name: &str,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        let records = self
            .members_of(owner_id)
            .records
            .into_iter()
            .filter(|symbol| symbol.name == name)
            .collect::<Vec<_>>();
        let disposition = if records.is_empty() {
            SemanticModelOverlayDisposition::Empty
        } else if records.len() == 1 && !records[0].provenance.ambiguous {
            SemanticModelOverlayDisposition::Unique
        } else {
            SemanticModelOverlayDisposition::Conflict
        };
        SemanticModelOverlayMatch {
            records,
            disposition,
        }
    }

    /// Resolve a static member through one exact modeled owner identity.
    ///
    /// This deliberately does not use the name index for `Owner.member`: that
    /// index also admits aliases and simple-name postings. The exact owner ID,
    /// its typed inherited surface, and each member's exact `owner_id` keep the
    /// result tied to the active model record that justified the receiver.
    pub fn member_target_on_owner(
        &self,
        owner_id: &str,
        member_name: &str,
    ) -> SemanticModelMemberTargetMatch<'_> {
        let owners = self.symbols_with_id(owner_id);
        if owners.disposition == SemanticModelOverlayDisposition::Conflict
            || owners.records.len() > 1
        {
            return SemanticModelMemberTargetMatch {
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Conflict,
            };
        }
        let [owner] = owners.records.as_slice() else {
            return SemanticModelMemberTargetMatch {
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        };
        if owner.provenance.ambiguous
            || owner.provenance.completeness != SemanticModelCompleteness::Complete
        {
            return SemanticModelMemberTargetMatch {
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        }

        let surface = self.owner_surface(owner);
        let surface_complete = surface.proves_absence()
            && self
                .gapped_member_surface(&owner.qualified_name, member_name)
                .is_none();
        for (ordinal, surface_owner) in surface.closure.into_iter().enumerate() {
            let mut records = self
                .members_of(&surface_owner.id)
                .records
                .into_iter()
                .filter(|symbol| {
                    symbol.owner_id.as_deref() == Some(surface_owner.id.as_str())
                        && symbol.name == member_name
                        && symbol.language == owner.language
                })
                .collect::<Vec<_>>();
            records.sort_by(|left, right| left.id.cmp(&right.id));
            records.dedup_by(|left, right| left.id == right.id);
            if records.is_empty() {
                continue;
            }
            if records.len() > 1 || records.iter().any(|symbol| symbol.provenance.ambiguous) {
                return SemanticModelMemberTargetMatch {
                    records,
                    disposition: SemanticModelMemberTargetDisposition::Conflict,
                };
            }
            let complete_record = records[0].provenance.completeness
                == SemanticModelCompleteness::Complete
                && self
                    .gapped_member_surface(&surface_owner.qualified_name, member_name)
                    .is_none();
            let complete_path = ordinal == 0 || surface_complete;
            return SemanticModelMemberTargetMatch {
                records,
                disposition: if complete_record && complete_path {
                    SemanticModelMemberTargetDisposition::Unique
                } else {
                    SemanticModelMemberTargetDisposition::Incomplete
                },
            };
        }

        SemanticModelMemberTargetMatch {
            records: Vec::new(),
            disposition: if surface_complete {
                SemanticModelMemberTargetDisposition::Absent
            } else {
                SemanticModelMemberTargetDisposition::Incomplete
            },
        }
    }

    /// Whether one exact modeled owner surface proves that a member exists.
    ///
    /// A unique complete record proves presence directly. Multiple records do
    /// so only when they form one complete callable family; competing fields,
    /// partial overloads, and incomplete owner surfaces remain unknown.
    pub fn member_present_on_owner(&self, owner_id: &str, member_name: &str) -> bool {
        let matched = self.member_target_on_owner(owner_id, member_name);
        match matched.disposition {
            SemanticModelMemberTargetDisposition::Unique => true,
            SemanticModelMemberTargetDisposition::Conflict => {
                semantic_model_callable_family_id(&matched.records).is_some()
            }
            SemanticModelMemberTargetDisposition::Absent
            | SemanticModelMemberTargetDisposition::Incomplete => false,
        }
    }

    /// Resolve one implicit special member through one exact modeled owner
    /// identity and one exact operation role.
    ///
    /// An operation role is not an absence claim: a complete owner with no
    /// matching role still returns `Incomplete`, because the active model may
    /// simply omit the role. The returned records remain the model's exact
    /// member records so callers can retain their declaration identity and
    /// provenance while treating partial or competing evidence as unusable.
    /// This lookup is deliberately direct-owner-only; implicit operations do
    /// not inherit through the owner's member surface.
    pub fn implicit_member_target_on_owner(
        &self,
        owner_id: &str,
        operation: &ImplicitOperation,
    ) -> SemanticModelMemberTargetMatch<'_> {
        self.role_member_target_on_owner(owner_id, &|member: &SemanticModelSymbol| {
            member.implicit_operation.as_ref() == Some(operation)
        })
    }

    /// Resolve the value operation an exact modeled owner performs for one
    /// member name written with one argument count.
    ///
    /// Because the call site spells the member, what has to be unique is the
    /// *operation*, not the declaration: `append(const string&)` and
    /// `append(const char*)` are two declarations of one operation, and a
    /// consumer that required a single record would decline a name the model
    /// answers completely. Every member of the owner with this name and
    /// argument count must therefore carry the same reviewed role. One that
    /// carries a different role, or none at all, leaves the operation
    /// undecided and the answer `Incomplete`.
    ///
    /// The rest of the disposition contract is the implicit lookup's: a
    /// complete owner that publishes no such member is `Incomplete` rather
    /// than an absence claim, ambiguous provenance is a `Conflict`, and
    /// partial provenance is never promoted.
    pub fn explicit_member_target_on_owner(
        &self,
        owner_id: &str,
        name: &str,
        argument_count: usize,
    ) -> SemanticModelExplicitOperationMatch<'_> {
        let owners = self.symbols_with_id(owner_id);
        if owners.disposition == SemanticModelOverlayDisposition::Conflict
            || owners.records.len() > 1
        {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Conflict,
            };
        }
        let [owner] = owners.records.as_slice() else {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        };
        if owner.owner_id.is_some() {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        }

        let members = self.members_of(owner_id);
        let mut records = members
            .records
            .into_iter()
            .filter(|member| {
                member.owner_id.as_deref() == Some(owner_id)
                    && member.name == name
                    && member
                        .structured_signature
                        .as_ref()
                        .is_some_and(|signature| signature.parameters.len() == argument_count)
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.id.cmp(&right.id));

        let [first, rest @ ..] = records.as_slice() else {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records,
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        };
        let Some(operation) = first.explicit_operation else {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records,
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        };
        if rest
            .iter()
            .any(|member| member.explicit_operation != Some(operation))
        {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records,
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        }
        if records.iter().any(|member| member.provenance.ambiguous) {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records,
                disposition: SemanticModelMemberTargetDisposition::Conflict,
            };
        }
        if owner.provenance.completeness != SemanticModelCompleteness::Complete
            || records
                .iter()
                .any(|member| member.provenance.completeness != SemanticModelCompleteness::Complete)
        {
            return SemanticModelExplicitOperationMatch {
                operation: None,
                records,
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        }
        SemanticModelExplicitOperationMatch {
            operation: Some(operation),
            records,
            disposition: SemanticModelMemberTargetDisposition::Unique,
        }
    }

    fn role_member_target_on_owner(
        &self,
        owner_id: &str,
        selects: &dyn Fn(&SemanticModelSymbol) -> bool,
    ) -> SemanticModelMemberTargetMatch<'_> {
        let owners = self.symbols_with_id(owner_id);
        if owners.disposition == SemanticModelOverlayDisposition::Conflict
            || owners.records.len() > 1
        {
            return SemanticModelMemberTargetMatch {
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Conflict,
            };
        }
        let [owner] = owners.records.as_slice() else {
            return SemanticModelMemberTargetMatch {
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        };
        if owner.owner_id.is_some() {
            return SemanticModelMemberTargetMatch {
                records: Vec::new(),
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        }

        let members = self.members_of(owner_id);
        // `members_of` reports `Conflict` for a multi-member posting, even
        // when each member has a distinct role. Only carry that disposition
        // into this role-specific lookup when it also reflects an explicitly
        // ambiguous member; the operation filter below is what decides whether
        // this exact role has competing records.
        let member_surface_has_ambiguous_record = members.disposition
            == SemanticModelOverlayDisposition::Conflict
            && members
                .records
                .iter()
                .any(|member| member.provenance.ambiguous);
        let mut records = members
            .records
            .into_iter()
            .filter(|member| member.owner_id.as_deref() == Some(owner_id) && selects(member))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.id.cmp(&right.id));

        if records.is_empty() {
            return SemanticModelMemberTargetMatch {
                records,
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        }
        if records.len() > 1
            || member_surface_has_ambiguous_record
            || records.iter().any(|member| member.provenance.ambiguous)
        {
            return SemanticModelMemberTargetMatch {
                records,
                disposition: SemanticModelMemberTargetDisposition::Conflict,
            };
        }
        if owner.provenance.completeness != SemanticModelCompleteness::Complete
            || records[0].provenance.completeness != SemanticModelCompleteness::Complete
        {
            return SemanticModelMemberTargetMatch {
                records,
                disposition: SemanticModelMemberTargetDisposition::Incomplete,
            };
        }

        SemanticModelMemberTargetMatch {
            records,
            disposition: SemanticModelMemberTargetDisposition::Unique,
        }
    }

    /// Resolve a TypeScript ambient global value's member through its
    /// structured declaration-model type.
    ///
    /// TypeScript's standard library spells `Array.isArray` as a global value
    /// `Array` typed as `ArrayConstructor`; the member is therefore published
    /// on `ArrayConstructor`, not on the `Array` interface. Keep this lookup
    /// bounded to one value-to-type hop and require one complete, unambiguous
    /// model record so a missing or competing pack cannot become a clean
    /// resolution.
    pub fn typescript_global_member_target(
        &self,
        receiver: &str,
        member: &str,
    ) -> Option<&SemanticModelSymbol> {
        let reference = format!("{receiver}.{member}");
        let mut direct = self
            .symbols_named(&reference)
            .records
            .into_iter()
            .filter(|symbol| {
                symbol.language == "typescript"
                    && symbol.owner_id.is_some()
                    && symbol.name == member
                    && !symbol.provenance.ambiguous
                    && symbol.provenance.completeness == SemanticModelCompleteness::Complete
            })
            .collect::<Vec<_>>();
        direct.sort_by(|left, right| left.id.cmp(&right.id));
        direct.dedup_by(|left, right| left.id == right.id);
        if let [symbol] = direct.as_slice() {
            return Some(*symbol);
        }
        if !direct.is_empty() {
            return None;
        }

        let mut receiver_type_ids = HashSet::default();
        let mut receiver_values = 0usize;
        for value in self
            .symbols_named(receiver)
            .records
            .into_iter()
            .filter(|symbol| {
                symbol.language == "typescript"
                    && symbol.owner_id.is_some()
                    && symbol.name == receiver
                    && !symbol.provenance.ambiguous
                    && symbol.provenance.completeness == SemanticModelCompleteness::Complete
            })
        {
            receiver_values += 1;
            let Some(signature) = value.structured_signature.as_ref() else {
                continue;
            };
            let Some(return_type) = signature.returns.as_ref() else {
                continue;
            };
            match return_type {
                TypeRef::Declared { id, .. } => {
                    receiver_type_ids.insert(id.clone());
                }
                TypeRef::Named { name, .. } => {
                    let owners = self
                        .symbols_named(name)
                        .records
                        .into_iter()
                        .filter(|owner| {
                            owner.owner_id.is_none()
                                && owner.qualified_name == *name
                                && owner.language == "typescript"
                                && !owner.provenance.ambiguous
                                && owner.provenance.completeness
                                    == SemanticModelCompleteness::Complete
                        });
                    receiver_type_ids.extend(owners.map(|owner| owner.id.clone()));
                }
                _ => {}
            }
        }
        if receiver_values != 1 || receiver_type_ids.len() != 1 {
            return None;
        }

        let mut members = receiver_type_ids
            .into_iter()
            .flat_map(|owner_id| self.members_of(&owner_id).records)
            .filter(|symbol| {
                symbol.language == "typescript"
                    && symbol.name == member
                    && !symbol.provenance.ambiguous
                    && symbol.provenance.completeness == SemanticModelCompleteness::Complete
            })
            .collect::<Vec<_>>();
        members.sort_by(|left, right| left.id.cmp(&right.id));
        members.dedup_by(|left, right| left.id == right.id);
        match members.as_slice() {
            [symbol] => Some(*symbol),
            _ => None,
        }
    }

    /// Resolve a target whose declared arity is already known.
    ///
    /// This compatibility entry point is used by source-declaration consumers.
    /// External call sites should use [`Self::callable_for_application`] so
    /// defaults and named actuals participate in selection.
    pub fn callable_for_target(
        &self,
        key: SemanticModelCallableKey<'_>,
    ) -> SemanticModelCallableMatch<'_> {
        let application = SemanticModelCallApplication::positional(key.parameter_count);
        self.callable_for_application(key, &application)
    }

    /// Resolve the stable identity of the whole declared callable family.
    ///
    /// Application filtering may select one overload or a compatible subset;
    /// policy endpoint identity must still remain the same family identity in
    /// either case. This lookup therefore uses the exact resolver-owned key but
    /// deliberately does not apply written arguments.
    pub fn callable_family_id_for_target(
        &self,
        key: SemanticModelCallableKey<'_>,
    ) -> Option<String> {
        let owners = self.callable_owner_candidates(key);
        let [owner] = owners.as_slice() else {
            return None;
        };
        self.callable_family_id_for_owner_member(
            &owner.id,
            key.language,
            key.member,
            key.has_receiver,
        )
    }

    /// Resolve the stable family identity containing one exact model record.
    ///
    /// Stable record IDs remain valid authored locators, but exact call rows
    /// publish family identity so overload selection cannot change endpoint
    /// identity. Expand the record through its structured owner/member shape
    /// before deriving that identity.
    pub fn callable_family_id_for_symbol(&self, symbol: &SemanticModelSymbol) -> Option<String> {
        let owner_id = symbol.owner_id.as_deref()?;
        self.callable_family_id_for_owner_member(
            owner_id,
            &symbol.language,
            &symbol.name,
            symbol.has_receiver(),
        )
    }

    fn callable_family_id_for_owner_member(
        &self,
        owner_id: &str,
        language: &str,
        member_name: &str,
        has_receiver: bool,
    ) -> Option<String> {
        let records = self
            .members_of(owner_id)
            .records
            .into_iter()
            .filter(|member| {
                member.language == language
                    && member.name == member_name
                    && member_is_callable(member)
                    && member_has_receiver(member) == has_receiver
            })
            .collect::<Vec<_>>();
        semantic_model_callable_family_id(&records)
    }

    /// Collect declaring owners without imposing a language's selection policy.
    /// The ordinary surface supplies edge resolution and completeness checks;
    /// original declaration facts retain generic arguments erased by name edges.
    /// Rust ranks all visible traits, whereas JVM consumers retain first match.
    #[doc(hidden)]
    pub fn callable_owners_on_surface<'a>(
        &'a self,
        active: &ResolvedActiveSemanticModels,
        owner: &'a SemanticModelSymbol,
        member: &str,
    ) -> Option<Vec<SemanticModelCallableOwner<'a>>> {
        let surface = self.owner_surface(owner);
        if surface.gaps.iter().any(|gap| {
            matches!(
                gap,
                SemanticModelSurfaceGap::UnresolvedEdge(_)
                    | SemanticModelSurfaceGap::AmbiguousType { .. }
            )
        }) {
            return None;
        }
        // Partial inventories retain positive typed implementation paths. The
        // callable matcher, not whole-pack absence, certifies a complete family.
        let mut candidates: Vec<SemanticModelCallableOwner<'_>> = Vec::new();
        let mut pending = vec![(owner, Vec::<HierarchyFact>::new())];
        let mut expanded = HashSet::default();
        while let Some((declaring, path)) = pending.pop() {
            // Expand an instantiated owner once. Retaining every route through
            // a diamond would grow exponentially even though it adds no member.
            if !expanded.insert((
                declaring.id.as_str(),
                path.last().map(|edge| edge.target.clone()),
            )) {
                continue;
            }
            if self
                .members_of(&declaring.id)
                .records
                .iter()
                .any(|symbol| symbol.name == member && member_is_callable(symbol))
                && !candidates.iter().any(|candidate| {
                    candidate.owner.id == declaring.id
                        && candidate.hierarchy.last().map(|edge| &edge.target)
                            == path.last().map(|edge| &edge.target)
                })
            {
                candidates.push(SemanticModelCallableOwner {
                    owner: declaring,
                    hierarchy: path.clone(),
                });
            }
            let ancestors = self.direct_ancestors_of(declaring);
            let declarations = active.types_with_id(&declaring.id);
            for declaration in declarations.records {
                for edge in &declaration.record.hierarchy {
                    let target = match &edge.target {
                        TypeRef::Named { name, .. } => name,
                        TypeRef::Declared { id, .. } => id,
                        _ => return None,
                    };
                    let resolved = self.resolve_edge_target(
                        target,
                        &declaring.language,
                        HierarchyTargetShape::Type,
                    );
                    if resolved.defect.is_some() {
                        return None;
                    }
                    for ancestor in resolved.records {
                        if !ancestors
                            .records
                            .iter()
                            .any(|allowed| allowed.id == ancestor.id)
                        {
                            continue;
                        }
                        let mut hierarchy = path.clone();
                        hierarchy.push(edge.clone());
                        pending.push((ancestor, hierarchy));
                    }
                }
            }
        }
        Some(candidates)
    }

    /// Resolve one oracle-owned external callable identity against the active
    /// declaration model and one structured call application.
    ///
    /// Owner lookup is exact on the model's qualified declaration field and
    /// member lookup is exact on its owner identity and member field. The
    /// rendered signature is never consulted. A missing or partial record is
    /// retained as an explicit incomplete result so a model gap cannot become
    /// an empty, clean answer. Multiple applicable overloads may share one
    /// exact binding layout, but they never become one selected overload.
    pub fn callable_for_application(
        &self,
        key: SemanticModelCallableKey<'_>,
        application: &SemanticModelCallApplication,
    ) -> SemanticModelCallableMatch<'_> {
        let Some((_, _, has_spread)) = application.written() else {
            return SemanticModelCallableMatch {
                records: Vec::new(),
                disposition: SemanticModelCallableDisposition::Incomplete(
                    SemanticModelCallableIncompleteReason::ApplicationUnavailable,
                ),
            };
        };
        let owners = self.callable_owner_candidates(key);

        if owners.is_empty() {
            return SemanticModelCallableMatch {
                records: Vec::new(),
                disposition: SemanticModelCallableDisposition::Empty,
            };
        }

        let owner_model_is_ambiguous = owners.iter().any(|owner| owner.provenance.ambiguous);
        let owner_model_is_partial = owners
            .iter()
            .any(|owner| owner.provenance.completeness == SemanticModelCompleteness::Partial);
        let owner_ids = owners
            .iter()
            .map(|owner| owner.id.as_str())
            .collect::<HashSet<_>>();
        let mut exact_candidates = Vec::new();
        let mut spread_candidates = Vec::new();
        let mut application_mismatches = false;
        let mut missing_signatures = Vec::new();

        for owner_id in owner_ids {
            for member in self.members_of(owner_id).records {
                if member.language != key.language
                    || member.name != key.member
                    || !member_is_callable(member)
                    || member_has_receiver(member) != key.has_receiver
                {
                    continue;
                }
                let Some(signature) = member.structured_signature.as_ref() else {
                    missing_signatures.push(member);
                    continue;
                };
                match bind_semantic_model_arguments(signature, application) {
                    SemanticModelArgumentBinding::Exact { .. } => exact_candidates.push(member),
                    SemanticModelArgumentBinding::PossibleSpread => spread_candidates.push(member),
                    SemanticModelArgumentBinding::Mismatch => application_mismatches = true,
                }
            }
        }

        // A signature-less member of the same callable family may accept this
        // application. A modeled sibling cannot make that unknown overload
        // disappear, so retain the family as incomplete before selecting any
        // known candidate.
        if !missing_signatures.is_empty() {
            return SemanticModelCallableMatch {
                records: missing_signatures,
                disposition: SemanticModelCallableDisposition::Incomplete(
                    SemanticModelCallableIncompleteReason::MissingSignature,
                ),
            };
        }

        if exact_candidates.iter().any(|candidate| {
            candidate
                .structured_signature
                .as_ref()
                .is_some_and(|signature| {
                    u32::try_from(signature.parameters.len()).ok() == Some(key.parameter_count)
                })
        }) {
            exact_candidates.retain(|candidate| {
                candidate
                    .structured_signature
                    .as_ref()
                    .is_some_and(|signature| {
                        u32::try_from(signature.parameters.len()).ok() == Some(key.parameter_count)
                    })
            });
        }

        // A spread's actual cardinality is unknown, so even a compatible
        // variadic declaration can produce formal rows only after expansion.
        // Keep the candidate visible in the incomplete match rather than
        // promoting its structured signature to exact binding rows.
        let candidates = if exact_candidates.is_empty() {
            spread_candidates
        } else {
            exact_candidates
        };

        if candidates.is_empty() {
            return SemanticModelCallableMatch {
                records: Vec::new(),
                disposition: if application_mismatches || owner_model_is_partial {
                    SemanticModelCallableDisposition::Incomplete(if application_mismatches {
                        SemanticModelCallableIncompleteReason::ApplicationMismatch
                    } else {
                        SemanticModelCallableIncompleteReason::PartialModel
                    })
                } else {
                    SemanticModelCallableDisposition::Empty
                },
            };
        }

        if owners.len() != 1 {
            return SemanticModelCallableMatch {
                records: candidates,
                disposition: SemanticModelCallableDisposition::Conflict,
            };
        }

        let candidate_model_is_ambiguous = candidates
            .iter()
            .any(|candidate| candidate.provenance.ambiguous);
        let candidate_model_is_partial = candidates.iter().any(|candidate| {
            candidate.provenance.completeness == SemanticModelCompleteness::Partial
                && !candidate.callable_family_complete
        });
        let callable_family_is_complete = candidates
            .iter()
            .all(|candidate| candidate.callable_family_complete);
        // Python's complete callable-shape evidence describes one exact
        // declaration. It can bind that declaration without claiming that
        // the partial pack enumerates its overload family.
        let python_single_declaration_has_shape = key.language == "python"
            && candidates.len() == 1
            && candidates[0].has_complete_callable_shape_evidence()
            && owners.len() == 1
            && self
                .members_of(&owners[0].id)
                .records
                .into_iter()
                .filter(|member| {
                    member.language == key.language
                        && member.name == key.member
                        && member_is_callable(member)
                        && member_has_receiver(member) == key.has_receiver
                })
                .eq(candidates.iter().copied());
        let disposition = if owner_model_is_ambiguous || candidate_model_is_ambiguous {
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::AmbiguousModel,
            )
        } else if !python_single_declaration_has_shape
            && ((owner_model_is_partial && !callable_family_is_complete)
                || candidate_model_is_partial)
        {
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::PartialModel,
            )
        } else if has_spread {
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::UnexpandedSpread,
            )
        } else {
            let signatures = candidates
                .iter()
                .map(|candidate| {
                    candidate
                        .structured_signature
                        .as_ref()
                        .expect("candidate filtering requires a signature")
                })
                .collect::<Vec<_>>();
            if let Some((ordinal, _)) = signatures.iter().find_map(|signature| {
                signature
                    .parameters
                    .iter()
                    .enumerate()
                    .find(|(_, parameter)| {
                        parameter.name.is_none()
                            && parameter.passing_mode != ParameterPassingMode::PositionalOnly
                    })
            }) {
                SemanticModelCallableDisposition::Incomplete(
                    SemanticModelCallableIncompleteReason::MissingFormalName { ordinal },
                )
            } else if candidates.len() == 1 {
                SemanticModelCallableDisposition::Unique
            } else if signatures[1..]
                .iter()
                .all(|signature| binding_layouts_match(signatures[0], signature))
            {
                SemanticModelCallableDisposition::CompatibleLayout
            } else {
                SemanticModelCallableDisposition::Conflict
            }
        };

        SemanticModelCallableMatch {
            records: candidates,
            disposition,
        }
    }

    /// Owners with the requested callable member are the only owners that can
    /// make a callable lookup ambiguous. A generated C header module and a
    /// typedef or class may deliberately share a qualified name (for example
    /// `sqlite3`); the unrelated type must not conflict with the module's
    /// file-scope function declarations. If no owner publishes that member,
    /// retain the exact owners so their partial coverage cannot become an
    /// empty, complete callable result.
    fn callable_owner_candidates(
        &self,
        key: SemanticModelCallableKey<'_>,
    ) -> Vec<&SemanticModelSymbol> {
        let owners = self
            .symbols_named(key.owner)
            .records
            .into_iter()
            .filter(|owner| {
                owner.owner_id.is_none()
                    && owner.qualified_name == key.owner
                    && owner.language == key.language
            })
            .collect::<Vec<_>>();
        let matching = owners
            .iter()
            .copied()
            .filter(|owner| {
                self.members_of(&owner.id)
                    .records
                    .into_iter()
                    .any(|member| {
                        member.language == key.language
                            && member.name == key.member
                            && member_is_callable(member)
                            && member_has_receiver(member) == key.has_receiver
                    })
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            owners
        } else {
            matching
        }
    }

    pub fn search<'a>(
        &'a self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
    ) -> Vec<&'a SemanticModelSymbol> {
        self.search_with_limit(patterns, usize::MAX, None).0
    }

    pub fn search_with_limit<'a>(
        &'a self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        limit: usize,
        cancellation: Option<&crate::CancellationToken>,
    ) -> (Vec<&'a SemanticModelSymbol>, usize, bool) {
        self.search_with_limit_filter(patterns, limit, cancellation, |_| true)
    }

    pub fn search_with_limit_filter<'a>(
        &'a self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        limit: usize,
        cancellation: Option<&crate::CancellationToken>,
        include: impl Fn(&SemanticModelSymbol) -> bool,
    ) -> (Vec<&'a SemanticModelSymbol>, usize, bool) {
        let mut records = Vec::new();
        let mut total = 0usize;
        for symbol in &self.symbols {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (records, total, false);
            }
            let matched = patterns.is_match(&symbol.name)
                || patterns.is_match(&symbol.qualified_name)
                || symbol.aliases.iter().any(|alias| patterns.is_match(alias));
            if matched && symbol.externally_visible() && include(symbol) {
                total = total.saturating_add(1);
                if records.len() < limit {
                    records.push(symbol);
                }
            }
        }
        (records, total, true)
    }

    pub fn relations_from(&self, id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelRelation> {
        self.relation_match(self.relations_from.get(id))
    }

    pub fn relations_to(&self, id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelRelation> {
        self.relation_match(self.relations_to.get(id))
    }

    /// Resolve a model type's transitive ancestors without materializing
    /// universal-root edges for every declaration in the overlay.
    pub fn ancestors_of(&self, symbol: &SemanticModelSymbol) -> SemanticModelAncestry<'_> {
        let mut records = Vec::new();
        let mut defects = Vec::new();
        let mut queue = VecDeque::from([symbol]);
        let mut seen = HashSet::from_iter([symbol.id.as_str()]);
        let mut conflict = symbol.provenance.ambiguous;
        while let Some(current) = queue.pop_front() {
            let direct = self.direct_ancestors_of(current);
            conflict |= direct.disposition == SemanticModelOverlayDisposition::Conflict;
            defects.extend(direct.defects);
            for ancestor in direct.records {
                if seen.insert(&ancestor.id) {
                    records.push(ancestor);
                    queue.push_back(ancestor);
                }
            }
        }
        let disposition = if conflict {
            SemanticModelOverlayDisposition::Conflict
        } else if records.is_empty() {
            SemanticModelOverlayDisposition::Empty
        } else {
            SemanticModelOverlayDisposition::Unique
        };
        SemanticModelAncestry {
            records,
            disposition,
            defects,
        }
    }

    /// One type's whole inherited surface, gated on the three conditions a
    /// member-absence proof needs.
    ///
    /// The owner leads the closure because its own members are part of the
    /// surface, and its own provenance is subject to the same gate as every
    /// ancestor's.
    pub fn owner_surface<'a>(
        &'a self,
        owner: &'a SemanticModelSymbol,
    ) -> SemanticModelOwnerSurface<'a> {
        let ancestry = self.ancestors_of(owner);
        let mut closure = Vec::with_capacity(ancestry.records.len().saturating_add(1));
        closure.push(owner);
        closure.extend(ancestry.records);
        // Edges first: a base nothing published is the most specific reason a
        // surface is short, and the one a suppression detail should name.
        let mut gaps = ancestry
            .defects
            .into_iter()
            .map(SemanticModelSurfaceGap::UnresolvedEdge)
            .collect::<Vec<_>>();
        for record in &closure {
            if record.provenance.ambiguous {
                gaps.push(SemanticModelSurfaceGap::AmbiguousType {
                    qualified_name: record.qualified_name.clone(),
                });
            }
            // A producer that could not enumerate a type's whole surface marks
            // its pack partial, which also covers every edge it never
            // recorded: an unrecorded base cannot show up as a defect.
            if record.provenance.completeness != SemanticModelCompleteness::Complete {
                gaps.push(SemanticModelSurfaceGap::PartialType {
                    qualified_name: record.qualified_name.clone(),
                });
            }
        }
        SemanticModelOwnerSurface { closure, gaps }
    }

    /// Return the active universal root for a language that has one, when it is
    /// uniquely present. The name indexes are already retained by the overlay,
    /// so this lazy lookup is cheaper than another per-type cache or authored
    /// edge.
    pub fn universal_root_for_language(
        &self,
        language: &str,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        let Some(root) = universal_root_name_for_language(language) else {
            return self.symbol_match(None);
        };
        self.symbols_named(root)
    }

    fn direct_ancestors_of(&self, symbol: &SemanticModelSymbol) -> SemanticModelAncestry<'_> {
        let hierarchy = self
            .relations_from(&symbol.id)
            .records
            .into_iter()
            .filter(|relation| {
                matches!(
                    relation.kind.as_str(),
                    "extends" | "implements" | "uses_trait" | "mixin_include" | "mixin_prepend"
                )
            })
            .collect::<Vec<_>>();
        let has_class_parent = hierarchy.iter().any(|relation| relation.kind == "extends");
        let mut records = Vec::new();
        let mut defects = Vec::new();
        let mut conflict = hierarchy
            .iter()
            .any(|relation| relation.provenance.ambiguous);
        for relation in hierarchy {
            let target = self.ancestry_target_name(symbol, &relation.to);
            // Declaration IDs are not module-relative names.
            let target = if self.symbols_with_id(&relation.to).records.is_empty() {
                target.as_ref()
            } else {
                &relation.to
            };
            // The label does not name the target's kind. A pack records a
            // supertype by name, and each producer labels its own way: the JVM
            // external packs call a trait or interface supertype `extends`, and
            // Rust calls a trait implementation `implements`. The target is a
            // type either way, so ask for that and let the language's own kind
            // decide the rest.
            let resolved =
                self.resolve_edge_target(target, &symbol.language, HierarchyTargetShape::Type);
            conflict |= resolved.defect == Some(SemanticModelEdgeDefect::Ambiguous);
            if let Some(defect) = resolved.defect {
                defects.push(SemanticModelUnresolvedEdge {
                    from: symbol.qualified_name.clone(),
                    to: relation.to.clone(),
                    defect,
                });
            }
            records.extend(resolved.records);
        }
        // A declaration that names no class parent still inherits the
        // language's universal root, and that root's members are part of its
        // surface. An unpublished root is therefore a hole in the surface, not
        // a clean bottom.
        if !has_class_parent
            && let Some(root_name) =
                universal_root_name(symbol).filter(|root| *root != symbol.qualified_name)
        {
            let resolved =
                self.resolve_edge_target(root_name, &symbol.language, HierarchyTargetShape::Type);
            conflict |= resolved.defect == Some(SemanticModelEdgeDefect::Ambiguous);
            if let Some(defect) = resolved.defect {
                defects.push(SemanticModelUnresolvedEdge {
                    from: symbol.qualified_name.clone(),
                    to: root_name.to_string(),
                    defect,
                });
            }
            records.extend(resolved.records);
        }
        let mut seen = HashSet::default();
        records.retain(|record| seen.insert(record.id.as_str()));
        SemanticModelAncestry {
            disposition: if conflict {
                SemanticModelOverlayDisposition::Conflict
            } else if records.is_empty() {
                SemanticModelOverlayDisposition::Empty
            } else {
                SemanticModelOverlayDisposition::Unique
            },
            records,
            defects,
        }
    }

    /// Same-qualified-name class records describe one class. Prefer a complete
    /// surface, then the smallest ID, as in external class identity (#4942).
    pub(crate) fn class_representative<'a>(
        &self,
        records: impl IntoIterator<Item = &'a SemanticModelSymbol>,
    ) -> Option<&'a SemanticModelSymbol> {
        records.into_iter().min_by_key(|record| {
            (
                record.provenance.completeness != SemanticModelCompleteness::Complete,
                &record.id,
            )
        })
    }

    /// Qualify a bare hierarchy-edge target through the declaring language's
    /// own rule. A legacy Python pack records `class Child(Base)` as `Base`,
    /// which means the `Base` in the declaring class's own module; every other
    /// language's producer records a target that is already complete.
    #[doc(hidden)]
    pub fn ancestry_target_name<'a>(
        &self,
        class: &SemanticModelSymbol,
        target: &'a str,
    ) -> std::borrow::Cow<'a, str> {
        let qualified = Language::from_config_label(&class.language)
            .and_then(|language| {
                crate::analyzer::languages::language_support_for_hook(
                    language,
                    "qualified_hierarchy_target",
                )
            })
            .and_then(|support| {
                support.qualified_hierarchy_target(
                    class.locator_path.as_deref(),
                    &class.qualified_name,
                    target,
                )
            });
        match qualified {
            Some(qualified) => std::borrow::Cow::Owned(qualified),
            None => target.into(),
        }
    }

    /// Resolve one hierarchy edge target to the declarations it names, and say
    /// whether that resolution is clean enough to carry a proof.
    ///
    /// A pack records a target either as a declaration identity or as a name,
    /// and the name it records ranges from a fully qualified one (PHP resolves
    /// its `extends` clause through the file's `use` aliases) to the bare
    /// source spelling (Python records `class Child(Base)` as `Base`). Matching
    /// a bare spelling against the overlay's simple-name postings is a guess:
    /// two indexed packages can each declare a `Base`. The records still carry
    /// the guess, because navigation wants the candidate, but the defect says a
    /// proof must not treat it as a crossed edge.
    ///
    /// A producer records a re-export as an exact alias of the declaring
    /// record, so `collections.abc.MutableSet` is an alias of
    /// `typing.MutableSet` and names that declaration as surely as its own
    /// qualified name does (#2958). Aliases also carry bare export spellings,
    /// which another language's pack can hold by coincidence, so an alias match
    /// counts only for the language that spelled the edge.
    fn resolve_edge_target(
        &self,
        target: &str,
        language: &str,
        shape: HierarchyTargetShape,
    ) -> ResolvedEdgeTarget<'_> {
        let mut by_id = self.symbols_with_id(target);
        by_id.records.retain(|record| {
            shape.admits(record) && record.owner_id.is_none() && record.language == language
        });
        if !by_id.records.is_empty() {
            return ResolvedEdgeTarget {
                defect: (by_id.disposition == SemanticModelOverlayDisposition::Conflict)
                    .then_some(SemanticModelEdgeDefect::Ambiguous),
                records: by_id.records,
            };
        }
        let mut by_name = self.symbols_named(target);
        by_name.records.retain(|record| {
            shape.admits(record) && record.owner_id.is_none() && record.language == language
        });
        if by_name.records.is_empty() {
            return ResolvedEdgeTarget {
                records: Vec::new(),
                defect: Some(SemanticModelEdgeDefect::Unpublished),
            };
        }
        let exact = by_name
            .records
            .iter()
            .copied()
            .filter(|record| {
                record.qualified_name == target
                    || (record.language == language
                        && record.aliases.iter().any(|alias| alias == target))
            })
            .collect::<Vec<_>>();
        // Same-qualified-name class records describe one class (#4942), so a
        // class base that several packs publish resolves to one representative
        // instead of reading as ambiguous. The rule is about the group being
        // class records, not about the edge's shape, because the generic pack
        // path asks for any type and cannot say "class" on the caller's behalf.
        if !exact.is_empty()
            && exact
                .iter()
                .all(|record| record.kind == SemanticModelSymbolKind::Class)
            && exact.iter().all(|record| {
                !record.provenance.ambiguous
                    && record.qualified_name == exact[0].qualified_name
                    && record.language == language
            })
        {
            return ResolvedEdgeTarget {
                records: vec![
                    self.class_representative(exact)
                        .expect("exact class group is nonempty"),
                ],
                defect: None,
            };
        }
        match exact.as_slice() {
            [] => ResolvedEdgeTarget {
                records: by_name.records,
                defect: Some(SemanticModelEdgeDefect::NameResolved),
            },
            [record] if !record.provenance.ambiguous => ResolvedEdgeTarget {
                records: exact,
                defect: None,
            },
            _ => ResolvedEdgeTarget {
                records: exact,
                defect: Some(SemanticModelEdgeDefect::Ambiguous),
            },
        }
    }

    fn rebuild_indexes(
        &mut self,
        cancellation: &crate::CancellationToken,
    ) -> Result<(), SemanticModelOverlayBuildError> {
        for (index, symbol) in self.symbols.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            push_unique_posting(&mut self.symbols_by_id, &symbol.id, index);
            push_unique_posting(&mut self.symbols_by_name, &symbol.name, index);
            push_unique_posting(&mut self.symbols_by_name, &symbol.qualified_name, index);
            for alias in &symbol.aliases {
                push_unique_posting(&mut self.symbols_by_name, alias, index);
            }
            if let Some(owner) = &symbol.owner_id {
                self.symbols_by_owner
                    .entry(owner.clone())
                    .or_default()
                    .push(index);
            }
            match &symbol.location {
                SemanticModelLocation::Authored(anchor) => {
                    self.symbols_by_authored_path
                        .entry(anchor.path.clone())
                        .or_default()
                        .push(index);
                }
                SemanticModelLocation::Model(location) => {
                    self.symbols_by_uri
                        .entry(location.uri.clone())
                        .or_default()
                        .push(index);
                }
            }
        }
        for (index, relation) in self.relations.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            self.relations_from
                .entry(relation.from.clone())
                .or_default()
                .push(index);
            self.relations_to
                .entry(relation.to.clone())
                .or_default()
                .push(index);
        }
        Ok(())
    }

    pub(crate) fn retained_bytes_lower_bound(&self) -> u64 {
        let symbol_bytes = self
            .symbols
            .iter()
            .map(|symbol| {
                std::mem::size_of::<SemanticModelSymbol>()
                    .saturating_add(symbol.id.capacity())
                    .saturating_add(symbol.owner_id.as_ref().map_or(0, String::capacity))
                    .saturating_add(symbol.name.capacity())
                    .saturating_add(symbol.qualified_name.capacity())
                    .saturating_add(symbol.rust_generated_scope.as_ref().map_or(0, |scope| {
                        std::mem::size_of_val(scope.as_ref())
                            .saturating_add(scope.module.capacity())
                            .saturating_add(scope.file.capacity())
                    }))
                    .saturating_add(symbol.language.capacity())
                    .saturating_add(symbol.signature.as_ref().map_or(0, String::capacity))
                    .saturating_add(symbol.aliases.iter().map(String::capacity).sum::<usize>())
                    .saturating_add(match &symbol.location {
                        SemanticModelLocation::Authored(anchor) => anchor
                            .path
                            .capacity()
                            .saturating_add(anchor.symbol.capacity()),
                        SemanticModelLocation::Model(location) => location.uri.capacity(),
                    })
                    .saturating_add(symbol.provenance.retained_string_bytes())
            })
            .sum::<usize>();
        let relation_bytes = self
            .relations
            .iter()
            .map(|relation| {
                std::mem::size_of::<SemanticModelRelation>()
                    .saturating_add(relation.id.capacity())
                    .saturating_add(relation.kind.capacity())
                    .saturating_add(relation.from.capacity())
                    .saturating_add(relation.to.capacity())
                    .saturating_add(relation.provenance.retained_string_bytes())
            })
            .sum::<usize>();
        let hierarchy_bytes = self
            .java_hierarchy
            .iter()
            .map(|(id, (parameters, edges))| {
                id.capacity()
                    .saturating_add(
                        parameters
                            .capacity()
                            .saturating_mul(std::mem::size_of::<String>()),
                    )
                    .saturating_add(parameters.iter().map(String::capacity).sum::<usize>())
                    .saturating_add(
                        edges
                            .capacity()
                            .saturating_mul(std::mem::size_of::<HierarchyFact>()),
                    )
            })
            .sum::<usize>();
        let mut index_bytes = 0usize;
        for map in [
            &self.symbols_by_id,
            &self.symbols_by_name,
            &self.symbols_by_uri,
            &self.symbols_by_authored_path,
            &self.symbols_by_owner,
            &self.relations_from,
            &self.relations_to,
            &self.conditional_types_by_callable,
        ] {
            for (key, posting) in map {
                index_bytes = index_bytes.saturating_add(key.capacity()).saturating_add(
                    posting
                        .capacity()
                        .saturating_mul(std::mem::size_of::<usize>()),
                );
            }
        }
        let conditional_bytes =
            self.conditional_type_refinements
                .iter()
                .fold(0usize, |bytes, fact| {
                    bytes
                        .saturating_add(std::mem::size_of::<ConditionalTypeRefinementContract>())
                        .saturating_add(fact.payload.callable.capacity())
                        .saturating_add(fact.provenance.retained_string_bytes())
                });
        let deferred_bytes = self.deferred_yields.iter().fold(0usize, |bytes, contract| {
            bytes
                .saturating_add(std::mem::size_of::<DeferredYieldContract>())
                .saturating_add(contract.factory.capacity())
                .saturating_add(contract.resume.capacity())
                .saturating_add(contract.handle_type.capacity())
                .saturating_add(contract.provenance.retained_string_bytes())
        });
        for ((factory, resume, handle_type), posting) in &self.deferred_yields_by_scope {
            index_bytes = index_bytes
                .saturating_add(factory.capacity())
                .saturating_add(resume.capacity())
                .saturating_add(handle_type.capacity())
                .saturating_add(
                    posting
                        .capacity()
                        .saturating_mul(std::mem::size_of::<usize>()),
                );
        }
        u64::try_from(
            std::mem::size_of::<Self>()
                .saturating_add(symbol_bytes)
                .saturating_add(relation_bytes)
                .saturating_add(hierarchy_bytes)
                .saturating_add(deferred_bytes)
                .saturating_add(conditional_bytes)
                .saturating_add(index_bytes),
        )
        .unwrap_or(u64::MAX)
    }

    fn symbol_match(
        &self,
        posting: Option<&Vec<usize>>,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        let records = posting
            .into_iter()
            .flatten()
            .map(|index| &self.symbols[*index])
            .collect::<Vec<_>>();
        SemanticModelOverlayMatch {
            disposition: disposition(&records, |record| record.provenance.ambiguous),
            records,
        }
    }

    fn collection_flow_match(
        &self,
        posting: Option<&Vec<usize>>,
    ) -> SemanticModelOverlayMatch<'_, CollectionFlowContract> {
        let records = posting
            .into_iter()
            .flatten()
            .map(|index| &self.collection_flows[*index])
            .collect::<Vec<_>>();
        let disposition = if records.is_empty() {
            SemanticModelOverlayDisposition::Empty
        } else if records.len() > 1 || records.iter().any(|record| record.provenance.ambiguous) {
            SemanticModelOverlayDisposition::Conflict
        } else {
            SemanticModelOverlayDisposition::Unique
        };
        SemanticModelOverlayMatch {
            records,
            disposition,
        }
    }

    fn deferred_yield_match(
        &self,
        indexes: Option<&Vec<usize>>,
    ) -> SemanticModelOverlayMatch<'_, DeferredYieldContract> {
        let Some(indexes) = indexes else {
            return SemanticModelOverlayMatch {
                records: Vec::new(),
                disposition: SemanticModelOverlayDisposition::Empty,
            };
        };
        let records = indexes
            .iter()
            .map(|index| &self.deferred_yields[*index])
            .collect::<Vec<_>>();
        let disposition = match records.first() {
            None => SemanticModelOverlayDisposition::Empty,
            Some(first)
                if records.iter().all(|record| {
                    !record.provenance.ambiguous
                        && record.payload == first.payload
                        && record.coverage == first.coverage
                        && record.provenance.pack_digest == first.provenance.pack_digest
                }) =>
            {
                SemanticModelOverlayDisposition::Unique
            }
            Some(_) => SemanticModelOverlayDisposition::Conflict,
        };
        SemanticModelOverlayMatch {
            records,
            disposition,
        }
    }

    fn relation_match(
        &self,
        posting: Option<&Vec<usize>>,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelRelation> {
        let records = posting
            .into_iter()
            .flatten()
            .map(|index| &self.relations[*index])
            .collect::<Vec<_>>();
        SemanticModelOverlayMatch {
            disposition: if records.is_empty() {
                SemanticModelOverlayDisposition::Empty
            } else if records.iter().any(|record| record.provenance.ambiguous) {
                SemanticModelOverlayDisposition::Conflict
            } else {
                SemanticModelOverlayDisposition::Unique
            },
            records,
        }
    }
}

pub(crate) fn type_declaration_records_conflict(
    matched: &SemanticModelMatch<'_, TypeFact>,
) -> bool {
    declaration_records_conflict(matched)
        && matched.records.first().is_some_and(|first| {
            matched
                .records
                .iter()
                .any(|candidate| !type_declarations_equivalent(first.record, candidate.record))
        })
}

pub(crate) fn declaration_records_conflict<T>(matched: &SemanticModelMatch<'_, T>) -> bool {
    if matched.disposition != SemanticModelMatchDisposition::Conflict {
        return false;
    }
    let mut artifacts = HashSet::default();
    !matched.records.iter().all(|record| {
        let evidence = &record.shard.matched_evidence;
        evidence.ecosystem == "jdk"
            && evidence
                .artifact_sha256
                .as_ref()
                .is_some_and(|digest| artifacts.insert(digest.as_str()))
    })
}

pub fn explain_semantic_model_site(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    site: SemanticModelSite,
    rule_id: Option<&str>,
    cancellation: &crate::CancellationToken,
    max_explanations: usize,
) -> SemanticModelMatchExplanationReport {
    let mut report = SemanticModelMatchExplanationReport {
        format: SEMANTIC_MODEL_MATCH_EXPLANATION_FORMAT,
        site: site.clone(),
        complete: true,
        explanations: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut rule_ids = active
        .shards()
        .iter()
        .flat_map(|shard| {
            shard
                .shard
                .payload()
                .generator_rules()
                .into_iter()
                .flatten()
                .map(|rule| rule.id.clone())
        })
        .filter(|id| rule_id.is_none_or(|requested| requested == id))
        .collect::<Vec<_>>();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    if rule_ids.is_empty() {
        report
            .diagnostics
            .push("no active generator rule matches the requested rule id".to_owned());
        return report;
    }

    for rule_id in rule_ids {
        if cancellation.is_cancelled() {
            report.complete = false;
            report.diagnostics.push("operation cancelled".to_owned());
            break;
        }
        if report.explanations.len() >= max_explanations {
            report.complete = false;
            report
                .diagnostics
                .push("explanation limit exceeded".to_owned());
            break;
        }
        let matched_rule = active.rules_with_id(&rule_id);
        let shadowing = match matched_rule.disposition {
            SemanticModelMatchDisposition::Empty => "absent",
            SemanticModelMatchDisposition::Unique => "unique",
            SemanticModelMatchDisposition::Conflict => "conflict",
        };
        for activated in matched_rule.records {
            if report.explanations.len() >= max_explanations {
                report.complete = false;
                report
                    .diagnostics
                    .push("explanation limit exceeded".to_owned());
                break;
            }
            let mut explanation = SemanticModelRuleExplanation {
                pack_id: activated.shard.manifest.pack_id.clone(),
                pack_version: activated.shard.manifest.version.clone(),
                shard_id: activated.shard.shard.shard_id.clone(),
                rule_id: activated.record.id.clone(),
                source_kind: source_kind(activated.shard.source_kind).to_owned(),
                source_id: activated.shard.source_id.clone(),
                shadowing: shadowing.to_owned(),
                matched: false,
                activation_evidence: matched_evidence(&activated.shard.matched_evidence),
                captures: BTreeMap::new(),
                emitted_symbols: Vec::new(),
                emitted_relations: Vec::new(),
                emitted_aliases: Vec::new(),
                first_failed_predicate: None,
            };
            if matched_rule.disposition == SemanticModelMatchDisposition::Conflict {
                explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
                    code: "rule.shadowed".to_owned(),
                    message: "equal-precedence active rules conflict, so production emits neither"
                        .to_owned(),
                });
                report.explanations.push(explanation);
                continue;
            }
            evaluate_explanation_at_site(
                analyzer,
                active,
                activated.shard,
                activated.record,
                &site,
                &mut explanation,
            );
            report.explanations.push(explanation);
        }
    }
    report
}

pub(crate) fn evaluate_explanation_at_site(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    rule: &GeneratorRule,
    site: &SemanticModelSite,
    explanation: &mut SemanticModelRuleExplanation,
) {
    let path = Path::new(&site.path);
    let provider_file = analyzer
        .structural_fact_providers()
        .into_iter()
        .filter(|provider| provider.structural_language().config_label() == shard.manifest.language)
        .find_map(|provider| {
            provider
                .structural_files()
                .into_iter()
                .find(|file| file.rel_path() == path)
                .map(|file| (provider, file))
        });
    let Some((provider, file)) = provider_file else {
        explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
            code: "site.not_indexed".to_owned(),
            message: "the requested path is not indexed for the rule language".to_owned(),
        });
        return;
    };
    let Some(facts) = provider.structural_facts(&file) else {
        explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
            code: "site.no_structural_facts".to_owned(),
            message: "the production structural provider has no facts for this file".to_owned(),
        });
        return;
    };
    let mut nodes = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.range.start_line <= site.line && node.range.end_line >= site.line)
        .collect::<Vec<_>>();
    nodes.sort_by_key(|(_, node)| node.range.end_byte.saturating_sub(node.range.start_byte));
    if nodes.is_empty() {
        explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
            code: "site.no_node".to_owned(),
            message: "the requested line has no normalized structural node".to_owned(),
        });
        return;
    }
    let mut first_failure = None;
    for (node_index, node) in nodes {
        let node_id = u32::try_from(node_index).expect("structural fact IDs fit u32");
        let enclosing = analyzer.enclosing_code_unit(&file, &node.range);
        match evaluate_rule_at_node(analyzer, rule, &facts, node_id, &file, enclosing.as_ref()) {
            Ok(matches) if !matches.is_empty() => {
                explanation.matched = true;
                explanation.captures = matches[0]
                    .values
                    .iter()
                    .map(|(name, value)| (name.clone(), value.value.clone()))
                    .collect();
                explanation
                    .captures
                    .extend(matches[0].groups.iter().map(|(name, values)| {
                        (
                            name.clone(),
                            format!(
                                "{:?}",
                                values.iter().map(|value| &value.value).collect::<Vec<_>>()
                            ),
                        )
                    }));
                let mut aliases = Vec::new();
                for captures in &matches {
                    emit_rule_match(
                        active,
                        shard,
                        rule,
                        captures,
                        &mut explanation.emitted_symbols,
                        &mut explanation.emitted_relations,
                        &mut aliases,
                    );
                }
                explanation.emitted_aliases = aliases
                    .into_iter()
                    .map(|(from, to)| SemanticModelEmittedAlias { from, to })
                    .collect();
                return;
            }
            Ok(_) => {}
            Err(failure) if first_failure.is_none() => first_failure = Some(failure),
            Err(_) => {}
        }
    }
    explanation.first_failed_predicate = first_failure;
}

pub fn preview_semantic_model_emissions(
    active: &ResolvedActiveSemanticModels,
    rule_id: &str,
    captures: &BTreeMap<String, String>,
) -> SemanticModelEmissionPreview {
    let matched = active.rules_with_id(rule_id);
    let shadowing = match matched.disposition {
        SemanticModelMatchDisposition::Empty => "absent",
        SemanticModelMatchDisposition::Unique => "unique",
        SemanticModelMatchDisposition::Conflict => "conflict",
    };
    let mut report = SemanticModelEmissionPreview {
        format: SEMANTIC_MODEL_EMISSION_PREVIEW_FORMAT,
        complete: matched.disposition == SemanticModelMatchDisposition::Unique,
        pack_id: None,
        rule_id: rule_id.to_owned(),
        shadowing: shadowing.to_owned(),
        captures: captures.clone(),
        emitted_symbols: Vec::new(),
        emitted_relations: Vec::new(),
        emitted_aliases: Vec::new(),
        diagnostics: Vec::new(),
    };
    let [activated] = matched.records.as_slice() else {
        report.diagnostics.push(
            match matched.disposition {
                SemanticModelMatchDisposition::Empty => "the active model set has no such rule",
                SemanticModelMatchDisposition::Conflict => {
                    "equal-precedence active rules conflict, so production emits neither"
                }
                SemanticModelMatchDisposition::Unique => unreachable!(),
            }
            .to_owned(),
        );
        return report;
    };
    report.pack_id = Some(activated.shard.manifest.pack_id.clone());
    let missing_captures = activated
        .record
        .captures
        .iter()
        .filter(|capture| {
            capture.cardinality == crate::analyzer::semantic_model::CaptureCardinality::One
                && !captures.contains_key(&capture.name)
        })
        .map(|capture| capture.name.clone())
        .collect::<Vec<_>>();
    if !missing_captures.is_empty() {
        report.complete = false;
        report.diagnostics.push(format!(
            "required captures are missing: {missing_captures:?}"
        ));
        return report;
    }
    let captures = GeneratorRuleMatch {
        values: captures
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    CapturedValue {
                        value: value.clone(),
                        anchor: None,
                    },
                )
            })
            .collect::<HashMap<_, _>>(),
        groups: HashMap::default(),
    };
    let mut aliases = Vec::new();
    emit_rule_match(
        active,
        activated.shard,
        activated.record,
        &captures,
        &mut report.emitted_symbols,
        &mut report.emitted_relations,
        &mut aliases,
    );
    report.emitted_aliases = aliases
        .into_iter()
        .map(|(from, to)| SemanticModelEmittedAlias { from, to })
        .collect();
    report
}

pub fn scan_unmapped_semantic_model_sites(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    selectors: &[SemanticModelGeneratorSelector],
    limits: SemanticModelUnmappedScanLimits,
    cancellation: &crate::CancellationToken,
) -> SemanticModelUnmappedScanReport {
    let mut report = SemanticModelUnmappedScanReport {
        format: SEMANTIC_MODEL_UNMAPPED_SCAN_FORMAT,
        complete: true,
        scanned_files: 0,
        scanned_nodes: 0,
        sites: Vec::new(),
        diagnostics: Vec::new(),
    };
    let active_rules = unique_active_rules(active);
    let provider_files = analyzer
        .structural_fact_providers()
        .into_iter()
        .map(|provider| {
            let mut files = provider.structural_files();
            files.sort();
            files.dedup();
            (provider, files)
        })
        .collect::<Vec<_>>();
    for selector in selectors {
        for (provider, files) in provider_files.iter().filter(|(provider, _)| {
            provider.structural_language().config_label() == selector.language
        }) {
            for file in files {
                if cancellation.is_cancelled() {
                    report.complete = false;
                    report.diagnostics.push("operation cancelled".to_owned());
                    return report;
                }
                if report.scanned_files >= limits.max_files {
                    report.complete = false;
                    report.diagnostics.push("file limit exceeded".to_owned());
                    return report;
                }
                report.scanned_files += 1;
                let Some(facts) = provider.structural_facts(file) else {
                    continue;
                };
                for (node_index, node) in facts.nodes().iter().enumerate() {
                    if report.scanned_nodes >= limits.max_nodes {
                        report.complete = false;
                        report.diagnostics.push("node limit exceeded".to_owned());
                        return report;
                    }
                    report.scanned_nodes += 1;
                    let node_id = u32::try_from(node_index).expect("structural fact IDs fit u32");
                    if !rule_trigger_matches(analyzer, file, &selector.trigger, &facts, node_id) {
                        continue;
                    }
                    let enclosing = analyzer.enclosing_code_unit(file, &node.range);
                    let modeled = active_rules.iter().any(|(shard, rule)| {
                        shard.manifest.language == selector.language
                            && evaluate_rule_at_node(
                                analyzer,
                                rule,
                                &facts,
                                node_id,
                                file,
                                enclosing.as_ref(),
                            )
                            .is_ok_and(|matches| !matches.is_empty())
                    });
                    if modeled {
                        continue;
                    }
                    if report.sites.len() >= limits.max_sites {
                        report.complete = false;
                        report.diagnostics.push("site limit exceeded".to_owned());
                        return report;
                    }
                    report.sites.push(SemanticModelUnmappedSite {
                        path: file.rel_path().to_string_lossy().replace('\\', "/"),
                        line: node.range.start_line,
                        name: node.name.map(|name| name.text(facts.source()).to_owned()),
                        site_kind: selector.site_kind,
                        requested_trigger: selector.trigger.clone(),
                    });
                }
            }
        }
    }
    report.sites.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.name.cmp(&right.name))
    });
    report
}

pub(crate) fn unique_active_rules(
    active: &ResolvedActiveSemanticModels,
) -> Vec<(&ActiveSemanticModelShard, &GeneratorRule)> {
    let mut rule_ids = active
        .shards()
        .iter()
        .flat_map(|shard| {
            shard
                .shard
                .payload()
                .generator_rules()
                .into_iter()
                .flatten()
                .map(|rule| rule.id.clone())
        })
        .collect::<Vec<_>>();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    rule_ids
        .iter()
        .filter_map(|rule_id| {
            let matched = active.rules_with_id(rule_id);
            let [activated] = matched.records.as_slice() else {
                return None;
            };
            Some((activated.shard, activated.record))
        })
        .collect()
}

pub fn run_semantic_model_conformance(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    fixture: &SemanticModelConformanceFixture,
    cancellation: &crate::CancellationToken,
    max_assertions: usize,
) -> SemanticModelConformanceReport {
    let mut report = SemanticModelConformanceReport {
        format: SEMANTIC_MODEL_CONFORMANCE_FORMAT,
        complete: true,
        passed: false,
        checked_assertions: 0,
        failures: Vec::new(),
    };
    if fixture.schema_version != 1 {
        report.complete = false;
        report.failures.push(format!(
            "unsupported conformance schema version {}",
            fixture.schema_version
        ));
        return report;
    }
    let assertion_count = fixture
        .symbols
        .len()
        .saturating_add(fixture.relationships.len())
        .saturating_add(fixture.forward_definitions.len())
        .saturating_add(fixture.inverse_usages.len())
        .saturating_add(fixture.positive_matches.len())
        .saturating_add(fixture.negative_matches.len());
    if assertion_count > max_assertions {
        report.complete = false;
        report.failures.push(format!(
            "conformance assertions exceed the limit of {max_assertions}"
        ));
        return report;
    }
    let overlay = match SemanticModelOverlay::build(analyzer, active, cancellation, u64::MAX) {
        Ok(overlay) => overlay,
        Err(error_value) => {
            report.complete = false;
            report
                .failures
                .push(format!("production overlay build failed: {error_value:?}"));
            return report;
        }
    };
    for expected in &fixture.symbols {
        report.checked_assertions += 1;
        let matched = overlay.symbols.iter().any(|symbol| {
            symbol.id == expected.id
                && symbol.owner_id == expected.owner_id
                && symbol.name == expected.name
                && symbol.signature == expected.signature
                && symbol
                    .location
                    .identity()
                    .starts_with(&expected.location_prefix)
                && symbol.provenance.pack_id == expected.pack_id
                && symbol.provenance.rule_id == expected.rule_id
                && symbol.provenance.completeness.label() == expected.completeness
        });
        if !matched {
            report
                .failures
                .push(format!("missing expected symbol `{}`", expected.id));
        }
    }
    for expected in &fixture.relationships {
        report.checked_assertions += 1;
        if !overlay.relations.iter().any(|relation| {
            relation.id == expected.id
                && relation.kind == expected.kind
                && relation.from == expected.from
                && relation.to == expected.to
        }) {
            report
                .failures
                .push(format!("missing expected relationship `{}`", expected.id));
        }
    }
    for expected in &fixture.forward_definitions {
        report.checked_assertions += 1;
        if !overlay.relations.iter().any(|relation| {
            relation.kind == "navigates_to"
                && relation.from == expected.from
                && relation.to == expected.to
        }) {
            report.failures.push(format!(
                "missing forward definition {} -> {}",
                expected.from, expected.to
            ));
        }
    }
    for expected in &fixture.inverse_usages {
        report.checked_assertions += 1;
        if !overlay.relations.iter().any(|relation| {
            relation.kind == "references"
                && relation.from == expected.from
                && relation.to == expected.to
        }) {
            report.failures.push(format!(
                "missing inverse usage {} -> {}",
                expected.from, expected.to
            ));
        }
    }
    for expected in &fixture.positive_matches {
        report.checked_assertions += 1;
        let explanation = explain_semantic_model_site(
            analyzer,
            active,
            expected.site.clone(),
            Some(&expected.rule_id),
            cancellation,
            64,
        );
        if !explanation
            .explanations
            .iter()
            .any(|explanation| explanation.matched)
        {
            report.failures.push(format!(
                "expected rule `{}` to match {}:{}",
                expected.rule_id, expected.site.path, expected.site.line
            ));
        }
    }
    for expected in &fixture.negative_matches {
        report.checked_assertions += 1;
        let explanation = explain_semantic_model_site(
            analyzer,
            active,
            expected.site.clone(),
            Some(&expected.rule_id),
            cancellation,
            64,
        );
        if explanation
            .explanations
            .iter()
            .any(|explanation| explanation.matched)
        {
            report.failures.push(format!(
                "expected rule `{}` to miss {}:{}",
                expected.rule_id, expected.site.path, expected.site.line
            ));
        }
    }
    if cancellation.is_cancelled() {
        report.complete = false;
        report.failures.push("operation cancelled".to_owned());
    }
    report.passed = report.complete && report.failures.is_empty();
    report
}

pub(crate) fn generated_overlay_facts(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    cancellation: &crate::CancellationToken,
) -> Result<GeneratedOverlayFacts, SemanticModelOverlayBuildError> {
    let active_rules = unique_active_rules(active);

    let provider_files = analyzer
        .structural_fact_providers()
        .into_iter()
        .map(|provider| {
            let mut files = provider.structural_files();
            files.sort();
            files.dedup();
            (provider, files)
        })
        .collect::<Vec<_>>();

    let mut symbols = Vec::new();
    let mut relations = Vec::new();
    let mut aliases = Vec::new();
    for (provider, files) in &provider_files {
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        let rules = active_rules
            .iter()
            .copied()
            .filter(|(shard, _)| {
                shard.manifest.language == provider.structural_language().config_label()
            })
            .collect::<Vec<_>>();
        if rules.is_empty() {
            continue;
        }
        // A large workspace can exceed the per-file hydration cache. Keep the
        // file outside the rule loop so each file state is loaded only once.
        let generated_files = files
            .par_iter()
            .map(|file| {
                if cancellation.is_cancelled() {
                    return Err(SemanticModelOverlayBuildError::Cancelled);
                }
                let mut generated = GeneratedFileFacts {
                    symbols: Vec::new(),
                    relations: Vec::new(),
                    aliases: Vec::new(),
                };
                let Some(facts) = provider.structural_facts(file) else {
                    return Ok(generated);
                };
                for (node_index, node) in facts.nodes().iter().enumerate() {
                    if cancellation.is_cancelled() {
                        return Err(SemanticModelOverlayBuildError::Cancelled);
                    }
                    let node_id = u32::try_from(node_index)
                        .expect("structural fact IDs are bounded to u32 by FileFacts");
                    let matching_rules = rules
                        .iter()
                        .copied()
                        .filter(|(_, rule)| {
                            rule_trigger_matches(analyzer, file, &rule.trigger, &facts, node_id)
                        })
                        .collect::<Vec<_>>();
                    if matching_rules.is_empty() {
                        continue;
                    }
                    // Enclosing-symbol lookup can hydrate source ranges. Do it
                    // only after a cheap trigger match, and share it across rules.
                    let enclosing = analyzer.enclosing_code_unit(file, &node.range);
                    for (shard, rule) in matching_rules {
                        let Ok(captures) = rule_capture_values(
                            analyzer,
                            rule,
                            &facts,
                            node_id,
                            file,
                            enclosing.as_ref(),
                        ) else {
                            continue;
                        };
                        for captures in &captures {
                            emit_rule_match(
                                active,
                                shard,
                                rule,
                                captures,
                                &mut generated.symbols,
                                &mut generated.relations,
                                &mut generated.aliases,
                            );
                        }
                    }
                }
                crate::analyzer::languages::language_support_for_hook(
                    provider.structural_language(),
                    "bind_generated_symbols",
                )
                .expect("every structural fact provider language has registered support")
                .bind_generated_symbols(
                    file,
                    facts.source(),
                    &mut generated.symbols,
                );
                Ok(generated)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Indexed Rayon collection preserves file order, so fact ordering is
        // identical to the former sequential traversal.
        for generated in generated_files {
            symbols.extend(generated.symbols);
            relations.extend(generated.relations);
            aliases.extend(generated.aliases);
        }
    }
    for (alias, target) in aliases {
        if let Some(symbol) = symbols
            .iter_mut()
            .find(|symbol| symbol.id == target || symbol.qualified_name == target)
            && !symbol.aliases.contains(&alias)
        {
            symbol.aliases.push(alias);
        }
    }
    Ok(GeneratedOverlayFacts { symbols, relations })
}

pub(crate) fn rule_trigger_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    trigger: &RuleTrigger,
    facts: &FileFacts,
    node_id: u32,
) -> bool {
    let node = facts.node(node_id);
    let name = node.name.map(|span| span.text(facts.source()));
    match trigger {
        RuleTrigger::LanguageConstruct { construct } => {
            node.construct.as_deref() == Some(construct)
                || NormalizedKind::from_label(construct).is_some_and(|kind| node.kind == kind)
        }
        RuleTrigger::Annotation { name: expected } => {
            node.kind == NormalizedKind::Decorator
                && (name.is_some_and(|actual| exact_trigger_name_matches(expected, actual))
                    || qualified_decorator_matches(expected, node.span().text(facts.source()))
                    || name.is_some_and(|actual| {
                        imported_trigger_name_matches(
                            analyzer,
                            file,
                            expected,
                            actual,
                            node.range.start_byte,
                        )
                    }))
        }
        RuleTrigger::AnnotatedField {
            annotation,
            value,
            excluded_annotations,
            owner_annotation_path,
        } => {
            node.kind == NormalizedKind::Declaration
                && node.name.is_some()
                && matching_applied_decorator(facts, node_id, annotation, value.as_deref())
                && excluded_annotations
                    .iter()
                    .all(|excluded| !matching_applied_decorator(facts, node_id, excluded, None))
                && node.parent.is_some_and(|owner_id| {
                    facts.node(owner_id).kind == NormalizedKind::Class
                        && matching_applied_decorator_path(
                            analyzer,
                            file,
                            facts,
                            owner_id,
                            owner_annotation_path,
                        )
                })
        }
        RuleTrigger::MacroInvocation { name: expected } => {
            node.kind.satisfies(NormalizedKind::Call)
                && (crate::analyzer::common::language_for_file(file) != Language::Rust
                    || node.construct.as_deref() == Some("rust_macro_invocation"))
                && name.is_some_and(|actual| exact_trigger_name_matches(expected, actual))
        }
        RuleTrigger::GeneratorInvocation { name: expected } => {
            node.kind.satisfies(NormalizedKind::Call)
                && name.is_some_and(|actual| exact_trigger_name_matches(expected, actual))
        }
        RuleTrigger::ResolvedOwner { .. } | RuleTrigger::ResolvedCall { .. } => false,
    }
}

pub(crate) fn imported_trigger_name_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    expected: &str,
    actual: &str,
    site_byte: usize,
) -> bool {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    if !expected.contains('.') || actual.contains('.') {
        return false;
    }
    let Some(provider) = analyzer.import_analysis_provider_for_file(file) else {
        return false;
    };
    let local_imports = provider
        .import_info_of(token, file)
        .into_iter()
        .filter(|import| {
            !import.is_wildcard
                && import.local_name() == Some(actual)
                && import.path.as_ref().is_none_or(|path| {
                    path.lexical_scopes
                        .iter()
                        .all(|scope| scope.start_byte <= site_byte && site_byte < scope.end_byte)
                })
        })
        .collect::<Vec<_>>();
    local_imports.len() == 1
        && local_imports.iter().all(|import| {
            import
                .path
                .as_ref()
                .is_some_and(|path| path.render_segments(".") == expected)
        })
}

pub(crate) fn evaluate_rule_at_node(
    analyzer: &dyn IAnalyzer,
    rule: &GeneratorRule,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Result<Vec<GeneratorRuleMatch>, SemanticModelPredicateFailure> {
    if !rule_trigger_matches(analyzer, file, &rule.trigger, facts, node_id) {
        let message = match rule.trigger {
            RuleTrigger::ResolvedOwner { .. } | RuleTrigger::ResolvedCall { .. } => {
                "the schema-v1 overlay has no resolved-owner evidence for this site"
            }
            _ => "the normalized node kind or exact trigger name does not match",
        };
        return Err(SemanticModelPredicateFailure {
            code: "trigger.mismatch".to_owned(),
            message: message.to_owned(),
        });
    }
    rule_capture_values(analyzer, rule, facts, node_id, file, enclosing)
}

pub(crate) fn matching_applied_decorator(
    facts: &FileFacts,
    target_id: u32,
    expected: &str,
    value: Option<&str>,
) -> bool {
    applied_decorator_roots(facts, target_id)
        .into_iter()
        .any(|root_id| {
            (root_id..facts.subtree_end(root_id)).any(|candidate_id| {
                facts.node(candidate_id).kind == NormalizedKind::Decorator
                    && decorator_fact_matches(facts, candidate_id, expected)
                    && value.is_none_or(|expected_value| {
                        facts
                            .role_targets(candidate_id, Role::Arg)
                            .any(|target| target.span.text(facts.source()) == expected_value)
                    })
            })
        })
}

pub(crate) fn matching_applied_decorator_path(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    facts: &FileFacts,
    target_id: u32,
    expected: &[String],
) -> bool {
    if expected.is_empty() {
        return false;
    }
    let expected_import = expected.join(".");
    applied_decorator_roots(facts, target_id)
        .into_iter()
        .any(|root_id| {
            (root_id..facts.subtree_end(root_id)).any(|candidate_id| {
                let candidate = facts.node(candidate_id);
                if candidate.kind != NormalizedKind::Decorator {
                    return false;
                }
                let mut actual = facts
                    .role_targets(candidate_id, Role::Module)
                    .filter_map(|target| target.name)
                    .map(|name| name.text(facts.source()))
                    .collect::<Vec<_>>();
                if let Some(name) = candidate.name {
                    let terminal = name.text(facts.source());
                    actual.push(terminal);
                    actual == expected.iter().map(String::as_str).collect::<Vec<_>>()
                        || (actual.len() == 1
                            && imported_trigger_name_matches(
                                analyzer,
                                file,
                                &expected_import,
                                terminal,
                                facts.node(target_id).range.start_byte,
                            ))
                } else {
                    false
                }
            })
        })
}

pub(crate) fn applied_decorator_roots(facts: &FileFacts, target_id: u32) -> Vec<u32> {
    let target = facts.node(target_id);
    let mut roots = Vec::new();
    let mut candidate_id = target_id;
    while candidate_id > 0 {
        candidate_id -= 1;
        let candidate = facts.node(candidate_id);
        if candidate.parent != target.parent {
            continue;
        }
        if candidate.kind != NormalizedKind::Decorator {
            break;
        }
        roots.push(candidate_id);
    }
    roots
}

pub(crate) fn decorator_fact_matches(facts: &FileFacts, decorator_id: u32, expected: &str) -> bool {
    let decorator = facts.node(decorator_id);
    decorator
        .name
        .is_some_and(|name| exact_trigger_name_matches(expected, name.text(facts.source())))
        || qualified_decorator_matches(expected, decorator.span().text(facts.source()))
}

pub(crate) fn rule_capture_values(
    analyzer: &dyn IAnalyzer,
    rule: &GeneratorRule,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Result<Vec<GeneratorRuleMatch>, SemanticModelPredicateFailure> {
    let mut scalar_match = HashMap::default();
    let mut repeated = Vec::new();
    let mut grouped = HashMap::default();
    for capture in &rule.captures {
        let values = capture_values(analyzer, &capture.binding, facts, node_id, file, enclosing);
        match (capture.cardinality, values.as_slice()) {
            (crate::analyzer::semantic_model::CaptureCardinality::One, []) => {
                return Err(SemanticModelPredicateFailure {
                    code: "capture.unbound".to_owned(),
                    message: format!(
                        "required capture `{}` has no structured value",
                        capture.name
                    ),
                });
            }
            (
                crate::analyzer::semantic_model::CaptureCardinality::One
                | crate::analyzer::semantic_model::CaptureCardinality::Optional,
                [value],
            ) => {
                scalar_match.insert(capture.name.clone(), value.clone());
            }
            (crate::analyzer::semantic_model::CaptureCardinality::Optional, []) => {}
            (crate::analyzer::semantic_model::CaptureCardinality::Many, []) => {
                return Ok(Vec::new());
            }
            (crate::analyzer::semantic_model::CaptureCardinality::Many, values) => {
                repeated.push((capture.name.clone(), values.to_vec()));
            }
            (crate::analyzer::semantic_model::CaptureCardinality::Group, values) => {
                grouped.insert(capture.name.clone(), values.to_vec());
            }
            (_, _) => {
                return Err(SemanticModelPredicateFailure {
                    code: "capture.cardinality".to_owned(),
                    message: format!(
                        "capture `{}` produced more than one structured value",
                        capture.name
                    ),
                });
            }
        }
    }
    let Some((_, first_values)) = repeated.first() else {
        return Ok(vec![GeneratorRuleMatch {
            values: scalar_match,
            groups: grouped,
        }]);
    };
    let row_count = first_values.len();
    if repeated.iter().any(|(_, values)| values.len() != row_count) {
        return Err(SemanticModelPredicateFailure {
            code: "capture.repeated_length".to_owned(),
            message: "repeated captures produced different row counts".to_owned(),
        });
    }
    Ok((0..row_count)
        .map(|index| {
            let mut row = scalar_match.clone();
            for (name, values) in &repeated {
                row.insert(name.clone(), values[index].clone());
            }
            GeneratorRuleMatch {
                values: row,
                groups: grouped.clone(),
            }
        })
        .collect())
}

pub(crate) fn capture_values(
    analyzer: &dyn IAnalyzer,
    binding: &CaptureBinding,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Vec<CapturedValue> {
    let scalar = |value: Option<String>, anchor| {
        value
            .map(|value| CapturedValue { value, anchor })
            .into_iter()
            .collect()
    };
    match &binding.source {
        CaptureSource::MatchedNode => scalar(
            projected_node_value(
                analyzer,
                binding.projection,
                facts,
                node_id,
                file,
                enclosing,
            ),
            Some(span_anchor(
                facts,
                file,
                facts.node(node_id).span(),
                enclosing,
            )),
        ),
        CaptureSource::EnclosingDeclaration => {
            let Some(enclosing) = enclosing else {
                return Vec::new();
            };
            scalar(
                projected_declaration_value(analyzer, binding.projection, file, enclosing),
                Some(code_unit_anchor(analyzer, enclosing)),
            )
        }
        CaptureSource::OwningType => {
            let Some(enclosing) = enclosing else {
                return Vec::new();
            };
            let owner = if enclosing.is_class() || enclosing.is_module() {
                Some(enclosing.clone())
            } else {
                analyzer.parent_of(enclosing)
            };
            let Some(owner) = owner.filter(|unit| unit.is_class() || unit.is_module()) else {
                return Vec::new();
            };
            scalar(
                projected_declaration_value(analyzer, binding.projection, file, &owner),
                Some(code_unit_anchor(analyzer, &owner)),
            )
        }
        CaptureSource::OwnedFields
        | CaptureSource::OwnedMutableFields
        | CaptureSource::OwnedUninitializedFinalFields => {
            let Some(enclosing) = enclosing else {
                return Vec::new();
            };
            let mut fields = if enclosing.is_field() {
                vec![enclosing.clone()]
            } else {
                analyzer.get_members_in_class(enclosing)
            };
            fields.retain(CodeUnit::is_field);
            fields.retain(|field| {
                let metadata = analyzer.signature_metadata_of(field);
                !metadata.iter().any(|metadata| metadata.field_is_static())
                    && (!matches!(&binding.source, CaptureSource::OwnedMutableFields)
                        || !metadata.iter().any(|metadata| metadata.field_is_final()))
                    && (!matches!(
                        &binding.source,
                        CaptureSource::OwnedUninitializedFinalFields
                    ) || metadata.iter().any(|metadata| metadata.field_is_final())
                        && !metadata
                            .iter()
                            .any(|metadata| metadata.field_has_initializer()))
            });
            fields.sort_by_key(|field| {
                analyzer
                    .ranges(field)
                    .into_iter()
                    .map(|range| (range.start_byte, range.end_byte))
                    .min()
                    .unwrap_or((usize::MAX, usize::MAX))
            });
            fields.dedup();
            fields
                .into_iter()
                .filter_map(|field| {
                    projected_declaration_value(analyzer, binding.projection, file, &field).map(
                        |value| CapturedValue {
                            value,
                            anchor: Some(code_unit_anchor(analyzer, &field)),
                        },
                    )
                })
                .collect()
        }
        CaptureSource::Argument { index } => scalar(
            facts
                .role_targets(node_id, Role::Arg)
                .nth(*index as usize)
                .and_then(|target| {
                    projected_role_value(binding.projection, facts, target, file, enclosing)
                }),
            facts
                .role_targets(node_id, Role::Arg)
                .nth(*index as usize)
                .map(|target| role_span_anchor(facts, file, target, enclosing)),
        ),
        CaptureSource::Arguments { from } => facts
            .roles(node_id)
            .iter()
            .filter(|target| matches!(target.role, Role::Arg | Role::Kwarg))
            .skip(*from as usize)
            .filter_map(|target| {
                projected_role_value(binding.projection, facts, target, file, enclosing).map(
                    |value| CapturedValue {
                        value,
                        anchor: Some(role_span_anchor(facts, file, target, enclosing)),
                    },
                )
            })
            .collect(),
        CaptureSource::AnnotationArgument { name } => facts
            .role_targets(node_id, Role::Kwarg)
            .find(|target| {
                target
                    .keyword
                    .is_some_and(|keyword| keyword.text(facts.source()) == name)
            })
            .and_then(|target| {
                projected_role_value(binding.projection, facts, target, file, enclosing)
                    .map(|value| (target, value))
            })
            .map(|(target, value)| CapturedValue {
                value,
                anchor: Some(role_span_anchor(facts, file, target, enclosing)),
            })
            .into_iter()
            .collect(),
        CaptureSource::ResolvedOwner => Vec::new(),
    }
}

pub(crate) fn role_span_anchor(
    facts: &FileFacts,
    file: &ProjectFile,
    target: &crate::analyzer::structural::RoleTarget,
    enclosing: Option<&CodeUnit>,
) -> SemanticModelAuthoredAnchor {
    let mut anchor = span_anchor(facts, file, target.span, enclosing);
    anchor.symbol =
        projected_role_value(CaptureProjection::StableId, facts, target, file, enclosing)
            .expect("every argument role has a stable capture identity");
    anchor
}

pub(crate) fn span_anchor(
    facts: &FileFacts,
    file: &ProjectFile,
    span: crate::analyzer::structural::Span,
    enclosing: Option<&CodeUnit>,
) -> SemanticModelAuthoredAnchor {
    make_authored_anchor(
        file.rel_path(),
        enclosing
            .map(CodeUnit::fq_name)
            .unwrap_or_else(|| span.text(facts.source()).to_owned()),
        SemanticModelRange {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: facts.line_of_byte(span.start_byte),
            end_line: facts.line_of_byte(span.end_byte),
        },
    )
}

pub(crate) fn code_unit_anchor(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> SemanticModelAuthoredAnchor {
    let range = analyzer
        .ranges(unit)
        .into_iter()
        .min_by_key(|range| (range.start_line, range.start_byte));
    make_authored_anchor(
        unit.source().rel_path(),
        unit.fq_name(),
        range.map(Into::into).unwrap_or(SemanticModelRange {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            end_line: 0,
        }),
    )
}

pub(crate) fn projected_node_value(
    analyzer: &dyn IAnalyzer,
    projection: CaptureProjection,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Option<String> {
    let node = facts.node(node_id);
    let declaration = enclosing.and_then(|enclosing| {
        if enclosing.is_field() {
            return Some(enclosing.clone());
        }
        if node.kind != NormalizedKind::Declaration
            || !(enclosing.is_class() || enclosing.is_module())
        {
            return None;
        }
        let name = node.name?.text(facts.source());
        let mut fields = analyzer
            .get_members_in_class(enclosing)
            .into_iter()
            .filter(|member| member.is_field() && member.identifier() == name);
        let field = fields.next()?;
        fields.next().is_none().then_some(field)
    });
    match projection {
        CaptureProjection::Name => node
            .name
            .map(|name| name.text(facts.source()).trim_end_matches('!').to_string()),
        CaptureProjection::Text => Some(node.span().text(facts.source()).to_string()),
        CaptureProjection::Path => Some(file.rel_path().to_string_lossy().replace('\\', "/")),
        CaptureProjection::StableId => declaration.as_ref().or(enclosing).map(CodeUnit::fq_name),
        CaptureProjection::Type => declaration
            .as_ref()
            .or(enclosing)
            .and_then(|unit| projected_declaration_value(analyzer, projection, file, unit)),
    }
}

pub(crate) fn projected_declaration_value(
    analyzer: &dyn IAnalyzer,
    projection: CaptureProjection,
    file: &ProjectFile,
    declaration: &CodeUnit,
) -> Option<String> {
    Some(match projection {
        CaptureProjection::Name => declaration.identifier().to_string(),
        CaptureProjection::StableId => declaration.fq_name(),
        CaptureProjection::Type if declaration.is_class() || declaration.is_module() => {
            declaration.fq_name()
        }
        CaptureProjection::Type => analyzer
            .signature_metadata_of(declaration)
            .into_iter()
            .find_map(|metadata| metadata.return_type_text().map(str::to_owned))?,
        CaptureProjection::Path => file.rel_path().to_string_lossy().replace('\\', "/"),
        CaptureProjection::Text => return None,
    })
}

pub(crate) fn projected_role_value(
    projection: CaptureProjection,
    facts: &FileFacts,
    target: &crate::analyzer::structural::RoleTarget,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Option<String> {
    match projection {
        CaptureProjection::Name => Some(
            target
                .name
                .unwrap_or(target.span)
                .text(facts.source())
                .to_string(),
        ),
        CaptureProjection::Text => Some(target.span.text(facts.source()).to_string()),
        CaptureProjection::Path => Some(file.rel_path().to_string_lossy().replace('\\', "/")),
        CaptureProjection::StableId => Some(enclosing.map_or_else(
            || {
                format!(
                    "{}@{}:{}:{}",
                    file.rel_path().to_string_lossy().replace('\\', "/"),
                    target.span.start_byte,
                    target.span.end_byte,
                    target.name.unwrap_or(target.span).text(facts.source())
                )
            },
            |unit| {
                let name = target.name.unwrap_or(target.span).text(facts.source());
                format!("{}.{}", unit.fq_name(), name)
            },
        )),
        CaptureProjection::Type => enclosing.map(|unit| unit.fq_name()),
    }
}

pub(crate) fn emit_rule_match(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    rule: &GeneratorRule,
    captures: &GeneratorRuleMatch,
    symbols: &mut Vec<SemanticModelSymbol>,
    relations: &mut Vec<SemanticModelRelation>,
    aliases: &mut Vec<(String, String)>,
) {
    for emission in &rule.emissions {
        match emission {
            RuleEmission::Declaration {
                id,
                name,
                anchor,
                declaration,
            } => {
                let (Some(id), Some(name)) = (
                    evaluate_template(id, captures),
                    evaluate_template(name, captures),
                ) else {
                    continue;
                };
                let location = anchor
                    .as_ref()
                    .and_then(|expression| capture_anchor(expression, captures))
                    .map(SemanticModelLocation::Authored)
                    .unwrap_or_else(|| {
                        model_location(shard, "generated", &format!("{}:{id}", rule.id))
                    });
                let mut model_provenance = provenance(active, shard, &id, &location, None, false);
                model_provenance.rule_id = Some(rule.id.clone());
                let symbol = match declaration {
                    EmittedDeclaration::Type {
                        type_kind: emitted_kind,
                        is_abstract,
                        is_sealed,
                        ..
                    } => SemanticModelSymbol {
                        jvm_owner_family_enumerated: false,
                        non_overridable: None,
                        ambient_use: None,
                        id,
                        owner_id: None,
                        name: terminal_name(&name).to_string(),
                        qualified_name: name,
                        language: shard.manifest.language.clone(),
                        kind: type_kind(*emitted_kind),
                        visibility: Visibility::Public,
                        is_static: false,
                        declaration_is_abstract: *is_abstract,
                        declaration_is_sealed: *is_sealed,
                        callable_surface_complete: false,
                        signature: None,
                        structured_signature: None,
                        has_explicit_type_terms: false,
                        callable_shape: None,
                        callable_shape_evidence_complete: false,
                        callable_family_complete: false,
                        exact_return_classes: Vec::new(),
                        aliases: Vec::new(),
                        type_parameter_constraints: Vec::new(),
                        underlying_type: None,
                        value_semantics: None,
                        embedded_types: Vec::new(),
                        receiver: None,
                        implicit_operation: None,
                        explicit_operation: None,
                        extension_receiver: None,
                        extension_receiver_constraints: Vec::new(),
                        value_type: None,
                        proxied_type: None,
                        locator_path: None,
                        locator_symbol: None,
                        rust_generated_scope: None,
                        location,
                        provenance: model_provenance,
                    },
                    EmittedDeclaration::Member {
                        owner,
                        member_kind: emitted_kind,
                        signature,
                        is_static,
                        is_abstract,
                        ..
                    } => {
                        let owner = match owner {
                            Some(owner) => {
                                let Some(owner) = evaluate_template(owner, captures) else {
                                    continue;
                                };
                                Some(owner)
                            }
                            None => None,
                        };
                        let structured_signature = signature
                            .as_ref()
                            .and_then(|signature| evaluate_template_signature(signature, captures));
                        let callable_shape_evidence_complete = structured_signature
                            .as_ref()
                            .is_some_and(signature_has_complete_callable_shape);
                        SemanticModelSymbol {
                            jvm_owner_family_enumerated: false,
                            non_overridable: None,
                            ambient_use: None,
                            id,
                            owner_id: owner.clone(),
                            name: name.clone(),
                            qualified_name: owner
                                .as_ref()
                                .map(|owner| format!("{owner}.{name}"))
                                .unwrap_or_else(|| name.clone()),
                            language: shard.manifest.language.clone(),
                            kind: member_kind(*emitted_kind),
                            visibility: Visibility::Public,
                            is_static: *is_static,
                            declaration_is_abstract: *is_abstract,
                            declaration_is_sealed: false,
                            callable_surface_complete: false,
                            signature: signature.as_ref().and_then(|signature| {
                                render_template_signature(&name, signature, captures)
                            }),
                            structured_signature,
                            has_explicit_type_terms: false,
                            callable_shape: signature.as_ref().and_then(|signature| {
                                render_template_callable_shape(signature, captures)
                            }),
                            callable_shape_evidence_complete,
                            callable_family_complete: false,
                            exact_return_classes: Vec::new(),
                            aliases: Vec::new(),
                            type_parameter_constraints: Vec::new(),
                            underlying_type: None,
                            value_semantics: None,
                            embedded_types: Vec::new(),
                            receiver: None,
                            implicit_operation: None,
                            explicit_operation: None,
                            value_type: None,
                            proxied_type: None,
                            extension_receiver: None,
                            extension_receiver_constraints: Vec::new(),
                            locator_path: None,
                            locator_symbol: None,
                            rust_generated_scope: None,
                            location,
                            provenance: model_provenance,
                        }
                    }
                };
                symbols.push(symbol);
            }
            RuleEmission::Alias { from, to, .. } => {
                if let (Some(from), Some(to)) = (
                    evaluate_template(from, captures),
                    evaluate_template(to, captures),
                ) {
                    aliases.push((from, to));
                }
            }
            RuleEmission::Relation {
                id,
                relation_kind,
                from,
                to,
            } => {
                let (Some(id), Some(from), Some(to)) = (
                    evaluate_template(id, captures),
                    evaluate_template(from, captures),
                    evaluate_template(to, captures),
                ) else {
                    continue;
                };
                let location =
                    model_location(shard, "generated-relation", &format!("{}:{id}", rule.id));
                let mut model_provenance = provenance(active, shard, &id, &location, None, false);
                model_provenance.rule_id = Some(rule.id.clone());
                relations.push(SemanticModelRelation {
                    id,
                    kind: relation_kind_label(*relation_kind).to_string(),
                    from,
                    to,
                    declaration_ordinal: None,
                    provenance: model_provenance,
                });
            }
        }
    }
}

pub(crate) fn type_symbol(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record: &TypeFact,
    ambiguous: bool,
) -> SemanticModelSymbol {
    let location = location(
        analyzer,
        shard,
        &record.locator,
        &record.name,
        "type",
        &record.id,
    );
    SemanticModelSymbol {
        jvm_owner_family_enumerated: shard.independently_enumerates_jvm_owner(record),
        non_overridable: None,
        id: record.id.clone(),
        owner_id: None,
        name: terminal_name(&record.name).to_string(),
        qualified_name: record.name.clone(),
        language: shard.manifest.language.clone(),
        kind: type_kind(record.type_kind),
        visibility: record.visibility,
        is_static: false,
        declaration_is_abstract: record.is_abstract,
        declaration_is_sealed: record.is_sealed,
        callable_surface_complete: record.callable_surface_complete,
        signature: None,
        structured_signature: None,
        has_explicit_type_terms: record.has_explicit_type_terms,
        callable_shape: None,
        callable_shape_evidence_complete: false,
        callable_family_complete: false,
        exact_return_classes: Vec::new(),
        aliases: record.aliases.clone(),
        type_parameter_constraints: record.type_parameter_constraints.clone(),
        underlying_type: record.underlying_type.clone(),
        value_semantics: record.value_semantics.clone(),
        embedded_types: record.embedded_types.clone(),
        receiver: None,
        implicit_operation: None,
        explicit_operation: None,
        ambient_use: record.ambient_use,
        value_type: None,
        proxied_type: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        locator_path: Some(locator_path(&record.locator).to_owned()),
        locator_symbol: locator_symbol(&record.locator).map(str::to_owned),
        rust_generated_scope: None,
        provenance: provenance(
            active,
            shard,
            &record.id,
            &location,
            Some(&record.locator),
            ambiguous,
        ),
        location,
    }
}

pub(crate) fn member_symbol(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record: &MemberFact,
    qualified_owner: Option<&str>,
    ambiguous: bool,
) -> SemanticModelSymbol {
    let qualified_name = format!(
        "{}.{}",
        qualified_owner.unwrap_or(&record.owner),
        record.name
    );
    let location = location(
        analyzer,
        shard,
        &record.locator,
        &qualified_name,
        "member",
        &record.id,
    );
    SemanticModelSymbol {
        jvm_owner_family_enumerated: false,
        non_overridable: record.non_overridable,
        id: record.id.clone(),
        owner_id: Some(record.owner.clone()),
        name: record.name.clone(),
        qualified_name,
        language: shard.manifest.language.clone(),
        kind: member_kind(record.member_kind),
        visibility: record.visibility,
        is_static: record.is_static,
        declaration_is_abstract: record.is_abstract,
        declaration_is_sealed: false,
        callable_surface_complete: false,
        signature: record
            .signature
            .as_ref()
            .map(|signature| render_signature(&record.name, signature)),
        structured_signature: record.signature.clone(),
        has_explicit_type_terms: false,
        callable_shape: record
            .signature
            .as_ref()
            .filter(|signature| !signature.contains_unknown_types())
            .map(render_callable_shape),
        callable_shape_evidence_complete: member_callable_shape_evidence_complete(record),
        callable_family_complete: record.callable_family_complete,
        exact_return_classes: record.exact_return_classes.clone(),
        aliases: record.aliases.clone(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        value_semantics: None,
        embedded_types: Vec::new(),
        receiver: record.receiver,
        implicit_operation: record.implicit_operation.clone(),
        explicit_operation: record.explicit_operation,
        ambient_use: record.ambient_use,
        value_type: record.value_type.clone(),
        proxied_type: record.proxied_type.clone(),
        extension_receiver: record.extension_receiver.clone(),
        extension_receiver_constraints: record.extension_receiver_constraints.clone(),
        locator_path: Some(locator_path(&record.locator).to_owned()),
        locator_symbol: locator_symbol(&record.locator).map(str::to_owned),
        rust_generated_scope: None,
        provenance: provenance(
            active,
            shard,
            &record.id,
            &location,
            Some(&record.locator),
            ambiguous,
        ),
        location,
    }
}

pub(crate) fn relation(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record: &RelationFact,
    ambiguous: bool,
) -> SemanticModelRelation {
    let location = model_location(shard, "relation", &record.id);
    SemanticModelRelation {
        id: record.id.clone(),
        kind: relation_kind_label(record.relation_kind).to_string(),
        from: record.from.clone(),
        to: record.to.clone(),
        declaration_ordinal: None,
        provenance: provenance(active, shard, &record.id, &location, None, ambiguous),
    }
}

pub(crate) fn hierarchy_relation(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    owner_id: &str,
    hierarchy: &HierarchyFact,
    ambiguous: bool,
) -> SemanticModelRelation {
    // Schema validation rejects unknown hierarchy targets, which must never
    // be converted into a rendered edge identity.
    debug_assert!(!hierarchy.target.contains_unknown());
    let target = match &hierarchy.target {
        TypeRef::Declared { id, .. } => id.clone(),
        TypeRef::Named { name, .. } => name.clone(),
        other => render_type_ref(other),
    };
    let kind = hierarchy_kind_label(hierarchy.hierarchy_kind).to_string();
    let id = format!("hierarchy:{owner_id}:{kind}:{target}");
    let location = model_location(shard, "hierarchy", &id);
    SemanticModelRelation {
        id: id.clone(),
        kind,
        from: owner_id.to_string(),
        to: target,
        declaration_ordinal: hierarchy.declaration_ordinal,
        provenance: provenance(active, shard, &id, &location, None, ambiguous),
    }
}

pub(crate) fn location(
    analyzer: &dyn IAnalyzer,
    shard: &ActiveSemanticModelShard,
    locator: &Locator,
    fallback_symbol: &str,
    record_kind: &str,
    record_id: &str,
) -> SemanticModelLocation {
    authored_anchor(
        analyzer,
        &shard.manifest.carried_sources,
        locator,
        fallback_symbol,
    )
    .map(SemanticModelLocation::Authored)
    .unwrap_or_else(|| model_location(shard, record_kind, record_id))
}

#[doc(hidden)]
pub fn authored_anchor(
    analyzer: &dyn IAnalyzer,
    carried_sources: &[String],
    locator: &Locator,
    fallback_symbol: &str,
) -> Option<SemanticModelAuthoredAnchor> {
    let Locator::Source {
        path: locator_path,
        symbol,
    } = locator
    else {
        return None;
    };
    let symbol = symbol.as_deref().unwrap_or(fallback_symbol);
    let path = Path::new(locator_path);
    let file = if path.is_absolute() {
        analyzer.project().file_by_abs_path(path)
    } else {
        analyzer.project().file_by_rel_path(path)
    };
    if let Some(file) = file
        && let Some(unit) = analyzer.definitions(symbol).find(|unit| {
            unit.source() == &file && (unit.fq_name() == symbol || unit.identifier() == symbol)
        })
        && let Some(range) = analyzer
            .ranges(&unit)
            .into_iter()
            .min_by_key(|range| (range.start_line, range.start_byte))
    {
        return Some(SemanticModelAuthoredAnchor {
            path: file.rel_path().to_string_lossy().replace('\\', "/"),
            symbol: unit.fq_name(),
            range: range.into(),
        });
    }
    // The pack carries this source (its producer parsed the named entry), so
    // the verbatim entry path is a legitimate authored target even though it is
    // not a workspace file. A path the pack merely names without carrying it
    // has no openable source anywhere, so the caller falls back to the durable
    // bifrost-model URI (#2613). Carried sources are validated to be strictly
    // ascending, which makes the binary search sound.
    if carried_sources
        .binary_search_by(|carried| carried.as_str().cmp(locator_path))
        .is_ok()
    {
        return Some(SemanticModelAuthoredAnchor {
            path: path.to_string_lossy().replace('\\', "/"),
            symbol: symbol.to_owned(),
            range: SemanticModelRange {
                start_byte: 0,
                end_byte: 0,
                start_line: 0,
                end_line: 0,
            },
        });
    }
    None
}

/// Preserve the declaration's own origin and activation for runtime ancestry.
#[doc(hidden)]
pub fn activated_type_provenance<E>(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record: &TypeFact,
    ambiguous: bool,
    visit: &mut impl FnMut() -> Result<(), E>,
) -> Result<SemanticModelProvenance, E> {
    let location = model_location(shard, "type", &record.id);
    provenance_with_visits(
        active,
        shard,
        &record.id,
        &location,
        Some(&record.locator),
        ambiguous,
        visit,
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests {
    #[cfg(test)]
    use crate::analyzer::semantic_model::overlay::go_extra_support_0::*;

    #[cfg(test)]
    use crate::analyzer::semantic_model::SemanticModelCallableMatch;

    #[cfg(test)]
    fn callable_key(parameter_count: u32) -> SemanticModelCallableKey<'static> {
        SemanticModelCallableKey::new("java", "pkg.Owner", "run", true, parameter_count)
    }
    #[cfg(test)]
    fn lookup(
        overlay: &SemanticModelOverlay,
        parameter_count: u32,
    ) -> SemanticModelCallableMatch<'_> {
        overlay.callable_for_target(callable_key(parameter_count))
    }

    #[cfg(test)]
    pub(super) use super::test_support::*;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::CollectionFlowContract;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::Completeness;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::EmbeddedTypeFact;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::HierarchyFact;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::HierarchyKind;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::ImplicitOperation;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::java_hierarchy::JavaHierarchyIncomplete;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelCallApplication;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelCallableDisposition;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelCallableIncompleteReason;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelCallableKey;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelCompleteness;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelEdgeDefect;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelMemberTargetDisposition;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOriginKind;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlayDisposition;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOwnerSurface;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSurfaceGap;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbol;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbolKind;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelUnresolvedEdge;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::Signature;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::augment_go_overlay_surface;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::semantic_model_callable_family_id;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::Language;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::semantic_model::model::ParameterPassingMode;

    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    #[cfg(test)]
    fn collection_flow_contract(
        callable: &str,
        completeness: SemanticModelCompleteness,
        ambiguous: bool,
    ) -> CollectionFlowContract {
        let mut provenance = provenance(completeness);
        provenance.ambiguous = ambiguous;
        CollectionFlowContract {
            provenance,
            callable: callable.to_owned(),
            payload: brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCollectionFlowPayload {
                kind: brokk_bifrost_analysis::analyzer::semantic_model::csmi::CsmiCollectionFlowKind::CollectionFlow,
                callable: callable.to_owned(),
                receiver_substitution: None,
                roots: Vec::new(),
                transfers: Vec::new(),
                invocations: Vec::new(),
            },
            coverage: Some(Completeness::Complete),
        }
    }

    #[cfg(test)]
    #[test]
    fn collection_flow_lookup_preserves_typed_contract_and_conflicts() {
        let contract = collection_flow_contract(
            "callable.normalize",
            SemanticModelCompleteness::Complete,
            false,
        );
        let mut overlay = overlay(Vec::new(), Vec::new());
        overlay.collection_flows.push(contract);
        overlay
            .collection_flows_by_callable
            .insert("callable.normalize".to_owned(), vec![0]);

        let unique = overlay.collection_flows_for("callable.normalize");
        assert_eq!(unique.disposition, SemanticModelOverlayDisposition::Unique);
        assert_eq!(unique.records.len(), 1);
        assert!(unique.records[0].is_complete());
        assert_eq!(unique.records[0].payload.callable, "callable.normalize");
        assert_eq!(
            overlay.collection_flows_for("missing").disposition,
            SemanticModelOverlayDisposition::Empty
        );

        overlay.collection_flows.push(collection_flow_contract(
            "callable.normalize",
            SemanticModelCompleteness::Complete,
            false,
        ));
        overlay
            .collection_flows_by_callable
            .insert("callable.normalize".to_owned(), vec![0, 1]);
        let conflict = overlay.collection_flows_for("callable.normalize");
        assert_eq!(
            conflict.disposition,
            SemanticModelOverlayDisposition::Conflict
        );
        assert_eq!(conflict.records.len(), 2);
    }

    #[cfg(test)]
    #[test]
    fn type_flow_external_class_identity_filters_before_uniqueness_and_keeps_canonical_identity() {
        use brokk_bifrost_analysis::analyzer::semantic::type_flow::ExternalClassCache;

        use brokk_bifrost_analysis::analyzer::semantic::type_flow::external_class_identity;

        let mut good = class("builtins.str", "python");
        good.aliases.push("StringAlias".to_string());
        let good_id = good.id.clone();
        let mut cache = ExternalClassCache::default();
        let good_overlay = overlay(vec![good], Vec::new());
        let identity = external_class_identity(
            Some(&good_overlay),
            Language::Python,
            "StringAlias",
            Some(&good_id),
            &mut cache,
        )
        .expect("an exact eligible class resolves");
        assert_eq!(identity.qualified_name(), "builtins.str");

        let mut owned = class("builtins.str", "python");
        owned.owner_id = Some("owner".to_string());
        let mut ambiguous = class("builtins.str", "python");
        ambiguous.provenance.ambiguous = true;
        let foreign = class("builtins.str", "ruby");
        for rejected in [owned, ambiguous, foreign] {
            let overlay = overlay(vec![rejected], Vec::new());
            assert!(
                external_class_identity(
                    Some(&overlay),
                    Language::Python,
                    "builtins.str",
                    None,
                    &mut ExternalClassCache::default(),
                )
                .is_none()
            );
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#4619: a colliding class alias hid the canonical open() return class")]
    fn type_flow_external_class_identity_prefers_exact_names_and_resolves_unique_aliases() {
        use brokk_bifrost_analysis::analyzer::semantic::type_flow::ExternalClassCache;

        use brokk_bifrost_analysis::analyzer::semantic::type_flow::external_class_identity;

        let mut alias = class("_io.TextIOWrapper", "python");
        alias.aliases.push("io.TextIOWrapper".to_string());
        let canonical = class("io.TextIOWrapper", "python");
        let model = overlay(vec![alias, canonical], Vec::new());
        let exact = external_class_identity(
            Some(&model),
            Language::Python,
            "io.TextIOWrapper",
            None,
            &mut ExternalClassCache::default(),
        )
        .expect("a canonical class name wins over another class's alias");
        assert_eq!(exact.qualified_name(), "io.TextIOWrapper");

        let mut lock = class("_thread.LockType", "python");
        lock.aliases.push("threading.Lock".to_string());
        let model = overlay(vec![lock], Vec::new());
        let alias = external_class_identity(
            Some(&model),
            Language::Python,
            "threading.Lock",
            None,
            &mut ExternalClassCache::default(),
        )
        .expect("a unique class record resolves through its published alias");
        assert_eq!(alias.qualified_name(), "_thread.LockType");
    }

    #[cfg(test)]
    fn named<'a>(
        overlay: &'a SemanticModelOverlay,
        qualified_name: &str,
    ) -> &'a SemanticModelSymbol {
        overlay
            .symbols_named(qualified_name)
            .records
            .into_iter()
            .find(|symbol| symbol.qualified_name == qualified_name)
            .unwrap_or_else(|| panic!("`{qualified_name}` is published"))
    }

    #[cfg(test)]
    fn closure_names<'a>(surface: &'a SemanticModelOwnerSurface<'a>) -> Vec<&'a str> {
        surface
            .closure
            .iter()
            .map(|symbol| symbol.qualified_name.as_str())
            .collect()
    }

    #[cfg(test)]
    fn global_value(
        owner: &SemanticModelSymbol,
        id: &str,
        name: &str,
        return_type: &str,
    ) -> SemanticModelSymbol {
        let mut value = method(
            owner,
            id,
            name,
            Some(Signature {
                type_parameters: Vec::new(),
                parameters: Vec::new(),
                returns: Some(TypeRef::Named {
                    name: return_type.to_string(),
                    arguments: Vec::new(),
                    nullable: false,
                }),
            }),
        );
        value.kind = SemanticModelSymbolKind::Constant;
        value.is_static = true;
        value.callable_shape = None;
        value
    }

    #[cfg(test)]
    #[test]
    fn callable_lookup_ignores_an_unrelated_same_named_owner() {
        let mut header = class("sqlite3", "cpp");
        header.id = "module.sqlite3".to_string();
        header.kind = SemanticModelSymbolKind::Module;
        let typedef = class("sqlite3", "cpp");
        let mut function = method(
            &header,
            "member.sqlite3.sqlite3_exec",
            "sqlite3_exec",
            Some(signature(&[Some("sql")], false)),
        );
        function.kind = SemanticModelSymbolKind::Function;
        function.is_static = true;
        function.receiver = None;
        let overlay = overlay(vec![header, typedef, function], Vec::new());
        let key = SemanticModelCallableKey::new("cpp", "sqlite3", "sqlite3_exec", false, 1);

        let result =
            overlay.callable_for_application(key, &SemanticModelCallApplication::positional(1));

        assert_eq!(result.disposition, SemanticModelCallableDisposition::Unique);
        assert_eq!(result.records.len(), 1);
        assert_eq!(
            overlay.callable_family_id_for_target(key),
            Some(result.records[0].id.clone())
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3312: same-arity Java overloads selected by argument layout")]
    fn external_callable_lookup_keeps_same_arity_overloads_layout_compatible() {
        let mut owner = class("pkg.Owner", "java");
        owner.provenance.completeness = SemanticModelCompleteness::Partial;
        let mut first = method(
            &owner,
            "member.run.first",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        first.provenance.completeness = SemanticModelCompleteness::Partial;
        first.callable_family_complete = true;
        let mut second = method(
            &owner,
            "member.run.second",
            "run",
            Some(signature(&[Some("other")], false)),
        );
        second.provenance.completeness = SemanticModelCompleteness::Partial;
        second.callable_family_complete = true;
        let overlay = overlay(vec![owner, first, second], Vec::new());

        let result = lookup(&overlay, 1);

        assert_eq!(
            result.disposition,
            SemanticModelCallableDisposition::CompatibleLayout
        );
        assert_eq!(result.records.len(), 2);
        assert!(result.unique().is_none());
    }

    #[cfg(test)]
    #[test]
    fn external_callable_lookup_keeps_an_unmodeled_sibling_signature_incomplete() {
        let owner = class("pkg.Owner", "java");
        let known = method(
            &owner,
            "member.run.known",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        let missing = method(&owner, "member.run.missing", "run", None);
        let overlay = overlay(vec![owner, known, missing], Vec::new());

        let result = lookup(&overlay, 1);

        assert_eq!(
            result.disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::MissingSignature
            )
        );
        assert!(result.unique().is_none());
    }

    #[cfg(test)]
    #[test]
    fn external_callable_application_honors_defaults_names_and_passing_modes() {
        let owner = class("pkg.Owner", "java");
        let mut modeled = signature(
            &[Some("args"), Some("shell"), Some("capture_output")],
            false,
        );
        modeled.parameters[0].passing_mode = ParameterPassingMode::PositionalOnly;
        modeled.parameters[1].optional = true;
        modeled.parameters[1].passing_mode = ParameterPassingMode::NamedOnly;
        modeled.parameters[2].optional = true;
        modeled.parameters[2].passing_mode = ParameterPassingMode::NamedOnly;
        let member = method(&owner, "member.run", "run", Some(modeled));
        let overlay = overlay(vec![owner, member], Vec::new());

        let exact = SemanticModelCallApplication::structured(1, vec!["shell".to_owned()], false);
        assert_eq!(
            overlay
                .callable_for_application(callable_key(2), &exact)
                .disposition,
            SemanticModelCallableDisposition::Unique
        );

        let positional_keyword_only =
            SemanticModelCallApplication::structured(2, Vec::new(), false);
        assert_eq!(
            overlay
                .callable_for_application(callable_key(2), &positional_keyword_only)
                .disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::ApplicationMismatch
            )
        );

        let named_positional_only =
            SemanticModelCallApplication::structured(0, vec!["args".to_owned()], false);
        assert_eq!(
            overlay
                .callable_for_application(callable_key(1), &named_positional_only)
                .disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::ApplicationMismatch
            )
        );
    }

    #[cfg(test)]
    #[test]
    fn external_callable_application_rejects_duplicate_binding_before_keyword_variadic() {
        let owner = class("pkg.Owner", "java");
        let mut modeled = signature(&[Some("value"), Some("kwargs")], false);
        modeled.parameters[1].variadic = true;
        modeled.parameters[1].passing_mode = ParameterPassingMode::NamedOnly;
        let member = method(&owner, "member.run", "run", Some(modeled));
        let overlay = overlay(vec![owner, member], Vec::new());
        let duplicate =
            SemanticModelCallApplication::structured(1, vec!["value".to_owned()], false);

        assert_eq!(
            overlay
                .callable_for_application(callable_key(2), &duplicate)
                .disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::ApplicationMismatch
            )
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "#4709: a Kotlin vararg before named-only formals was rejected as a non-final keyword collector"
    )]
    fn external_callable_application_distinguishes_named_vararg_slot_from_keyword_rest() {
        let owner = class("pkg.Owner", "java");
        let mut modeled = signature(&[Some("values"), Some("tail")], false);
        modeled.parameters[0].variadic = true;
        modeled.parameters[0].passing_mode = ParameterPassingMode::PositionalOrNamed;
        modeled.parameters[1].optional = true;
        modeled.parameters[1].passing_mode = ParameterPassingMode::NamedOnly;
        let member = method(&owner, "member.run", "run", Some(modeled));
        let named_overlay = overlay(vec![owner, member], Vec::new());

        let declared_name =
            SemanticModelCallApplication::structured(0, vec!["values".to_owned()], false);
        assert_eq!(
            named_overlay
                .callable_for_application(callable_key(2), &declared_name)
                .disposition,
            SemanticModelCallableDisposition::Unique
        );

        let unknown_name =
            SemanticModelCallApplication::structured(0, vec!["other".to_owned()], false);
        assert_eq!(
            named_overlay
                .callable_for_application(callable_key(2), &unknown_name)
                .disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::ApplicationMismatch
            )
        );

        let duplicate_known_slot =
            SemanticModelCallApplication::structured(1, vec!["values".to_owned()], false);
        assert_eq!(
            named_overlay
                .callable_for_application(callable_key(2), &duplicate_known_slot)
                .disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::ApplicationMismatch
            )
        );

        let mut keyword_rest = signature(&[Some("kwargs")], false);
        keyword_rest.parameters[0].variadic = true;
        keyword_rest.parameters[0].passing_mode = ParameterPassingMode::NamedOnly;
        let keyword_owner = class("pkg.Owner", "java");
        let keyword_member = method(
            &keyword_owner,
            "member.run.kwargs",
            "run",
            Some(keyword_rest),
        );
        let keyword_overlay = overlay(vec![keyword_owner, keyword_member], Vec::new());
        let arbitrary_name =
            SemanticModelCallApplication::structured(0, vec!["other".to_owned()], false);
        assert_eq!(
            keyword_overlay
                .callable_for_application(callable_key(1), &arbitrary_name)
                .disposition,
            SemanticModelCallableDisposition::Unique
        );
    }

    #[cfg(test)]
    #[test]
    fn external_callable_application_keeps_shared_layout_overloads_distinct() {
        let owner = class("pkg.Owner", "java");
        let first = method(
            &owner,
            "member.run.first",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        let second = method(
            &owner,
            "member.run.second",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        let overlay = overlay(vec![owner, first, second], Vec::new());
        let application = SemanticModelCallApplication::positional(1);

        let result = overlay.callable_for_application(callable_key(1), &application);

        assert_eq!(
            result.disposition,
            SemanticModelCallableDisposition::CompatibleLayout
        );
        assert_eq!(result.records.len(), 2);
        assert!(result.unique().is_none(), "no overload was selected");
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3312: same-layout overloads with different formal names were conflated")]
    fn external_callable_application_keeps_different_formal_names_in_one_layout() {
        let owner = class("pkg.Owner", "java");
        let first = method(
            &owner,
            "member.run.first",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        let second = method(
            &owner,
            "member.run.second",
            "run",
            Some(signature(&[Some("values")], false)),
        );
        let overlay = overlay(vec![owner, first, second], Vec::new());

        let result = overlay.callable_for_application(
            callable_key(1),
            &SemanticModelCallApplication::positional(1),
        );

        assert_eq!(
            result.disposition,
            SemanticModelCallableDisposition::CompatibleLayout
        );
        assert_eq!(result.records.len(), 2);
    }

    #[cfg(test)]
    #[test]
    fn callable_family_identity_is_stable_when_application_selects_one_overload() {
        let owner = class("pkg.Owner", "java");
        let first = method(
            &owner,
            "member.run.first",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        let mut wider = signature(&[Some("value"), Some("mode")], false);
        wider.parameters[1].optional = true;
        let second = method(&owner, "member.run.second", "run", Some(wider));
        let overlay = overlay(vec![owner, first, second], Vec::new());
        let key = callable_key(1);

        let selected = overlay
            .callable_for_application(key, &SemanticModelCallApplication::positional(1))
            .unique()
            .expect("the exact-arity preference selects one overload");
        let family_id = overlay
            .callable_family_id_for_target(key)
            .expect("the complete overload family has one identity");

        assert_eq!(selected.id, "member.run.first");
        assert_ne!(family_id, selected.id);
        assert_eq!(
            family_id,
            semantic_model_callable_family_id(
                &overlay
                    .symbols_named("pkg.Owner.run")
                    .records
                    .into_iter()
                    .filter(|record| record.owner_id.is_some())
                    .collect::<Vec<_>>()
            )
            .expect("the name index exposes the same structured family")
        );
    }

    #[cfg(test)]
    #[test]
    fn generated_c_variadic_function_uses_qualified_family_identity() {
        let mut owner = class("fcntl", "cpp");
        owner.kind = SemanticModelSymbolKind::Module;
        let mut member = method(
            &owner,
            "member.content-derived-digest",
            "open",
            Some(signature(
                &[Some("path"), Some("flags"), Some("args")],
                true,
            )),
        );
        member.kind = SemanticModelSymbolKind::Function;
        member.is_static = true;
        member.provenance.origin = SemanticModelOriginKind::ExactGeneratedOutput;
        member.provenance.completeness = SemanticModelCompleteness::Partial;
        member.provenance.activation.matched_evidence.language = "cpp".to_owned();

        let overlay = overlay(vec![owner, member], Vec::new());
        let records = overlay
            .symbols_named("fcntl.open")
            .records
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        assert!(!records[0].callable_family_complete);
        assert_eq!(records[0].id, "member.content-derived-digest");
        assert_eq!(
            semantic_model_callable_family_id(&records),
            Some("fcntl.open".to_owned())
        );
        assert_eq!(
            overlay.callable_family_id_for_symbol(records[0]),
            Some("fcntl.open".to_owned())
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("ae5ec7304945: callable owner filtering hid partial sibling coverage")]
    fn external_callable_lookup_uses_scoped_completeness_without_promoting_provenance() {
        let mut owner = class("pkg.Owner", "java");
        owner.provenance.completeness = SemanticModelCompleteness::Partial;
        let mut claimed = method(
            &owner,
            "member.run.claimed",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        claimed.provenance.completeness = SemanticModelCompleteness::Partial;
        claimed.callable_family_complete = true;

        let claimed_overlay = overlay(vec![owner.clone(), claimed.clone()], Vec::new());
        let claimed_result = lookup(&claimed_overlay, 1);
        assert_eq!(
            claimed_result.disposition,
            SemanticModelCallableDisposition::Unique
        );
        let selected = claimed_result.unique().expect("one claimed family");
        assert!(selected.callable_family_complete);
        assert_eq!(
            selected.provenance.completeness,
            SemanticModelCompleteness::Partial,
            "the family claim must not promote pack provenance"
        );
        assert_eq!(
            claimed_overlay
                .callable_for_application(
                    SemanticModelCallableKey::new("java", "pkg.Owner", "unmodeled", true, 1),
                    &SemanticModelCallApplication::positional(1),
                )
                .disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::PartialModel
            ),
            "a scoped callable claim does not close an unmodeled sibling name"
        );

        claimed.callable_family_complete = false;
        let unclaimed_overlay = overlay(vec![owner, claimed], Vec::new());
        let unclaimed_result = lookup(&unclaimed_overlay, 1);
        assert_eq!(
            unclaimed_result.disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::PartialModel
            )
        );
    }

    #[cfg(test)]
    #[test]
    fn external_callable_lookup_reports_partial_and_missing_formals() {
        let owner = class("pkg.Owner", "java");
        let mut partial = method(
            &owner,
            "member.run.partial",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        partial.provenance.completeness = SemanticModelCompleteness::Partial;
        let partial_overlay = overlay(vec![owner.clone(), partial], Vec::new());
        let result = lookup(&partial_overlay, 1);
        assert_eq!(
            result.disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::PartialModel
            )
        );

        let owner = class("pkg.Owner", "java");
        let missing = method(
            &owner,
            "member.run.missing",
            "run",
            Some(signature(&[None], false)),
        );
        let missing_overlay = overlay(vec![owner, missing], Vec::new());
        let result = lookup(&missing_overlay, 1);
        assert_eq!(
            result.disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::MissingFormalName { ordinal: 0 }
            )
        );

        let owner = class("pkg.Owner", "java");
        let mut positional_signature = signature(&[None], false);
        positional_signature.parameters[0].passing_mode = ParameterPassingMode::PositionalOnly;
        let positional = method(
            &owner,
            "member.run.positional",
            "run",
            Some(positional_signature),
        );
        let positional_overlay = overlay(vec![owner, positional], Vec::new());
        assert_eq!(
            lookup(&positional_overlay, 1).disposition,
            SemanticModelCallableDisposition::Unique
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#2482: exact declared arity lost to a variadic fallback")]
    fn external_callable_lookup_prefers_declared_arity_over_variadic_fallback() {
        let owner = class("pkg.Owner", "java");
        let variadic = method(
            &owner,
            "member.run.variadic",
            "run",
            Some(signature(&[Some("values")], true)),
        );
        let exact = method(
            &owner,
            "member.run.exact",
            "run",
            Some(signature(
                &[Some("locale"), Some("format"), Some("values")],
                true,
            )),
        );
        let overlay = overlay(vec![owner, variadic, exact], Vec::new());

        let result = lookup(&overlay, 3);

        assert_eq!(result.disposition, SemanticModelCallableDisposition::Unique);
        assert_eq!(result.unique().unwrap().id, "member.run.exact");
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#2741: incomplete TypeScript stdlib inventory produced a false member proof")]
    fn typescript_global_value_follows_declared_constructor_to_exact_member() {
        let global = class("global.es5", "typescript");
        let constructor = class("ArrayConstructor", "typescript");
        let value = global_value(
            &global,
            "typescript-global-array",
            "Array",
            "ArrayConstructor",
        );
        let member = method(&constructor, "typescript-array-is-array", "isArray", None);
        let resolved_overlay = overlay(
            vec![
                global.clone(),
                constructor.clone(),
                value.clone(),
                member.clone(),
            ],
            Vec::new(),
        );

        assert_eq!(
            resolved_overlay
                .typescript_global_member_target("Array", "isArray")
                .map(|symbol| symbol.id.as_str()),
            Some("typescript-array-is-array")
        );
        assert!(
            resolved_overlay
                .typescript_global_member_target("Array", "missing")
                .is_none()
        );

        let mut ambiguous_member = member.clone();
        ambiguous_member.id = "typescript-array-is-array-duplicate".to_string();
        let ambiguous_overlay = overlay(
            vec![
                global.clone(),
                constructor.clone(),
                value.clone(),
                member.clone(),
                ambiguous_member,
            ],
            Vec::new(),
        );
        assert!(
            ambiguous_overlay
                .typescript_global_member_target("Array", "isArray")
                .is_none(),
            "competing member records must not produce an exact target"
        );

        let mut partial_member = method(
            &constructor,
            "typescript-array-is-array-partial",
            "isArray",
            None,
        );
        partial_member.provenance.completeness = SemanticModelCompleteness::Partial;
        let partial_overlay = overlay(vec![global, constructor, value, partial_member], Vec::new());
        assert!(
            partial_overlay
                .typescript_global_member_target("Array", "isArray")
                .is_none(),
            "a partial member record must not produce an exact target"
        );
    }

    #[cfg(test)]
    #[test]
    fn java_functional_return_requires_positive_inventory_and_an_agreeing_method() {
        let mut object = class("java.lang.Object", "java");
        object.callable_surface_complete = true;
        object.provenance.completeness = SemanticModelCompleteness::Partial;
        let mut action = class("fixture.Action", "java");
        action.kind = SemanticModelSymbolKind::Interface;
        action.callable_surface_complete = true;
        action.provenance.completeness = SemanticModelCompleteness::Partial;
        let void_signature = Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: None,
        };
        let value_signature = Signature {
            returns: Some(TypeRef::Named {
                name: "int".to_owned(),
                arguments: Vec::new(),
                nullable: false,
            }),
            ..void_signature.clone()
        };
        let hash = method(
            &object,
            "object.hash",
            "hashCode",
            Some(value_signature.clone()),
        );
        let mut declared_hash = method(
            &action,
            "action.hash",
            "hashCode",
            Some(value_signature.clone()),
        );
        declared_hash.declaration_is_abstract = true;
        let mut run = method(&action, "action.run", "run", Some(void_signature));
        run.declaration_is_abstract = true;
        let mut factory = method(
            &action,
            "action.factory",
            "factory",
            Some(value_signature.clone()),
        );
        factory.is_static = true;
        let default = method(
            &action,
            "action.size",
            "size",
            Some(value_signature.clone()),
        );
        for returns in [None, value_signature.returns.clone()] {
            run.structured_signature.as_mut().unwrap().returns = returns.clone();
            let model = overlay(
                vec![
                    object.clone(),
                    action.clone(),
                    hash.clone(),
                    declared_hash.clone(),
                    run.clone(),
                    factory.clone(),
                    default.clone(),
                ],
                Vec::new(),
            );
            let mut work = 1000;
            let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
            assert_eq!(
                model
                    .java_functional_method(
                        named(&model, "fixture.Action"),
                        named(&model, "java.lang.Object"),
                        &mut work,
                        &cancellation
                    )
                    .map(|method| method
                        .structured_signature
                        .as_ref()
                        .unwrap()
                        .returns
                        .is_some()),
                Some(returns.is_some())
            );
            assert!(work < 1000);
            assert!(
                model
                    .java_functional_method(
                        named(&model, "fixture.Action"),
                        named(&model, "java.lang.Object"),
                        &mut 0,
                        &cancellation
                    )
                    .is_none()
            );
        }
        action.callable_surface_complete = false;
        let model = overlay(
            vec![object.clone(), action.clone(), hash.clone(), run.clone()],
            Vec::new(),
        );
        assert!(
            model
                .java_functional_method(
                    named(&model, "fixture.Action"),
                    named(&model, "java.lang.Object"),
                    &mut 1000,
                    &brokk_bifrost_core::cancellation::CancellationToken::default()
                )
                .is_none()
        );
        action.callable_surface_complete = true;
        action.declaration_is_sealed = true;
        let model = overlay(vec![object, action, hash, run], Vec::new());
        assert!(
            model
                .java_functional_method(
                    named(&model, "fixture.Action"),
                    named(&model, "java.lang.Object"),
                    &mut 1000,
                    &brokk_bifrost_core::cancellation::CancellationToken::default()
                )
                .is_none()
        );
    }

    #[cfg(test)]
    #[test]
    fn java_functional_return_respects_inherited_default_overrides() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            brokk_bifrost_core::analyzer::Language::Java,
        ]);
        let mut object = class("java.lang.Object", "java");
        object.callable_surface_complete = true;
        let mut parent = class("fixture.Parent", "java");
        parent.kind = SemanticModelSymbolKind::Interface;
        parent.callable_surface_complete = true;
        let mut child = class("fixture.Child", "java");
        child.kind = SemanticModelSymbolKind::Interface;
        child.callable_surface_complete = true;
        let signature = Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: None,
        };
        let mut inherited = method(&parent, "parent.run", "run", Some(signature.clone()));
        inherited.declaration_is_abstract = true;
        let default = method(&child, "child.run", "run", Some(signature.clone()));
        let mut own = method(
            &child,
            "child.get",
            "get",
            Some(Signature {
                returns: Some(TypeRef::Named {
                    name: "int".to_owned(),
                    arguments: Vec::new(),
                    nullable: false,
                }),
                ..signature
            }),
        );
        own.declaration_is_abstract = true;
        let edge = extends(&child, &parent.qualified_name);
        let model = overlay(
            vec![
                object.clone(),
                parent,
                child.clone(),
                inherited,
                default,
                own,
            ],
            vec![edge],
        );
        assert_eq!(
            model
                .java_functional_method(
                    named(&model, "fixture.Child"),
                    named(&model, "java.lang.Object"),
                    &mut 1000,
                    &brokk_bifrost_core::cancellation::CancellationToken::default()
                )
                .map(|method| method
                    .structured_signature
                    .as_ref()
                    .unwrap()
                    .returns
                    .is_some()),
            Some(true)
        );
        let missing = extends(&child, "fixture.Missing");
        let model = overlay(vec![object, child], vec![missing]);
        assert!(
            model
                .java_functional_method(
                    named(&model, "fixture.Child"),
                    named(&model, "java.lang.Object"),
                    &mut 1000,
                    &brokk_bifrost_core::cancellation::CancellationToken::default()
                )
                .is_none()
        );
    }

    #[cfg(test)]
    #[test]
    fn java_argument_family_requires_complete_inherited_inventory() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            brokk_bifrost_core::analyzer::Language::Java,
        ]);
        let mut parent = class("fixture.Parent", "java");
        parent.kind = SemanticModelSymbolKind::Interface;
        parent.callable_surface_complete = true;
        let mut child = class("fixture.Child", "java");
        child.kind = SemanticModelSymbolKind::Interface;
        child.callable_surface_complete = true;
        let signature = Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: None,
        };
        let inherited = method(
            &parent,
            "parent.consume",
            "consume",
            Some(signature.clone()),
        );
        let overload = method(&child, "child.consume", "consume", Some(signature));
        let edge = extends(&child, &parent.qualified_name);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let model = overlay(
            vec![parent.clone(), child.clone(), inherited.clone()],
            vec![edge.clone()],
        );
        assert_eq!(
            model
                .java_single_instance_method(
                    named(&model, "fixture.Child"),
                    "consume",
                    &mut 1000,
                    &cancellation
                )
                .map(|method| method.id.as_str()),
            Some("parent.consume")
        );
        let model = overlay(
            vec![parent.clone(), child.clone(), inherited.clone(), overload],
            vec![edge.clone()],
        );
        assert!(
            model
                .java_single_instance_method(
                    named(&model, "fixture.Child"),
                    "consume",
                    &mut 1000,
                    &cancellation
                )
                .is_none()
        );
        parent.callable_surface_complete = false;
        let model = overlay(vec![parent, child, inherited], vec![edge]);
        assert!(
            model
                .java_single_instance_method(
                    named(&model, "fixture.Child"),
                    "consume",
                    &mut 1000,
                    &cancellation
                )
                .is_none()
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#1789: unpublished ancestor edges were omitted from absence proofs")]
    fn a_direct_edge_to_an_unpublished_target_is_reported_rather_than_dropped() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Php,
        ]);
        let child = class("pkg.Child", "php");
        let edge = extends(&child, "vendor.Base");
        let overlay = overlay(vec![child], vec![edge]);

        let ancestry = overlay.ancestors_of(named(&overlay, "pkg.Child"));

        assert!(ancestry.records.is_empty(), "{ancestry:#?}");
        assert_eq!(
            vec![SemanticModelUnresolvedEdge {
                from: "pkg.Child".to_string(),
                to: "vendor.Base".to_string(),
                defect: SemanticModelEdgeDefect::Unpublished,
            }],
            ancestry.defects,
            "an unpublished base must be distinguishable from no base"
        );
    }

    #[cfg(test)]
    #[test]
    fn go_embedded_type_gaps_make_the_owner_surface_partial_at_every_depth() {
        let embed = |owner: &mut SemanticModelSymbol, target: TypeRef| {
            owner.embedded_types.push(EmbeddedTypeFact {
                target,
                pointer: false,
            });
        };
        let declared = |id: &str| TypeRef::Declared {
            id: id.to_owned(),
            arguments: Vec::new(),
            nullable: false,
        };
        let owner_is_partial = |mut symbols: Vec<SemanticModelSymbol>, owner_id: &str| {
            let mut relations = Vec::new();
            augment_go_overlay_surface(
                &mut symbols,
                &mut relations,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .expect("bounded Go surface augmentation succeeds");
            assert_eq!(
                symbols
                    .iter()
                    .find(|symbol| symbol.id == owner_id)
                    .unwrap()
                    .provenance
                    .completeness,
                SemanticModelCompleteness::Partial,
                "a missing embedded method surface cannot prove absence"
            );
        };

        let mut unknown_owner = class("pkg.UnknownOwner", "go");
        embed(&mut unknown_owner, TypeRef::Unknown);
        owner_is_partial(vec![unknown_owner.clone()], &unknown_owner.id);

        let mut absent_owner = class("pkg.AbsentOwner", "go");
        embed(&mut absent_owner, declared("type.pkg.Missing"));
        owner_is_partial(vec![absent_owner.clone()], &absent_owner.id);

        let mut partial_target = class("pkg.PartialTarget", "go");
        partial_target.provenance.completeness = SemanticModelCompleteness::Partial;
        let mut partial_owner = class("pkg.PartialOwner", "go");
        embed(&mut partial_owner, declared(&partial_target.id));
        owner_is_partial(
            vec![partial_owner.clone(), partial_target],
            &partial_owner.id,
        );

        let mut nested_owner = class("pkg.NestedOwner", "go");
        let mut nested_middle = class("pkg.NestedMiddle", "go");
        embed(&mut nested_owner, declared(&nested_middle.id));
        embed(&mut nested_middle, declared("type.pkg.NestedMissing"));
        owner_is_partial(vec![nested_owner.clone(), nested_middle], &nested_owner.id);
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "8ea61138c182: unpublished ancestor edges were silently dropped, making an incomplete inherited surface look complete; transitive control"
    )]
    fn a_dangling_edge_deeper_in_the_closure_still_fails_the_gate() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Php,
        ]);
        let child = class("pkg.Child", "php");
        let middle = class("pkg.Middle", "php");
        let child_edge = extends(&child, "pkg.Middle");
        let middle_edge = extends(&middle, "vendor.Missing");
        let overlay = overlay(vec![child, middle], vec![child_edge, middle_edge]);

        let surface = overlay.owner_surface(named(&overlay, "pkg.Child"));

        assert!(!surface.proves_absence(), "{surface:#?}");
        assert_eq!(
            vec![SemanticModelSurfaceGap::UnresolvedEdge(
                SemanticModelUnresolvedEdge {
                    from: "pkg.Middle".to_string(),
                    to: "vendor.Missing".to_string(),
                    defect: SemanticModelEdgeDefect::Unpublished,
                }
            )],
            surface.gaps,
            "the transitive edge must name the type that declares it"
        );
        assert!(
            surface.gaps[0].to_string().contains("vendor.Missing"),
            "{surface:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#2958: exact wildcard re-export alias failed across a hierarchy edge")]
    fn an_exact_re_export_alias_crosses_a_hierarchy_edge_and_proves_absence() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Python,
        ]);
        let mut declaring = class("typing.MutableSet", "python");
        declaring.aliases.push("shim.MutableSet".to_string());
        let root = class("builtins.object", "python");
        let uses = class("pkg.Uses", "python");
        let overlay = overlay(
            vec![uses.clone(), declaring.clone(), root],
            vec![
                extends(&uses, "shim.MutableSet"),
                extends(&declaring, "builtins.object"),
            ],
        );

        let surface = overlay.owner_surface(named(&overlay, "pkg.Uses"));
        assert!(surface.proves_absence(), "{surface:#?}");
        assert_eq!(
            vec!["pkg.Uses", "typing.MutableSet", "builtins.object"],
            closure_names(&surface),
            "a wildcard re-export shim names the declaring class"
        );
        assert_eq!(
            overlay
                .member_target_on_owner(&uses.id, "strip")
                .disposition,
            SemanticModelMemberTargetDisposition::Absent,
            "a resolved re-export edge closes the surface"
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#2958: cross-language alias falsely proved hierarchy absence")]
    fn an_alias_another_language_published_never_crosses_a_hierarchy_edge() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Python,
        ]);
        let mut foreign = class("widget.Local", "typescript");
        foreign.aliases.push("Base".to_string());
        let child = class("pkg.Child", "python");
        let root = class("builtins.object", "python");
        let overlay = overlay(
            vec![child.clone(), foreign, root],
            vec![extends(&child, "Base")],
        );

        let surface = overlay.owner_surface(named(&overlay, "pkg.Child"));
        assert!(
            !surface.proves_absence(),
            "a bare export spelling from another language is a guess: {surface:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn exact_owner_member_lookup_prefers_a_direct_member_then_a_complete_base() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::TypeScript,
        ]);
        let child = class("pkg.Child", "typescript");
        let base = class("pkg.Base", "typescript");
        let base_member = field(&base, "member.base.value", "value");
        let edge = extends(&child, "pkg.Base");
        let inherited = overlay(
            vec![child.clone(), base.clone(), base_member.clone()],
            vec![edge.clone()],
        );

        let inherited_match = inherited.member_target_on_owner(&child.id, "value");
        assert_eq!(
            inherited_match.disposition,
            SemanticModelMemberTargetDisposition::Unique
        );
        assert_eq!(
            inherited_match.records[0].id, base_member.id,
            "the exact inherited model record is retained"
        );

        let direct_member = field(&child, "member.child.value", "value");
        let overridden = overlay(
            vec![child.clone(), base, base_member, direct_member.clone()],
            vec![edge],
        );
        let direct_match = overridden.member_target_on_owner(&child.id, "value");
        assert_eq!(
            direct_match.disposition,
            SemanticModelMemberTargetDisposition::Unique
        );
        assert_eq!(
            direct_match.records[0].id, direct_member.id,
            "dispatch order must select the direct member before its base"
        );

        let absent = overridden.member_target_on_owner(&child.id, "missing");
        assert_eq!(
            absent.disposition,
            SemanticModelMemberTargetDisposition::Absent,
            "a complete owner surface may prove exact absence"
        );
    }

    #[cfg(test)]
    #[test]
    fn exact_owner_member_lookup_preserves_conflict_and_incompleteness() {
        let owner = class("pkg.Owner", "typescript");
        let first = field(&owner, "member.owner.value.first", "value");
        let second = field(&owner, "member.owner.value.second", "value");
        let conflict = overlay(vec![owner.clone(), first, second], Vec::new());
        assert_eq!(
            conflict
                .member_target_on_owner(&owner.id, "value")
                .disposition,
            SemanticModelMemberTargetDisposition::Conflict
        );

        let mut partial = field(&owner, "member.owner.value.partial", "value");
        partial.provenance.completeness = SemanticModelCompleteness::Partial;
        let partial_overlay = overlay(vec![owner.clone(), partial], Vec::new());
        assert_eq!(
            partial_overlay
                .member_target_on_owner(&owner.id, "value")
                .disposition,
            SemanticModelMemberTargetDisposition::Incomplete
        );
        assert_eq!(
            partial_overlay
                .member_target_on_owner("type.missing", "value")
                .disposition,
            SemanticModelMemberTargetDisposition::Incomplete,
            "an unpublished owner is not an absence proof"
        );
    }

    #[cfg(test)]
    #[test]
    fn exact_owner_member_presence_accepts_only_complete_callable_families() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Python,
        ]);
        let owner = class("pkg.Owner", "python");
        let first = method(
            &owner,
            "member.owner.run.first",
            "run",
            Some(signature(&[Some("value")], false)),
        );
        let second = method(
            &owner,
            "member.owner.run.second",
            "run",
            Some(signature(&[Some("value"), Some("mode")], false)),
        );
        let direct = overlay(
            vec![owner.clone(), first.clone(), second.clone()],
            Vec::new(),
        );
        assert!(direct.member_present_on_owner(&owner.id, "run"));

        let child = class("pkg.Child", "python");
        let inherited = overlay(
            vec![child.clone(), owner.clone(), first, second],
            vec![extends(&child, "pkg.Owner")],
        );
        assert!(inherited.member_present_on_owner(&child.id, "run"));

        let fields = overlay(
            vec![
                owner.clone(),
                field(&owner, "member.owner.value.first", "value"),
                field(&owner, "member.owner.value.second", "value"),
            ],
            Vec::new(),
        );
        assert!(!fields.member_present_on_owner(&owner.id, "value"));

        let mut ambiguous_first = method(
            &owner,
            "member.owner.ambiguous.first",
            "ambiguous",
            Some(signature(&[Some("value")], false)),
        );
        ambiguous_first.provenance.ambiguous = true;
        let ambiguous_second = method(
            &owner,
            "member.owner.ambiguous.second",
            "ambiguous",
            Some(signature(&[Some("value"), Some("mode")], false)),
        );
        let ambiguous = overlay(
            vec![owner.clone(), ambiguous_first, ambiguous_second],
            Vec::new(),
        );
        assert!(!ambiguous.member_present_on_owner(&owner.id, "ambiguous"));

        let different_pack_first = method(
            &owner,
            "member.owner.mixed.first",
            "mixed",
            Some(signature(&[Some("value")], false)),
        );
        let mut different_pack_second = method(
            &owner,
            "member.owner.mixed.second",
            "mixed",
            Some(signature(&[Some("value"), Some("mode")], false)),
        );
        different_pack_second.provenance.pack_id = "other.pack".to_string();
        different_pack_second.provenance.pack_digest = "other.digest".to_string();
        let different_pack = overlay(
            vec![owner.clone(), different_pack_first, different_pack_second],
            Vec::new(),
        );
        assert!(!different_pack.member_present_on_owner(&owner.id, "mixed"));

        let mut partial = method(
            &owner,
            "member.owner.partial.first",
            "partial",
            Some(signature(&[Some("value")], false)),
        );
        partial.provenance.completeness = SemanticModelCompleteness::Partial;
        let incomplete = overlay(vec![owner.clone(), partial], Vec::new());
        assert!(!incomplete.member_present_on_owner(&owner.id, "partial"));
        assert!(!incomplete.member_present_on_owner(&owner.id, "missing"));
    }

    #[cfg(test)]
    #[test]
    fn exact_owner_implicit_operation_lookup_preserves_conflicts_and_incompleteness() {
        let owner = class("std.basic_string", "cpp");
        let mut first = method(&owner, "member.copy_assignment.first", "operator=", None);
        first.implicit_operation = Some(ImplicitOperation::CopyAssignment);
        let mut second = method(&owner, "member.copy_assignment.second", "operator=", None);
        second.implicit_operation = Some(ImplicitOperation::CopyAssignment);
        let conflict = overlay(vec![owner.clone(), first, second], Vec::new());
        let conflict_match =
            conflict.implicit_member_target_on_owner(&owner.id, &ImplicitOperation::CopyAssignment);
        assert_eq!(
            conflict_match.disposition,
            SemanticModelMemberTargetDisposition::Conflict
        );
        assert_eq!(conflict_match.records.len(), 2);

        let mut duplicate_id = method(&owner, "member.copy_assignment", "operator=", None);
        duplicate_id.implicit_operation = Some(ImplicitOperation::CopyAssignment);
        let duplicate_id_overlay = overlay(
            vec![owner.clone(), duplicate_id.clone(), duplicate_id],
            Vec::new(),
        );
        let duplicate_id_match = duplicate_id_overlay
            .implicit_member_target_on_owner(&owner.id, &ImplicitOperation::CopyAssignment);
        assert_eq!(
            duplicate_id_match.disposition,
            SemanticModelMemberTargetDisposition::Conflict,
            "duplicate records with one stable id are still competing evidence"
        );

        let mut partial = method(&owner, "member.copy_assignment.partial", "operator=", None);
        partial.implicit_operation = Some(ImplicitOperation::CopyAssignment);
        partial.provenance.completeness = SemanticModelCompleteness::Partial;
        let incomplete = overlay(vec![owner.clone(), partial], Vec::new());
        let incomplete_match = incomplete
            .implicit_member_target_on_owner(&owner.id, &ImplicitOperation::CopyAssignment);
        assert_eq!(
            incomplete_match.disposition,
            SemanticModelMemberTargetDisposition::Incomplete
        );
        assert_eq!(incomplete_match.records.len(), 1);
        assert_eq!(
            incomplete_match.records[0].provenance.completeness,
            SemanticModelCompleteness::Partial,
            "partial operation provenance remains visible to the caller"
        );

        let mut ambiguous = method(
            &owner,
            "member.copy_assignment.ambiguous",
            "operator=",
            None,
        );
        ambiguous.implicit_operation = Some(ImplicitOperation::CopyAssignment);
        ambiguous.provenance.ambiguous = true;
        let ambiguous_overlay = overlay(vec![owner, ambiguous], Vec::new());
        let ambiguous_match = ambiguous_overlay.implicit_member_target_on_owner(
            "type.std.basic_string",
            &ImplicitOperation::CopyAssignment,
        );
        assert_eq!(
            ambiguous_match.disposition,
            SemanticModelMemberTargetDisposition::Conflict
        );
        assert_eq!(ambiguous_match.records.len(), 1);
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "8ea61138c182: the introducing repair explicitly identifies the #1619 simple-name-posting bug: navigation guesses cannot certify proof edges"
    )]
    fn a_simple_name_edge_resolves_for_navigation_but_never_for_a_proof() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Php,
        ]);
        // What Python's producer records for `class Child(Base)` is the source
        // spelling `Base`, which the overlay's simple-name postings will happily
        // match against any indexed `Base`.
        let child = class("pkg.Child", "php");
        let base = class("pkg.Base", "php");
        let edge = extends(&child, "Base");
        let overlay = overlay(vec![child, base], vec![edge]);

        let surface = overlay.owner_surface(named(&overlay, "pkg.Child"));

        assert_eq!(
            vec!["pkg.Child", "pkg.Base"],
            closure_names(&surface),
            "the candidate stays available to navigation"
        );
        assert_eq!(
            vec![SemanticModelSurfaceGap::UnresolvedEdge(
                SemanticModelUnresolvedEdge {
                    from: "pkg.Child".to_string(),
                    to: "Base".to_string(),
                    defect: SemanticModelEdgeDefect::NameResolved,
                }
            )],
            surface.gaps
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "8ea61138c182: the missing-ancestor repair must reject a partial published base as an absence proof"
    )]
    fn a_partial_pack_anywhere_in_the_closure_fails_the_gate() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Php,
        ]);
        let child = class("pkg.Child", "php");
        let mut base = class("pkg.Base", "php");
        base.provenance.completeness = SemanticModelCompleteness::Partial;
        let edge = extends(&child, "pkg.Base");
        let overlay = overlay(vec![child, base], vec![edge]);

        let surface = overlay.owner_surface(named(&overlay, "pkg.Child"));

        assert_eq!(
            vec![SemanticModelSurfaceGap::PartialType {
                qualified_name: "pkg.Base".to_string(),
            }],
            surface.gaps
        );
    }

    #[cfg(test)]
    #[test]
    fn a_python_class_without_a_published_object_root_cannot_prove_absence() {
        let klass = class("theta.Klass", "python");
        let overlay = overlay(vec![klass], Vec::new());

        let surface = overlay.owner_surface(named(&overlay, "theta.Klass"));

        assert_eq!(
            vec![SemanticModelSurfaceGap::UnresolvedEdge(
                SemanticModelUnresolvedEdge {
                    from: "theta.Klass".to_string(),
                    to: "builtins.object".to_string(),
                    defect: SemanticModelEdgeDefect::Unpublished,
                }
            )],
            surface.gaps,
            "an unseen `object` surface is a hole, not a clean bottom"
        );
    }

    #[cfg(test)]
    fn java_hierarchy_fixture() -> SemanticModelOverlay {
        let child = class("example.Child", "java");
        let parent = class("example.Parent", "java");
        let unrelated = class("example.Other", "java");
        let mut result = overlay(vec![child, parent, unrelated], Vec::new());
        for name in ["example.Child", "example.Parent", "example.Other"] {
            let id = named(&result, name).id.clone();
            let edges = if name == "example.Child" {
                vec![HierarchyFact {
                    hierarchy_kind: HierarchyKind::Extends,
                    target: TypeRef::Named {
                        name: "example.Parent".into(),
                        arguments: Vec::new(),
                        nullable: false,
                    },
                    declaration_ordinal: None,
                }]
            } else {
                Vec::new()
            };
            result.java_hierarchy.insert(id, (Vec::new(), edges));
        }
        result
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3713: Java widening lost the exact hierarchy witness")]
    fn java_hierarchy_witness_retains_exact_path() {
        let result = java_hierarchy_fixture();
        let answer = result.java_reference_widening(
            named(&result, "example.Child"),
            named(&result, "example.Parent"),
            8,
            None,
        );
        assert!(answer.incomplete.is_empty(), "{answer:?}");
        assert_eq!(answer.witness.unwrap().declarations.len(), 2);
        assert!(
            result
                .java_reference_widening(
                    named(&result, "example.Parent"),
                    named(&result, "example.Child"),
                    8,
                    None
                )
                .witness
                .is_none()
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3713: partial Java hierarchy erased a known positive path")]
    fn java_hierarchy_partialness_does_not_erase_positive_path() {
        let mut result = java_hierarchy_fixture();
        let child = result
            .symbols
            .iter_mut()
            .find(|symbol| symbol.qualified_name == "example.Child")
            .unwrap();
        child.provenance.completeness = SemanticModelCompleteness::Partial;
        let answer = result.java_reference_widening(
            named(&result, "example.Child"),
            named(&result, "example.Parent"),
            8,
            None,
        );
        assert!(answer.witness.is_some());
        assert_eq!(
            answer.incomplete,
            vec![JavaHierarchyIncomplete::MissingHierarchy]
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3713: missing or ambiguous generic hierarchy evidence proved widening")]
    fn java_hierarchy_missing_generic_and_ambiguous_do_not_prove_widening() {
        for reason in [
            JavaHierarchyIncomplete::MissingHierarchy,
            JavaHierarchyIncomplete::GenericSubstitution,
            JavaHierarchyIncomplete::Ambiguous,
        ] {
            let mut result = java_hierarchy_fixture();
            let id = named(&result, "example.Child").id.clone();
            match reason {
                JavaHierarchyIncomplete::MissingHierarchy => {
                    result.java_hierarchy.remove(&id);
                }
                JavaHierarchyIncomplete::GenericSubstitution => {
                    result
                        .java_hierarchy
                        .get_mut(&id)
                        .unwrap()
                        .0
                        .push("T".into());
                }
                JavaHierarchyIncomplete::Ambiguous => {
                    result
                        .symbols
                        .iter_mut()
                        .find(|s| s.id == id)
                        .unwrap()
                        .provenance
                        .ambiguous = true;
                }
                _ => unreachable!(),
            }
            let answer = result.java_reference_widening(
                named(&result, "example.Child"),
                named(&result, "example.Parent"),
                8,
                None,
            );
            assert!(answer.witness.is_none(), "{answer:?}");
            assert_eq!(answer.incomplete, vec![reason]);
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3713: implements and unrelated Java types shared a widening result")]
    fn java_hierarchy_implements_and_unrelated_types_keep_distinct_proof() {
        let mut result = java_hierarchy_fixture();
        let parent_id = named(&result, "example.Parent").id.clone();
        result
            .symbols
            .iter_mut()
            .find(|s| s.id == parent_id)
            .unwrap()
            .kind = SemanticModelSymbolKind::Interface;
        let child_id = named(&result, "example.Child").id.clone();
        result.java_hierarchy.get_mut(&child_id).unwrap().1[0].hierarchy_kind =
            HierarchyKind::Implements;
        let answer = result.java_reference_widening(
            named(&result, "example.Child"),
            named(&result, "example.Parent"),
            8,
            None,
        );
        assert_eq!(
            answer.witness.unwrap().edges[0].hierarchy_kind,
            HierarchyKind::Implements
        );
        assert!(
            result
                .java_reference_widening(
                    named(&result, "example.Other"),
                    named(&result, "example.Parent"),
                    8,
                    None
                )
                .witness
                .is_none()
        );
    }

    #[cfg(test)]
    #[test]
    fn external_callable_application_keeps_spread_incomplete() {
        let owner = class("pkg.Owner", "java");
        let member = method(
            &owner,
            "member.run",
            "run",
            Some(signature(&[Some("values")], true)),
        );
        let overlay = overlay(vec![owner, member], Vec::new());
        let application = SemanticModelCallApplication::structured(0, Vec::new(), true);

        assert_eq!(
            overlay
                .callable_for_application(callable_key(1), &application)
                .disposition,
            SemanticModelCallableDisposition::Incomplete(
                SemanticModelCallableIncompleteReason::UnexpandedSpread
            )
        );
    }

    #[cfg(test)]
    #[test]
    fn external_callable_lookup_preserves_variadic_metadata_for_the_binder() {
        let owner = class("pkg.Owner", "java");
        let member = method(
            &owner,
            "member.run.variadic",
            "run",
            Some(signature(&[Some("values")], true)),
        );
        let overlay = overlay(vec![owner, member], Vec::new());

        let result = lookup(&overlay, 1);

        assert_eq!(result.disposition, SemanticModelCallableDisposition::Unique);
        assert!(
            result
                .unique()
                .unwrap()
                .structured_signature()
                .unwrap()
                .parameters[0]
                .variadic
        );

        let repeated = lookup(&overlay, 3);
        assert_eq!(
            repeated.disposition,
            SemanticModelCallableDisposition::Unique
        );
        assert!(
            repeated
                .unique()
                .unwrap()
                .structured_signature()
                .unwrap()
                .parameters[0]
                .variadic
        );
    }

    #[cfg(test)]
    #[test]
    fn a_type_that_declares_no_supertype_bottoms_out_cleanly() {
        let root = class("pkg.Root", "php");
        let overlay = overlay(vec![root], Vec::new());

        let surface = overlay.owner_surface(named(&overlay, "pkg.Root"));

        assert!(surface.proves_absence(), "{surface:#?}");
        assert_eq!(vec!["pkg.Root"], closure_names(&surface));
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "8ea61138c182: the missing-ancestor repair must still admit an exact fully published closure; positive control"
    )]
    fn a_fully_qualified_edge_across_a_complete_closure_proves_absence() {
        let _neutral_rules = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
            crate::analyzer::Language::Php,
        ]);
        let child = class("pkg.Child", "php");
        let base = class("pkg.Base", "php");
        let edge = extends(&child, "pkg.Base");
        let overlay = overlay(vec![child, base], vec![edge]);

        let surface = overlay.owner_surface(named(&overlay, "pkg.Child"));

        assert!(surface.proves_absence(), "{surface:#?}");
        assert_eq!(vec!["pkg.Child", "pkg.Base"], closure_names(&surface));
    }

    #[cfg(test)]
    #[test]
    fn exact_owner_implicit_operation_lookup_uses_owner_id_and_role() {
        let owner = class("std.basic_string", "cpp");
        let other_owner = class("other.basic_string", "cpp");
        let mut copy = method(&owner, "member.copy_assignment", "operator=", None);
        copy.implicit_operation = Some(ImplicitOperation::CopyAssignment);
        let mut move_member = method(&owner, "member.move_assignment", "operator=", None);
        move_member.implicit_operation = Some(ImplicitOperation::MoveAssignment);
        let mut same_name_other_owner = method(
            &other_owner,
            "member.other.copy_assignment",
            "operator=",
            None,
        );
        same_name_other_owner.implicit_operation = Some(ImplicitOperation::CopyAssignment);
        let overlay = overlay(
            vec![
                owner.clone(),
                copy.clone(),
                move_member.clone(),
                other_owner,
                same_name_other_owner,
            ],
            Vec::new(),
        );
        assert_eq!(
            overlay.members_of(&owner.id).disposition,
            SemanticModelOverlayDisposition::Conflict,
            "the broad member posting contains both operation roles"
        );

        let copy_match =
            overlay.implicit_member_target_on_owner(&owner.id, &ImplicitOperation::CopyAssignment);
        assert_eq!(
            copy_match.disposition,
            SemanticModelMemberTargetDisposition::Unique
        );
        assert_eq!(copy_match.records.len(), 1);
        assert_eq!(copy_match.records[0].id, copy.id);
        assert_eq!(
            copy_match.records[0].provenance.pack_id, "test.pack",
            "the selected operation keeps its model provenance"
        );

        let move_match =
            overlay.implicit_member_target_on_owner(&owner.id, &ImplicitOperation::MoveAssignment);
        assert_eq!(
            move_match.disposition,
            SemanticModelMemberTargetDisposition::Unique
        );
        assert_eq!(move_match.records[0].id, move_member.id);

        let missing_role =
            overlay.implicit_member_target_on_owner(&owner.id, &ImplicitOperation::CopyConstructor);
        assert_eq!(
            missing_role.disposition,
            SemanticModelMemberTargetDisposition::Incomplete,
            "a zero operation match is not a proved absence"
        );

        let missing_owner = overlay
            .implicit_member_target_on_owner("type.missing", &ImplicitOperation::CopyAssignment);
        assert_eq!(
            missing_owner.disposition,
            SemanticModelMemberTargetDisposition::Incomplete
        );
    }

    #[cfg(test)]
    #[test]
    fn a_python_class_reaches_the_published_object_root() {
        let klass = class("theta.Klass", "python");
        let object = class("builtins.object", "python");
        let overlay = overlay(vec![klass, object], Vec::new());

        let surface = overlay.owner_surface(named(&overlay, "theta.Klass"));

        assert!(surface.proves_absence(), "{surface:#?}");
        assert_eq!(
            vec!["theta.Klass", "builtins.object"],
            closure_names(&surface),
            "Python's implicit `object` base contributes universal members"
        );
    }

    #[cfg(test)]
    #[test]
    fn the_object_root_itself_does_not_inherit_itself() {
        let object = class("builtins.object", "python");
        let overlay = overlay(vec![object], Vec::new());

        let surface = overlay.owner_surface(named(&overlay, "builtins.object"));

        assert!(surface.proves_absence(), "{surface:#?}");
        assert_eq!(vec!["builtins.object"], closure_names(&surface));
    }
    #[cfg(test)]
    #[hardwon(
        "#3713: Java hierarchy proof exhaustion and cancellation were not kept as typed incomplete evidence"
    )]
    #[test]
    fn java_hierarchy_budget_and_cancellation_stay_typed() {
        let result = java_hierarchy_fixture();
        let source = named(&result, "example.Child");
        let target = named(&result, "example.Parent");
        let answer = result.java_reference_widening(source, target, 0, None);
        assert_eq!(
            answer.incomplete,
            vec![JavaHierarchyIncomplete::BudgetExhausted]
        );
        assert!(answer.witness.is_none());
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        cancellation.cancel();
        let answer = result.java_reference_widening(source, target, 8, Some(&cancellation));
        assert_eq!(answer.incomplete, vec![JavaHierarchyIncomplete::Cancelled]);
        assert!(answer.witness.is_none());
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extra_support_0 {
    use brokk_bifrost_semantic::analyzer::semantic_model::model::ReceiverFact;

    pub(super) use crate::analyzer::semantic_model::overlay::test_support::*;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::Signature;
    use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;

    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbol;
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbolKind;

    #[doc(hidden)]
    pub fn field(owner: &SemanticModelSymbol, id: &str, name: &str) -> SemanticModelSymbol {
        let mut field = method(owner, id, name, None);
        field.kind = SemanticModelSymbolKind::Field;
        field.receiver = None;
        field
    }
    #[doc(hidden)]
    pub fn signature(names: &[Option<&str>], variadic: bool) -> Signature {
        Signature {
            type_parameters: Vec::new(),
            parameters: names
                .iter()
                .enumerate()
                .map(|(ordinal, name)| {
                    brokk_bifrost_analysis::analyzer::semantic_model::model::Parameter {
                        name: name.map(str::to_owned),
                        r#type: TypeRef::Named {
                            name: format!("java.lang.T{ordinal}"),
                            arguments: Vec::new(),
                            nullable: false,
                        },
                        optional: false,
                        variadic: variadic && ordinal + 1 == names.len(),
                        role: None,
                        passing_mode: Default::default(),
                    }
                })
                .collect(),
            returns: None,
        }
    }

    use super::*;
    #[doc(hidden)]
    pub fn go_external_receiver_test_overlay() -> std::sync::Arc<SemanticModelOverlay> {
        let mut strings_package = class("strings", "go");
        strings_package.kind = SemanticModelSymbolKind::Module;
        strings_package.visibility = Visibility::Package;
        strings_package.aliases = vec!["strings".to_owned()];
        let mut codec_package = class("example.com/acme/codec", "go");
        codec_package.kind = SemanticModelSymbolKind::Module;
        codec_package.visibility = Visibility::Package;
        codec_package.aliases = vec!["wire".to_owned()];
        let mut buffer = class("example.com/acme/codec.Buffer", "go");
        buffer.kind = SemanticModelSymbolKind::Struct;
        let mut builder = class("strings.Builder", "go");
        builder.kind = SemanticModelSymbolKind::Struct;
        let mut len = method(
            &builder,
            "strings.Builder.Len",
            "Len",
            Some(signature(&[], false)),
        );
        len.receiver = Some(ReceiverFact { pointer: false });
        let mut write_string = method(
            &builder,
            "strings.Builder.WriteString",
            "WriteString",
            Some(signature(&[Some("value")], false)),
        );
        write_string.receiver = Some(ReceiverFact { pointer: true });

        let mut os_package = class("os", "go");
        os_package.kind = SemanticModelSymbolKind::Module;
        os_package.visibility = Visibility::Package;
        os_package.aliases = vec!["os".to_owned()];
        let mut file = class("os.File", "go");
        file.kind = SemanticModelSymbolKind::Struct;
        let mut close = method(&file, "os.File.Close", "Close", Some(signature(&[], false)));
        close.receiver = Some(ReceiverFact { pointer: true });

        let mut image_package = class("image", "go");
        image_package.kind = SemanticModelSymbolKind::Module;
        image_package.visibility = Visibility::Package;
        image_package.aliases = vec!["image".to_owned()];
        let mut point = class("image.Point", "go");
        point.kind = SemanticModelSymbolKind::Struct;
        let mut string = method(
            &point,
            "image.Point.String",
            "String",
            Some(signature(&[], false)),
        );
        string.receiver = Some(ReceiverFact { pointer: false });

        let mut sync_package = class("sync", "go");
        sync_package.kind = SemanticModelSymbolKind::Module;
        sync_package.visibility = Visibility::Package;
        sync_package.aliases = vec!["sync".to_owned()];
        let mut once = class("sync.Once", "go");
        once.kind = SemanticModelSymbolKind::Struct;
        let mut once_do = method(
            &once,
            "sync.Once.Do",
            "Do",
            Some(signature(&[Some("f")], false)),
        );
        once_do.receiver = Some(ReceiverFact { pointer: true });

        let mut embed_package = class("embed", "go");
        embed_package.kind = SemanticModelSymbolKind::Module;
        embed_package.visibility = Visibility::Package;
        embed_package.aliases = vec!["embed".to_owned()];
        let mut embed_fs = class("embed.FS", "go");
        embed_fs.kind = SemanticModelSymbolKind::Struct;
        let mut embed_open = method(
            &embed_fs,
            "embed.FS.Open",
            "Open",
            Some(signature(&[Some("name")], false)),
        );
        embed_open.receiver = Some(ReceiverFact { pointer: false });

        std::sync::Arc::new(overlay(
            vec![
                strings_package,
                codec_package,
                buffer,
                builder,
                len,
                write_string,
                os_package,
                file,
                close,
                image_package,
                point,
                string,
                sync_package,
                once,
                once_do,
                embed_package,
                embed_fs,
                embed_open,
            ],
            Vec::new(),
        ))
    }
    #[doc(hidden)]
    pub fn go_callback_source_field_test_overlay(artifact_sha256: &str) -> SemanticModelOverlay {
        let mut overlay =
            go_callback_field_test_overlay(artifact_sha256, Visibility::Public, false);
        for symbol in &mut overlay.symbols {
            symbol.locator_path = Some("api.go".to_owned());
            symbol.locator_symbol = Some(if symbol.owner_id.is_none() {
                "example.test/ssh.Config".to_owned()
            } else {
                "example.test/ssh.Config.Callback".to_owned()
            });
        }
        overlay
    }
    #[doc(hidden)]
    pub fn go_callback_field_test_overlay(
        artifact_sha256: &str,
        field_visibility: Visibility,
        conflict: bool,
    ) -> SemanticModelOverlay {
        let mut owner = class("example.test/ssh.Config", "go");
        owner.kind = SemanticModelSymbolKind::Struct;
        let mut callback = field(&owner, "field.callback", "Callback");
        callback.structured_signature = Some(Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: Some(TypeRef::Function {
                parameters: Vec::new(),
                result: None,
            }),
        });
        callback.visibility = field_visibility;
        for record in [&mut owner, &mut callback] {
            record.provenance.proof = SemanticModelProof::ExactArtifact;
            record.provenance.activation.matched_evidence.language = "go".to_owned();
            record
                .provenance
                .activation
                .matched_evidence
                .artifact_sha256 = Some(artifact_sha256.to_owned());
        }
        let mut records = vec![owner, callback];
        if conflict {
            let mut other = records[1].clone();
            other.id = "other.callback".to_owned();
            other.provenance.pack_digest = "other pack".to_owned();
            records.push(other);
        }
        overlay(records, Vec::new())
    }
}

#[doc(hidden)]
pub mod jvm_external;
