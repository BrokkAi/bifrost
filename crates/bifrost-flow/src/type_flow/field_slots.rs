//! Workspace-wide syntactic summaries for class-owned instance fields.

use std::path::Path;
use std::sync::Arc;

use brokk_bifrost_core::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};

#[cfg(test)]
use crate::analyzer::semantic::MemberAccessKind;
use crate::analyzer::semantic::{
    ClassAtom, ClassIdentity, ClassSeed, DynamicFieldWrite, IcfgProviderBehaviorIdentity,
    LengthDelimitedDigest, MemberAccessQuery, MemoryLocationKind, ProcedureHandle, SemanticBudget,
    SemanticBudgetExceeded, SemanticEffect, SemanticIrVersion, SemanticRequest, SemanticValueKind,
    SourcePosition, SourceSpan, StableDigest, TypeFlowAdapter, UnknownReason, ValueFlowKind,
    WorkspaceMountId, WorkspaceRelativePath,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::store::StoreError;
use crate::analyzer::store::class_set_field_slots::{
    ClassSetFieldSlotArtifactRow, ClassSetFieldSlotAtomRow, ClassSetFieldSlotAtomValueRow,
    ClassSetFieldSlotClassRow, ClassSetFieldSlotIndexKey, ClassSetFieldSlotIndexRow,
    ClassSetFieldSlotRow, ClassSetFieldSlotSourceRow, ClassSetFieldStoreRow,
    ClassSetFieldStoreSurveyRow,
};
use crate::analyzer::{AnalyzerQueryScope, IAnalyzer, ProjectFile, WorkspaceAnalyzer};
use crate::hash::{HashMap, HashSet};

use super::plan::TypeFlowPlanError;
use crate::analyzer::semantic::{SourceSite, SourceSiteKind};

type FieldSlotKey = (ClassIdentity, Box<str>);
type FieldSlotAtom = (ClassAtom, SourceSite);
const FIELD_SLOT_CACHE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FieldSlotIndexCacheKey {
    semantic: ClassSetFieldSlotIndexKey,
    mount: WorkspaceMountId,
}

#[derive(Clone)]
pub struct FieldSlotIndexCache {
    complete: CompleteValueCache<FieldSlotIndexCacheKey, FieldSlotIndex>,
}

impl Default for FieldSlotIndexCache {
    fn default() -> Self {
        Self {
            complete: CompleteValueCache::<FieldSlotIndexCacheKey, FieldSlotIndex>::new(
                FIELD_SLOT_CACHE_BYTES,
                |_, index| {
                    u32::try_from(
                        index
                            .retained_bytes()
                            .saturating_add(std::mem::size_of::<FieldSlotIndexCacheKey>()),
                    )
                    .unwrap_or(u32::MAX)
                },
            ),
        }
    }
}

impl std::fmt::Debug for FieldSlotIndexCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FieldSlotIndexCache")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSlot {
    pub class: ClassIdentity,
    pub member: Box<str>,
    pub atoms: Vec<(ClassAtom, SourceSite)>,
}

#[derive(Debug, Clone)]
pub struct FieldSlotIndex {
    slots: Vec<FieldSlot>,
    lookup: HashMap<ClassIdentity, HashMap<Box<str>, usize>>,
    digest: StableDigest,
    store_survey: FieldStoreSurvey,
    semantic_budget_exhaustion: Option<SemanticBudgetExceeded>,
    transient_resolver_budget: bool,
    persistent_artifacts: Vec<ClassSetFieldSlotArtifactRow>,
    mounted_artifacts: Vec<MountedArtifactReplay>,
    persistable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSlotIndexAcquisitionKind {
    MemoryHit,
    PersistentHit,
    Built,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSlotIndexMissReason {
    NoSemanticKey,
    NoPersistentStore,
    KeyMiss,
    PersistenceValidation,
    StoreFailure,
    PersistenceReplayBudget,
    MemoryReplayBudget,
}

#[derive(Debug)]
pub struct FieldSlotIndexAcquisition {
    pub index: Arc<FieldSlotIndex>,
    pub kind: FieldSlotIndexAcquisitionKind,
    pub miss_reason: Option<FieldSlotIndexMissReason>,
    pub published: bool,
}

#[derive(Debug, Clone)]
struct MountedArtifactReplay {
    fingerprint: StableDigest,
    work: crate::analyzer::semantic::SemanticWork,
}

struct PersistedArtifactReplay {
    mounted: Vec<MountedArtifactReplay>,
    source_lengths: HashMap<String, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistedHydrationRejection {
    ReplayBudget,
    Hydration,
    Cancelled,
}

#[derive(Default)]
struct CollectedSlots {
    stores: HashMap<FieldSlotKey, Vec<FieldSlotAtom>>,
    loads: HashMap<FieldSlotKey, SourceSite>,
    foreign_members: HashSet<Box<str>>,
    dynamic_members: HashSet<Box<str>>,
    dynamic_any: bool,
    globally_incomplete: bool,
    transient_resolver_budget: bool,
    semantic_budget_exhaustion: Option<SemanticBudgetExceeded>,
    persistent_artifacts: HashSet<(
        String,
        StableDigest,
        StableDigest,
        crate::analyzer::semantic::SemanticWork,
    )>,
}

/// Store evidence is separate from a callable declaration or a field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MemberStoreEvidence {
    Stored,
    NoStore,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FieldStoreSurvey {
    stores: HashMap<ClassIdentity, HashSet<Box<str>>>,
    unowned_members: HashSet<Box<str>>,
    unknown_members: bool,
}

impl FieldStoreSurvey {
    fn from_collected(collected: &CollectedSlots) -> Self {
        let mut stores: HashMap<ClassIdentity, HashSet<Box<str>>> = HashMap::default();
        for (class, member) in collected.stores.keys() {
            stores
                .entry(class.clone())
                .or_default()
                .insert(member.clone());
        }
        Self {
            stores,
            unowned_members: collected
                .foreign_members
                .union(&collected.dynamic_members)
                .cloned()
                .collect(),
            unknown_members: collected.globally_incomplete || collected.dynamic_any,
        }
    }

    fn ordered_stores(&self) -> Vec<(Option<&ClassIdentity>, &str)> {
        let mut rows = self
            .unowned_members
            .iter()
            .map(|member| (None, member.as_ref()))
            .collect::<Vec<_>>();
        rows.extend(self.stores.iter().flat_map(|(class, members)| {
            members
                .iter()
                .map(move |member| (Some(class), member.as_ref()))
        }));
        rows.sort_unstable_by(|(left, left_member), (right, right_member)| {
            match (left, right) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (Some(left), Some(right)) => class_order(left, right),
            }
            .then_with(|| left_member.cmp(right_member))
        });
        rows
    }

    fn to_persisted(&self) -> Option<ClassSetFieldStoreSurveyRow> {
        Some(ClassSetFieldStoreSurveyRow {
            stores: self
                .ordered_stores()
                .into_iter()
                .map(|(owner, member)| {
                    Some(ClassSetFieldStoreRow {
                        owner: match owner {
                            Some(owner) => Some(persist_class(owner)?),
                            None => None,
                        },
                        member: member.to_owned(),
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            unknown_members: self.unknown_members,
        })
    }

    fn retained_bytes(&self) -> usize {
        let member_bytes = |members: &HashSet<Box<str>>| {
            members
                .capacity()
                .saturating_mul(std::mem::size_of::<Box<str>>())
                .saturating_add(members.iter().map(|member| member.len()).sum::<usize>())
        };
        self.stores
            .iter()
            .fold(
                self.stores
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(ClassIdentity, HashSet<Box<str>>)>()),
                |bytes, (class, members)| {
                    bytes
                        .saturating_add(class_identity_heap_bytes(class))
                        .saturating_add(member_bytes(members))
                },
            )
            .saturating_add(member_bytes(&self.unowned_members))
    }
}

impl FieldSlotIndex {
    // Bump when the language-neutral field-slot algorithm changes.
    const ALGORITHM_VERSION: u32 = 5;
    // Bump only when the persisted row encoding changes.
    const REPRESENTATION_VERSION: u32 = 2;

    /// Load one exact complete index when possible, otherwise build it.
    ///
    /// Store failures and malformed/stale payloads are ordinary cache misses.
    /// A persisted hit first reserves the semantic work recorded by the cold
    /// build; a caller whose budget cannot pay it receives a fresh bounded
    /// build instead of a free answer.
    #[allow(clippy::too_many_arguments)]
    pub fn acquire(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        provider_behavior: IcfgProviderBehaviorIdentity,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        cache: &FieldSlotIndexCache,
        semantic_budget: &mut SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<FieldSlotIndexAcquisition, TypeFlowPlanError> {
        // Bind every adapter lookup in this acquisition to the exact immutable
        // model publication named by the persistence key.
        let _snapshot_scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            active_semantic_model_snapshot.clone(),
        );
        let _cancellation_scope =
            AnalyzerQueryScope::with_cancellation(workspace.analyzer(), cancellation);
        let Some(semantic_key) = field_slot_persistence_key(
            workspace,
            adapter,
            provider_behavior,
            active_semantic_model_snapshot.as_deref(),
        ) else {
            return Ok(FieldSlotIndexAcquisition {
                index: Self::build_checked(workspace, adapter, semantic_budget, cancellation)?,
                kind: FieldSlotIndexAcquisitionKind::Built,
                miss_reason: Some(FieldSlotIndexMissReason::NoSemanticKey),
                published: false,
            });
        };
        let memory_key = FieldSlotIndexCacheKey {
            semantic: semantic_key.clone(),
            mount: WorkspaceMountId::from_root(workspace.analyzer().project().root()),
        };
        let (acquisition, _) = cache.complete.acquire(&memory_key, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                let mut staged_budget = semantic_budget.clone();
                if value.replay_mounted_artifacts(&mut staged_budget, cancellation) {
                    *semantic_budget = staged_budget;
                    return Ok(FieldSlotIndexAcquisition {
                        index: value,
                        kind: FieldSlotIndexAcquisitionKind::MemoryHit,
                        miss_reason: None,
                        published: false,
                    });
                }
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                Ok(FieldSlotIndexAcquisition {
                    index: Self::build_checked(workspace, adapter, semantic_budget, cancellation)?,
                    kind: FieldSlotIndexAcquisitionKind::Built,
                    miss_reason: Some(FieldSlotIndexMissReason::MemoryReplayBudget),
                    published: false,
                })
            }
            CompleteValueAcquisition::Cancelled => Err(TypeFlowPlanError::Cancelled),
            CompleteValueAcquisition::Rejected => Ok(FieldSlotIndexAcquisition {
                index: Self::build_checked(workspace, adapter, semantic_budget, cancellation)?,
                kind: FieldSlotIndexAcquisitionKind::Built,
                miss_reason: Some(FieldSlotIndexMissReason::StoreFailure),
                published: false,
            }),
            CompleteValueAcquisition::Leader { permit } => {
                let persistent = workspace.persisted_store_path().is_some();
                let mut initial_key_miss = false;
                let mut miss_reason = if persistent {
                    FieldSlotIndexMissReason::KeyMiss
                } else {
                    FieldSlotIndexMissReason::NoPersistentStore
                };
                let mut shared_publish_eligible = true;
                if persistent && let Some(store) = workspace.store() {
                    match store.class_set_field_slot_index(&semantic_key, cancellation) {
                        Ok(Some(row)) => {
                            let mut staged_budget = semantic_budget.clone();
                            match Self::from_persisted(
                                workspace,
                                row,
                                &mut staged_budget,
                                cancellation,
                            ) {
                                Ok(index) => {
                                    if cancellation.is_cancelled() {
                                        return Err(TypeFlowPlanError::Cancelled);
                                    }
                                    let index = Arc::new(index);
                                    *semantic_budget = staged_budget;
                                    permit.publish_complete(Arc::clone(&index));
                                    return Ok(FieldSlotIndexAcquisition {
                                        index,
                                        kind: FieldSlotIndexAcquisitionKind::PersistentHit,
                                        miss_reason: None,
                                        published: false,
                                    });
                                }
                                Err(PersistedHydrationRejection::Cancelled) => {
                                    return Err(TypeFlowPlanError::Cancelled);
                                }
                                Err(PersistedHydrationRejection::ReplayBudget) => {
                                    miss_reason = FieldSlotIndexMissReason::PersistenceReplayBudget;
                                }
                                Err(PersistedHydrationRejection::Hydration) => {
                                    miss_reason = FieldSlotIndexMissReason::PersistenceValidation;
                                }
                            }
                        }
                        Ok(None) => initial_key_miss = true,
                        Err(error) => {
                            if cancellation.is_cancelled() {
                                return Err(TypeFlowPlanError::Cancelled);
                            }
                            workspace
                                .analyzer()
                                .record_query_failure(StoreError::new(format!(
                                    "loading persisted class-set field slots: {error}"
                                )));
                            if error.is_corrupt() || error.is_resource_bound() {
                                miss_reason = FieldSlotIndexMissReason::PersistenceValidation;
                            } else {
                                miss_reason = FieldSlotIndexMissReason::StoreFailure;
                                shared_publish_eligible = false;
                            }
                        }
                    }
                }

                let index = Self::build_checked(workspace, adapter, semantic_budget, cancellation)?;
                // Stage from the post-build ledger: the losing work was
                // performed and remains charged. Its paid-artifact set turns
                // winner hydration into repeat charges instead of charging
                // each retained census a second time.
                if !index.persistable
                    && initial_key_miss
                    && let Some(store) = workspace.store()
                    && let Some((winner, winner_budget)) = Self::recover_persisted_winner(
                        workspace,
                        store,
                        &semantic_key,
                        semantic_budget.clone(),
                        cancellation,
                    )?
                {
                    if cancellation.is_cancelled() {
                        return Err(TypeFlowPlanError::Cancelled);
                    }
                    *semantic_budget = winner_budget;
                    permit.publish_complete(Arc::clone(&winner));
                    return Ok(FieldSlotIndexAcquisition {
                        index: winner,
                        // This caller performed a build after an exact miss.
                        // Keep those counters exclusive even though a raced
                        // persistent winner supplied the returned value.
                        kind: FieldSlotIndexAcquisitionKind::Built,
                        miss_reason: Some(FieldSlotIndexMissReason::KeyMiss),
                        published: false,
                    });
                }
                let mut published = false;
                if index.persistable && !cancellation.is_cancelled() {
                    if persistent && let Some(store) = workspace.store() {
                        match index.to_persisted(semantic_key) {
                            Ok(Some(row)) => {
                                match store.publish_class_set_field_slot_index(row, cancellation) {
                                    Ok(inserted) => published = inserted,
                                    Err(error) => {
                                        if cancellation.is_cancelled() {
                                            return Err(TypeFlowPlanError::Cancelled);
                                        }
                                        workspace.analyzer().record_query_failure(
                                            StoreError::new(format!(
                                                "publishing persisted class-set field slots: {error}"
                                            )),
                                        );
                                        shared_publish_eligible = false;
                                    }
                                }
                            }
                            Ok(None) => {
                                shared_publish_eligible = false;
                            }
                            Err(error) => {
                                workspace.analyzer().record_query_failure(StoreError::new(
                                    format!(
                                        "encoding complete class-set field slots for persistence: {error}"
                                    ),
                                ));
                                shared_publish_eligible = false;
                            }
                        }
                    }
                    if cancellation.is_cancelled() {
                        return Err(TypeFlowPlanError::Cancelled);
                    }
                    if shared_publish_eligible {
                        permit.publish_complete(Arc::clone(&index));
                    }
                }
                Ok(FieldSlotIndexAcquisition {
                    index,
                    kind: FieldSlotIndexAcquisitionKind::Built,
                    miss_reason: Some(miss_reason),
                    published,
                })
            }
        }
    }

    fn recover_persisted_winner(
        workspace: &WorkspaceAnalyzer,
        store: &crate::analyzer::store::AnalyzerStore,
        semantic_key: &ClassSetFieldSlotIndexKey,
        mut budget_after_build: SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Option<(Arc<Self>, SemanticBudget)>, TypeFlowPlanError> {
        let row = match store.class_set_field_slot_index(semantic_key, cancellation) {
            Ok(row) => row,
            Err(error) => {
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                workspace
                    .analyzer()
                    .record_query_failure(StoreError::new(format!(
                        "reloading concurrently published class-set field slots: {error}"
                    )));
                return Ok(None);
            }
        };
        let Some(row) = row else {
            return Ok(None);
        };
        match Self::from_persisted(workspace, row, &mut budget_after_build, cancellation) {
            Ok(index) => {
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                Ok(Some((Arc::new(index), budget_after_build)))
            }
            Err(PersistedHydrationRejection::Cancelled) => Err(TypeFlowPlanError::Cancelled),
            Err(
                PersistedHydrationRejection::ReplayBudget | PersistedHydrationRejection::Hydration,
            ) => Ok(None),
        }
    }

    pub fn build(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        semantic_budget: &mut SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Self, TypeFlowPlanError> {
        let files = workspace
            .analyzer()
            .project()
            .analyzable_files(adapter.language())
            .map_err(TypeFlowPlanError::WorkspaceEnumeration)?;
        let mut collected = CollectedSlots::default();
        for file in files {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            let outcome = workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(semantic_budget, cancellation),
                )
                .map_err(TypeFlowPlanError::Discovery)?;
            if cancellation.is_cancelled()
                || matches!(
                    &outcome,
                    crate::analyzer::semantic::SemanticOutcome::Cancelled { .. }
                )
            {
                return Err(TypeFlowPlanError::Cancelled);
            }
            collected.globally_incomplete |= !outcome.is_complete();
            if collected.semantic_budget_exhaustion.is_none() {
                collected.semantic_budget_exhaustion = outcome.budget_exceeded();
            }
            let Some(artifact) = outcome.available_value() else {
                continue;
            };
            let fingerprint = artifact.key().fingerprint();
            debug_assert!(semantic_budget.has_charged_artifact(fingerprint));
            collected.persistent_artifacts.insert((
                artifact.key().path().as_str().to_string(),
                artifact.key().public_fingerprint(),
                fingerprint,
                artifact.work(),
            ));
            for procedure in artifact.procedures() {
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                let procedure = artifact
                    .procedure_handle(procedure.id())
                    .expect("a retained artifact owns each procedure");
                collect_procedure(workspace, adapter, &procedure, &mut collected, cancellation)?;
            }
        }
        Self::finish(workspace, adapter, collected, cancellation)
    }

    fn build_checked(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        semantic_budget: &mut SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Arc<Self>, TypeFlowPlanError> {
        let index = Self::build(workspace, adapter, semantic_budget, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        Ok(Arc::new(index))
    }

    fn finish(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        collected: CollectedSlots,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Self, TypeFlowPlanError> {
        let store_survey = FieldStoreSurvey::from_collected(&collected);
        let persistable = !collected.globally_incomplete
            && !collected.transient_resolver_budget
            && collected.semantic_budget_exhaustion.is_none();
        let mut artifacts = collected
            .persistent_artifacts
            .into_iter()
            .map(|(rel_path, public_digest, fingerprint, work)| {
                (
                    ClassSetFieldSlotArtifactRow {
                        rel_path,
                        public_digest: *public_digest.as_bytes(),
                        work,
                    },
                    MountedArtifactReplay { fingerprint, work },
                )
            })
            .collect::<Vec<_>>();
        artifacts.sort_unstable_by(|(left, _), (right, _)| left.rel_path.cmp(&right.rel_path));
        let (persistent_artifacts, mounted_artifacts) = artifacts.into_iter().unzip();
        let mut requested = collected.loads.keys().cloned().collect::<Vec<_>>();
        requested.sort_by(|(left_class, left_member), (right_class, right_member)| {
            class_order(left_class, right_class).then_with(|| left_member.cmp(right_member))
        });
        let mut hierarchy_cache = HashMap::default();
        let mut slots = Vec::new();
        for (class, member) in requested {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            let hierarchy = hierarchy_cache
                .entry(class.clone())
                .or_insert_with(|| adapter.class_hierarchy(workspace, &class))
                .clone();
            let mut related = vec![class.clone()];
            related.extend(hierarchy.ancestors.iter().cloned());
            if let Some(descendants) = &hierarchy.descendants {
                related.extend(descendants.iter().cloned());
            }
            related.sort_by(class_order);
            related.dedup();

            let mut atoms = Vec::new();
            let mut incomplete = collected.globally_incomplete
                || hierarchy.descendants.is_none()
                || hierarchy.unresolved_base
                || hierarchy.dynamic_attributes
                || collected.dynamic_any
                || collected.foreign_members.contains(member.as_ref())
                || collected.dynamic_members.contains(member.as_ref());
            for owner in &related {
                if cancellation.is_cancelled() {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                let owner_hierarchy = hierarchy_cache
                    .entry(owner.clone())
                    .or_insert_with(|| adapter.class_hierarchy(workspace, owner));
                if matches!(owner, ClassIdentity::External { .. })
                    || owner_hierarchy.descendants.is_none()
                    || owner_hierarchy.unresolved_base
                    || owner_hierarchy.dynamic_attributes
                    || !adapter.field_slot_is_complete(workspace, owner, &member)
                {
                    incomplete = true;
                }
                if let Some(stored) = collected.stores.get(&(owner.clone(), member.clone())) {
                    atoms.extend(stored.iter().cloned());
                }
            }
            dedup_atoms(&mut atoms);
            if incomplete {
                let site = collected
                    .loads
                    .get(&(class.clone(), member.clone()))
                    .expect("a requested slot retains a load site")
                    .clone();
                atoms.push((
                    ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete),
                    SourceSite {
                        kind: SourceSiteKind::Unknown,
                        ..site
                    },
                ));
                dedup_atoms(&mut atoms);
            }
            if atoms.is_empty() {
                continue;
            }
            slots.push(FieldSlot {
                class,
                member,
                atoms,
            });
        }
        let digest = digest_index(&slots, &store_survey, field_slot_semantics_digest(adapter));
        let mut lookup: HashMap<ClassIdentity, HashMap<Box<str>, usize>> = HashMap::default();
        for (index, slot) in slots.iter().enumerate() {
            lookup
                .entry(slot.class.clone())
                .or_default()
                .insert(slot.member.clone(), index);
        }
        let mut index = Self {
            slots,
            lookup,
            digest,
            store_survey,
            semantic_budget_exhaustion: collected.semantic_budget_exhaustion,
            transient_resolver_budget: collected.transient_resolver_budget,
            persistent_artifacts,
            mounted_artifacts,
            persistable,
        };
        index.persistable &= index.retained_bytes() <= FIELD_SLOT_CACHE_BYTES as usize;
        Ok(index)
    }

    fn to_persisted(
        &self,
        key: ClassSetFieldSlotIndexKey,
    ) -> Result<Option<ClassSetFieldSlotIndexRow>, StoreError> {
        let Some(slots) = self
            .slots
            .iter()
            .map(|slot| {
                Some(ClassSetFieldSlotRow {
                    owner: persist_class(&slot.class)?,
                    member: slot.member.to_string(),
                    atoms: slot
                        .atoms
                        .iter()
                        .map(|(atom, source)| {
                            Some(ClassSetFieldSlotAtomRow {
                                value: match atom {
                                    ClassAtom::Class(class) => {
                                        ClassSetFieldSlotAtomValueRow::Class(persist_class(class)?)
                                    }
                                    ClassAtom::Unknown(reason) => {
                                        ClassSetFieldSlotAtomValueRow::Unknown(
                                            reason.label().to_string(),
                                        )
                                    }
                                },
                                source: persist_source(source)?,
                            })
                        })
                        .collect::<Option<Vec<_>>>()?,
                })
            })
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(None);
        };
        let Some(store_survey) = self.store_survey.to_persisted() else {
            return Ok(None);
        };
        ClassSetFieldSlotIndexRow::try_new(
            key,
            slots,
            self.persistent_artifacts.clone(),
            store_survey,
        )
        .map(Some)
    }

    fn from_persisted(
        workspace: &WorkspaceAnalyzer,
        row: ClassSetFieldSlotIndexRow,
        semantic_budget: &mut SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Self, PersistedHydrationRejection> {
        let semantics_digest = StableDigest::from_array(row.key.adapter_semantics_digest);
        let persistent_artifacts = row.artifacts.clone();
        let replay = replay_artifact_charges(
            workspace,
            &persistent_artifacts,
            semantic_budget,
            cancellation,
        )?;
        let mut workspace_class_names = HashSet::default();
        for slot in &row.slots {
            if cancellation.is_cancelled() {
                return Err(PersistedHydrationRejection::Cancelled);
            }
            if let ClassSetFieldSlotClassRow::Workspace { fq_name, .. } = &slot.owner {
                workspace_class_names.insert(fq_name.clone());
            }
            for atom in &slot.atoms {
                if let ClassSetFieldSlotAtomValueRow::Class(
                    ClassSetFieldSlotClassRow::Workspace { fq_name, .. },
                ) = &atom.value
                {
                    workspace_class_names.insert(fq_name.clone());
                }
            }
        }
        for store in &row.store_survey.stores {
            if let Some(ClassSetFieldSlotClassRow::Workspace { fq_name, .. }) = &store.owner {
                workspace_class_names.insert(fq_name.clone());
            }
        }
        let mut workspace_class_names = workspace_class_names.into_iter().collect::<Vec<_>>();
        workspace_class_names.sort_unstable();
        for names in workspace_class_names.chunks(256) {
            if cancellation.is_cancelled() {
                return Err(PersistedHydrationRejection::Cancelled);
            }
            IAnalyzer::prefetch_definitions(workspace.analyzer(), names);
        }

        let mut workspace_classes = HashMap::default();
        let mut source_files = HashMap::default();
        let mut store_survey = FieldStoreSurvey {
            unknown_members: row.store_survey.unknown_members,
            ..FieldStoreSurvey::default()
        };
        for store in row.store_survey.stores {
            if cancellation.is_cancelled() {
                return Err(PersistedHydrationRejection::Cancelled);
            }
            match store.owner {
                Some(owner) => {
                    let owner = rehydrate_class(workspace, owner, &mut workspace_classes)
                        .ok_or(PersistedHydrationRejection::Hydration)?;
                    store_survey
                        .stores
                        .entry(owner)
                        .or_default()
                        .insert(store.member.into_boxed_str());
                }
                None => {
                    store_survey
                        .unowned_members
                        .insert(store.member.into_boxed_str());
                }
            }
        }
        let slots = row
            .slots
            .into_iter()
            .map(|slot| {
                if cancellation.is_cancelled() {
                    return None;
                }
                Some(FieldSlot {
                    class: rehydrate_class(workspace, slot.owner, &mut workspace_classes)?,
                    member: slot.member.into_boxed_str(),
                    atoms: slot
                        .atoms
                        .into_iter()
                        .map(|atom| {
                            if cancellation.is_cancelled() {
                                return None;
                            }
                            Some((
                                match atom.value {
                                    ClassSetFieldSlotAtomValueRow::Class(class) => {
                                        ClassAtom::Class(rehydrate_class(
                                            workspace,
                                            class,
                                            &mut workspace_classes,
                                        )?)
                                    }
                                    ClassSetFieldSlotAtomValueRow::Unknown(reason) => {
                                        ClassAtom::Unknown(unknown_reason(&reason)?)
                                    }
                                },
                                rehydrate_source(
                                    workspace,
                                    atom.source,
                                    &replay.source_lengths,
                                    &mut source_files,
                                )?,
                            ))
                        })
                        .collect::<Option<Vec<_>>>()?,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                if cancellation.is_cancelled() {
                    PersistedHydrationRejection::Cancelled
                } else {
                    PersistedHydrationRejection::Hydration
                }
            })?;
        if slots.windows(2).any(|rows| {
            class_order(&rows[0].class, &rows[1].class)
                .then_with(|| rows[0].member.cmp(&rows[1].member))
                .is_ge()
        }) || slots.iter().any(|slot| {
            slot.atoms
                .windows(2)
                .any(|atoms| atom_order(&atoms[0], &atoms[1]).is_ge())
        }) {
            return Err(PersistedHydrationRejection::Hydration);
        }
        let digest = digest_index(&slots, &store_survey, semantics_digest);
        let mut lookup: HashMap<ClassIdentity, HashMap<Box<str>, usize>> = HashMap::default();
        for (index, slot) in slots.iter().enumerate() {
            if lookup
                .entry(slot.class.clone())
                .or_default()
                .insert(slot.member.clone(), index)
                .is_some()
            {
                return Err(PersistedHydrationRejection::Hydration);
            }
        }
        let index = Self {
            slots,
            lookup,
            digest,
            store_survey,
            semantic_budget_exhaustion: None,
            transient_resolver_budget: false,
            persistent_artifacts,
            mounted_artifacts: replay.mounted,
            persistable: true,
        };
        (index.retained_bytes() <= FIELD_SLOT_CACHE_BYTES as usize)
            .then_some(index)
            .ok_or(PersistedHydrationRejection::Hydration)
    }

    /// An exact receiver class can inherit stores from ancestors, never from
    /// descendants. Named writes without an owner keep only that name open.
    pub(super) fn member_store_evidence(
        &self,
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        class: &ClassIdentity,
        member: &str,
    ) -> MemberStoreEvidence {
        let has_store = |owner: &ClassIdentity| {
            self.store_survey
                .stores
                .get(owner)
                .is_some_and(|members| members.contains(member))
        };
        if has_store(class) {
            return MemberStoreEvidence::Stored;
        }
        let hierarchy = adapter.class_hierarchy(workspace, class);
        if hierarchy.ancestors.iter().any(has_store) {
            return MemberStoreEvidence::Stored;
        }
        if self.store_survey.unknown_members
            || self.store_survey.unowned_members.contains(member)
            || hierarchy.unresolved_base
            || hierarchy.dynamic_attributes
        {
            MemberStoreEvidence::Unknown
        } else {
            MemberStoreEvidence::NoStore
        }
    }

    pub fn slot(&self, class: &ClassIdentity, member: &str) -> Option<&FieldSlot> {
        self.lookup
            .get(class)?
            .get(member)
            .map(|index| &self.slots[*index])
    }

    pub const fn digest(&self) -> StableDigest {
        self.digest
    }

    pub const fn semantic_budget_exhausted(&self) -> bool {
        self.semantic_budget_exhaustion.is_some() || self.transient_resolver_budget
    }

    pub const fn semantic_budget_exhaustion(&self) -> Option<SemanticBudgetExceeded> {
        self.semantic_budget_exhaustion
    }

    pub fn slots(&self) -> &[FieldSlot] {
        &self.slots
    }

    fn replay_mounted_artifacts(
        &self,
        semantic_budget: &mut SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> bool {
        let mut staged = semantic_budget.clone();
        for artifact in &self.mounted_artifacts {
            if cancellation.is_cancelled()
                || staged
                    .charge_complete_artifact_hit(artifact.fingerprint, artifact.work)
                    .is_err()
            {
                return false;
            }
        }
        if cancellation.is_cancelled() {
            return false;
        }
        *semantic_budget = staged;
        true
    }

    fn retained_bytes(&self) -> usize {
        let slot_bytes = self.slots.iter().fold(
            self.slots
                .capacity()
                .saturating_mul(std::mem::size_of::<FieldSlot>()),
            |total, slot| {
                total
                    .saturating_add(slot.member.len())
                    .saturating_add(
                        slot.atoms
                            .capacity()
                            .saturating_mul(std::mem::size_of::<FieldSlotAtom>()),
                    )
                    .saturating_add(class_identity_heap_bytes(&slot.class))
                    .saturating_add(slot.atoms.iter().fold(0usize, |total, (atom, source)| {
                        total
                            .saturating_add(match atom {
                                ClassAtom::Class(class) => class_identity_heap_bytes(class),
                                ClassAtom::Unknown(_) => 0,
                            })
                            .saturating_add(project_file_path_bytes(&source.file))
                    }))
            },
        );
        let lookup_bytes = self.lookup.iter().fold(
            self.lookup
                .capacity()
                .saturating_mul(std::mem::size_of::<(ClassIdentity, HashMap<Box<str>, usize>)>()),
            |total, (class, members)| {
                total
                    .saturating_add(class_identity_heap_bytes(class))
                    .saturating_add(
                        members
                            .capacity()
                            .saturating_mul(std::mem::size_of::<(Box<str>, usize)>()),
                    )
                    .saturating_add(
                        members
                            .keys()
                            .fold(0usize, |bytes, member| bytes.saturating_add(member.len())),
                    )
            },
        );
        let artifact_bytes = self.persistent_artifacts.iter().fold(
            self.persistent_artifacts
                .capacity()
                .saturating_mul(std::mem::size_of::<ClassSetFieldSlotArtifactRow>()),
            |total, artifact| total.saturating_add(artifact.rel_path.len()),
        );
        std::mem::size_of::<Self>()
            .saturating_add(self.store_survey.retained_bytes())
            .saturating_add(slot_bytes)
            .saturating_add(lookup_bytes)
            .saturating_add(artifact_bytes)
            .saturating_add(
                self.mounted_artifacts
                    .capacity()
                    .saturating_mul(std::mem::size_of::<MountedArtifactReplay>()),
            )
    }
}

fn class_identity_heap_bytes(class: &ClassIdentity) -> usize {
    match class {
        ClassIdentity::Workspace(unit) => unit
            .fq_name_str()
            .len()
            .saturating_add(unit.declaration_id().as_str().len())
            .saturating_add(project_file_path_bytes(unit.source())),
        ClassIdentity::External {
            qualified_name,
            symbol_id,
        } => qualified_name.len().saturating_add(symbol_id.len()),
    }
}

fn project_file_path_bytes(file: &ProjectFile) -> usize {
    file.root()
        .as_os_str()
        .to_string_lossy()
        .len()
        .saturating_add(file.rel_path().as_os_str().to_string_lossy().len())
}

fn field_slot_persistence_key(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    provider_behavior: IcfgProviderBehaviorIdentity,
    active_semantic_model_snapshot: Option<&ActiveSemanticModelSnapshot>,
) -> Option<ClassSetFieldSlotIndexKey> {
    let workspace_content = workspace
        .analyzer()
        .workspace_content_identities()?
        .language(adapter.language())?;
    let active_pack_digest = active_semantic_model_pack_digest(active_semantic_model_snapshot);
    let adapter_semantics = field_slot_semantics_digest(adapter);
    Some(field_slot_persistence_key_from_components(
        adapter.language(),
        StableDigest::from_array(*workspace_content.as_bytes()),
        provider_behavior.digest(),
        active_pack_digest,
        adapter_semantics,
        FieldSlotIndex::REPRESENTATION_VERSION,
    ))
}

/// Stable digest of the exact active semantic-model pack set used by
/// class-set analysis.
///
/// This is shared by every persisted class-set representation so field-slot
/// and final-result keys cannot silently disagree about the no-pack case.
pub fn active_semantic_model_pack_digest(
    active_semantic_model_snapshot: Option<&ActiveSemanticModelSnapshot>,
) -> StableDigest {
    match active_semantic_model_snapshot {
        Some(snapshot) => {
            StableDigest::sha256(snapshot.active_models().active_model_set_hash().as_bytes())
        }
        None => StableDigest::sha256(b"bifrost-class-set-field-slots:no-active-packs:v1"),
    }
}

fn field_slot_persistence_key_from_components(
    language: crate::analyzer::Language,
    workspace_content: StableDigest,
    provider_behavior: StableDigest,
    active_pack: StableDigest,
    adapter_semantics: StableDigest,
    representation_version: u32,
) -> ClassSetFieldSlotIndexKey {
    ClassSetFieldSlotIndexKey {
        language,
        workspace_content_digest: *workspace_content.as_bytes(),
        provider_behavior_digest: *provider_behavior.as_bytes(),
        active_pack_digest: *active_pack.as_bytes(),
        adapter_semantics_digest: *adapter_semantics.as_bytes(),
        representation_version,
    }
}

fn field_slot_semantics_digest(adapter: &dyn TypeFlowAdapter) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-class-set-field-slot-semantics-v1");
    let adapter_version = adapter.semantics_version();
    digest.push(adapter_version.name().as_bytes());
    digest.push(adapter_version.fingerprint().as_bytes());
    digest.push(SemanticIrVersion::current().as_bytes());
    digest.push(&FieldSlotIndex::ALGORITHM_VERSION.to_le_bytes());
    digest.finish()
}

fn replay_artifact_charges(
    workspace: &WorkspaceAnalyzer,
    artifacts: &[ClassSetFieldSlotArtifactRow],
    semantic_budget: &mut SemanticBudget,
    cancellation: &crate::analyzer::semantic::CancellationToken,
) -> Result<PersistedArtifactReplay, PersistedHydrationRejection> {
    let project = workspace.analyzer().project();
    let mut remaining_source_bytes = semantic_budget.remaining().source_bytes;
    let mut mounted = Vec::with_capacity(artifacts.len());
    let mut source_lengths = HashMap::default();
    for artifact in artifacts {
        if cancellation.is_cancelled() {
            return Err(PersistedHydrationRejection::Cancelled);
        }
        let file = project
            .file_by_rel_path(Path::new(&artifact.rel_path))
            .ok_or(PersistedHydrationRejection::Hydration)?;
        let provider = workspace
            .program_semantics_provider_for_file(&file)
            .ok_or(PersistedHydrationRejection::Hydration)?;
        let snapshot = match provider.current_artifact_source(&file, remaining_source_bytes) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return Err(PersistedHydrationRejection::ReplayBudget),
            Err(error) => {
                workspace
                    .analyzer()
                    .record_query_failure(StoreError::new(format!(
                        "validating persisted class-set field-slot artifact source: {error}"
                    )));
                return Err(PersistedHydrationRejection::Hydration);
            }
        };
        remaining_source_bytes = remaining_source_bytes
            .checked_sub(snapshot.source().len())
            .ok_or(PersistedHydrationRejection::ReplayBudget)?;
        let key = snapshot.key();
        if key.public_fingerprint().as_bytes() != &artifact.public_digest {
            return Err(PersistedHydrationRejection::Hydration);
        }
        let fingerprint = key.fingerprint();
        if source_lengths
            .insert(artifact.rel_path.clone(), snapshot.source().len())
            .is_some()
        {
            return Err(PersistedHydrationRejection::Hydration);
        }
        semantic_budget
            .charge(crate::analyzer::semantic::SemanticWork {
                source_bytes: snapshot.source().len(),
                ..crate::analyzer::semantic::SemanticWork::default()
            })
            .map_err(|_| PersistedHydrationRejection::ReplayBudget)?;
        semantic_budget
            .charge_complete_artifact_hit(fingerprint, artifact.work)
            .map_err(|_| PersistedHydrationRejection::ReplayBudget)?;
        mounted.push(MountedArtifactReplay {
            fingerprint,
            work: artifact.work,
        });
    }
    Ok(PersistedArtifactReplay {
        mounted,
        source_lengths,
    })
}

fn persist_class(class: &ClassIdentity) -> Option<ClassSetFieldSlotClassRow> {
    match class {
        ClassIdentity::Workspace(unit) => Some(ClassSetFieldSlotClassRow::Workspace {
            declaration_id: unit.declaration_id().to_string(),
            fq_name: unit.fq_name(),
            rel_path: portable_path(unit.source())?,
        }),
        ClassIdentity::External {
            qualified_name,
            symbol_id,
        } => Some(ClassSetFieldSlotClassRow::External {
            fq_name: qualified_name.to_string(),
            symbol_id: symbol_id.to_string(),
        }),
    }
}

fn rehydrate_class(
    workspace: &WorkspaceAnalyzer,
    class: ClassSetFieldSlotClassRow,
    workspace_classes: &mut HashMap<String, (String, String, crate::analyzer::CodeUnit)>,
) -> Option<ClassIdentity> {
    match class {
        ClassSetFieldSlotClassRow::Workspace {
            declaration_id,
            fq_name,
            rel_path,
        } => {
            if let Some((cached_fq_name, cached_rel_path, unit)) =
                workspace_classes.get(&declaration_id)
            {
                return (cached_fq_name == &fq_name && cached_rel_path == &rel_path)
                    .then(|| ClassIdentity::Workspace(unit.clone()));
            }
            let mut matches = workspace
                .analyzer()
                .get_definitions(&fq_name)
                .into_iter()
                .filter(|unit| {
                    unit.declaration_id().as_str() == declaration_id.as_str()
                        && portable_path(unit.source()).as_deref() == Some(rel_path.as_str())
                });
            let unit = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            workspace_classes.insert(declaration_id, (fq_name, rel_path, unit.clone()));
            Some(ClassIdentity::Workspace(unit))
        }
        ClassSetFieldSlotClassRow::External { fq_name, symbol_id } => {
            Some(ClassIdentity::External {
                qualified_name: fq_name.into_boxed_str(),
                symbol_id: symbol_id.into_boxed_str(),
            })
        }
    }
}

fn persist_source(source: &SourceSite) -> Option<ClassSetFieldSlotSourceRow> {
    let start = source.span.start();
    let end = source.span.end();
    Some(ClassSetFieldSlotSourceRow {
        rel_path: portable_path(&source.file)?,
        start_byte: start.byte_offset(),
        start_line: start.line(),
        start_byte_column: start.byte_column(),
        end_byte: end.byte_offset(),
        end_line: end.line(),
        end_byte_column: end.byte_column(),
        kind: source_kind_label(source.kind).to_string(),
    })
}

fn rehydrate_source(
    workspace: &WorkspaceAnalyzer,
    source: ClassSetFieldSlotSourceRow,
    source_lengths: &HashMap<String, usize>,
    source_files: &mut HashMap<String, ProjectFile>,
) -> Option<SourceSite> {
    let source_len = *source_lengths.get(&source.rel_path)?;
    if usize::try_from(source.end_byte).ok()? > source_len {
        return None;
    }
    let file = match source_files.get(&source.rel_path) {
        Some(file) => file.clone(),
        None => {
            let file = workspace
                .analyzer()
                .project()
                .file_by_rel_path(Path::new(&source.rel_path))?;
            source_files.insert(source.rel_path.clone(), file.clone());
            file
        }
    };
    let span = SourceSpan::new(
        SourcePosition::new(
            source.start_byte,
            source.start_line,
            source.start_byte_column,
        ),
        SourcePosition::new(source.end_byte, source.end_line, source.end_byte_column),
    )
    .ok()?;
    Some(SourceSite {
        file,
        span,
        kind: source_kind(&source.kind)?,
    })
}

fn portable_path(file: &ProjectFile) -> Option<String> {
    WorkspaceRelativePath::try_from_path(file.rel_path())
        .ok()
        .map(|path| path.as_str().to_string())
}

fn unknown_reason(label: &str) -> Option<UnknownReason> {
    Some(match label {
        "root_parameter" => UnknownReason::RootParameter,
        "self_receiver" => UnknownReason::SelfReceiver,
        "variadic_parameter" => UnknownReason::VariadicParameter,
        "unresolved_call" => UnknownReason::UnresolvedCall,
        "truncated" => UnknownReason::Truncated,
        "unmodeled_load" => UnknownReason::UnmodeledLoad,
        "await" => UnknownReason::Await,
        "capture" => UnknownReason::Capture,
        "ambiguous_callee" => UnknownReason::AmbiguousCallee,
        "external_not_modeled" => UnknownReason::ExternalNotModeled,
        "unresolved_base" => UnknownReason::UnresolvedBase,
        "dynamic_attributes" => UnknownReason::DynamicAttributes,
        "pack_incomplete" => UnknownReason::PackIncomplete,
        "uncertain_flow" => UnknownReason::UncertainFlow,
        "field_slot_incomplete" => UnknownReason::FieldSlotIncomplete,
        "solver_budget" => UnknownReason::SolverBudget,
        "semantic_budget" => UnknownReason::SemanticBudget,
        "incomplete_root" => UnknownReason::IncompleteRoot,
        "open_type_bound" => UnknownReason::OpenTypeBound,
        "scalar_receiver" => UnknownReason::ScalarReceiver,
        _ => return None,
    })
}

fn source_kind(label: &str) -> Option<SourceSiteKind> {
    Some(match label {
        "constructor_call" => SourceSiteKind::ConstructorCall,
        "literal" => SourceSiteKind::Literal,
        "container_literal" => SourceSiteKind::ContainerLiteral,
        "declared_parameter" => SourceSiteKind::DeclaredParameter,
        "root_receiver" => SourceSiteKind::RootReceiver,
        "unknown" => SourceSiteKind::Unknown,
        _ => return None,
    })
}

fn collect_procedure(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedure: &ProcedureHandle,
    collected: &mut CollectedSlots,
    cancellation: &crate::analyzer::semantic::CancellationToken,
) -> Result<(), TypeFlowPlanError> {
    for write in adapter.dynamic_field_writes(workspace, procedure) {
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        match write {
            DynamicFieldWrite::Member(member) => {
                collected.dynamic_members.insert(member);
            }
            DynamicFieldWrite::Any => collected.dynamic_any = true,
        }
    }
    let semantics = procedure.semantics();
    let receiver_values = receiver_values(procedure);
    let enclosing_class = adapter.enclosing_class(workspace, procedure);
    let (predecessors, computed_targets) = value_predecessors(semantics.points());
    for point in semantics.points() {
        if cancellation.is_cancelled() {
            return Err(TypeFlowPlanError::Cancelled);
        }
        for event in &point.events {
            match event.effect {
                SemanticEffect::MemoryStore {
                    location, value, ..
                } => {
                    let location = semantics
                        .memory_location(location)
                        .expect("a memory-store location is retained");
                    let MemoryLocationKind::Field { base, .. } = location.kind else {
                        continue;
                    };
                    let Some(member) = adapter.accessed_member(
                        workspace,
                        procedure,
                        MemberAccessQuery::Load(location),
                    ) else {
                        collected.dynamic_any = true;
                        continue;
                    };
                    let Some(class) = enclosing_class
                        .clone()
                        .filter(|_| receiver_values.contains(&base))
                    else {
                        collected.foreign_members.insert(member);
                        continue;
                    };
                    let span = mapping_span(
                        procedure,
                        semantics
                            .value(value)
                            .expect("a stored value is retained")
                            .source,
                    );
                    let Some(file) = file_for_procedure(workspace, procedure) else {
                        collected.globally_incomplete = true;
                        continue;
                    };
                    let classified = classify_stored_value(
                        workspace,
                        adapter,
                        procedure,
                        value,
                        &predecessors,
                        &computed_targets,
                        file,
                        span,
                    );
                    collected.transient_resolver_budget |= classified.transient_resolver_budget;
                    collected
                        .stores
                        .entry((class, member))
                        .or_default()
                        .extend(classified.atoms);
                }
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } => {
                    let location = semantics
                        .memory_location(location)
                        .expect("a memory-load location is retained");
                    let MemoryLocationKind::Field { base, .. } = location.kind else {
                        continue;
                    };
                    let Some(class) = enclosing_class
                        .clone()
                        .filter(|_| receiver_values.contains(&base))
                    else {
                        continue;
                    };
                    let Some(member) = adapter.accessed_member(
                        workspace,
                        procedure,
                        MemberAccessQuery::Load(location),
                    ) else {
                        continue;
                    };
                    let Some(file) = file_for_procedure(workspace, procedure) else {
                        collected.globally_incomplete = true;
                        continue;
                    };
                    let result = semantics.value(result).expect("a load result is retained");
                    let key = (class, member);
                    let site = SourceSite {
                        file,
                        span: mapping_span(procedure, result.source),
                        kind: SourceSiteKind::Unknown,
                    };
                    if collected
                        .loads
                        .get(&key)
                        .is_none_or(|existing| source_site_order(&site, existing).is_lt())
                    {
                        collected.loads.insert(key, site);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub(super) fn receiver_values(
    procedure: &ProcedureHandle,
) -> HashSet<crate::analyzer::semantic::ValueId> {
    let semantics = procedure.semantics();
    let mut values = semantics
        .values()
        .iter()
        .filter_map(|value| {
            matches!(value.kind, SemanticValueKind::Receiver { .. }).then_some(value.id)
        })
        .collect::<HashSet<_>>();
    loop {
        let before = values.len();
        for point in semantics.points() {
            for event in &point.events {
                if let SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    target,
                } = event.effect
                    && values.contains(&source)
                {
                    values.insert(target);
                }
            }
        }
        if values.len() == before {
            return values;
        }
    }
}

fn value_predecessors(
    points: &[crate::analyzer::semantic::ProgramPoint],
) -> (
    HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::ValueId>>,
    HashSet<crate::analyzer::semantic::ValueId>,
) {
    let mut predecessors: HashMap<_, Vec<_>> = HashMap::default();
    let mut computed_targets = HashSet::default();
    for point in points {
        for (index, event) in point.events.iter().enumerate() {
            if let SemanticEffect::ValueFlow { kind, target, .. } = event.effect
                && !kind.preserves_runtime_class()
            {
                computed_targets.insert(target);
            }
            let pair = match event.effect {
                SemanticEffect::Assignment { target, value }
                    if !point.assignment_has_transfer_marker(index) =>
                {
                    Some((target, value))
                }
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } if kind.preserves_runtime_class() => Some((target, source)),
                _ => None,
            };
            if let Some((target, source)) = pair {
                let entries = predecessors.entry(target).or_default();
                if !entries.contains(&source) {
                    entries.push(source);
                }
            }
        }
    }
    (predecessors, computed_targets)
}

#[derive(Default)]
struct StoredValueClassification {
    atoms: Vec<FieldSlotAtom>,
    incomplete: bool,
    transient_resolver_budget: bool,
}

impl StoredValueClassification {
    fn observe_seed(
        &mut self,
        seed: ClassSeed,
        file: &ProjectFile,
        span: SourceSpan,
        kind: SourceSiteKind,
    ) {
        if matches!(seed, ClassSeed::NotApplicable) {
            self.incomplete = true;
            return;
        }
        for atom in seed.into_atoms() {
            match atom {
                ClassAtom::Class(_) => self.atoms.push((
                    atom,
                    SourceSite {
                        file: file.clone(),
                        span,
                        kind,
                    },
                )),
                ClassAtom::Unknown(UnknownReason::OpenTypeBound) => self.atoms.push((
                    atom,
                    SourceSite {
                        file: file.clone(),
                        span,
                        kind: SourceSiteKind::Unknown,
                    },
                )),
                ClassAtom::Unknown(reason) => {
                    self.incomplete = true;
                    self.transient_resolver_budget |=
                        matches!(reason, UnknownReason::SemanticBudget);
                }
            }
        }
    }

    fn finish(mut self, file: ProjectFile, span: SourceSpan) -> Self {
        if self.incomplete || self.atoms.is_empty() {
            self.atoms.push((
                ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete),
                SourceSite {
                    file,
                    span,
                    kind: SourceSiteKind::Unknown,
                },
            ));
        }
        dedup_atoms(&mut self.atoms);
        self
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_stored_value(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedure: &ProcedureHandle,
    value: crate::analyzer::semantic::ValueId,
    predecessors: &HashMap<
        crate::analyzer::semantic::ValueId,
        Vec<crate::analyzer::semantic::ValueId>,
    >,
    computed_targets: &HashSet<crate::analyzer::semantic::ValueId>,
    file: ProjectFile,
    span: SourceSpan,
) -> StoredValueClassification {
    let semantics = procedure.semantics();
    let mut pending = vec![value];
    let mut seen = HashSet::default();
    let mut classified = StoredValueClassification::default();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            classified.incomplete = true;
            continue;
        }
        let row = semantics
            .value(value)
            .expect("a predecessor value is retained");
        if computed_targets.contains(&value) {
            classified.observe_seed(
                adapter.computed_class(workspace, procedure, row),
                &file,
                span,
                SourceSiteKind::Unknown,
            );
            // Values are stable binding identities, not SSA definitions.
            // Retain ordinary alternate definitions as well as this result.
            if let Some(alternatives) = predecessors.get(&value) {
                pending.extend(alternatives.iter().copied());
            }
            continue;
        }
        if let Some(call) = semantics
            .call_sites()
            .iter()
            .find(|call| call.result == Some(value) || call.normal_results.contains(&value))
        {
            classified.observe_seed(
                adapter.constructed_class(workspace, procedure, call),
                &file,
                span,
                SourceSiteKind::ConstructorCall,
            );
            continue;
        }
        if let Some(allocation) = semantics
            .allocations()
            .iter()
            .find(|allocation| allocation.result == value)
        {
            classified.observe_seed(
                adapter.allocation_class(workspace, procedure, allocation),
                &file,
                span,
                SourceSiteKind::ContainerLiteral,
            );
            continue;
        }
        match &row.kind {
            SemanticValueKind::Constant => {
                classified.observe_seed(
                    adapter.constant_class(workspace, procedure, row),
                    &file,
                    span,
                    SourceSiteKind::Literal,
                );
                continue;
            }
            SemanticValueKind::Parameter {
                ordinal,
                multiplicity,
                ..
            } => {
                if multiplicity.is_rest() {
                    classified.incomplete = true;
                } else {
                    classified.observe_seed(
                        adapter.declared_parameter_class(workspace, procedure, *ordinal),
                        &file,
                        span,
                        SourceSiteKind::DeclaredParameter,
                    );
                }
                continue;
            }
            SemanticValueKind::Local
            | SemanticValueKind::DefaultArgument { .. }
            | SemanticValueKind::Return
            | SemanticValueKind::Temporary
            | SemanticValueKind::Address
            | SemanticValueKind::Null
            | SemanticValueKind::Boolean(_)
            | SemanticValueKind::UnsignedInteger(_)
            | SemanticValueKind::Exception
            | SemanticValueKind::Callable
            | SemanticValueKind::AwaitResult
            | SemanticValueKind::Receiver { .. }
            | SemanticValueKind::LanguageDefined(_) => {
                let seed = adapter.retained_value_class(workspace, procedure, row);
                if !matches!(seed, ClassSeed::NotApplicable) {
                    classified.observe_seed(seed, &file, span, SourceSiteKind::Unknown);
                    continue;
                }
            }
        }
        match predecessors.get(&value) {
            Some(sources) if !sources.is_empty() => pending.extend(sources.iter().copied()),
            _ => classified.incomplete = true,
        }
    }
    classified.finish(file, span)
}

fn mapping_span(
    procedure: &ProcedureHandle,
    source: crate::analyzer::semantic::SourceMappingId,
) -> SourceSpan {
    procedure
        .semantics()
        .source_mapping(source)
        .expect("a retained IR row's source mapping is live")
        .locator
        .anchor()
        .span()
}

fn file_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
) -> Option<ProjectFile> {
    workspace
        .analyzer()
        .project()
        .file_by_rel_path(Path::new(procedure.semantics().locator().path().as_str()))
}

pub(super) fn class_order(left: &ClassIdentity, right: &ClassIdentity) -> std::cmp::Ordering {
    match (left, right) {
        (ClassIdentity::Workspace(left), ClassIdentity::Workspace(right)) => left
            .fq_name_str()
            .cmp(right.fq_name_str())
            .then_with(|| left.source().rel_path().cmp(right.source().rel_path()))
            .then_with(|| left.declaration_id().cmp(&right.declaration_id())),
        (ClassIdentity::Workspace(_), ClassIdentity::External { .. }) => std::cmp::Ordering::Less,
        (ClassIdentity::External { .. }, ClassIdentity::Workspace(_)) => {
            std::cmp::Ordering::Greater
        }
        (
            ClassIdentity::External {
                qualified_name: left_name,
                symbol_id: left_id,
            },
            ClassIdentity::External {
                qualified_name: right_name,
                symbol_id: right_id,
            },
        ) => left_name
            .cmp(right_name)
            .then_with(|| left_id.cmp(right_id)),
    }
}

fn atom_order(
    (left, left_site): &(ClassAtom, SourceSite),
    (right, right_site): &(ClassAtom, SourceSite),
) -> std::cmp::Ordering {
    let atom_order = match (left, right) {
        (ClassAtom::Class(left), ClassAtom::Class(right)) => class_order(left, right),
        (ClassAtom::Class(_), ClassAtom::Unknown(_)) => std::cmp::Ordering::Less,
        (ClassAtom::Unknown(_), ClassAtom::Class(_)) => std::cmp::Ordering::Greater,
        (ClassAtom::Unknown(left), ClassAtom::Unknown(right)) => left.label().cmp(right.label()),
    };
    atom_order.then_with(|| source_site_order(left_site, right_site))
}

fn source_site_order(left: &SourceSite, right: &SourceSite) -> std::cmp::Ordering {
    left.file
        .cmp(&right.file)
        .then_with(|| left.span.start_byte().cmp(&right.span.start_byte()))
        .then_with(|| left.span.end_byte().cmp(&right.span.end_byte()))
        .then_with(|| source_kind_label(left.kind).cmp(source_kind_label(right.kind)))
}

fn dedup_atoms(atoms: &mut Vec<(ClassAtom, SourceSite)>) {
    atoms.sort_by(atom_order);
    atoms.dedup();
}

fn digest_index(
    slots: &[FieldSlot],
    survey: &FieldStoreSurvey,
    semantics: StableDigest,
) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-type-flow-field-index-v2");
    digest.push(digest_slots(slots, semantics).as_bytes());
    digest.push(&[u8::from(survey.unknown_members)]);
    for (owner, member) in survey.ordered_stores() {
        match owner {
            Some(owner) => {
                digest.push(b"owned");
                push_class(&mut digest, owner);
            }
            None => digest.push(b"unowned"),
        }
        digest.push(member.as_bytes());
    }
    digest.finish()
}

fn digest_slots(slots: &[FieldSlot], semantics: StableDigest) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-type-flow-field-slots-v1");
    digest.push(semantics.as_bytes());
    for slot in slots {
        push_class(&mut digest, &slot.class);
        digest.push(slot.member.as_bytes());
        for (atom, site) in &slot.atoms {
            match atom {
                ClassAtom::Class(class) => {
                    digest.push(b"class");
                    push_class(&mut digest, class);
                }
                ClassAtom::Unknown(reason) => {
                    digest.push(b"unknown");
                    digest.push(reason.label().as_bytes());
                }
            }
            digest.push(site.file.rel_path().to_string_lossy().as_bytes());
            digest.push(&site.span.start_byte().to_le_bytes());
            digest.push(&site.span.end_byte().to_le_bytes());
            digest.push(source_kind_label(site.kind).as_bytes());
        }
    }
    digest.finish()
}

fn push_class(digest: &mut LengthDelimitedDigest, class: &ClassIdentity) {
    match class {
        ClassIdentity::Workspace(unit) => {
            digest.push(b"workspace");
            digest.push(unit.fq_name_str().as_bytes());
            digest.push(unit.source().rel_path().to_string_lossy().as_bytes());
            digest.push(unit.declaration_id().as_str().as_bytes());
        }
        ClassIdentity::External {
            qualified_name,
            symbol_id,
        } => {
            digest.push(b"external");
            digest.push(qualified_name.as_bytes());
            digest.push(symbol_id.as_bytes());
        }
    }
}

const fn source_kind_label(kind: SourceSiteKind) -> &'static str {
    match kind {
        SourceSiteKind::ConstructorCall => "constructor_call",
        SourceSiteKind::Literal => "literal",
        SourceSiteKind::ContainerLiteral => "container_literal",
        SourceSiteKind::DeclaredParameter => "declared_parameter",
        SourceSiteKind::RootReceiver => "root_receiver",
        SourceSiteKind::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::analyzer::semantic::{
        AllocationSite, ClassHierarchy, ClassSeed, DynamicFieldWrite, IcfgProvider,
        MemberAccessQuery, MemberLookup, SemanticCallSite, SemanticValue, TypeFlowAdapter,
        WorkspaceIcfgProvider, type_flow_adapter,
    };
    use crate::analyzer::{AnalyzerConfig, CodeUnit, CodeUnitType, Language};
    use crate::dataflow::SolverBudget;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::type_flow::solve_type_flow_workspace;
    use crate::value_flow::ClosureLimits;

    #[test]
    fn computed_definition_keeps_only_its_independent_identity_predecessors() {
        use crate::analyzer::semantic::{
            ProgramPoint, SemanticEvent, TransferKind, TransferOperation, ValueId,
            ValuePreservation, ValueTransfer,
        };
        let target = ValueId::new(0);
        let ordinary = ValueId::new(1);
        let operand = ValueId::new(2);
        let event = |effect| SemanticEvent::new(effect, Default::default(), Default::default());
        let point = ProgramPoint {
            id: Default::default(),
            block: Default::default(),
            source: Default::default(),
            evidence: Default::default(),
            events: vec![
                event(SemanticEffect::Assignment {
                    target,
                    value: ordinary,
                }),
                event(SemanticEffect::Assignment {
                    target,
                    value: operand,
                }),
                event(SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(ValueTransfer {
                        kind: TransferKind::Conversion {
                            preservation: ValuePreservation::Changing,
                        },
                        operation: TransferOperation::None,
                    }),
                    source: operand,
                    target,
                }),
            ]
            .into_boxed_slice(),
        };
        let (predecessors, computed) = value_predecessors(&[point]);
        assert_eq!(predecessors[&target], vec![ordinary]);
        assert_eq!(computed, HashSet::from_iter([target]));
    }

    #[test]
    fn field_slot_digest_includes_the_exact_workspace_declaration() {
        let root = if cfg!(windows) {
            std::path::PathBuf::from(r"C:\field-slot-digest")
        } else {
            std::path::PathBuf::from("/field-slot-digest")
        };
        let file = ProjectFile::new(root, "app.py");
        let first = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Class,
            "app",
            "Same",
            None,
            false,
        );
        let second = CodeUnit::with_signature(
            file,
            CodeUnitType::Class,
            "app",
            "Same",
            Some("distinct structured declaration".to_string()),
            false,
        );
        assert_eq!(first.fq_name(), second.fq_name());
        assert_ne!(first.declaration_id(), second.declaration_id());

        let digest = |unit| {
            let mut digest = LengthDelimitedDigest::new(b"field-slot-class-digest-test");
            push_class(&mut digest, &ClassIdentity::Workspace(unit));
            digest.finish()
        };
        assert_ne!(digest(first), digest(second));
    }

    #[test]
    fn open_bound_field_seed_retains_class_and_typed_remainder() {
        let root = if cfg!(windows) {
            std::path::PathBuf::from(r"C:\field-slot-open-bound")
        } else {
            std::path::PathBuf::from("/field-slot-open-bound")
        };
        let file = ProjectFile::new(root, "app.py");
        let class = ClassIdentity::External {
            qualified_name: "pkg.Widget".into(),
            symbol_id: "class-widget".into(),
        };
        let span = SourceSpan::new(SourcePosition::new(0, 0, 0), SourcePosition::new(1, 0, 1))
            .expect("fixture span is valid");
        let mut classification = StoredValueClassification::default();

        classification.observe_seed(
            ClassSeed::ClassWithOpenBound(class.clone()),
            &file,
            span,
            SourceSiteKind::ConstructorCall,
        );
        let classification = classification.finish(file, span);

        assert!(
            classification
                .atoms
                .iter()
                .any(|(atom, _)| { atom == &ClassAtom::Class(class.clone()) })
        );
        assert!(classification.atoms.iter().any(|(atom, site)| {
            atom == &ClassAtom::Unknown(UnknownReason::OpenTypeBound)
                && site.kind == SourceSiteKind::Unknown
        }));
        assert!(
            !classification.atoms.iter().any(|(atom, _)| {
                atom == &ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete)
            })
        );
    }

    fn field_slot_project() -> BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Python)
            .with_git()
            .file(
                "app.py",
                concat!(
                    "class Stored:\n",
                    "    pass\n",
                    "\n",
                    "class Box:\n",
                    "    def update(self):\n",
                    "        self.value = Stored()\n",
                    "        return self.value\n",
                ),
            )
            .build()
    }

    fn acquire(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        cache: &FieldSlotIndexCache,
        budget: &mut SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<FieldSlotIndexAcquisition, TypeFlowPlanError> {
        FieldSlotIndex::acquire(
            workspace,
            adapter,
            WorkspaceIcfgProvider::new(workspace).behavior_identity(),
            None,
            cache,
            budget,
            cancellation,
        )
    }

    fn artifact_census(index: &FieldSlotIndex) -> crate::analyzer::semantic::SemanticWork {
        index.persistent_artifacts.iter().fold(
            crate::analyzer::semantic::SemanticWork::default(),
            |work, artifact| work.conservative_add(artifact.work),
        )
    }

    fn cache_file_with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        name.into()
    }

    fn copy_persisted_store(source_root: &Path, destination_root: &Path) {
        let source = brokk_bifrost_core::gitblob::cache_db_path(source_root);
        let destination = brokk_bifrost_core::gitblob::cache_db_path(destination_root);
        std::fs::create_dir_all(
            destination
                .parent()
                .expect("a cache database has a parent directory"),
        )
        .expect("create destination cache directory");
        for suffix in ["", "-wal", "-shm"] {
            let from = cache_file_with_suffix(&source, suffix);
            if !from.exists() {
                continue;
            }
            std::fs::copy(&from, cache_file_with_suffix(&destination, suffix))
                .expect("copy exact persisted store component");
        }
    }

    fn wait_for_field_slot_follower(cache: &FieldSlotIndexCache) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.complete.waiting_count_for_test() == 0 {
            assert!(
                Instant::now() < deadline,
                "same-key field-slot follower never entered the flight"
            );
            thread::yield_now();
        }
    }

    struct BlockingTypeFlowAdapter {
        inner: &'static dyn TypeFlowAdapter,
        semantics: crate::analyzer::semantic::AdapterSemanticsVersion,
        constructed_seed: Option<ClassSeed>,
        block_hierarchy: bool,
        entered: Barrier,
        release: Barrier,
        blocked: AtomicBool,
    }

    impl BlockingTypeFlowAdapter {
        fn python() -> Self {
            let inner =
                type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
            Self {
                inner,
                semantics: inner.semantics_version(),
                constructed_seed: None,
                block_hierarchy: true,
                entered: Barrier::new(2),
                release: Barrier::new(2),
                blocked: AtomicBool::new(false),
            }
        }

        fn wait_until_blocked(&self) {
            self.entered.wait();
        }

        fn release(&self) {
            self.release.wait();
        }

        fn with_semantics(
            mut self,
            semantics: crate::analyzer::semantic::AdapterSemanticsVersion,
        ) -> Self {
            self.semantics = semantics;
            self
        }

        fn with_constructed_seed(mut self, seed: ClassSeed) -> Self {
            self.constructed_seed = Some(seed);
            self
        }

        fn without_hierarchy_block(mut self) -> Self {
            self.block_hierarchy = false;
            self
        }
    }

    impl TypeFlowAdapter for BlockingTypeFlowAdapter {
        fn language(&self) -> Language {
            self.inner.language()
        }

        fn semantics_version(&self) -> crate::analyzer::semantic::AdapterSemanticsVersion {
            self.semantics.clone()
        }

        fn constructed_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            call: &SemanticCallSite,
        ) -> ClassSeed {
            self.constructed_seed
                .clone()
                .unwrap_or_else(|| self.inner.constructed_class(workspace, procedure, call))
        }

        fn constant_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            value: &SemanticValue,
        ) -> ClassSeed {
            self.inner.constant_class(workspace, procedure, value)
        }

        fn allocation_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            allocation: &AllocationSite,
        ) -> ClassSeed {
            self.inner
                .allocation_class(workspace, procedure, allocation)
        }

        fn declared_parameter_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            ordinal: u32,
        ) -> ClassSeed {
            self.inner
                .declared_parameter_class(workspace, procedure, ordinal)
        }

        fn accessed_member(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
            site: MemberAccessQuery<'_>,
        ) -> Option<Box<str>> {
            self.inner.accessed_member(workspace, procedure, site)
        }

        fn member_lookup(
            &self,
            workspace: &WorkspaceAnalyzer,
            kind: MemberAccessKind,
            class: &ClassIdentity,
            member: &str,
        ) -> MemberLookup {
            self.inner.member_lookup(workspace, kind, class, member)
        }

        fn enclosing_class(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
        ) -> Option<ClassIdentity> {
            self.inner.enclosing_class(workspace, procedure)
        }

        fn class_hierarchy(
            &self,
            workspace: &WorkspaceAnalyzer,
            class: &ClassIdentity,
        ) -> ClassHierarchy {
            if self.block_hierarchy && !self.blocked.swap(true, Ordering::AcqRel) {
                self.entered.wait();
                self.release.wait();
            }
            self.inner.class_hierarchy(workspace, class)
        }

        fn field_slot_is_complete(
            &self,
            workspace: &WorkspaceAnalyzer,
            class: &ClassIdentity,
            member: &str,
        ) -> bool {
            self.inner.field_slot_is_complete(workspace, class, member)
        }

        fn dynamic_field_writes(
            &self,
            workspace: &WorkspaceAnalyzer,
            procedure: &ProcedureHandle,
        ) -> Vec<DynamicFieldWrite> {
            self.inner.dynamic_field_writes(workspace, procedure)
        }
    }

    #[test]
    fn member_store_survey_survives_memory_and_persistent_replay() {
        let project = InlineTestProject::with_language(Language::Python)
            .with_git()
            .file(
                "app.py",
                concat!(
                    "class Base:\n",
                    "    def assign(self):\n",
                    "        self.item = 1\n",
                    "class Child(Base):\n",
                    "    def assign_child(self):\n",
                    "        self.child_item = 1\n",
                    "def attach(target):\n",
                    "    target.extra = 1\n",
                    "    target.item = 1\n",
                ),
            )
            .build();
        let adapter = type_flow_adapter(Language::Python).expect("Python adapter");
        let cancellation = crate::analyzer::semantic::CancellationToken::new();
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace");
        let class = |name: &str| {
            ClassIdentity::Workspace(
                workspace
                    .analyzer()
                    .get_definitions(name)
                    .into_iter()
                    .next()
                    .expect("fixture class"),
            )
        };
        let base = class("app.Base");
        let child = class("app.Child");
        let cache = FieldSlotIndexCache::default();
        let cold = acquire(
            &workspace,
            adapter,
            &cache,
            &mut SemanticBudget::default(),
            &cancellation,
        )
        .expect("cold survey");
        assert_eq!(cold.kind, FieldSlotIndexAcquisitionKind::Built);
        assert!(cold.published);
        let memory = acquire(
            &workspace,
            adapter,
            &cache,
            &mut SemanticBudget::default(),
            &cancellation,
        )
        .expect("memory survey");
        assert_eq!(memory.kind, FieldSlotIndexAcquisitionKind::MemoryHit);
        let persisted = acquire(
            &workspace,
            adapter,
            &FieldSlotIndexCache::default(),
            &mut SemanticBudget::default(),
            &cancellation,
        )
        .expect("persistent survey");
        assert_eq!(persisted.kind, FieldSlotIndexAcquisitionKind::PersistentHit);
        for index in [&cold.index, &memory.index, &persisted.index] {
            assert_eq!(index.digest(), cold.index.digest());
            assert_eq!(index.store_survey, cold.index.store_survey);
            assert_eq!(
                index.member_store_evidence(&workspace, adapter, &base, "item"),
                MemberStoreEvidence::Stored
            );
            assert_eq!(
                index.member_store_evidence(&workspace, adapter, &child, "item"),
                MemberStoreEvidence::Stored
            );
            assert_eq!(
                index.member_store_evidence(&workspace, adapter, &base, "child_item"),
                MemberStoreEvidence::NoStore
            );
            assert_eq!(
                index.member_store_evidence(&workspace, adapter, &child, "extra"),
                MemberStoreEvidence::Unknown
            );
            assert_eq!(
                index.member_store_evidence(&workspace, adapter, &child, "missing"),
                MemberStoreEvidence::NoStore
            );
        }
        let mut starved = SemanticBudget::new(crate::analyzer::semantic::SemanticWork::uniform(1))
            .expect("positive budget");
        let incomplete = FieldSlotIndex::build(&workspace, adapter, &mut starved, &cancellation)
            .expect("bounded survey");
        assert_eq!(
            incomplete.member_store_evidence(&workspace, adapter, &child, "missing"),
            MemberStoreEvidence::Unknown
        );
        assert!(!incomplete.persistable);
    }

    #[test]
    fn field_slot_semantic_key_rotates_each_independent_input() {
        let project = field_slot_project();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let adapter = type_flow_adapter(Language::Python).expect("Python type-flow adapter");
        let provider = IcfgProviderBehaviorIdentity::hash_bytes(b"provider-v1");
        let baseline = field_slot_persistence_key(&workspace, adapter, provider, None)
            .expect("a git-backed workspace has a semantic key");
        assert_eq!(
            baseline.active_pack_digest,
            *active_semantic_model_pack_digest(None).as_bytes(),
            "the field-slot key and shared class-set pack identity are identical"
        );

        let changed_provider = field_slot_persistence_key(
            &workspace,
            adapter,
            IcfgProviderBehaviorIdentity::hash_bytes(b"provider-v2"),
            None,
        )
        .expect("provider change retains a key");
        assert_ne!(baseline, changed_provider);

        let changed_adapter = BlockingTypeFlowAdapter::python().with_semantics(
            crate::analyzer::semantic::AdapterSemanticsVersion::hash_bytes(
                "python-test",
                b"adapter-v2",
            )
            .expect("adapter identity is named"),
        );
        let changed_adapter =
            field_slot_persistence_key(&workspace, &changed_adapter, provider, None)
                .expect("adapter change retains a key");
        assert_ne!(baseline, changed_adapter);

        let changed_pack = field_slot_persistence_key_from_components(
            baseline.language,
            StableDigest::from_array(baseline.workspace_content_digest),
            StableDigest::from_array(baseline.provider_behavior_digest),
            StableDigest::sha256(b"different-active-pack-set"),
            StableDigest::from_array(baseline.adapter_semantics_digest),
            baseline.representation_version,
        );
        assert_ne!(baseline, changed_pack);

        let changed_representation = field_slot_persistence_key_from_components(
            baseline.language,
            StableDigest::from_array(baseline.workspace_content_digest),
            StableDigest::from_array(baseline.provider_behavior_digest),
            StableDigest::from_array(baseline.active_pack_digest),
            StableDigest::from_array(baseline.adapter_semantics_digest),
            baseline
                .representation_version
                .checked_add(1)
                .expect("test representation version increments"),
        );
        assert_ne!(baseline, changed_representation);

        project
            .file("extra.py")
            .write("class Added:\n    pass\n")
            .expect("write changed workspace content");
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let changed_content =
            field_slot_persistence_key(&changed_workspace, adapter, provider, None)
                .expect("changed workspace retains a key");
        assert_ne!(baseline, changed_content);
    }

    #[test]
    fn complete_field_slots_single_flight_builds_once_and_replays_each_callers_budget() {
        let project = field_slot_project();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace builds");
        let adapter = BlockingTypeFlowAdapter::python();
        let cache = FieldSlotIndexCache::default();
        let cancellation = crate::analyzer::semantic::CancellationToken::new();

        thread::scope(|scope| {
            let leader = scope.spawn(|| {
                let mut budget = SemanticBudget::default();
                let acquired = acquire(&workspace, &adapter, &cache, &mut budget, &cancellation)
                    .expect("leader builds field slots");
                (acquired, budget)
            });
            adapter.wait_until_blocked();
            let follower = scope.spawn(|| {
                let mut budget = SemanticBudget::default();
                let acquired = acquire(&workspace, &adapter, &cache, &mut budget, &cancellation)
                    .expect("follower receives field slots");
                (acquired, budget)
            });
            wait_for_field_slot_follower(&cache);
            adapter.release();

            let (leader, leader_budget) = leader.join().expect("leader thread");
            let (follower, follower_budget) = follower.join().expect("follower thread");
            assert_eq!(leader.kind, FieldSlotIndexAcquisitionKind::Built);
            assert_eq!(follower.kind, FieldSlotIndexAcquisitionKind::MemoryHit);
            assert!(Arc::ptr_eq(&leader.index, &follower.index));
            assert!(leader_budget.used().source_bytes > 0);
            assert_eq!(follower_budget.used().source_bytes, 0);
            assert_eq!(follower_budget.used(), artifact_census(&follower.index));
        });
    }

    #[test]
    fn field_slot_follower_cancellation_does_not_poison_leader() {
        let project = field_slot_project();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace builds");
        let adapter = BlockingTypeFlowAdapter::python();
        let cache = FieldSlotIndexCache::default();
        let leader_cancellation = crate::analyzer::semantic::CancellationToken::new();
        let follower_cancellation = crate::analyzer::semantic::CancellationToken::new();

        thread::scope(|scope| {
            let leader = scope.spawn(|| {
                let mut budget = SemanticBudget::default();
                acquire(
                    &workspace,
                    &adapter,
                    &cache,
                    &mut budget,
                    &leader_cancellation,
                )
            });
            adapter.wait_until_blocked();
            let follower = scope.spawn(|| {
                let mut budget = SemanticBudget::default();
                acquire(
                    &workspace,
                    &adapter,
                    &cache,
                    &mut budget,
                    &follower_cancellation,
                )
            });
            wait_for_field_slot_follower(&cache);
            follower_cancellation.cancel();
            let follower = follower.join().expect("follower thread");
            assert!(matches!(follower, Err(TypeFlowPlanError::Cancelled)));
            adapter.release();
            let leader = leader
                .join()
                .expect("leader thread")
                .expect("leader completes");
            assert_eq!(leader.kind, FieldSlotIndexAcquisitionKind::Built);

            let mut budget = SemanticBudget::default();
            let after = acquire(
                &workspace,
                &adapter,
                &cache,
                &mut budget,
                &leader_cancellation,
            )
            .expect("completed leader remains reusable");
            assert_eq!(after.kind, FieldSlotIndexAcquisitionKind::MemoryHit);
            assert!(Arc::ptr_eq(&leader.index, &after.index));
        });
    }

    #[test]
    fn cancelled_field_slot_leader_drops_permit_and_next_caller_rebuilds() {
        let project = field_slot_project();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace builds");
        let adapter = BlockingTypeFlowAdapter::python();
        let cache = FieldSlotIndexCache::default();
        let cancellation = crate::analyzer::semantic::CancellationToken::new();

        thread::scope(|scope| {
            let leader = scope.spawn(|| {
                let mut budget = SemanticBudget::default();
                acquire(&workspace, &adapter, &cache, &mut budget, &cancellation)
            });
            adapter.wait_until_blocked();
            cancellation.cancel();
            adapter.release();
            assert!(matches!(
                leader.join().expect("leader thread"),
                Err(TypeFlowPlanError::Cancelled)
            ));
        });

        let uncancelled = crate::analyzer::semantic::CancellationToken::new();
        let mut rebuilt_budget = SemanticBudget::default();
        let rebuilt = acquire(
            &workspace,
            &adapter,
            &cache,
            &mut rebuilt_budget,
            &uncancelled,
        )
        .expect("next caller rebuilds");
        assert_eq!(rebuilt.kind, FieldSlotIndexAcquisitionKind::Built);
        let mut replay_budget = SemanticBudget::default();
        let replayed = acquire(
            &workspace,
            &adapter,
            &cache,
            &mut replay_budget,
            &uncancelled,
        )
        .expect("rebuilt index is reusable");
        assert_eq!(replayed.kind, FieldSlotIndexAcquisitionKind::MemoryHit);
        assert!(Arc::ptr_eq(&rebuilt.index, &replayed.index));
    }

    #[test]
    fn budget_incomplete_field_slot_build_is_never_cached_or_persisted() {
        let project = field_slot_project();
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        let adapter = type_flow_adapter(Language::Python).expect("Python type-flow adapter");
        let cache = FieldSlotIndexCache::default();
        let cancellation = crate::analyzer::semantic::CancellationToken::new();
        let limits = crate::analyzer::semantic::SemanticWork::uniform(1);
        let mut starved_budget = SemanticBudget::new(limits).expect("positive semantic limits");
        let incomplete = acquire(
            &workspace,
            adapter,
            &cache,
            &mut starved_budget,
            &cancellation,
        )
        .expect("bounded build returns an honest incomplete index");
        assert_eq!(incomplete.kind, FieldSlotIndexAcquisitionKind::Built);
        assert!(incomplete.index.semantic_budget_exhausted());
        assert!(!incomplete.published);

        let mut complete_budget = SemanticBudget::default();
        let complete = acquire(
            &workspace,
            adapter,
            &cache,
            &mut complete_budget,
            &cancellation,
        )
        .expect("adequate caller rebuilds");
        assert_eq!(complete.kind, FieldSlotIndexAcquisitionKind::Built);
        assert!(complete.published);

        let mut replay_budget = SemanticBudget::default();
        let replayed = acquire(
            &workspace,
            adapter,
            &cache,
            &mut replay_budget,
            &cancellation,
        )
        .expect("complete rebuild is reusable");
        assert_eq!(replayed.kind, FieldSlotIndexAcquisitionKind::MemoryHit);
    }

    #[test]
    fn resolver_budget_incomplete_field_slots_are_never_cached_or_persisted() {
        let project = field_slot_project();
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        let adapter = BlockingTypeFlowAdapter::python()
            .with_constructed_seed(ClassSeed::Unknown(UnknownReason::SemanticBudget))
            .without_hierarchy_block()
            .with_semantics(
                crate::analyzer::semantic::AdapterSemanticsVersion::hash_bytes(
                    "python-semantic-budget-seed-test",
                    b"v1",
                )
                .expect("test adapter identity is named"),
            );
        let cache = FieldSlotIndexCache::default();
        let cancellation = crate::analyzer::semantic::CancellationToken::new();

        for _ in 0..2 {
            let mut budget = SemanticBudget::default();
            let acquired = acquire(&workspace, &adapter, &cache, &mut budget, &cancellation)
                .expect("resolver-budget classification returns an honest incomplete index");
            assert_eq!(acquired.kind, FieldSlotIndexAcquisitionKind::Built);
            assert!(!acquired.published);
            assert!(!acquired.index.persistable);
            assert!(acquired.index.semantic_budget_exhausted());
            assert_eq!(acquired.index.semantic_budget_exhaustion(), None);
            assert!(acquired.index.slots().iter().any(|slot| {
                slot.atoms.iter().any(|(atom, _)| {
                    matches!(atom, ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete))
                })
            }));
        }

        let key = field_slot_persistence_key(
            &workspace,
            &adapter,
            WorkspaceIcfgProvider::new(&workspace).behavior_identity(),
            None,
        )
        .expect("persisted workspace has a field-slot key");
        assert!(
            workspace
                .store()
                .expect("persisted workspace has a store")
                .class_set_field_slot_index(&key, &cancellation)
                .expect("field-slot lookup succeeds")
                .is_none()
        );
    }

    #[test]
    fn field_slot_winner_published_during_incomplete_acquisition_is_recovered() {
        let project = field_slot_project();
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        let adapter = type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
        let provider = WorkspaceIcfgProvider::new(&workspace).behavior_identity();
        let key = field_slot_persistence_key(&workspace, adapter, provider, None)
            .expect("a git-backed workspace has a semantic key");
        let cancellation = crate::analyzer::semantic::CancellationToken::new();
        let mut winner_build_budget = SemanticBudget::default();
        let winner =
            FieldSlotIndex::build(&workspace, adapter, &mut winner_build_budget, &cancellation)
                .expect("complete winner builds");
        let winner_row = winner
            .to_persisted(key.clone())
            .expect("winner encodes")
            .expect("winner is persistable");
        let store = workspace.store().expect("persisted workspace has a store");
        assert!(
            store
                .class_set_field_slot_index(&key, &cancellation)
                .expect("initial lookup succeeds")
                .is_none(),
            "the recovery window starts with an exact key miss"
        );

        let local_oracle = BlockingTypeFlowAdapter::python()
            .with_constructed_seed(ClassSeed::Unknown(UnknownReason::SemanticBudget))
            .without_hierarchy_block();
        let mut local_oracle_budget = SemanticBudget::default();
        let local_oracle_index = FieldSlotIndex::build(
            &workspace,
            &local_oracle,
            &mut local_oracle_budget,
            &cancellation,
        )
        .expect("nonblocking incomplete oracle builds");
        assert!(!local_oracle_index.persistable);

        let blocking = BlockingTypeFlowAdapter::python()
            .with_constructed_seed(ClassSeed::Unknown(UnknownReason::SemanticBudget));
        let cache = FieldSlotIndexCache::default();
        thread::scope(|scope| {
            let builder = scope.spawn(|| {
                let mut local_budget = SemanticBudget::default();
                let recovered = FieldSlotIndex::acquire(
                    &workspace,
                    &blocking,
                    provider,
                    None,
                    &cache,
                    &mut local_budget,
                    &cancellation,
                )
                .expect("post-build recovery succeeds");
                (recovered, local_budget)
            });

            blocking.wait_until_blocked();
            assert!(
                store
                    .publish_class_set_field_slot_index(winner_row, &cancellation)
                    .expect("concurrent winner publishes")
            );
            blocking.release();

            let (recovered, recovered_budget) = builder.join().expect("local builder thread");
            assert_eq!(recovered.kind, FieldSlotIndexAcquisitionKind::Built);
            assert_eq!(
                recovered.miss_reason,
                Some(FieldSlotIndexMissReason::KeyMiss)
            );
            assert!(!recovered.published);
            assert_eq!(recovered.index.slots(), winner.slots());
            assert!(recovered.index.persistable);
            assert_eq!(
                recovered_budget
                    .used()
                    .component_max(local_oracle_budget.used()),
                recovered_budget.used(),
                "recovery retains the local build and hydration charges"
            );
            assert_eq!(
                recovered_budget.used().procedures,
                local_oracle_budget.used().procedures,
                "already-paid artifact censuses are not charged twice"
            );
            assert_eq!(
                recovered_budget.used().nested_entries,
                local_oracle_budget
                    .used()
                    .nested_entries
                    .saturating_add(recovered.index.persistent_artifacts.len()),
                "winner hydration charges one repeat hit per paid artifact"
            );

            let mut replay_budget = SemanticBudget::default();
            let replayed = acquire(
                &workspace,
                &blocking,
                &cache,
                &mut replay_budget,
                &cancellation,
            )
            .expect("recovered winner is reusable in memory");
            assert_eq!(replayed.kind, FieldSlotIndexAcquisitionKind::MemoryHit);
            assert!(Arc::ptr_eq(&recovered.index, &replayed.index));
        });
    }

    #[test]
    fn ephemeral_field_slots_reuse_memory_without_durable_store() {
        let project = field_slot_project();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace builds");
        let adapter = type_flow_adapter(Language::Python).expect("Python type-flow adapter");
        let cache = FieldSlotIndexCache::default();
        let cancellation = crate::analyzer::semantic::CancellationToken::new();

        let mut cold_budget = SemanticBudget::default();
        let cold = acquire(&workspace, adapter, &cache, &mut cold_budget, &cancellation)
            .expect("ephemeral index builds");
        assert_eq!(cold.kind, FieldSlotIndexAcquisitionKind::Built);
        assert_eq!(
            cold.miss_reason,
            Some(FieldSlotIndexMissReason::NoPersistentStore)
        );
        assert!(!cold.published);

        let mut warm_budget = SemanticBudget::default();
        let warm = acquire(&workspace, adapter, &cache, &mut warm_budget, &cancellation)
            .expect("ephemeral index reuses memory");
        assert_eq!(warm.kind, FieldSlotIndexAcquisitionKind::MemoryHit);
        assert_eq!(warm.miss_reason, None);
        assert!(!warm.published);
        assert!(Arc::ptr_eq(&cold.index, &warm.index));
        assert_eq!(cold.index.digest(), warm.index.digest());
        assert_eq!(warm_budget.used(), artifact_census(&warm.index));
    }

    #[test]
    fn complete_field_slots_reuse_across_persisted_workspace_instances() {
        let project = field_slot_project();
        let adapter = type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
        let cancellation = crate::analyzer::semantic::CancellationToken::new();
        let cache = FieldSlotIndexCache::default();

        let cold_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("cold persisted workspace builds");
        let cold_behavior = WorkspaceIcfgProvider::new(&cold_workspace).behavior_identity();
        let mut cold_budget = SemanticBudget::default();
        let cold = FieldSlotIndex::acquire(
            &cold_workspace,
            adapter,
            cold_behavior,
            None,
            &cache,
            &mut cold_budget,
            &cancellation,
        )
        .expect("cold field-slot index builds");
        assert_eq!(cold.kind, FieldSlotIndexAcquisitionKind::Built);
        assert_eq!(cold.miss_reason, Some(FieldSlotIndexMissReason::KeyMiss));
        assert!(cold.published);
        assert!(!cold.index.slots().is_empty());
        drop(cold_workspace);

        let warm_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("warm persisted workspace builds");
        let warm_behavior = WorkspaceIcfgProvider::new(&warm_workspace).behavior_identity();
        assert_eq!(cold_behavior, warm_behavior);
        let mut warm_budget = SemanticBudget::default();
        let warm_cache = FieldSlotIndexCache::default();
        let warm = FieldSlotIndex::acquire(
            &warm_workspace,
            adapter,
            warm_behavior,
            None,
            &warm_cache,
            &mut warm_budget,
            &cancellation,
        )
        .expect("warm field-slot index loads");
        assert_eq!(warm.kind, FieldSlotIndexAcquisitionKind::PersistentHit);
        assert_eq!(warm.miss_reason, None);
        assert!(!warm.published);
        assert_eq!(warm.index.slots(), cold.index.slots());
        assert_eq!(warm.index.digest(), cold.index.digest());
        let artifact_census = artifact_census(&cold.index);
        assert_eq!(
            crate::analyzer::semantic::SemanticWork {
                source_bytes: 0,
                ..warm_budget.used()
            },
            artifact_census
        );
        assert_eq!(
            warm_budget.used().source_bytes,
            cold_budget.used().source_bytes
        );
    }

    #[test]
    fn independent_prewarm_states_build_and_publish_one_identical_field_slot_dto() {
        fn prewarm(workspace: &WorkspaceAnalyzer, project: &BuiltInlineTestProject) {
            let mut budget = SemanticBudget::default();
            let cancellation = crate::analyzer::semantic::CancellationToken::new();
            let outcome = workspace
                .materialize_program_semantics(
                    &project.file("app.py"),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("prewarming program semantics succeeds");
            assert!(outcome.is_complete(), "{outcome:#?}");
        }

        fn build_row(workspace: &WorkspaceAnalyzer) -> ClassSetFieldSlotIndexRow {
            let adapter =
                type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
            let provider_behavior = WorkspaceIcfgProvider::new(workspace).behavior_identity();
            let key = field_slot_persistence_key(workspace, adapter, provider_behavior, None)
                .expect("a persisted workspace has an exact field-slot key");
            let cancellation = crate::analyzer::semantic::CancellationToken::new();
            let mut budget = SemanticBudget::default();
            let index = FieldSlotIndex::build(workspace, adapter, &mut budget, &cancellation)
                .expect("complete field slots build");
            assert!(index.persistable);
            index
                .to_persisted(key)
                .expect("field-slot DTO encoding succeeds")
                .expect("the complete portable index has a DTO")
        }

        let project = field_slot_project();
        let cold_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("cold persisted workspace builds");
        let once_prewarmed_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("once-prewarmed persisted workspace builds");
        prewarm(&once_prewarmed_workspace, &project);
        let hit_prewarmed_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("hit-prewarmed persisted workspace builds");
        prewarm(&hit_prewarmed_workspace, &project);
        prewarm(&hit_prewarmed_workspace, &project);

        let rows = [
            build_row(&cold_workspace),
            build_row(&once_prewarmed_workspace),
            build_row(&hit_prewarmed_workspace),
        ];
        assert_eq!(rows[0], rows[1], "one prewarm must not change the DTO");
        assert_eq!(rows[0], rows[2], "a cache hit must not change the DTO");

        let path = brokk_bifrost_core::gitblob::cache_db_path(project.root());
        let stores = [
            crate::analyzer::store::AnalyzerStore::open_persistent(&path)
                .expect("first independent store opens"),
            crate::analyzer::store::AnalyzerStore::open_persistent(&path)
                .expect("second independent store opens"),
            crate::analyzer::store::AnalyzerStore::open_persistent(&path)
                .expect("third independent store opens"),
        ];
        let barrier = Arc::new(Barrier::new(stores.len()));
        let mut publications = thread::scope(|scope| {
            stores
                .into_iter()
                .zip(rows.iter().cloned())
                .map(|(store, row)| {
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        store
                            .publish_class_set_field_slot_index(
                                row,
                                &crate::analyzer::semantic::CancellationToken::new(),
                            )
                            .expect("identical concurrent publication succeeds")
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("publication thread completes"))
                .collect::<Vec<_>>()
        });
        publications.sort_unstable();
        assert_eq!(publications, [false, false, true]);

        let store = crate::analyzer::store::AnalyzerStore::open_persistent(&path)
            .expect("verification store opens");
        assert_eq!(
            store
                .class_set_field_slot_index(
                    &rows[0].key,
                    &crate::analyzer::semantic::CancellationToken::new(),
                )
                .expect("published DTO loads"),
            Some(rows[0].clone())
        );
    }

    #[test]
    fn persisted_field_slots_remount_into_an_equivalent_checkout_root() {
        let cold_project = field_slot_project();
        let warm_project = field_slot_project();
        assert_ne!(cold_project.root(), warm_project.root());
        let adapter = type_flow_adapter(Language::Python).expect("Python type-flow adapter");
        let cancellation = crate::analyzer::semantic::CancellationToken::new();

        let cold_workspace = WorkspaceAnalyzer::build_persisted(
            cold_project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("cold persisted workspace builds");
        let mut cold_budget = SemanticBudget::default();
        let cold = acquire(
            &cold_workspace,
            adapter,
            &FieldSlotIndexCache::default(),
            &mut cold_budget,
            &cancellation,
        )
        .expect("cold field-slot index builds");
        assert_eq!(cold.kind, FieldSlotIndexAcquisitionKind::Built);
        assert!(cold.published);
        drop(cold_workspace);

        copy_persisted_store(cold_project.root(), warm_project.root());
        let warm_workspace = WorkspaceAnalyzer::build_persisted(
            warm_project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("equivalent checkout opens the copied store");
        let mut warm_budget = SemanticBudget::default();
        let warm = acquire(
            &warm_workspace,
            adapter,
            &FieldSlotIndexCache::default(),
            &mut warm_budget,
            &cancellation,
        )
        .expect("equivalent checkout hydrates field slots");
        assert_eq!(warm.kind, FieldSlotIndexAcquisitionKind::PersistentHit);
        assert_eq!(warm.index.digest(), cold.index.digest());
        assert_eq!(warm.index.slots().len(), cold.index.slots().len());

        let mut mounted_workspace_classes = 0usize;
        let mut mounted_sources = 0usize;
        for slot in warm.index.slots() {
            if let ClassIdentity::Workspace(class) = &slot.class {
                mounted_workspace_classes = mounted_workspace_classes.saturating_add(1);
                assert_eq!(class.source().root(), warm_project.root());
            }
            for (atom, source) in &slot.atoms {
                mounted_sources = mounted_sources.saturating_add(1);
                assert_eq!(source.file.root(), warm_project.root());
                if let ClassAtom::Class(ClassIdentity::Workspace(class)) = atom {
                    mounted_workspace_classes = mounted_workspace_classes.saturating_add(1);
                    assert_eq!(class.source().root(), warm_project.root());
                }
            }
        }
        assert!(mounted_workspace_classes > 0);
        assert!(mounted_sources > 0);
    }

    #[test]
    fn persisted_replay_budget_refusal_is_atomic_and_does_not_fill_the_ready_cache() {
        let project = field_slot_project();
        let adapter = type_flow_adapter(Language::Python).expect("Python type-flow adapter");
        let cancellation = crate::analyzer::semantic::CancellationToken::new();
        let cold_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("cold persisted workspace builds");
        let mut cold_budget = SemanticBudget::default();
        let cold = acquire(
            &cold_workspace,
            adapter,
            &FieldSlotIndexCache::default(),
            &mut cold_budget,
            &cancellation,
        )
        .expect("cold field-slot index builds");
        assert!(cold.published);
        drop(cold_workspace);

        let warm_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("warm persisted workspace builds");
        let cache = FieldSlotIndexCache::default();
        let limits = crate::analyzer::semantic::SemanticWork::uniform(1);
        let mut refused_budget = SemanticBudget::new(limits).expect("positive semantic limits");
        let refused = acquire(
            &warm_workspace,
            adapter,
            &cache,
            &mut refused_budget,
            &cancellation,
        )
        .expect("replay refusal falls back to an honest bounded build");
        assert_eq!(refused.kind, FieldSlotIndexAcquisitionKind::Built);
        assert_eq!(
            refused.miss_reason,
            Some(FieldSlotIndexMissReason::PersistenceReplayBudget)
        );
        assert!(refused.index.semantic_budget_exhausted());
        assert!(!refused.published);

        let direct_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("comparison workspace builds");
        let mut direct_budget = SemanticBudget::new(limits).expect("positive semantic limits");
        let direct = FieldSlotIndex::build(
            &direct_workspace,
            adapter,
            &mut direct_budget,
            &cancellation,
        )
        .expect("direct bounded build completes honestly");
        assert!(direct.semantic_budget_exhausted());
        assert_eq!(
            refused_budget.used(),
            direct_budget.used(),
            "failed replay charges stay staged; only fallback work reaches the caller"
        );

        let mut adequate_budget = SemanticBudget::default();
        let adequate = acquire(
            &warm_workspace,
            adapter,
            &cache,
            &mut adequate_budget,
            &cancellation,
        )
        .expect("an adequate caller can still hydrate the durable row");
        assert_eq!(adequate.kind, FieldSlotIndexAcquisitionKind::PersistentHit);
        assert_eq!(adequate.miss_reason, None);
    }

    #[test]
    fn operational_store_failure_is_typed_and_does_not_fill_the_ready_cache() {
        let project = field_slot_project();
        let adapter = type_flow_adapter(Language::Python).expect("Python type-flow adapter");
        let cancellation = crate::analyzer::semantic::CancellationToken::new();
        let cold_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("cold persisted workspace builds");
        let mut cold_budget = SemanticBudget::default();
        let cold = acquire(
            &cold_workspace,
            adapter,
            &FieldSlotIndexCache::default(),
            &mut cold_budget,
            &cancellation,
        )
        .expect("cold field-slot index builds");
        assert!(cold.published);
        drop(cold_workspace);

        let warm_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("warm persisted workspace builds");
        let store = warm_workspace
            .store()
            .expect("persisted workspace has a store");
        store.set_class_set_field_slot_operational_failure_for_test(true);
        let cache = FieldSlotIndexCache::default();
        let mut failed_budget = SemanticBudget::default();
        let failed = acquire(
            &warm_workspace,
            adapter,
            &cache,
            &mut failed_budget,
            &cancellation,
        )
        .expect("an operational store failure falls back to a fresh index");
        assert_eq!(failed.kind, FieldSlotIndexAcquisitionKind::Built);
        assert_eq!(
            failed.miss_reason,
            Some(FieldSlotIndexMissReason::StoreFailure)
        );
        assert!(!failed.published);

        store.set_class_set_field_slot_operational_failure_for_test(false);
        let mut recovered_budget = SemanticBudget::default();
        let recovered = acquire(
            &warm_workspace,
            adapter,
            &cache,
            &mut recovered_budget,
            &cancellation,
        )
        .expect("the durable index remains available after the operational failure");
        assert_eq!(recovered.kind, FieldSlotIndexAcquisitionKind::PersistentHit);
        assert_eq!(recovered.miss_reason, None);
        assert_eq!(recovered.index.digest(), failed.index.digest());
    }

    #[test]
    fn public_workspace_solve_publishes_the_field_slot_index() {
        let project = InlineTestProject::with_language(Language::Python)
            .with_git()
            .file(
                "app.py",
                concat!(
                    "class Stored:\n",
                    "    pass\n",
                    "\n",
                    "class Box:\n",
                    "    def __init__(self):\n",
                    "        self.value = Stored()\n",
                    "\n",
                    "    def read(self):\n",
                    "        return self.value\n",
                ),
            )
            .build();
        let cancellation = crate::analyzer::semantic::CancellationToken::new();
        let cold_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("cold persisted workspace builds");
        solve_type_flow_workspace(
            &cold_workspace,
            ClosureLimits { max_procedures: 64 },
            SolverBudget::default(),
            &cancellation,
        )
        .expect("the public workspace solve completes");
        drop(cold_workspace);

        let warm_workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("warm persisted workspace builds");
        let adapter = type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
        let provider = WorkspaceIcfgProvider::new(&warm_workspace);
        let mut warm_budget = SemanticBudget::default();
        let warm = FieldSlotIndex::acquire(
            &warm_workspace,
            adapter,
            provider.behavior_identity(),
            None,
            &FieldSlotIndexCache::default(),
            &mut warm_budget,
            &cancellation,
        )
        .expect("the public workspace solve published its field-slot index");
        assert_eq!(warm.kind, FieldSlotIndexAcquisitionKind::PersistentHit);
    }
}
