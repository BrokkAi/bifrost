//! Whole-operation selected resolution over persisted and transient facts.
//!
//! This owner assembles one immutable native attempt, drops every borrowing
//! source/session, and then revalidates both the retained database inventory
//! and the live overlay generation before authorizing publication. It holds no
//! lease after return: `Current` is authorization at that final boundary, not
//! a long transaction or workspace lock.

pub(super) mod go_context;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use go_context::GoDotImportContext;
pub(super) mod go_named;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use go_named::{GoExternalPackageProvenance, GoSelectedExternalImport};
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod go_reverse_rows;
pub(super) mod go_same_package;
mod java_access;
mod java_demand;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod java_reverse_rows;
pub(super) mod jvm_context;
mod source_demand;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use jvm_context::{JavaExternalStaticImportBoundary, JavaImportContext};
pub(super) mod native_units;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use native_units::{
    SelectedNativeDefinition, SelectedNativeDefinitions, SelectedNativeReferenceTypes,
    SelectedNativeReferenceUnits, SelectedNativeTypes,
};
pub(super) mod package_context;
pub(super) mod rust_crate_access;
pub(super) mod rust_crate_context;
use super::resolution_stage::SelectedResolutionStageOutcome;
use crate::analyzer::resolution::SeamProfiled;
#[cfg(test)]
pub(crate) use rust_crate_context::{
    reset_rust_context_bridge_peak_for_test, rust_context_bridge_peak_for_test,
};
pub(super) mod rust_crate_rows;
mod rust_demand;
use rust_demand::forward::{ForwardProvider, PreparedForwardSource, RustDemandPreparation};
use rust_demand::relations::{ClosedForwardSource, ClosedRelations};
mod rust_forward;
mod rust_graph;
mod rust_prefix;
mod rust_privacy;
mod rust_reverse;
pub(super) mod rust_reverse_rows;
use rust_prefix::RustPrefixResolutionBatch;
pub(crate) use rust_prefix::{resolve_rust_type_prefixes, rust_qualified_prefix};
pub(crate) use rust_reverse_rows::RustReverseConfirmation;
// The planner-statistics pin that shares this builder with the bounded reader
// lives in a test-support module, so the re-export follows that gate.
#[cfg(any(test, feature = "test-support"))]
pub(crate) use rust_privacy::selected_rust_declaration_authority_sql;
pub(crate) use rust_privacy::{
    RustSelectedDeclarationAuthorityFact,
    read_selected_rust_declaration_authority_with_cancellation,
};
pub(crate) use rust_reverse::{
    SelectedRustReverseBatchOutcome, SelectedRustReverseQueries, SelectedRustTargetReferences,
};

use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionNamespace, ResolutionRootImportAnchor, ResolutionScopeId, ResolutionSiteId,
    ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::rust_facts;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustDeclarationPropertyFact, RustSourceContextKind, RustUsageFacts,
};
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclarationId, SourceOccurrenceId, SourceOccurrenceProvenance,
};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_rust::selected_context::{
    RustSelectedBuildOutcome, RustSelectedContext, RustSelectedContextGap,
    RustSelectedDeclarationAuthority, RustSelectedDependencyEdge, RustSelectedRootBridge,
    RustSelectedRootBridgeTopology, RustSelectedRootRoute, RustSelectedTargetMembership,
};
use rusqlite::OptionalExtension;

use crate::CancellationToken;
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE;
#[cfg(test)]
use crate::analyzer::resolution::SelectedNodeProvenance;
use crate::analyzer::resolution::{
    BatchResolutionFragmentSource, BindingFragmentId, BindingNodeId, CandidatePathIdentity,
    FactDemandResolution, FactPageVisitor, FactReferenceBatchAnswer, FactReferenceSiteMetadata,
    FactResolutionAnswer, FactResolutionBatchSummary, FactReverseResolutionMetrics,
    LoweredRustDeclarationAuthority, LoweredRustReferenceContext, LoweredSemanticRole,
    MAX_REFERENCE_SEEDS_PER_BATCH, MAX_SOURCE_ROWS_PER_BATCH, MAX_TYPED_FACT_REQUESTS_PER_BATCH,
    ReferenceSearchAnswer, ResolutionBatchMetrics, ResolutionCompletion,
    ResolutionIncompleteReason, ResolutionLocalKey, ResolutionLookupSemanticRecipe,
    ResolutionQuery, RustDeclarationContextSource, RustReferenceContextSource,
    SelectedContextIdentities, SelectedFactOperationBlueprint,
    SelectedFactOperationBlueprintConstruction, SelectedResolutionContextInputs,
    SelectedResolutionContextSet, SelectedResolutionContextValidationOutcome,
    SelectedResolutionMountContext, SelectedResolutionMountOrdinal, SelectedRootBridgeDescriptor,
    SelectedRootPathHalf, SelectedSemanticLocator, SelectedSemanticMount,
    SelectedSemanticProvenance, SelectedTypedFactSource, SelectedTypedRow, SemanticId,
    TypedFactRequest, classify_selected_root_path_half, visit_selected_root_export_half_pages,
    visit_selected_root_import_half_pages,
};
use crate::analyzer::{CodeUnit, Project, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};

use super::resolution_lexical::{
    SelectedLookupRecipeReadOutcome, SelectedLookupRecipeRequest, SelectedResolutionLexicalSource,
    SelectedSemanticLookupOutcome,
};
use super::resolution_selection::{
    SelectedResolutionContentMountRequest, SelectedResolutionLanguage,
    SelectedResolutionMountInventory, SelectedResolutionMountInventoryOutcome,
    SelectedResolutionOverlayAuthority, SelectedResolutionOverlayIntent,
    SelectedResolutionOverlayMask, SelectedResolutionRevalidationOutcome, SelectedResolutionStale,
    SelectedResolutionUnavailable,
};
use super::resolution_typed::SelectedResolutionTypedSource;
use super::selected_definition::{
    SelectedDeclarationDefinition, SelectedDefinitionSemanticReadOutcome,
    SelectedDefinitionUnitReadOutcome, SelectedLexicalDefinitionReadOutcome,
};
use super::{AnalyzerStore, Result, StoreError, WorkspaceId, WorkspaceSnapshots};

/// Project only the compact source identities required by transient Rust
/// reference-context reads. The parsed source facts remain producer-owned;
/// resolution retains no source arena or parallel range extraction.
pub(crate) fn rust_reference_context_sources(
    source_facts: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<Vec<RustReferenceContextSource>> {
    #[derive(Debug, Clone, Copy)]
    struct ModuleRange {
        context: SourceOccurrenceId,
        declaration: Option<SourceDeclarationId>,
        start: usize,
        end: usize,
    }

    let mut modules = Vec::new();
    for context in &source_facts.rust_items.contexts {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Rust reference context projection cancelled",
            ));
        }
        if !matches!(
            context.kind,
            RustSourceContextKind::FileRoot | RustSourceContextKind::Module
        ) {
            continue;
        }
        let occurrence = source_facts
            .occurrences
            .occurrences()
            .get(context.context.index())
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "Rust source context names missing occurrence: context={:?}",
                    context.context
                ))
            })?;
        if occurrence.provenance != SourceOccurrenceProvenance::PrimaryNode {
            continue;
        }
        modules.push(ModuleRange {
            context: context.context,
            declaration: context.owner,
            start: occurrence.range.start_byte,
            end: occurrence.range.end_byte,
        });
    }
    modules.sort_unstable_by_key(|module| {
        (
            module.start,
            std::cmp::Reverse(module.end),
            module.context.get(),
        )
    });

    let mut sites = source_facts
        .native_site_occurrences
        .iter()
        .copied()
        .enumerate()
        .collect::<Vec<_>>();
    sites.sort_unstable_by_key(|(_, occurrence)| {
        source_facts
            .occurrences
            .occurrences()
            .get(occurrence.index())
            .map_or((usize::MAX, usize::MAX, occurrence.get()), |row| {
                (row.range.start_byte, row.range.end_byte, occurrence.get())
            })
    });

    let mut cfg_regions = source_facts
        .rust_declaration_properties
        .iter()
        .map(|property| {
            let declaration = source_facts.occurrences.declaration(property.declaration);
            let occurrence = source_facts.occurrences.occurrence(declaration.occurrence);
            (
                occurrence.range.start_byte,
                occurrence.range.end_byte,
                &property.cfg_condition,
            )
        })
        .collect::<Vec<_>>();
    cfg_regions.sort_unstable_by_key(|(start, end, _)| (*start, std::cmp::Reverse(*end)));
    let mut cfg_regions = cfg_regions.into_iter().peekable();
    let mut cfg_stack = Vec::new();
    let mut projected = Vec::with_capacity(sites.len());
    let mut next_module = 0usize;
    let mut containing_modules = Vec::<ModuleRange>::new();
    for (site_index, source_occurrence) in sites {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Rust reference context projection cancelled",
            ));
        }
        let reference = source_facts
            .occurrences
            .occurrences()
            .get(source_occurrence.index())
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "Rust native site names missing occurrence: site={}, occurrence={source_occurrence:?}",
                    site_index
                ))
            })?;
        let matched_macro_fragment = reference.provenance == SourceOccurrenceProvenance::Embedded
            && source_facts.rust_items.macros.iter().any(|invocation| {
                let occurrence = source_facts.occurrences.occurrence(invocation.invocation);
                occurrence.provenance == SourceOccurrenceProvenance::PrimaryNode
                    && occurrence.range.start_byte <= reference.range.start_byte
                    && reference.range.end_byte <= occurrence.range.end_byte
            });
        let macro_definition_fragment = reference.provenance
            == SourceOccurrenceProvenance::Embedded
            && source_facts
                .rust_items
                .macro_definitions
                .iter()
                .any(|definition| {
                    let declaration = source_facts.occurrences.declaration(definition.declaration);
                    let occurrence = source_facts.occurrences.occurrence(declaration.occurrence);
                    occurrence.provenance == SourceOccurrenceProvenance::PrimaryNode
                        && occurrence.range.start_byte <= reference.range.start_byte
                        && reference.range.end_byte <= occurrence.range.end_byte
                });
        if !matches!(
            reference.provenance,
            SourceOccurrenceProvenance::PrimaryNode | SourceOccurrenceProvenance::ExplicitSubspan
        ) && !matched_macro_fragment
            && !macro_definition_fragment
        {
            return Err(StoreError::corrupt(format!(
                "Rust native reference has neither primary nor macro fragment provenance: site={}, occurrence={source_occurrence:?}, provenance={:?}",
                site_index, reference.provenance
            )));
        }
        while let Some(module) = modules.get(next_module).copied() {
            if module.start > reference.range.start_byte {
                break;
            }
            while containing_modules
                .last()
                .is_some_and(|parent| parent.end <= module.start)
            {
                containing_modules.pop();
            }
            if let Some(parent) = containing_modules.last()
                && parent.end < module.end
            {
                return Err(StoreError::corrupt(format!(
                    "Rust Module/FileRoot contexts cross instead of nesting: parent={parent:?}, child={module:?}"
                )));
            }
            containing_modules.push(module);
            next_module += 1;
        }
        while containing_modules
            .last()
            .is_some_and(|module| module.end < reference.range.end_byte)
        {
            containing_modules.pop();
        }
        let module = containing_modules.last().ok_or_else(|| {
            StoreError::corrupt(format!(
                "Rust native reference has no containing Module/FileRoot context: site={}, occurrence={source_occurrence:?}, range={:?}",
                site_index, reference.range
            ))
        })?;
        while cfg_regions
            .peek()
            .is_some_and(|(start, _, _)| *start <= reference.range.start_byte)
        {
            let region = cfg_regions.next().expect("peeked cfg region");
            while cfg_stack.last().is_some_and(|(_, end, _)| *end <= region.0) {
                cfg_stack.pop();
            }
            cfg_stack.push(region);
        }
        while cfg_stack
            .last()
            .is_some_and(|(_, end, _)| *end < reference.range.end_byte)
        {
            cfg_stack.pop();
        }
        let cfg_condition = cfg_stack.last().map_or(
            brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always,
            |(_, _, condition)| (*condition).clone(),
        );
        projected.push(
            RustReferenceContextSource::new(
                ResolutionSiteId::new(
                    u32::try_from(site_index)
                        .map_err(|_| StoreError::corrupt("Rust native site index exceeds u32"))?,
                ),
                source_occurrence,
                module.context,
                module.declaration,
            )
            .with_cfg_condition(cfg_condition),
        );
    }
    projected.sort_unstable_by_key(|source| source.source_site());
    Ok(projected)
}

/// Project declaring modules from canonical item context parents. A module
/// declaration belongs to its parent, never to the module that it introduces.
pub(crate) fn rust_declaration_context_sources(
    source_facts: &ParsedSourceFacts,
    bridges: &[(ResolutionSiteId, SourceDeclarationId)],
    cancellation: &CancellationToken,
) -> Result<Vec<RustDeclarationContextSource>> {
    let mut contexts = HashMap::default();
    let mut declaring_contexts = HashMap::default();
    for context in &source_facts.rust_items.contexts {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Rust declaration context projection cancelled",
            ));
        }
        assert!(contexts.insert(context.context, context).is_none());
        if let Some(owner) = context.owner {
            let parent = context.parent.expect("an owned Rust context has a parent");
            assert!(declaring_contexts.insert(owner, parent).is_none());
        }
    }
    for (declaration, context) in source_facts
        .rust_items
        .callables
        .iter()
        .map(|item| (item.declaration, item.context))
        .chain(
            source_facts
                .rust_items
                .aliases
                .iter()
                .map(|item| (item.declaration, item.context)),
        )
        .chain(
            source_facts
                .rust_items
                .values
                .iter()
                .map(|item| (item.declaration, item.context)),
        )
    {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Rust declaration context projection cancelled",
            ));
        }
        if let Some(previous) = declaring_contexts.insert(declaration, context) {
            assert_eq!(
                previous, context,
                "Rust item and owned context agree on their parent"
            );
        }
    }
    let mut module_by_context = HashMap::default();
    let mut projected = Vec::with_capacity(bridges.len());
    for &(source_site, declaration) in bridges {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "Rust declaration context projection cancelled",
            ));
        }
        let occurrence = source_facts.occurrences.declaration(declaration).occurrence;
        let start = if let Some(&start) = declaring_contexts.get(&declaration) {
            start
        } else {
            if !source_facts
                .rust_declaration_properties
                .iter()
                .any(|property| property.declaration == declaration)
            {
                // Pattern/local declarations do not have item access authority.
                continue;
            }
            // Only this fallback compares the declaration's own range against
            // the primary contexts that might contain it, so only here does its
            // occurrence have to be one of them. A declaration replay made for
            // an item inside a macro invocation has an `Embedded` occurrence by
            // construction and reaches the branch above instead, with the
            // declaring context replay recorded for it.
            if source_facts.occurrences.occurrence(occurrence).provenance
                != SourceOccurrenceProvenance::PrimaryNode
            {
                return Err(StoreError::corrupt(format!(
                    "Rust declaration access requires a primary occurrence: declaration={declaration}, occurrence={occurrence}"
                )));
            }
            let range = source_facts.occurrences.occurrence(occurrence).range;
            contexts
                .values()
                .filter(|context| {
                    matches!(
                        context.kind,
                        RustSourceContextKind::FileRoot | RustSourceContextKind::Module
                    )
                })
                .filter_map(|context| {
                    let enclosing = source_facts.occurrences.occurrence(context.context);
                    (enclosing.provenance == SourceOccurrenceProvenance::PrimaryNode
                        && enclosing.range.start_byte <= range.start_byte
                        && range.end_byte <= enclosing.range.end_byte)
                        .then_some((
                            enclosing.range.end_byte - enclosing.range.start_byte,
                            context.context,
                        ))
                })
                .min_by_key(|(size, _)| *size)
                .expect("primary item has a containing module")
                .1
        };
        let mut current = start;
        let mut traversed = HashSet::default();
        let module = loop {
            if cancellation.is_cancelled() {
                return Err(StoreError::new(
                    "Rust declaration context projection cancelled",
                ));
            }
            if let Some(&module) = module_by_context.get(&current) {
                break module;
            }
            if !traversed.insert(current) {
                return Err(StoreError::corrupt(format!(
                    "Rust declaration context ancestry cycles: declaration={declaration}, contexts={traversed:?}"
                )));
            }
            let context = contexts.get(&current).ok_or_else(|| StoreError::corrupt(format!(
                "Rust declaration context ancestry is missing: declaration={declaration}, context={current}"
            )))?;
            // A file root with a parent is the root declaration replay parsed
            // for one item-macro invocation, a child of the context the
            // invocation is written in. It is not a module: the items the
            // expansion declares belong to the module that contains the
            // invocation, so the walk continues through it.
            let module_boundary = match context.kind {
                RustSourceContextKind::Module => true,
                RustSourceContextKind::FileRoot => context.parent.is_none(),
                _ => false,
            };
            if module_boundary {
                break (context.context, context.owner);
            }
            current = context.parent.ok_or_else(|| StoreError::corrupt(format!(
                "Rust declaration context has no module ancestor: declaration={declaration}, context={current}"
            )))?;
        };
        for context in traversed {
            if cancellation.is_cancelled() {
                return Err(StoreError::new(
                    "Rust declaration context projection cancelled",
                ));
            }
            module_by_context.insert(context, module);
        }
        // A module boundary is the file root, which is primary, or a `mod`
        // with a body. The latter may be one an item macro's expansion
        // declares (`plain! { pub mod m { .. } }`): declaration replay gives
        // it an embedded occurrence and its own module declaration, and the
        // module sources give it a scope, so it is placed like any inline
        // module and its declaration names it.
        if source_facts.occurrences.occurrence(module.0).provenance
            != SourceOccurrenceProvenance::PrimaryNode
            && module.1.is_none()
        {
            return Err(StoreError::corrupt(format!(
                "Rust declaration access requires a module declaration for an embedded module context: declaration={declaration}, module={module:?}"
            )));
        }
        projected.push(RustDeclarationContextSource::new(
            source_site,
            declaration,
            module.0,
            module.1,
        ));
    }
    projected.sort_unstable_by_key(|source| source.source_site());
    Ok(projected)
}

/// Exact selection inputs plus the live overlay authority captured before any
/// selected database read.
pub(crate) struct SelectedResolutionOperationInput<'a> {
    project: &'a dyn Project,
    analysis_generation: u64,
    workspace_id: &'a WorkspaceId,
    snapshots: &'a WorkspaceSnapshots,
    languages: &'a [SelectedResolutionLanguage],
    overlay_masks: &'a [SelectedResolutionOverlayMask],
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
}

impl<'a> SelectedResolutionOperationInput<'a> {
    pub(crate) fn new(
        project: &'a dyn Project,
        workspace_id: &'a WorkspaceId,
        snapshots: &'a WorkspaceSnapshots,
        languages: &'a [SelectedResolutionLanguage],
        overlay_masks: &'a [SelectedResolutionOverlayMask],
    ) -> Self {
        Self {
            project,
            analysis_generation: project.analysis_generation(),
            workspace_id,
            snapshots,
            languages,
            overlay_masks,
            content_mounts: Vec::new(),
        }
    }

    pub(crate) fn with_content_mounts(
        mut self,
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
    ) -> Self {
        self.content_mounts = content_mounts;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SelectedResolutionFallbackReason {
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
}

pub(crate) enum SelectedResolutionOperationOutcome<T> {
    Native(T),
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
    Cancelled(ResolutionCompletion),
}

pub(crate) enum SelectedResolutionOperationResult<T> {
    Native(T),
    Legacy {
        value: T,
        reason: SelectedResolutionFallbackReason,
    },
    Cancelled(ResolutionCompletion),
}

impl<T> SelectedResolutionOperationOutcome<T> {
    /// Run legacy only after the complete native attempt has been discarded.
    /// Store errors never construct this enum and are therefore structurally
    /// ineligible for fallback.
    pub(crate) fn with_legacy(
        self,
        cancellation: &CancellationToken,
        legacy: impl FnOnce() -> Result<T>,
    ) -> Result<SelectedResolutionOperationResult<T>> {
        Ok(match self {
            Self::Native(value) => SelectedResolutionOperationResult::Native(value),
            Self::Unavailable(reason) => {
                if cancellation.is_cancelled() {
                    SelectedResolutionOperationResult::Cancelled(cancelled_completion())
                } else {
                    let result = legacy();
                    if cancellation.is_cancelled() {
                        SelectedResolutionOperationResult::Cancelled(cancelled_completion())
                    } else {
                        SelectedResolutionOperationResult::Legacy {
                            value: result?,
                            reason: SelectedResolutionFallbackReason::Unavailable(reason),
                        }
                    }
                }
            }
            Self::Stale(reason) => {
                if cancellation.is_cancelled() {
                    SelectedResolutionOperationResult::Cancelled(cancelled_completion())
                } else {
                    let result = legacy();
                    if cancellation.is_cancelled() {
                        SelectedResolutionOperationResult::Cancelled(cancelled_completion())
                    } else {
                        SelectedResolutionOperationResult::Legacy {
                            value: result?,
                            reason: SelectedResolutionFallbackReason::Stale(reason),
                        }
                    }
                }
            }
            Self::Cancelled(completion) => SelectedResolutionOperationResult::Cancelled(completion),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SelectedResolutionLocated<T> {
    Found(T),
    Missing,
}

/// Bounded broad-result staging that rolls back on drop until `publish`.
///
/// Commit G supplies the concrete transaction. Commit F depends only on this
/// ownership law and never materializes an eager workspace-sized result.
pub(crate) trait SelectedResolutionBroadStager {
    type Published;

    fn stage(&mut self, batch: &FactReferenceBatchAnswer) -> Result<()>;

    fn publish(self, summary: FactResolutionBatchSummary) -> Result<Self::Published>;
}

/// Whether this crate stage has prepared its generated SQL facts.
#[derive(Default)]
struct MacroOverlaySlot {
    prepared: bool,
    /// Whether this crate stage closed its proven serde helper gaps.
    serde_helpers_closed: bool,
}

/// Preparation owned by one selected query; reader checkin retains only SQL state.
pub(super) struct QueryResolutionPreparation {
    /// Scalar preparation state for the current SQL crate stage.
    macro_overlay: RefCell<MacroOverlaySlot>,
    prepared_macro_files: RefCell<HashSet<PathBuf>>,
    rust_caller_context: RefCell<Option<RetainedRustCallerContext>>,
    rust_caller_demand: RefCell<Option<RetainedRustCallerDemand>>,
    /// Endpoint cells are immutable once closed under this retained selection.
    rust_workspace_relations: RefCell<ClosedRelations>,
}

/// One caller's context reused only within the active operation.
/// FW replaces this profile-shaped point preparation with a crate-row demand.
struct RetainedRustCallerContext {
    caller: PathBuf,
    /// `None` records that no selected Cargo target owns this caller, which is
    /// as much a result as a context and must not be recomputed per request.
    context: Option<SelectedResolutionContextSet>,
}

/// The demand preparation most recently built for one caller file.
///
/// Shared rather than owned by the request because the point entry consumes
/// the operation by value while the request still reads the preparation; the
/// operation cell and the request therefore hold the same immutable
/// preparation.
struct RetainedRustCallerDemand {
    caller: PathBuf,
    /// `None` records that no selected Cargo target owns this caller.
    prepared: Option<Arc<RustCallerDemand>>,
}

/// One caller's bridge-free request context and the demand preparation behind
/// it.
/// How one request names the declaration authority it answers under.
type RustDeclarationAccessFactory =
    fn(
        &SelectedResolutionOperation<'_, '_>,
        Vec<[u8; 32]>,
    ) -> Result<Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>>;

fn point_access(
    operation: &SelectedResolutionOperation<'_, '_>,
    crate_keys: Vec<[u8; 32]>,
) -> Result<Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>> {
    Ok(operation.crate_access_policy(crate_keys)?)
}

fn crate_set_access(
    operation: &SelectedResolutionOperation<'_, '_>,
    crate_keys: Vec<[u8; 32]>,
) -> Result<Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>> {
    Ok(operation.crate_set_access_policy(crate_keys)?)
}

pub(crate) struct RustCallerDemand {
    contexts: SelectedResolutionContextSet,
    crate_keys: Vec<[u8; 32]>,
    demand: RustDemandPreparation,
}

pub(crate) enum SelectedRustCallerDemandOutcome {
    Ready(Arc<RustCallerDemand>),
    /// No selected Cargo target owns this caller.
    Unavailable,
    Cancelled,
}

enum SelectedContentValidationOutcome {
    Ready,
    Unavailable(SelectedResolutionUnavailable),
    Cancelled,
}

struct ReadySelectedResolution<'store, 'input> {
    store: &'store AnalyzerStore,
    inventory: Box<SelectedResolutionMountInventory<'store>>,
    query_preparation: Option<Box<QueryResolutionPreparation>>,
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
    project: &'input dyn Project,
    analysis_generation: u64,
    /// What this request has already asked the crate rows about textual macro
    /// visibility. Built empty when the request opens and dropped when it
    /// returns, so nothing here outlives the query; the retained preparation
    /// beside it never sees these answers.
    macro_walk: RefCell<SelectedTextualMacroWalkMemo>,
    /// The current crate stage's `rust_crate_point_export.sql` answers.
    /// `None` outside a crate stage; see `rust_crate_rows::CrateExportMemo`.
    crate_rows: RefCell<Option<rust_crate_rows::CrateRowMemo>>,
    /// The numbers this request's selected contexts mint for the identities
    /// they invent: a crate gap reason, an open-inventory reason, a bridge's
    /// path and its tail.
    ///
    /// They belong to no file, so they are `Operation` identities in the
    /// context's half of that range, and they are content keys rather than a
    /// stream: two compilations of one gap have to agree. One table per
    /// request is what makes them agree across the contexts a request builds,
    /// and it is dropped with the request.
    context_identities: crate::analyzer::resolution::SelectedContextIdentities,
    // One scalar publication identity for this request, never a package index.
    go_publication: RefCell<Option<super::GoContextIdentity>>,
}

/// One request's answers to the textual-macro module walk.
///
/// `select_textual_macro_definition` asks "which `macro_rules!` named N is
/// visible at byte P of file F". On tract it was asked 323 times for a median
/// definition request and 10,468 times for a slow one, twice per invocation
/// and again on every later request, with nothing between the question and
/// SQLite. The questions repeat because the walk starts at each invocation
/// separately and then climbs the same module ancestry: a file with 214
/// invocations asks the crate's whole macro-visible module closure 214 times
/// over. Holding the answers for the request collapses that to one ask per
/// distinct question.
///
/// Recorded per question rather than per call, because the duplicate call
/// `prepare_selected_macro_reference_overlay` makes (once through
/// `match_selected_textual_macro`, once directly) asks the identical question.
///
/// It is bounded by the files one request's walks reach, which for a point
/// request is the caller and the module ancestry above it. A whole-workspace
/// request reaches more, so a crate stage clears it
/// (`clear_selected_macro_walk_answers`): the answers are keyed by file and
/// carry each file's whole usage facts, and nothing outside the walk refers to
/// them, so dropping them at a stage boundary can only cost a reread. The
/// macro overlay beside it cannot be dropped the same way, because it
/// registers identities that outlive it; the lane document has that
/// measurement.
#[derive(Default)]
struct SelectedTextualMacroWalkMemo {
    /// What the module walk itself answered for `(name, file, position)`.
    ///
    /// Only answers from a walk that broke no import cycle are recorded: a
    /// cyclic walk's answer depends on where it entered the cycle, so it is
    /// not a property of the question alone.
    visible: HashMap<(String, PathBuf, usize), Option<(PathBuf, SourceDeclarationId)>>,
    /// What `select_textual_macro_definition` answered for the same key, the
    /// imported-macro fallback included.
    selected: HashMap<(String, PathBuf, usize), Option<(PathBuf, SourceDeclarationId)>>,
    /// The usage facts of every file the walk has read. Shared rather than
    /// cloned because a file's facts carry every identifier occurrence in it
    /// and the walk reads the caller's once per invocation.
    sources: HashMap<PathBuf, Option<std::rc::Rc<RustUsageFacts>>>,
    /// The parents of every file an ancestry read has reached, keyed by the
    /// file's workspace-relative path: the file that declares or includes it
    /// and the byte at which it does. A file's parents do not depend on the
    /// macro name or the position asked about, and one read
    /// (`MACRO_WALK_ANCESTRY`) returns them for the file and every ancestor at
    /// once, so each file's parents cost the request at most one statement.
    parents: HashMap<String, Vec<(PathBuf, usize)>>,
}

impl std::ops::Deref for ReadySelectedResolution<'_, '_> {
    type Target = QueryResolutionPreparation;

    fn deref(&self) -> &Self::Target {
        self.query_preparation
            .as_deref()
            .expect("ready selected resolution retains operation preparation until drop")
    }
}

impl std::ops::DerefMut for ReadySelectedResolution<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.query_preparation
            .as_deref_mut()
            .expect("ready selected resolution retains operation preparation until drop")
    }
}

impl<'store> ReadySelectedResolution<'store, '_> {
    /// Where this request's lowerings and its own demands get a shared name's
    /// id. The table lives on the inventory, which is built for one request
    /// and dropped with it.
    pub(super) fn shared_names(&self) -> super::resolution::StoreSharedNames<'_> {
        self.inventory.shared_names()
    }

    pub(super) fn lexical_source(&self) -> SelectedResolutionLexicalSource<'_, 'store> {
        SelectedResolutionLexicalSource::new_on_demand(&self.inventory)
    }

    pub(super) fn typed_source(&self) -> SelectedResolutionTypedSource<'_, 'store> {
        SelectedResolutionTypedSource::new_on_demand(&self.inventory)
    }

    /// Read route-prefix spellings from the selected ordinary or stage source.
    pub(super) fn rust_prefix_spellings(
        &self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        references: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<HashMap<SemanticId, String>> {
        let mut spellings = HashMap::default();
        for page in references.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            spellings.extend(source.reference_lookup_spellings(
                page,
                ResolutionNamespace::Type,
                cancellation,
            )?);
        }
        Ok(spellings)
    }
}

#[cfg(test)]
thread_local! {
    /// The fragment-local identity counts one query's rebaser held when the
    /// query ended, by kind: semantics, nodes, paths, stack variables.
    ///
    /// This is the number RM-2 printed by hand at the same point to attribute
    /// the 3.2 GiB floor. It is taken before query-owned registrations drop,
    /// so the pin records the identities accumulated by the operation.
    static REBASER_IDENTITIES_AT_HANDBACK: std::cell::Cell<[usize; 4]> =
        const { std::cell::Cell::new([0; 4]) };
}

#[cfg(test)]
pub(crate) fn take_rebaser_identities_at_handback_for_test() -> [usize; 4] {
    REBASER_IDENTITIES_AT_HANDBACK.with(std::cell::Cell::take)
}

impl Drop for ReadySelectedResolution<'_, '_> {
    fn drop(&mut self) {
        let preparation = self
            .query_preparation
            .take()
            .expect("ready selected resolution drops operation preparation exactly once");
        #[cfg(test)]
        REBASER_IDENTITIES_AT_HANDBACK.with(|identities| {
            identities.set(
                self.inventory
                    .mount_rebaser()
                    .borrow()
                    .fragment_local_identity_entries(),
            );
        });
        // The size of the rebaser at the end of a query, which RM-2 had to
        // hand-instrument twice to attribute the 3.2 GiB floor. It is cheap
        // and it is the number this reader is judged on, so it belongs in the
        // timing output; `note_with` computes it only when notes are on.
        {
            let rebaser = self.inventory.mount_rebaser().borrow();
            brokk_bifrost_core::profiling::note_with(|| {
                let [semantics, nodes, paths, variables] =
                    rebaser.fragment_local_identity_entries();
                format!(
                    "selected operation handback mounts={} fragment_local semantics={semantics} \
                     nodes={nodes} paths={paths} variables={variables}",
                    rebaser.mount_count()
                )
            });
        }
        // Dropping preparation here releases all supplemental/transient facts.
        // No operation-owned state is returned to the retained SQLite reader.
        drop(preparation);
    }
}

/// One selected Rust path's macro capsule: the mount this query holds the path
/// at, and the persisted blob whose parsed macro definitions, invocations and
/// inputs describe that mount's bytes.
pub(super) struct SelectedMacroCapsule {
    mount: SelectedResolutionOperationMount,
    blob_id: i64,
    content_oid: git2::Oid,
}

impl SelectedMacroCapsule {
    /// A capsule exists only when its blob's bytes are its mount's bytes, and
    /// the two OIDs are how that is known. Constructing one from a blob that
    /// carries different bytes would publish another revision's macro
    /// expansions as this revision's, so the equality is asserted here rather
    /// than assumed by each of the readers below.
    fn new(
        mount: SelectedResolutionOperationMount,
        blob_id: i64,
        blob_oid: git2::Oid,
        mount_oid: git2::Oid,
    ) -> Self {
        assert_eq!(
            blob_oid,
            mount_oid,
            "a Rust macro capsule describes its own mount's bytes: blob {blob_id} for {} carries {blob_oid}, the mount carries {mount_oid}",
            mount.persisted_relative_path()
        );
        Self {
            mount,
            blob_id,
            content_oid: blob_oid,
        }
    }

    pub(super) const fn mount(&self) -> &SelectedResolutionOperationMount {
        &self.mount
    }

    pub(super) const fn blob_id(&self) -> i64 {
        self.blob_id
    }

    pub(super) const fn content_oid(&self) -> git2::Oid {
        self.content_oid
    }

    /// The registered reader of this capsule's macro rows.
    ///
    /// A capsule is minted for one selected mount, and the mount carries the
    /// language that wrote its rows, so the reader is the one that language
    /// registers. The capsule exists only because that language publishes
    /// macro rows at all, which is why a missing reader is an assertion here
    /// rather than an outcome each caller below would have to interpret.
    pub(super) fn macro_rows(&self) -> &'static dyn SelectedMacroSourceRows {
        let language = self.mount.semantic_language();
        crate::analyzer::languages::language_support(language)
            .expect("every selected mount's language has registered support")
            .selected_macro_source_rows()
            .unwrap_or_else(|| {
                panic!(
                    "a selected macro capsule is minted only for a language that publishes \
                     macro rows: {language:?} for {}",
                    self.mount.persisted_relative_path()
                )
            })
    }
}

/// One language's reader of the macro rows it sealed into a selected blob.
///
/// Selected resolution replays a macro invocation from persisted rows instead
/// of reparsing source, and which rows those are is the producing language's
/// own schema. The operation therefore asks the mount's registered support for
/// this reader instead of calling one language's storage module, which is what
/// `language_reach_in_gate` requires of framework code.
///
/// The row types are core's Rust macro facts because Rust is the only language
/// whose producer seals macro definitions and inputs today. A second language
/// that grows a macro replay brings its own rows, and that is the point at
/// which these signatures become generic over them; inventing that abstraction
/// now would only guess at the second shape.
pub(crate) trait SelectedMacroSourceRows: Send + Sync {
    /// The canonical matcher arms sealed in `blob_id`, or `None` when
    /// `keep_going` reported cancellation part way through the read.
    fn definition_rows(
        &self,
        connection: &rusqlite::Connection,
        blob_id: i64,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<rust_facts::RustMacroDefinitionSourceFact>>>;

    /// The canonical invocation input snapshots sealed in `blob_id`, or `None`
    /// when `keep_going` reported cancellation part way through the read.
    fn input_rows(
        &self,
        connection: &rusqlite::Connection,
        blob_id: i64,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<rust_facts::RustMacroInvocationInputSourceFact>>>;

    /// Where the item-position invocation `invocation` sealed in `blob_id`
    /// expands to: an associated-item body or a lexical scope. An invocation
    /// that is not in item position answers `Lexical`.
    fn item_container(
        &self,
        connection: &rusqlite::Connection,
        blob_id: i64,
        invocation: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
    ) -> Result<brokk_bifrost_rust::macro_matcher::RustMacroItemContainer>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedResolutionOperationMount {
    ordinal: SelectedResolutionMountOrdinal,
    storage_language: String,
    persisted_relative_path: String,
    semantic_language: Language,
    fragment: BindingFragmentId,
}

impl SelectedResolutionOperationMount {
    pub(crate) const fn ordinal(&self) -> SelectedResolutionMountOrdinal {
        self.ordinal
    }

    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) fn persisted_relative_path(&self) -> &str {
        &self.persisted_relative_path
    }

    pub(crate) const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    pub(crate) const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }
}

/// The selection's spelling of one workspace-relative path.
///
/// `persisted_relative_path` is stored with forward slashes, and that is the
/// spelling the temp table's path index is sorted on, so a `Path` key is
/// normalized once here instead of being compared component by component
/// against every mount.
fn selected_path_key(path: &Path) -> String {
    crate::path_utils::normalize_pattern(&path.to_string_lossy())
}

#[cfg(test)]
thread_local! {
    /// Mount-table entries the readers below examined, counted for the
    /// acceptance test that a request's mount lookups do not scale with the
    /// selection.
    ///
    /// Entries rather than calls: that is what tells an index apart from a
    /// walk, because a walk of a larger selection examines more entries for
    /// the same question while an index examines one.
    static SELECTED_MOUNT_TABLE_VISITS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_selected_mount_table_visits(examined: usize) {
    SELECTED_MOUNT_TABLE_VISITS.with(|visits| {
        visits.set(
            visits
                .get()
                .checked_add(examined)
                .expect("selected mount visits fit usize"),
        );
    });
}

#[cfg(test)]
pub(crate) fn take_selected_mount_table_visits_for_test() -> usize {
    SELECTED_MOUNT_TABLE_VISITS.with(|visits| visits.replace(0))
}

/// Requested operation metadata read through the existing TEMP ordinal/path
/// indexes. Explicit query-owned enumeration is separate from point reads
/// and never occurs at warm operation construction.
#[derive(Clone, Copy)]
pub(crate) struct SelectedMountTable<'a, 'store> {
    inventory: &'a SelectedResolutionMountInventory<'store>,
}

impl<'a, 'store> SelectedMountTable<'a, 'store> {
    pub(crate) fn new(inventory: &'a SelectedResolutionMountInventory<'store>) -> Self {
        Self { inventory }
    }

    pub(crate) fn mount_count(&self) -> usize {
        self.inventory.persisted_mount_count()
    }

    pub(crate) fn mounts(&self) -> Result<Vec<SelectedResolutionOperationMount>> {
        Ok(self
            .inventory
            .mounts()?
            .iter()
            .map(operation_mount_record)
            .collect())
    }

    pub(crate) fn mount_by_ordinal(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Result<SelectedResolutionOperationMount> {
        #[cfg(test)]
        note_selected_mount_table_visits(1);
        let record = self.inventory.mount_record_by_ordinal(ordinal)?;
        Ok(operation_mount_record(&record))
    }

    pub(crate) fn mount_for_fragment(
        &self,
        fragment: BindingFragmentId,
    ) -> Result<Option<SelectedResolutionOperationMount>> {
        let Some(mount) = self
            .inventory
            .mount_rebaser()
            .borrow()
            .mount_for_fragment(fragment)
        else {
            return Ok(None);
        };
        Ok(Some(self.mount_by_ordinal(mount.ordinal())?))
    }

    pub(crate) fn mount_for_path(
        &self,
        storage_language: &str,
        persisted_relative_path: &str,
    ) -> Result<Option<SelectedResolutionOperationMount>> {
        if let Some(record) = self
            .inventory
            .mount_record_for_path(storage_language, persisted_relative_path)?
        {
            return Ok(Some(operation_mount_record(&record)));
        }
        Ok(None)
    }

    pub(crate) fn mount_for_joined_path(
        &self,
        persisted: Option<(SelectedResolutionMountOrdinal, Language)>,
        storage_language: &str,
        persisted_relative_path: &str,
    ) -> Option<SelectedResolutionOperationMount> {
        if let Some((ordinal, semantic_language)) = persisted {
            assert!(
                (ordinal.get() as usize) < self.inventory.persisted_mount_count(),
                "joined persisted ordinal belongs to selected inventory"
            );
            return Some(SelectedResolutionOperationMount {
                ordinal,
                semantic_language,
                storage_language: storage_language.to_owned(),
                persisted_relative_path: persisted_relative_path.to_owned(),
                fragment: BindingFragmentId::at_ordinal(ordinal.get()),
            });
        }
        None
    }
}

fn selected_mount_columns(
    ordinal: Option<u32>,
    semantic_language: Option<String>,
) -> Result<Option<(SelectedResolutionMountOrdinal, Language)>> {
    assert_eq!(
        ordinal.is_some(),
        semantic_language.is_some(),
        "a joined selected row carries both ordinal and semantic language"
    );
    ordinal
        .map(|ordinal| {
            let label = semantic_language.expect("joined ordinal has semantic language");
            let language = Language::from_config_label(&label).ok_or_else(|| {
                StoreError::corrupt(format!("unknown selected semantic language {label:?}"))
            })?;
            Ok((SelectedResolutionMountOrdinal::new(ordinal), language))
        })
        .transpose()
}

fn operation_mount_record(
    mount: &super::resolution_selection::SelectedResolutionMountRecord,
) -> SelectedResolutionOperationMount {
    SelectedResolutionOperationMount {
        ordinal: mount.ordinal(),
        storage_language: mount.storage_language().to_owned(),
        persisted_relative_path: mount.persisted_relative_path().to_owned(),
        semantic_language: mount.semantic_language(),
        fragment: mount.fragment_id(),
    }
}

pub(crate) enum SelectedResolutionOperationOpenOutcome<'store, 'input> {
    Ready(Box<SelectedResolutionOperation<'store, 'input>>),
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
    Cancelled,
}

pub(crate) enum SelectedResolutionOperationOpenResult<'store, 'input, T> {
    Ready(Box<SelectedResolutionOperation<'store, 'input>>),
    Legacy {
        value: T,
        reason: SelectedResolutionFallbackReason,
    },
    Cancelled,
}

impl<'store, 'input> SelectedResolutionOperationOpenOutcome<'store, 'input> {
    pub(crate) fn with_legacy<T>(
        self,
        cancellation: &CancellationToken,
        legacy: impl FnOnce() -> Result<T>,
    ) -> Result<SelectedResolutionOperationOpenResult<'store, 'input, T>> {
        Ok(match self {
            Self::Ready(operation) => SelectedResolutionOperationOpenResult::Ready(operation),
            Self::Unavailable(reason) => {
                if cancellation.is_cancelled() {
                    SelectedResolutionOperationOpenResult::Cancelled
                } else {
                    let result = legacy();
                    if cancellation.is_cancelled() {
                        SelectedResolutionOperationOpenResult::Cancelled
                    } else {
                        SelectedResolutionOperationOpenResult::Legacy {
                            value: result?,
                            reason: SelectedResolutionFallbackReason::Unavailable(reason),
                        }
                    }
                }
            }
            Self::Stale(reason) => {
                if cancellation.is_cancelled() {
                    SelectedResolutionOperationOpenResult::Cancelled
                } else {
                    let result = legacy();
                    if cancellation.is_cancelled() {
                        SelectedResolutionOperationOpenResult::Cancelled
                    } else {
                        SelectedResolutionOperationOpenResult::Legacy {
                            value: result?,
                            reason: SelectedResolutionFallbackReason::Stale(reason),
                        }
                    }
                }
            }
            Self::Cancelled => SelectedResolutionOperationOpenResult::Cancelled,
        })
    }
}

/// Non-clone selected owner consumed by exactly one semantic operation.
pub(crate) struct SelectedResolutionOperation<'store, 'input> {
    ready: ReadySelectedResolution<'store, 'input>,
    enumerated_mounts: OnceCell<Vec<SelectedResolutionOperationMount>>,
}

pub(crate) enum SelectedRustContextOutcome {
    Ready(SelectedResolutionContextSet),
    Cancelled,
}

/// A Rust context built for named files, with the crates that compile them.
///
/// A forward request binds only inside the dependency closure of its own
/// crates, and it installs that scope before it collects its blueprint. The
/// crates are read while the context is built, so the caller that installs the
/// scope takes them from here instead of asking the crate rows again.
pub(crate) enum SelectedRustFileContextOutcome {
    Ready {
        context: Box<SelectedResolutionContextSet>,
        crate_keys: Vec<[u8; 32]>,
    },
    Cancelled,
}

#[derive(Clone, Debug)]
pub(crate) struct SelectedRustImportBridge {
    source_file: std::path::PathBuf,
    source_import_ordinal: usize,
    target_file: std::path::PathBuf,
    target_name: String,
    namespace: ResolutionNamespace,
}

impl SelectedRustImportBridge {
    pub(crate) fn source_file(&self) -> &std::path::Path {
        &self.source_file
    }

    pub(crate) fn target_file(&self) -> &std::path::Path {
        &self.target_file
    }

    pub(crate) const fn source_import_ordinal(&self) -> usize {
        self.source_import_ordinal
    }

    pub(crate) fn target_name(&self) -> &str {
        &self.target_name
    }

    pub(crate) const fn namespace(&self) -> ResolutionNamespace {
        self.namespace
    }
}

struct SelectedRustRouteInventory<'a> {
    identity: &'a [u8],
    target_memberships: &'a BTreeSet<RustSelectedTargetMembership>,
    dependency_edges: &'a [RustSelectedDependencyEdge],
    root_routes: &'a [RustSelectedRootRoute],
    gaps: &'a BTreeSet<RustSelectedContextGap>,
}

impl<'a> SelectedRustRouteInventory<'a> {
    fn from_context(context: &'a RustSelectedContext) -> Self {
        Self {
            identity: context.identity.as_bytes(),
            target_memberships: &context.target_memberships,
            dependency_edges: &context.dependency_edges,
            root_routes: &context.root_routes,
            gaps: &context.gaps,
        }
    }
}

pub(crate) enum SelectedRustCallerContextOutcome {
    Ready(SelectedResolutionContextSet),
    Unavailable,
    Cancelled,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum SelectedRustCallerReferenceOutcome<T = ()> {
    Operation(
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<Vec<SelectedRustReferenceAnswer<T>>>,
        >,
    ),
    UnsupportedCallerProfile,
}

/// One located answer set per requested site, in request order.
pub(crate) type LocatedRustReferenceAnswers<T> =
    Vec<SelectedResolutionLocated<Vec<SelectedRustReferenceAnswer<T>>>>;

/// The same answer for several sites of one caller, in request order.
pub(crate) enum SelectedRustCallerReferencesOutcome<T = ()> {
    Operation(SelectedResolutionOperationOutcome<LocatedRustReferenceAnswers<T>>),
    UnsupportedCallerProfile,
}

impl<T> SelectedRustCallerReferencesOutcome<T> {
    /// Take the single site's answer out of a one-site request.
    fn into_single(self) -> SelectedRustCallerReferenceOutcome<T> {
        let outcome = match self {
            Self::Operation(outcome) => outcome,
            Self::UnsupportedCallerProfile => {
                return SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile;
            }
        };
        SelectedRustCallerReferenceOutcome::Operation(match outcome {
            SelectedResolutionOperationOutcome::Native(mut located) => {
                assert_eq!(
                    located.len(),
                    1,
                    "a one-site caller request answers exactly one site"
                );
                SelectedResolutionOperationOutcome::Native(located.remove(0))
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                SelectedResolutionOperationOutcome::Unavailable(reason)
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                SelectedResolutionOperationOutcome::Stale(reason)
            }
            SelectedResolutionOperationOutcome::Cancelled(completion) => {
                SelectedResolutionOperationOutcome::Cancelled(completion)
            }
        })
    }
}

pub(crate) enum SelectedRustDefinitionProjection {
    Complete(Vec<CodeUnit>),
    Unavailable,
    Cancelled,
}

pub(crate) enum SelectedRustSourceDefinitionProjection {
    Complete(Vec<(SemanticId, SelectedRustSourceDefinition)>),
    Unavailable,
    Cancelled,
}

pub(crate) enum SelectedRustSourceDefinition {
    Unit(CodeUnit),
    Lexical(LexicalDefinition),
    /// A definition whose source declaration the parser recorded but published
    /// no `CodeUnit` for, and which is no lexical binder either.
    ///
    /// The usage graph's nodes are `CodeUnit`s, so such a definition is out of
    /// the graph exactly as a lexical binding is; every other Rust route
    /// answers it with the `MissingDefinitionUnit` unavailability it already
    /// publishes for a resolved target with no nominal unit. It is never an
    /// error: the resolver resolved, and the projection target simply does not
    /// exist in the `CodeUnit` model.
    ///
    /// On tract at `26edc98ea` 173 of 72,451 persisted definition semantics
    /// are in this class, in 38 of 958 fragment interiors. The shapes are
    /// associated items of an `impl` whose self type is not a declarable path
    /// (`impl Output for usize`, `impl PartialEq for dyn Lut`,
    /// `impl AttrScalarType for &'a str`), items inside a macro invocation's
    /// token tree, and a second item declared under a different `cfg`.
    ///
    /// A macro overlay's own definition is a fourth shape and the reason the
    /// range is optional. A staged producer publishes lexical declarations and
    /// nothing else -- `resolution_capsule_declarations` takes exactly the
    /// lexical binder kinds, and a capsule has no definition-to-unit crosswalk
    /// at all, because the items an expansion introduces are not in the host
    /// blob's `code_units` -- so a generated item is in neither vocabulary by
    /// construction. The one exception is an item the crate declared for a
    /// cross-file passthrough invocation: the stage records the name range of
    /// each capsule definition at admission, and replay's declaration at that
    /// range carries the item's `CodeUnit` (`selected_macro_item_unit`).
    WithoutUnit {
        source_file: ProjectFile,
        declaration_range: Option<Range>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedRustDefinitionSemanticOutcome {
    Found(SemanticId),
    Missing,
    Cancelled,
}

pub(crate) enum SelectedRustDefinitionSemanticMapOutcome {
    Ready(HashMap<CodeUnit, SemanticId>),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SelectedRustBindingDefinitionOutcome {
    Found(SelectedRustBindingDefinition),
    Missing,
    Cancelled,
}

pub(crate) enum SelectedRustBindingDefinitionUnitsOutcome {
    Ready(BTreeMap<SelectedRustBindingDefinition, CodeUnit>),
    Cancelled,
}

/// Where one selected member target was found, in the presentation vocabulary.
///
/// Declared beside the answer that carries it: the point route is its only
/// producer and the native definition adapter its only reader.
pub(crate) struct SelectedRustMemberAttribution {
    pub(crate) target: SemanticId,
    pub(crate) owner: CodeUnit,
    pub(crate) reach: SelectedRustMemberReach,
}

/// How the Rust member lookup got from the qualifier's own type to the owner.
pub(crate) enum SelectedRustMemberReach {
    /// The qualifier's own type declares the member. `declared_by_trait_implementation`
    /// says whether the declaration sits in an `impl Trait for Type` block,
    /// which is what makes a direct find a trait dispatch rather than an
    /// inherent one. Read from the member's contract references, the rows the
    /// producer writes for exactly those declarations.
    Direct {
        declared_by_trait_implementation: bool,
    },
    /// The owner is a trait `implementor`, the qualifier's own type,
    /// implements, and the member is the trait's own declaration.
    Hierarchy {
        owner_path: Vec<CodeUnit>,
        implementation_hop: bool,
    },
}

/// A selected macro gap tied to its producer-recorded invocation, so an
/// activated model can account for that exact expansion without parsing a
/// diagnostic string or discharging unrelated incomplete bindings.
#[derive(Clone, Debug)]
pub(crate) struct SelectedRustMacroExpansionGap {
    pub(crate) semantic: SemanticId,
    pub(crate) relative_path: String,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) macro_name: String,
}

/// Whether a Rust reference that reached a block-local item is decided.
///
/// A Rust item declared inside a block has no parser unit, and the producer
/// says so with an `UnsupportedScopeOrBinder` gap on the declaration
/// (`brokk_bifrost_rust::resolution`, `lower_item_declaration`). That reason
/// is load-bearing for the whole-workspace graph, whose domain such a
/// declaration is genuinely outside of, so it stays where it is: removing it
/// made `native_rust_graph_projects_block_local_struct_fields_without_refusing`
/// claim a complete projection it does not have.
///
/// A reference answer hears the same reason, but it also holds the
/// out-of-graph lexical declaration the reference resolved to, published for
/// exactly this purpose on 2026-09-11 by `b3836b21f`. There the question the
/// reason asks has an answer: the reference names that block-local item and
/// nothing else. Repeating it as `incomplete` denied the definition the answer
/// was already carrying at a point request, and at a reverse request it left
/// every workspace target that shares the item's name unable to prove its
/// inventory.
///
/// The discharge is deliberately narrow. It needs the block-local lexical
/// declaration to be the whole answer -- one lexical definition of that kind
/// and no projected workspace definition beside it -- and every reason to be
/// an `UnsupportedSemantic`, which is the shape the producer's gap takes. An
/// answer that also reached a workspace definition, or that carries a
/// boundary or any other reason kind, keeps its incompleteness.
pub(crate) fn rust_block_local_binding_is_decided(
    definitions: &[CodeUnit],
    lexical: &[LexicalDefinition],
    completion: &ResolutionCompletion,
) -> bool {
    definitions.is_empty()
        && matches!(lexical, [definition]
            if definition.kind == brokk_bifrost_core::analyzer::model::DeclarationKind::BlockLocalItem)
        && matches!(completion, ResolutionCompletion::Incomplete(reasons)
        if reasons.iter().all(|reason| matches!(
            reason,
            crate::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(_)
        )))
}

pub(crate) struct SelectedRustReferenceAnswer<T = ()> {
    pub(crate) macro_expansion_gaps: Vec<SelectedRustMacroExpansionGap>,
    pub(crate) enumeration: Option<(ProjectFile, ResolutionCompletion)>,
    pub(crate) inventory_details: Vec<String>,
    /// The stable name and evidence of each named reason the binding's
    /// completion carries (`SelectedContextIdentities::named_semantic`), so a
    /// reply can say which dead end an incomplete answer stopped at.
    pub(crate) named_reasons: Vec<(&'static str, String)>,
    pub(crate) resolution: FactResolutionAnswer,
    pub(crate) definitions: Vec<CodeUnit>,
    pub(crate) lexical_definitions: Vec<LexicalDefinition>,
    /// The name each of the binding's own targets projects to, in the order
    /// `project_rust_source_definitions` returned them. A diagnostic that
    /// names a semantic can spell it when it is one of these; the presentation
    /// vocabularies below deliberately drop the semantic each row came from.
    pub(crate) definition_names: Vec<(SemanticId, String)>,
    /// Original structured import paths for external-boundary reasons.
    pub(crate) boundary_import_names: Vec<String>,
    /// Member attribution for the targets the member lookup itself selected.
    /// A target reached lexically or through a module route has no row.
    pub(crate) member_attributions: Vec<SelectedRustMemberAttribution>,
    pub(crate) projection: T,
}

/// The vocabularies a point route publishes one projected Rust definition
/// batch as.
struct SelectedRustDefinitionVocabularies {
    /// The distinct parser units the batch's targets project to. Two targets
    /// can name one unit -- `pub fn value` twice in one `impl`, or one item
    /// declared under two `cfg`s -- and that is one definition here, because
    /// this vocabulary is a set of `CodeUnit`s and nothing else.
    units: Vec<CodeUnit>,
    lexical: Vec<LexicalDefinition>,
    /// The name each target is published under, in projection order. This one
    /// keeps a row per target, so a caller can still see how many targets one
    /// unit collapsed.
    names: Vec<(SemanticId, String)>,
}

/// Split one projected Rust definition batch into those vocabularies.
///
/// A target the parser published no `CodeUnit` and no lexical binder for has
/// no name to publish and no row in either vocabulary, exactly as
/// [`SelectedRustSourceDefinition::WithoutUnit`] documents: the resolver
/// resolved, and the projection target simply does not exist in the `CodeUnit`
/// model. It degrades itself, not its batch, so the batch keeps every sibling
/// target that does project.
///
/// `None` reports a batch in which no target projected at all. Every caller
/// answers that with `MissingDefinitionUnit`, which is the unavailability
/// those routes already publish for a resolved target with no nominal unit.
fn split_projected_rust_definitions(
    rows: Vec<(SemanticId, SelectedRustSourceDefinition)>,
) -> Option<SelectedRustDefinitionVocabularies> {
    let requested = rows.len();
    let mut units = Vec::new();
    let mut lexical = Vec::new();
    let mut names = Vec::with_capacity(requested);
    for (semantic, definition) in rows {
        match definition {
            SelectedRustSourceDefinition::Unit(unit) => {
                names.push((semantic, unit.fq_name()));
                if !units.contains(&unit) {
                    units.push(unit);
                }
            }
            SelectedRustSourceDefinition::Lexical(definition) => {
                names.push((semantic, definition.identifier.clone()));
                lexical.push(definition);
            }
            SelectedRustSourceDefinition::WithoutUnit { .. } => {}
        }
    }
    if requested > 0 && names.is_empty() {
        return None;
    }
    Some(SelectedRustDefinitionVocabularies {
        units,
        lexical,
        names,
    })
}

pub(crate) struct SelectedRustTypeProjection {
    pub(crate) nominal_types: Vec<(SemanticId, SelectedRustSourceDefinition)>,
    pub(crate) intrinsic_types: Box<[crate::analyzer::resolution::FactIntrinsicTypeDescriptor]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedReferenceSourceSite {
    reference: SemanticId,
    file: ProjectFile,
    metadata: Option<FactReferenceSiteMetadata>,
    enclosing: Option<Option<CodeUnit>>,
}

impl SelectedReferenceSourceSite {
    pub(crate) const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub(crate) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(crate) const fn metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.metadata
    }

    /// The producer-owned enclosing declaration after parser-unit projection.
    ///
    /// `None` means ownership is unknown or was not requested. `Some(None)`
    /// means the reference has no enclosing unit -- the file root owns it, or
    /// its enclosing declaration is one the parser publishes no `CodeUnit` for,
    /// such as a block-local `fn`. `Some(Some(_))` is one exact declaration.
    pub(crate) fn enclosing(&self) -> Option<Option<&CodeUnit>> {
        self.enclosing.as_ref().map(Option::as_ref)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedReferenceSearchAnswer {
    answer: ReferenceSearchAnswer,
    source_sites: Box<[SelectedReferenceSourceSite]>,
}

impl SelectedReferenceSearchAnswer {
    pub(crate) fn answer(&self) -> &ReferenceSearchAnswer {
        &self.answer
    }

    pub(crate) fn references(&self) -> &[SemanticId] {
        self.answer.references()
    }

    pub(crate) fn completion(&self) -> &ResolutionCompletion {
        self.answer.completion()
    }

    pub(crate) fn source_sites(&self) -> &[SelectedReferenceSourceSite] {
        &self.source_sites
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRustBindingSite {
    file: ProjectFile,
    metadata: Option<FactReferenceSiteMetadata>,
    owner: SelectedRustBindingOwner,
    definitions: Box<[SelectedRustBindingDefinition]>,
    completion: ResolutionCompletion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SelectedRustBindingOwner {
    Unknown,
    FileRoot,
    Definition(CodeUnit),
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SelectedRustBindingDefinition {
    Stable(SemanticId),
}

impl SelectedRustBindingSite {
    pub(crate) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(crate) const fn metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.metadata
    }

    pub(crate) const fn owner(&self) -> &SelectedRustBindingOwner {
        &self.owner
    }

    pub(crate) fn definitions(&self) -> &[SelectedRustBindingDefinition] {
        &self.definitions
    }

    pub(crate) const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRustBindingWorld {
    target: SelectedRustBindingDefinition,
    sites: Box<[SelectedRustBindingSite]>,
    completion: ResolutionCompletion,
}

impl SelectedRustBindingWorld {
    pub(crate) const fn target(&self) -> &SelectedRustBindingDefinition {
        &self.target
    }

    pub(crate) fn sites(&self) -> &[SelectedRustBindingSite] {
        &self.sites
    }

    pub(crate) const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

impl<'store> SelectedResolutionOperation<'store, '_> {
    pub(crate) fn mounts(&self) -> Result<&[SelectedResolutionOperationMount]> {
        if self.enumerated_mounts.get().is_none() {
            assert!(
                self.enumerated_mounts
                    .set(self.mount_table().mounts()?)
                    .is_ok()
            );
        }
        Ok(self
            .enumerated_mounts
            .get()
            .expect("explicit operation enumeration initialized"))
    }

    /// This operation's mount table, with the three readers every mount
    /// question goes through.
    pub(crate) fn mount_table(&self) -> SelectedMountTable<'_, 'store> {
        SelectedMountTable::new(&self.ready.inventory)
    }

    /// Revalidate the selection and authorize `value` as this operation's
    /// result.
    ///
    /// A root-less Rust graph build stages one crate at a time and combines
    /// their summaries, so the revalidation that used to end a single staging
    /// call belongs to the caller that owns the whole result.
    pub(crate) fn finish_native<T>(
        &mut self,
        value: T,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        self.ready.finish(value, completion, cancellation)
    }

    /// The context set that carries none of this operation's own relations.
    pub(crate) fn empty_contexts(
        &self,
        reverse_inventory_completion: &ResolutionCompletion,
    ) -> Result<SelectedResolutionContextSet> {
        empty_contexts_for(
            self.mount_table(),
            reverse_inventory_completion,
            &selected_mount_lookup(self.mount_table()),
            self.ready.context_identities.clone(),
        )
    }

    pub(crate) fn project_rust_definitions(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustDefinitionProjection> {
        project_rust_definitions(
            &self.ready,
            self.mount_table(),
            definitions,
            cancellation,
            &ResolutionSession::unbounded(),
        )
    }

    pub(crate) fn rust_definition_mount_for_target(
        &self,
        target: &CodeUnit,
    ) -> Result<Option<SelectedResolutionMountOrdinal>> {
        if target.source().root() != self.ready.project.root() {
            return Ok(None);
        }
        let relative_path = crate::path_utils::rel_path_string(target.source());
        // One path under one storage language is one mount: the selection
        // declares that key UNIQUE, so there is nothing to disambiguate here.
        let Some(mount) = self.mount_table().mount_for_path("rust", &relative_path)? else {
            return Ok(None);
        };
        assert_eq!(mount.semantic_language(), Language::Rust);
        Ok(Some(mount.ordinal()))
    }

    pub(crate) fn selected_rust_definition_semantics_for_mount(
        &self,
        mount_ordinal: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustDefinitionSemanticMapOutcome> {
        let mount = self.mount_table().mount_by_ordinal(mount_ordinal)?;
        assert_eq!(mount.storage_language(), "rust");
        assert_eq!(mount.semantic_language(), Language::Rust);
        let rows = match self
            .ready
            .inventory
            .selected_definition_semantics_for_mount(mount_ordinal, cancellation)?
        {
            SelectedDefinitionSemanticReadOutcome::Ready(rows) => rows,
            SelectedDefinitionSemanticReadOutcome::Cancelled => {
                return Ok(SelectedRustDefinitionSemanticMapOutcome::Cancelled);
            }
        };
        let mut definitions = HashMap::with_capacity_and_hasher(rows.len(), Default::default());
        let units = RustMountUnits::new(&self.ready, &mount)?;
        for (local_key, row) in rows {
            if cancellation.is_cancelled() {
                return Ok(SelectedRustDefinitionSemanticMapOutcome::Cancelled);
            }
            // The row carries the semantic's storage-local key, which is its
            // catalog position, which is the bottom half of its runtime id. So
            // this still reads no rebaser and writes none -- registering every
            // definition semantic of every mount a reverse frontier opens is
            // how the rebaser used to reach 120,498 entries on tract -- and it
            // no longer has to recompute a digest to get there.
            let semantic = SemanticId::local(
                mount.fragment().ordinal(),
                u32::try_from(local_key.get()).expect("a catalog position fits u32"),
            );
            let unit = units.unit(&row)?;
            if definitions.insert(unit.clone(), semantic).is_some() {
                return Err(StoreError::new(format!(
                    "selected persisted Rust mount maps one parser unit to multiple definition semantics: {unit:?}"
                )));
            }
        }
        if cancellation.is_cancelled() {
            Ok(SelectedRustDefinitionSemanticMapOutcome::Cancelled)
        } else {
            Ok(SelectedRustDefinitionSemanticMapOutcome::Ready(definitions))
        }
    }

    /// Locate the native definition semantic crosswalked to one current Rust
    /// parser unit.
    ///
    /// This is the target-side counterpart of a source-site locator. Read the
    /// exact selected blob's crosswalk before comparing hydrated structured
    /// `CodeUnit` identity, including published replacement content.
    pub(crate) fn locate_rust_definition(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustDefinitionSemanticOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedRustDefinitionSemanticOutcome::Cancelled);
        }
        let Some(mount_ordinal) = self.rust_definition_mount_for_target(target)? else {
            return Ok(SelectedRustDefinitionSemanticOutcome::Missing);
        };
        let mount = self.mount_table().mount_by_ordinal(mount_ordinal)?;

        let rows = match self
            .ready
            .inventory
            .selected_definition_semantics_for_mount(mount_ordinal, cancellation)?
        {
            SelectedDefinitionSemanticReadOutcome::Ready(rows) => rows,
            SelectedDefinitionSemanticReadOutcome::Cancelled => {
                return Ok(SelectedRustDefinitionSemanticOutcome::Cancelled);
            }
        };
        let mut found = None;
        let units = RustMountUnits::new(&self.ready, &mount)?;
        for (definition, row) in rows {
            if cancellation.is_cancelled() {
                return Ok(SelectedRustDefinitionSemanticOutcome::Cancelled);
            }
            if units.unit(&row)? == *target {
                assert!(
                    found.is_none(),
                    "one target has one selected definition: {target:?}"
                );
                // The row's storage-local key is the position the identity
                // occupies in its blob's catalog, and a local id is the mount
                // ordinal and that position. The digest beside it is evidence
                // of what the position means, not the way to find it.
                found = Some(SemanticId::local(
                    mount.ordinal().get(),
                    u32::try_from(definition.get()).map_err(|_| {
                        StoreError::new(format!(
                            "a persisted local key is a catalog position and fits u32: \
                             {definition:?}"
                        ))
                    })?,
                ));
            }
        }
        Ok(found.map_or(
            SelectedRustDefinitionSemanticOutcome::Missing,
            SelectedRustDefinitionSemanticOutcome::Found,
        ))
    }

    /// Whether every unit locates a selected definition semantic, as
    /// [`Self::locate_rust_definition`] would find it for each.
    ///
    /// Reads each mount's crosswalk once for all of that mount's units. A
    /// reverse confirmation of 502 `fbb_` sites in tract's generated
    /// flatbuffers file read the file's whole crosswalk 502 times.
    pub(crate) fn all_rust_definitions_located(
        &self,
        units: &HashSet<&CodeUnit>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let mut by_mount: HashMap<SelectedResolutionMountOrdinal, Vec<&CodeUnit>> =
            HashMap::default();
        for unit in units {
            let Some(mount) = self.rust_definition_mount_for_target(unit)? else {
                return Ok(false);
            };
            by_mount.entry(mount).or_default().push(unit);
        }
        for (mount, units) in by_mount {
            let SelectedRustDefinitionSemanticMapOutcome::Ready(definitions) =
                self.selected_rust_definition_semantics_for_mount(mount, cancellation)?
            else {
                return Ok(false);
            };
            if !units.iter().all(|unit| definitions.contains_key(*unit)) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn locate_rust_binding_definition(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustBindingDefinitionOutcome> {
        let semantic = match self.locate_rust_definition(target, cancellation)? {
            SelectedRustDefinitionSemanticOutcome::Found(semantic) => semantic,
            SelectedRustDefinitionSemanticOutcome::Missing => {
                return Ok(SelectedRustBindingDefinitionOutcome::Missing);
            }
            SelectedRustDefinitionSemanticOutcome::Cancelled => {
                return Ok(SelectedRustBindingDefinitionOutcome::Cancelled);
            }
        };
        Ok(SelectedRustBindingDefinitionOutcome::Found(
            SelectedRustBindingDefinition::Stable(semantic),
        ))
    }

    /// Crosswalk every selected Rust parser unit in one mount-major pass.
    ///
    /// Broad consumers use this inventory to project binding identities without
    /// reopening one definition query per graph node. Definitions without a
    /// parser-unit row, including locals and parameters, are intentionally
    /// absent.
    pub(crate) fn rust_binding_definition_units(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustBindingDefinitionUnitsOutcome> {
        let admitted_definitions = self
            .ready
            .inventory
            .connection()
            .prepare_cached(RUST_GRAPH_DEFINITIONS_SQL)?
            .query_map([], |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        let mut units = BTreeMap::new();
        for mount in self.mounts()?.iter().filter(|mount| {
            mount.storage_language() == "rust" && mount.semantic_language() == Language::Rust
        }) {
            if cancellation.is_cancelled() {
                return Ok(SelectedRustBindingDefinitionUnitsOutcome::Cancelled);
            }
            let rows = match self
                .ready
                .inventory
                .selected_definition_semantics_for_mount(mount.ordinal(), cancellation)?
            {
                SelectedDefinitionSemanticReadOutcome::Ready(rows) => rows,
                SelectedDefinitionSemanticReadOutcome::Cancelled => {
                    return Ok(SelectedRustBindingDefinitionUnitsOutcome::Cancelled);
                }
            };
            let mount_units = RustMountUnits::new(&self.ready, mount)?;
            for (definition, row) in rows {
                if !admitted_definitions.contains(&(mount.ordinal().get(), definition.get())) {
                    continue;
                }

                if cancellation.is_cancelled() {
                    return Ok(SelectedRustBindingDefinitionUnitsOutcome::Cancelled);
                }
                // The row carries the semantic's storage-local key, which is
                // its catalog position, which is the bottom half of its
                // runtime id. Registering it said nothing the id does not
                // already say, and registering every definition semantic of
                // every mount a reverse frontier opens is how the rebaser
                // reached 120,498 entries on tract.
                let semantic = SemanticId::local(
                    mount.fragment().ordinal(),
                    u32::try_from(definition.get()).expect("a catalog position fits u32"),
                );
                let unit = mount_units.unit(&row)?;
                let definition = SelectedRustBindingDefinition::Stable(semantic);
                if let Some(previous) = units.insert(definition.clone(), unit.clone()) {
                    return Err(StoreError::new(format!(
                        "selected Rust definition {definition:?} maps to multiple parser units: {previous:?}, {unit:?}"
                    )));
                }
            }
        }
        if cancellation.is_cancelled() {
            Ok(SelectedRustBindingDefinitionUnitsOutcome::Cancelled)
        } else {
            Ok(SelectedRustBindingDefinitionUnitsOutcome::Ready(units))
        }
    }

    /// Publish the still-dense instantiated capsule before stage assignment.
    ///
    /// Call only after source cursors have been collected and outside a private
    /// TEMP transaction. The ordinary finish/revalidation path checks main-store
    /// changes; publication does not reset the selected reader's change stamp.
    #[allow(clippy::too_many_arguments)]
    fn prepare_publish_macro_capsule(
        &self,
        host: &super::resolution_selection::SelectedResolutionMountRecord,
        key: super::resolution_publication::ResolutionCapsuleKey,
        checkpoint: crate::analyzer::resolution::ResolutionNodeIdentity,
        module_scope: ResolutionScopeId,
        dense: crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
        lowering: &brokk_bifrost_rust::macro_matcher::SelectedMacroInputLowering,
        input_start_line: usize,
        references: Vec<super::resolution_publication::ResolutionCapsuleReferenceContext>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        use super::resolution_publication::{
            ResolutionContentPublicationOutcome, prepare_resolution_capsule,
        };
        assert_eq!(host.semantic_language(), Language::Rust);
        assert_eq!(host.blob_oid(), key.host_content_oid);
        assert_eq!(host.producer_epoch(), key.producer_epoch);
        assert_eq!(host.fragment_id(), dense.identities().fragment());
        let Some(prepared) = prepare_resolution_capsule(
            key,
            checkpoint,
            module_scope,
            &dense,
            lowering,
            input_start_line,
            references,
            cancellation,
        )?
        else {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        };
        let owner = super::WorkspaceSnapshotId {
            workspace_id: super::WorkspaceId(host.workspace_id().to_owned()),
            lang: host.storage_language().to_owned(),
            generation: super::GenerationId::from_persisted(host.generation()),
            revision: host.revision(),
        };
        // The capsule is published through the store's writer and admitted from
        // this reader below, so a crate stage's snapshot must end before the
        // publication and start again after it.
        self.ready.inventory.pause_stage_read()?;
        let published = self.ready.store.publish_selected_resolution_capsule(
            &owner,
            host.persisted_relative_path(),
            prepared,
            cancellation,
        );
        self.ready.inventory.resume_stage_read()?;
        let content = match published? {
            ResolutionContentPublicationOutcome::Ready(content) => content,
            ResolutionContentPublicationOutcome::Cancelled => {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            ResolutionContentPublicationOutcome::Stale(reason) => {
                return Ok(SelectedResolutionStageOutcome::Stale(reason));
            }
            ResolutionContentPublicationOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionStageOutcome::Unavailable(reason));
            }
        };
        // Every definition the capsule lowered, at its name's range.
        let facts = &lowering.facts;
        let definition_names = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role
                    == brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole::Declaration
            })
            .map(|identifier| {
                let site = &facts.sites[identifier.site.index()];
                assert_eq!(site.id, identifier.site, "capsule sites are dense");
                (identifier.site, site.start_byte, site.end_byte)
            })
            .collect::<Vec<_>>();
        super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory).admit_capsule(
            *content,
            host,
            dense,
            &definition_names,
            cancellation,
        )
    }

    /// Read macro input authority from the actual selected content mount.
    /// Replacements publish their own complete parsed source before opening.
    fn rust_macro_capsule(&self, path: &str) -> Result<Option<SelectedMacroCapsule>> {
        let Some(mount) = self.mount_table().mount_for_path("rust", path)? else {
            return Ok(None);
        };
        let record = self
            .ready
            .inventory
            .persisted_mount_record(mount.ordinal())?
            .expect("every selected content mount has an inventory record");
        let oid = record.blob_oid();
        Ok(Some(SelectedMacroCapsule::new(
            mount,
            record.blob_id(),
            oid,
            oid,
        )))
    }

    fn selected_rust_usage_facts(
        &self,
        file: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Option<RustUsageFacts>> {
        Ok(self
            .selected_rust_usage_facts_shared(file, cancellation)?
            .map(|facts| (*facts).clone()))
    }

    /// The same read, shared with this request's other readers of the file.
    ///
    /// The module walk reads the caller's facts once per macro invocation in
    /// it and every module it climbs through once per invocation as well. On
    /// tract that was 60,450 executions of the three usage-fact statements in
    /// one 40-request arm. The result of the read belongs to the request, so
    /// the request holds it.
    fn selected_rust_usage_facts_shared(
        &self,
        file: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Option<std::rc::Rc<RustUsageFacts>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let recorded = self.ready.macro_walk.borrow().sources.get(file).cloned();
        if let Some(shared) = recorded {
            return Ok(shared);
        }
        let facts = self.read_selected_rust_usage_facts(file, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let shared = facts.map(std::rc::Rc::new);
        self.ready
            .macro_walk
            .borrow_mut()
            .sources
            .insert(file.to_path_buf(), shared.clone());
        Ok(shared)
    }

    fn read_selected_rust_usage_facts(
        &self,
        file: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Option<RustUsageFacts>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(mount) = self
            .ready
            .inventory
            .mount_record_for_path("rust", &selected_path_key(file))?
        else {
            return Ok(None);
        };
        super::read_rust_usage_facts_with_session(
            self.ready.inventory.connection(),
            &mount.blob_oid().to_string(),
            "rust",
            None,
        )
    }

    /// Replay a parent-module textual macro using selected source authority.
    /// The input is addressed by its canonical persisted range; no definition
    /// source file is opened or reparsed by the selected consumer.
    ///
    /// The answer is held for this request (`SelectedTextualMacroWalkMemo`),
    /// because the overlay asks the identical question twice per invocation
    /// and the frontier asks it a third time.
    fn select_textual_macro_definition(
        &self,
        caller: &Path,
        invocation_start: usize,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<RustSelectedBuildOutcome<Option<(PathBuf, SourceDeclarationId)>>> {
        let question = (name.to_owned(), caller.to_path_buf(), invocation_start);
        let recorded = self
            .ready
            .macro_walk
            .borrow()
            .selected
            .get(&question)
            .cloned();
        if let Some(answer) = recorded {
            return Ok(RustSelectedBuildOutcome::Ready(answer));
        }
        let RustSelectedBuildOutcome::Ready(visible) =
            self.select_visible_textual_macro(caller, invocation_start, name, cancellation)?
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        let selected = match visible {
            Some(selected) => Some(selected),
            None => {
                let RustSelectedBuildOutcome::Ready(imported) = self
                    .select_imported_macro_definition(
                        caller,
                        invocation_start,
                        name,
                        cancellation,
                    )?
                else {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                };
                imported
            }
        };
        self.ready
            .macro_walk
            .borrow_mut()
            .selected
            .insert(question, selected.clone());
        Ok(RustSelectedBuildOutcome::Ready(selected))
    }

    /// The module walk itself: the `macro_rules!` named `name` that is textually
    /// visible at `invocation_start` of `caller`, without the imported-macro
    /// fallback.
    ///
    /// Every frame this walk finishes is recorded for the request, so the next
    /// invocation in the same file climbs the same ancestry for free. A walk
    /// that breaks an import cycle records nothing: where such a walk enters
    /// the cycle decides which member is answered `None`, so its frames are
    /// not a property of the question alone.
    fn select_visible_textual_macro(
        &self,
        caller: &Path,
        invocation_start: usize,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<RustSelectedBuildOutcome<Option<(PathBuf, SourceDeclarationId)>>> {
        type Query = (PathBuf, usize);
        type Definition = (PathBuf, SourceDeclarationId);
        type Rank = (usize, std::cmp::Reverse<usize>);
        enum Frame {
            Visit(Query),
            Finish {
                query: Query,
                local: Vec<(Rank, Definition)>,
                imported: Vec<(Rank, Query)>,
                parents: Vec<Query>,
            },
        }

        let initial = (caller.to_path_buf(), invocation_start);
        let mut pending = vec![Frame::Visit(initial.clone())];
        let mut active = BTreeSet::new();
        let mut answers = BTreeMap::<Query, Option<Definition>>::new();
        let mut broke_a_cycle = false;
        while let Some(frame) = pending.pop() {
            if cancellation.is_cancelled() {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            match frame {
                Frame::Visit(query) => {
                    if answers.contains_key(&query) {
                        continue;
                    }
                    let recorded = self
                        .ready
                        .macro_walk
                        .borrow()
                        .visible
                        .get(&(name.to_owned(), query.0.clone(), query.1))
                        .cloned();
                    if let Some(answer) = recorded {
                        answers.insert(query, answer);
                        continue;
                    }
                    if !active.insert(query.clone()) {
                        broke_a_cycle = true;
                        answers.insert(query, None);
                        continue;
                    }
                    let (file, position) = &query;
                    let Some(facts) = self.selected_rust_usage_facts_shared(file, cancellation)?
                    else {
                        answers.insert(query.clone(), None);
                        active.remove(&query);
                        continue;
                    };
                    let root = facts.module_routes.scopes.first();
                    let mut local = Vec::new();
                    for definition in &facts.module_routes.item_macros {
                        if definition.name == name
                            && definition.visible_after <= *position
                            && definition.scope_start <= *position
                            && (*position < definition.scope_end
                                || root.is_some_and(|root| {
                                    *position == root.body_end
                                        && definition.scope_start == root.body_start
                                        && definition.scope_end == root.body_end
                                }))
                        {
                            local.push((
                                (
                                    definition.scope_end - definition.scope_start,
                                    std::cmp::Reverse(definition.visible_after),
                                ),
                                (file.clone(), definition.declaration),
                            ));
                        }
                    }

                    let file_string = crate::path_utils::normalize_pattern(&file.to_string_lossy());
                    let connection = self.ready.inventory.connection();
                    let parents = self.selected_macro_walk_parents(&file_string)?;

                    let mut imported = Vec::new();
                    for scope in &facts.module_routes.scopes {
                        if !scope.imports_macros {
                            continue;
                        }
                        let Some(parent) = scope.parent else {
                            continue;
                        };
                        let owner = &facts.module_routes.scopes[parent];
                        if scope.body_end <= *position
                            && owner.body_start <= *position
                            && (*position < owner.body_end
                                || root.is_some_and(|root| {
                                    *position == root.body_end
                                        && owner.body_start == root.body_start
                                        && owner.body_end == root.body_end
                                }))
                        {
                            imported.push((
                                (
                                    owner.body_end - owner.body_start,
                                    std::cmp::Reverse(scope.body_end),
                                ),
                                (file.clone(), scope.body_end.saturating_sub(1)),
                            ));
                        }
                    }
                    for route in facts
                        .module_routes
                        .routes
                        .iter()
                        .filter(|route| route.imports_macros)
                    {
                        let owner = &facts.module_routes.scopes[route.scope];
                        if route.declaration_end > *position
                            || owner.body_start > *position
                            || (*position >= owner.body_end
                                && !root.is_some_and(|root| {
                                    *position == root.body_end
                                        && owner.body_start == root.body_start
                                        && owner.body_end == root.body_end
                                }))
                        {
                            continue;
                        }
                        let children = connection
                            .prepare_cached(rust_crate_context::MACRO_WALK_CHILD_MODULE_FILES)?
                            .query_map(rusqlite::params![file_string, route.module_name], |row| {
                                row.get::<_, String>(0)
                            })?
                            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
                        for child in children {
                            let child = PathBuf::from(child);
                            let child_facts =
                                self.selected_rust_usage_facts_shared(&child, cancellation)?;
                            let Some(target) = child_facts
                                .as_ref()
                                .and_then(|facts| facts.module_routes.scopes.first())
                            else {
                                continue;
                            };
                            imported.push((
                                (
                                    owner.body_end - owner.body_start,
                                    std::cmp::Reverse(route.declaration_end),
                                ),
                                (child, target.body_end),
                            ));
                        }
                    }
                    for edge in &facts.include_edges {
                        if edge.include_start >= *position {
                            continue;
                        }
                        let Some(owner) = facts
                            .module_routes
                            .scopes
                            .iter()
                            .filter(|scope| {
                                scope.body_start <= edge.include_start
                                    && edge.include_start < scope.body_end
                            })
                            .min_by_key(|scope| scope.body_end - scope.body_start)
                        else {
                            continue;
                        };
                        if *position >= owner.body_end
                            && !root.is_some_and(|root| {
                                *position == root.body_end
                                    && owner.body_start == root.body_start
                                    && owner.body_end == root.body_end
                            })
                        {
                            continue;
                        }
                        let included = connection
                            .prepare_cached(rust_crate_context::MACRO_INCLUDED_FILE)?
                            .query_map(rusqlite::params![file_string, edge.file_name], |row| {
                                row.get::<_, String>(0)
                            })?
                            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
                        for included in included {
                            let included = PathBuf::from(included);
                            let included_facts =
                                self.selected_rust_usage_facts_shared(&included, cancellation)?;
                            let Some(target) = included_facts
                                .as_ref()
                                .and_then(|facts| facts.module_routes.scopes.first())
                            else {
                                continue;
                            };
                            imported.push((
                                (
                                    owner.body_end - owner.body_start,
                                    std::cmp::Reverse(edge.include_start),
                                ),
                                (included, target.body_end),
                            ));
                        }
                    }

                    // The files this module brings into scope are visited
                    // next, and each climbs to its own parents; read all of
                    // their ancestries in one statement. The parents' own are
                    // already held: this file's ancestry read included them.
                    let imported_files = imported
                        .iter()
                        .map(|(_, (file, _))| {
                            crate::path_utils::normalize_pattern(&file.to_string_lossy())
                        })
                        .collect::<Vec<_>>();
                    self.read_selected_macro_walk_ancestry(
                        &imported_files
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                    )?;
                    let dependencies = imported
                        .iter()
                        .map(|(_, query)| query.clone())
                        .chain(parents.iter().cloned())
                        .collect::<Vec<_>>();
                    pending.push(Frame::Finish {
                        query,
                        local,
                        imported,
                        parents,
                    });
                    pending.extend(dependencies.into_iter().map(Frame::Visit));
                }
                Frame::Finish {
                    query,
                    mut local,
                    imported,
                    parents,
                } => {
                    for (rank, dependency) in imported {
                        if let Some(Some(definition)) = answers.get(&dependency) {
                            local.push((rank, definition.clone()));
                        }
                    }
                    local.sort();
                    let selected = if let Some((rank, definition)) = local.first() {
                        local
                            .iter()
                            .take_while(|(other, _)| other == rank)
                            .all(|(_, candidate)| candidate == definition)
                            .then(|| definition.clone())
                    } else {
                        let candidates = parents
                            .iter()
                            .map(|parent| answers.get(parent).cloned().flatten())
                            .collect::<BTreeSet<_>>();
                        (candidates.len() == 1)
                            .then(|| candidates.into_iter().next().flatten())
                            .flatten()
                    };
                    active.remove(&query);
                    answers.insert(query, selected);
                }
            }
        }
        let selected = answers.get(&initial).cloned().flatten();
        if !broke_a_cycle {
            let mut memo = self.ready.macro_walk.borrow_mut();
            for (query, answer) in answers {
                memo.visible
                    .insert((name.to_owned(), query.0, query.1), answer);
            }
        }
        Ok(RustSelectedBuildOutcome::Ready(selected))
    }
    /// The files that declare or include `file` in the textual-macro climb,
    /// each with the byte at which it does, sorted.
    ///
    /// The first question about a file reads its whole ancestry in one
    /// statement and records the parents of every file on it for the request,
    /// so the climb above that file costs no further statement.
    fn selected_macro_walk_parents(&self, file: &str) -> Result<Vec<(PathBuf, usize)>> {
        self.read_selected_macro_walk_ancestry(&[file])?;
        Ok(self.ready.macro_walk.borrow().parents[file].clone())
    }

    /// Record the parents of every file on the ancestry of `files` that the
    /// request does not hold yet, reading them in one statement.
    ///
    /// Every file the read reaches has had all of its parents read, so a
    /// reached file with no edge of its own has none. A file's parents depend
    /// on the file alone, so a later read that reaches it again adds nothing.
    fn read_selected_macro_walk_ancestry(&self, files: &[&str]) -> Result<()> {
        let missing = {
            let memo = self.ready.macro_walk.borrow();
            files
                .iter()
                .copied()
                .filter(|file| !memo.parents.contains_key(*file))
                .collect::<BTreeSet<_>>()
        };
        if missing.is_empty() {
            return Ok(());
        }
        let requested = serde_json::to_string(&missing).expect("file paths serialize");
        let edges = self
            .ready
            .inventory
            .connection()
            .prepare_cached(rust_crate_context::MACRO_WALK_ANCESTRY)?
            .query_map([&requested], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, usize>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut reached = missing
            .into_iter()
            .map(|file| (file.to_owned(), Vec::new()))
            .collect::<HashMap<String, Vec<(PathBuf, usize)>>>();
        for (child, parent, position) in edges {
            reached.entry(parent.clone()).or_default();
            reached
                .entry(child)
                .or_default()
                .push((PathBuf::from(parent), position));
        }
        let mut memo = self.ready.macro_walk.borrow_mut();
        for (file, mut parents) in reached {
            parents.sort_unstable();
            parents.dedup();
            memo.parents.entry(file).or_insert(parents);
        }
        Ok(())
    }

    pub(crate) fn match_selected_textual_macro(
        &self,
        caller: &std::path::Path,
        invocation_start: usize,
        arguments_start: usize,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<
        Option<
            std::result::Result<
                brokk_bifrost_rust::macro_matcher::MacroArmMatch,
                brokk_bifrost_rust::macro_matcher::MacroMatchError,
            >,
        >,
    > {
        let (file, declaration) = match self.select_textual_macro_definition(
            caller,
            invocation_start,
            name,
            cancellation,
        )? {
            RustSelectedBuildOutcome::Ready(Some(selected)) => selected,
            RustSelectedBuildOutcome::Ready(None) => return Ok(None),
            RustSelectedBuildOutcome::Stopped => {
                return Ok(Some(Err(
                    brokk_bifrost_rust::macro_matcher::MacroMatchError::Interrupted,
                )));
            }
        };
        let capsule_for =
            |file: &std::path::Path| self.rust_macro_capsule(&selected_path_key(file));
        let (Some(definition_mount), Some(invocation_mount)) =
            (capsule_for(&file)?, capsule_for(caller)?)
        else {
            return Ok(None);
        };
        let connection = self.ready.inventory.connection();
        let Some(definitions) = definition_mount.macro_rows().definition_rows(
            connection,
            definition_mount.blob_id(),
            &|| !cancellation.is_cancelled(),
        )?
        else {
            return Ok(Some(Err(
                brokk_bifrost_rust::macro_matcher::MacroMatchError::Interrupted,
            )));
        };
        let definition = definitions
            .iter()
            .find(|definition| definition.declaration == declaration)
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "selected textual macro has no canonical definition: {file:?}, {declaration:?}"
                ))
            })?;
        let Some(inputs) = invocation_mount.macro_rows().input_rows(
            connection,
            invocation_mount.blob_id(),
            &|| !cancellation.is_cancelled(),
        )?
        else {
            return Ok(Some(Err(
                brokk_bifrost_rust::macro_matcher::MacroMatchError::Interrupted,
            )));
        };
        let input = inputs
            .iter()
            .find(|input| input.tree.start_byte == arguments_start)
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "selected invocation has no canonical input: {caller:?}, {arguments_start}"
                ))
            })?;
        Ok(Some(
            brokk_bifrost_rust::macro_matcher::match_captured_macro_rules(
                definition,
                &input.tree,
                &|| !cancellation.is_cancelled(),
            ),
        ))
    }

    fn prepare_selected_macro_reference_overlay(
        &self,
        files: &[String],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        if self.ready.macro_overlay.borrow().prepared {
            return Ok(SelectedResolutionStageOutcome::Ready);
        }
        let outcome = self.prepare_selected_macro_reference_overlay_in_scope(
            files,
            self.ready.inventory.connection(),
            cancellation,
        )?;
        if matches!(outcome, SelectedResolutionStageOutcome::Ready) {
            self.ready.macro_overlay.borrow_mut().prepared = true;
        }
        Ok(outcome)
    }

    /// Close the open binder gap of every selected module-level struct or enum
    /// whose `serde` helper the producer could not prove inert in its file
    /// (`source_rust_declaration_properties.serde_helper_derive`), when the
    /// crate rows prove it: at every placement of the declaration, the derive
    /// name, looked up in the item's module, is bound by `use serde::<name>;`
    /// (`SERDE_DERIVE_BINDING`, globs and re-exports included) and no
    /// workspace macro of that name answers the lookup (`EXPORT`). A gap that
    /// stays open keeps the item's name and the paths that reach it
    /// incomplete, which is right while `#[serde]` might still be an
    /// attribute macro that replaces the item.
    fn close_serde_helper_gaps(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        use crate::analyzer::resolution::LoweringGapOrigin;
        use crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code;
        use brokk_bifrost_core::analyzer::structural::resolution::ResolutionGapOriginKind;
        let connection = self.ready.inventory.connection();
        let origin = gap_origin_code(LoweringGapOrigin::from_kind(
            ResolutionGapOriginKind::UnsupportedScopeOrBinder,
        ));
        let rows = connection
            .prepare_cached(rust_crate_context::SERDE_HELPER_CONDITIONS)?
            .query_map([origin], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Rows arrive ordered by mount and reason; one declaration placed in
        // several modules closes only when every placement proves it.
        let mut decided: Vec<(u32, i64, bool)> = Vec::new();
        for (ordinal, reason, derive, topology, path) in rows {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            let workspace_macro = connection
                .prepare_cached(rust_crate_context::EXPORT)?
                .exists(rusqlite::params![
                    topology, path, "macro", derive, topology, path
                ])?;
            let proven = !workspace_macro
                && connection
                    .prepare_cached(rust_crate_context::SERDE_DERIVE_BINDING)?
                    .query_row(
                        rusqlite::params![topology, path, "macro", derive, topology, path],
                        |row| row.get::<_, bool>(0),
                    )?;
            match decided.last_mut() {
                Some((last_ordinal, last_reason, all))
                    if (*last_ordinal, *last_reason) == (ordinal, reason) =>
                {
                    *all &= proven;
                }
                _ => decided.push((ordinal, reason, proven)),
            }
        }
        let stage = super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory);
        for group in decided.chunk_by(|left, right| left.0 == right.0) {
            let ordinal = group[0].0;
            let reasons = group
                .iter()
                .filter(|(_, _, proven)| *proven)
                .map(|(_, reason, _)| (i64::from(ordinal) << 32) + reason)
                .collect::<Vec<_>>();
            if reasons.is_empty() {
                continue;
            }
            let host = self
                .ready
                .inventory
                .persisted_mount_record(SelectedResolutionMountOrdinal::new(ordinal))?
                .expect("a serde helper condition's mount is selected");
            let outcome = stage.close_serde_helper_reasons(&host, &reasons, cancellation)?;
            if !matches!(outcome, SelectedResolutionStageOutcome::Ready) {
                return Ok(outcome);
            }
        }
        Ok(SelectedResolutionStageOutcome::Ready)
    }

    fn clear_selected_macro_overlay(&self) -> Result<()> {
        super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory)
            .clear_facts()?;
        let mut slot = self.ready.macro_overlay.borrow_mut();
        slot.prepared = false;
        slot.serde_helpers_closed = false;
        drop(slot);
        self.ready.prepared_macro_files.borrow_mut().clear();
        Ok(())
    }

    /// Locate a declaration already selected by Rust's textual macro walk.
    fn selected_macro_binding_target(
        &self,
        file: &Path,
        declaration: SourceDeclarationId,
        cancellation: &CancellationToken,
    ) -> Result<Option<SelectedMacroBindingTarget>> {
        let mount = self
            .rust_macro_capsule(&selected_path_key(file))?
            .expect("selected macro definition has a macro capsule");
        let connection = self.ready.inventory.connection();
        let site: u32 = connection.prepare_cached(
            "SELECT source_site FROM source_native_declaration_bridges WHERE blob_id = ?1 AND declaration_id = ?2",
        )?.query_row(rusqlite::params![mount.blob_id(), declaration.get()], |row| row.get(0))?;
        let persisted = self.ready.lexical_source();
        let locator = SelectedSemanticLocator::new(
            "rust",
            mount.mount().persisted_relative_path(),
            ResolutionSiteId::new(site),
            LoweredSemanticRole::Definition,
        );
        let LocatedSemantic::Found(semantic) =
            self.ready
                .lookup_locator(&persisted, &locator, cancellation)?
        else {
            return Ok(None);
        };
        let observed = SeamProfiled::observing(&persisted);
        let Some(node) = observed.lookup_definition_node(semantic, cancellation)? else {
            return Ok(None);
        };
        let host = self
            .ready
            .inventory
            .persisted_mount_record(mount.mount().ordinal())?
            .expect("selected macro definition has an inventory record");
        Ok(Some(SelectedMacroBindingTarget {
            host,
            semantic,
            node,
        }))
    }

    /// An unqualified use target can name a textually visible macro_rules
    /// declaration. It does not make that private declaration a general module
    /// export: retain the source-order proof for this exact import reference.
    fn prepare_selected_textual_macro_imports(
        &self,
        file: &Path,
        source: &RustUsageFacts,
        blob_id: i64,
        host_ordinal: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        use brokk_bifrost_rust::selected_context::RustSelectedActivation;
        let connection = self.ready.inventory.connection();
        let persisted = self.ready.lexical_source();
        let stage = super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory);
        for import in &source.import_targets {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            if import.is_glob
                || import.is_extern_crate
                || import.leading_absolute
                || !import.module_path.is_empty()
            {
                continue;
            }
            if import.cfg_condition
                != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always
            {
                match self.rust_cfg_activation_for_caller(
                    file,
                    &import.cfg_condition,
                    cancellation,
                )? {
                    Some(RustSelectedActivation::Active) => {}
                    Some(RustSelectedActivation::Inactive | RustSelectedActivation::Unknown) => {
                        continue;
                    }
                    None => return Ok(SelectedResolutionStageOutcome::Cancelled),
                }
            }
            let Some(target) = import.source_occurrences.and_then(|source| source.target) else {
                continue;
            };
            let name = import
                .imported_name
                .as_deref()
                .expect("named import has a target");
            let (start, end): (usize, usize) = connection
                .prepare_cached(rust_crate_context::MACRO_IMPORT_TARGET_RANGE)?
                .query_row(rusqlite::params![blob_id, target.get()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
            let selected = self.select_visible_textual_macro(file, start, name, cancellation)?;
            let (definition_file, declaration) = match selected {
                RustSelectedBuildOutcome::Ready(Some(selected)) => selected,
                RustSelectedBuildOutcome::Ready(None) => continue,
                RustSelectedBuildOutcome::Stopped => {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
            };
            let Some(definition) =
                self.selected_macro_binding_target(&definition_file, declaration, cancellation)?
            else {
                continue;
            };
            let locator = SelectedSemanticLocator::for_reference_range(
                "rust",
                selected_path_key(file),
                start,
                end,
            );
            let sites = match persisted.lookup_semantic_sites(
                &locator,
                cancellation,
                &ResolutionSession::unbounded(),
            )? {
                SelectedSemanticLookupOutcome::Found(sites) => sites,
                SelectedSemanticLookupOutcome::Missing => continue,
                SelectedSemanticLookupOutcome::Cancelled => {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
            };
            let host = self
                .ready
                .inventory
                .persisted_mount_record(host_ordinal)?
                .expect("selected macro import has an inventory record");
            for site in sites
                .into_iter()
                .filter(|site| site.namespace() == ResolutionNamespace::Macro)
            {
                if stage
                    .admit_macro_head_pair(
                        &host,
                        site.semantic(),
                        site.node(),
                        &definition.host,
                        definition.semantic,
                        definition.node,
                        cancellation,
                    )?
                    .is_none()
                {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
            }
        }
        Ok(SelectedResolutionStageOutcome::Ready)
    }

    /// Publish one producer at a time into the current SQL stage.
    fn prepare_selected_macro_reference_overlay_in_scope(
        &self,
        files: &[String],
        connection: &rusqlite::Connection,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        use crate::analyzer::resolution::{
            BatchCandidateRequest, EndpointSignature, LoweredResolutionFragment,
            SelectedNodeProvenance, SelectedTypedFactSource, StackPattern, TypedFactRequest,
        };
        let persisted = self.ready.lexical_source();
        let typed_source = self.ready.typed_source();
        let observed_lexical = SeamProfiled::observing(&persisted);
        let observed_typed = SeamProfiled::observing(&typed_source);
        let fragment_source = &observed_lexical;
        let stage = super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory);
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            let caller = Path::new(&file);
            let capsule = self
                .rust_macro_capsule(file.as_str())?
                .expect("selected macro input has a macro capsule");
            let mount = capsule.mount();
            let fragment = mount.fragment();
            let Some(source) = self.selected_rust_usage_facts(caller, cancellation)? else {
                continue;
            };
            match self.prepare_selected_textual_macro_imports(
                caller,
                &source,
                capsule.blob_id(),
                mount.ordinal(),
                cancellation,
            )? {
                SelectedResolutionStageOutcome::Ready => {}
                terminal => return Ok(terminal),
            }
            let Some(inputs) =
                capsule
                    .macro_rows()
                    .input_rows(connection, capsule.blob_id(), &|| {
                        !cancellation.is_cancelled()
                    })?
            else {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            };
            for input in inputs {
                if input.native_frontier.is_none() {
                    continue;
                }
                let invocation = connection
                    .prepare_cached(MACRO_INVOCATION_START_AND_NAME_SQL)?
                    .query_row(
                        rusqlite::params![capsule.blob_id(), input.invocation.get()],
                        |row| Ok((row.get::<_, usize>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                let Some((start, name)) = invocation else {
                    continue;
                };
                let locator = SelectedSemanticLocator::for_reference_range(
                    "rust".to_owned(),
                    file.clone(),
                    start,
                    start + name.len(),
                );
                let LocatedSemantic::Found(head) =
                    self.ready
                        .lookup_locator(&persisted, &locator, cancellation)?
                else {
                    continue;
                };
                let seeds = fragment_source
                    .lookup_reference_seeds(&[ResolutionQuery::new(head)], cancellation)?;
                if seeds.is_cancelled() {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
                let seed = seeds.rows()[0]
                    .seed()
                    .expect("located macro head has a reference seed");
                let RustSelectedBuildOutcome::Ready(Some((definition_file, declaration))) =
                    self.select_textual_macro_definition(caller, start, &name, cancellation)?
                else {
                    continue;
                };
                let Some(SelectedMacroBindingTarget {
                    host: definition_host,
                    semantic: definition,
                    node: definition_node,
                }) = self.selected_macro_binding_target(
                    &definition_file,
                    declaration,
                    cancellation,
                )?
                else {
                    continue;
                };
                let host = self
                    .ready
                    .inventory
                    .persisted_mount_record(mount.ordinal())?
                    .expect("selected macro host has an inventory record");
                // The macro name binds independently of argument matching.
                let Some(Ok(arm)) = self.match_selected_textual_macro(
                    caller,
                    start,
                    input.tree.start_byte,
                    &name,
                    cancellation,
                )?
                else {
                    if stage
                        .admit_macro_head_pair(
                            &host,
                            head,
                            seed.node(),
                            &definition_host,
                            definition,
                            definition_node,
                            cancellation,
                        )?
                        .is_none()
                    {
                        return Ok(SelectedResolutionStageOutcome::Cancelled);
                    }
                    continue;
                };
                let container = capsule.macro_rows().item_container(
                    connection,
                    capsule.blob_id(),
                    input.invocation,
                )?;
                let lowered_input =
                    brokk_bifrost_rust::macro_matcher::lower_selected_macro_input_with_sources(
                        &input.tree,
                        &arm,
                        container,
                    );
                let facts = &lowered_input.facts;
                let Some(module_scope) = source
                    .module_routes
                    .scopes
                    .iter()
                    .filter(|scope| scope.body_start <= start && start < scope.body_end)
                    .min_by_key(|scope| scope.body_end - scope.body_start)
                    .and_then(|scope| scope.resolution_scope)
                else {
                    continue;
                };
                let candidates = fragment_source.match_forward_candidates(
                    &[BatchCandidateRequest::new(
                        0,
                        EndpointSignature::new(
                            seed.node(),
                            StackPattern::closed([]),
                            StackPattern::closed([]),
                        ),
                    )],
                    cancellation,
                )?;
                let paths = fragment_source.hydrate_candidate_paths(
                    &candidates
                        .matches()
                        .iter()
                        .map(|row| row.candidate())
                        .collect::<Vec<_>>(),
                    cancellation,
                )?;
                if cancellation.is_cancelled() {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
                let checkpoints = paths
                    .iter()
                    .filter(|(_, path)| path.start().node() == seed.node())
                    .map(|(_, path)| path.end().node())
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    checkpoints.len(),
                    1,
                    "one macro head has one lexical entry checkpoint"
                );
                let checkpoint = *checkpoints.first().expect("macro checkpoint");
                let Some(provenance) = persisted.node_provenance(checkpoint, cancellation)? else {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                };
                let checkpoint = match provenance {
                    Some(SelectedNodeProvenance::FragmentLocal(local)) => local.identity(),
                    Some(SelectedNodeProvenance::Stage(stage)) => stage.identity(),
                    provenance => panic!("macro checkpoint must be source-owned: {provenance:?}"),
                };
                let mut host_context = Vec::new();
                let outcome = observed_typed.visit_rust_reference_context_pages(
                    TypedFactRequest::new(&[head]),
                    cancellation,
                    &mut FactPageVisitor::new(&mut |rows| {
                        host_context.extend_from_slice(rows);
                        Ok(true)
                    }),
                )?;
                if outcome.is_cancelled() {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
                assert_eq!(
                    host_context.len(),
                    1,
                    "macro head has canonical module context"
                );
                let host_context = host_context[0].row();
                let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                    fragment,
                    &self.ready.shared_names(),
                    Language::Rust,
                    facts,
                );
                let Some(artifact) = artifact.instantiate_macro_input(
                    selected_macro_capture_digest(input.invocation, &input.tree, &arm),
                    checkpoint,
                    module_scope,
                    cancellation,
                ) else {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                };
                use super::resolution_publication::{
                    ResolutionCapsuleKey, ResolutionCapsuleReferenceContext,
                    ResolutionCapsuleReferenceOwner,
                };
                let owner = match seed.reference_owner() {
                    None => ResolutionCapsuleReferenceOwner::Unknown,
                    Some(None) => ResolutionCapsuleReferenceOwner::Root,
                    Some(Some(owner)) => {
                        match persisted.semantic_provenance(owner, cancellation)? {
                            Some(SelectedSemanticProvenance::FragmentLocal(local)) => {
                                assert_eq!(
                                    local.mount().ordinal(),
                                    host.ordinal(),
                                    "macro reference owner belongs to its host"
                                );
                                ResolutionCapsuleReferenceOwner::HostLocal(local.local_key())
                            }
                            None => return Ok(SelectedResolutionStageOutcome::Cancelled),
                            other => {
                                panic!("original macro reference owner must be ordinary: {other:?}")
                            }
                        }
                    }
                };
                let mut references = Vec::new();
                for site in artifact.lexical().semantics() {
                    if site.role() != LoweredSemanticRole::Reference {
                        continue;
                    }
                    let metadata = site
                        .site_metadata()
                        .expect("macro reference has exact range");
                    let token = input
                        .tree
                        .tokens
                        .iter()
                        .position(|token| {
                            token.start_byte == metadata.start_byte()
                                && token.end_byte == metadata.end_byte()
                        })
                        .expect("lowered macro reference has canonical token occurrence");
                    references.push(ResolutionCapsuleReferenceContext {
                        semantic_key: ResolutionLocalKey::new(i64::from(
                            site.semantic()
                                .local_key()
                                .expect("dense capsule semantic is producer-local"),
                        )),
                        source_site: site.site(),
                        host_occurrence: input.occurrences[token],
                        module_context: host_context.module_context(),
                        module_declaration: host_context.module_declaration(),
                        reference_owner: owner,
                    });
                }
                let input_line: usize = connection
                    .prepare_cached(
                        "SELECT json_extract(arena.spans, '$[' || ?2 || '][2]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
                    )?
                    .query_row(
                        rusqlite::params![capsule.blob_id(), input.occurrences[0].get()],
                        |row| row.get(0),
                    )?;
                let key = ResolutionCapsuleKey {
                    host_content_oid: host.blob_oid(),
                    invocation: input.invocation,
                    definition_content_oid: definition_host.blob_oid(),
                    selected_declaration: declaration,
                    matched_arm_index: arm.arm_index,
                    producer_epoch: host.producer_epoch().to_owned(),
                };
                match self.prepare_publish_macro_capsule(
                    &host,
                    key,
                    checkpoint,
                    module_scope,
                    artifact,
                    &lowered_input,
                    input_line,
                    references,
                    cancellation,
                )? {
                    SelectedResolutionStageOutcome::Ready => {}
                    terminal => return Ok(terminal),
                }
                if stage
                    .admit_macro_head_pair(
                        &host,
                        head,
                        seed.node(),
                        &definition_host,
                        definition,
                        definition_node,
                        cancellation,
                    )?
                    .is_none()
                {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
            }
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        // An include splice equates the included content root with its host
        // scope. Discover only the include component reachable from the files
        // admitted by this request; crate container rows provide the placement.
        let mut include_scopes = BTreeMap::<
            (BindingFragmentId, ResolutionScopeId),
            BTreeSet<(BindingFragmentId, ResolutionScopeId)>,
        >::new();
        let mut facts_by_fragment = BTreeMap::<BindingFragmentId, RustUsageFacts>::new();
        let mut pending_hosts = files.iter().map(PathBuf::from).collect::<Vec<_>>();
        let mut visited_hosts = HashSet::default();
        while let Some(host_file) = pending_hosts.pop() {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            if !visited_hosts.insert(host_file.clone()) {
                continue;
            }
            let Some(host) = self.rust_macro_capsule(&selected_path_key(&host_file))? else {
                continue;
            };
            let Some(host_facts) = self.selected_rust_usage_facts(&host_file, cancellation)? else {
                continue;
            };
            facts_by_fragment.insert(host.mount().fragment(), host_facts.clone());
            let host_path = crate::path_utils::normalize_pattern(&host_file.to_string_lossy());
            for edge in &host_facts.include_edges {
                let included_files = connection
                    .prepare_cached(rust_crate_context::MACRO_INCLUDED_FILE)?
                    .query_map(rusqlite::params![host_path, edge.file_name], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<BTreeSet<_>>>()?;
                for included_file in included_files {
                    let included_file = PathBuf::from(included_file);
                    let Some(included) =
                        self.rust_macro_capsule(&selected_path_key(&included_file))?
                    else {
                        continue;
                    };
                    if let Some(facts) =
                        self.selected_rust_usage_facts(&included_file, cancellation)?
                    {
                        facts_by_fragment.insert(included.mount().fragment(), facts);
                    }
                    let scope: Option<u32> = connection
                        .prepare_cached(
                            "SELECT i.native_scope
                         FROM source_rust_macro_inputs AS i
                         WHERE i.blob_id=?1 AND i.invocation_start_byte=?2",
                        )?
                        .query_row(
                            rusqlite::params![host.blob_id(), edge.include_start],
                            |row| row.get(0),
                        )
                        .optional()?
                        .flatten();
                    let Some(scope) = scope else {
                        continue;
                    };
                    let host_scope = (host.mount().fragment(), ResolutionScopeId::new(scope));
                    let included_scope = (included.mount().fragment(), ResolutionScopeId::new(0));
                    include_scopes
                        .entry(host_scope)
                        .or_default()
                        .insert(included_scope);
                    include_scopes
                        .entry(included_scope)
                        .or_default()
                        .insert(host_scope);
                    pending_hosts.push(included_file);
                }
            }
        }
        let mut visited_scopes = BTreeSet::new();
        for &initial in include_scopes.keys() {
            if !visited_scopes.insert(initial) {
                continue;
            }
            let mut pending = vec![initial];
            let mut component = vec![initial];
            while let Some(scope) = pending.pop() {
                for &adjacent in &include_scopes[&scope] {
                    if visited_scopes.insert(adjacent) {
                        pending.push(adjacent);
                        component.push(adjacent);
                    }
                }
            }
            let mut include_demands = BTreeMap::new();
            let mut explicit_names = HashSet::default();
            for &(fragment, scope) in &component {
                let mount = self
                    .ready
                    .inventory
                    .mount_record_for_fragment(fragment)?
                    .expect("splice scope is mounted");
                let source = facts_by_fragment
                    .get(&fragment)
                    .expect("splice scope has source facts");
                explicit_names.extend(
                    source
                        .import_targets
                        .iter()
                        .filter(|import| import.native_scope == Some(scope) && !import.is_glob)
                        .filter_map(|import| import.bound_name.clone()),
                );
                // Enumerate this include component's actual lookup demands.
                let Some(recipes) = persisted.lookup_recipes(mount.ordinal(), cancellation)? else {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                };
                for recipe in recipes {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedResolutionStageOutcome::Cancelled);
                    }
                    if !matches!(
                        recipe.namespace(),
                        ResolutionNamespace::Type
                            | ResolutionNamespace::Value
                            | ResolutionNamespace::Macro
                    ) {
                        continue;
                    }
                    assert_eq!(recipe.semantic_language(), Language::Rust.config_label());
                    include_demands.insert(recipe.semantic(&self.ready.shared_names()), recipe);
                }
            }
            for &(origin_fragment, origin_scope) in &component {
                let mut original_paths =
                    persisted.include_scope_paths(origin_fragment, origin_scope, cancellation)?;
                if cancellation.is_cancelled() {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                }
                let origin_mount = self
                    .ready
                    .inventory
                    .mount_record_for_fragment(origin_fragment)?
                    .expect("include origin is mounted");
                let origin_source = facts_by_fragment
                    .get(&origin_fragment)
                    .expect("glob origin has source facts");
                // The import halves the origin scope already holds, keyed as
                // a glob demand is compared against them. Classifying a path
                // reads its anchor's owner, so each path is classified once
                // here rather than once per glob import and demand: tract's
                // `include!`-spliced mobilenet tests re-read tens of
                // thousands of anchors per point request.
                let mut present_imports = HashSet::default();
                for (identity, path) in &original_paths {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedResolutionStageOutcome::Cancelled);
                    }
                    if let Some(SelectedRootPathHalf::Import {
                        route,
                        demand,
                        anchor,
                        ..
                    }) = crate::analyzer::resolution::classify_selected_root_path_half(
                        &persisted,
                        *identity,
                        path,
                        cancellation,
                    )? {
                        present_imports.insert((route, demand, anchor));
                    }
                }
                for import in origin_source
                    .import_targets
                    .iter()
                    .filter(|import| import.is_glob && import.native_scope == Some(origin_scope))
                {
                    for demand in include_demands
                        .values()
                        .filter(|demand| !explicit_names.contains(demand.spelling()))
                    {
                        let route = import
                            .module_path
                            .iter()
                            .map(|name| {
                                ResolutionLookupSemanticRecipe::new(
                                    Language::Rust,
                                    demand.namespace(),
                                    name,
                                )
                                .semantic(&self.ready.shared_names())
                            })
                            .collect::<Vec<_>>();
                        let anchor = if import.leading_absolute {
                            ResolutionRootImportAnchor::Absolute
                        } else {
                            ResolutionRootImportAnchor::Lexical
                        };
                        let key = (
                            route.into_boxed_slice(),
                            demand.semantic(&self.ready.shared_names()),
                            anchor,
                        );
                        if present_imports.contains(&key) {
                            continue;
                        }
                        let (glob, catalog) = LoweredResolutionFragment::selected_include_glob(
                            origin_fragment,
                            &self.ready.shared_names(),
                            import,
                            demand,
                        );
                        let Some(path) =
                            stage.admit_include_glob(&origin_mount, glob, catalog, cancellation)?
                        else {
                            return Ok(SelectedResolutionStageOutcome::Cancelled);
                        };
                        original_paths.push(path);
                        present_imports.insert(key);
                    }
                }
                for (original_identity, original) in original_paths {
                    let end = original.end().node();
                    let classification = persisted.classify_endpoint_nodes(&[end], cancellation)?;
                    if cancellation.is_cancelled() {
                        return Ok(SelectedResolutionStageOutcome::Cancelled);
                    }
                    let end_kind = classification[0]
                        .definition()
                        .map(crate::analyzer::resolution::BindingNodeKind::Definition)
                        .unwrap_or(crate::analyzer::resolution::BindingNodeKind::Scope);
                    for &(destination_fragment, destination_scope) in &component {
                        if (destination_fragment, destination_scope)
                            == (origin_fragment, origin_scope)
                        {
                            continue;
                        }
                        let destination_mount = self
                            .ready
                            .inventory
                            .mount_record_for_fragment(destination_fragment)?
                            .expect("include destination is mounted");
                        let Some(destination) = persisted.scope_head_node_of(
                            destination_fragment,
                            destination_scope,
                            cancellation,
                        )?
                        else {
                            return Ok(SelectedResolutionStageOutcome::Cancelled);
                        };
                        if stage
                            .admit_include_binding_pair(
                                &destination_mount,
                                destination,
                                &origin_mount,
                                original_identity,
                                &original,
                                end_kind,
                                cancellation,
                            )?
                            .is_none()
                        {
                            return Ok(SelectedResolutionStageOutcome::Cancelled);
                        }
                    }
                }
            }
        }
        Ok(SelectedResolutionStageOutcome::Ready)
    }

    /// Forget what the textual-macro module walk has answered so far.
    ///
    /// Called at a crate-stage boundary, where a whole-workspace request would
    /// otherwise accumulate one `RustUsageFacts` per file every stage's walks
    /// read. Nothing else in the request refers to these answers, so dropping
    /// them can only cost a reread.
    fn clear_selected_macro_walk_answers(&self) {
        *self.ready.macro_walk.borrow_mut() = SelectedTextualMacroWalkMemo::default();
    }

    /// Prepare generated frontiers only for files admitted by this query.
    fn prepare_selected_macro_frontiers_for_files(
        &self,
        files: &[&Path],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        if !self.ready.macro_overlay.borrow().serde_helpers_closed {
            let outcome = self.close_serde_helper_gaps(cancellation)?;
            if !matches!(outcome, SelectedResolutionStageOutcome::Ready) {
                return Ok(outcome);
            }
            self.ready.macro_overlay.borrow_mut().serde_helpers_closed = true;
        }
        let mut demanded = files
            .iter()
            .map(|file| file.to_path_buf())
            .collect::<Vec<_>>();
        for file in files {
            let path = crate::path_utils::rel_path_string(&ProjectFile::new(
                self.ready.project.root(),
                file,
            ));
            for host in self
                .ready
                .inventory
                .connection()
                .prepare_cached(rust_crate_context::MACRO_HOST_FILES)?
                .query_map([path], |row| row.get::<_, String>(0))?
            {
                demanded.push(PathBuf::from(host?));
            }
        }
        demanded.sort_unstable();
        demanded.dedup();
        let mut macro_files = Vec::new();
        for caller in &demanded {
            let Some(mount) = self.rust_macro_capsule(&selected_path_key(caller))? else {
                continue;
            };
            let Some(inputs) = mount.macro_rows().input_rows(
                self.ready.inventory.connection(),
                mount.blob_id(),
                &|| !cancellation.is_cancelled(),
            )?
            else {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            };
            if !inputs.is_empty() {
                macro_files.push(mount.mount().persisted_relative_path().to_owned());
            }
        }
        if macro_files.is_empty() {
            return Ok(if cancellation.is_cancelled() {
                SelectedResolutionStageOutcome::Cancelled
            } else {
                SelectedResolutionStageOutcome::Ready
            });
        }
        if let outcome @ (SelectedResolutionStageOutcome::Cancelled
        | SelectedResolutionStageOutcome::Stale(_)
        | SelectedResolutionStageOutcome::Unavailable(_)) =
            self.prepare_selected_macro_reference_overlay(&macro_files, cancellation)?
        {
            return Ok(outcome);
        }
        for file in &macro_files {
            if let outcome @ (SelectedResolutionStageOutcome::Cancelled
            | SelectedResolutionStageOutcome::Stale(_)
            | SelectedResolutionStageOutcome::Unavailable(_)) =
                self.prepare_selected_macro_file_frontiers(Path::new(file), cancellation)?
            {
                return Ok(outcome);
            }
        }
        Ok(SelectedResolutionStageOutcome::Ready)
    }

    fn prepare_selected_macro_frontiers(
        &self,
        caller: &Path,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        self.prepare_selected_macro_frontiers_for_files(&[caller], cancellation)
    }

    fn prepare_selected_macro_file_frontiers(
        &self,
        caller: &Path,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        if self.ready.prepared_macro_files.borrow().contains(caller) {
            return Ok(SelectedResolutionStageOutcome::Ready);
        }
        let Some(mount) = self.rust_macro_capsule(&selected_path_key(caller))? else {
            return Ok(SelectedResolutionStageOutcome::Ready);
        };
        let connection = self.ready.inventory.connection();
        let Some(inputs) = mount
            .macro_rows()
            .input_rows(connection, mount.blob_id(), &|| {
                !cancellation.is_cancelled()
            })?
        else {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        };
        if inputs.is_empty() {
            return Ok(SelectedResolutionStageOutcome::Ready);
        }
        if let outcome @ (SelectedResolutionStageOutcome::Cancelled
        | SelectedResolutionStageOutcome::Stale(_)
        | SelectedResolutionStageOutcome::Unavailable(_)) = self
            .prepare_selected_macro_reference_overlay(
                &[caller.to_string_lossy().into_owned()],
                cancellation,
            )?
        {
            return Ok(outcome);
        }
        let caller_path = crate::path_utils::normalize_pattern(&caller.to_string_lossy());
        let included_sources = connection
            .prepare_cached(rust_crate_context::MACRO_INCLUDE_STARTS)?
            .query_map([caller_path], |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let stage = super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory);
        let host = self
            .ready
            .inventory
            .persisted_mount_record(mount.mount().ordinal())?
            .expect("macro frontier host is selected");
        for input in inputs {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            if input.native_frontier.is_none() {
                continue;
            }
            let invocation = connection
                .prepare_cached(MACRO_INVOCATION_START_AND_NAME_SQL)?
                .query_row(
                    rusqlite::params![mount.blob_id(), input.invocation.get()],
                    |row| Ok((row.get::<_, usize>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let Some((start, name)) = invocation else {
                continue;
            };
            let mut included = false;
            for (_, path, blob) in included_sources
                .iter()
                .filter(|(edge, _, _)| *edge == start)
            {
                let Some(source) = self.ready.inventory.mount_record_for_path("rust", path)? else {
                    return Ok(SelectedResolutionStageOutcome::Unavailable(
                        SelectedResolutionUnavailable::MissingBlob {
                            storage_language: "rust".to_owned(),
                            persisted_relative_path: path.clone(),
                        },
                    ));
                };
                if source.blob_id() != *blob {
                    return Ok(SelectedResolutionStageOutcome::Stale(
                        SelectedResolutionStale::MountInventoryChanged,
                    ));
                }
                match stage.close_included_macro_input(
                    &host,
                    input.invocation,
                    &source,
                    start,
                    cancellation,
                )? {
                    SelectedResolutionStageOutcome::Ready => included = true,
                    terminal => return Ok(terminal),
                }
            }
            if included {
                continue;
            }
            match stage.has_admitted_macro_input(host.ordinal(), input.invocation, cancellation)? {
                Some(true) => continue,
                Some(false) => {}
                None => return Ok(SelectedResolutionStageOutcome::Cancelled),
            }
            let matched = self.match_selected_textual_macro(
                caller,
                start,
                input.tree.start_byte,
                &name,
                cancellation,
            )?;
            let closes = match &matched {
                Some(Err(brokk_bifrost_rust::macro_matcher::MacroMatchError::NoArmMatched)) => true,
                Some(Ok(arm)) => {
                    let container = mount.macro_rows().item_container(
                        connection,
                        mount.blob_id(),
                        input.invocation,
                    )?;
                    let facts = brokk_bifrost_rust::macro_matcher::lower_selected_macro_input(
                        &input.tree,
                        arm,
                        container,
                    );
                    facts.identifiers.is_empty()
                        && facts.gaps.is_empty()
                        && facts.reference_enumeration_gaps.is_empty()
                }
                _ => false,
            };
            if !closes {
                continue;
            }
            let (definition_file, declaration) =
                match self.select_textual_macro_definition(caller, start, &name, cancellation)? {
                    RustSelectedBuildOutcome::Ready(Some(selected)) => selected,
                    RustSelectedBuildOutcome::Ready(None) => {
                        panic!("matched macro has a selected definition")
                    }
                    RustSelectedBuildOutcome::Stopped => {
                        return Ok(SelectedResolutionStageOutcome::Cancelled);
                    }
                };
            let Some(definition) = self
                .ready
                .inventory
                .mount_record_for_path("rust", &selected_path_key(&definition_file))?
            else {
                return Ok(SelectedResolutionStageOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingBlob {
                        storage_language: "rust".to_owned(),
                        persisted_relative_path: selected_path_key(&definition_file),
                    },
                ));
            };
            let outcome = match matched {
                Some(Err(brokk_bifrost_rust::macro_matcher::MacroMatchError::NoArmMatched)) => {
                    stage.close_unmatched_macro_input(
                        &host,
                        input.invocation,
                        &definition,
                        declaration,
                        cancellation,
                    )?
                }
                Some(Ok(arm)) => stage.close_empty_macro_input(
                    &host,
                    input.invocation,
                    &definition,
                    declaration,
                    arm.arm_index,
                    cancellation,
                )?,
                _ => unreachable!("only structurally closed macro input reaches publication"),
            };
            if !matches!(outcome, SelectedResolutionStageOutcome::Ready) {
                return Ok(outcome);
            }
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        self.ready
            .prepared_macro_files
            .borrow_mut()
            .insert(caller.to_path_buf());
        Ok(SelectedResolutionStageOutcome::Ready)
    }

    fn select_imported_macro_definition(
        &self,
        caller: &Path,
        position: usize,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<RustSelectedBuildOutcome<Option<(PathBuf, SourceDeclarationId)>>> {
        if cancellation.is_cancelled() {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let caller = crate::path_utils::normalize_pattern(&caller.to_string_lossy());
        let sql = "WITH candidates(rel_path, declaration_id, local_extent, is_glob) AS (
            SELECT DISTINCT target_source.rel_path, bridge.declaration_id,
                   COALESCE(source.local_end-source.local_start, 9223372036854775807), 0
            FROM rust_crate_container_sources AS owner
            CROSS JOIN selected_rust_crates AS selected
              ON selected.topology_id=owner.topology_id
            CROSS JOIN rust_crate_imports AS import
              ON import.topology_id=owner.topology_id
             AND import.module_path=owner.container_path
             AND import.blob_id=owner.blob_id
            CROSS JOIN source_rust_import_targets AS source
              ON source.blob_id=import.blob_id
             AND source.ordinal=import.import_ordinal
             AND source.native_scope=import.binder_scope
            CROSS JOIN selected_rust_crates AS target
              ON target.crate_key=import.target_crate_key
            CROSS JOIN rust_crate_exports AS export
              ON export.topology_id=target.topology_id
             AND export.module_path=import.target_module_path
             AND export.namespace='macro'
             AND export.name=import.target_name
            CROSS JOIN source_native_declaration_bridges AS bridge
              ON bridge.blob_id=export.declaration_blob_id
             AND bridge.source_site=export.declaration_site
            CROSS JOIN rust_crate_container_sources AS target_source
              ON target_source.topology_id=export.topology_id
             AND target_source.blob_id=export.declaration_blob_id
            WHERE owner.rel_path=?1 AND import.namespace='macro'
              AND import.bound_name=?3
              AND source.owner_start<=?2 AND ?2<source.owner_end
              AND (source.local_start IS NULL
                   OR (source.local_start<=?2 AND ?2<source.local_end))
            UNION ALL
            SELECT DISTINCT target_source.rel_path, bridge.declaration_id,
                   COALESCE(source.local_end-source.local_start, 9223372036854775807), 1
            FROM rust_crate_container_sources AS owner
            CROSS JOIN selected_rust_crates AS selected
              ON selected.topology_id=owner.topology_id
            CROSS JOIN rust_crate_glob_imports AS import
              ON import.topology_id=owner.topology_id
             AND import.module_path=owner.container_path
             AND import.blob_id=owner.blob_id
            CROSS JOIN source_rust_import_targets AS source
              ON source.blob_id=import.blob_id
             AND source.ordinal=import.import_ordinal
             AND source.native_scope=import.binder_scope
            CROSS JOIN selected_rust_crates AS target
              ON target.crate_key=import.target_crate_key
            CROSS JOIN rust_crate_exports AS export
              ON export.topology_id=target.topology_id
             AND export.module_path=import.target_module_path
             AND export.namespace='macro' AND export.name=?3
            CROSS JOIN source_native_declaration_bridges AS bridge
              ON bridge.blob_id=export.declaration_blob_id
             AND bridge.source_site=export.declaration_site
            CROSS JOIN rust_crate_container_sources AS target_source
              ON target_source.topology_id=export.topology_id
             AND target_source.blob_id=export.declaration_blob_id
            WHERE owner.rel_path=?1
              AND source.owner_start<=?2 AND ?2<source.owner_end
              AND (source.local_start IS NULL
                   OR (source.local_start<=?2 AND ?2<source.local_end))
        )
        SELECT rel_path, declaration_id, local_extent, is_glob
        FROM candidates ORDER BY local_extent, is_glob, rel_path, declaration_id";
        let mut nearest = None;
        let mut selected = BTreeSet::new();
        let mut statement = self.ready.inventory.connection().prepare_cached(sql)?;
        for row in statement.query_map(rusqlite::params![caller, position, name], |row| {
            Ok((
                PathBuf::from(row.get::<_, String>(0)?),
                SourceDeclarationId::new(row.get::<_, u32>(1)?),
                (row.get::<_, i64>(2)?, row.get::<_, bool>(3)?),
            ))
        })? {
            if cancellation.is_cancelled() {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let (file, declaration, rank) = row?;
            if nearest.is_some_and(|previous| rank > previous) {
                continue;
            }
            if nearest.is_none_or(|previous| rank < previous) {
                selected.clear();
                nearest = Some(rank);
            }
            selected.insert((file, declaration));
        }
        Ok(RustSelectedBuildOutcome::Ready((selected.len() == 1).then(
            || selected.pop_first().expect("unique selected macro"),
        )))
    }

    #[cfg(test)]
    pub(crate) fn attach_active_reverse_sql_work_trace(&self) {
        if !rust_reverse_rows::reverse_sql_work_trace_active() {
            return;
        }
        rust_reverse_rows::attach_reverse_sql_work_trace(self.ready.inventory.connection());
    }

    fn ensure_selected_rust_inputs(&self, cancellation: &CancellationToken) -> Result<bool> {
        Ok(!cancellation.is_cancelled())
    }

    fn ensure_selected_rust_inputs_in_session(
        &self,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<bool> {
        Ok(!cancellation.is_cancelled() && session.scope_step())
    }

    pub(crate) fn rust_demand_preparation_for_caller_in_session(
        &self,
        caller: &std::path::Path,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<SelectedRustCallerDemandOutcome> {
        if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
            return Ok(SelectedRustCallerDemandOutcome::Cancelled);
        }
        {
            let retained = self.ready.rust_caller_demand.borrow();
            if let Some(retained) = retained
                .as_ref()
                .filter(|retained| retained.caller == caller)
            {
                return Ok(match &retained.prepared {
                    Some(prepared) => SelectedRustCallerDemandOutcome::Ready(prepared.clone()),
                    None => SelectedRustCallerDemandOutcome::Unavailable,
                });
            }
        }
        // Preparation is bounded by cancellation, never by the requesting
        // site's receiver budget: it is shared by every request in the file and
        // charging the first request for it is what made the five Rust #2767
        // sites answer `exceeded_budget` before they resolved anything.
        let outcome = self.build_rust_demand_preparation_for_caller(caller, cancellation, None)?;
        match &outcome {
            SelectedRustCallerDemandOutcome::Ready(prepared) => {
                self.ready
                    .rust_caller_demand
                    .replace(Some(RetainedRustCallerDemand {
                        caller: caller.to_path_buf(),
                        prepared: Some(prepared.clone()),
                    }));
            }
            SelectedRustCallerDemandOutcome::Unavailable => {
                self.ready
                    .rust_caller_demand
                    .replace(Some(RetainedRustCallerDemand {
                        caller: caller.to_path_buf(),
                        prepared: None,
                    }));
            }
            // A cancelled build produced nothing, so there is nothing to retain
            // and the next request must build it again.
            SelectedRustCallerDemandOutcome::Cancelled => {}
        }
        Ok(outcome)
    }

    fn build_rust_demand_preparation_for_caller(
        &self,
        caller: &Path,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<SelectedRustCallerDemandOutcome> {
        if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
            return Ok(SelectedRustCallerDemandOutcome::Cancelled);
        }
        let crate_keys = self.rust_crate_keys_for_file(caller, cancellation)?;
        if crate_keys.is_empty() {
            return Ok(SelectedRustCallerDemandOutcome::Unavailable);
        }
        // The topologies those keys name, read once for the whole file rather
        // than once per site: the root anchor is followed per owning Cargo
        // target, and a request made on behalf of one target must not follow
        // it into another. One primary-key seek per key, on a statement this
        // module already pins.
        let mut topologies = Vec::with_capacity(crate_keys.len());
        {
            let connection = self.ready.inventory.connection();
            let mut statement = connection.prepare_cached(rust_crate_context::CRATE)?;
            for key in &crate_keys {
                topologies.push(statement.query_row([key.as_slice()], |row| row.get::<_, i64>(0))?);
            }
        }
        topologies.sort_unstable();
        topologies.dedup();
        // The preparation is shared by every request in the file and carries no
        // declaration authority: a point request and a reverse confirmation
        // read a detached root's cfg atoms differently, and each attaches its
        // own policy below.
        Ok(SelectedRustCallerDemandOutcome::Ready(Arc::new(
            RustCallerDemand {
                contexts: self.empty_contexts(&ResolutionCompletion::Complete)?,
                crate_keys,
                demand: RustDemandPreparation::new(topologies.into_boxed_slice()),
            },
        )))
    }

    /// The scope's sources own the import and reference halves a bridge can
    /// leave from; its targets own the export halves a bridge can land on.
    /// Nothing outside those two mount sets is probed.
    fn rust_root_halves(
        &self,
        scope: &RustRootHalfScope,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<Option<(Vec<SelectedRootPathHalf>, ResolutionCompletion)>> {
        let persisted = self.ready.lexical_source();
        let mut halves = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        if !collect_selected_root_halves(
            &self.ready.context_identities,
            &persisted,
            &persisted,
            scope,
            cancellation,
            session,
            &mut halves,
            &mut completion,
        )? {
            return Ok(None);
        }
        let mut completions = vec![completion];
        for half in &halves {
            if let SelectedRootPathHalf::Export {
                incomplete_reasons, ..
            } = half
            {
                completions.push(if incomplete_reasons.is_empty() {
                    ResolutionCompletion::Complete
                } else {
                    ResolutionCompletion::incomplete(incomplete_reasons.iter().copied())
                });
            }
        }
        let Some(closed) = persisted.close_completions(&completions, cancellation)? else {
            return Ok(None);
        };
        let mut closed = closed.into_iter();
        let mut completion = closed.next().expect("top-level completion is first");
        for half in &mut halves {
            if let SelectedRootPathHalf::Export {
                incomplete_reasons, ..
            } = half
            {
                *incomplete_reasons = match closed.next().expect("one completion per export") {
                    ResolutionCompletion::Complete => Box::new([]),
                    ResolutionCompletion::Incomplete(reasons) => reasons.iter().copied().collect(),
                };
            }
        }
        assert!(closed.next().is_none());
        if let ResolutionCompletion::Incomplete(reasons) = &completion {
            let mut candidates = Vec::new();
            for &reason in reasons.iter() {
                if cancellation.is_cancelled()
                    || session.is_some_and(|session| !session.scope_step())
                {
                    return Ok(None);
                }
                if let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason {
                    candidates.push(reason);
                }
            }
            // The same indexed provenance used by typed reverse narrowing
            // distinguishes enumerated qualified routes from omitted root
            // inventory. Their binding uncertainty remains on the typed route.
            let persisted_typed = self.ready.typed_source();
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            candidates.sort_unstable();
            candidates.dedup();
            let mut represented = BTreeSet::new();
            let mut read_completion = ResolutionCompletion::Complete;
            for candidates in candidates.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                let outcome = observed_typed.visit_qualified_route_pages_for_gap_reasons(
                    TypedFactRequest::new(candidates),
                    cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        for route in page {
                            if cancellation.is_cancelled()
                                || session.is_some_and(|session| !session.scope_step())
                            {
                                return Ok(false);
                            }
                            represented.insert(ResolutionIncompleteReason::UnsupportedSemantic(
                                route.row().coarse_gap_reason(),
                            ));
                        }
                        Ok(true)
                    }),
                )?;
                if !outcome.is_exhausted() || cancellation.is_cancelled() {
                    return Ok(None);
                }
                read_completion = read_completion.combine(outcome.evidence());
            }
            let Some(retained) = reasons.without_reasons_with_poll(represented, &mut || {
                cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step())
            }) else {
                return Ok(None);
            };
            completion = retained
                .map_or(
                    ResolutionCompletion::Complete,
                    ResolutionCompletion::Incomplete,
                )
                .combine(&read_completion);
        }
        Ok(Some((halves, completion)))
    }

    /// Read the exact native authority for every selected export definition.
    /// A persisted endpoint's definition node names a source site in the
    /// blob's interior, and that source site joins `resolution_semantic_sites`
    /// to the native declaration bridge. An endpoint without ordinary source
    /// authority remains a structured error.
    fn rust_declaration_authorities_for_exports(
        &self,
        persisted: &SelectedResolutionLexicalSource<'_, '_>,
        halves: &[SelectedRootPathHalf],
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<Option<BTreeMap<BindingNodeId, RustSelectedDeclarationAuthorityFact>>> {
        let mut authorities = BTreeMap::new();
        let mut persisted_requests = BTreeSet::new();
        let mounts = self.mount_table();
        for half in halves {
            if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let SelectedRootPathHalf::Export {
                identity,
                definition,
                ..
            } = half
            else {
                continue;
            };
            let mount = mounts
                .mount_for_fragment(identity.fragment())?
                .expect("selected Rust export endpoint names an operation mount");
            persisted_requests.insert((mount.ordinal(), *definition));
        }
        let persisted_requests = persisted_requests.into_iter().collect::<Vec<_>>();
        let mut site_requests = Vec::with_capacity(persisted_requests.len());
        let Some(sites) = persisted.definition_source_sites(&persisted_requests, cancellation)?
        else {
            return Ok(None);
        };
        let mut located = Vec::with_capacity(persisted_requests.len());
        for (&(mount, definition), site) in persisted_requests.iter().zip(sites) {
            let Some(site) = site else {
                // A macro overlay's export names a node the stage minted, not
                // one the persisted interior holds, so this read has no source
                // site for it and there is no ordinary declaration authority
                // to publish. The consumer already skips an export with no
                // authority, which is the right answer: an exact bridge lands
                // on a declaration the store can name, and this expansion's is
                // not one. A persisted node with no source site is still a
                // store inconsistency and still reported.
                if definition
                    .local_key()
                    .is_some_and(|key| i64::from(key) >= SUPPLEMENTAL_LOCAL_KEY_BASE)
                {
                    continue;
                }
                return Err(StoreError::corrupt(format!(
                    "selected Rust export definition node declares no source site: mount={mount:?}, definition={definition:?}"
                )));
            };
            site_requests.push((mount, site));
            located.push(definition);
        }
        let authority_facts = read_selected_rust_declaration_authority_with_cancellation(
            &self.ready.inventory,
            &site_requests,
            cancellation,
            session,
        )?;
        let Some(authority_facts) = authority_facts else {
            return Ok(None);
        };
        if authority_facts.len() != located.len() {
            return Err(StoreError::corrupt(format!(
                "selected Rust export authority request/result mismatch: requests={located:?}, authorities={authority_facts:?}"
            )));
        }
        for (definition, authority) in located.into_iter().zip(authority_facts) {
            if let Some(previous) = authorities.insert(definition, authority.clone())
                && previous != authority
            {
                return Err(StoreError::corrupt(format!(
                    "selected Rust export definition has conflicting authorities: definition={definition:?}, previous={previous:?}, current={authority:?}"
                )));
            }
        }
        Ok(Some(authorities))
    }
}

/// One macro invocation's start byte and name, by its occurrence in a blob.
/// Both macro-overlay preparations ask it once per macro input.
/// The macro each unexpanded-item-macro reason in `completion` stands for,
/// as a name the incomplete-binding diagnostic prints beside the reason.
///
/// The reason is the producer's gap at the invocation, so its fragment-local
/// key finds the gap row, the gap's site finds the invocation input whose
/// frontier it is, and the input finds the invocation's macro name.
/// Recover every invocation behind one retained crate inventory reason.
/// A reason containing any other evidence cannot be discharged by a generated
/// declaration model. JSON is the existing SQL-readable crate evidence row.
fn inventory_macro_gaps(
    ready: &ReadySelectedResolution<'_, '_>,
    detail: &str,
    semantic: SemanticId,
) -> Result<Vec<SelectedRustMacroExpansionGap>> {
    let mut statement = ready.inventory.connection().prepare_cached(
        "SELECT evidence.value ->> '$.reason', head.macro_name,
                mount.persisted_relative_path, head.start_byte, head.end_byte
         FROM json_each(?1, '$.evidence') AS evidence
         LEFT JOIN source_rust_macro_invocations AS head
           ON head.blob_id = evidence.value ->> '$.member_blob'
          AND head.occurrence_id = evidence.value ->> '$.invocation_occurrence'
         LEFT JOIN temp.selected_resolution_mounts AS mount
           ON mount.blob_id = head.blob_id AND mount.storage_language = 'rust'",
    )?;
    let rows = statement.query_map([detail], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<usize>>(3)?,
            row.get::<_, Option<usize>>(4)?,
        ))
    })?;
    let mut gaps = Vec::new();
    for row in rows {
        let (reason, name, path, start, end) = row?;
        let (Some(macro_name), Some(relative_path), Some(start_byte), Some(end_byte)) =
            (name, path, start, end)
        else {
            return Ok(Vec::new());
        };
        if reason.as_deref() != Some("UnsupportedMacroGeneratedModule") {
            return Ok(Vec::new());
        }
        gaps.push(SelectedRustMacroExpansionGap {
            semantic,
            relative_path,
            start_byte,
            end_byte,
            macro_name,
        });
    }
    Ok(gaps)
}

fn unexpanded_item_macro_gaps(
    ready: &ReadySelectedResolution<'_, '_>,
    completion: &ResolutionCompletion,
) -> Result<Vec<SelectedRustMacroExpansionGap>> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(Vec::new());
    };
    let [item_origin, impl_origin] = [
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedItemMacro,
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro,
    ]
    .map(|kind| {
        crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(kind),
        )
    });
    let connection = ready.inventory.connection();
    let mut names = Vec::new();
    for reason in reasons.iter() {
        let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
            continue;
        };
        let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
            continue;
        };
        let Some(mount) = ready
            .inventory
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(ordinal))?
        else {
            continue;
        };
        let name = connection
            .prepare_cached(
                "SELECT head.macro_name, head.start_byte, head.end_byte FROM resolution_gap_reasons AS gap
                 JOIN source_rust_macro_inputs AS input
                   ON input.blob_id = gap.blob_id AND input.native_gap_site = gap.site
                 JOIN source_rust_macro_invocations AS head
                   ON head.blob_id = input.blob_id
                  AND head.occurrence_id = input.invocation_occurrence_id
                 WHERE gap.blob_id = ?1 AND gap.reason = ?2 AND gap.origin IN (?3, ?4)",
            )?
            .query_row(
                rusqlite::params![mount.blob_id(), key, item_origin, impl_origin],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?, row.get::<_, usize>(2)?)),
            )
            .optional()?;
        if let Some((macro_name, start_byte, end_byte)) = name {
            names.push(SelectedRustMacroExpansionGap {
                semantic: *semantic,
                relative_path: mount.persisted_relative_path().to_owned(),
                start_byte,
                end_byte,
                macro_name,
            });
        }
    }
    Ok(names)
}

const MACRO_INVOCATION_START_AND_NAME_SQL: &str = "SELECT i.start_byte, i.macro_name FROM source_rust_macro_invocations i WHERE i.blob_id = ?1 AND i.occurrence_id = ?2";

/// R2.3 work attribution: report the session's charged work at a named point
/// on the Rust point path.
///
/// The budget that decides whether a point request answers or gives up is one
/// running total, so a total alone cannot say which stage spent it. These
/// checkpoints turn the total into a per-stage attribution. They are off
/// unless `BIFROST_R23_WORK_ATTRIBUTION` is set, and the flag is read once.
fn note_rust_point_work(checkpoint: &str, session: &ResolutionSession) {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if !*ENABLED.get_or_init(|| {
        std::env::var_os("BIFROST_R23_WORK_ATTRIBUTION").is_some_and(|value| value == "1")
    }) {
        return;
    }
    let work = session.finish(()).work();
    println!(
        "{{\"attribution\":\"rust_point_work\",\"checkpoint\":\"{checkpoint}\",\"scope_nodes\":{},\"summary_expansions\":{}}}",
        work.scope_nodes, work.summary_expansions
    );
}

/// Hydrates definition rows of one selected Rust mount into `CodeUnit`s.
///
/// Every row of a mount is in one file and a file has one package naming, so
/// the naming is read once here and every row the caller hydrates reuses it.
/// A caller that walks a mount's rows builds one of these before the walk.
struct RustMountUnits {
    file: ProjectFile,
    naming: Option<rust_crate_context::RustFileNaming>,
}

impl RustMountUnits {
    fn new(
        ready: &ReadySelectedResolution<'_, '_>,
        mount: &SelectedResolutionOperationMount,
    ) -> Result<Self> {
        assert_eq!(
            mount.semantic_language(),
            Language::Rust,
            "only a Rust mount can hydrate a Rust definition unit"
        );
        let file = ProjectFile::new(
            ready.project.root(),
            std::path::PathBuf::from(mount.persisted_relative_path()),
        );
        let naming = rust_crate_context::RustFileNaming::read(ready, &file)?;
        Ok(Self { file, naming })
    }

    fn unit(&self, row: &super::HydratedCandidateRow) -> Result<CodeUnit> {
        let prefix = row.fq.as_ref().and_then(|fq| fq.anchor).and_then(|anchor| {
            self.naming
                .as_ref()
                .map(|naming| naming.package_prefix(anchor))
        });
        let (fq, package_segment_count) = super::hydrate_unit_fq_with_anchor(
            row.fq.as_ref(),
            &row.content_qualifier,
            &self.file,
            |_, _, _| prefix,
        )?;
        Ok(CodeUnit::from_fq(
            self.file.clone(),
            row.kind,
            fq,
            package_segment_count,
            row.signature.clone(),
            row.flags.synthetic,
        ))
    }
}

fn selected_reference_source_sites(
    source: &(impl BatchResolutionFragmentSource + ?Sized),
    mounts: SelectedMountTable<'_, '_>,
    project_root: &std::path::Path,
    answer: &ReferenceSearchAnswer,
    cancellation: &CancellationToken,
) -> Result<Option<Box<[SelectedReferenceSourceSite]>>> {
    let mut source_sites = Vec::with_capacity(answer.references().len());
    for references in answer.references().chunks(MAX_REFERENCE_SEEDS_PER_BATCH) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let queries = references
            .iter()
            .copied()
            .map(ResolutionQuery::new)
            .collect::<Vec<_>>();
        let seeds = source.lookup_reference_seeds(&queries, cancellation)?;
        if seeds.is_cancelled() || cancellation.is_cancelled() {
            return Ok(None);
        }
        for row in seeds.rows() {
            let seed = row.seed().ok_or_else(|| {
                StoreError::new(format!(
                    "selected reverse result {} has no source reference seed",
                    row.query().reference()
                ))
            })?;
            let mount = mounts.mount_for_fragment(seed.fragment())?.ok_or_else(|| {
                StoreError::new(format!(
                    "selected reverse result {} names unmounted fragment {:?}",
                    seed.reference(),
                    seed.fragment()
                ))
            })?;
            source_sites.push(SelectedReferenceSourceSite {
                reference: seed.reference(),
                file: ProjectFile::new(
                    project_root,
                    std::path::PathBuf::from(mount.persisted_relative_path()),
                ),
                metadata: seed.site_metadata(),
                enclosing: None,
            });
        }
    }
    assert_eq!(
        source_sites.len(),
        answer.references().len(),
        "selected reverse source projection preserves every exact reference"
    );
    Ok(Some(source_sites.into_boxed_slice()))
}

/// The outcome of attributing every enumerated reference site to its enclosing
/// `CodeUnit`. Neither caller consumes the projected units, so this carries no
/// payload: the sites themselves receive the attribution.
pub(crate) enum SelectedRustReferenceOwnerProjection {
    Complete,
    Unavailable,
    Cancelled,
}

/// Attribute every enumerated reference site to the `CodeUnit` that encloses
/// it, when one exists.
///
/// A reference's enclosing declaration is not always a `CodeUnit`. A block-local
/// `fn`, a closure and an `impl` item whose self type is not a declarable path
/// are all declarations the parser records without publishing a nominal unit,
/// exactly as [`SelectedRustSourceDefinition::WithoutUnit`] documents for a
/// resolved target. Such an owner is a decided answer -- the reference has no
/// enclosing unit -- not a missing one, so it is recorded as `Some(None)`
/// alongside a reference the file root owns. Demanding a unit for every owner
/// turned an ordinary scan over a nested `fn` into a store error.
fn project_rust_reference_owners(
    ready: &ReadySelectedResolution<'_, '_>,
    mounts: SelectedMountTable<'_, '_>,
    source_sites: &mut [SelectedReferenceSourceSite],
    cancellation: &CancellationToken,
) -> Result<SelectedRustReferenceOwnerProjection> {
    let owners = source_sites
        .iter()
        .filter_map(|site| {
            site.metadata
                .and_then(|metadata| metadata.reference_owner())
        })
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let projected = match project_rust_source_definitions(
        ready,
        mounts,
        &owners,
        cancellation,
        &ResolutionSession::unbounded(),
    )? {
        SelectedRustSourceDefinitionProjection::Complete(projected) => projected,
        SelectedRustSourceDefinitionProjection::Unavailable => {
            return Ok(SelectedRustReferenceOwnerProjection::Unavailable);
        }
        SelectedRustSourceDefinitionProjection::Cancelled => {
            return Ok(SelectedRustReferenceOwnerProjection::Cancelled);
        }
    };
    let projected_by_owner = projected
        .into_iter()
        .map(|(semantic, definition)| {
            (
                semantic,
                match definition {
                    SelectedRustSourceDefinition::Unit(unit) => Some(unit),
                    SelectedRustSourceDefinition::Lexical(_)
                    | SelectedRustSourceDefinition::WithoutUnit { .. } => None,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    for site in source_sites {
        site.enclosing = match site
            .metadata
            .and_then(|metadata| metadata.reference_owner())
        {
            None => None,
            Some(None) => Some(None),
            Some(Some(owner)) => Some(
                projected_by_owner
                    .get(&owner)
                    .expect("every selected Rust reference owner was projected")
                    .clone(),
            ),
        };
    }
    Ok(SelectedRustReferenceOwnerProjection::Complete)
}

fn project_rust_definitions(
    ready: &ReadySelectedResolution<'_, '_>,
    mounts: SelectedMountTable<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedRustDefinitionProjection> {
    Ok(
        match project_rust_source_definitions(ready, mounts, definitions, cancellation, session)? {
            SelectedRustSourceDefinitionProjection::Complete(rows) => {
                let units = rows
                    .into_iter()
                    .map(|(_, definition)| match definition {
                        SelectedRustSourceDefinition::Unit(unit) => Some(unit),
                        SelectedRustSourceDefinition::Lexical(_)
                        | SelectedRustSourceDefinition::WithoutUnit { .. } => None,
                    })
                    .collect::<Option<Vec<_>>>();
                match units {
                    Some(units) => SelectedRustDefinitionProjection::Complete(units),
                    None => SelectedRustDefinitionProjection::Unavailable,
                }
            }
            SelectedRustSourceDefinitionProjection::Unavailable => {
                SelectedRustDefinitionProjection::Unavailable
            }
            SelectedRustSourceDefinitionProjection::Cancelled => {
                SelectedRustDefinitionProjection::Cancelled
            }
        },
    )
}

fn project_rust_source_definitions(
    ready: &ReadySelectedResolution<'_, '_>,
    mounts: SelectedMountTable<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedRustSourceDefinitionProjection> {
    if !(0..definitions.len()).all(|_| session.scope_step()) {
        return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
    }
    let lexical = ready.lexical_source();
    let mut persisted = Vec::new();
    let mut coordinates = BTreeMap::new();
    let mut stage_coordinates = BTreeMap::new();
    for &definition in definitions {
        if cancellation.is_cancelled() {
            return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
        }
        let Some(provenance) = lexical.semantic_provenance(definition, cancellation)? else {
            return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
        };
        let provenance = match provenance {
            SelectedSemanticProvenance::FragmentLocal(provenance) => provenance,
            SelectedSemanticProvenance::Stage(provenance) => {
                if stage_coordinates
                    .insert(definition, provenance.mount().ordinal())
                    .is_some()
                {
                    return Err(StoreError::new(
                        "selected Rust definition projection received duplicate semantics",
                    ));
                }
                continue;
            }
            SelectedSemanticProvenance::Shared(_) => {
                return Ok(SelectedRustSourceDefinitionProjection::Unavailable);
            }
        };
        let coordinate = (provenance.mount().ordinal(), provenance.local_key());
        if coordinates.insert(definition, coordinate).is_some() {
            return Err(StoreError::new(
                "selected Rust definition projection received duplicate semantics",
            ));
        }
        persisted.push(coordinate);
    }
    let stage_requests = stage_coordinates
        .iter()
        .map(|(&semantic, &host)| (host, semantic))
        .collect::<Vec<_>>();
    let Some(stage_rows) = lexical.stage_lexical_definitions(&stage_requests, cancellation)? else {
        return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
    };
    let mut stage_rows = stage_rows.into_iter().collect::<BTreeMap<_, _>>();
    drop(lexical);

    let persisted_rows = match ready
        .inventory
        .selected_definition_units(&persisted, cancellation)?
    {
        SelectedDefinitionUnitReadOutcome::Ready(rows) => rows,
        SelectedDefinitionUnitReadOutcome::Cancelled => {
            return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
        }
    };
    let mut rows_by_coordinate = BTreeMap::new();
    for (mount, definition, row) in persisted_rows {
        let coordinate = (mount, definition);
        if rows_by_coordinate.insert(coordinate, row).is_some() {
            return Err(StoreError::new(
                "selected Rust definition projection repeated a parser unit",
            ));
        }
    }

    // A definition whose parser unit another definition in the same blob
    // already holds the crosswalk row for -- two `pub fn value` in one `impl`,
    // or one item declared under two `cfg`s -- is still an ordinary
    // declaration with an ordinary unit. The crosswalk is injective on
    // `unit_key` because it also answers the unit-to-definition direction; the
    // parser's own declaration-to-unit relation kept every link.
    let unclaimed = persisted
        .iter()
        .filter(|coordinate| !rows_by_coordinate.contains_key(coordinate))
        .copied()
        .collect::<Vec<_>>();
    let declaration_rows = match ready
        .inventory
        .selected_declaration_units(&unclaimed, cancellation)?
    {
        SelectedDefinitionUnitReadOutcome::Ready(rows) => rows,
        SelectedDefinitionUnitReadOutcome::Cancelled => {
            return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
        }
    };
    for (mount, definition, row) in declaration_rows {
        let coordinate = (mount, definition);
        if rows_by_coordinate.insert(coordinate, row).is_some() {
            return Err(StoreError::new(
                "selected Rust definition projection repeated a parser unit",
            ));
        }
    }

    let missing = persisted
        .iter()
        .filter(|coordinate| !rows_by_coordinate.contains_key(coordinate))
        .copied()
        .collect::<Vec<_>>();
    let lexical_rows = match ready
        .inventory
        .selected_lexical_definitions(&missing, cancellation)?
    {
        SelectedLexicalDefinitionReadOutcome::Ready(rows) => rows,
        SelectedLexicalDefinitionReadOutcome::Cancelled => {
            return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
        }
    };
    let mut declaration_by_coordinate = BTreeMap::new();
    for (mount, definition, row) in lexical_rows {
        if declaration_by_coordinate
            .insert((mount, definition), row)
            .is_some()
        {
            return Err(StoreError::new(
                "selected lexical projection repeated a canonical definition",
            ));
        }
    }
    let mut projected = Vec::with_capacity(definitions.len());
    for definition in definitions {
        if let Some(&host) = stage_coordinates.get(definition) {
            let mount = mounts.mount_by_ordinal(host)?;
            if mount.semantic_language() != Language::Rust {
                return Ok(SelectedRustSourceDefinitionProjection::Unavailable);
            }
            let source_file = ProjectFile::new(
                ready.project.root().to_path_buf(),
                mount.persisted_relative_path(),
            );
            // A staged producer publishes lexical declarations and nothing
            // else, so this read answers a macro overlay's binders. An item
            // an expansion introduces is in no lexical binder; it has a
            // `CodeUnit` only when the crate declared it for a cross-file
            // passthrough invocation (`selected_macro_item_unit`), and
            // otherwise it is in no `CodeUnit` either, which is what
            // `WithoutUnit` names. Refusing the batch for one of them failed
            // the whole workspace graph on tract with a store error, at
            // `linalg/src/generic/by_scalar.rs`, where `by_scalar_impl_wrap!`
            // generates `pub struct SMulByScalar4` and its impl members.
            let projection = match stage_rows.remove(definition) {
                Some(mut row) => {
                    if row.source_file.is_none() {
                        row.source_file = Some(source_file);
                    }
                    SelectedRustSourceDefinition::Lexical(row)
                }
                None => match ready.inventory.selected_macro_item_unit(
                    host,
                    *definition,
                    cancellation,
                )? {
                    None => return Ok(SelectedRustSourceDefinitionProjection::Cancelled),
                    Some(Some(row)) => SelectedRustSourceDefinition::Unit(
                        RustMountUnits::new(ready, &mount)?.unit(&row)?,
                    ),
                    Some(None) => SelectedRustSourceDefinition::WithoutUnit {
                        source_file,
                        declaration_range: None,
                    },
                },
            };
            projected.push((*definition, projection));
            continue;
        }
        let Some(&coordinate) = coordinates.get(definition) else {
            return Ok(SelectedRustSourceDefinitionProjection::Unavailable);
        };
        let mount = mounts.mount_by_ordinal(coordinate.0)?;
        if mount.semantic_language() != Language::Rust {
            return Ok(SelectedRustSourceDefinitionProjection::Unavailable);
        }
        if let Some(row) = rows_by_coordinate.remove(&coordinate) {
            projected.push((
                *definition,
                SelectedRustSourceDefinition::Unit(RustMountUnits::new(ready, &mount)?.unit(&row)?),
            ));
        } else if let Some(row) = declaration_by_coordinate.remove(&coordinate) {
            let source_file = ProjectFile::new(
                ready.project.root().to_path_buf(),
                mount.persisted_relative_path(),
            );
            projected.push((
                *definition,
                match row {
                    SelectedDeclarationDefinition::Lexical(mut row) => {
                        row.source_file = Some(source_file);
                        SelectedRustSourceDefinition::Lexical(row)
                    }
                    SelectedDeclarationDefinition::WithoutUnit(declaration_range) => {
                        SelectedRustSourceDefinition::WithoutUnit {
                            source_file,
                            declaration_range: Some(declaration_range),
                        }
                    }
                },
            ));
        } else {
            return Ok(SelectedRustSourceDefinitionProjection::Unavailable);
        }
    }
    if cancellation.is_cancelled() {
        return Ok(SelectedRustSourceDefinitionProjection::Cancelled);
    }
    Ok(SelectedRustSourceDefinitionProjection::Complete(projected))
}

fn project_rust_reference_types(
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    resolution: &FactResolutionAnswer,
    ready: &ReadySelectedResolution<'_, '_>,
    mounts: SelectedMountTable<'_, '_>,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
    locator: &SelectedSemanticLocator,
) -> Result<SelectedResolutionOperationOutcome<SelectedRustTypeProjection>> {
    let mut identities = BTreeSet::new();
    for frontier in resolution.projected_frontiers() {
        for value in frontier.possible_values() {
            if cancellation.is_cancelled() || !session.scope_step() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            identities.insert(value.ty().identity());
        }
    }
    let identities = identities.into_iter().collect::<Vec<_>>();
    let Some(intrinsic_types) = operation.read_intrinsic_type_descriptors(&identities)? else {
        return Ok(SelectedResolutionOperationOutcome::Cancelled(
            cancelled_completion(),
        ));
    };
    let intrinsic_identities = intrinsic_types
        .iter()
        .map(|descriptor| descriptor.identity())
        .collect::<BTreeSet<_>>();
    let nominal = identities
        .into_iter()
        .filter(|identity| !intrinsic_identities.contains(identity))
        .collect::<Vec<_>>();
    let nominal_types =
        match project_rust_source_definitions(ready, mounts, &nominal, cancellation, session)? {
            SelectedRustSourceDefinitionProjection::Complete(rows) => rows,
            SelectedRustSourceDefinitionProjection::Unavailable => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingDefinitionUnit {
                        storage_language: locator.storage_language().to_owned(),
                        persisted_relative_path: locator.relative_path().to_owned(),
                    },
                ));
            }
            SelectedRustSourceDefinitionProjection::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
    Ok(SelectedResolutionOperationOutcome::Native(
        SelectedRustTypeProjection {
            nominal_types,
            intrinsic_types,
        },
    ))
}

struct RustReferenceAnswerContext<'a, 'store, 'input> {
    ready: &'a ReadySelectedResolution<'store, 'input>,
    mounts: SelectedMountTable<'a, 'store>,
    /// The reference this answer is for. Its provenance names the mount the
    /// locator addresses, so the answer reads the mount off the rebaser it
    /// already consulted instead of asking the selection for the path again.
    reference: SemanticId,
    locator: &'a SelectedSemanticLocator,
    session: &'a ResolutionSession,
    cancellation: &'a CancellationToken,
}

/// The kind of gap a request-staged reason is, when the stage recorded one.
const STAGED_REASON_GAP_ORIGIN: &str = "SELECT origin FROM temp.selected_resolution_stage_gaps
 WHERE host_ordinal=?1 AND reason_key=?2 LIMIT 1";

/// The name a staged (request-allocated, supplemental-coordinate) reason
/// publishes: a mounted file's reason minted by this request's own staging of
/// that file (a capsule, or a macro expansion it replays), not by the
/// persisted rows.
const STAGED_CAPSULE_REASON: &str = "StagedCapsuleReason";

/// Import paths proved by the selected external-boundary binding rows.
fn boundary_import_names(
    ready: &ReadySelectedResolution<'_, '_>,
    completion: &ResolutionCompletion,
) -> Result<Vec<String>> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for reason in reasons.iter() {
        let ResolutionIncompleteReason::OpenBoundary { semantic, .. } = reason else {
            continue;
        };
        let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
            continue;
        };
        let mut statement = ready.inventory.connection().prepare_cached(
            "SELECT DISTINCT json((SELECT json_group_array(segment) FROM (
                 SELECT segment FROM source_rust_import_module_segments
                 WHERE blob_id=import.blob_id AND import_ordinal=import.ordinal ORDER BY ordinal
             ))), import.imported_name
             FROM temp.selected_resolution_mounts AS mount
             CROSS JOIN resolution_paths AS binding ON binding.blob_id=mount.blob_id
              AND binding.end_node=-1 AND binding.start_node<>-1 AND binding.end_open_tail=1
              AND json_extract(binding.end_fixed_key,'$[#-2][0]')=?2
             CROSS JOIN resolution_identities AS identity ON identity.id=binding.root_terminal
             CROSS JOIN resolution_node_catalog AS scope
              ON scope.blob_id=binding.blob_id AND scope.local_key=binding.start_node
             CROSS JOIN source_rust_import_targets AS import
              ON import.blob_id=scope.blob_id AND import.native_scope=scope.source_scope
              AND import.bound_name=identity.spelling AND import.is_glob=0
             CROSS JOIN rust_crate_container_sources AS placement
              ON placement.blob_id=import.blob_id AND placement.rel_path=mount.persisted_relative_path
             CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=placement.topology_id
             CROSS JOIN rust_crate_gaps AS gap ON gap.topology_id=owner.topology_id
              AND gap.gap_kind='external_dependency'
              AND gap.subject=placement.container_path || '::' || import.bound_name
             CROSS JOIN json_each(gap.detail, '$.evidence') AS evidence
              ON evidence.value ->> 'import_ordinal'=import.ordinal
             WHERE mount.mount_ordinal=?1 AND import.imported_name IS NOT NULL",
        )?;
        for row in statement.query_map(rusqlite::params![ordinal, key], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (segments, name) = row?;
            let mut segments: Vec<String> = serde_json::from_str(&segments)
                .map_err(|error| StoreError::corrupt(error.to_string()))?;
            segments.push(name);
            names.push(segments.join("."));
        }
    }
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

/// The named reasons among a completion's incompleteness reasons, sorted:
/// those a context minted by name, and the request-staged reasons, which carry
/// supplemental coordinates no persisted row names.
fn named_reason_details(
    ready: &ReadySelectedResolution<'_, '_>,
    completion: &ResolutionCompletion,
) -> Result<Vec<(&'static str, String)>> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(Vec::new());
    };
    let mut named = Vec::new();
    for reason in reasons.iter() {
        let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
            continue;
        };
        if let Some((name, evidence)) = ready.context_identities.named_reason(*semantic) {
            named.push((name, evidence.to_string()));
            continue;
        }
        let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
            continue;
        };
        if i64::from(key) < crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE {
            continue;
        }
        let gap_kind = ready
            .inventory
            .connection()
            .prepare_cached(STAGED_REASON_GAP_ORIGIN)?
            .query_row(
                rusqlite::params![
                    ordinal,
                    super::resolution_stage::codec::encode_semantic(*semantic)
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|origin| {
                super::resolution_prepare::resolution_rows::gap_origin_from_code(origin)
                    .kind()
                    .label()
            });
        let rel_path = SelectedMountTable::new(&ready.inventory)
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
            .persisted_relative_path()
            .to_owned();
        named.push((
            STAGED_CAPSULE_REASON,
            serde_json::json!({
                "evidence": [{
                    "reason": STAGED_CAPSULE_REASON,
                    "rel_path": rel_path,
                    "gap_kind": gap_kind,
                }]
            })
            .to_string(),
        ));
    }
    named.sort_unstable();
    named.dedup();
    Ok(named)
}

/// Turn one resolved reference into a projected answer.
///
/// Shared by the eager and demand point routes so the two cannot drift in what
/// they do with an answer; they differ only in how the answer was produced.
fn assemble_rust_reference_answer<T>(
    context: &RustReferenceAnswerContext<'_, '_, '_>,
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    mut resolution: FactResolutionAnswer,
    project: &mut impl FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        &FactResolutionAnswer,
        &ReadySelectedResolution<'_, '_>,
        SelectedMountTable<'_, '_>,
        &ResolutionSession,
        &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<T>>,
) -> Result<SelectedResolutionOperationOutcome<SelectedRustReferenceAnswer<T>>> {
    let RustReferenceAnswerContext {
        ready,
        mounts,
        reference,
        locator,
        session,
        cancellation,
    } = *context;
    let projection = match project(operation, &resolution, ready, mounts, session, cancellation)? {
        SelectedResolutionOperationOutcome::Native(value) => value,
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(SelectedResolutionOperationOutcome::Stale(reason));
        }
        SelectedResolutionOperationOutcome::Cancelled(completion) => {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
        }
    };
    let resolved_targets = resolution.binding().targets();
    if !(0..resolved_targets.len()).all(|_| session.scope_step()) {
        return Ok(SelectedResolutionOperationOutcome::Cancelled(
            resolution.completion().combine(&cancelled_completion()),
        ));
    }
    let SelectedSemanticMount::FragmentLocal(provenance) = ready
        .inventory
        .mount_rebaser()
        .borrow()
        .semantic_mount(reference)
    else {
        return Err(StoreError::corrupt(format!(
            "located reference {reference:?} has no selected mount provenance: {locator:?}"
        )));
    };
    let mount = mounts.mount_by_ordinal(provenance.ordinal())?;
    debug_assert_eq!(
        (mount.storage_language(), mount.persisted_relative_path()),
        (locator.storage_language(), locator.relative_path()),
        "a located reference belongs to the mount its locator addresses"
    );
    let mut targets = resolved_targets.to_vec();
    // The lexical chain has answered. A `#[macro_use]` binding is not in it,
    // so an unqualified macro name that reached a complete absence asks the
    // crate rows before the absence is published.
    targets.extend(rust_macro_use_binding_targets(
        ready,
        mounts,
        provenance.ordinal(),
        reference,
        &resolution,
        cancellation,
    )?);
    let SelectedRustDefinitionVocabularies {
        units: definitions,
        lexical: lexical_definitions,
        names: mut definition_names,
    } = match project_rust_source_definitions(ready, mounts, &targets, cancellation, session)? {
        SelectedRustSourceDefinitionProjection::Complete(rows) => {
            match split_projected_rust_definitions(rows) {
                Some(vocabularies) => vocabularies,
                None => {
                    return Ok(SelectedResolutionOperationOutcome::Unavailable(
                        SelectedResolutionUnavailable::MissingDefinitionUnit {
                            storage_language: locator.storage_language().to_owned(),
                            persisted_relative_path: locator.relative_path().to_owned(),
                        },
                    ));
                }
            }
        }
        SelectedRustSourceDefinitionProjection::Unavailable => {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingDefinitionUnit {
                    storage_language: locator.storage_language().to_owned(),
                    persisted_relative_path: locator.relative_path().to_owned(),
                },
            ));
        }
        SelectedRustSourceDefinitionProjection::Cancelled => {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                resolution.completion().combine(&cancelled_completion()),
            ));
        }
    };
    if let Some(reason) = rust_type_parameter_member_reason(
        ready,
        mounts,
        operation,
        locator.relative_path(),
        reference,
        &resolution,
        session,
        cancellation,
    )? {
        resolution.combine_binding_completion(&reason);
    }
    let named_reasons = named_reason_details(ready, resolution.binding().completion())?;
    let mut macro_expansion_gaps =
        unexpanded_item_macro_gaps(ready, resolution.binding().completion())?;
    let mut inventory_details = Vec::new();
    if let ResolutionCompletion::Incomplete(reasons) = resolution.binding().completion() {
        for detail in ready
            .inventory
            .connection()
            .prepare_cached(rust_crate_context::GAP_DETAILS)?
            .query_map([locator.relative_path()], |row| row.get::<_, String>(0))?
        {
            let detail = detail?;
            let reason = ResolutionIncompleteReason::UnsupportedSemantic(
                rust_crate_context::inventory_reason(&ready.context_identities, &detail),
            );
            if reasons.iter().any(|candidate| *candidate == reason) {
                let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
                    unreachable!("inventory reasons are unsupported semantic identities")
                };
                macro_expansion_gaps.extend(inventory_macro_gaps(ready, &detail, semantic)?);
                inventory_details.push(detail);
            }
        }
    }
    definition_names.extend(macro_expansion_gaps.iter().map(|gap| {
        (
            gap.semantic,
            format!("unexpanded item macro {}!", gap.macro_name),
        )
    }));
    let member_attributions = match project_rust_member_attributions(
        ready,
        mounts,
        &resolution,
        cancellation,
        session,
    )? {
        Some(attributions) => attributions,
        None => {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                resolution.completion().combine(&cancelled_completion()),
            ));
        }
    };
    let lexical = ready.lexical_source();
    if let Some(boundary) = rust_path_root_boundary(
        ready,
        &lexical,
        provenance.ordinal(),
        reference,
        &resolution,
        cancellation,
    )? {
        resolution.combine_binding_completion(&boundary);
    }
    let enumeration =
        lexical.reference_inventory_completion(mount.fragment(), cancellation, session)?;
    let Some(enumeration) = lexical.close_completion(&enumeration, cancellation)? else {
        return Ok(SelectedResolutionOperationOutcome::Cancelled(
            enumeration.combine(&cancelled_completion()),
        ));
    };
    Ok(SelectedResolutionOperationOutcome::Native(
        SelectedRustReferenceAnswer {
            macro_expansion_gaps,
            inventory_details,
            named_reasons,
            enumeration: Some((
                ProjectFile::new(ready.project.root(), locator.relative_path()),
                enumeration,
            )),
            boundary_import_names: boundary_import_names(ready, resolution.binding().completion())?,
            resolution,
            definitions,
            lexical_definitions,
            definition_names,
            member_attributions,
            projection,
        },
    ))
}

/// Project the member attribution the resolver recorded into the vocabulary a
/// presentation route reads.
///
/// The resolver names the owner as a semantic type identity; a consumer needs
/// the owner's declaration. The dispatch bucket comes from the member's own
/// contract references, which the producer writes for exactly the declarations
/// that sit in an `impl Trait for Type` block, so a direct find inside a trait
/// implementation is reported as trait dispatch without any hierarchy walk.
///
/// `None` reports cancellation.
fn project_rust_member_attributions(
    ready: &ReadySelectedResolution<'_, '_>,
    mounts: SelectedMountTable<'_, '_>,
    resolution: &FactResolutionAnswer,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<Option<Vec<SelectedRustMemberAttribution>>> {
    let rows = resolution.member_owners();
    if rows.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut owner_identities = rows
        .iter()
        .flat_map(|row| row.owner_path().iter().copied())
        .collect::<Vec<_>>();
    owner_identities.sort_unstable();
    owner_identities.dedup();
    let owners = match project_rust_source_definitions(
        ready,
        mounts,
        &owner_identities,
        cancellation,
        session,
    )? {
        SelectedRustSourceDefinitionProjection::Complete(owners) => owners,
        // An owner the parser published no declaration for leaves every member
        // it owns unattributed, which is the honest report: absence, never a
        // plausible-looking depth zero.
        SelectedRustSourceDefinitionProjection::Unavailable => return Ok(Some(Vec::new())),
        SelectedRustSourceDefinitionProjection::Cancelled => return Ok(None),
    };
    let owner_units = owners
        .into_iter()
        .filter_map(|(identity, definition)| match definition {
            SelectedRustSourceDefinition::Unit(unit) => Some((identity, unit)),
            SelectedRustSourceDefinition::Lexical(_)
            | SelectedRustSourceDefinition::WithoutUnit { .. } => None,
        })
        .collect::<HashMap<_, _>>();
    let lexical = ready.lexical_source();
    let mut attributions = Vec::with_capacity(rows.len());
    for row in rows {
        if !session.scope_step() {
            return Ok(None);
        }
        let Some(owner) = owner_units.get(&row.owner()) else {
            continue;
        };
        let reach = match row.hierarchy_depth() {
            0 => {
                let Some(ordinal) = row.target().ordinal() else {
                    continue;
                };
                let Some(contract) = lexical.contract_reference_sites(
                    SelectedResolutionMountOrdinal::new(ordinal),
                    row.target(),
                    row.kind(),
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                SelectedRustMemberReach::Direct {
                    declared_by_trait_implementation: !contract.is_empty(),
                }
            }
            _ => {
                let Some(owner_path) = row
                    .owner_path()
                    .iter()
                    .map(|identity| owner_units.get(identity).cloned())
                    .collect::<Option<Vec<_>>>()
                else {
                    continue;
                };
                SelectedRustMemberReach::Hierarchy {
                    owner_path,
                    implementation_hop: row.implementation_hop(),
                }
            }
        };
        attributions.push(SelectedRustMemberAttribution {
            target: row.target(),
            owner: owner.clone(),
            reach,
        });
    }
    Ok(Some(attributions))
}

/// Resolve selected membership and language for one requested fragment.
/// Persisted metadata uses the request-owned keyed row memo; SQL failure is
/// distinct from a fragment that is not selected.
fn selected_mount_lookup<'a>(
    mounts: SelectedMountTable<'a, '_>,
) -> impl Fn(BindingFragmentId) -> Result<Option<(SelectedResolutionMountOrdinal, Language)>> + 'a {
    move |fragment| {
        Ok(mounts
            .mount_for_fragment(fragment)?
            .map(|mount| (mount.ordinal(), mount.semantic_language())))
    }
}

/// The context set a demand request starts from: none of the request's own
/// relations, and at most one entry carrying the reverse inventory evidence.
///
/// The demand engine starts from this: a request's own bridges are compiled
/// and registered by the endpoint relation that needs them, never by a
/// workspace-wide precompilation. Mount ordinals, fragments and languages come
/// from the operation's own mounts, so the construction cannot fail.
///
/// `reverse_inventory_completion` is not a detail. It is the evidence about the
/// root inventory the context was read from, and the eager route puts the
/// root-half completion here. A request context that claimed `Complete` over an
/// inventory that was not would turn honest incompleteness into a false exact
/// answer, so the caller supplies what it actually read.
///
/// The evidence is about the read and not about one mount, and the context set
/// combines it into one operand, so it rides on the set's single entry. Giving
/// every mount a copy is not free: combining a workspace-sized reason set once
/// per mount cost 440 s of a 562 s caller preparation on the #2767 corpus, which
/// is more than the inventory read it was describing. A complete inventory has
/// nothing to carry, so such a set holds no entry at all and its selected mount
/// count still covers every mount the operation selected.
///
/// The lookup is a generic parameter rather than the context set's own
/// `SelectedMountLookup`, because that alias is private to `resolution` and the
/// coercion to it happens where the set's own constructor takes it.
fn empty_contexts_for(
    mounts: SelectedMountTable<'_, '_>,
    reverse_inventory_completion: &ResolutionCompletion,
    selected_mount_of: &impl Fn(
        BindingFragmentId,
    ) -> Result<Option<(SelectedResolutionMountOrdinal, Language)>>,
    identities: SelectedContextIdentities,
) -> Result<SelectedResolutionContextSet> {
    let mut carried = Vec::new();
    if mounts.mount_count() != 0
        && !matches!(reverse_inventory_completion, ResolutionCompletion::Complete)
    {
        let mount = mounts.mount_by_ordinal(SelectedResolutionMountOrdinal::new(0))?;
        carried.push(SelectedResolutionMountContext::new(
            mount.ordinal(),
            mount.fragment(),
            mount.semantic_language(),
            Vec::new(),
            reverse_inventory_completion.clone(),
        )?);
    }
    SelectedResolutionContextSet::new(identities, carried, mounts.mount_count(), selected_mount_of)
}

/// The mounts one Rust context request may read root halves from.
///
/// An import or reference half only ever compiles a bridge out of the file
/// that owns it, so a request needs the halves of the files it is answering
/// for and of no others. An export half is only ever matched against a module
/// this crate or one of its dependencies mounts, so the rest cannot land a
/// bridge either. Reading the workspace's halves in order to use this many is
/// the crate-sized context R8.6 removes.
pub(crate) struct RustRootHalfScope {
    sources: RustRootHalfMounts,
    targets: RustRootHalfMounts,
}

#[derive(Default)]
struct RustRootHalfMounts {
    ordinals: Vec<SelectedResolutionMountOrdinal>,
    fragments: HashSet<BindingFragmentId>,
}

impl RustRootHalfMounts {
    fn new<'mount>(
        mounts: impl IntoIterator<Item = &'mount SelectedResolutionOperationMount>,
    ) -> Self {
        let mut ordinals = Vec::new();
        let mut fragments = HashSet::default();
        for mount in mounts {
            ordinals.push(mount.ordinal());
            fragments.insert(mount.fragment());
        }
        ordinals.sort_unstable();
        ordinals.dedup();
        Self {
            ordinals,
            fragments,
        }
    }
}

impl RustRootHalfScope {
    pub(crate) fn new<'mount>(
        sources: impl IntoIterator<Item = &'mount SelectedResolutionOperationMount>,
        targets: impl IntoIterator<Item = &'mount SelectedResolutionOperationMount>,
    ) -> Self {
        Self {
            sources: RustRootHalfMounts::new(sources),
            targets: RustRootHalfMounts::new(targets),
        }
    }

    /// A transient source keeps its fragments in memory and answers from all
    /// of them whatever the request names, so the scope is applied again here.
    fn admits(&self, half: &SelectedRootPathHalf) -> bool {
        match half {
            SelectedRootPathHalf::Import { identity, .. }
            | SelectedRootPathHalf::Reference { identity, .. } => {
                self.sources.fragments.contains(&identity.fragment())
            }
            SelectedRootPathHalf::Export { identity, .. } => {
                self.targets.fragments.contains(&identity.fragment())
            }
        }
    }
}

/// The workspace crate a Rust reference spelled in the Type namespace names
/// in its own module, if any (`rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE`).
fn rust_reference_workspace_crate(
    ready: &ReadySelectedResolution<'_, '_>,
    lexical: &SelectedResolutionLexicalSource<'_, '_>,
    mount: SelectedResolutionMountOrdinal,
    reference: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<String>> {
    let Some(key) = reference.local_key() else {
        return Ok(None);
    };
    let Some(name) = lexical
        .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, cancellation)?
        .remove(&reference)
    else {
        return Ok(None);
    };
    Ok(ready
        .inventory
        .connection()
        .prepare_cached(rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE)?
        .query_row(rusqlite::params![mount.get(), key, name], |row| row.get(0))
        .optional()?)
}

/// The external boundary a Rust path root establishes about itself.
///
/// A bare `root::item` path resolves its root by lexical lookup, so the root
/// token owns no route of its own and the crate route never sees it: a caret
/// on `ext_crate` in `ext_crate::Widget` reached the universal root, matched
/// no candidate, and the point route answered a decided absence (#1162). The
/// terminal below the same root already answers the boundary, through
/// `external_root` in `rust_demand/rows.rs`, because the root is the
/// terminal's prefix. `ext_crate::Widget` is one question asked at two tokens
/// and the two answers have to agree.
///
/// The proof this claim rests on is the root's own finished selection: the
/// lookup completed, named no target, and the root is a path root, which the
/// selection states structurally by carrying it as a Reference half's
/// `prefix_reference`. A root that names nothing the selection compiles is a
/// root that left it, and leaving the selection is the boundary, not an
/// absence the selection proved. The predicate fails closed: an incomplete
/// lookup, a bound root, or a token no half carries as a prefix claims
/// nothing.
///
/// The read is one probe over the one mount the caret is in, not the
/// selection.
///
/// A root that names a module the crate declares for an item macro in the
/// root's own module did not leave the selection: the module is compiled, and
/// the lookup found nothing only because a crate-declared module has no
/// lexical binder (`lower_capsule_module_declaration`). That root answers
/// incomplete, with a reason that names it, rather than the boundary.
fn rust_path_root_boundary(
    ready: &ReadySelectedResolution<'_, '_>,
    lexical: &SelectedResolutionLexicalSource<'_, '_>,
    mount: SelectedResolutionMountOrdinal,
    reference: SemanticId,
    resolution: &FactResolutionAnswer,
    cancellation: &CancellationToken,
) -> Result<Option<ResolutionCompletion>> {
    let identities = &ready.context_identities;
    let root_token = resolution.site_metadata().is_some_and(|metadata| {
        metadata.namespace() == ResolutionNamespace::Type
            && metadata.site_kind() == ResolutionSiteKind::TypeReference
    });
    if !root_token
        || !resolution.binding().targets().is_empty()
        || *resolution.binding().completion() != ResolutionCompletion::Complete
    {
        return Ok(None);
    }
    let mut is_path_root = false;
    let outcome = visit_selected_root_import_half_pages(
        identities,
        lexical,
        lexical,
        Some(&[mount]),
        cancellation,
        &mut FactPageVisitor::new(&mut |page| {
            is_path_root |= page.iter().any(|half| {
                matches!(
                    half,
                    SelectedRootPathHalf::Reference {
                        prefix_reference: Some(prefix),
                        ..
                    } if *prefix == reference
                )
            });
            Ok(!is_path_root)
        }),
    )?;
    if outcome.is_cancelled() || cancellation.is_cancelled() || !is_path_root {
        return Ok(None);
    }
    // A root that names a crate this workspace compiles did not leave it: a
    // crate root has no declaration to find, so the empty selection is the
    // answer, and the point adapter names the crate.
    if rust_reference_workspace_crate(ready, lexical, mount, reference, cancellation)?.is_some() {
        return Ok(None);
    }
    if let Some(key) = reference.local_key()
        && let Some(name) = lexical
            .reference_lookup_spellings(&[reference], ResolutionNamespace::Type, cancellation)?
            .get(&reference)
        && ready
            .inventory
            .connection()
            .prepare_cached(rust_crate_rows::REFERENCE_NAMES_MACRO_MODULE)?
            .exists(rusqlite::params![mount.get(), key, name])?
    {
        return Ok(Some(ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic({
                let mut digest = CanonicalHasher::new(b"bifrost-rust-macro-module-path-root:v1");
                digest.field("mount", &mount.get().to_be_bytes());
                digest.field("reference", name.as_bytes());
                identities.semantic(digest.finish())
            }),
        ])));
    }
    Ok(Some(ResolutionCompletion::incomplete([
        ResolutionIncompleteReason::OpenBoundary {
            semantic: reference,
            status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
        },
    ])))
}

/// The name `GenericParameterMember` publishes.
const GENERIC_PARAMETER_MEMBER: &str = "GenericParameterMember";

/// The named reason a member path through a type parameter publishes when it
/// finds nothing.
///
/// `T::one` asks the parameter's bounds for `one`, and the typed member route
/// reads those bounds (inline, from a `where` clause, or both). When it finds
/// nothing, the miss is incompleteness and not an absence: a blanket impl over
/// a bound can give the parameter more members. The engine's own reason for
/// that is an operation-local number that says none of this, so the reply
/// could not tell a bound that lacks the member from an unbounded parameter.
/// This reason names the parameter, the bound traits, and the member.
///
/// `bounds` lists the bound traits the index resolved. `unresolved_bounds`
/// says the parameter states a bound the index could not resolve, such as a
/// prelude or external trait (`T: Default`), which may well declare the
/// member. A parameter with no bound lists none and has no unresolved bound.
///
/// The prefix is found structurally, from the reference's own typed rows,
/// and its targets must be type parameters.
#[allow(clippy::too_many_arguments)]
fn rust_type_parameter_member_reason(
    ready: &ReadySelectedResolution<'_, '_>,
    mounts: SelectedMountTable<'_, '_>,
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    rel_path: &str,
    reference: SemanticId,
    resolution: &FactResolutionAnswer,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Option<ResolutionCompletion>> {
    if !resolution.binding().targets().is_empty() {
        return Ok(None);
    }
    let identities = &ready.context_identities;
    let lexical = ready.lexical_source();
    let typed = ready.typed_source();
    // The prefix is the reference whose type identity the lookup's qualifier
    // takes as its receiver: the qualified route names the qualifier slot, a
    // `Receiver` transfer feeds that slot from the prefix's identity slot, and
    // the prefix's `TargetTypeIdentity` projection names that slot. All three
    // are rows of the reference's own blob.
    let mut routes = Vec::new();
    if typed
        .visit_qualified_route_pages_for_references(
            TypedFactRequest::new(&[reference]),
            cancellation,
            &mut FactPageVisitor::new(
                &mut |page: &[crate::analyzer::resolution::SelectedQualifiedRoute]| {
                    routes.extend(page.iter().copied());
                    Ok(true)
                },
            ),
        )?
        .is_cancelled()
    {
        return Ok(None);
    }
    let [route] = routes.as_slice() else {
        return Ok(None);
    };
    let mut receivers = Vec::new();
    if typed
        .visit_type_transfer_pages_to_targets(
            TypedFactRequest::new(&[route.row().qualifier_slot()]),
            cancellation,
            &mut FactPageVisitor::new(
                &mut |page: &[SelectedTypedRow<crate::analyzer::resolution::LoweredTypeTransfer>]| {
                    receivers.extend(
                        page.iter()
                            .filter(|transfer| {
                                transfer.row().kind()
                                    == brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind::Receiver
                            })
                            .map(|transfer| transfer.row().source_slot()),
                    );
                    Ok(true)
                },
            ),
        )?
        .is_cancelled()
    {
        return Ok(None);
    }
    let mut prefixes = Vec::new();
    if typed
        .visit_binding_projection_pages_for_outputs(
            TypedFactRequest::new(&receivers),
            cancellation,
            &mut FactPageVisitor::new(
                &mut |page: &[SelectedTypedRow<crate::analyzer::resolution::LoweredBindingProjection>]| {
                    prefixes.extend(
                        page.iter()
                            .filter(|projection| {
                                projection.row().kind()
                                    == brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetTypeIdentity
                            })
                            .map(|projection| projection.row().reference()),
                    );
                    Ok(true)
                },
            ),
        )?
        .is_cancelled()
    {
        return Ok(None);
    }
    prefixes.sort_unstable();
    prefixes.dedup();
    let [prefix] = prefixes[..] else {
        return Ok(None);
    };
    let parameter = operation.resolve_reference(prefix)?;
    if !rust_crate_context::prefix_names_type_parameters(ready, parameter.binding().targets())? {
        return Ok(None);
    }
    // The parameter's bounds are the values of its type identity: the
    // lowering feeds a type parameter's identity slot from every bound it
    // states, and from an `InferredType` gap on the parameter when it states
    // none.
    let identity_slots = parameter
        .projections()
        .iter()
        .filter(|projection| {
            projection.kind()
                == brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetTypeIdentity
        })
        .map(|projection| projection.output_slot())
        .collect::<HashSet<_>>();
    let conn = ready.inventory.connection();
    let mut bounds = BTreeSet::new();
    let mut unbounded = false;
    let mut unresolved_bounds = false;
    for frontier in parameter.projected_frontiers() {
        if !identity_slots.contains(&frontier.slot()) {
            continue;
        }
        bounds.extend(
            frontier
                .possible_values()
                .iter()
                .map(|value| value.ty().identity()),
        );
        let ResolutionCompletion::Incomplete(reasons) = frontier.completion() else {
            continue;
        };
        for reason in reasons.iter() {
            let inferred = match reason {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                    match (semantic.ordinal(), semantic.local_key()) {
                        (Some(ordinal), Some(key)) => conn
                            .prepare_cached(rust_crate_context::REASON_GAP_ORIGIN)?
                            .query_row(rusqlite::params![ordinal, key], |row| {
                                row.get::<_, i64>(0)
                            })
                            .optional()?
                            .is_some_and(|origin| {
                                super::resolution_prepare::resolution_rows::gap_origin_from_code(
                                    origin,
                                ) == crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::InferredType,
                                )
                            }),
                        _ => false,
                    }
                }
                _ => false,
            };
            unbounded |= inferred;
            unresolved_bounds |= !inferred;
        }
    }
    // A parameter that states bounds feeds its identity from them; a bound
    // the index could not resolve (a prelude or external trait) feeds it
    // nothing, with or without a reason of its own. Only the `InferredType`
    // gap says the parameter states no bound at all.
    unresolved_bounds |= bounds.is_empty() && !unbounded;
    let bounds = bounds.into_iter().collect::<Vec<_>>();
    let bound_names =
        match project_rust_source_definitions(ready, mounts, &bounds, cancellation, session)? {
            SelectedRustSourceDefinitionProjection::Complete(rows) => {
                match split_projected_rust_definitions(rows) {
                    Some(vocabularies) => vocabularies
                        .units
                        .iter()
                        .map(CodeUnit::fq_name)
                        .collect::<BTreeSet<_>>(),
                    None => return Ok(None),
                }
            }
            SelectedRustSourceDefinitionProjection::Unavailable
            | SelectedRustSourceDefinitionProjection::Cancelled => return Ok(None),
        };
    let parameter_name = lexical
        .reference_lookup_spellings(&[prefix], ResolutionNamespace::Type, cancellation)?
        .remove(&prefix);
    let SelectedLookupRecipeReadOutcome::Ready(recipes) = lexical.lookup_semantic_recipes(
        &[SelectedLookupRecipeRequest {
            fragment: route.fragment(),
            semantic: route.row().source_lookup(),
        }],
        cancellation,
        None,
    )?
    else {
        return Ok(None);
    };
    let demand = recipes
        .into_vec()
        .pop()
        .flatten()
        .map(|recipe| recipe.spelling().to_owned());
    let evidence = serde_json::json!({
        "evidence": [{
            "reason": GENERIC_PARAMETER_MEMBER,
            "rel_path": rel_path,
            "parameter": parameter_name,
            "bounds": bound_names,
            "unresolved_bounds": unresolved_bounds,
            "demand": demand,
            "namespace": rust_crate_context::namespace(route.row().namespace()),
        }]
    })
    .to_string();
    let mut digest = CanonicalHasher::new(b"bifrost-rust-generic-parameter-member:v1");
    digest.field("evidence", evidence.as_bytes());
    Ok(Some(ResolutionCompletion::incomplete([
        ResolutionIncompleteReason::UnsupportedSemantic(identities.named_semantic(
            digest.finish(),
            GENERIC_PARAMETER_MEMBER,
            &evidence,
        )),
    ])))
}

/// The macro a `#[macro_use] extern crate` bound for the reference's crate.
///
/// `routes![..]` written in `cookies::message` names a macro that
/// `#[macro_use] extern crate rocket;` imported at that crate's root and that
/// `rocket` re-exported from `rocket_codegen`. None of that is in the
/// reference's lexical chain: the binding is written in another file and binds
/// for the whole crate, so the stack graph answers a complete absence and is
/// right to. The crate rows hold the binding and the route, and the
/// point-export walk already continues a macro lookup from a module to its
/// crate root for exactly this reason, so the reference asks that walk the
/// question its own chain could not answer.
///
/// Asking it earlier was tried and withdrawn (`c198d5a7b`): a root reference
/// per invocation made every `println!` a rooted reference, which changed what
/// a module's own glob import demands and what a macro capsule costs, and
/// broke 22 library tests. The question belongs to the reference whose lexical
/// lookup ended empty, not to every macro name, so it is asked here, once,
/// after that answer is in hand.
fn rust_macro_use_binding_targets(
    ready: &ReadySelectedResolution<'_, '_>,
    mounts: SelectedMountTable<'_, '_>,
    mount: SelectedResolutionMountOrdinal,
    reference: SemanticId,
    resolution: &FactResolutionAnswer,
    cancellation: &CancellationToken,
) -> Result<Vec<SemanticId>> {
    let unqualified_macro = resolution.site_metadata().is_some_and(|metadata| {
        metadata.namespace() == ResolutionNamespace::Macro
            && metadata.site_kind() == ResolutionSiteKind::MacroReference
            && metadata.unqualified()
    });
    // A lexical answer outranks this one, and an incomplete lexical answer is
    // not a dead end: it is a question the graph is still entitled to own.
    if !unqualified_macro
        || !resolution.binding().targets().is_empty()
        || *resolution.binding().completion() != ResolutionCompletion::Complete
    {
        return Ok(Vec::new());
    }
    // The reference's lookup path carries the name it spells, in the
    // namespace it spells it in. The reference's own semantic is its site
    // identity, not a name, which is why the lookup recipe read cannot
    // answer here.
    let lexical = ready.lexical_source();
    let spellings = lexical.reference_lookup_spellings(
        &[reference],
        ResolutionNamespace::Macro,
        cancellation,
    )?;
    let Some(name) = spellings.get(&reference) else {
        return Ok(Vec::new());
    };
    let rows = rust_crate_rows::RustCrateRows { ready };
    let mut targets = Vec::new();
    for module in rows.modules_for_mount(mounts, mount, cancellation)? {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        for export in rows.crate_exports(
            &module,
            module.topology,
            &module.path,
            rust_crate_context::namespace(ResolutionNamespace::Macro),
            name,
        )? {
            // The walk names ordinary declaration sites in the blob that owns
            // them, which is the same coordinate the endpoint route reads. The
            // crate declares no macro-namespace item (`rust_crate_macro_items`
            // holds types and values), so every macro export has a site.
            let rust_crate_rows::RustCrateDeclaration::Site(site) = export.declaration else {
                unreachable!("a macro export is a persisted declaration: {export:?}");
            };
            targets.push(crate::analyzer::resolution::mounted_site_semantic(
                mounts.mount_by_ordinal(export.mount)?.fragment(),
                ResolutionSiteId::new(site),
            ));
        }
    }
    targets.sort_unstable();
    targets.dedup();
    Ok(targets)
}

#[allow(clippy::too_many_arguments)]
fn collect_selected_root_halves<S>(
    identities: &SelectedContextIdentities,
    anchors: &dyn crate::analyzer::resolution::SelectedRootImportAnchors,
    source: &S,
    scope: &RustRootHalfScope,
    cancellation: &CancellationToken,
    session: Option<&ResolutionSession>,
    halves: &mut Vec<SelectedRootPathHalf>,
    completion: &mut ResolutionCompletion,
) -> Result<bool>
where
    S: crate::analyzer::resolution::BatchResolutionFragmentSource + ?Sized,
{
    let imports_timing = crate::profiling::scope("rust_selected::workspace_root_import_halves");
    let imports = visit_selected_root_import_half_pages(
        identities,
        anchors,
        source,
        Some(&scope.sources.ordinals),
        cancellation,
        &mut FactPageVisitor::new(&mut |page| {
            if session.is_some_and(|session| !(0..page.len()).all(|_| session.scope_step())) {
                return Ok(false);
            }
            halves.extend(page.iter().filter(|half| scope.admits(half)).cloned());
            Ok(true)
        }),
    )?;
    drop(imports_timing);
    *completion = completion.combine(imports.evidence());
    if imports.is_cancelled()
        || cancellation.is_cancelled()
        || session.is_some_and(|session| !session.observe_cancellation())
    {
        return Ok(false);
    }
    assert!(imports.is_exhausted(), "root inventory visitor never stops");

    let exports_timing = crate::profiling::scope("rust_selected::workspace_root_export_halves");
    let exports = visit_selected_root_export_half_pages(
        identities,
        anchors,
        source,
        Some(&scope.targets.ordinals),
        cancellation,
        &mut FactPageVisitor::new(&mut |page| {
            if session.is_some_and(|session| !(0..page.len()).all(|_| session.scope_step())) {
                return Ok(false);
            }
            halves.extend(page.iter().filter(|half| scope.admits(half)).cloned());
            Ok(true)
        }),
    )?;
    drop(exports_timing);
    *completion = completion.combine(exports.evidence());
    if exports.is_cancelled()
        || cancellation.is_cancelled()
        || session.is_some_and(|session| !session.observe_cancellation())
    {
        return Ok(false);
    }
    assert!(exports.is_exhausted(), "root inventory visitor never stops");
    Ok(true)
}

trait RustSelectedBridgeView {
    fn source_file(&self) -> &std::path::Path;
    // Positioned reference authorities have no import declaration. They must
    // not certify inventory coverage for a different, merely similar import.
    fn source_import_identity(&self) -> Option<(usize, ResolutionScopeId)>;
    fn source_import_site(&self) -> Option<ResolutionSiteId>;
    fn anchor(&self) -> ResolutionRootImportAnchor;
    fn target_file(&self) -> &std::path::Path;
    fn target_root_scope(
        &self,
    ) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
    fn route(&self) -> &[String];
    fn source_name(&self) -> &str;
    fn target_name(&self) -> &str;
    fn namespace(&self) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    fn declaration_authority(&self) -> Option<&RustSelectedDeclarationAuthority>;
}

impl RustSelectedBridgeView for RustSelectedRootBridge {
    fn source_file(&self) -> &std::path::Path {
        &self.source_file
    }

    fn source_import_identity(&self) -> Option<(usize, ResolutionScopeId)> {
        Some((self.source_import_ordinal, self.source_root_scope))
    }

    fn source_import_site(&self) -> Option<ResolutionSiteId> {
        Some(self.source_import_site)
    }

    fn anchor(&self) -> ResolutionRootImportAnchor {
        self.anchor
    }

    fn target_file(&self) -> &std::path::Path {
        &self.target_file
    }

    fn target_root_scope(
        &self,
    ) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId {
        self.target_root_scope
    }

    fn route(&self) -> &[String] {
        &self.route
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }

    fn target_name(&self) -> &str {
        &self.target_name
    }

    fn namespace(&self) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace {
        self.namespace
    }

    fn declaration_authority(&self) -> Option<&RustSelectedDeclarationAuthority> {
        self.declaration_authority.as_ref()
    }
}

impl RustSelectedBridgeView for RustSelectedRootBridgeTopology {
    fn source_file(&self) -> &std::path::Path {
        &self.source_file
    }

    fn source_import_identity(&self) -> Option<(usize, ResolutionScopeId)> {
        self.source_import_ordinal
            .map(|ordinal| (ordinal, self.source_root_scope))
    }

    fn source_import_site(&self) -> Option<ResolutionSiteId> {
        None
    }

    fn anchor(&self) -> ResolutionRootImportAnchor {
        self.anchor
    }

    fn target_file(&self) -> &std::path::Path {
        &self.target_file
    }

    fn target_root_scope(
        &self,
    ) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId {
        self.target_root_scope
    }

    fn route(&self) -> &[String] {
        &self.route
    }

    fn source_name(&self) -> &str {
        &self.source_name
    }

    fn target_name(&self) -> &str {
        &self.target_name
    }

    fn namespace(&self) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace {
        self.namespace
    }

    fn declaration_authority(&self) -> Option<&RustSelectedDeclarationAuthority> {
        self.declaration_authority.as_ref()
    }
}

enum PreparedSelectedResolution<'store, 'input> {
    Ready(Box<ReadySelectedResolution<'store, 'input>>),
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
    Cancelled,
}

struct SelectedMacroBindingTarget {
    host: Arc<super::resolution_selection::SelectedResolutionMountRecord>,
    semantic: SemanticId,
    node: BindingNodeId,
}

enum LocatedSemantic {
    Found(SemanticId),
    Missing,
    Cancelled,
}

enum LocatedSemantics {
    Found(Vec<SemanticId>),
    Missing,
    Cancelled,
}

enum SelectedDefinitionRoot<'locator> {
    Locator(&'locator SelectedSemanticLocator),
    RustSemantic {
        definition: SemanticId,
        target_path: String,
    },
}

enum ContextRegistrationOutcome {
    Ready,
    Cancelled,
}

/// Operation-local work used to validate and compile selected context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SelectedResolutionContextMetrics;

impl SelectedResolutionContextMetrics {
    fn assert_fresh(&self) {
        assert_eq!(
            self, &Self,
            "selected resolution context metrics must be fresh and default-valued"
        );
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedResolutionBoundarySnapshotForTest {
    universal_root: SelectedNodeProvenance,
    boundaries: Box<[(BindingNodeId, SelectedNodeProvenance)]>,
    callable_static_import_boundaries: Box<[BindingNodeId]>,
}

#[cfg(test)]
impl SelectedResolutionBoundarySnapshotForTest {
    pub(crate) const fn universal_root(&self) -> SelectedNodeProvenance {
        self.universal_root
    }

    pub(crate) fn boundaries(&self) -> &[(BindingNodeId, SelectedNodeProvenance)] {
        &self.boundaries
    }

    pub(crate) fn callable_static_import_boundaries(&self) -> &[BindingNodeId] {
        &self.callable_static_import_boundaries
    }
}

#[cfg(test)]
thread_local! {
    static SELECTED_RESOLUTION_BOUNDARY_SNAPSHOT: std::cell::RefCell<
        Option<SelectedResolutionBoundarySnapshotForTest>
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn reset_selected_resolution_boundary_snapshot_for_test() {
    SELECTED_RESOLUTION_BOUNDARY_SNAPSHOT.with(|snapshot| *snapshot.borrow_mut() = None);
}

#[cfg(test)]
pub(crate) fn selected_resolution_boundary_snapshot_for_test()
-> Option<SelectedResolutionBoundarySnapshotForTest> {
    SELECTED_RESOLUTION_BOUNDARY_SNAPSHOT.with(|snapshot| snapshot.borrow().clone())
}

impl AnalyzerStore {
    pub(crate) fn open_selected_resolution_operation<'store, 'input>(
        &'store self,
        input: SelectedResolutionOperationInput<'input>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'store, 'input>> {
        Ok(
            match self.prepare_selected_resolution(input, cancellation)? {
                PreparedSelectedResolution::Ready(ready) => {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedResolutionOperationOpenOutcome::Cancelled);
                    }
                    SelectedResolutionOperationOpenOutcome::Ready(Box::new(
                        SelectedResolutionOperation {
                            ready: *ready,
                            enumerated_mounts: OnceCell::new(),
                        },
                    ))
                }
                PreparedSelectedResolution::Unavailable(reason) => {
                    SelectedResolutionOperationOpenOutcome::Unavailable(reason)
                }
                PreparedSelectedResolution::Stale(reason) => {
                    SelectedResolutionOperationOpenOutcome::Stale(reason)
                }
                PreparedSelectedResolution::Cancelled => {
                    SelectedResolutionOperationOpenOutcome::Cancelled
                }
            },
        )
    }

    fn prepare_selected_resolution<'store, 'input>(
        &'store self,
        input: SelectedResolutionOperationInput<'input>,
        cancellation: &CancellationToken,
    ) -> Result<PreparedSelectedResolution<'store, 'input>> {
        if cancellation.is_cancelled() {
            return Ok(PreparedSelectedResolution::Cancelled);
        }
        let current_generation = input.project.analysis_generation();
        if cancellation.is_cancelled() {
            return Ok(PreparedSelectedResolution::Cancelled);
        }
        if current_generation != input.analysis_generation {
            return Ok(PreparedSelectedResolution::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: input.analysis_generation,
                    actual: current_generation,
                },
            ));
        }
        for language in input.languages {
            match self.native_configuration_overlay_mismatch(
                input.project,
                input.snapshots,
                language.storage_language(),
                language.semantic_language(),
                cancellation,
            )? {
                super::NativeConfigurationOverlayAuthority::Current => {}
                super::NativeConfigurationOverlayAuthority::Mismatch(path) => {
                    return Ok(PreparedSelectedResolution::Unavailable(
                        SelectedResolutionUnavailable::MissingTransientOverlayInput {
                            storage_language: language.storage_language().to_owned(),
                            persisted_relative_path: path,
                        },
                    ));
                }
                super::NativeConfigurationOverlayAuthority::Cancelled => {
                    return Ok(PreparedSelectedResolution::Cancelled);
                }
            }
        }
        match validate_selected_overlay_authority(
            input.project,
            input.languages,
            input.overlay_masks,
            &input.content_mounts,
            cancellation,
        ) {
            SelectedOverlayAuthorityValidation::Ready => {}
            SelectedOverlayAuthorityValidation::Unavailable(reason) => {
                return Ok(PreparedSelectedResolution::Unavailable(reason));
            }
            SelectedOverlayAuthorityValidation::Stale(reason) => {
                return Ok(PreparedSelectedResolution::Stale(reason));
            }
            SelectedOverlayAuthorityValidation::Cancelled => {
                return Ok(PreparedSelectedResolution::Cancelled);
            }
        }
        let inventory = match self.open_selected_resolution_mount_inventory_with_content_mounts(
            input.workspace_id,
            input.snapshots,
            input.languages,
            input.overlay_masks,
            &input.content_mounts,
            cancellation,
        )? {
            SelectedResolutionMountInventoryOutcome::Ready(inventory) => inventory,
            SelectedResolutionMountInventoryOutcome::Unavailable(reason) => {
                return Ok(PreparedSelectedResolution::Unavailable(reason));
            }
            SelectedResolutionMountInventoryOutcome::Cancelled => {
                return Ok(PreparedSelectedResolution::Cancelled);
            }
            SelectedResolutionMountInventoryOutcome::Stale(reason) => {
                return Ok(PreparedSelectedResolution::Stale(reason));
            }
        };
        match validate_selected_content_mounts(&inventory, cancellation)? {
            SelectedContentValidationOutcome::Ready => {}
            SelectedContentValidationOutcome::Unavailable(reason) => {
                return Ok(PreparedSelectedResolution::Unavailable(reason));
            }
            SelectedContentValidationOutcome::Cancelled => {
                return Ok(PreparedSelectedResolution::Cancelled);
            }
        };
        let query_preparation = Box::new(QueryResolutionPreparation {
            macro_overlay: RefCell::default(),
            prepared_macro_files: RefCell::default(),
            rust_caller_context: RefCell::new(None),
            rust_caller_demand: RefCell::new(None),
            rust_workspace_relations: RefCell::new(ClosedRelations::default()),
        });
        if cancellation.is_cancelled() {
            return Ok(PreparedSelectedResolution::Cancelled);
        }
        let current_generation = input.project.analysis_generation();
        if cancellation.is_cancelled() {
            return Ok(PreparedSelectedResolution::Cancelled);
        }
        if current_generation != input.analysis_generation {
            return Ok(PreparedSelectedResolution::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: input.analysis_generation,
                    actual: current_generation,
                },
            ));
        }
        Ok(PreparedSelectedResolution::Ready(Box::new(
            ReadySelectedResolution {
                store: self,
                inventory,
                query_preparation: Some(query_preparation),
                content_mounts: input.content_mounts,
                project: input.project,
                analysis_generation: input.analysis_generation,
                macro_walk: RefCell::default(),
                crate_rows: RefCell::default(),
                context_identities: SelectedContextIdentities::new(),
                go_publication: RefCell::new(None),
            },
        )))
    }
}

enum SelectedOverlayAuthorityValidation {
    Ready,
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
    Cancelled,
}

fn validate_content_mount_authority(
    project: &dyn Project,
    content_mounts: &[SelectedResolutionContentMountRequest],
    cancellation: &CancellationToken,
) -> SelectedOverlayAuthorityValidation {
    let overlays = project.overlay_content();
    let overlay_entries = overlays
        .as_deref()
        .map(|content| content.entries())
        .unwrap_or(&[]);
    let mut overlay_digests = crate::hash::map_with_capacity(overlay_entries.len());
    for (file, digest) in overlay_entries {
        if cancellation.is_cancelled() {
            return SelectedOverlayAuthorityValidation::Cancelled;
        }
        overlay_digests.insert(crate::path_utils::rel_path_string(file), *digest);
    }
    for content_mount in content_mounts {
        if cancellation.is_cancelled() {
            return SelectedOverlayAuthorityValidation::Cancelled;
        }
        let Some(authority) = content_mount.overlay_authority() else {
            return SelectedOverlayAuthorityValidation::Unavailable(
                SelectedResolutionUnavailable::MissingTransientOverlayInput {
                    storage_language: content_mount.storage_language().to_owned(),
                    persisted_relative_path: content_mount.persisted_relative_path().to_owned(),
                },
            );
        };
        let actual = overlay_digests
            .get(content_mount.persisted_relative_path())
            .copied();
        let (expected, accepts_missing) = match authority {
            SelectedResolutionOverlayAuthority::LiveOverlay { content_digest } => {
                (*content_digest, false)
            }
            SelectedResolutionOverlayAuthority::Counterfactual {
                base_content_digest,
            } => (*base_content_digest, true),
        };
        if actual != Some(expected) && !(accepts_missing && actual.is_none()) {
            return SelectedOverlayAuthorityValidation::Stale(
                SelectedResolutionStale::TransientOverlayChanged {
                    storage_language: content_mount.storage_language().to_owned(),
                    persisted_relative_path: content_mount.persisted_relative_path().to_owned(),
                    expected_content_digest: expected,
                    actual_content_digest: actual,
                },
            );
        }
    }
    SelectedOverlayAuthorityValidation::Ready
}

fn validate_selected_overlay_authority(
    project: &dyn Project,
    languages: &[SelectedResolutionLanguage],
    overlay_masks: &[SelectedResolutionOverlayMask],
    content_mounts: &[SelectedResolutionContentMountRequest],
    cancellation: &CancellationToken,
) -> SelectedOverlayAuthorityValidation {
    let overlays = project.overlay_content();
    let overlay_entries = overlays
        .as_deref()
        .map(|content| content.entries())
        .unwrap_or(&[]);
    let mut overlay_digests = crate::hash::map_with_capacity(overlay_entries.len());
    for (file, digest) in overlay_entries {
        if cancellation.is_cancelled() {
            return SelectedOverlayAuthorityValidation::Cancelled;
        }
        overlay_digests.insert(crate::path_utils::rel_path_string(file), *digest);
    }
    let mut masks_by_key = crate::hash::map_with_capacity(overlay_masks.len());
    for mask in overlay_masks {
        if cancellation.is_cancelled() {
            return SelectedOverlayAuthorityValidation::Cancelled;
        }
        masks_by_key.insert(
            (mask.storage_language(), mask.persisted_relative_path()),
            mask,
        );
    }
    let mut content_mounts_by_key = crate::hash::map_with_capacity(content_mounts.len());
    for content_mount in content_mounts {
        if cancellation.is_cancelled() {
            return SelectedOverlayAuthorityValidation::Cancelled;
        }
        content_mounts_by_key.insert(
            (
                content_mount.storage_language(),
                content_mount.persisted_relative_path(),
            ),
            content_mount,
        );
    }

    match validate_content_mount_authority(project, content_mounts, cancellation) {
        SelectedOverlayAuthorityValidation::Ready => {}
        other => return other,
    }
    for content_mount in content_mounts {
        if cancellation.is_cancelled() {
            return SelectedOverlayAuthorityValidation::Cancelled;
        }
        let key = (
            content_mount.storage_language(),
            content_mount.persisted_relative_path(),
        );
        let Some(mask) = masks_by_key.get(&key).copied() else {
            return SelectedOverlayAuthorityValidation::Unavailable(
                SelectedResolutionUnavailable::MissingTransientOverlayInput {
                    storage_language: content_mount.storage_language().to_owned(),
                    persisted_relative_path: content_mount.persisted_relative_path().to_owned(),
                },
            );
        };
        if mask.intent() != SelectedResolutionOverlayIntent::Replacement {
            return SelectedOverlayAuthorityValidation::Unavailable(
                SelectedResolutionUnavailable::MissingTransientOverlayInput {
                    storage_language: content_mount.storage_language().to_owned(),
                    persisted_relative_path: content_mount.persisted_relative_path().to_owned(),
                },
            );
        }
    }

    for (file, _) in overlay_entries {
        if cancellation.is_cancelled() {
            return SelectedOverlayAuthorityValidation::Cancelled;
        }
        let semantic_language = crate::analyzer::common::language_for_file(file);
        for language in languages
            .iter()
            .filter(|language| language.semantic_language() == semantic_language)
        {
            if cancellation.is_cancelled() {
                return SelectedOverlayAuthorityValidation::Cancelled;
            }
            let persisted_relative_path = crate::path_utils::rel_path_string(file);
            let key = (
                language.storage_language(),
                persisted_relative_path.as_str(),
            );
            let Some(mask) = masks_by_key.get(&key).copied() else {
                return SelectedOverlayAuthorityValidation::Unavailable(
                    SelectedResolutionUnavailable::MissingTransientOverlayInput {
                        storage_language: language.storage_language().to_owned(),
                        persisted_relative_path,
                    },
                );
            };
            if mask.intent() != SelectedResolutionOverlayIntent::Replacement {
                return SelectedOverlayAuthorityValidation::Unavailable(
                    SelectedResolutionUnavailable::MissingTransientOverlayInput {
                        storage_language: language.storage_language().to_owned(),
                        persisted_relative_path,
                    },
                );
            }
            let content_mount = content_mounts_by_key.get(&key).copied();
            if content_mount.is_none() {
                return SelectedOverlayAuthorityValidation::Unavailable(
                    SelectedResolutionUnavailable::MissingTransientOverlayInput {
                        storage_language: language.storage_language().to_owned(),
                        persisted_relative_path,
                    },
                );
            }
            if content_mount
                .is_some_and(|content_mount| content_mount.overlay_authority().is_none())
            {
                return SelectedOverlayAuthorityValidation::Unavailable(
                    SelectedResolutionUnavailable::MissingTransientOverlayInput {
                        storage_language: language.storage_language().to_owned(),
                        persisted_relative_path,
                    },
                );
            }
        }
    }
    SelectedOverlayAuthorityValidation::Ready
}

impl SelectedResolutionOperation<'_, '_> {
    pub(crate) fn resolve_reference(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<SelectedResolutionLocated<FactResolutionAnswer>>>
    {
        self.resolve_reference_with_projection(
            context,
            locator,
            cancellation,
            context_metrics,
            &ResolutionSession::unbounded(),
            |_, _, answer| Ok(answer),
        )
    }

    fn resolve_reference_with_projection<T>(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        session: &ResolutionSession,
        project: impl FnOnce(
            &ReadySelectedResolution<'_, '_>,
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            FactResolutionAnswer,
        ) -> Result<T>,
    ) -> Result<SelectedResolutionOperationOutcome<SelectedResolutionLocated<T>>> {
        if !session.scope_step() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        let context = match self.prepare_context(context, cancellation, context_metrics)? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        let ready = &self.ready;
        let (projected, completion) = {
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancellation_completion,
                    ));
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let located = if locator.storage_language() == "java" {
                ready.lookup_java_definition_locator(&persisted_lexical, locator, cancellation)?
            } else {
                ready.lookup_locator(&persisted_lexical, locator, cancellation)?
            };
            match located {
                LocatedSemantic::Found(reference) => {
                    let resolve =
                        |operation: &mut crate::analyzer::resolution::FactResolutionOperation<
                            '_,
                        >| {
                            let answer = operation.resolve_reference_with_metrics(
                                reference,
                                &mut ResolutionBatchMetrics::default(),
                            )?;
                            let completion = answer.completion().clone();
                            Ok((
                                SelectedResolutionLocated::Found(project(
                                    ready, operation, answer,
                                )?),
                                completion,
                            ))
                        };
                    if locator.storage_language() == "java" {
                        self.with_java_forward_operation(
                            &blueprint,
                            &observed_lexical,
                            &observed_typed,
                            locator.relative_path(),
                            cancellation,
                            session,
                            resolve,
                        )?
                    } else {
                        blueprint.with_forward_operation_in_session(
                            &observed_lexical,
                            &persisted_lexical,
                            &observed_typed,
                            cancellation,
                            session,
                            resolve,
                        )?
                    }
                }
                LocatedSemantic::Missing => (
                    SelectedResolutionLocated::Missing,
                    ResolutionCompletion::Complete,
                ),
                LocatedSemantic::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            }
        };
        self.ready.finish(projected, &completion, cancellation)
    }

    pub(crate) fn resolve_rust_reference(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<Vec<SelectedRustReferenceAnswer>>,
        >,
    > {
        let mut point_metrics = ResolutionBatchMetrics::default();
        self.resolve_rust_reference_with_metrics(
            context,
            locator,
            cancellation,
            context_metrics,
            &mut point_metrics,
        )
    }

    /// Resolve and project one Rust reference while retaining exact lexical work.
    pub(crate) fn resolve_rust_reference_with_metrics(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<Vec<SelectedRustReferenceAnswer>>,
        >,
    > {
        let session = ResolutionSession::unbounded();
        self.resolve_rust_reference_in_session(
            context,
            locator,
            cancellation,
            context_metrics,
            point_metrics,
            &session,
        )
    }

    pub(crate) fn resolve_rust_reference_bounded(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<
        BoundedResolution<
            SelectedResolutionOperationOutcome<
                SelectedResolutionLocated<Vec<SelectedRustReferenceAnswer>>,
            >,
        >,
    > {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_rust_reference_in_session(
            context,
            locator,
            cancellation,
            context_metrics,
            point_metrics,
            &session,
        )?;
        Ok(session.finish(outcome))
    }

    /// A declaration name denotes itself. Resolve its canonical definition
    /// semantic without building a reference context, for retained and dirty files.
    pub(crate) fn rust_cfg_activation_for_caller(
        &self,
        caller: &Path,
        condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
        cancellation: &CancellationToken,
    ) -> Result<Option<brokk_bifrost_rust::selected_context::RustSelectedActivation>> {
        use brokk_bifrost_rust::selected_context::RustSelectedActivation;
        let mut activation = None;
        for key in self.rust_crate_keys_for_file(caller, cancellation)? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let atoms: String = self
                .ready
                .inventory
                .connection()
                .prepare_cached(rust_crate_context::CFG)?
                .query_row([key.as_slice()], |row| row.get(0))?;
            let atoms = serde_json::from_str(&atoms)
                .map_err(|error| StoreError::corrupt(error.to_string()))?;
            let selected = brokk_bifrost_rust::cfg::crate_activation(&atoms, condition);
            if activation.is_some_and(|previous| previous != selected) {
                return Ok(Some(RustSelectedActivation::Unknown));
            }
            activation = Some(selected);
        }
        Ok((!cancellation.is_cancelled())
            .then_some(activation.unwrap_or(RustSelectedActivation::Unknown)))
    }

    /// The declaration a range denotes by being one, or `None` when the range
    /// has no declaration answer of its own.
    ///
    /// One range can carry both roles. A Rust pattern token in a match arm or
    /// a `let` condition is a reference to a visible unit variant or constant
    /// and, only when no such declaration is visible, the binder it looks
    /// like; the producer publishes both halves at the same range and pairs
    /// them in a `ResolutionConditionalBinderFact`. Which one the token is, is
    /// exactly what the reference route decides, so a range that also carries
    /// a reference has no declaration answer here and this route stands down.
    pub(crate) fn rust_declaration_at_range_bounded(
        &mut self,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> Result<
        Option<
            BoundedResolution<
                SelectedResolutionOperationOutcome<SelectedRustSourceDefinitionProjection>,
            >,
        >,
    > {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let persisted = self.ready.lexical_source();
        let (start_byte, end_byte) = locator
            .declaration_range()
            .expect("a declaration route needs a declaration range");
        let reference = SelectedSemanticLocator::for_reference_range(
            locator.storage_language(),
            locator.relative_path(),
            start_byte,
            end_byte,
        );
        if let LocatedSemantics::Found(_) =
            self.ready
                .lookup_locators_in_session(&persisted, &reference, cancellation, &session)?
        {
            return Ok(None);
        }
        let projection = match self.ready.lookup_locators_in_session(
            &persisted,
            locator,
            cancellation,
            &session,
        )? {
            LocatedSemantics::Missing => return Ok(None),
            LocatedSemantics::Cancelled => SelectedRustSourceDefinitionProjection::Cancelled,
            LocatedSemantics::Found(definitions) => {
                if !cancellation.is_cancelled() && session.scope_step() {
                    project_rust_source_definitions(
                        &self.ready,
                        self.mount_table(),
                        &definitions,
                        cancellation,
                        &session,
                    )?
                } else {
                    SelectedRustSourceDefinitionProjection::Cancelled
                }
            }
        };
        let outcome =
            self.ready
                .finish(projection, &ResolutionCompletion::Complete, cancellation)?;
        Ok(Some(session.finish(outcome)))
    }

    /// A reverse confirmation certifies absence, so it answers under the
    /// crate-set authority: a detached root's absent feature atoms stay
    /// unknown instead of being refuted, and one undecided candidate site
    /// keeps the reverse answer incomplete.
    /// Confirm every candidate site of one caller file in one request.
    ///
    /// Reverse confirmation is the only caller of this: it holds all the
    /// candidate sites of a blob at once, and they share the caller's macro
    /// frontier, crate context, demand inventory and blueprint. Confirming
    /// them one at a time paid for all of that once per site.
    pub(crate) fn confirm_rust_references_for_caller_bounded(
        self,
        caller: &std::path::Path,
        locators: &[&SelectedSemanticLocator],
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<BoundedResolution<SelectedRustCallerReferencesOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_rust_references_for_caller_in_session(
            caller,
            locators,
            cancellation,
            context_metrics,
            point_metrics,
            &session,
            crate_set_access,
            |_, _, _, _, _, _| Ok(SelectedResolutionOperationOutcome::Native(())),
        )?;
        Ok(session.finish(outcome))
    }

    pub(crate) fn resolve_rust_reference_for_caller_bounded(
        self,
        caller: &std::path::Path,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<BoundedResolution<SelectedRustCallerReferenceOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_rust_references_for_caller_in_session(
            caller,
            &[locator],
            cancellation,
            context_metrics,
            point_metrics,
            &session,
            point_access,
            |_, _, _, _, _, _| Ok(SelectedResolutionOperationOutcome::Native(())),
        )?;
        Ok(session.finish(outcome.into_single()))
    }

    pub(crate) fn resolve_rust_reference_for_caller(
        self,
        caller: &Path,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<SelectedRustCallerReferenceOutcome> {
        Ok(self
            .resolve_rust_references_for_caller_in_session(
                caller,
                &[locator],
                cancellation,
                context_metrics,
                point_metrics,
                &ResolutionSession::unbounded(),
                point_access,
                |_, _, _, _, _, _| Ok(SelectedResolutionOperationOutcome::Native(())),
            )?
            .into_single())
    }

    pub(crate) fn resolve_rust_binding_site_for_caller(
        self,
        caller: &Path,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustCallerReferenceOutcome<SelectedRustBindingSite>> {
        Ok(self
            .resolve_rust_references_for_caller_in_session(
                caller,
                &[locator],
                cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
                &ResolutionSession::unbounded(),
                point_access,
                |_, answer, ready, mounts, session, cancellation| {
                    let metadata = answer.site_metadata();
                    let owner = match metadata.and_then(|metadata| metadata.reference_owner()) {
                        None => SelectedRustBindingOwner::Unknown,
                        Some(None) => SelectedRustBindingOwner::FileRoot,
                        Some(Some(owner)) => match project_rust_definitions(
                            ready,
                            mounts,
                            &[owner],
                            cancellation,
                            session,
                        )? {
                            SelectedRustDefinitionProjection::Complete(mut units) => {
                                SelectedRustBindingOwner::Definition(
                                    units.pop().expect("one owner"),
                                )
                            }
                            SelectedRustDefinitionProjection::Unavailable => {
                                SelectedRustBindingOwner::Unavailable
                            }
                            SelectedRustDefinitionProjection::Cancelled => {
                                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                    cancelled_completion(),
                                ));
                            }
                        },
                    };
                    let mut definitions = answer
                        .binding()
                        .targets()
                        .iter()
                        .map(|semantic| SelectedRustBindingDefinition::Stable(*semantic))
                        .collect::<Vec<_>>();
                    definitions.sort();
                    Ok(SelectedResolutionOperationOutcome::Native(
                        SelectedRustBindingSite {
                            file: ProjectFile::new(ready.project.root(), locator.relative_path()),
                            metadata,
                            owner,
                            definitions: definitions.into_boxed_slice(),
                            completion: answer.binding().completion().clone(),
                        },
                    ))
                },
            )?
            .into_single())
    }

    pub(crate) fn finish_rust_row_binding_world(
        mut self,
        target: SelectedRustBindingDefinition,
        mut sites: Vec<SelectedRustBindingSite>,
        completion: ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<SelectedRustBindingWorld>> {
        sites.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.metadata.cmp(&right.metadata))
                .then_with(|| left.definitions.cmp(&right.definitions))
        });
        sites.dedup();
        self.ready.finish(
            SelectedRustBindingWorld {
                target,
                sites: sites.into_boxed_slice(),
                completion: completion.clone(),
            },
            &completion,
            cancellation,
        )
    }

    pub(crate) fn resolve_rust_type_for_caller_bounded(
        self,
        caller: &Path,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<BoundedResolution<SelectedRustCallerReferenceOutcome<SelectedRustTypeProjection>>>
    {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_rust_references_for_caller_in_session(
            caller,
            &[locator],
            cancellation,
            context_metrics,
            point_metrics,
            &session,
            point_access,
            |operation, resolution, ready, mounts, session, cancellation| {
                project_rust_reference_types(
                    operation,
                    resolution,
                    ready,
                    mounts,
                    session,
                    cancellation,
                    locator,
                )
            },
        )?;
        Ok(session.finish(outcome.into_single()))
    }

    /// Whether the reference at `locator` spells, in the Type namespace, a
    /// module the crate declares for an item macro in the module the reference
    /// is written in (`rust_crate_rows::REFERENCE_NAMES_MACRO_MODULE`).
    ///
    /// A bare path head is bound lexically, and a crate-declared module has no
    /// lexical binder (the capsule declares it for the crate's export lookup
    /// only), so a head that names one finds nothing lexically. It exists all
    /// the same, which is what the point route's route-head boundary claim
    /// must not deny.
    pub(crate) fn rust_reference_names_macro_module(
        &self,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let persisted = self.ready.lexical_source();
        let session = ResolutionSession::unbounded();
        let sites = match persisted.lookup_semantic_sites(locator, cancellation, &session)? {
            SelectedSemanticLookupOutcome::Found(sites) => sites,
            SelectedSemanticLookupOutcome::Missing | SelectedSemanticLookupOutcome::Cancelled => {
                return Ok(false);
            }
        };
        let connection = self.ready.inventory.connection();
        for site in sites {
            let semantic = site.semantic();
            let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
                continue;
            };
            let spellings = persisted.reference_lookup_spellings(
                &[semantic],
                ResolutionNamespace::Type,
                cancellation,
            )?;
            let Some(name) = spellings.get(&semantic) else {
                continue;
            };
            if connection
                .prepare_cached(rust_crate_rows::REFERENCE_NAMES_MACRO_MODULE)?
                .exists(rusqlite::params![ordinal, key, name])?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The workspace crate the path head at `locator` names, when it names one
    /// (`rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE`).
    ///
    /// A crate root has no declaration, so a head that names a workspace crate
    /// (`forc_pkg` in `forc_pkg::Built`, or an alias bound to its root) finds
    /// nothing lexically. The crate is compiled by this workspace all the
    /// same, which is what the route-head boundary claim must not deny.
    pub(crate) fn rust_reference_names_workspace_crate(
        &self,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<String>> {
        let persisted = self.ready.lexical_source();
        let session = ResolutionSession::unbounded();
        let sites = match persisted.lookup_semantic_sites(locator, cancellation, &session)? {
            SelectedSemanticLookupOutcome::Found(sites) => sites,
            SelectedSemanticLookupOutcome::Missing | SelectedSemanticLookupOutcome::Cancelled => {
                return Ok(None);
            }
        };
        for site in sites {
            let semantic = site.semantic();
            let Some(ordinal) = semantic.ordinal() else {
                continue;
            };
            if let Some(name) = rust_reference_workspace_crate(
                &self.ready,
                &persisted,
                SelectedResolutionMountOrdinal::new(ordinal),
                semantic,
                cancellation,
            )? {
                return Ok(Some(name));
            }
        }
        Ok(None)
    }

    /// The files whose capsules define a crate-declared item that `files`
    /// spell (`rust_crate_macro_items`, `rust_crate_context::MACRO_ITEM_HOSTS`).
    ///
    /// Such an item has no persisted definition: the capsule of the file that
    /// invokes the macro defines it, and a request stages only the capsules of
    /// the files it prepares. Preparing these hosts with `files` lets the
    /// export lookup reach the item. A request whose files reach the item only
    /// under another name finds no staged definition and answers incomplete
    /// (`rust_crate_context::unstaged_macro_item`).
    fn rust_macro_item_hosts(&self, files: &[&Path]) -> Result<Vec<PathBuf>> {
        let connection = self.ready.inventory.connection();
        if !connection
            .prepare_cached(rust_crate_context::MACRO_ITEMS_PRESENT)?
            .exists([])?
        {
            return Ok(Vec::new());
        }
        let mut hosts = Vec::new();
        for file in files {
            for host in connection
                .prepare_cached(rust_crate_context::MACRO_ITEM_HOSTS)?
                .query_map([selected_path_key(file)], |row| row.get::<_, String>(0))?
            {
                hosts.push(PathBuf::from(host?));
            }
        }
        hosts.sort_unstable();
        hosts.dedup();
        Ok(hosts)
    }

    #[allow(clippy::too_many_arguments)]
    /// `access` names the declaration authority this request answers under.
    /// A point request reads a detached root's cfg atoms as decided; a reverse
    /// confirmation, which certifies absence, reads them as unknown. The two
    /// policies are `crate_access_policy` and `crate_set_access_policy`.
    #[allow(clippy::too_many_arguments)]
    /// Resolve several reference sites of one caller against one preparation.
    ///
    /// The caller's macro frontier, crate context, demand inventory and
    /// blueprint are what a point request pays for before it resolves
    /// anything, and every site in the same file needs the same ones. Reverse
    /// confirmation asks about every candidate site of a blob at once, so it
    /// pays for that blob once instead of once per site.
    #[allow(clippy::too_many_arguments)]
    fn resolve_rust_references_for_caller_in_session<T>(
        self,
        caller: &Path,
        locators: &[&SelectedSemanticLocator],
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
        session: &ResolutionSession,
        access: RustDeclarationAccessFactory,
        project: impl FnMut(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            &FactResolutionAnswer,
            &ReadySelectedResolution<'_, '_>,
            SelectedMountTable<'_, '_>,
            &ResolutionSession,
            &CancellationToken,
        ) -> Result<SelectedResolutionOperationOutcome<T>>,
    ) -> Result<SelectedRustCallerReferencesOutcome<T>> {
        // Each point request owns a fresh metric sink. Crate-context preparation
        // is outside its receiver budget; native stitching charges this request.
        assert_eq!(
            point_metrics,
            &ResolutionBatchMetrics::default(),
            "selected Rust point metrics must be fresh and default-valued"
        );
        if self
            .mount_table()
            .mount_for_path("rust", &selected_path_key(caller))?
            .is_none()
        {
            return Ok(SelectedRustCallerReferencesOutcome::UnsupportedCallerProfile);
        }
        let operation_cancellation = session.cancellation().unwrap_or(cancellation);
        // One preparation for every file this request asks about. Preparing
        // them one at a time left all but the first without an overlay,
        // because the preparer answers "already done" for whatever is set.
        let mut macro_callers = vec![caller];
        for path in locators
            .iter()
            .map(|locator| Path::new(locator.relative_path()))
        {
            if path != caller && !macro_callers.contains(&path) {
                macro_callers.push(path);
            }
        }
        let macro_timing = crate::profiling::scope("rust_caller::macro_frontiers");
        let macro_item_hosts = self.rust_macro_item_hosts(&macro_callers)?;
        for path in &macro_item_hosts {
            if !macro_callers.contains(&path.as_path()) {
                macro_callers.push(path.as_path());
            }
        }
        match self
            .prepare_selected_macro_frontiers_for_files(&macro_callers, operation_cancellation)?
        {
            SelectedResolutionStageOutcome::Ready => {}
            SelectedResolutionStageOutcome::Cancelled => {
                return Ok(SelectedRustCallerReferencesOutcome::Operation(
                    SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                ));
            }
            SelectedResolutionStageOutcome::Stale(reason) => {
                return Ok(SelectedRustCallerReferencesOutcome::Operation(
                    SelectedResolutionOperationOutcome::Stale(reason),
                ));
            }
            SelectedResolutionStageOutcome::Unavailable(reason) => {
                return Ok(SelectedRustCallerReferencesOutcome::Operation(
                    SelectedResolutionOperationOutcome::Unavailable(reason),
                ));
            }
        }
        drop(macro_timing);
        let demand_timing = crate::profiling::scope("rust_caller::demand_preparation");
        let prepared = match self.rust_demand_preparation_for_caller_in_session(
            caller,
            operation_cancellation,
            Some(session),
        )? {
            SelectedRustCallerDemandOutcome::Ready(prepared) => prepared,
            SelectedRustCallerDemandOutcome::Unavailable => {
                return Ok(SelectedRustCallerReferencesOutcome::UnsupportedCallerProfile);
            }
            SelectedRustCallerDemandOutcome::Cancelled => {
                return Ok(SelectedRustCallerReferencesOutcome::Operation(
                    SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                ));
            }
        };
        let contexts = prepared
            .contexts
            .clone()
            .with_declaration_access_source(access(&self, prepared.crate_keys.clone())?);
        drop(demand_timing);
        let outcome = self.resolve_rust_reference_demand_projection_in_session(
            &prepared,
            contexts,
            locators,
            operation_cancellation,
            context_metrics,
            session,
            project,
        )?;
        Ok(SelectedRustCallerReferencesOutcome::Operation(outcome))
    }

    fn resolve_rust_reference_in_session(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
        session: &ResolutionSession,
    ) -> Result<
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<Vec<SelectedRustReferenceAnswer>>,
        >,
    > {
        self.resolve_rust_reference_projection_in_session(
            context,
            locator,
            cancellation,
            context_metrics,
            point_metrics,
            session,
            |_, _, _, _, _, _| Ok(SelectedResolutionOperationOutcome::Native(())),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_rust_reference_projection_in_session<T>(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
        session: &ResolutionSession,
        mut project: impl FnMut(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            &FactResolutionAnswer,
            &ReadySelectedResolution<'_, '_>,
            SelectedMountTable<'_, '_>,
            &ResolutionSession,
            &CancellationToken,
        ) -> Result<SelectedResolutionOperationOutcome<T>>,
    ) -> Result<
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<Vec<SelectedRustReferenceAnswer<T>>>,
        >,
    > {
        let cancellation = session.cancellation().unwrap_or(cancellation);
        assert_eq!(
            point_metrics,
            &ResolutionBatchMetrics::default(),
            "selected Rust point metrics must be fresh and default-valued"
        );
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        note_rust_point_work("search_entry_inputs", session);
        let context = match self.prepare_context_in_session(
            context,
            cancellation,
            context_metrics,
            session,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        note_rust_point_work("search_validate_mounts", session);
        let mut ready = self.ready;
        let attempt = {
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint =
                match ready.collect_blueprint_in_session(context, cancellation, session)? {
                    SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                    SelectedFactOperationBlueprintConstruction::Cancelled {
                        cancellation_completion,
                        ..
                    } => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancellation_completion,
                        ));
                    }
                };
            note_rust_point_work("search_collect_blueprint", session);
            if matches!(
                ready.register_context_in_session(&blueprint, cancellation, session)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            note_rust_point_work("search_register_context", session);
            match ready.lookup_locators_in_session(
                &persisted_lexical,
                locator,
                cancellation,
                session,
            )? {
                LocatedSemantics::Found(references) => {
                    note_rust_point_work("search_lookup_locators", session);
                    let answers = ready.with_workspace_forward_fact_operation(
                        &blueprint,
                        &observed_lexical,
                        &observed_typed,
                        cancellation,
                        session,
                        |operation| {
                            let mut answers = Vec::new();
                            for reference in references {
                                if !session.scope_step() || cancellation.is_cancelled() {
                                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                        cancelled_completion(),
                                    ));
                                }
                                let mut alternative_metrics = ResolutionBatchMetrics::default();
                                let resolution = operation.resolve_reference_with_metrics(
                                    reference,
                                    &mut alternative_metrics,
                                )?;
                                point_metrics.accumulate(alternative_metrics);
                                if !session.observe_cancellation() || cancellation.is_cancelled() {
                                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                        cancelled_completion(),
                                    ));
                                }
                                match assemble_rust_reference_answer(
                                    &RustReferenceAnswerContext {
                                        ready: &ready,
                                        mounts: SelectedMountTable::new(&ready.inventory),
                                        reference,
                                        locator,
                                        session,
                                        cancellation,
                                    },
                                    operation,
                                    resolution,
                                    &mut project,
                                )? {
                                    SelectedResolutionOperationOutcome::Native(answer) => {
                                        answers.push(answer)
                                    }
                                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                                        return Ok(
                                            SelectedResolutionOperationOutcome::Unavailable(reason),
                                        );
                                    }
                                    SelectedResolutionOperationOutcome::Stale(reason) => {
                                        return Ok(SelectedResolutionOperationOutcome::Stale(
                                            reason,
                                        ));
                                    }
                                    SelectedResolutionOperationOutcome::Cancelled(completion) => {
                                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                            completion,
                                        ));
                                    }
                                }
                            }
                            Ok(SelectedResolutionOperationOutcome::Native(answers))
                        },
                    )?;
                    match answers {
                        SelectedResolutionOperationOutcome::Native(answers) => {
                            SelectedResolutionLocated::Found(answers)
                        }
                        SelectedResolutionOperationOutcome::Unavailable(reason) => {
                            return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
                        }
                        SelectedResolutionOperationOutcome::Stale(reason) => {
                            return Ok(SelectedResolutionOperationOutcome::Stale(reason));
                        }
                        SelectedResolutionOperationOutcome::Cancelled(completion) => {
                            return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
                        }
                    }
                }
                LocatedSemantics::Missing => SelectedResolutionLocated::Missing,
                LocatedSemantics::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            }
        };
        let completion = match &attempt {
            SelectedResolutionLocated::Found(answers) => answers
                .iter()
                .fold(ResolutionCompletion::Complete, |completion, answer| {
                    completion.combine(answer.resolution.completion())
                }),
            SelectedResolutionLocated::Missing => ResolutionCompletion::Complete,
        };
        note_rust_point_work("search_answers", session);
        // `finish` re-reads the analysis generation and the selection's change
        // stamp. Both are constant-time, so this is one step. It used to
        // charge one step per selected mount, which made a point request's
        // budget depend on inventory the request never read: R2.3 measured it
        // at one third of the charged work at 2,048 unrelated mounts.
        if !session.scope_step() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        note_rust_point_work("search_final_authority", session);
        ready.finish(attempt, &completion, cancellation)
    }

    /// Resolve and project one Rust reference through the demand provider.
    ///
    /// The difference from the eager twin above is exactly three things: the
    /// request starts from a context with no root bridge, the lexical source is
    /// the closed-relation source over the ordinary composite, and each
    /// reference is resolved by the scheduler, which discovers and closes only
    /// the endpoint relations that reference actually pauses on. Everything
    /// after the answer -- projection, definition units, completion, final
    /// authority -- is the same code the eager route runs.
    ///
    /// `point_metrics` stays fresh: batch metrics describe one eager batch
    /// driver, and a demand answer is composed from per-endpoint relations that
    /// no single batch summarises. The production point path already drops
    /// them (`analyzer/rust/native_points.rs`).
    #[allow(clippy::too_many_arguments)]
    fn resolve_rust_reference_demand_projection_in_session<T>(
        self,
        prepared: &RustCallerDemand,
        contexts: SelectedResolutionContextSet,
        locators: &[&SelectedSemanticLocator],
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        session: &ResolutionSession,
        mut project: impl FnMut(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            &FactResolutionAnswer,
            &ReadySelectedResolution<'_, '_>,
            SelectedMountTable<'_, '_>,
            &ResolutionSession,
            &CancellationToken,
        ) -> Result<SelectedResolutionOperationOutcome<T>>,
    ) -> Result<SelectedResolutionOperationOutcome<LocatedRustReferenceAnswers<T>>> {
        let cancellation = session.cancellation().unwrap_or(cancellation);
        if !self.ensure_selected_rust_inputs_in_session(cancellation, session)? {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        note_rust_point_work("search_entry_inputs", session);
        let context_timing = crate::profiling::scope("rust_caller::prepare_context");
        let context = match self.prepare_context_in_session(
            contexts,
            cancellation,
            context_metrics,
            session,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        drop(context_timing);
        note_rust_point_work("search_validate_mounts", session);
        let mut ready = self.ready;
        let attempts = {
            // The crates that compile the caller bound the mounts this request
            // may bind into, exactly as the graph route's staged crate does: a
            // reference written in this file resolves inside its crate's
            // dependency closure or nowhere, and a gap in a blob outside that
            // closure was never about this request. The scope is installed
            // where the graph stage installs it -- after the context has been
            // validated and before the blueprint is collected -- so every read
            // the request's own resolution makes is inside it, including the
            // candidate gap boxes the lexical source memoizes per direction.
            // `rust_demand_preparation_for_caller_in_session` already read the
            // caller's crates, so this costs no extra read.
            //
            // The request's crates are fixed for the rest of this block, as a
            // graph stage's crate is, so it keeps the same stage memos: export,
            // placement and membership answers and the publications it has
            // checked. They drop at the end of the block, before `finish`
            // revalidates the whole selection. A reverse confirmation of one
            // candidate blob of tract's `name` checked the same publications
            // about 2,300 times without them (#3761).
            let _crate_memos = ready.crate_stage_memos()?;
            let _scope =
                ready.narrow_forward_scope_to_crates(&prepared.crate_keys, cancellation)?;
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint_timing = crate::profiling::scope("rust_caller::collect_blueprint");
            let blueprint =
                match ready.collect_blueprint_in_session(context, cancellation, session)? {
                    SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                    SelectedFactOperationBlueprintConstruction::Cancelled {
                        cancellation_completion,
                        ..
                    } => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancellation_completion,
                        ));
                    }
                };
            drop(blueprint_timing);
            note_rust_point_work("search_collect_blueprint", session);
            let _resolve_timing = crate::profiling::scope("rust_caller::register_and_resolve");
            if matches!(
                ready.register_context_in_session(&blueprint, cancellation, session)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            note_rust_point_work("search_register_context", session);
            let mut located = Vec::with_capacity(locators.len());
            for locator in locators {
                match ready.lookup_locators_in_session(
                    &persisted_lexical,
                    locator,
                    cancellation,
                    session,
                )? {
                    LocatedSemantics::Found(references) => {
                        located.push((*locator, Some(references)))
                    }
                    LocatedSemantics::Missing => located.push((*locator, None)),
                    LocatedSemantics::Cancelled => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancelled_completion(),
                        ));
                    }
                }
            }
            note_rust_point_work("search_lookup_locators", session);
            // One arena per request. A closed relation is immutable for
            // the request that closed it and is never shared with
            // another request, because the answers it justifies are the
            // ones this request's own prefixes established.
            let arena = RefCell::new(ClosedRelations::default());
            let source =
                ClosedForwardSource::new(&observed_lexical, &persisted_lexical, &arena, session);
            let forward = PreparedForwardSource::new(
                &ready,
                &prepared.demand,
                &observed_lexical,
                &persisted_lexical,
            );
            let mut provider = ForwardProvider::new(&forward, &arena, session, cancellation);
            let attempts = blueprint.with_forward_operation_in_session(
                &source,
                &persisted_lexical,
                &observed_typed,
                cancellation,
                session,
                |operation| {
                    let mut attempts = Vec::with_capacity(located.len());
                    for (locator, references) in &located {
                        let Some(references) = references else {
                            attempts.push(SelectedResolutionLocated::Missing);
                            continue;
                        };
                        let mut answers = Vec::new();
                        for &reference in references {
                            if !session.scope_step() || cancellation.is_cancelled() {
                                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                    cancelled_completion(),
                                ));
                            }
                            let resolution = match operation
                                .resolve_reference_by_demand(reference, &mut provider)?
                            {
                                FactDemandResolution::Ready(resolution) => *resolution,
                                FactDemandResolution::Cancelled(completion) => {
                                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                        completion,
                                    ));
                                }
                            };
                            if !session.observe_cancellation() || cancellation.is_cancelled() {
                                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                    cancelled_completion(),
                                ));
                            }
                            match assemble_rust_reference_answer(
                                &RustReferenceAnswerContext {
                                    ready: &ready,
                                    mounts: SelectedMountTable::new(&ready.inventory),
                                    reference,
                                    locator,
                                    session,
                                    cancellation,
                                },
                                operation,
                                resolution,
                                &mut project,
                            )? {
                                SelectedResolutionOperationOutcome::Native(answer) => {
                                    answers.push(answer)
                                }
                                SelectedResolutionOperationOutcome::Unavailable(reason) => {
                                    return Ok(SelectedResolutionOperationOutcome::Unavailable(
                                        reason,
                                    ));
                                }
                                SelectedResolutionOperationOutcome::Stale(reason) => {
                                    return Ok(SelectedResolutionOperationOutcome::Stale(reason));
                                }
                                SelectedResolutionOperationOutcome::Cancelled(completion) => {
                                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                        completion,
                                    ));
                                }
                            }
                        }
                        attempts.push(SelectedResolutionLocated::Found(answers));
                    }
                    Ok(SelectedResolutionOperationOutcome::Native(attempts))
                },
            )?;
            match attempts {
                SelectedResolutionOperationOutcome::Native(attempts) => attempts,
                SelectedResolutionOperationOutcome::Unavailable(reason) => {
                    return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
                }
                SelectedResolutionOperationOutcome::Stale(reason) => {
                    return Ok(SelectedResolutionOperationOutcome::Stale(reason));
                }
                SelectedResolutionOperationOutcome::Cancelled(completion) => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
                }
            }
        };
        let completion = attempts.iter().fold(
            ResolutionCompletion::Complete,
            |completion, attempt| match attempt {
                SelectedResolutionLocated::Found(answers) => {
                    answers.iter().fold(completion, |completion, answer| {
                        completion.combine(answer.resolution.completion())
                    })
                }
                SelectedResolutionLocated::Missing => completion,
            },
        );
        note_rust_point_work("search_answers", session);
        if !session.scope_step() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        note_rust_point_work("search_final_authority", session);
        ready.finish(attempts, &completion, cancellation)
    }

    pub(crate) fn references_to_selected_definition(
        self,
        context: SelectedResolutionContextSet,
        maximum_batch_size: usize,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        reverse_metrics: &mut FactReverseResolutionMetrics,
    ) -> Result<
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<SelectedReferenceSearchAnswer>,
        >,
    > {
        self.references_to_selected_definition_root(
            context,
            maximum_batch_size,
            SelectedDefinitionRoot::Locator(locator),
            cancellation,
            context_metrics,
            reverse_metrics,
        )
    }

    pub(crate) fn references_to_rust_definition(
        self,
        context: SelectedResolutionContextSet,
        maximum_batch_size: usize,
        target: &CodeUnit,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        reverse_metrics: &mut FactReverseResolutionMetrics,
    ) -> Result<
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<SelectedReferenceSearchAnswer>,
        >,
    > {
        let definition = match self.locate_rust_definition(target, cancellation)? {
            SelectedRustDefinitionSemanticOutcome::Found(definition) => definition,
            SelectedRustDefinitionSemanticOutcome::Missing => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingDefinitionUnit {
                        storage_language: "rust".to_owned(),
                        persisted_relative_path: crate::path_utils::rel_path_string(
                            target.source(),
                        ),
                    },
                ));
            }
            SelectedRustDefinitionSemanticOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        self.references_to_selected_definition_root(
            context,
            maximum_batch_size,
            SelectedDefinitionRoot::RustSemantic {
                definition,
                target_path: crate::path_utils::rel_path_string(target.source()),
            },
            cancellation,
            context_metrics,
            reverse_metrics,
        )
    }

    fn references_to_selected_definition_root(
        self,
        context: SelectedResolutionContextSet,
        maximum_batch_size: usize,
        root: SelectedDefinitionRoot<'_>,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        reverse_metrics: &mut FactReverseResolutionMetrics,
    ) -> Result<
        SelectedResolutionOperationOutcome<
            SelectedResolutionLocated<SelectedReferenceSearchAnswer>,
        >,
    > {
        let context = match self.prepare_context(context, cancellation, context_metrics)? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        if matches!(&root, SelectedDefinitionRoot::RustSemantic { .. })
            && !self.ensure_selected_rust_inputs(cancellation)?
        {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        let mut ready = self.ready;
        let attempt = {
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    contextual_reverse_inventory_completion,
                } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancellation_completion.combine(&contextual_reverse_inventory_completion),
                    ));
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    blueprint
                        .contextual_reverse_inventory_completion()
                        .combine(&cancelled_completion()),
                ));
            }
            let located = match &root {
                SelectedDefinitionRoot::Locator(locator) => {
                    ready.lookup_locator(&persisted_lexical, locator, cancellation)?
                }
                SelectedDefinitionRoot::RustSemantic { definition, .. } => {
                    LocatedSemantic::Found(*definition)
                }
            };
            match located {
                LocatedSemantic::Found(definition) => {
                    let answer = match &root {
                        // These contexts already contain their selected root relations.
                        // Rust's demand closure derives additional crate routes and must
                        // not replace another language's published context authority.
                        SelectedDefinitionRoot::Locator(_) => blueprint.references_to(
                            &observed_lexical,
                            &persisted_lexical,
                            &observed_typed,
                            maximum_batch_size,
                            definition,
                            cancellation,
                            reverse_metrics,
                        )?,
                        SelectedDefinitionRoot::RustSemantic { .. } => ready
                            .with_rust_workspace_fact_operation(
                                &blueprint,
                                &observed_lexical,
                                &observed_typed,
                                cancellation,
                                |facts| {
                                    facts.references_to_with_metrics(
                                        maximum_batch_size,
                                        definition,
                                        blueprint.contextual_reverse_inventory_completion(),
                                        reverse_metrics,
                                    )
                                },
                            )?,
                    };
                    let Some(mut source_sites) = selected_reference_source_sites(
                        &observed_lexical,
                        SelectedMountTable::new(&ready.inventory),
                        ready.project.root(),
                        &answer,
                        cancellation,
                    )?
                    else {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            answer.completion().combine(&cancelled_completion()),
                        ));
                    };
                    if let SelectedDefinitionRoot::RustSemantic { target_path, .. } = &root {
                        match project_rust_reference_owners(
                            &ready,
                            SelectedMountTable::new(&ready.inventory),
                            &mut source_sites,
                            cancellation,
                        )? {
                            SelectedRustReferenceOwnerProjection::Complete => {}
                            SelectedRustReferenceOwnerProjection::Unavailable => {
                                return Ok(SelectedResolutionOperationOutcome::Unavailable(
                                    SelectedResolutionUnavailable::MissingDefinitionUnit {
                                        storage_language: "rust".to_owned(),
                                        persisted_relative_path: target_path.clone(),
                                    },
                                ));
                            }
                            SelectedRustReferenceOwnerProjection::Cancelled => {
                                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                    answer.completion().combine(&cancelled_completion()),
                                ));
                            }
                        }
                    }
                    SelectedResolutionLocated::Found(SelectedReferenceSearchAnswer {
                        answer,
                        source_sites,
                    })
                }
                LocatedSemantic::Missing => SelectedResolutionLocated::Missing,
                LocatedSemantic::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        blueprint
                            .contextual_reverse_inventory_completion()
                            .combine(&cancelled_completion()),
                    ));
                }
            }
        };
        let completion = match &attempt {
            SelectedResolutionLocated::Found(answer) => answer.completion().clone(),
            SelectedResolutionLocated::Missing => ResolutionCompletion::Complete,
        };
        ready.finish(attempt, &completion, cancellation)
    }

    pub(crate) fn stage_selected_reference_batches<S>(
        self,
        context: SelectedResolutionContextSet,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        mut stager: S,
    ) -> Result<SelectedResolutionOperationOutcome<S::Published>>
    where
        S: SelectedResolutionBroadStager,
    {
        let context = match self.prepare_context(context, cancellation, context_metrics)? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        let mut ready = self.ready;
        let summary = {
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancellation_completion,
                    ));
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            blueprint.stage_all_reference_batches(
                &observed_lexical,
                &persisted_lexical,
                &observed_typed,
                maximum_batch_size,
                cancellation,
                &mut |batch| stager.stage(batch),
            )?
        };
        let completion = summary
            .completion()
            .combine(summary.reference_enumeration_completion());
        match ready.finish(summary, &completion, cancellation)? {
            SelectedResolutionOperationOutcome::Native(summary) => {
                if cancellation.is_cancelled() {
                    Ok(SelectedResolutionOperationOutcome::Cancelled(
                        completion.combine(&cancelled_completion()),
                    ))
                } else {
                    Ok(SelectedResolutionOperationOutcome::Native(
                        stager.publish(summary)?,
                    ))
                }
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                Ok(SelectedResolutionOperationOutcome::Unavailable(reason))
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                Ok(SelectedResolutionOperationOutcome::Stale(reason))
            }
            SelectedResolutionOperationOutcome::Cancelled(completion) => {
                Ok(SelectedResolutionOperationOutcome::Cancelled(completion))
            }
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Resolve the positioned Type prefixes against an anchored-only selected
    /// context. Bare references are deliberately absent from this blueprint;
    /// only their native lexical prefix references are evaluated here.
    fn resolve_rust_prefixes_preliminary(
        &self,
        context: SelectedResolutionContextSet,
        halves: &[SelectedRootPathHalf],
        cancellation: &CancellationToken,
    ) -> Result<Option<RustPrefixResolutionBatch>> {
        let prefixes = halves
            .iter()
            .filter_map(rust_qualified_prefix)
            .collect::<Vec<_>>();
        if prefixes.is_empty() {
            return Ok(Some(Vec::new().into_boxed_slice()));
        }
        let Some(blueprint) = self.prepare_prefix_blueprint(context, cancellation)? else {
            return Ok(None);
        };
        let persisted_lexical = self.ready.lexical_source();
        let persisted_typed = self.ready.typed_source();
        let observed_lexical = SeamProfiled::observing(&persisted_lexical);
        let observed_typed = SeamProfiled::observing(&persisted_typed);
        let resolutions = resolve_rust_type_prefixes(
            &blueprint,
            &observed_lexical,
            &persisted_lexical,
            &observed_typed,
            &prefixes,
            cancellation,
        )?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(resolutions)
    }

    /// Prepare one query-owned native context for positioned prefix lookup.
    /// Language-specific callers classify the resulting declarations.
    fn prepare_prefix_blueprint(
        &self,
        context: SelectedResolutionContextSet,
        cancellation: &CancellationToken,
    ) -> Result<Option<SelectedFactOperationBlueprint>> {
        let context_metrics = SelectedResolutionContextMetrics;
        let context = match self.prepare_context(context, cancellation, &context_metrics)? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => return Ok(None),
        };
        let blueprint = match self.ready.collect_blueprint(context, cancellation)? {
            SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
            SelectedFactOperationBlueprintConstruction::Cancelled { .. } => return Ok(None),
        };
        if matches!(
            self.ready.register_context(&blueprint, cancellation)?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Ok(None);
        }
        Ok(Some(blueprint))
    }

    fn prepare_context(
        &self,
        context: SelectedResolutionContextSet,
        cancellation: &CancellationToken,
        metrics: &SelectedResolutionContextMetrics,
    ) -> Result<SelectedResolutionContextValidationOutcome> {
        metrics.assert_fresh();
        context.validate_exact_mounts(
            self.mount_table().mount_count(),
            &selected_mount_lookup(self.mount_table()),
            cancellation,
        )
    }

    fn prepare_context_in_session(
        &self,
        context: SelectedResolutionContextSet,
        cancellation: &CancellationToken,
        metrics: &SelectedResolutionContextMetrics,
        session: &ResolutionSession,
    ) -> Result<SelectedResolutionContextValidationOutcome> {
        metrics.assert_fresh();
        context.validate_exact_mounts_in_session(
            self.mount_table().mount_count(),
            &selected_mount_lookup(self.mount_table()),
            cancellation,
            session,
        )
    }
}

impl ReadySelectedResolution<'_, '_> {
    /// Compile and publish one descriptor at a time. Request metadata remains
    /// separate from token-specific candidate authority and reverse evidence.
    fn publish_context_paths(
        &self,
        context: SelectedResolutionContextInputs,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<crate::analyzer::resolution::SelectedContextPathPublicationOutcome> {
        use crate::analyzer::resolution::{
            SelectedContextPathPublication, SelectedContextPathPublicationOutcome,
            compile_selected_root_bridge,
        };
        #[cfg(test)]
        let work_before = tests::context_publication_work(session);
        let (
            bridges,
            completion,
            declaration_access_source,
            context_owned_gap_identities,
            identities,
            package_bridges,
            go_import_bindings,
        ) = context.into_parts();
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return Err(StoreError::new(
                "selected root inventory completion contains operation cancellation",
            ));
        }
        let mut shared = BTreeSet::new();
        let mut local = BTreeSet::new();
        // Only descriptor references live until this one publication ends.
        // Compare full derivations, including completion, before SQL dedup.
        let mut derivations = HashMap::default();
        let names = self.shared_names();
        let token = super::resolution_stage::SelectedResolutionStage::new(&self.inventory)
            .publish_context_paths(cancellation, |writer| {
                for bridge in bridges.iter() {
                    let Some(projected) = compile_selected_root_bridge(
                        &identities, bridge, &names, cancellation, session,
                    )? else {
                        return Ok(false);
                    };
                    let paths = projected.lexical.paths();
                    assert_eq!(paths.len(), 1, "one context descriptor produces one path");
                    let (path_id, path) = &paths[0];
                    let candidate = CandidatePathIdentity::new(projected.lexical.fragment(), *path_id);
                    if let Some(previous) = derivations.insert(candidate, bridge)
                        && previous != bridge {
                            return Err(StoreError::new(format!(
                                "selected context has conflicting derivations for candidate path {candidate:?}: previous={previous:?}, current={bridge:?}"
                            )));
                        }
                    local.insert(projected.local_anchor);
                    for (_, recipe) in &projected.recipes {
                        shared.insert(recipe.identity(&names));
                    }
                    if !writer.insert(candidate, path)? {
                        return Ok(false);
                    }
                }
                let mut package_derivations = HashMap::default();
                for bridge in &package_bridges {
                    let Some((candidate, path)) = bridge.compile(&identities, cancellation, session) else {
                        return Ok(false);
                    };
                    if let Some(previous) = package_derivations.insert(candidate, bridge)
                        && previous != bridge {
                            return Err(StoreError::new(format!(
                                "selected package context has conflicting derivations for {candidate:?}: previous={previous:?}, current={bridge:?}"
                            )));
                        }
                    shared.extend(bridge.shared_identities());
                    if !writer.insert(candidate, &path)? {
                        return Ok(false);
                    }
                }
                let mut go_import_derivations = HashMap::default();
                for bridge in &go_import_bindings {
                    let Some((candidate, path)) = bridge.compile(&identities, cancellation, session) else {
                        return Ok(false);
                    };
                    if let Some(previous) = go_import_derivations.insert(candidate, bridge)
                        && previous != bridge {
                            return Err(StoreError::new(format!(
                                "selected Go import context has conflicting derivations for {candidate:?}: previous={previous:?}, current={bridge:?}"
                            )));
                        }
                    shared.extend(bridge.shared_identities());
                    if !writer.insert(candidate, &path)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            })?;
        let Some(token) = token else {
            return Ok(SelectedContextPathPublicationOutcome::Cancelled {
                contextual_reverse_inventory_completion: completion,
            });
        };
        #[cfg(test)]
        if let Some(work_before) = work_before {
            let incomplete_evidence = match &completion {
                ResolutionCompletion::Complete => 0,
                ResolutionCompletion::Incomplete(reasons) => reasons.iter().count(),
            };
            eprintln!(
                "context publication work: derivations={}, paths={}, shared={}, incomplete_evidence={}, completion={completion:?}, before={work_before:?}, after={:?}",
                bridges.len(),
                derivations.len(),
                shared.len(),
                incomplete_evidence,
                tests::context_publication_work(session)
                    .expect("scoped context observation remains enabled"),
            );
        }
        Ok(SelectedContextPathPublicationOutcome::Ready(
            SelectedContextPathPublication {
                token,
                contextual_reverse_inventory_completion: completion,
                declaration_access_source,
                context_owned_gap_identities,
                identities: identities.clone(),
                shared_semantic_identities: shared.into_iter().collect(),
                fragment_local_semantic_identities: local.into_iter().collect(),
            },
        ))
    }

    fn collect_blueprint(
        &self,
        context: SelectedResolutionContextInputs,
        cancellation: &CancellationToken,
    ) -> Result<SelectedFactOperationBlueprintConstruction> {
        self.collect_blueprint_in_session(context, cancellation, &ResolutionSession::unbounded())
    }

    fn collect_blueprint_in_session(
        &self,
        context: SelectedResolutionContextInputs,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<SelectedFactOperationBlueprintConstruction> {
        use crate::analyzer::resolution::SelectedContextPathPublicationOutcome;
        Ok(
            match self.publish_context_paths(context, cancellation, session)? {
                SelectedContextPathPublicationOutcome::Ready(publication) => {
                    SelectedFactOperationBlueprintConstruction::Ready(
                        SelectedFactOperationBlueprint::from_publication(publication),
                    )
                }
                SelectedContextPathPublicationOutcome::Cancelled {
                    contextual_reverse_inventory_completion,
                } => SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion: ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::Cancelled,
                    ]),
                    contextual_reverse_inventory_completion,
                },
            },
        )
    }

    /// Check every context anchor against the selection and against the blob
    /// that owns it, before the context registers anything.
    ///
    /// An anchor used to be translated here as well: its blob's whole identity
    /// catalog was walked into the rebaser so that the anchor's storage-local
    /// key could be read back out of it and registered again. The anchor's
    /// runtime ID now names its own mount, and its key is the position it
    /// occupies in that mount's interior identity catalog, so there is nothing
    /// to translate and nothing to register. The check is still worth its
    /// read: an anchor its blob does not own would name no rows, and the
    /// answer would be silently short rather than reported.
    fn validate_context_local_semantic_anchors(
        &self,
        persisted: &SelectedResolutionLexicalSource<'_, '_>,
        blueprint: &SelectedFactOperationBlueprint,
        cancellation: &CancellationToken,
    ) -> Result<Option<()>> {
        let anchors = blueprint.fragment_local_semantic_identities();
        let Some(runtimes) = persisted.local_semantics_for_identities(anchors, cancellation)?
        else {
            return Ok(None);
        };
        for (&(fragment, identity), runtime) in anchors.iter().zip(runtimes) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(runtime) = runtime else {
                return Err(StoreError::new(format!(
                    "selected context anchor identity is not in its blob's catalog: \
                     fragment={fragment}, identity={identity:?}"
                )));
            };
            let registered = self
                .inventory
                .mount_rebaser()
                .borrow()
                .registered_semantic_provenance(runtime);
            match registered {
                Some(SelectedSemanticProvenance::FragmentLocal(provenance)) => {
                    if provenance.mount().fragment() != fragment
                        || provenance.identity() != identity
                    {
                        return Err(StoreError::new(format!(
                            "selected context anchor {runtime} has conflicting provenance"
                        )));
                    }
                    continue;
                }
                Some(SelectedSemanticProvenance::Stage(provenance)) => {
                    if provenance.mount().fragment() != fragment
                        || provenance.identity() != identity
                    {
                        return Err(StoreError::new(format!(
                            "selected context anchor {runtime} has conflicting stage provenance"
                        )));
                    }
                    continue;
                }
                Some(SelectedSemanticProvenance::Shared(_)) => {
                    return Err(StoreError::new(format!(
                        "selected context anchor {runtime} was registered as Shared"
                    )));
                }
                None => {}
            }
            if self
                .inventory
                .mount_rebaser()
                .borrow()
                .mount_for_fragment(fragment)
                .is_none()
            {
                return Err(StoreError::new(format!(
                    "selected context anchor {runtime} names an unknown selected mount"
                )));
            }
            let Some(provenance) = persisted.semantic_provenance(runtime, cancellation)? else {
                return Ok(None);
            };
            // A persisted anchor decodes to its blob's catalog. An anchor a
            // staged mount minted (an `include!`-spliced file's lookups are
            // lowered in its host's stage) decodes to that mount's stage
            // catalog, as the registered arm above accepts.
            let (mount, decoded) = match provenance {
                SelectedSemanticProvenance::FragmentLocal(provenance) => {
                    (provenance.mount(), provenance.identity())
                }
                SelectedSemanticProvenance::Stage(provenance) => {
                    (provenance.mount(), provenance.identity())
                }
                SelectedSemanticProvenance::Shared(_) => {
                    return Err(StoreError::new(format!(
                        "selected context anchor {identity:?} for fragment {fragment} decodes to a shared identity"
                    )));
                }
            };
            if mount.fragment() != fragment || decoded != identity {
                return Err(StoreError::new(format!(
                    "selected context anchor {identity:?} for fragment {fragment} decodes to {decoded:?} in {mount:?}"
                )));
            }
        }
        Ok(Some(()))
    }

    fn register_context(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        cancellation: &CancellationToken,
    ) -> Result<ContextRegistrationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        // Anchor translation registers each named mount's identity catalog
        // with the live rebaser, so it must finish before the staged clone is
        // taken or the clone would not carry those keys.
        let persisted = self.lexical_source();
        if self
            .validate_context_local_semantic_anchors(&persisted, blueprint, cancellation)?
            .is_none()
        {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        let mut staged = self.inventory.mount_rebaser().borrow().clone();
        if cancellation.is_cancelled() {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        for &identity in blueprint.shared_semantic_identities() {
            if cancellation.is_cancelled() {
                return Ok(ContextRegistrationOutcome::Cancelled);
            }
            staged.register_shared_semantic(identity);
        }
        for &reason in blueprint.context_owned_gap_identities() {
            if cancellation.is_cancelled() {
                return Ok(ContextRegistrationOutcome::Cancelled);
            }
            staged.register_context_owned_semantic(reason, &self.inventory.shared_names());
        }
        for &node in blueprint.boundary_nodes() {
            if cancellation.is_cancelled() {
                return Ok(ContextRegistrationOutcome::Cancelled);
            }
            staged.register_context_boundary(node);
        }
        if cancellation.is_cancelled() {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        *self.inventory.mount_rebaser().borrow_mut() = staged;
        #[cfg(test)]
        {
            let rebaser = self.inventory.mount_rebaser().borrow();
            let snapshot = SelectedResolutionBoundarySnapshotForTest {
                universal_root: rebaser
                    .node_provenance(BindingNodeId::universal_root())
                    .expect("the selected rebaser retains the universal root"),
                boundaries: blueprint
                    .boundary_nodes()
                    .iter()
                    .copied()
                    .map(|node| {
                        (
                            node,
                            rebaser
                                .node_provenance(node)
                                .expect("every validated Java boundary is registered"),
                        )
                    })
                    .collect(),
                callable_static_import_boundaries: blueprint
                    .callable_static_import_boundaries_for_test()
                    .into(),
            };
            SELECTED_RESOLUTION_BOUNDARY_SNAPSHOT
                .with(|observed| *observed.borrow_mut() = Some(snapshot));
        }
        Ok(ContextRegistrationOutcome::Ready)
    }

    fn register_context_in_session(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<ContextRegistrationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        // The selected inventory has already registered every identity read
        // while collecting the context. Cloning that complete, mount-sized
        // rebaser just to add the small contextual overlay made point
        // resolution budget depend on unrelated selected mounts. Contextual
        // anchors already present in that inventory are free; only persisted
        // anchor keys that still need hydration consume bounded work.
        let persisted = self.lexical_source();
        if self
            .validate_context_local_semantic_anchors(&persisted, blueprint, cancellation)?
            .is_none()
        {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        // Only the registrations this phase still performs are charged: the
        // persisted anchors need no key translation and no registration now
        // that their runtime IDs name their own mounts.
        let registration_work = blueprint
            .shared_semantic_identities()
            .len()
            .checked_add(blueprint.boundary_nodes().len())
            .and_then(|count| count.checked_add(blueprint.context_owned_gap_identities().len()))
            .expect("selected context registration work must fit usize");
        if !(0..registration_work).all(|_| session.scope_step()) {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        let mut rebaser = self.inventory.mount_rebaser().borrow_mut();
        for &identity in blueprint.shared_semantic_identities() {
            rebaser.register_shared_semantic(identity);
        }
        let names = self.inventory.shared_names();
        for &reason in blueprint.context_owned_gap_identities() {
            rebaser.register_context_owned_semantic(reason, &names);
        }
        for &node in blueprint.boundary_nodes() {
            rebaser.register_context_boundary(node);
        }
        Ok(ContextRegistrationOutcome::Ready)
    }

    fn lookup_locator(
        &self,
        persisted: &SelectedResolutionLexicalSource<'_, '_>,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> Result<LocatedSemantic> {
        match self.lookup_locators_in_session(
            persisted,
            locator,
            cancellation,
            &ResolutionSession::unbounded(),
        )? {
            LocatedSemantics::Found(mut semantics) => {
                if semantics.len() != 1 {
                    return Err(StoreError::new(format!(
                        "singular semantic operation requires one source site: {locator:?}, alternatives {semantics:?}"
                    )));
                }
                Ok(LocatedSemantic::Found(
                    semantics.pop().expect("one semantic"),
                ))
            }
            LocatedSemantics::Missing => Ok(LocatedSemantic::Missing),
            LocatedSemantics::Cancelled => Ok(LocatedSemantic::Cancelled),
        }
    }

    fn lookup_java_definition_locator(
        &self,
        persisted: &SelectedResolutionLexicalSource<'_, '_>,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> Result<LocatedSemantic> {
        let sites = match persisted.lookup_semantic_sites(
            locator,
            cancellation,
            &ResolutionSession::unbounded(),
        )? {
            SelectedSemanticLookupOutcome::Found(sites) => sites,
            SelectedSemanticLookupOutcome::Missing => return Ok(LocatedSemantic::Missing),
            SelectedSemanticLookupOutcome::Cancelled => return Ok(LocatedSemantic::Cancelled),
        };
        if sites.len() == 1 {
            return Ok(LocatedSemantic::Found(sites[0].semantic()));
        }

        // A `new Type()` name has distinct source operations for its type and
        // constructor. Cursor definition lookup at the type token selects the
        // Type namespace; constructor applicability remains a separate query.
        let mut type_sites = sites
            .iter()
            .filter(|site| site.namespace() == ResolutionNamespace::Type);
        let Some(type_site) = type_sites.next() else {
            return Err(StoreError::new(format!(
                "singular Java definition lookup has no unique type operation: {locator:?}, alternatives {sites:?}"
            )));
        };
        if type_sites.next().is_some() {
            return Err(StoreError::new(format!(
                "singular Java definition lookup has multiple type operations: {locator:?}, alternatives {sites:?}"
            )));
        }
        Ok(LocatedSemantic::Found(type_site.semantic()))
    }

    fn lookup_locators_in_session(
        &self,
        persisted: &SelectedResolutionLexicalSource<'_, '_>,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<LocatedSemantics> {
        if !session.scope_step() || cancellation.is_cancelled() {
            return Ok(LocatedSemantics::Cancelled);
        }
        Ok(
            match persisted.lookup_semantic_sites(locator, cancellation, session)? {
                SelectedSemanticLookupOutcome::Found(sites) => {
                    LocatedSemantics::Found(sites.into_iter().map(|site| site.semantic()).collect())
                }
                SelectedSemanticLookupOutcome::Missing => LocatedSemantics::Missing,
                SelectedSemanticLookupOutcome::Cancelled => LocatedSemantics::Cancelled,
            },
        )
    }

    fn lookup_locator_in_session(
        &self,
        persisted: &SelectedResolutionLexicalSource<'_, '_>,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<LocatedSemantic> {
        if !session.scope_step() {
            return Ok(LocatedSemantic::Cancelled);
        }
        self.lookup_locator(persisted, locator, cancellation)
    }

    fn finish<T>(
        &mut self,
        value: T,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        if cancellation.is_cancelled()
            || completion.contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        let current_generation = self.project.analysis_generation();
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        if current_generation != self.analysis_generation {
            return Ok(SelectedResolutionOperationOutcome::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: self.analysis_generation,
                    actual: current_generation,
                },
            ));
        }
        if let Some(publication) = self.go_publication.borrow().as_ref() {
            match self
                .store
                .go_context_head_status(publication, cancellation)?
            {
                super::GoContextHeadStatus::Current => {}
                super::GoContextHeadStatus::Withdrawn => {
                    return Ok(SelectedResolutionOperationOutcome::Stale(
                        SelectedResolutionStale::NativeContextPublication {
                            storage_language: "go".to_owned(),
                        },
                    ));
                }
                super::GoContextHeadStatus::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        completion.combine(&cancelled_completion()),
                    ));
                }
            }
        }
        let revalidation = self.inventory.revalidate(cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        match revalidation {
            SelectedResolutionRevalidationOutcome::Current => {}
            SelectedResolutionRevalidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    completion.combine(&cancelled_completion()),
                ));
            }
            SelectedResolutionRevalidationOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
        }
        let current_generation = self.project.analysis_generation();
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        if current_generation != self.analysis_generation {
            return Ok(SelectedResolutionOperationOutcome::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: self.analysis_generation,
                    actual: current_generation,
                },
            ));
        }
        match validate_content_mount_authority(self.project, &self.content_mounts, cancellation) {
            SelectedOverlayAuthorityValidation::Ready => {}
            SelectedOverlayAuthorityValidation::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
            SelectedOverlayAuthorityValidation::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedOverlayAuthorityValidation::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    completion.combine(&cancelled_completion()),
                ));
            }
        }
        Ok(SelectedResolutionOperationOutcome::Native(value))
    }
}

fn cancelled_completion() -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled])
}

fn validate_selected_content_mounts(
    inventory: &SelectedResolutionMountInventory<'_>,
    cancellation: &CancellationToken,
) -> Result<SelectedContentValidationOutcome> {
    // Every replacement must already be an ordinary published content mount.
    // Removal masks contribute no selected mount or alternate fact authority.
    for mask in inventory.overlay_masks()? {
        if cancellation.is_cancelled() {
            return Ok(SelectedContentValidationOutcome::Cancelled);
        }
        let content = inventory
            .mount_record_for_path(mask.storage_language(), mask.persisted_relative_path())?
            .is_some_and(|mount| mount.file_version_id().is_none());
        match mask.intent() {
            SelectedResolutionOverlayIntent::Replacement => {
                if !content {
                    return Ok(SelectedContentValidationOutcome::Unavailable(
                        SelectedResolutionUnavailable::MissingTransientReplacement {
                            storage_language: mask.storage_language().to_owned(),
                            persisted_relative_path: mask.persisted_relative_path().to_owned(),
                        },
                    ));
                }
                assert_eq!(mask.expected_transient_replacement_count(), 1);
            }
            SelectedResolutionOverlayIntent::Removal => {
                assert!(
                    !content,
                    "removal masks cannot own published replacement content"
                );
                assert_eq!(mask.expected_transient_replacement_count(), 0);
            }
        }
    }
    if cancellation.is_cancelled() {
        return Ok(SelectedContentValidationOutcome::Cancelled);
    }
    Ok(SelectedContentValidationOutcome::Ready)
}

pub(super) struct TransientRustContextRows {
    references: Vec<SelectedTypedRow<LoweredRustReferenceContext>>,
    declarations: Vec<SelectedTypedRow<LoweredRustDeclarationAuthority>>,
}

impl TransientRustContextRows {
    pub(super) fn into_parts(
        self,
    ) -> (
        Vec<SelectedTypedRow<LoweredRustReferenceContext>>,
        Vec<SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) {
        (self.references, self.declarations)
    }
}

pub(super) fn lower_rust_context_rows(
    path: &str,
    reference_contexts: &BTreeMap<ResolutionSiteId, RustReferenceContextSource>,
    declaration_contexts: &BTreeMap<ResolutionSiteId, RustDeclarationContextSource>,
    native_declaration_sources: &[(ResolutionSiteId, SourceDeclarationId)],
    declaration_properties: &[RustDeclarationPropertyFact],
    final_lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
) -> Result<Option<TransientRustContextRows>> {
    let fragment = final_lowered.lexical().fragment();
    let mut rust_reference_context_rows = Vec::new();
    let mut rust_declaration_authority_rows = Vec::new();
    for site in final_lowered
        .lexical()
        .semantics()
        .iter()
        .filter(|site| site.role() == LoweredSemanticRole::Reference)
    {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let source = reference_contexts
            .get(&site.site())
            .cloned()
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "transient Rust reference has no exact source context: site={}, semantic={:?}, path={:?}",
                    site.site(),
                    site.semantic(),
                    path,
                ))
            })?;
        rust_reference_context_rows.push(SelectedTypedRow::new(
            fragment,
            LoweredRustReferenceContext::new(
                site.semantic(),
                source.source_site(),
                source.source_occurrence(),
                source.module_context(),
                source.module_declaration(),
            )
            .with_cfg_condition(source.cfg_condition().clone()),
        ));
    }

    let mut bridges = BTreeMap::new();
    for &(source_site, declaration) in native_declaration_sources {
        if bridges.insert(source_site, declaration).is_some() {
            return Err(StoreError::corrupt(format!(
                "Rust source site {source_site} has duplicate native declaration bridges"
            )));
        }
    }
    let mut properties = HashMap::default();
    for property in declaration_properties {
        if properties
            .insert(property.declaration, property.visibility.clone())
            .is_some()
        {
            return Err(StoreError::corrupt(format!(
                "Rust declaration {} has duplicate property rows",
                property.declaration
            )));
        }
    }
    let authority_properties = bridges
        .into_iter()
        .map(|(site, declaration)| (site, (declaration, properties.get(&declaration).cloned())))
        .collect::<BTreeMap<_, _>>();
    for site in final_lowered
        .lexical()
        .semantics()
        .iter()
        .filter(|site| site.role() == LoweredSemanticRole::Definition)
    {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(context) = declaration_contexts.get(&site.site()) else {
            continue;
        };
        let (declaration, visibility) =
            authority_properties.get(&site.site()).ok_or_else(|| {
                StoreError::corrupt(format!(
                    "transient Rust item context lacks its canonical declaration bridge: site={}",
                    site.site()
                ))
            })?;
        if visibility.is_none() {
            return Err(StoreError::corrupt(format!(
                "transient Rust item context lacks its canonical visibility property: site={}, declaration={declaration}",
                site.site()
            )));
        }
        if context.declaration() != *declaration {
            return Err(StoreError::corrupt(format!(
                "transient Rust declaration context bridge disagrees with property bridge: site={}, context_declaration={}, property_declaration={}",
                site.site(),
                context.declaration(),
                declaration
            )));
        }
        rust_declaration_authority_rows.push(SelectedTypedRow::new(
            fragment,
            LoweredRustDeclarationAuthority::new(
                site.semantic(),
                site.site(),
                *declaration,
                visibility.clone(),
                context.module_context(),
                context.module_declaration(),
            )
            .with_cfg_condition(
                declaration_properties
                    .iter()
                    .find(|property| property.declaration == *declaration)
                    .expect("item declaration has properties")
                    .cfg_condition
                    .clone(),
            )
            .with_activation_reason(
                final_lowered
                    .lexical()
                    .gaps()
                    .iter()
                    .find(|gap| {
                        gap.site() == site.site()
                            && gap.origin()
                                == crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnprovenActivation,
                                )
                    })
                    .map(|gap| gap.reason_semantic()),
            ),
        ));
    }
    Ok(Some(TransientRustContextRows {
        references: rust_reference_context_rows,
        declarations: rust_declaration_authority_rows,
    }))
}

fn selected_macro_capture_digest(
    invocation: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
    input: &brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
    arm: &brokk_bifrost_rust::macro_matcher::MacroArmMatch,
) -> [u8; 32] {
    let mut identity = CanonicalHasher::new(b"bifrost-selected-macro-capture:v1");
    identity.field("invocation", &invocation.get().to_le_bytes());
    identity.field("source", input.source.as_bytes());
    identity.field("start", &(input.start_byte as u64).to_le_bytes());
    identity.field("arm", &(arm.arm_index as u64).to_le_bytes());
    for binding in &arm.bindings {
        use brokk_bifrost_rust::macro_matcher::MacroIdentRole;
        identity.field("binding", binding.name.as_bytes());
        identity.field("fragment", binding.fragment.as_str().as_bytes());
        identity.field("start", &(binding.start_byte as u64).to_le_bytes());
        identity.field("end", &(binding.end_byte as u64).to_le_bytes());
        let role = match binding.ident_role {
            None => "none",
            Some(MacroIdentRole::Type) => "type",
            Some(MacroIdentRole::Value) => "value",
            Some(MacroIdentRole::Pattern) => "pattern",
            Some(MacroIdentRole::Declaration) => "declaration",
            Some(MacroIdentRole::Mixed) => "mixed",
            Some(MacroIdentRole::Unused) => "unused",
            Some(MacroIdentRole::Undetermined) => "undetermined",
        };
        identity.field("role", role.as_bytes());
        for position in &binding.repetition_path {
            identity.field("repeat", &(*position as u64).to_le_bytes());
        }
    }
    identity.finish()
}

#[cfg(test)]
#[path = "resolution_operation_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "resolution_operation_context_tests.rs"]
mod context_path_tests;

#[cfg(test)]
pub(super) use tests::{DenseSelectedMacroFixture, with_dense_selected_macro_fixture};

#[cfg(test)]
pub(crate) use tests::point_latency::heap_pin_bytes;

impl ReadySelectedResolution<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn with_workspace_forward_fact_operation<T>(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let demand = RustDemandPreparation::new(Box::new([]));
        let paths = self.lexical_source();
        let prepared = PreparedForwardSource::new(self, &demand, lexical, &paths);
        let source =
            ClosedForwardSource::new(lexical, &paths, &self.rust_workspace_relations, session);
        let provider = ForwardProvider::new(
            &prepared,
            &self.rust_workspace_relations,
            session,
            cancellation,
        );
        blueprint.with_demand_operation(
            &source,
            &paths,
            lexical,
            typed,
            provider,
            cancellation,
            session,
            run,
        )
    }

    fn with_rust_workspace_fact_operation<T>(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let demand = RustDemandPreparation::new(Box::new([]));
        let session = ResolutionSession::unbounded();
        let paths = self.lexical_source();
        let prepared = PreparedForwardSource::new(self, &demand, lexical, &paths);
        let source =
            ClosedForwardSource::new(lexical, &paths, &self.rust_workspace_relations, &session);
        let provider = ForwardProvider::new(
            &prepared,
            &self.rust_workspace_relations,
            &session,
            cancellation,
        );
        blueprint.with_demand_operation(
            &source,
            &paths,
            lexical,
            typed,
            provider,
            cancellation,
            &session,
            run,
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn rust_crate_point_sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    rust_crate_context::sql_pins()
        .into_iter()
        .chain(rust_demand::rows::sql_pins())
        .collect()
}

pub(super) const RUST_GRAPH_DEFINITIONS_SQL: &str = "SELECT DISTINCT mount.mount_ordinal, site.semantic_key FROM selected_rust_crate_containers AS member CROSS JOIN temp.selected_resolution_mounts AS mount ON mount.blob_id=member.blob_id AND mount.persisted_relative_path=member.rel_path AND mount.storage_language='rust' CROSS JOIN resolution_semantic_sites AS site ON site.blob_id=member.blob_id AND site.semantic_role='definition' CROSS JOIN resolution_definition_unit_crosswalks AS unit ON unit.blob_id=site.blob_id AND unit.definition_semantic_key=site.semantic_key";
