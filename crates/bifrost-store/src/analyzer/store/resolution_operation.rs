//! Whole-operation selected resolution over persisted and transient facts.
//!
//! This owner assembles one immutable native attempt, drops every borrowing
//! source/session, and then revalidates both the retained database inventory
//! and the live overlay generation before authorizing publication. It holds no
//! lease after return: `Current` is authorization at that final boundary, not
//! a long transaction or workspace lock.

mod services;
pub(in crate::analyzer::store) use services::selected_jvm_declaration_owner;
pub use services::{SelectedAnalyzerServices, SelectedModelAuthority};

#[doc(hidden)]
pub mod go_context;
#[doc(hidden)]
pub mod go_named;
pub(crate) use go_named::GoPreparedImportContext;

#[doc(hidden)]
pub use go_named::GoPreparedImportContextOutcome;

#[doc(hidden)]
pub mod go_demand;
use go_demand::GoForwardOperationContext;

#[doc(hidden)]
pub mod go_method_family;
#[doc(hidden)]
pub mod go_receiver_anchor;
#[doc(hidden)]
pub mod go_reverse_rows;
#[doc(hidden)]
pub mod go_same_package;
mod java_access;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod java_reverse_rows;
#[doc(hidden)]
pub mod jvm_context;
#[doc(hidden)]
pub mod jvm_demand;
mod jvm_hierarchy_order;
#[cfg(any(test, feature = "test-support"))]
mod python_demand;
#[cfg(any(test, feature = "test-support"))]
#[path = "resolution_operation/python_demand/lexical.rs"]
pub(crate) mod python_lexical;
#[cfg(any(test, feature = "test-support"))]
mod python_members;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod python_reverse;
#[doc(hidden)]
pub mod source_demand;

#[doc(hidden)]
pub use jvm_context::JvmImportContext;
#[doc(hidden)]
pub use jvm_context::JvmImportContextGap;

#[doc(hidden)]
pub mod native_units;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use native_units::SelectedNativeAssignmentValue;

#[doc(hidden)]
pub use native_units::NativeExternalMemberTarget;
#[doc(hidden)]
pub use native_units::ProjectedNativeMemberContext;
#[doc(hidden)]
pub use native_units::SelectedNativeDefinition;
#[doc(hidden)]
pub use native_units::SelectedNativeDefinitions;
#[doc(hidden)]
pub use native_units::SelectedNativeNamedArgument;
#[doc(hidden)]
pub use native_units::SelectedNativeReferenceTypes;
#[doc(hidden)]
pub use native_units::SelectedNativeReferenceUnits;
#[doc(hidden)]
pub use native_units::SelectedNativeTypes;

pub(super) struct NativeReferenceQuery<'a> {
    context: SelectedResolutionContextSet,
    locator: &'a SelectedSemanticLocator,
    cancellation: &'a CancellationToken,
    context_metrics: &'a mut SelectedResolutionContextMetrics,
    session: &'a ResolutionSession,
    artifacts: Option<&'a mut crate::analyzer::resolution::ForwardCandidateArtifactCache>,
    go_demand: Option<go_named::GoDemandContext>,
    selected_import_gap: Option<(SemanticId, SemanticId)>,
    go_receiver_overlay: Option<crate::analyzer::resolution::GoReceiverSlotTypeOverlay>,
    query_result_slot: Option<SemanticId>,
    point_metrics: Option<&'a mut ResolutionBatchMetrics>,
}

#[doc(hidden)]
pub mod package_context;
use package_context::PackageReferenceReadKey;

#[doc(hidden)]
pub mod rust_crate_access;
pub(crate) use rust_crate_access::RustBlobActivity;

#[doc(hidden)]
pub mod rust_crate_context;
pub(super) mod rust_derive_helpers;
use super::resolution_stage::SelectedResolutionStageOutcome;

use crate::analyzer::resolution::SeamProfiled;

mod context_preparation;
#[doc(hidden)]
pub mod demand;
#[doc(hidden)]
pub mod demand_closure;
#[doc(hidden)]
pub mod graph_stage;
#[doc(hidden)]
pub mod imports;
pub(crate) mod member_access;
mod placement_access;
#[path = "reverse.rs"]
#[doc(hidden)]
pub mod reverse;
#[path = "reverse_candidates.rs"]
#[doc(hidden)]
pub mod reverse_candidates;
#[path = "reverse_nomination.rs"]
#[doc(hidden)]
pub mod reverse_nomination;

pub(crate) use reverse_candidates::REVERSE_CANDIDATE_KEYS_DDL;

#[cfg(any(test, feature = "test-support"))]
pub(crate) use reverse_candidates::REVERSE_CANDIDATE_KEYS_CLEAR_SQL;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use reverse_candidates::REVERSE_CANDIDATE_KEYS_INSERT_SQL;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use reverse_candidates::REVERSE_CANDIDATES_SQL;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use reverse_candidates::{REVERSE_LOOKUP_IDENTITY_ARM_SQL, reverse_candidates_sql};

#[doc(hidden)]
pub mod rust_crate_rows;
#[doc(hidden)]
pub mod rust_demand;
use demand::ClosedForwardSource;
use demand::ClosedRelations;
use demand::DemandProvider;

use rust_demand::forward::ForwardProvider;
use rust_demand::forward::PreparedForwardSource;
use rust_demand::forward::RustDemandPreparation;

#[doc(hidden)]
pub mod rust_forward;
mod rust_prefix;
#[doc(hidden)]
pub mod rust_privacy;
#[doc(hidden)]
pub mod rust_reverse;
#[doc(hidden)]
pub mod rust_reverse_rows;
use rust_prefix::RustPrefixResolutionBatch;

pub(crate) use rust_prefix::resolve_rust_type_prefixes;
pub(crate) use rust_prefix::rust_qualified_prefix;

pub(crate) use rust_reverse_rows::RustReverseConfirmation;

// The planner-statistics pin that shares this builder with the bounded reader
// lives in a test-support module, so the re-export follows that gate.
#[cfg(any(test, feature = "test-support"))]
pub(crate) use rust_privacy::selected_rust_declaration_authority_sql;

pub(crate) use rust_privacy::RustSelectedDeclarationAuthorityFact;
pub(crate) use rust_privacy::read_selected_rust_declaration_authority_with_cancellation;

pub(crate) use rust_reverse::ReferenceOmission;
pub(crate) use rust_reverse::ReferenceResolution;
pub(crate) use rust_reverse::RustReverseRequest;
pub(crate) use rust_reverse::SelectedRustReverseBatchOutcome;
pub(crate) use rust_reverse::SelectedRustReverseQueries;
pub(crate) use rust_reverse::SelectedRustTargetReferences;

use std::cell::OnceCell;
use std::cell::RefCell;

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use std::path::Path;
use std::path::PathBuf;

use std::sync::Arc;

use brokk_bifrost_core::analyzer::Language;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;

use brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;

use brokk_bifrost_core::analyzer::rust_facts;

use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationPropertyFact;
use brokk_bifrost_core::analyzer::rust_facts::RustImportTargetFact;
use brokk_bifrost_core::analyzer::rust_facts::RustSourceContextKind;
use brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts;

use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId;
use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use brokk_bifrost_rust::selected_context::RustSelectedBuildOutcome;
use brokk_bifrost_rust::selected_context::RustSelectedContext;
use brokk_bifrost_rust::selected_context::RustSelectedContextGap;
use brokk_bifrost_rust::selected_context::RustSelectedDeclarationAuthority;
use brokk_bifrost_rust::selected_context::RustSelectedDependencyEdge;
use brokk_bifrost_rust::selected_context::RustSelectedRootBridge;
use brokk_bifrost_rust::selected_context::RustSelectedRootBridgeTopology;
use brokk_bifrost_rust::selected_context::RustSelectedRootRoute;
use brokk_bifrost_rust::selected_context::RustSelectedTargetMembership;

use moka::sync::Cache;

use rusqlite::OptionalExtension;

use crate::CancellationToken;

use crate::analyzer::resolution::lexical_definition::LexicalDefinition;

use crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::SelectedNodeProvenance;

use crate::analyzer::resolution::BatchResolutionFragmentSource;
use crate::analyzer::resolution::BindingFragmentId;
use crate::analyzer::resolution::BindingNodeId;
use crate::analyzer::resolution::BindingNodeKind;
use crate::analyzer::resolution::CandidatePathIdentity;
use crate::analyzer::resolution::DemandClosureDischarges;
use crate::analyzer::resolution::FactDemandResolution;
use crate::analyzer::resolution::FactPageVisitor;
use crate::analyzer::resolution::FactProjectedTypeNodeForm;
use crate::analyzer::resolution::FactReferenceBatchAnswer;
use crate::analyzer::resolution::FactReferenceSiteMetadata;
use crate::analyzer::resolution::FactResolutionAnswer;
use crate::analyzer::resolution::FactResolutionBatchSummary;
use crate::analyzer::resolution::FactReverseResolutionMetrics;
use crate::analyzer::resolution::ForwardOperationArtifactContext;
use crate::analyzer::resolution::LoweredRustDeclarationAuthority;
use crate::analyzer::resolution::LoweredRustReferenceContext;
use crate::analyzer::resolution::LoweredSemanticRole;
use crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH;
use crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH;
use crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH;
use crate::analyzer::resolution::PartialPath;
use crate::analyzer::resolution::ReferenceSearchAnswer;
use crate::analyzer::resolution::ResolutionBatchMetrics;
use crate::analyzer::resolution::ResolutionCompletion;
use crate::analyzer::resolution::ResolutionIncompleteReason;
use crate::analyzer::resolution::ResolutionLocalKey;
use crate::analyzer::resolution::ResolutionLookupSemanticRecipe;
use crate::analyzer::resolution::ResolutionQuery;
use crate::analyzer::resolution::ResolutionSemanticIdentity;
use crate::analyzer::resolution::ResolutionSlotValue;
use crate::analyzer::resolution::RustDeclarationContextSource;
use crate::analyzer::resolution::RustReferenceContextSource;
use crate::analyzer::resolution::SelectedContextIdentities;
use crate::analyzer::resolution::SelectedFactOperationBlueprint;
use crate::analyzer::resolution::SelectedFactOperationBlueprintConstruction;
use crate::analyzer::resolution::SelectedResolutionContextInputs;
use crate::analyzer::resolution::SelectedResolutionContextSet;
use crate::analyzer::resolution::SelectedResolutionContextValidationOutcome;
use crate::analyzer::resolution::SelectedResolutionMountContext;
use crate::analyzer::resolution::SelectedResolutionMountOrdinal;
use crate::analyzer::resolution::SelectedRootBridgeDescriptor;
use crate::analyzer::resolution::SelectedRootPathHalf;
use crate::analyzer::resolution::SelectedSemanticLocator;
use crate::analyzer::resolution::SelectedSemanticMount;
use crate::analyzer::resolution::SelectedSemanticProvenance;
use crate::analyzer::resolution::SelectedTypedFactSource;
use crate::analyzer::resolution::SelectedTypedRow;
use crate::analyzer::resolution::SemanticId;
use crate::analyzer::resolution::TypedFactRequest;
use crate::analyzer::resolution::cancelled_completion;
use crate::analyzer::resolution::classify_selected_root_path_half;
use crate::analyzer::resolution::language_identity_domain;
use crate::analyzer::resolution::visit_selected_root_export_half_pages;
use crate::analyzer::resolution::visit_selected_root_import_half_pages;

use crate::analyzer::CodeUnit;
use crate::analyzer::Project;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;

use crate::hash::HashMap;
use crate::hash::HashSet;

use super::resolution_lexical::BoundaryCandidateReadMemo;
use super::resolution_lexical::SelectedLookupRecipeReadOutcome;
use super::resolution_lexical::SelectedLookupRecipeRequest;
use super::resolution_lexical::SelectedResolutionLexicalSource;
use super::resolution_lexical::SelectedSemanticLookupOutcome;
use super::resolution_lexical::UnconditionalCandidateCache;

use super::resolution_selection::SelectedResolutionContentMountRequest;
use super::resolution_selection::SelectedResolutionLanguage;
use super::resolution_selection::SelectedResolutionMountInventory;
use super::resolution_selection::SelectedResolutionMountInventoryOutcome;
use super::resolution_selection::SelectedResolutionOverlayAuthority;
use super::resolution_selection::SelectedResolutionOverlayIntent;
use super::resolution_selection::SelectedResolutionOverlayMask;
use super::resolution_selection::SelectedResolutionRevalidationOutcome;
use super::resolution_selection::SelectedResolutionStale;
use super::resolution_selection::SelectedResolutionUnavailable;

use super::resolution_typed::SelectedResolutionTypedSource;

use super::selected_definition::SelectedDeclarationDefinition;
use super::selected_definition::SelectedDefinitionSemanticReadOutcome;
use super::selected_definition::SelectedDefinitionUnitReadOutcome;
use super::selected_definition::SelectedLexicalDefinitionReadOutcome;

use super::selected_read_memo::ExactReadMemo;

use super::AnalyzerStore;
use super::Result;
use super::StoreError;
use super::WorkspaceId;
use super::WorkspaceSnapshots;

pub(super) const SELECTED_MACRO_OCCURRENCE_LINES_SQL: &str = "SELECT CAST(entry.key AS INTEGER), json_extract(entry.value, '$[2]') FROM source_occurrence_arenas AS arena, json_each(arena.spans) AS entry WHERE arena.blob_id = ?1";

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static SELECTED_MACRO_OCCURRENCE_LINE_QUERY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reset_selected_macro_occurrence_line_query_count_for_test() {
    SELECTED_MACRO_OCCURRENCE_LINE_QUERY_COUNT.with(|count| count.set(0));
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_macro_occurrence_line_query_count_for_test() -> usize {
    SELECTED_MACRO_OCCURRENCE_LINE_QUERY_COUNT.with(std::cell::Cell::get)
}

/// Project only the compact source identities required by transient Rust
/// reference-context reads. The parsed source facts remain producer-owned;
/// resolution retains no source arena or parallel range extraction.
#[doc(hidden)]
pub fn rust_reference_context_sources(
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

    // Reparsed macro arguments can retain an Embedded reference occurrence at
    // the exact range of a primary AST token, including arguments inside a
    // procedural attribute. That exact alias proves the reference has a
    // source-authored anchor even when no bang-macro invocation encloses it.
    let primary_occurrence_ranges = source_facts
        .occurrences
        .occurrences()
        .iter()
        .filter(|occurrence| occurrence.provenance == SourceOccurrenceProvenance::PrimaryNode)
        .map(|occurrence| (occurrence.range.start_byte, occurrence.range.end_byte))
        .collect::<HashSet<_>>();

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
        let exact_primary_source = reference.provenance == SourceOccurrenceProvenance::Embedded
            && primary_occurrence_ranges
                .contains(&(reference.range.start_byte, reference.range.end_byte));
        if !matches!(
            reference.provenance,
            SourceOccurrenceProvenance::PrimaryNode | SourceOccurrenceProvenance::ExplicitSubspan
        ) && !exact_primary_source
            && !matched_macro_fragment
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
#[doc(hidden)]
pub struct SelectedResolutionOperationInput<'project, 'selection> {
    project: &'project dyn Project,
    analyzer: Option<&'project dyn SelectedAnalyzerServices>,
    analysis_generation: u64,
    workspace_id: &'selection WorkspaceId,
    snapshots: &'selection WorkspaceSnapshots,
    languages: &'selection [SelectedResolutionLanguage],
    overlay_masks: &'selection [SelectedResolutionOverlayMask],
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
}

/// A worker recreates exactly the enclosing query's authority inputs.
/// Owned selection descriptors die with that query; project/analyzer remain borrowed.
#[doc(hidden)]
pub struct CapturedSelectedResolutionInput<'project> {
    project: &'project dyn Project,
    analyzer: Option<&'project dyn SelectedAnalyzerServices>,
    analysis_generation: u64,
    workspace_id: WorkspaceId,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    overlay_masks: Vec<SelectedResolutionOverlayMask>,
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
}

impl<'project> CapturedSelectedResolutionInput<'project> {
    #[doc(hidden)]
    pub fn capture(input: &SelectedResolutionOperationInput<'project, '_>) -> Self {
        Self {
            project: input.project,
            analyzer: input.analyzer,
            analysis_generation: input.analysis_generation,
            workspace_id: input.workspace_id.clone(),
            snapshots: input.snapshots.clone(),
            languages: input.languages.to_vec(),
            overlay_masks: input.overlay_masks.to_vec(),
            content_mounts: input.content_mounts.clone(),
        }
    }

    #[doc(hidden)]
    pub fn input(&self) -> SelectedResolutionOperationInput<'project, '_> {
        SelectedResolutionOperationInput {
            project: self.project,
            analyzer: self.analyzer,
            analysis_generation: self.analysis_generation,
            workspace_id: &self.workspace_id,
            snapshots: &self.snapshots,
            languages: &self.languages,
            overlay_masks: &self.overlay_masks,
            content_mounts: self.content_mounts.clone(),
        }
    }
}

impl<'project, 'selection> SelectedResolutionOperationInput<'project, 'selection> {
    #[doc(hidden)]
    pub fn new(
        project: &'project dyn Project,
        workspace_id: &'selection WorkspaceId,
        snapshots: &'selection WorkspaceSnapshots,
        languages: &'selection [SelectedResolutionLanguage],
        overlay_masks: &'selection [SelectedResolutionOverlayMask],
    ) -> Self {
        Self {
            project,
            analyzer: None,
            analysis_generation: project.analysis_generation(),
            workspace_id,
            snapshots,
            languages,
            overlay_masks,
            content_mounts: Vec::new(),
        }
    }

    #[doc(hidden)]
    pub fn with_content_mounts(
        mut self,
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
    ) -> Self {
        self.content_mounts = content_mounts;
        self
    }

    #[doc(hidden)]
    pub fn with_analyzer(mut self, analyzer: &'project dyn SelectedAnalyzerServices) -> Self {
        self.analyzer = Some(analyzer);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedResolutionFallbackReason {
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
}

#[doc(hidden)]
pub enum SelectedResolutionOperationOutcome<T> {
    Native(T),
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
    Cancelled(ResolutionCompletion),
}

#[doc(hidden)]
pub enum SelectedResolutionOperationResult<T> {
    Native(T),
    Legacy {
        value: T,
        reason: SelectedResolutionFallbackReason,
    },
    Cancelled(ResolutionCompletion),
}

fn run_selected_resolution_legacy<T, R>(
    cancellation: &CancellationToken,
    reason: R,
    legacy: impl FnOnce() -> Result<T>,
) -> Result<Option<(T, R)>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let result = legacy();
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some((result?, reason)))
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
                let Some((value, reason)) = run_selected_resolution_legacy(
                    cancellation,
                    SelectedResolutionFallbackReason::Unavailable(reason),
                    legacy,
                )?
                else {
                    return Ok(SelectedResolutionOperationResult::Cancelled(
                        cancelled_completion(),
                    ));
                };
                SelectedResolutionOperationResult::Legacy { value, reason }
            }
            Self::Stale(reason) => {
                let Some((value, reason)) = run_selected_resolution_legacy(
                    cancellation,
                    SelectedResolutionFallbackReason::Stale(reason),
                    legacy,
                )?
                else {
                    return Ok(SelectedResolutionOperationResult::Cancelled(
                        cancelled_completion(),
                    ));
                };
                SelectedResolutionOperationResult::Legacy { value, reason }
            }
            Self::Cancelled(completion) => SelectedResolutionOperationResult::Cancelled(completion),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedResolutionLocated<T> {
    Found(T),
    Missing,
}

/// Bounded broad-result staging that rolls back on drop until `publish`.
///
/// Commit G supplies the concrete transaction. Commit F depends only on this
/// ownership law and never materializes an eager workspace-sized result.
#[doc(hidden)]
pub trait SelectedResolutionBroadStager {
    type Published;

    fn stage(&mut self, batch: &FactReferenceBatchAnswer) -> Result<()>;

    fn publish(self, summary: FactResolutionBatchSummary) -> Result<Self::Published>;
}

/// Generated macro-reference facts staged for this crate operation.
#[derive(Default)]
#[doc(hidden)]
pub struct MacroOverlaySlot {
    /// Caller files already covered. Reverse confirmation adds callers in
    /// batches, so a crate-wide prepared bit can hide later files' facts.
    #[doc(hidden)]
    pub prepared_files: HashSet<String>,
}

#[derive(Clone)]
struct PreparedMacroIncludeOverlay {
    components: Vec<PreparedMacroIncludeComponent>,
    path_count: usize,
    binding_pair_count: usize,
}

#[derive(Clone)]
struct PreparedMacroIncludeComponent {
    scopes: Vec<(BindingFragmentId, ResolutionScopeId, BindingNodeId)>,
    origins: Vec<PreparedMacroIncludeOrigin>,
}

#[derive(Clone)]
struct PreparedMacroIncludeOrigin {
    fragment: BindingFragmentId,
    scope: ResolutionScopeId,
    paths: Vec<PreparedMacroIncludePath>,
    globs: Vec<PreparedMacroIncludeGlob>,
}

#[derive(Clone)]
struct PreparedMacroIncludePath {
    identity: CandidatePathIdentity,
    path: PartialPath,
    end_kind: BindingNodeKind,
}

#[derive(Clone)]
struct PreparedMacroIncludeGlob {
    import: RustImportTargetFact,
    demand: ResolutionLookupSemanticRecipe,
}

/// Reuses immutable include-splice planning across identical selected macro
/// inputs. The SQL stage remains request-local and each request republishes
/// the cached plan into its own transaction.
#[doc(hidden)]
pub struct SelectedRustMacroIncludeOverlayCache {
    entries: Cache<[u8; 32], Arc<PreparedMacroIncludeOverlay>>,
    #[cfg(any(test, feature = "test-support"))]
    hits: std::sync::atomic::AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    inserts: std::sync::atomic::AtomicUsize,
}

impl SelectedRustMacroIncludeOverlayCache {
    const ENTRIES: u64 = 4;

    pub(crate) fn new() -> Self {
        Self {
            entries: Cache::builder().max_capacity(Self::ENTRIES).build(),
            #[cfg(any(test, feature = "test-support"))]
            hits: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            inserts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<Arc<PreparedMacroIncludeOverlay>> {
        let value = self.entries.get(key);
        #[cfg(any(test, feature = "test-support"))]
        if value.is_some() {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        value
    }

    fn insert(&self, key: [u8; 32], overlay: Arc<PreparedMacroIncludeOverlay>) {
        if overlay.path_count <= 20_000 {
            self.entries.insert(key, overlay);
            #[cfg(any(test, feature = "test-support"))]
            self.inserts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn hit_count_for_test(&self) -> usize {
        self.hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn insert_count_for_test(&self) -> usize {
        self.inserts.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Preparation owned by one selected query; reader checkin retains only SQL state.
#[doc(hidden)]
pub struct QueryResolutionPreparation {
    /// Scalar preparation state for the current SQL crate stage.
    #[doc(hidden)]
    pub macro_overlay: RefCell<MacroOverlaySlot>,
    #[doc(hidden)]
    pub prepared_macro_files: RefCell<HashSet<PathBuf>>,
    /// Caller and macro-host files already checked for frontiers, including
    /// files with no macro input rows. These facts belong to this operation.
    checked_macro_frontier_files: RefCell<HashSet<PathBuf>>,
    /// Context registrations already validated for this operation and caller.
    registered_rust_caller_contexts:
        RefCell<HashMap<RustCallerRegistrationKey, Vec<RustCallerRegistrationFacts>>>,
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

/// The declaration authority one caller's selected reference uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RustDeclarationAccessKind {
    Caller,
    CrateSet,
}

impl RustDeclarationAccessKind {
    fn source(
        self,
        operation: &SelectedResolutionOperation<'_, '_>,
        crate_keys: Vec<[u8; 32]>,
    ) -> Result<Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>> {
        match self {
            Self::Caller => point_access(operation, crate_keys),
            Self::CrateSet => crate_set_access(operation, crate_keys),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RustCallerRegistrationKey {
    caller: PathBuf,
    crate_keys: Vec<[u8; 32]>,
    access: RustDeclarationAccessKind,
}

/// The exact identities installed by one caller-context blueprint.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RustCallerRegistrationFacts {
    fragment_local_semantics: Vec<(BindingFragmentId, ResolutionSemanticIdentity)>,
    shared_semantics: Vec<ResolutionSemanticIdentity>,
    context_owned_gaps: Vec<SemanticId>,
    boundary_nodes: Vec<BindingNodeId>,
}

impl RustCallerRegistrationFacts {
    fn from_blueprint(blueprint: &SelectedFactOperationBlueprint) -> Self {
        Self {
            fragment_local_semantics: blueprint.fragment_local_semantic_identities().to_vec(),
            shared_semantics: blueprint.shared_semantic_identities().to_vec(),
            context_owned_gaps: blueprint
                .context_owned_gap_identities()
                .iter()
                .copied()
                .collect(),
            boundary_nodes: blueprint.boundary_nodes().to_vec(),
        }
    }

    fn registration_work(&self) -> usize {
        self.shared_semantics
            .len()
            .checked_add(self.boundary_nodes.len())
            .and_then(|count| count.checked_add(self.context_owned_gaps.len()))
            .expect("selected context registration work must fit usize")
    }
}

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

struct RustReversePrepared {
    demand: Arc<RustCallerDemand>,
    contexts: SelectedResolutionContextSet,
}

struct RustReverseLifecycle<'a, 'store, 'input, T, Setup, Project> {
    selected: &'a mut SelectedResolutionOperation<'store, 'input>,
    caller: &'a Path,
    access: RustDeclarationAccessKind,
    cancellation: &'a CancellationToken,
    session: &'a ResolutionSession,
    context_metrics: &'a SelectedResolutionContextMetrics,
    setup: Setup,
    project: Project,
    marker: std::marker::PhantomData<T>,
}

struct RustReverseScoped<'a, 'store, 'input, T, Setup, Project> {
    ready: &'a ReadySelectedResolution<'store, 'input>,
    prepared: &'a RustCallerDemand,
    caller: &'a Path,
    access: RustDeclarationAccessKind,
    cancellation: &'a CancellationToken,
    session: &'a ResolutionSession,
    setup: &'a mut Setup,
    project: &'a mut Project,
    marker: std::marker::PhantomData<T>,
}

impl<'store, 'input, T, Setup, Project> reverse::ReverseLifecycle
    for RustReverseLifecycle<'_, 'store, 'input, T, Setup, Project>
where
    Setup: FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        SemanticId,
    ) -> Result<()>,
    Project: FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        &FactResolutionAnswer,
        &ReadySelectedResolution<'_, '_>,
        SelectedMountTable<'_, '_>,
        &ResolutionSession,
        &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<T>>,
{
    type Answer = SelectedRustReferenceAnswer<T>;
    type Limit = std::convert::Infallible;
    type Prepared = RustReversePrepared;
    type Scoped<'a>
        = RustReverseScoped<'a, 'store, 'input, T, Setup, Project>
    where
        Self: 'a;

    fn prepare(
        &mut self,
        locators: &[&SelectedSemanticLocator],
    ) -> Result<reverse::ReverseBatch<Self::Prepared, Self::Limit>> {
        use reverse::{ReverseBatch, ReverseCancellationStage};
        let selected = &mut self.selected;
        let caller = self.caller;
        let cancellation = self.cancellation;
        let session = self.session;
        if selected
            .mount_table()
            .mount_for_path("rust", &selected_path_key(caller))?
            .is_none()
        {
            return Ok(ReverseBatch::UnsupportedContext);
        }
        let mut macro_callers = vec![caller];
        for path in locators
            .iter()
            .map(|locator| Path::new(locator.relative_path()))
        {
            if path != caller && !macro_callers.contains(&path) {
                macro_callers.push(path);
            }
        }
        match selected.prepare_selected_macro_frontiers_for_files(&macro_callers, cancellation)? {
            SelectedResolutionStageOutcome::Ready => {}
            SelectedResolutionStageOutcome::Cancelled => {
                return Ok(ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Prepare,
                    completion: cancelled_completion(),
                });
            }
            SelectedResolutionStageOutcome::Stale(reason) => {
                return Ok(ReverseBatch::Stale(reason));
            }
            SelectedResolutionStageOutcome::Unavailable(reason) => {
                return Ok(ReverseBatch::Unavailable(reason));
            }
        }
        let _timing = crate::profiling::scope("rust_caller::demand_preparation");
        let demand = match selected.rust_demand_preparation_for_caller_in_session(
            caller,
            cancellation,
            Some(session),
        )? {
            SelectedRustCallerDemandOutcome::Ready(demand) => demand,
            SelectedRustCallerDemandOutcome::Unavailable => {
                return Ok(ReverseBatch::UnsupportedContext);
            }
            SelectedRustCallerDemandOutcome::Cancelled => {
                return Ok(ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Prepare,
                    completion: cancelled_completion(),
                });
            }
        };
        let contexts = demand.contexts.clone().with_declaration_access_source(
            self.access.source(selected, demand.crate_keys.clone())?,
        );
        Ok(ReverseBatch::Ready(RustReversePrepared {
            demand,
            contexts,
        }))
    }

    fn validate(
        &mut self,
        prepared: &Self::Prepared,
    ) -> Result<reverse::ReverseBatch<SelectedResolutionContextInputs, Self::Limit>> {
        use reverse::{ReverseBatch, ReverseCancellationStage};
        if !self
            .selected
            .ensure_selected_rust_inputs_in_session(self.cancellation, self.session)?
        {
            return Ok(ReverseBatch::Cancelled {
                stage: ReverseCancellationStage::Prepare,
                completion: cancelled_completion(),
            });
        }
        note_rust_point_work("search_entry_inputs", self.session);
        let _timing = crate::profiling::scope("rust_caller::prepare_context");
        let context = match self.selected.prepare_context_in_session(
            prepared.contexts.clone(),
            self.cancellation,
            self.context_metrics,
            self.session,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Prepare,
                    completion: cancelled_completion(),
                });
            }
        };
        note_rust_point_work("search_validate_mounts", self.session);
        Ok(ReverseBatch::Ready(context))
    }

    fn with_scope<'a, V>(
        &'a mut self,
        prepared: &'a Self::Prepared,
        run: impl FnOnce(&mut Self::Scoped<'a>) -> Result<reverse::ReverseBatch<V, Self::Limit>>,
    ) -> Result<reverse::ReverseBatch<V, Self::Limit>> {
        let ready = &self.selected.ready;
        // The crate closure and its query-lived memos cover blueprint and demand
        // reads, then drop before final selected authority is checked (#3761).
        let _memos = ready.crate_stage_memos()?;
        let _scope =
            ready.narrow_forward_scope_to_crates(&prepared.demand.crate_keys, self.cancellation)?;
        run(&mut RustReverseScoped {
            ready,
            prepared: &prepared.demand,
            caller: self.caller,
            access: self.access,
            cancellation: self.cancellation,
            session: self.session,
            setup: &mut self.setup,
            project: &mut self.project,
            marker: std::marker::PhantomData,
        })
    }

    fn finish(
        &mut self,
        reports: Vec<reverse::ReverseSessionReport<Self::Answer>>,
    ) -> reverse::ReverseSessionOutcome<Self::Answer, Self::Limit> {
        use reverse::{ReverseBatch, ReverseCancellationStage, ReverseSessionReport};
        let mut completion = ResolutionCompletion::Complete;
        for report in &reports {
            if let ReverseSessionReport::Found { meanings, .. } = report {
                for (_, answers) in meanings {
                    for answer in answers {
                        completion = completion.combine(answer.resolution.completion());
                    }
                }
            }
        }
        note_rust_point_work("search_answers", self.session);
        if !self.session.scope_step() {
            return Ok(ReverseBatch::Cancelled {
                stage: ReverseCancellationStage::Projection,
                completion: completion.combine(&cancelled_completion()),
            });
        }
        note_rust_point_work("search_final_authority", self.session);
        Ok(self
            .selected
            .ready
            .finish(reports, &completion, self.cancellation)?
            .into())
    }
}

impl<T, Setup, Project> reverse::ReverseScopedLifecycle
    for RustReverseScoped<'_, '_, '_, T, Setup, Project>
where
    Setup: FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        SemanticId,
    ) -> Result<()>,
    Project: FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        &FactResolutionAnswer,
        &ReadySelectedResolution<'_, '_>,
        SelectedMountTable<'_, '_>,
        &ResolutionSession,
        &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<T>>,
{
    type Answer = SelectedRustReferenceAnswer<T>;
    type Limit = std::convert::Infallible;

    fn blueprint(
        &mut self,
        context: SelectedResolutionContextInputs,
    ) -> Result<reverse::ReverseBatch<SelectedFactOperationBlueprint, Self::Limit>> {
        use reverse::{ReverseBatch, ReverseCancellationStage};
        let _timing = crate::profiling::scope("rust_caller::collect_blueprint");
        let blueprint = match self.ready.collect_blueprint_in_session(
            context,
            self.cancellation,
            self.session,
        )? {
            SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
            SelectedFactOperationBlueprintConstruction::Cancelled {
                cancellation_completion,
                ..
            } => {
                return Ok(ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Blueprint,
                    completion: cancellation_completion,
                });
            }
        };
        note_rust_point_work("search_collect_blueprint", self.session);
        Ok(ReverseBatch::Ready(blueprint))
    }

    fn register(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
    ) -> Result<reverse::ReverseBatch<(), Self::Limit>> {
        use reverse::{ReverseBatch, ReverseCancellationStage};
        if matches!(
            register_selected_rust_caller_context_in_session(
                self.ready,
                self.caller,
                &self.prepared.crate_keys,
                self.access,
                blueprint,
                self.cancellation,
                self.session,
            )?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Ok(ReverseBatch::Cancelled {
                stage: ReverseCancellationStage::Register,
                completion: cancelled_completion(),
            });
        }
        note_rust_point_work("search_register_context", self.session);
        Ok(ReverseBatch::Ready(()))
    }

    fn locate(
        &mut self,
        locator: &SelectedSemanticLocator,
    ) -> Result<reverse::ReverseBatch<LocatedSemantics, Self::Limit>> {
        use reverse::{ReverseBatch, ReverseCancellationStage};
        match self.ready.lookup_locators_in_session(
            &self.ready.lexical_source(),
            locator,
            self.cancellation,
            self.session,
        )? {
            LocatedSemantics::Cancelled => Ok(ReverseBatch::Cancelled {
                stage: ReverseCancellationStage::Locator,
                completion: cancelled_completion(),
            }),
            found => Ok(ReverseBatch::Ready(found)),
        }
    }

    fn with_evaluator<V>(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
        run: impl FnOnce(
            &mut dyn reverse::ReverseSessionEvaluator<Answer = Self::Answer, Limit = Self::Limit>,
        ) -> Result<reverse::ReverseBatch<V, Self::Limit>>,
    ) -> Result<reverse::ReverseBatch<V, Self::Limit>> {
        use reverse::{ReverseBatch, ReverseCancellationStage, ReverseEvaluatorFn};
        let Self {
            ready,
            prepared,
            cancellation,
            session,
            setup,
            project,
            access,
            ..
        } = self;
        let ready = *ready;
        let cancellation = *cancellation;
        let session = *session;
        note_rust_point_work("search_lookup_locators", session);
        let persisted_lexical = ready.lexical_source();
        let persisted_typed = ready.typed_source();
        let observed_lexical = SeamProfiled::observing(&persisted_lexical);
        let observed_typed = SeamProfiled::observing(&persisted_typed);
        let arena = RefCell::new(ClosedRelations::default());
        let source = ClosedForwardSource::new(
            &observed_lexical,
            &persisted_lexical,
            &arena,
            session,
            crate::analyzer::resolution::CALLER_ENVIRONMENT,
        );
        let forward = PreparedForwardSource::new(
            ready,
            &prepared.demand,
            &observed_lexical,
            &persisted_lexical,
        );
        let mut provider = DemandProvider::new(ForwardProvider::new(
            &forward,
            &arena,
            session,
            cancellation,
        ));
        blueprint.with_forward_operation_in_session(
            &source,
            &persisted_lexical,
            &observed_typed,
            cancellation,
            session,
            |operation| {
                operation
                    .enable_completed_root_reuse(&ready.operation_demand_state, *access as u64);
                let mut evaluator = ReverseEvaluatorFn {
                    marker: std::marker::PhantomData,
                    run: |locator: &SelectedSemanticLocator, reference: SemanticId| {
                        if !session.scope_step() || cancellation.is_cancelled() {
                            return Ok(ReverseBatch::Cancelled {
                                stage: ReverseCancellationStage::Locator,
                                completion: cancelled_completion(),
                            });
                        }
                        setup(operation, reference)?;
                        let resolution = match operation
                            .resolve_reference_by_demand(reference, &mut provider)?
                        {
                            FactDemandResolution::Ready(resolution) => *resolution,
                            FactDemandResolution::Cancelled(completion) => {
                                return Ok(ReverseBatch::Cancelled {
                                    stage: ReverseCancellationStage::Projection,
                                    completion,
                                });
                            }
                        };
                        if !session.observe_cancellation() || cancellation.is_cancelled() {
                            return Ok(ReverseBatch::Cancelled {
                                stage: ReverseCancellationStage::Projection,
                                completion: cancelled_completion(),
                            });
                        }
                        Ok(
                            match assemble_rust_reference_answer(
                                &RustReferenceAnswerContext {
                                    ready,
                                    mounts: SelectedMountTable::new(&ready.inventory),
                                    reference,
                                    locator,
                                    session,
                                    cancellation,
                                },
                                operation,
                                resolution,
                                &mut |operation, reference| {
                                    operation.resolve_reference_by_demand(reference, &mut provider)
                                },
                                project,
                            )? {
                                SelectedResolutionOperationOutcome::Native(answer) => {
                                    ReverseBatch::Ready(vec![answer])
                                }
                                other => match other {
                                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                                        ReverseBatch::Unavailable(reason)
                                    }
                                    SelectedResolutionOperationOutcome::Stale(reason) => {
                                        ReverseBatch::Stale(reason)
                                    }
                                    SelectedResolutionOperationOutcome::Cancelled(completion) => {
                                        ReverseBatch::Cancelled {
                                            stage: ReverseCancellationStage::Projection,
                                            completion,
                                        }
                                    }
                                    SelectedResolutionOperationOutcome::Native(_) => unreachable!(),
                                },
                            },
                        )
                    },
                };
                run(&mut evaluator)
            },
        )
    }
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

#[doc(hidden)]
pub struct ReadySelectedResolution<'store, 'input> {
    store: &'store AnalyzerStore,
    #[doc(hidden)]
    pub inventory: Box<SelectedResolutionMountInventory<'store>>,
    query_preparation: Option<Box<QueryResolutionPreparation>>,
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
    project: &'input dyn Project,
    analyzer: Option<&'input dyn SelectedAnalyzerServices>,
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
    #[doc(hidden)]
    pub context_identities: crate::analyzer::resolution::SelectedContextIdentities,
    /// Demand answers and minting authority touched by this operation only.
    /// Blueprints lend the identity registry to otherwise fresh fact arenas.
    #[doc(hidden)]
    pub operation_demand_state: Arc<crate::analyzer::resolution::SelectedDemandState>,
    // Publication identities bound by this query, dropped with the request.
    go_publications: RefCell<HashMap<i64, super::GoContextIdentity>>,
    go_snapshot: Option<super::WorkspaceSnapshotId>,
    go_base_profile: std::cell::Cell<Option<[u8; 32]>>,
    /// Whether this request encountered any complete selected Go package.
    go_package_inventory_complete: RefCell<Option<bool>>,
    /// Per-fragment package completeness for packages used by this request.
    /// This is query-scoped so one workspace query can visit several packages.
    go_package_inventory_fragments: RefCell<HashMap<BindingFragmentId, bool>>,
    /// Exact lexical answers shared for this request in every language.
    /// These entries are dropped with the operation, never retained or pooled.
    operation_candidate_cache: std::rc::Rc<UnconditionalCandidateCache>,
    /// Reader memos retained only while one graph-stage unit is active.
    graph_stage_candidate_cache: RefCell<Option<std::rc::Rc<UnconditionalCandidateCache>>>,
    boundary_candidate_read_memo: BoundaryCandidateReadMemo,
    package_reference_read_memo: std::rc::Rc<RefCell<ExactReadMemo<PackageReferenceReadKey, bool>>>,
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
    #[doc(hidden)]
    pub fn identity_content_digest(
        &self,
        key: crate::analyzer::resolution::ResolutionIdentityDigestKey,
        cancellation: &CancellationToken,
    ) -> Result<[u8; 32]> {
        if let Some(digest) = self
            .inventory
            .authority_request_memo()
            .borrow()
            .canonical_digests
            .get(&key)
            .copied()
        {
            return Ok(digest);
        }
        if let Some(number) = key.context_number() {
            return Ok(self
                .context_identities
                .content_digest(number)
                .expect("a selected context alias has a canonical digest"));
        }
        if let Some(number) = key.operation_number() {
            return Ok(self
                .operation_demand_state
                .identity_digest(number)
                .expect("a selected demand alias has a canonical digest"));
        }
        self.lexical_source()
            .identity_content_digest(key, cancellation)?
            .ok_or_else(|| {
                StoreError::new(format!("selected identity has no content digest: {key:?}"))
            })
    }

    /// Where this request's lowerings and its own demands get a shared name's
    /// id. The table lives on the inventory, which is built for one request
    /// and dropped with it.
    #[doc(hidden)]
    pub fn shared_names(&self) -> super::resolution::StoreSharedNames<'_> {
        self.inventory.shared_names()
    }

    #[doc(hidden)]
    pub fn lexical_source(&self) -> SelectedResolutionLexicalSource<'_, 'store> {
        if let Some(cache) = self.graph_stage_candidate_cache.borrow().as_ref() {
            return SelectedResolutionLexicalSource::new_on_demand_with_unconditional_cache(
                &self.inventory,
                std::rc::Rc::clone(cache),
            )
            .with_boundary_read_memo(std::rc::Rc::clone(&self.boundary_candidate_read_memo));
        }
        SelectedResolutionLexicalSource::new_on_demand_with_unconditional_cache(
            &self.inventory,
            std::rc::Rc::clone(&self.operation_candidate_cache),
        )
        .with_boundary_read_memo(std::rc::Rc::clone(&self.boundary_candidate_read_memo))
    }

    fn bind_go_context_publication(&self, publication: super::GoContextIdentity) {
        if let Some(previous) = self
            .go_publications
            .borrow_mut()
            .insert(publication.context_id, publication.clone())
        {
            assert_eq!(
                previous, publication,
                "one context has one bound publication identity"
            );
        }
    }

    #[doc(hidden)]
    pub fn typed_source(&self) -> SelectedResolutionTypedSource<'_, 'store> {
        let mut providers = self
            .analyzer
            .map(|analyzer| analyzer.external_inventory_providers())
            .unwrap_or_default();
        let external_models = self.analyzer.and_then(|analyzer| analyzer.active_models());
        if let Some(models) = &external_models {
            providers.extend(
                models
                    .shards()
                    .iter()
                    .map(|shard| shard.manifest.semantic_sha256.clone()),
            );
        }
        providers.sort_unstable();
        providers.dedup();
        SelectedResolutionTypedSource::new_on_demand(&self.inventory)
            .with_go_context_binder(self)
            .with_context_identities(self.context_identities.clone())
            .with_external_providers(providers)
            .with_external_models(external_models)
            .with_model_authority(
                self.analyzer
                    .and_then(|analyzer| analyzer.model_authority()),
            )
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn take_rebaser_identities_at_handback_for_test() -> [usize; 4] {
    REBASER_IDENTITIES_AT_HANDBACK.with(std::cell::Cell::take)
}

impl Drop for ReadySelectedResolution<'_, '_> {
    fn drop(&mut self) {
        let preparation = self
            .query_preparation
            .take()
            .expect("ready selected resolution drops operation preparation exactly once");
        #[cfg(any(test, feature = "test-support"))]
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
#[doc(hidden)]
pub struct SelectedMacroCapsule {
    #[doc(hidden)]
    pub mount: SelectedResolutionOperationMount,
    #[doc(hidden)]
    pub blob_id: i64,
    #[doc(hidden)]
    pub content_oid: git2::Oid,
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

    #[doc(hidden)]
    pub const fn mount(&self) -> &SelectedResolutionOperationMount {
        &self.mount
    }

    #[doc(hidden)]
    pub const fn blob_id(&self) -> i64 {
        self.blob_id
    }

    #[doc(hidden)]
    pub const fn content_oid(&self) -> git2::Oid {
        self.content_oid
    }

    /// The registered reader of this capsule's macro rows.
    ///
    /// A capsule is minted for one selected mount, and the mount carries the
    /// language that wrote its rows, so the reader is the one that language
    /// registers. The capsule exists only because that language publishes
    /// macro rows at all, which is why a missing reader is an assertion here
    /// rather than an outcome each caller below would have to interpret.
    #[doc(hidden)]
    pub fn macro_rows(&self) -> &'static dyn SelectedMacroSourceRows {
        let language = self.mount.semantic_language();
        crate::analyzer::store::store_language_support_for_hook(
            language,
            "selected_macro_source_rows",
        )
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
#[doc(hidden)]
pub trait SelectedMacroSourceRows: Send + Sync {
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

    /// Whether any invocation input is sealed in the blob, without decoding
    /// its cfg, source payload, frontier or tokens.
    fn has_inputs(&self, connection: &rusqlite::Connection, blob_id: i64) -> Result<bool>;

    /// The first canonical input at the stored token-tree start, with only
    /// that invocation's tokens. `None` reports cancellation, as in `input_rows`.
    fn invocation_input_rows(
        &self,
        connection: &rusqlite::Connection,
        blob_id: i64,
        arguments_start: usize,
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
#[doc(hidden)]
pub struct SelectedResolutionOperationMount {
    #[doc(hidden)]
    pub ordinal: SelectedResolutionMountOrdinal,
    #[doc(hidden)]
    pub storage_language: String,
    #[doc(hidden)]
    pub persisted_relative_path: String,
    #[doc(hidden)]
    pub semantic_language: Language,
    #[doc(hidden)]
    pub fragment: BindingFragmentId,
}

impl SelectedResolutionOperationMount {
    #[doc(hidden)]
    pub const fn ordinal(&self) -> SelectedResolutionMountOrdinal {
        self.ordinal
    }

    #[doc(hidden)]
    pub fn storage_language(&self) -> &str {
        &self.storage_language
    }

    #[doc(hidden)]
    pub fn persisted_relative_path(&self) -> &str {
        &self.persisted_relative_path
    }

    #[doc(hidden)]
    pub const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    #[doc(hidden)]
    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }
}

/// The selection's spelling of one workspace-relative path.
///
/// `persisted_relative_path` is stored with forward slashes, and that is the
/// spelling the temp table's path index is sorted on, so a `Path` key is
/// normalized once here instead of being compared component by component
/// against every mount.
#[doc(hidden)]
pub fn selected_path_key(path: &Path) -> String {
    crate::path_utils::normalize_pattern(&path.to_string_lossy())
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn take_selected_mount_table_visits_for_test() -> usize {
    SELECTED_MOUNT_TABLE_VISITS.with(|visits| visits.replace(0))
}

/// Requested operation metadata read through the existing TEMP ordinal/path
/// indexes. Explicit query-owned enumeration is separate from point reads
/// and never occurs at warm operation construction.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct SelectedMountTable<'a, 'store> {
    #[doc(hidden)]
    pub inventory: &'a SelectedResolutionMountInventory<'store>,
}

impl<'a, 'store> SelectedMountTable<'a, 'store> {
    #[doc(hidden)]
    pub fn new(inventory: &'a SelectedResolutionMountInventory<'store>) -> Self {
        Self { inventory }
    }

    #[doc(hidden)]
    pub fn mount_count(&self) -> usize {
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

    #[doc(hidden)]
    pub fn mount_by_ordinal(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Result<SelectedResolutionOperationMount> {
        #[cfg(any(test, feature = "test-support"))]
        note_selected_mount_table_visits(1);
        let record = self.inventory.mount_record_by_ordinal(ordinal)?;
        Ok(operation_mount_record(&record))
    }

    #[doc(hidden)]
    pub fn mount_for_fragment(
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

    /// The selected blob ID for one path in this inventory.
    #[doc(hidden)]
    pub fn blob_for_path(
        &self,
        storage_language: &str,
        persisted_relative_path: &str,
    ) -> Result<Option<i64>> {
        Ok(self
            .inventory
            .mount_record_for_path(storage_language, persisted_relative_path)?
            .map(|mount| mount.blob_id()))
    }

    #[doc(hidden)]
    pub fn mount_for_path(
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

#[doc(hidden)]
pub enum SelectedResolutionOperationOpenOutcome<'store, 'input> {
    Ready(Box<SelectedResolutionOperation<'store, 'input>>),
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
    Cancelled,
}

impl std::fmt::Debug for SelectedResolutionOperationOpenOutcome<'_, '_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(_) => formatter.write_str("Ready(..)"),
            Self::Unavailable(reason) => {
                formatter.debug_tuple("Unavailable").field(reason).finish()
            }
            Self::Stale(reason) => formatter.debug_tuple("Stale").field(reason).finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
        }
    }
}

#[doc(hidden)]
pub enum SelectedResolutionOperationOpenResult<'store, 'input, T> {
    Ready(Box<SelectedResolutionOperation<'store, 'input>>),
    Legacy {
        value: T,
        reason: SelectedResolutionFallbackReason,
    },
    Cancelled,
}

impl<'store, 'input> SelectedResolutionOperationOpenOutcome<'store, 'input> {
    #[doc(hidden)]
    pub fn with_legacy<T>(
        self,
        cancellation: &CancellationToken,
        legacy: impl FnOnce() -> Result<T>,
    ) -> Result<SelectedResolutionOperationOpenResult<'store, 'input, T>> {
        Ok(match self {
            Self::Ready(operation) => SelectedResolutionOperationOpenResult::Ready(operation),
            Self::Unavailable(reason) => {
                let Some((value, reason)) = run_selected_resolution_legacy(
                    cancellation,
                    SelectedResolutionFallbackReason::Unavailable(reason),
                    legacy,
                )?
                else {
                    return Ok(SelectedResolutionOperationOpenResult::Cancelled);
                };
                SelectedResolutionOperationOpenResult::Legacy { value, reason }
            }
            Self::Stale(reason) => {
                let Some((value, reason)) = run_selected_resolution_legacy(
                    cancellation,
                    SelectedResolutionFallbackReason::Stale(reason),
                    legacy,
                )?
                else {
                    return Ok(SelectedResolutionOperationOpenResult::Cancelled);
                };
                SelectedResolutionOperationOpenResult::Legacy { value, reason }
            }
            Self::Cancelled => SelectedResolutionOperationOpenResult::Cancelled,
        })
    }
}

/// Non-clone selected owner retained for one query lifetime. A Rust definition
/// batch may use it for several bounded point requests.
#[doc(hidden)]
pub struct SelectedResolutionOperation<'store, 'input> {
    captured_input: CapturedSelectedResolutionInput<'input>,
    #[doc(hidden)]
    pub ready: ReadySelectedResolution<'store, 'input>,
    enumerated_mounts: OnceCell<Vec<SelectedResolutionOperationMount>>,
    /// Same-package peer mounts and grouped member rows, retained only for
    /// this selected operation while it prepares multiple Go source files.
    go_package_member_indexes: RefCell<go_same_package::GoPackageMemberIndexCache>,
    /// The selected Go publication per (context, source role), read once per
    /// operation because it scans the publication's gap list.
    go_context_selections: RefCell<HashMap<(i64, String), Option<go_context::GoContextSelection>>>,
    /// Import bindings and selected import rows of the Go files this operation
    /// prepares, read one statement per batch of files and dropped with it.
    #[doc(hidden)]
    pub go_import_inputs: RefCell<go_named::GoImportInputCache>,
    /// Prepared Go file contexts admitted by point, graph, or forward-fallback
    /// demand. Values die with this selected operation.
    go_prepared_contexts: go_named::GoPreparedContextMemo,
    /// Provider cell deltas shared by Go preparation, closure and nested evaluation.
    go_context_registrations: RefCell<go_demand::GoContextRegistrationMemo>,
    /// Declared receiver types demanded by this selected query. Keys include
    /// the exact anchor and staged selection; member names do not affect it.
    go_receiver_anchor_types_memo: RefCell<go_receiver_anchor::GoReceiverAnchorTypesMemo>,
    /// Completed file contexts for distinct inputs over this query's selection.
    jvm_file_contexts: RefCell<jvm_context::JvmFileContextMemo>,
    jvm_context_preparations: jvm_context::JvmContextPreparationMemo,
    jvm_context_blueprints: jvm_context::JvmContextBlueprintMemo,
    /// Provider registrations shared by named contexts in this query only.
    jvm_context_registrations: RefCell<jvm_demand::JvmContextRegistrationMemo>,
    /// Visibility evidence for exact source pairs in this query's selection.
    jvm_source_access_memo: RefCell<jvm_context::JvmSourceAccessMemo>,
    /// Interned paths keep source-pair memo hits allocation-free.
    jvm_source_paths: RefCell<HashMap<String, usize>>,
    jvm_source_domains: jvm_context::JvmSourceDomainMemo,
    jvm_implicit_project_memo: jvm_context::JvmImplicitProjectMemo,
    jvm_implicit_project_contexts: jvm_context::JvmImplicitProjectContextMemo,
    /// Exact recipe rows requested in this query, independent of batch layout.
    jvm_lookup_recipe_memo: RefCell<jvm_context::JvmLookupRecipeMemo>,
    /// Full export reads for mounts demanded by this query, including evidence.
    jvm_root_exports_memo: RefCell<jvm_context::JvmRootExportMemo>,
    /// Exact import membership facts demanded by this operation.
    jvm_import_target_memo: RefCell<jvm_context::JvmImportTargetMemo>,
    jvm_named_import_target_memo: RefCell<jvm_context::JvmNamedImportTargetMemo>,
    jvm_import_uncertainty_memo: RefCell<jvm_context::JvmImportUncertaintyMemo>,
    /// Raw alias facts and generated names demanded by this query only.
    jvm_alias_rows_memo: RefCell<jvm_context::JvmAliasRowsMemo>,
    jvm_generated_lookup_memo: RefCell<jvm_context::JvmGeneratedLookupMemo>,
    jvm_package_member_memo: jvm_context::JvmPackageMemberMemo,
    jvm_package_indexes: RefCell<jvm_context::JvmPackageIndexMemo>,
    jvm_package_target_memo: RefCell<jvm_context::JvmPackageTargetMemo>,
    jvm_package_uncertainty_memo: RefCell<
        ExactReadMemo<jvm_context::JvmPackageTargetKey, Arc<[jvm_context::JvmImportTarget]>>,
    >,
    jvm_package_presence_memo: RefCell<jvm_context::JvmPackagePresenceMemo>,
    /// Complete node/visibility reads for distinct selected JVM inputs.
    jvm_endpoint_memo: RefCell<jvm_context::JvmEndpointMemo>,
    jvm_import_token_memo: RefCell<jvm_context::JvmImportTokenMemo>,
    jvm_visibility_memo: RefCell<jvm_context::JvmVisibilityMemo>,
    /// Repeated member continuations retain the full input and owner-found effect.
    jvm_member_import_memo: RefCell<jvm_context::JvmMemberImportMemo>,
    /// Opt-in invocation ledger, dropped with this selected query.
    #[doc(hidden)]
    pub jvm_context_profile: RefCell<Option<jvm_context::JvmContextReadProfile>>,
}

impl<'store, 'input> SelectedResolutionOperation<'store, 'input> {
    #[doc(hidden)]
    pub fn worker_input(&self) -> &CapturedSelectedResolutionInput<'input> {
        &self.captured_input
    }

    #[doc(hidden)]
    pub fn worker_store(&self) -> &'store AnalyzerStore {
        self.ready.store
    }

    pub(crate) fn identity_content_digest(
        &self,
        key: crate::analyzer::resolution::ResolutionIdentityDigestKey,
        cancellation: &CancellationToken,
    ) -> Result<[u8; 32]> {
        self.ready.identity_content_digest(key, cancellation)
    }

    pub(crate) fn worker_shared_names(&self) -> super::resolution::StoreSharedNames<'_> {
        self.ready.shared_names()
    }

    pub(crate) fn worker_context_identities(
        &self,
    ) -> &crate::analyzer::resolution::SelectedContextIdentities {
        &self.ready.context_identities
    }

    pub(crate) fn worker_demand_state(&self) -> &crate::analyzer::resolution::SelectedDemandState {
        &self.ready.operation_demand_state
    }

    pub(crate) fn finish_worker_answer<T>(
        mut self,
        answer: T,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        self.ready
            .finish(answer, &ResolutionCompletion::Complete, cancellation)
    }
}

#[allow(clippy::large_enum_variant)]
#[doc(hidden)]
pub enum SelectedRustContextOutcome {
    Ready(SelectedResolutionContextSet),
    Cancelled,
}

/// A Rust context built for named files, with the crates that compile them.
///
/// A forward request binds only inside the dependency closure of its own
/// crates, and it installs that scope before it collects its blueprint. The
/// crates are read while the context is built, so the caller that installs the
/// scope takes them from here instead of asking the crate rows again.
#[doc(hidden)]
pub enum SelectedRustFileContextOutcome {
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

#[allow(clippy::large_enum_variant)]
pub(crate) enum SelectedRustCallerContextOutcome {
    Ready(SelectedResolutionContextSet),
    Unavailable,
    Cancelled,
}

#[allow(clippy::large_enum_variant)]
#[doc(hidden)]
pub enum SelectedRustCallerReferenceOutcome<T = ()> {
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

fn repeat_bounded_resolution<T>(
    count: usize,
    terminal: BoundedResolution<()>,
    mut value: impl FnMut() -> T,
) -> Vec<BoundedResolution<T>> {
    match terminal {
        BoundedResolution::Complete { work, .. } => (0..count)
            .map(|_| BoundedResolution::Complete {
                value: value(),
                work,
            })
            .collect(),
        BoundedResolution::Exceeded { limit, work } => (0..count)
            .map(|_| BoundedResolution::Exceeded { limit, work })
            .collect(),
        BoundedResolution::Cancelled { work } => (0..count)
            .map(|_| BoundedResolution::Cancelled { work })
            .collect(),
    }
}

#[doc(hidden)]
pub enum SelectedRustDefinitionProjection {
    Complete(Vec<CodeUnit>),
    Unavailable,
    Cancelled,
}

#[doc(hidden)]
pub enum SelectedRustSourceDefinitionProjection {
    Complete(Vec<(SemanticId, SelectedRustSourceDefinition)>),
    Unavailable,
    Cancelled,
}

#[doc(hidden)]
pub enum SelectedRustSourceDefinition {
    Unit(CodeUnit),
    Lexical(LexicalDefinition),
    /// A resolved target that is an entry of the language's fixed universe
    /// table: `i64` in a Rust type position, which the request interns as a
    /// shared name. It belongs to no file, so no source declaration projects
    /// it, and that is a fact about the target rather than a question this
    /// projection could not answer. One such target must not withdraw the
    /// answer of every sibling target in its batch. The usage graph's nodes
    /// are `CodeUnit`s, so such a target is out of the graph exactly as a
    /// lexical binder is, and the definition path publishes no name for it.
    UniverseEntry,
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
#[doc(hidden)]
pub enum SelectedRustDefinitionSemanticOutcome {
    Found(SemanticId),
    Missing,
    Cancelled,
}

#[doc(hidden)]
pub enum SelectedRustDefinitionSemanticMapOutcome {
    Ready(HashMap<CodeUnit, SemanticId>),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedRustBindingDefinitionOutcome {
    Found(SelectedRustBindingDefinition),
    Missing,
    Cancelled,
}

#[doc(hidden)]
pub enum SelectedRustBindingDefinitionUnitsOutcome {
    Ready(BTreeMap<SelectedRustBindingDefinition, CodeUnit>),
    Cancelled,
}

/// Where one selected member target was found, in the presentation vocabulary.
///
/// Declared beside the answer that carries it: the point route is its only
/// producer and the native definition adapter its only reader.
#[doc(hidden)]
pub struct SelectedRustMemberAttribution {
    #[doc(hidden)]
    pub target: SemanticId,
    #[doc(hidden)]
    pub owner: CodeUnit,
    #[doc(hidden)]
    pub reach: SelectedRustMemberReach,
}

/// The typed producer frontier for one gap retained by this Rust lookup.
/// Explicit macro invocations are checked by their native gap site; an
/// attribute frontier is the generated-item or scope/binder gap that does not
/// join an invocation input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedRustGapFrontierKind {
    ExplicitMacroInvocation,
    GeneratedItemSurface,
    UnsupportedScopeOrBinder,
    Other,
}

impl SelectedRustGapFrontierKind {
    #[doc(hidden)]
    pub const fn is_attribute_macro_frontier(self) -> bool {
        matches!(
            self,
            Self::GeneratedItemSurface | Self::UnsupportedScopeOrBinder
        )
    }

    #[doc(hidden)]
    pub const fn evidence_name(self) -> &'static str {
        match self {
            Self::ExplicitMacroInvocation => "explicit_macro_invocation",
            Self::GeneratedItemSurface => "GeneratedItemSurface",
            Self::UnsupportedScopeOrBinder => "UnsupportedScopeOrBinder",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedRustGapFrontier {
    #[doc(hidden)]
    pub semantic: SemanticId,
    #[doc(hidden)]
    pub kind: SelectedRustGapFrontierKind,
}

/// How the Rust member lookup got from the qualifier's own type to the owner.
#[doc(hidden)]
pub enum SelectedRustMemberReach {
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
#[doc(hidden)]
pub struct SelectedRustMacroExpansionGap {
    #[doc(hidden)]
    pub semantic: SemanticId,
    #[doc(hidden)]
    pub relative_path: String,
    #[doc(hidden)]
    pub start_byte: usize,
    #[doc(hidden)]
    pub end_byte: usize,
    #[doc(hidden)]
    pub macro_name: String,
    #[doc(hidden)]
    pub private_module_route: bool,
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
#[doc(hidden)]
pub fn rust_block_local_binding_is_decided(
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

#[doc(hidden)]
pub struct SelectedRustReferenceAnswer<T = ()> {
    #[doc(hidden)]
    pub macro_expansion_gaps: Vec<SelectedRustMacroExpansionGap>,
    #[doc(hidden)]
    pub generated_surface_gaps: Vec<SemanticId>,
    #[doc(hidden)]
    pub retained_gap_frontiers: Vec<SelectedRustGapFrontier>,
    #[doc(hidden)]
    pub enumeration: Option<(ProjectFile, ResolutionCompletion)>,
    #[doc(hidden)]
    pub inventory_details: Vec<String>,
    /// The stable name and evidence of each named reason the binding's
    /// completion carries (`SelectedContextIdentities::named_semantic`), so a
    /// reply can say which dead end an incomplete answer stopped at.
    #[doc(hidden)]
    pub named_reasons: Vec<(&'static str, String)>,
    #[doc(hidden)]
    pub resolution: FactResolutionAnswer,
    #[doc(hidden)]
    pub definitions: Vec<CodeUnit>,
    #[doc(hidden)]
    pub lexical_definitions: Vec<LexicalDefinition>,
    /// The name each of the binding's own targets projects to, in the order
    /// `project_rust_source_definitions` returned them. A diagnostic that
    /// names a semantic can spell it when it is one of these; the presentation
    /// vocabularies below deliberately drop the semantic each row came from.
    #[doc(hidden)]
    pub definition_names: Vec<(SemanticId, String)>,
    /// Original structured import paths for external-boundary reasons.
    #[doc(hidden)]
    pub boundary_import_names: Vec<String>,
    /// Member attribution for the targets the member lookup itself selected.
    /// A target reached lexically or through a module route has no row.
    #[doc(hidden)]
    pub member_attributions: Vec<SelectedRustMemberAttribution>,
    #[doc(hidden)]
    pub projection: T,
}

impl<T> SelectedRustReferenceAnswer<T> {
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        boundary_import_names: Vec<String>,
        macro_expansion_gaps: Vec<SelectedRustMacroExpansionGap>,
        generated_surface_gaps: Vec<SemanticId>,
        retained_gap_frontiers: Vec<SelectedRustGapFrontier>,
        enumeration: Option<(ProjectFile, ResolutionCompletion)>,
        inventory_details: Vec<String>,
        named_reasons: Vec<(&'static str, String)>,
        resolution: FactResolutionAnswer,
        definitions: Vec<CodeUnit>,
        lexical_definitions: Vec<LexicalDefinition>,
        definition_names: Vec<(SemanticId, String)>,
        member_attributions: Vec<SelectedRustMemberAttribution>,
        projection: T,
    ) -> Self {
        Self {
            boundary_import_names,
            macro_expansion_gaps,
            generated_surface_gaps,
            retained_gap_frontiers,
            enumeration,
            inventory_details,
            named_reasons,
            resolution,
            definitions,
            lexical_definitions,
            definition_names,
            member_attributions,
            projection,
        }
    }
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
            SelectedRustSourceDefinition::UniverseEntry => {}
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

#[doc(hidden)]
pub struct SelectedRustTypeProjection {
    #[doc(hidden)]
    pub named_reasons: Vec<(&'static str, String)>,
    #[doc(hidden)]
    pub nominal_types: Vec<(SemanticId, SelectedRustSourceDefinition)>,
    #[doc(hidden)]
    pub intrinsic_types: Box<[crate::analyzer::resolution::FactIntrinsicTypeDescriptor]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedReferenceSourceSite {
    reference: SemanticId,
    file: ProjectFile,
    metadata: Option<FactReferenceSiteMetadata>,
    enclosing: Option<Option<CodeUnit>>,
}

impl SelectedReferenceSourceSite {
    #[doc(hidden)]
    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    #[doc(hidden)]
    pub fn file(&self) -> &ProjectFile {
        &self.file
    }

    #[doc(hidden)]
    pub const fn metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.metadata
    }

    /// The producer-owned enclosing declaration after parser-unit projection.
    ///
    /// `None` means ownership is unknown or was not requested. `Some(None)`
    /// means the reference has no enclosing unit -- the file root owns it, or
    /// its enclosing declaration is one the parser publishes no `CodeUnit` for,
    /// such as a block-local `fn`. `Some(Some(_))` is one exact declaration.
    #[doc(hidden)]
    pub fn enclosing(&self) -> Option<Option<&CodeUnit>> {
        self.enclosing.as_ref().map(Option::as_ref)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedReferenceSearchAnswer {
    #[doc(hidden)]
    pub answer: ReferenceSearchAnswer,
    #[doc(hidden)]
    pub source_sites: Box<[SelectedReferenceSourceSite]>,
}

impl SelectedReferenceSearchAnswer {
    #[doc(hidden)]
    pub fn answer(&self) -> &ReferenceSearchAnswer {
        &self.answer
    }

    #[doc(hidden)]
    pub fn references(&self) -> &[SemanticId] {
        self.answer.references()
    }

    #[doc(hidden)]
    pub fn completion(&self) -> &ResolutionCompletion {
        self.answer.completion()
    }

    #[doc(hidden)]
    pub fn source_sites(&self) -> &[SelectedReferenceSourceSite] {
        &self.source_sites
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedRustBindingSite {
    #[doc(hidden)]
    pub file: ProjectFile,
    #[doc(hidden)]
    pub metadata: Option<FactReferenceSiteMetadata>,
    #[doc(hidden)]
    pub owner: SelectedRustBindingOwner,
    #[doc(hidden)]
    pub definitions: Box<[SelectedRustBindingDefinition]>,
    #[doc(hidden)]
    pub completion: ResolutionCompletion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedRustBindingOwner {
    Unknown,
    FileRoot,
    Definition(CodeUnit),
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub enum SelectedRustBindingDefinition {
    Stable(SemanticId),
}

impl SelectedRustBindingSite {
    #[doc(hidden)]
    pub fn file(&self) -> &ProjectFile {
        &self.file
    }

    #[doc(hidden)]
    pub const fn metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.metadata
    }

    #[doc(hidden)]
    pub const fn owner(&self) -> &SelectedRustBindingOwner {
        &self.owner
    }

    #[doc(hidden)]
    pub fn definitions(&self) -> &[SelectedRustBindingDefinition] {
        &self.definitions
    }

    #[doc(hidden)]
    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedRustBindingWorld {
    #[doc(hidden)]
    pub target: SelectedRustBindingDefinition,
    #[doc(hidden)]
    pub sites: Box<[SelectedRustBindingSite]>,
    #[doc(hidden)]
    pub completion: ResolutionCompletion,
}

impl SelectedRustBindingWorld {
    #[doc(hidden)]
    pub const fn target(&self) -> &SelectedRustBindingDefinition {
        &self.target
    }

    #[doc(hidden)]
    pub fn sites(&self) -> &[SelectedRustBindingSite] {
        &self.sites
    }

    #[doc(hidden)]
    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

impl<'store> SelectedResolutionOperation<'store, '_> {
    #[doc(hidden)]
    pub fn go_point_candidate_read_stats(&self) -> Option<(usize, usize)> {
        Some(self.ready.operation_candidate_cache.offered_row_stats())
    }

    #[doc(hidden)]
    pub fn mounts(&self) -> Result<&[SelectedResolutionOperationMount]> {
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
    #[doc(hidden)]
    pub fn mount_table(&self) -> SelectedMountTable<'_, 'store> {
        SelectedMountTable::new(&self.ready.inventory)
    }

    /// Bind the selected Go publication before any local fast path can answer.
    #[doc(hidden)]
    pub fn bind_go_context_publication(&self, publication: super::GoContextIdentity) {
        self.ready.bind_go_context_publication(publication);
    }

    /// Identities used by this request, for a projection that must release
    /// its selected connection before its final authority check.
    #[doc(hidden)]
    pub fn bound_go_context_publications(&self) -> Vec<super::GoContextIdentity> {
        self.ready
            .go_publications
            .borrow()
            .values()
            .cloned()
            .collect()
    }

    /// Revalidate the selection and authorize `value` as this operation's
    /// result.
    ///
    /// A root-less Rust graph build stages one crate at a time and combines
    /// their summaries, so the revalidation that used to end a single staging
    /// call belongs to the caller that owns the whole result.
    #[doc(hidden)]
    pub fn finish_native<T>(
        &mut self,
        value: T,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        self.ready.finish(value, completion, cancellation)
    }

    /// The context set that carries none of this operation's own relations.
    #[doc(hidden)]
    pub fn empty_contexts(
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

    #[doc(hidden)]
    pub fn project_rust_definitions(
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

    #[doc(hidden)]
    pub fn rust_definition_mount_for_target(
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

    #[doc(hidden)]
    pub fn selected_rust_definition_semantics_for_mount(
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
    #[doc(hidden)]
    pub fn locate_rust_definition(
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
        let units = RustMountUnits::new(&self.ready, &mount)?;
        match match_selected_definition(&mount, target, &rows, cancellation, |row| units.unit(row))?
        {
            std::ops::ControlFlow::Break(()) => {
                Ok(SelectedRustDefinitionSemanticOutcome::Cancelled)
            }
            std::ops::ControlFlow::Continue(found) => Ok(found.map_or(
                SelectedRustDefinitionSemanticOutcome::Missing,
                SelectedRustDefinitionSemanticOutcome::Found,
            )),
        }
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

    #[doc(hidden)]
    pub fn locate_rust_binding_definition(
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
    #[doc(hidden)]
    pub fn rust_binding_definition_units(
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
    #[doc(hidden)]
    pub fn rust_macro_capsule(&self, path: &str) -> Result<Option<SelectedMacroCapsule>> {
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

    #[doc(hidden)]
    pub fn selected_rust_usage_facts(
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
    #[doc(hidden)]
    pub fn select_textual_macro_definition(
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

    #[doc(hidden)]
    pub fn match_selected_textual_macro(
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
        // Macro-namespace selection also reaches #[proc_macro] and
        // #[proc_macro_attribute] functions. Their declaration properties retain
        // the AST's Function kind, unlike macro_rules!'s Macro kind.
        // Keep their binding target, but leave expansion to a procedural engine.
        let declaration_kind = connection
            .prepare_cached(
                "SELECT declaration_kind FROM source_rust_declaration_properties
                 WHERE blob_id = ?1 AND declaration_id = ?2",
            )?
            .query_row(
                rusqlite::params![definition_mount.blob_id(), declaration.get()],
                |row| row.get(0),
            )
            .optional()?
            .map(super::source_facts::decode_rust_declaration_kind)
            .transpose()?;
        if declaration_kind == Some(rust_facts::RustDeclarationKind::Function) {
            return Ok(None);
        }
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
        let Some(inputs) = invocation_mount.macro_rows().invocation_input_rows(
            connection,
            invocation_mount.blob_id(),
            arguments_start,
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
        let pending_files = {
            let overlay = self.ready.macro_overlay.borrow();
            files
                .iter()
                .filter(|file| {
                    !overlay
                        .prepared_files
                        .contains(&crate::path_utils::normalize_pattern(file))
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        if pending_files.is_empty() {
            return Ok(SelectedResolutionStageOutcome::Ready);
        }
        let outcome = self.prepare_selected_macro_reference_overlay_in_scope(
            &pending_files,
            self.ready.inventory.connection(),
            cancellation,
        )?;
        if matches!(outcome, SelectedResolutionStageOutcome::Ready) {
            self.ready.macro_overlay.borrow_mut().prepared_files.extend(
                pending_files
                    .iter()
                    .map(|file| crate::path_utils::normalize_pattern(file)),
            );
        }
        Ok(outcome)
    }

    #[doc(hidden)]
    pub fn clear_selected_macro_overlay(&self) -> Result<()> {
        super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory)
            .clear_facts()?;
        let mut slot = self.ready.macro_overlay.borrow_mut();
        slot.prepared_files.clear();
        drop(slot);
        self.ready.prepared_macro_files.borrow_mut().clear();
        self.ready.checked_macro_frontier_files.borrow_mut().clear();
        self.ready
            .registered_rust_caller_contexts
            .borrow_mut()
            .clear();
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
                        self.ready
                            .identity_content_digest(site.semantic().into(), cancellation)?,
                        self.ready
                            .identity_content_digest(definition.semantic.into(), cancellation)?,
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
            BatchCandidateRequest, EndpointSignature, SelectedNodeProvenance,
            SelectedTypedFactSource, StackPattern, TypedFactRequest,
        };

        let persisted = self.ready.lexical_source();
        let typed_source = self.ready.typed_source();
        let observed_lexical = SeamProfiled::observing(&persisted);
        let observed_typed = SeamProfiled::observing(&typed_source);
        let fragment_source = &observed_lexical;
        let stage = super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory);
        let mut input_identity =
            CanonicalHasher::new(b"bifrost-selected-macro-overlay-input-set:v1");
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
            let Some(source) = self.selected_rust_usage_facts_shared(caller, cancellation)? else {
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
            input_identity.field("path", file.as_bytes());
            input_identity.field("content_oid", capsule.content_oid().as_bytes());
            for input in &inputs {
                input_identity.field("invocation", &input.invocation.get().to_be_bytes());
                input_identity.field(
                    "input_start_byte",
                    &(input.tree.start_byte as u64).to_be_bytes(),
                );
                match input.native_frontier {
                    Some((site, scope)) => {
                        input_identity.field("frontier", &[1]);
                        input_identity.field("frontier_site", &site.get().to_be_bytes());
                        input_identity.field("frontier_scope", &scope.get().to_be_bytes());
                    }
                    None => {
                        input_identity.field("frontier", &[0]);
                    }
                }
            }
            let mut occurrence_start_lines = None;
            for input in inputs {
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
                // Name binding is independent of argument matching and
                // expansion replay. Only those later operations need a
                // native frontier.
                if input.native_frontier.is_none() {
                    if stage
                        .admit_macro_head_pair(
                            &host,
                            head,
                            seed.node(),
                            &definition_host,
                            definition,
                            definition_node,
                            self.ready
                                .identity_content_digest(head.into(), cancellation)?,
                            self.ready
                                .identity_content_digest(definition.into(), cancellation)?,
                            cancellation,
                        )?
                        .is_none()
                    {
                        return Ok(SelectedResolutionStageOutcome::Cancelled);
                    }
                    continue;
                }
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
                            self.ready
                                .identity_content_digest(head.into(), cancellation)?,
                            self.ready
                                .identity_content_digest(definition.into(), cancellation)?,
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
                let checkpoint_paths = paths
                    .iter()
                    .filter(|(_, path)| path.start().node() == seed.node())
                    .collect::<Vec<_>>();
                let checkpoints = checkpoint_paths
                    .iter()
                    .map(|(_, path)| path.end().node())
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    checkpoints.len(),
                    1,
                    "one macro head has one lexical entry checkpoint: caller={file:?}, invocation_start={start}, macro={name:?}, input_start={}, occurrence={:?}, native_frontier={:?}, module_scope={module_scope:?}, definition={definition_file:?}:{declaration:?}, head={head:?}, seed={:?}, checkpoints={checkpoints:?}, candidate_paths={checkpoint_paths:?}",
                    input.tree.start_byte,
                    input.invocation,
                    input.native_frontier,
                    seed.node(),
                );
                let checkpoint = *checkpoints.first().expect("macro checkpoint");
                let Some(provenance) = persisted.node_provenance(checkpoint, cancellation)? else {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                };
                let Some(checkpoint_scopes) =
                    persisted.node_scope_ordinals(std::iter::once(checkpoint), cancellation)?
                else {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                };
                let checkpoint_scope = checkpoint_scopes[&checkpoint].map(|(owner, scope)| {
                    assert_eq!(
                        owner, fragment,
                        "a macro checkpoint scope belongs to the capsule's host"
                    );
                    scope
                });
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
                    checkpoint_scope,
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
                        .expect("macro reference has source metadata");
                    if site.published_site_metadata().is_none() {
                        assert_eq!(
                            metadata.site_kind(),
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::SyntheticReference,
                            "only synthetic macro references lack a published source range"
                        );
                        continue;
                    }
                    let token = input
                        .tree
                        .tokens
                        .iter()
                        .position(|token| {
                            token.start_byte == metadata.start_byte()
                                && token.end_byte == metadata.end_byte()
                        })
                        .unwrap_or_else(|| {
                            let relative = metadata
                                .start_byte()
                                .checked_sub(input.tree.start_byte)
                                .zip(metadata.end_byte().checked_sub(input.tree.start_byte));
                            let reference_text = relative
                                .and_then(|(start, end)| input.tree.source.get(start..end))
                                .map(|text| text.chars().take(256).collect::<String>());
                            let overlapping_tokens = input
                                .tree
                                .tokens
                                .iter()
                                .enumerate()
                                .filter(|(_, token)| {
                                    token.start_byte < metadata.end_byte()
                                        && metadata.start_byte() < token.end_byte
                                })
                                .map(|(ordinal, token)| {
                                    (ordinal, token.syntax_kind.as_str(), token.start_byte, token.end_byte)
                                })
                                .collect::<Vec<_>>();
                            panic!(
                                "lowered macro reference has no canonical token occurrence: \
                                 path={file:?}, invocation_start={start}, macro={name:?}, arm={}, \
                                 invocation_occurrence={:?}, reference_span={}..{}, reference_text={reference_text:?}, \
                                 overlapping_input_tokens={overlapping_tokens:?}",
                                arm.arm_index,
                                input.invocation,
                                metadata.start_byte(),
                                metadata.end_byte(),
                            )
                        });
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
                if occurrence_start_lines.is_none() {
                    let loaded_occurrence_start_lines = {
                        let mut statement =
                            connection.prepare_cached(SELECTED_MACRO_OCCURRENCE_LINES_SQL)?;
                        let mut rows = statement.query([capsule.blob_id()])?;
                        let mut lines = Vec::<Option<usize>>::new();
                        while let Some(row) = rows.next()? {
                            let occurrence: usize = row.get(0)?;
                            let line: usize = row.get(1)?;
                            if lines.len() <= occurrence {
                                lines.resize(occurrence + 1, None);
                            }
                            assert!(
                                lines[occurrence].replace(line).is_none(),
                                "one source occurrence arena row per occurrence id"
                            );
                        }
                        lines
                            .into_iter()
                            .map(|line| {
                                line.expect("source occurrence arena indexes are contiguous")
                            })
                            .collect::<Vec<_>>()
                    };
                    occurrence_start_lines = Some(loaded_occurrence_start_lines);
                    #[cfg(any(test, feature = "test-support"))]
                    SELECTED_MACRO_OCCURRENCE_LINE_QUERY_COUNT
                        .with(|count| count.set(count.get() + 1));
                }
                let input_line = *occurrence_start_lines
                    .as_ref()
                    .expect("macro occurrence lines were loaded")
                    .get(input.occurrences[0].get() as usize)
                    .expect("macro input references a source occurrence in its host arena");
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
                        self.ready
                            .identity_content_digest(head.into(), cancellation)?,
                        self.ready
                            .identity_content_digest(definition.into(), cancellation)?,
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
        let input_identity = input_identity.finish();
        let mut overlay_cache_key =
            CanonicalHasher::new(b"bifrost-selected-macro-include-overlay-cache:v1");
        overlay_cache_key.field("selection", &self.ready.inventory.fingerprint());
        overlay_cache_key.field("macro-input-set", &input_identity);
        let overlay_cache_key = overlay_cache_key.finish();
        let cache = &self.ready.store.rust_macro_include_overlay_cache;
        let (include_overlay, cache_miss) = match cache.get(&overlay_cache_key) {
            Some(overlay) => (overlay, false),
            None => {
                let Some(overlay) = self.build_selected_macro_include_overlay_plan(
                    files,
                    connection,
                    cancellation,
                )?
                else {
                    return Ok(SelectedResolutionStageOutcome::Cancelled);
                };
                (Arc::new(overlay), true)
            }
        };
        if !self.apply_selected_macro_include_overlay_plan(&include_overlay, cancellation)? {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        if cache_miss {
            cache.insert(overlay_cache_key, Arc::clone(&include_overlay));
        }
        Ok(SelectedResolutionStageOutcome::Ready)
    }

    fn build_selected_macro_include_overlay_plan(
        &self,
        files: &[String],
        connection: &rusqlite::Connection,
        cancellation: &CancellationToken,
    ) -> Result<Option<PreparedMacroIncludeOverlay>> {
        let persisted = self.ready.lexical_source();
        let mut include_scopes = BTreeMap::<
            (BindingFragmentId, ResolutionScopeId),
            BTreeSet<(BindingFragmentId, ResolutionScopeId)>,
        >::new();
        let mut facts_by_fragment = HashMap::default();
        let mut pending_hosts = files.iter().map(PathBuf::from).collect::<Vec<_>>();
        let mut visited_hosts = HashSet::default();
        while let Some(host_file) = pending_hosts.pop() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if !visited_hosts.insert(host_file.clone()) {
                continue;
            }
            let Some(host) = self.rust_macro_capsule(&selected_path_key(&host_file))? else {
                continue;
            };
            let Some(host_facts) =
                self.selected_rust_usage_facts_shared(&host_file, cancellation)?
            else {
                continue;
            };
            facts_by_fragment.insert(host.mount().fragment(), host_facts.clone());
            let host_path = crate::path_utils::normalize_pattern(&host_file.to_string_lossy());
            for edge in &host_facts.include_edges {
                let included = connection
                    .prepare_cached(rust_crate_context::MACRO_INCLUDED_FILE)?
                    .query_map(rusqlite::params![host_path, edge.file_name], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<BTreeSet<_>>>()?;
                for included_file in included {
                    let included_file = PathBuf::from(included_file);
                    let Some(included) =
                        self.rust_macro_capsule(&selected_path_key(&included_file))?
                    else {
                        continue;
                    };
                    if let Some(facts) =
                        self.selected_rust_usage_facts_shared(&included_file, cancellation)?
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
                            |row| row.get::<_, Option<u32>>(0),
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
        let mut components = Vec::new();
        let mut path_count = 0usize;
        let mut binding_pair_count = 0usize;
        for &initial in include_scopes.keys() {
            if !visited_scopes.insert(initial) {
                continue;
            }
            let mut pending = vec![initial];
            let mut component = vec![initial];
            while let Some(scope) = pending.pop() {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                for &adjacent in &include_scopes[&scope] {
                    if visited_scopes.insert(adjacent) {
                        pending.push(adjacent);
                        component.push(adjacent);
                    }
                }
            }

            let mut include_demands = BTreeMap::new();
            let mut explicit_names = HashSet::default();
            let mut prepared_scopes = Vec::with_capacity(component.len());
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
                let Some(recipes) = persisted.lookup_recipes(mount.ordinal(), cancellation)? else {
                    return Ok(None);
                };
                for recipe in recipes {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    if !matches!(
                        recipe.namespace(),
                        ResolutionNamespace::Type
                            | ResolutionNamespace::Value
                            | ResolutionNamespace::Macro
                    ) {
                        continue;
                    }
                    assert_eq!(
                        recipe.identity_domain(),
                        language_identity_domain(Language::Rust)
                    );
                    include_demands.insert(recipe.semantic(&self.ready.shared_names()), recipe);
                }
                let Some(destination) =
                    persisted.scope_head_node_of(fragment, scope, cancellation)?
                else {
                    return Ok(None);
                };
                prepared_scopes.push((fragment, scope, destination));
            }
            let mut origins = Vec::with_capacity(component.len());
            for &(origin_fragment, origin_scope) in &component {
                let original_paths =
                    persisted.include_scope_paths(origin_fragment, origin_scope, cancellation)?;
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let source = facts_by_fragment
                    .get(&origin_fragment)
                    .expect("glob origin has source facts");
                let mut present_imports = HashSet::default();
                for (identity, path) in &original_paths {
                    if cancellation.is_cancelled() {
                        return Ok(None);
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
                let mut globs = Vec::new();
                for import in source
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
                        if present_imports.insert(key) {
                            globs.push(PreparedMacroIncludeGlob {
                                import: import.clone(),
                                demand: demand.clone(),
                            });
                        }
                    }
                }

                let ends = original_paths
                    .iter()
                    .map(|(_, path)| path.end().node())
                    .collect::<Vec<_>>();
                let classifications = persisted.classify_endpoint_nodes(&ends, cancellation)?;
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let paths = original_paths
                    .into_iter()
                    .zip(classifications)
                    .map(
                        |((identity, path), classification)| PreparedMacroIncludePath {
                            identity,
                            path,
                            end_kind: classification
                                .definition()
                                .map(BindingNodeKind::Definition)
                                .unwrap_or(BindingNodeKind::Scope),
                        },
                    )
                    .collect::<Vec<_>>();
                path_count += paths.len() + globs.len();
                binding_pair_count +=
                    (paths.len() + globs.len()) * prepared_scopes.len().saturating_sub(1);
                origins.push(PreparedMacroIncludeOrigin {
                    fragment: origin_fragment,
                    scope: origin_scope,
                    paths,
                    globs,
                });
            }
            components.push(PreparedMacroIncludeComponent {
                scopes: prepared_scopes,
                origins,
            });
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(PreparedMacroIncludeOverlay {
            components,
            path_count,
            binding_pair_count,
        }))
    }

    fn apply_selected_macro_include_overlay_plan(
        &self,
        overlay: &PreparedMacroIncludeOverlay,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        use crate::analyzer::resolution::LoweredResolutionFragment;

        let persisted = self.ready.lexical_source();
        let stage = super::resolution_stage::SelectedResolutionStage::new(&self.ready.inventory);
        let mut mount_records = HashMap::default();
        for component in &overlay.components {
            for &(fragment, _, _) in &component.scopes {
                if mount_records.contains_key(&fragment) {
                    continue;
                }
                let mount = self
                    .ready
                    .inventory
                    .mount_record_for_fragment(fragment)?
                    .expect("splice scope is mounted");
                mount_records.insert(fragment, mount);
            }
        }

        let mut generated = Vec::new();
        let mut generated_ends = Vec::new();
        for (component_index, component) in overlay.components.iter().enumerate() {
            for (origin_index, origin) in component.origins.iter().enumerate() {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                let origin_mount = mount_records
                    .get(&origin.fragment)
                    .expect("include origin is a component scope");
                for glob in &origin.globs {
                    let (lexical, catalog) = LoweredResolutionFragment::selected_include_glob(
                        origin.fragment,
                        &self.ready.shared_names(),
                        &glob.import,
                        &glob.demand,
                    );
                    let Some((identity, path)) =
                        stage.admit_include_glob(origin_mount, lexical, catalog, cancellation)?
                    else {
                        return Ok(false);
                    };
                    generated_ends.push(path.end().node());
                    generated.push((component_index, origin_index, identity, path));
                }
            }
        }
        let generated_classifications =
            persisted.classify_endpoint_nodes(&generated_ends, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut generated_by_origin = overlay
            .components
            .iter()
            .map(|component| vec![Vec::new(); component.origins.len()])
            .collect::<Vec<Vec<Vec<PreparedMacroIncludePath>>>>();
        for ((component, origin, identity, path), classification) in
            generated.into_iter().zip(generated_classifications)
        {
            generated_by_origin[component][origin].push(PreparedMacroIncludePath {
                identity,
                path,
                end_kind: classification
                    .definition()
                    .map(BindingNodeKind::Definition)
                    .unwrap_or(BindingNodeKind::Scope),
            });
        }

        let mut pairs = Vec::with_capacity(overlay.binding_pair_count);
        for (component_index, component) in overlay.components.iter().enumerate() {
            for (origin_index, origin) in component.origins.iter().enumerate() {
                let origin_mount = mount_records
                    .get(&origin.fragment)
                    .expect("include origin is a component scope");
                for path in origin
                    .paths
                    .iter()
                    .chain(&generated_by_origin[component_index][origin_index])
                {
                    for &(destination_fragment, destination_scope, destination) in &component.scopes
                    {
                        if (destination_fragment, destination_scope)
                            == (origin.fragment, origin.scope)
                        {
                            continue;
                        }
                        let destination_mount = mount_records
                            .get(&destination_fragment)
                            .expect("splice scope is mounted");
                        pairs.push(super::resolution_stage::SelectedIncludeBindingPair {
                            destination_host: destination_mount,
                            destination,
                            origin_host: origin_mount,
                            original_identity: path.identity,
                            original: &path.path,
                            path_content: self.ready.identity_content_digest(
                                path.identity.path().into(),
                                cancellation,
                            )?,
                            destination_content: self
                                .ready
                                .identity_content_digest(destination.into(), cancellation)?,
                            end_kind: path.end_kind,
                        });
                    }
                }
            }
        }
        Ok(stage
            .admit_include_binding_pairs(&pairs, cancellation)?
            .is_some())
    }

    /// Forget what the textual-macro module walk has answered so far.
    ///
    /// Called at a crate-stage boundary, where a whole-workspace request would
    /// otherwise accumulate one `RustUsageFacts` per file every stage's walks
    /// read. Nothing else in the request refers to these answers, so dropping
    /// them can only cost a reread.
    #[doc(hidden)]
    pub fn clear_selected_macro_walk_answers(&self) {
        *self.ready.macro_walk.borrow_mut() = SelectedTextualMacroWalkMemo::default();
    }

    /// Prepare generated frontiers only for files admitted by this query.
    #[doc(hidden)]
    pub fn prepare_selected_macro_frontiers_for_files(
        &self,
        files: &[&Path],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        self.ready.inventory.enable_derive_helper_decisions();
        let needs_frontier_check = {
            let checked = self.ready.checked_macro_frontier_files.borrow();
            files.iter().any(|file| !checked.contains(*file))
        };
        if !needs_frontier_check {
            return Ok(SelectedResolutionStageOutcome::Ready);
        }
        let _macro_timing = crate::profiling::scope("rust_caller::macro_frontiers");
        let pending_callers = {
            let checked = self.ready.checked_macro_frontier_files.borrow();
            files
                .iter()
                .copied()
                .filter(|file| !checked.contains(*file))
                .collect::<Vec<_>>()
        };
        let macro_item_hosts = self.rust_macro_item_hosts(&pending_callers)?;
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        let mut requested = pending_callers
            .iter()
            .map(|file| file.to_path_buf())
            .collect::<Vec<_>>();
        {
            let checked = self.ready.checked_macro_frontier_files.borrow();
            requested.extend(
                macro_item_hosts
                    .into_iter()
                    .filter(|host| !checked.contains(host)),
            );
        }
        requested.sort_unstable();
        requested.dedup();
        let mut demanded = requested.clone();
        {
            let checked = self.ready.checked_macro_frontier_files.borrow();
            for file in &requested {
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
                    let host = PathBuf::from(host?);
                    if !checked.contains(&host) {
                        demanded.push(host);
                    }
                }
            }
        }
        demanded.sort_unstable();
        demanded.dedup();
        if demanded.is_empty() {
            return Ok(if cancellation.is_cancelled() {
                SelectedResolutionStageOutcome::Cancelled
            } else {
                SelectedResolutionStageOutcome::Ready
            });
        }
        let mut macro_files = Vec::new();
        for caller in &demanded {
            let Some(mount) = self.rust_macro_capsule(&selected_path_key(caller))? else {
                continue;
            };
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            if mount
                .macro_rows()
                .has_inputs(self.ready.inventory.connection(), mount.blob_id())?
            {
                macro_files.push(mount.mount().persisted_relative_path().to_owned());
            }
        }
        if macro_files.is_empty() {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            self.ready
                .checked_macro_frontier_files
                .borrow_mut()
                .extend(demanded);
            return Ok(SelectedResolutionStageOutcome::Ready);
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
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        self.ready
            .checked_macro_frontier_files
            .borrow_mut()
            .extend(demanded);
        Ok(SelectedResolutionStageOutcome::Ready)
    }

    #[doc(hidden)]
    pub fn prepare_selected_macro_frontiers(
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
        let mut nearest = None;
        let mut selected = BTreeSet::new();
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(rust_crate_context::SELECT_IMPORTED_MACRO_DEFINITION)?;
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

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn attach_active_reverse_sql_work_trace(&self) {
        if !rust_reverse_rows::reverse_sql_work_trace_active() {
            return;
        }
        rust_reverse_rows::attach_reverse_sql_work_trace(self.ready.inventory.connection());
    }

    #[doc(hidden)]
    pub fn ensure_selected_rust_inputs(&self, cancellation: &CancellationToken) -> Result<bool> {
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
    #[doc(hidden)]
    pub fn rust_root_halves(
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
                mount.persisted_relative_path, head.start_byte, head.end_byte,
                (SELECT properties.visibility
                 FROM source_rust_item_macro_expansions AS expansion
                 CROSS JOIN source_rust_module_scopes AS scope
                   ON scope.blob_id=expansion.blob_id
                 CROSS JOIN source_rust_module_declarations AS module
                   ON module.blob_id=scope.blob_id AND module.declaration_id=scope.declaration_id
                 CROSS JOIN source_declarations AS declaration
                   ON declaration.blob_id=module.blob_id AND declaration.declaration_id=module.declaration_id
                 CROSS JOIN source_rust_declaration_properties AS properties
                   ON properties.blob_id=module.blob_id AND properties.declaration_id=module.declaration_id
                 WHERE expansion.blob_id=evidence.value ->> '$.member_blob'
                   AND scope.ordinal<>0
                   AND expansion.invocation_occurrence_id=evidence.value ->> '$.invocation_occurrence'
                   AND declaration.start_byte<=expansion.invocation_start_byte
                   AND expansion.invocation_end_byte<=declaration.end_byte
                 ORDER BY declaration.end_byte-declaration.start_byte
                 LIMIT 1)
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
            row.get::<_, Option<String>>(5)?,
        ))
    })?;
    let mut gaps = Vec::new();
    for row in rows {
        let (reason, name, path, start, end, visibility) = row?;
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
            private_module_route: visibility.is_some_and(|visibility| visibility != "public"),
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
    let mut inventories = HashSet::default();
    for reason in reasons.iter() {
        let semantic = match reason {
            ResolutionIncompleteReason::UnsupportedSemantic(semantic)
            | ResolutionIncompleteReason::OpenBoundary {
                semantic,
                status: crate::analyzer::structural::BoundaryStatus::WorkspaceLocal,
            } => semantic,
            _ => continue,
        };
        if let Some(("UnsupportedMacroGeneratedModule", detail)) =
            ready.context_identities.named_reason(*semantic)
        {
            if inventories.insert(*semantic) {
                names.extend(inventory_macro_gaps(ready, &detail, *semantic)?);
            }
            continue;
        }
        if !matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(_)) {
            continue;
        }
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
                private_module_route: false,
            });
        }
    }
    Ok(names)
}

/// The selected binding reasons that name an attribute-generated item
/// surface. The source item remains authored, but the producer does not
/// publish declarations added by its derive or attribute macro.
fn generated_item_surface_gaps(
    ready: &ReadySelectedResolution<'_, '_>,
    completion: &ResolutionCompletion,
) -> Result<Vec<SemanticId>> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(Vec::new());
    };
    let origin = crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface,
        ),
    );
    let conn = ready.inventory.connection();
    let mut gaps = Vec::new();
    for reason in reasons.iter() {
        let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
            continue;
        };
        let context_reason = ready.context_identities.named_reason(*semantic);
        if context_reason
            .as_ref()
            .is_some_and(|(name, _)| *name == rust_crate_context::GENERATED_ITEM_SURFACE_REASON)
        {
            gaps.push(*semantic);
            continue;
        }
        let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
            continue;
        };
        if conn
            .prepare_cached(rust_crate_context::REASON_GAP_ORIGIN)?
            .query_row(rusqlite::params![ordinal, key], |row| row.get::<_, i64>(0))
            .optional()?
            == Some(origin)
        {
            gaps.push(*semantic);
        }
    }
    gaps.sort_unstable();
    gaps.dedup();
    Ok(gaps)
}

/// The item-position function-like macro invocation that published this gap
/// reason as its input frontier.
///
/// An item-position function-like macro's generated surface belongs to the
/// invocation, not to an attribute on one source item: the expansion can add
/// members to every type the invocation's lexical scope owns, but it cannot
/// establish that one of those members is absent. `native_gap_site` records the
/// gap site the invocation's input frontier published, so this join names the
/// invocation exactly.
const ITEM_MACRO_INVOCATION_NAME_SQL: &str = "SELECT head.macro_name
 FROM resolution_gap_reasons AS gap
 JOIN source_rust_macro_inputs AS input
   ON input.blob_id = gap.blob_id AND input.native_gap_site = gap.site
 JOIN source_rust_macro_invocations AS head
   ON head.blob_id = input.blob_id
  AND head.occurrence_id = input.invocation_occurrence_id
 WHERE gap.blob_id = ?1 AND gap.reason = ?2 AND gap.origin = ?3";

fn item_macro_invocation_name(
    ready: &ReadySelectedResolution<'_, '_>,
    semantic: SemanticId,
) -> Result<Option<String>> {
    let origin = crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface,
        ),
    );
    let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
        return Ok(None);
    };
    let Some(mount) = ready
        .inventory
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(ordinal))?
    else {
        return Ok(None);
    };
    let name = ready
        .inventory
        .connection()
        .prepare_cached(ITEM_MACRO_INVOCATION_NAME_SQL)?
        .query_row(rusqlite::params![mount.blob_id(), key, origin], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    Ok(name)
}

/// Classify each unsupported semantic the selected lookup actually retained.
/// The native macro-input join is the same producer fact used by Rust reverse
/// candidate discovery: it separates an explicit invocation that can invent
/// arbitrary items from an attribute-generated surface.
fn retained_gap_frontiers(
    ready: &ReadySelectedResolution<'_, '_>,
    completion: &ResolutionCompletion,
) -> Result<Vec<SelectedRustGapFrontier>> {
    const GAP_FRONTIER_SQL: &str = "SELECT reason.origin,
        EXISTS (
          SELECT 1 FROM main.source_rust_macro_inputs AS input
          WHERE input.blob_id=reason.blob_id
            AND input.native_gap_site=reason.site
        )
        FROM temp.selected_resolution_mounts AS mount
        JOIN main.resolution_gap_reasons AS reason
          ON reason.blob_id=mount.blob_id
        WHERE mount.mount_ordinal=?1 AND reason.reason=?2";
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(Vec::new());
    };
    let conn = ready.inventory.connection();
    let mut statement = conn.prepare_cached(GAP_FRONTIER_SQL)?;
    let mut frontiers = Vec::new();
    for reason in reasons.iter() {
        let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
            continue;
        };
        let persisted = semantic
            .ordinal()
            .zip(semantic.local_key())
            .map(|(ordinal, key)| {
                statement
                    .query_row(rusqlite::params![ordinal, key], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))
                    })
                    .optional()
            })
            .transpose()?
            .flatten();
        let kind = if persisted.is_some_and(|(_, macro_input)| macro_input) {
            SelectedRustGapFrontierKind::ExplicitMacroInvocation
        } else if let Some((origin, _)) = persisted {
            match crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_from_code(
                origin,
            ) {
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface,
                ) => SelectedRustGapFrontierKind::GeneratedItemSurface,
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder,
                ) => SelectedRustGapFrontierKind::UnsupportedScopeOrBinder,
                _ => SelectedRustGapFrontierKind::Other,
            }
        } else if ready
            .context_identities
            .named_reason(*semantic)
            .is_some_and(|(name, _)| name == rust_crate_context::GENERATED_ITEM_SURFACE_REASON)
        {
            SelectedRustGapFrontierKind::GeneratedItemSurface
        } else {
            SelectedRustGapFrontierKind::Other
        };
        frontiers.push(SelectedRustGapFrontier {
            semantic: *semantic,
            kind,
        });
    }
    frontiers.sort_unstable_by_key(|frontier| (frontier.semantic, frontier.kind.evidence_name()));
    frontiers.dedup();
    Ok(frontiers)
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
/// Compare complete hydrated source identities in one selected mount. Package
/// naming is supplied by the language; iteration and uniqueness are shared.
fn match_selected_definition(
    mount: &SelectedResolutionOperationMount,
    target: &CodeUnit,
    rows: &[(ResolutionLocalKey, super::HydratedCandidateRow)],
    cancellation: &CancellationToken,
    mut hydrate: impl FnMut(&super::HydratedCandidateRow) -> Result<CodeUnit>,
) -> Result<std::ops::ControlFlow<(), Option<SemanticId>>> {
    let mut found = None;
    for (definition, row) in rows {
        if cancellation.is_cancelled() {
            return Ok(std::ops::ControlFlow::Break(()));
        }
        if hydrate(row)? == *target {
            assert!(
                found.is_none(),
                "one target has one selected definition: {target:?}"
            );
            found = Some(SemanticId::local(
                mount.ordinal().get(),
                u32::try_from(definition.get()).map_err(|_| {
                    StoreError::new(format!(
                        "a persisted local key is a catalog position and fits u32: {definition:?}"
                    ))
                })?,
            ));
        }
    }
    Ok(std::ops::ControlFlow::Continue(found))
}

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
        Ok(super::code_unit_from_hydrated_row(
            row,
            &self.file,
            fq,
            package_segment_count,
        ))
    }
}

fn selected_reference_source_sites(
    source: &(impl BatchResolutionFragmentSource + ?Sized),
    mounts: SelectedMountTable<'_, '_>,
    project_root: &std::path::Path,
    references: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Option<Box<[SelectedReferenceSourceSite]>>> {
    let mut source_sites = Vec::with_capacity(references.len());
    for reference_batch in references.chunks(MAX_REFERENCE_SEEDS_PER_BATCH) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let queries = reference_batch
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
        references.len(),
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
                    | SelectedRustSourceDefinition::UniverseEntry
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
                        | SelectedRustSourceDefinition::UniverseEntry
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

#[doc(hidden)]
pub fn project_rust_source_definitions(
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
    let mut universe_entries = BTreeSet::new();
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
                // A fixed universe entry is a language builtin, not a
                // declaration of any file: it is outside the source
                // vocabulary, so it answers itself and every sibling target
                // keeps its own definition. Any other shared name is still a
                // question this projection cannot answer.
                if lexical
                    .shared_name_digest_for_identity(definition, cancellation)?
                    .is_some_and(|digest| {
                        crate::analyzer::resolution::universe_is_entry_digest(
                            crate::analyzer::Language::Rust,
                            digest,
                        )
                    })
                {
                    universe_entries.insert(definition);
                    continue;
                }
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
        if universe_entries.contains(definition) {
            projected.push((*definition, SelectedRustSourceDefinition::UniverseEntry));
            continue;
        }
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
            named_reasons: resolution
                .projected_frontiers()
                .iter()
                .map(|frontier| named_reason_details(ready, frontier.completion()))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect(),
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
        let mut statement = ready
            .inventory
            .connection()
            .prepare_cached(rust_crate_context::BOUNDARY_IMPORT_NAMES)?;
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

/// Project the parser-selected site; source text is used only to render its spelling.
fn obligation_site_details(
    ready: &ReadySelectedResolution<'_, '_>,
    ordinal: u32,
    site: i64,
) -> Result<Option<serde_json::Value>> {
    let mount = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let range = ready.inventory.connection().prepare_cached(
        "SELECT COALESCE(site.start_byte, declaration.name_start_byte, declaration.start_byte),
                COALESCE(site.end_byte, declaration.name_end_byte, declaration.end_byte)
         FROM resolution_sites AS site
         LEFT JOIN source_native_declaration_bridges AS bridge
           ON bridge.blob_id=site.blob_id AND bridge.source_site=site.site
         LEFT JOIN source_declarations AS declaration
           ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
         WHERE site.blob_id=?1 AND site.site=?2"
    )?.query_row(rusqlite::params![mount.blob_id(), site], |row| {
        Ok((row.get::<_, Option<usize>>(0)?, row.get::<_, Option<usize>>(1)?))
    }).optional()?;
    let Some((Some(start), Some(end))) = range else {
        return Ok(None);
    };
    let file = ProjectFile::new(ready.project.root(), mount.persisted_relative_path());
    let source = ready.project.read_source(&file)?;
    let spelling = source.get(start..end).ok_or_else(|| {
        StoreError::corrupt(format!(
            "obligation site range {start}..{end} is invalid in {}",
            mount.persisted_relative_path()
        ))
    })?;
    let starts = brokk_bifrost_core::text_utils::compute_line_starts(&source);
    let (line, column) =
        brokk_bifrost_core::text_utils::line_column_for_offset(&source, &starts, start);
    Ok(Some(
        serde_json::json!({"path": mount.persisted_relative_path(), "line": line,
        "column": column, "spelling": spelling}),
    ))
}

fn persisted_obligation_details(
    ready: &ReadySelectedResolution<'_, '_>,
    semantic: SemanticId,
) -> Result<Option<(&'static str, String)>> {
    let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
        return Ok(None);
    };
    let mount = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    // Preserve other frontends' existing diagnostic contracts.
    if !matches!(
        mount.semantic_language(),
        Language::Kotlin | Language::Java | Language::Scala
    ) {
        return Ok(None);
    }
    let gap = ready
        .inventory
        .connection()
        .prepare_cached(
            "SELECT site, origin FROM resolution_gap_reasons WHERE blob_id=?1 AND reason=?2",
        )?
        .query_row(rusqlite::params![mount.blob_id(), key], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    let (site, origin) = if let Some((site, origin)) = gap {
        (
            site,
            super::resolution_prepare::resolution_rows::gap_origin_from_code(origin),
        )
    } else {
        let property = ready.inventory.connection().prepare_cached(
            "SELECT site, kind FROM resolution_definition_property_gaps WHERE blob_id=?1 AND reason=?2"
        )?.query_row(rusqlite::params![mount.blob_id(), key], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        }).optional()?;
        let Some((site, kind)) = property else {
            return Ok(None);
        };
        let property = super::resolution_prepare::typed_rows::decode_definition_property_gap_fields(
            semantic, kind, semantic, semantic, site,
        );
        (
            site,
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(property.kind()),
        )
    };
    use crate::analyzer::resolution::LoweringGapOrigin;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
    let kind = match origin {
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability) => {
            "UnsupportedCallApplicability"
        }
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal) => {
            "UnsupportedHierarchyTraversal"
        }
        _ => "UnsupportedSemantic",
    };
    Ok(Some((
        kind,
        serde_json::json!({"kind": kind, "semantic": origin.kind().label(),
        "site": obligation_site_details(ready, ordinal, site)?})
        .to_string(),
    )))
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
        let semantic = match reason {
            ResolutionIncompleteReason::UnsupportedSemantic(semantic) => semantic,
            // A context also names an open boundary it can explain, such as
            // the implicit prelude item an unqualified Rust name falls through
            // to. Publishing that evidence lets a caller tell the prelude
            // item from any other unindexed boundary (#3757).
            ResolutionIncompleteReason::OpenBoundary { semantic, .. } => {
                if let Some((name, evidence)) = ready.context_identities.named_reason(*semantic) {
                    named.push((name, evidence.to_string()));
                }
                continue;
            }
            _ => continue,
        };
        if let Some((name, evidence)) = ready.context_identities.named_reason(*semantic) {
            named.push((name, evidence.to_string()));
            continue;
        }
        if let Some(detail) = persisted_obligation_details(ready, *semantic)? {
            named.push(detail);
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
    for (_, evidence) in &mut named {
        *evidence = feature_invariant_reason_json(std::mem::take(evidence));
    }
    named.sort_unstable();
    named.dedup();
    Ok(named)
}

/// Render reason evidence with sorted object keys when it is JSON.
///
/// `serde_json` orders object keys by insertion only under its
/// `preserve_order` feature, and Cargo unifies that feature into this crate
/// whenever a build also selects a crate that enables it (the policy crate's
/// tests do). Messages built with `json!` would otherwise render differently
/// in a workspace build and a single-crate build (#6112). Plain-text evidence
/// is returned unchanged.
pub(super) fn feature_invariant_reason_json(evidence: String) -> String {
    match serde_json::from_str::<serde_json::Value>(&evidence) {
        Ok(mut value) => {
            value.sort_all_objects();
            value.to_string()
        }
        Err(_) => evidence,
    }
}

/// Turn one resolved reference into a projected answer.
///
/// Shared by the eager and demand point routes so the two cannot drift in what
/// they do with an answer; they differ only in how the answer was produced.
fn project_rust_reference_unit(
    _operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    _answer: &FactResolutionAnswer,
    _ready: &ReadySelectedResolution<'_, '_>,
    _mounts: SelectedMountTable<'_, '_>,
    _session: &ResolutionSession,
    _cancellation: &CancellationToken,
) -> Result<SelectedResolutionOperationOutcome<()>> {
    Ok(SelectedResolutionOperationOutcome::Native(()))
}

fn assemble_rust_reference_answer<T>(
    context: &RustReferenceAnswerContext<'_, '_, '_>,
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    mut resolution: FactResolutionAnswer,
    resolve_prefix: &mut impl FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        SemanticId,
    ) -> Result<FactDemandResolution>,
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
    let resolved_targets_empty = resolved_targets.is_empty();
    if let Some(reason) = rust_type_parameter_member_reason(
        ready,
        mounts,
        operation,
        resolve_prefix,
        locator.relative_path(),
        reference,
        &resolution,
        session,
        cancellation,
    )? {
        resolution.combine_binding_completion(&reason);
    }
    if resolved_targets_empty
        && matches!(
            resolution.binding().completion(),
            ResolutionCompletion::Incomplete(_)
        )
        && let Some(spelling) = ready
            .rust_prefix_spellings(&ready.lexical_source(), &[reference], cancellation)?
            .remove(&reference)
    {
        let generated_surface = rust_crate_context::generated_surface_prefix_boundary(
            ready.inventory.connection(),
            &ready.context_identities,
            &[],
            Some(provenance.ordinal().get()),
            Some(&spelling),
            &[],
        )?;
        resolution.combine_binding_completion(&generated_surface);
    }
    let named_reasons = named_reason_details(ready, resolution.binding().completion())?;
    let mut macro_expansion_gaps =
        unexpanded_item_macro_gaps(ready, resolution.binding().completion())?;
    let mut generated_surface_gaps =
        generated_item_surface_gaps(ready, resolution.binding().completion())?;
    // #5487: an item-position function-like macro invocation keeps the member
    // surfaces of every type its lexical scope owns open, including a lookup
    // that finds an authored member. Its generated surface belongs to the
    // invocation rather than to an attribute on one source item, so a member
    // lookup gated by it stays incomplete with the invocation named, instead of
    // closing as an attribute-style boundary that would decide the member
    // absent. The invocation can add a member the authored impls do not
    // declare, and it cannot prove one absent.
    if resolution
        .site_metadata()
        .is_some_and(|metadata| metadata.site_kind() == ResolutionSiteKind::MemberReference)
    {
        let mut retained = Vec::with_capacity(generated_surface_gaps.len());
        for semantic in generated_surface_gaps {
            match item_macro_invocation_name(ready, semantic)? {
                Some(name) => {
                    definition_names.push((semantic, format!("unexpanded item macro {name}!")))
                }
                None => retained.push(semantic),
            }
        }
        generated_surface_gaps = retained;
    }
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
                // Named completion evidence already publishes this identity.
                // Keep its invocation coordinates without publishing the same
                // inventory again through a differently ordered JSON object.
                if ready.context_identities.named_reason(semantic).is_none() {
                    macro_expansion_gaps.extend(inventory_macro_gaps(ready, &detail, semantic)?);
                    inventory_details.push(detail);
                }
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
    let retained_gap_frontiers = retained_gap_frontiers(ready, resolution.binding().completion())?;
    let enumeration =
        lexical.reference_inventory_completion(mount.fragment(), cancellation, session)?;
    let Some(enumeration) = lexical.close_completion(&enumeration, cancellation)? else {
        return Ok(SelectedResolutionOperationOutcome::Cancelled(
            enumeration.combine(&cancelled_completion()),
        ));
    };
    for (key, digest) in crate::analyzer::resolution::worker_transport::forward_identity_digests(
        operation,
        &resolution,
        &enumeration,
    )? {
        let previous = ready
            .inventory
            .authority_request_memo()
            .borrow_mut()
            .canonical_digests
            .insert(key, digest);
        assert!(
            previous.is_none_or(|previous| previous == digest),
            "one selected operation never reassigns an identity alias: {key:?}"
        );
    }
    Ok(SelectedResolutionOperationOutcome::Native(
        SelectedRustReferenceAnswer {
            macro_expansion_gaps,
            generated_surface_gaps,
            retained_gap_frontiers,
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
            | SelectedRustSourceDefinition::UniverseEntry
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
#[doc(hidden)]
pub fn selected_mount_lookup<'a>(
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
#[doc(hidden)]
pub struct RustRootHalfScope {
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
    #[doc(hidden)]
    pub fn new<'mount>(
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
        .prepare_cached(rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE.as_str())?
        .query_row(
            rusqlite::params![
                mount.get(),
                key,
                name,
                super::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ],
            |row| row.get(0),
        )
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
                digest.field(
                    "mount",
                    &ready
                        .inventory
                        .mount_record_by_ordinal(mount)?
                        .fragment_digest()
                        .as_bytes(),
                );
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
    resolve_prefix: &mut impl FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        SemanticId,
    ) -> Result<FactDemandResolution>,
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
    // Answer decoration may need a prefix the root scheduler did not visit,
    // including when the selected operation reused a completed root answer.
    // Use the entry point's resolver so demand-backed callers close that
    // prefix's relations before reading them (#5223).
    let parameter = match resolve_prefix(operation, prefix)? {
        FactDemandResolution::Ready(parameter) => parameter,
        FactDemandResolution::Cancelled(completion) => return Ok(Some(completion)),
    };
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
    let connection = ready.inventory.connection();
    let mut targets = Vec::new();
    for module in rows.modules_for_mount(mounts, mount, &[], cancellation)? {
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
            // The crate rows answer with the declaration a path reaches at
            // the crate root, so this fallback admits only names the crate
            // root really exports by path. A `macro_rules!` is textually
            // scoped: its site's own namespace is the macro namespace, and
            // only `#[macro_export]` moves it to the crate root. Without that
            // attribute the source-order walk owns the name (#4925). A
            // procedural macro is an ordinary function promoted into the
            // macro namespace (`#[proc_macro]`, `#[proc_macro_attribute]`),
            // so its site's own namespace is the value namespace and a facade
            // glob re-export such as `pub use rocket_codegen::*;` carries it
            // to the `#[macro_use] extern crate` binding this fallback asks
            // for (#3072).
            let exported_by_path = connection
                .prepare_cached(
                    r#"SELECT COALESCE(properties.macro_exported=1 OR sites.namespace<>'macro',0)
                       FROM resolution_rust_declaration_authorities AS authority
                       CROSS JOIN source_rust_declaration_properties AS properties
                         ON properties.blob_id=authority.blob_id
                        AND properties.declaration_id=authority.declaration
                       CROSS JOIN resolution_semantic_sites AS sites
                         ON sites.blob_id=authority.blob_id
                        AND sites.semantic_key=authority.semantic_key
                        AND sites.semantic_role='definition'
                       WHERE authority.blob_id=?1 AND authority.source_site=?2"#,
                )?
                .query_row(rusqlite::params![export.blob, site], |row| {
                    row.get::<_, bool>(0)
                })
                .optional()?
                .unwrap_or(false);
            if !exported_by_path {
                continue;
            }
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

#[doc(hidden)]
pub enum LocatedSemantic {
    Found(SemanticId),
    Missing,
    Cancelled,
}

#[doc(hidden)]
pub enum LocatedSemantics {
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

/// Borrowed cells to register for one context; full consumers pass the whole
/// blueprint, while named contexts pass only their operation-owned delta.
struct SelectedContextRegistrationCells<'a> {
    shared: &'a [ResolutionSemanticIdentity],
    boundaries: &'a [BindingNodeId],
    gaps: &'a BTreeSet<SemanticId>,
}

#[doc(hidden)]
pub enum ContextRegistrationOutcome {
    Ready,
    Cancelled,
}

fn register_selected_rust_caller_context_in_session(
    ready: &ReadySelectedResolution<'_, '_>,
    caller: &Path,
    crate_keys: &[[u8; 32]],
    access: RustDeclarationAccessKind,
    blueprint: &SelectedFactOperationBlueprint,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<ContextRegistrationOutcome> {
    if cancellation.is_cancelled() {
        return Ok(ContextRegistrationOutcome::Cancelled);
    }
    let key = RustCallerRegistrationKey {
        caller: caller.to_path_buf(),
        crate_keys: crate_keys.to_vec(),
        access,
    };
    let facts = RustCallerRegistrationFacts::from_blueprint(blueprint);
    let already_registered = ready
        .registered_rust_caller_contexts
        .borrow()
        .get(&key)
        .is_some_and(|registered| registered.contains(&facts));
    if already_registered {
        // Registration work remains part of this locator's independent
        // receiver budget even though the operation already installed these
        // exact identities for an earlier locator.
        if !(0..facts.registration_work()).all(|_| session.scope_step())
            || cancellation.is_cancelled()
            || !session.observe_cancellation()
            || cancellation.is_cancelled()
            || !session.observe_cancellation()
        {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        return Ok(ContextRegistrationOutcome::Ready);
    }

    let _registration_timing = crate::profiling::scope("rust_caller::register_context");
    let outcome = ready.register_context_in_session(blueprint, cancellation, session)?;
    if matches!(&outcome, ContextRegistrationOutcome::Ready) {
        let mut registered = ready.registered_rust_caller_contexts.borrow_mut();
        let facts_for_key = registered.entry(key).or_default();
        if !facts_for_key.contains(&facts) {
            facts_for_key.push(facts);
        }
    }
    Ok(outcome)
}

/// Operation-local work used to validate and compile selected context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionContextMetrics;

impl SelectedResolutionContextMetrics {
    fn assert_fresh(&self) {
        assert_eq!(
            self, &Self,
            "selected resolution context metrics must be fresh and default-valued"
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionBoundarySnapshotForTest {
    #[doc(hidden)]
    pub universal_root: SelectedNodeProvenance,
    #[doc(hidden)]
    pub boundaries: Box<[(BindingNodeId, SelectedNodeProvenance)]>,
    #[doc(hidden)]
    pub callable_static_import_boundaries: Box<[BindingNodeId]>,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedResolutionBoundarySnapshotForTest {
    #[doc(hidden)]
    pub const fn universal_root(&self) -> SelectedNodeProvenance {
        self.universal_root
    }

    #[doc(hidden)]
    pub fn boundaries(&self) -> &[(BindingNodeId, SelectedNodeProvenance)] {
        &self.boundaries
    }

    #[doc(hidden)]
    pub fn callable_static_import_boundaries(&self) -> &[BindingNodeId] {
        &self.callable_static_import_boundaries
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static SELECTED_RESOLUTION_BOUNDARY_SNAPSHOT: std::cell::RefCell<
        Option<SelectedResolutionBoundarySnapshotForTest>
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reset_selected_resolution_boundary_snapshot_for_test() {
    SELECTED_RESOLUTION_BOUNDARY_SNAPSHOT.with(|snapshot| *snapshot.borrow_mut() = None);
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_resolution_boundary_snapshot_for_test()
-> Option<SelectedResolutionBoundarySnapshotForTest> {
    SELECTED_RESOLUTION_BOUNDARY_SNAPSHOT.with(|snapshot| snapshot.borrow().clone())
}

impl AnalyzerStore {
    #[doc(hidden)]
    pub fn open_selected_resolution_operation<'store, 'project, 'selection>(
        &'store self,
        input: SelectedResolutionOperationInput<'project, 'selection>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'store, 'project>> {
        let captured_input = CapturedSelectedResolutionInput::capture(&input);
        Ok(
            match self.prepare_selected_resolution(input, cancellation)? {
                PreparedSelectedResolution::Ready(ready) => {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedResolutionOperationOpenOutcome::Cancelled);
                    }
                    SelectedResolutionOperationOpenOutcome::Ready(Box::new(
                        SelectedResolutionOperation {
                            captured_input,
                            ready: *ready,
                            enumerated_mounts: OnceCell::new(),
                            go_package_member_indexes: RefCell::default(),
                            go_context_selections: RefCell::default(),
                            go_import_inputs: RefCell::default(),
                            go_prepared_contexts: go_named::GoPreparedContextMemo::default(),
                            go_context_registrations: RefCell::default(),
                            go_receiver_anchor_types_memo: RefCell::default(),
                            jvm_file_contexts: RefCell::default(),
                            jvm_context_preparations: Default::default(),
                            jvm_context_blueprints: Default::default(),
                            jvm_context_registrations: RefCell::default(),
                            jvm_source_access_memo: RefCell::default(),
                            jvm_source_paths: RefCell::default(),
                            jvm_source_domains: Default::default(),
                            jvm_implicit_project_memo: Default::default(),
                            jvm_implicit_project_contexts: Default::default(),
                            jvm_lookup_recipe_memo: RefCell::default(),
                            jvm_root_exports_memo: RefCell::default(),
                            jvm_import_target_memo: RefCell::default(),
                            jvm_named_import_target_memo: RefCell::default(),
                            jvm_import_uncertainty_memo: RefCell::default(),
                            jvm_alias_rows_memo: RefCell::default(),
                            jvm_generated_lookup_memo: RefCell::default(),
                            jvm_package_member_memo: Default::default(),
                            jvm_package_indexes: RefCell::default(),
                            jvm_package_target_memo: RefCell::default(),
                            jvm_package_uncertainty_memo: RefCell::default(),
                            jvm_package_presence_memo: RefCell::default(),
                            jvm_endpoint_memo: RefCell::default(),
                            jvm_import_token_memo: RefCell::default(),
                            jvm_visibility_memo: RefCell::default(),
                            jvm_member_import_memo: RefCell::default(),
                            jvm_context_profile: RefCell::new(
                                crate::analyzer::resolution::seam_profile::enabled()
                                    .then(jvm_context::JvmContextReadProfile::default),
                            ),
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

    fn prepare_selected_resolution<'store, 'project, 'selection>(
        &'store self,
        input: SelectedResolutionOperationInput<'project, 'selection>,
        cancellation: &CancellationToken,
    ) -> Result<PreparedSelectedResolution<'store, 'project>> {
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
            checked_macro_frontier_files: RefCell::default(),
            registered_rust_caller_contexts: RefCell::default(),
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
                analyzer: input.analyzer,
                analysis_generation: input.analysis_generation,
                macro_walk: RefCell::default(),
                crate_rows: RefCell::default(),
                context_identities: SelectedContextIdentities::new(),
                operation_demand_state: Arc::default(),
                go_publications: RefCell::default(),
                go_snapshot: input.snapshots.get("go").cloned(),
                go_base_profile: std::cell::Cell::new(None),
                go_package_inventory_complete: RefCell::new(None),
                go_package_inventory_fragments: RefCell::default(),
                operation_candidate_cache: std::rc::Rc::new(
                    UnconditionalCandidateCache::for_operation(),
                ),
                graph_stage_candidate_cache: RefCell::new(None),
                boundary_candidate_read_memo: std::rc::Rc::new(RefCell::default()),
                package_reference_read_memo: std::rc::Rc::new(RefCell::default()),
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

struct SelectedOverlaySnapshot {
    overlays: Option<Arc<WorkspaceOverlayContent>>,
    digests: crate::hash::HashMap<String, [u8; 32]>,
}

fn selected_overlay_digests(
    overlays: Option<Arc<WorkspaceOverlayContent>>,
    cancellation: &CancellationToken,
) -> Option<SelectedOverlaySnapshot> {
    let overlay_entries = overlays
        .as_deref()
        .map(|content| content.entries())
        .unwrap_or(&[]);
    let mut overlay_digests = crate::hash::map_with_capacity(overlay_entries.len());
    for (file, digest) in overlay_entries {
        if cancellation.is_cancelled() {
            return None;
        }
        overlay_digests.insert(crate::path_utils::rel_path_string(file), *digest);
    }
    Some(SelectedOverlaySnapshot {
        overlays,
        digests: overlay_digests,
    })
}

fn validate_content_mount_authority(
    content_mounts: &[SelectedResolutionContentMountRequest],
    overlay_digests: &crate::hash::HashMap<String, [u8; 32]>,
    cancellation: &CancellationToken,
) -> SelectedOverlayAuthorityValidation {
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
    let Some(snapshot) = selected_overlay_digests(project.overlay_content(), cancellation) else {
        return SelectedOverlayAuthorityValidation::Cancelled;
    };
    let overlay_entries = snapshot
        .overlays
        .as_deref()
        .map(|content| content.entries())
        .unwrap_or(&[]);
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

    match validate_content_mount_authority(content_mounts, &snapshot.digests, cancellation) {
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
    #[doc(hidden)]
    pub fn resolve_reference(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<SelectedResolutionLocated<FactResolutionAnswer>>>
    {
        self.resolve_reference_with_projection(
            NativeReferenceQuery {
                context,
                locator,
                cancellation,
                context_metrics,
                session: &ResolutionSession::unbounded(),
                artifacts: None,
                go_demand: None,
                selected_import_gap: None,
                go_receiver_overlay: None,
                query_result_slot: None,
                point_metrics: None,
            },
            |_, _, _, answer| Ok(answer),
        )
    }

    fn resolve_reference_with_projection<T>(
        &mut self,
        query: NativeReferenceQuery<'_>,
        project: impl FnOnce(
            &ReadySelectedResolution<'_, '_>,
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            SemanticId,
            FactResolutionAnswer,
        ) -> Result<T>,
    ) -> Result<SelectedResolutionOperationOutcome<SelectedResolutionLocated<T>>> {
        self.resolve_reference_with_projection_and_setup(query, |_, _| Ok(()), project)
    }

    fn resolve_reference_with_projection_and_setup<T>(
        &mut self,
        query: NativeReferenceQuery<'_>,
        setup: impl FnOnce(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            SemanticId,
        ) -> Result<()>,
        project: impl FnOnce(
            &ReadySelectedResolution<'_, '_>,
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            SemanticId,
            FactResolutionAnswer,
        ) -> Result<T>,
    ) -> Result<SelectedResolutionOperationOutcome<SelectedResolutionLocated<T>>> {
        let NativeReferenceQuery {
            context,
            locator,
            cancellation,
            context_metrics,
            session,
            mut artifacts,
            mut go_demand,
            selected_import_gap,
            go_receiver_overlay,
            query_result_slot,
            point_metrics,
        } = query;
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
        let mut resolution_metrics = ResolutionBatchMetrics::default();
        let (projected, completion) = {
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let construction =
                if jvm_demand::jvm_demand_storage_language(locator.storage_language()) {
                    self.collect_jvm_blueprint_in_session(
                        context,
                        cancellation,
                        &ResolutionSession::unbounded(),
                    )?
                } else {
                    ready.collect_blueprint(context, cancellation)?
                };
            let blueprint = match construction {
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
                            if let Some(overlay) = go_receiver_overlay {
                                operation.set_go_receiver_slot_type_overlay(overlay);
                            }
                            if let Some(slot) = query_result_slot {
                                if locator.role()
                                    == crate::analyzer::resolution::LoweredSemanticRole::Definition
                                {
                                    operation.set_query_value_slot(reference, slot);
                                } else {
                                    operation.set_query_result_slot(reference, slot);
                                }
                            }
                            setup(operation, reference)?;
                            let answer = operation.resolve_reference_with_metrics(
                                reference,
                                &mut resolution_metrics,
                            )?;
                            if jvm_demand::jvm_demand_storage_language(locator.storage_language()) {
                                self.profile_jvm_read("native_point_answer", (reference, &answer));
                            }
                            let completion = answer.completion().clone();
                            Ok((
                                SelectedResolutionLocated::Found(project(
                                    ready, operation, reference, answer,
                                )?),
                                completion,
                            ))
                        };
                    if jvm_demand::jvm_demand_storage_language(locator.storage_language()) {
                        self.with_jvm_forward_operation(
                            locator.storage_language(),
                            &blueprint,
                            &observed_lexical,
                            &observed_typed,
                            locator.relative_path(),
                            None,
                            cancellation,
                            session,
                            selected_import_gap,
                            resolve,
                        )?
                    } else if let Some(demand) = go_demand.take() {
                        assert_eq!(locator.storage_language(), "go");
                        let caller_mount = self
                            .mount_table()
                            .mount_for_path("go", locator.relative_path())?
                            .expect("selected Go locator has a source mount")
                            .ordinal();
                        if demand.needs_demand_provider_for(caller_mount) {
                            self.with_go_forward_operation(
                                GoForwardOperationContext {
                                    blueprint: &blueprint,
                                    demand,
                                    caller_path: locator.relative_path(),
                                    lexical: &observed_lexical,
                                    typed: &observed_typed,
                                    cancellation,
                                    session,
                                },
                                artifacts.take(),
                                resolve,
                            )?
                        } else if let Some(artifacts) = artifacts.take() {
                            blueprint.with_forward_operation_in_session_using_artifacts(
                                &observed_lexical,
                                &persisted_lexical,
                                &observed_typed,
                                ForwardOperationArtifactContext {
                                    cancellation,
                                    session,
                                    artifacts,
                                },
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
                    } else if let Some(artifacts) = artifacts.take() {
                        blueprint.with_forward_operation_in_session_using_artifacts(
                            &observed_lexical,
                            &persisted_lexical,
                            &observed_typed,
                            ForwardOperationArtifactContext {
                                cancellation,
                                session,
                                artifacts,
                            },
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
        if let Some(point_metrics) = point_metrics {
            point_metrics.accumulate(resolution_metrics);
        }
        self.ready.finish(projected, &completion, cancellation)
    }

    #[doc(hidden)]
    pub fn resolve_rust_reference(
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
    #[doc(hidden)]
    pub fn resolve_rust_reference_with_metrics(
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

    #[doc(hidden)]
    pub fn resolve_rust_reference_bounded(
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
        crate::analyzer::resolution::with_bounded_resolution_session(
            budget,
            cancellation,
            |session| {
                self.resolve_rust_reference_in_session(
                    context,
                    locator,
                    cancellation,
                    context_metrics,
                    point_metrics,
                    session,
                )
            },
        )
    }

    /// A declaration name denotes itself. Resolve its canonical definition
    /// semantic without building a reference context, for retained and dirty files.
    /// Selected crate prelude evidence for one caller. Multiple compilation
    /// contexts must agree; callers cannot assume std from the file's spelling.
    #[doc(hidden)]
    pub fn rust_prelude_for_caller(
        &self,
        caller: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Option<(String, String)>> {
        let mut selected = None;
        for key in self.rust_crate_keys_for_file(caller, cancellation)? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let context = self
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT contexts.edition, contexts.prelude
                 FROM selected_rust_unit_summaries AS units
                 CROSS JOIN main.rust_resolution_unit_summary_contexts AS contexts
                   ON contexts.summary_id=units.summary_id
                 WHERE units.unit_key=?1",
                )?
                .query_row([key.as_slice()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
            if selected
                .as_ref()
                .is_some_and(|previous| previous != &context)
            {
                return Ok(None);
            }
            selected = Some(context);
        }
        Ok(selected)
    }

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

    /// Evaluate a reference site's cfg by searching assignments to its
    /// undecidable literals. The Boolean reports whether the answer depends
    /// on one of those assignments.
    #[doc(hidden)]
    pub fn rust_cfg_activation_for_caller_under_site_cfg(
        &self,
        caller: &Path,
        condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
        cancellation: &CancellationToken,
    ) -> Result<
        Option<(
            brokk_bifrost_rust::selected_context::RustSelectedActivation,
            bool,
        )>,
    > {
        use brokk_bifrost_rust::selected_context::RustSelectedActivation;
        let mut context = None;
        for key in self.rust_crate_keys_for_file(caller, cancellation)? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let (atoms, target_kind): (String, String) = self
                .ready
                .inventory
                .connection()
                .prepare_cached(rust_crate_context::CFG)?
                .query_row([key.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let atoms: BTreeSet<String> = serde_json::from_str(&atoms)
                .map_err(|error| StoreError::corrupt(error.to_string()))?;
            let selected = rust_crate_access::site_cfg_activation(
                &atoms,
                target_kind == "detached",
                condition,
            );
            if context
                .as_ref()
                .is_some_and(|previous| previous != &selected)
            {
                return Ok(Some((RustSelectedActivation::Unknown, false)));
            }
            context = Some(selected);
        }
        let (activation, conditional, _) =
            context.unwrap_or((RustSelectedActivation::Unknown, false, None));
        Ok((!cancellation.is_cancelled()).then_some((
            activation,
            activation == RustSelectedActivation::Active && conditional,
        )))
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
    #[doc(hidden)]
    pub fn rust_declaration_at_range_bounded(
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
        &mut self,
        caller: &std::path::Path,
        locators: &[&SelectedSemanticLocator],
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<
        BoundedResolution<
            reverse::ReverseBatch<
                Vec<reverse::ReverseSessionReport<SelectedRustReferenceAnswer>>,
                std::convert::Infallible,
            >,
        >,
    > {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        assert_eq!(
            point_metrics,
            &ResolutionBatchMetrics::default(),
            "selected Rust point metrics must be fresh and default-valued"
        );
        let cancellation = session.cancellation().unwrap_or(cancellation);
        let outcome = {
            let mut lifecycle = RustReverseLifecycle {
                selected: self,
                caller,
                access: RustDeclarationAccessKind::CrateSet,
                cancellation,
                session: &session,
                context_metrics,
                setup: |_: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
                        _: SemanticId| Ok(()),
                project: |_: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
                          _: &FactResolutionAnswer,
                          _: &ReadySelectedResolution<'_, '_>,
                          _: SelectedMountTable<'_, '_>,
                          _: &ResolutionSession,
                          _: &CancellationToken| {
                    Ok(SelectedResolutionOperationOutcome::Native(()))
                },
                marker: std::marker::PhantomData::<()>,
            };
            reverse::confirm_reverse_session(locators, &mut lifecycle)?
        };
        Ok(session.finish(outcome))
    }

    #[doc(hidden)]
    pub fn resolve_rust_reference_for_caller_bounded(
        &mut self,
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
            RustDeclarationAccessKind::Caller,
            |_, _, _, _, _, _| Ok(SelectedResolutionOperationOutcome::Native(())),
        )?;
        Ok(session.finish(outcome.into_single()))
    }

    /// Resolve several Rust call targets after preparing their shared caller
    /// context once. Each locator carries its own bounded session, seeded with
    /// the work shared by the file operation, so one exhausted target cannot
    /// stop its siblings.
    #[doc(hidden)]
    pub fn resolve_rust_references_for_caller_bounded_per_locator(
        &mut self,
        caller: &Path,
        locators: &[&SelectedSemanticLocator],
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> Result<Vec<BoundedResolution<SelectedRustCallerReferenceOutcome>>> {
        if locators.is_empty() {
            return Ok(Vec::new());
        }
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        if self
            .mount_table()
            .mount_for_path("rust", &selected_path_key(caller))?
            .is_none()
        {
            return Ok(repeat_bounded_resolution(
                locators.len(),
                session.finish(()),
                || SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile,
            ));
        }
        let operation_cancellation = session.cancellation().unwrap_or(cancellation);
        let mut macro_callers = vec![caller];
        for path in locators
            .iter()
            .map(|locator| Path::new(locator.relative_path()))
        {
            if path != caller && !macro_callers.contains(&path) {
                macro_callers.push(path);
            }
        }
        match self
            .prepare_selected_macro_frontiers_for_files(&macro_callers, operation_cancellation)?
        {
            SelectedResolutionStageOutcome::Ready => {}
            SelectedResolutionStageOutcome::Cancelled => {
                return Ok(repeat_bounded_resolution(
                    locators.len(),
                    session.finish(()),
                    || {
                        SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                        )
                    },
                ));
            }
            SelectedResolutionStageOutcome::Stale(reason) => {
                return Ok(repeat_bounded_resolution(
                    locators.len(),
                    session.finish(()),
                    || {
                        SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Stale(reason.clone()),
                        )
                    },
                ));
            }
            SelectedResolutionStageOutcome::Unavailable(reason) => {
                return Ok(repeat_bounded_resolution(
                    locators.len(),
                    session.finish(()),
                    || {
                        SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Unavailable(reason.clone()),
                        )
                    },
                ));
            }
        }
        let prepared = match self.rust_demand_preparation_for_caller_in_session(
            caller,
            operation_cancellation,
            Some(&session),
        )? {
            SelectedRustCallerDemandOutcome::Ready(prepared) => prepared,
            SelectedRustCallerDemandOutcome::Unavailable => {
                return Ok(repeat_bounded_resolution(
                    locators.len(),
                    session.finish(()),
                    || SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile,
                ));
            }
            SelectedRustCallerDemandOutcome::Cancelled => {
                return Ok(repeat_bounded_resolution(
                    locators.len(),
                    session.finish(()),
                    || {
                        SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                        )
                    },
                ));
            }
        };
        let contexts = prepared.contexts.clone().with_declaration_access_source(
            RustDeclarationAccessKind::Caller.source(self, prepared.crate_keys.clone())?,
        );
        let mut context_metrics = SelectedResolutionContextMetrics;
        self.resolve_rust_reference_demand_projection_per_locator(
            caller,
            &prepared,
            contexts,
            locators,
            budget,
            cancellation,
            &mut context_metrics,
            &session,
        )
    }

    #[doc(hidden)]
    pub fn resolve_rust_reference_for_caller(
        mut self,
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
                RustDeclarationAccessKind::Caller,
                |_, _, _, _, _, _| Ok(SelectedResolutionOperationOutcome::Native(())),
            )?
            .into_single())
    }

    #[doc(hidden)]
    pub fn resolve_rust_binding_site_for_caller(
        mut self,
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
                RustDeclarationAccessKind::Caller,
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

    #[doc(hidden)]
    pub fn finish_rust_row_binding_world(
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

    #[doc(hidden)]
    pub fn resolve_rust_type_for_caller_bounded(
        &mut self,
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
            RustDeclarationAccessKind::Caller,
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
    #[doc(hidden)]
    pub fn rust_reference_names_macro_module(
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
    #[doc(hidden)]
    pub fn rust_reference_names_workspace_crate(
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
    #[doc(hidden)]
    pub fn rust_macro_item_hosts(&self, files: &[&Path]) -> Result<Vec<PathBuf>> {
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
        &mut self,
        caller: &Path,
        locators: &[&SelectedSemanticLocator],
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
        session: &ResolutionSession,
        access: RustDeclarationAccessKind,
        project: impl FnMut(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            &FactResolutionAnswer,
            &ReadySelectedResolution<'_, '_>,
            SelectedMountTable<'_, '_>,
            &ResolutionSession,
            &CancellationToken,
        ) -> Result<SelectedResolutionOperationOutcome<T>>,
    ) -> Result<SelectedRustCallerReferencesOutcome<T>> {
        self.resolve_rust_references_for_caller_with_setup(
            caller,
            locators,
            cancellation,
            context_metrics,
            point_metrics,
            session,
            access,
            |_, _| Ok(()),
            project,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_rust_references_for_caller_with_setup<T>(
        &mut self,
        caller: &Path,
        locators: &[&SelectedSemanticLocator],
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        point_metrics: &mut ResolutionBatchMetrics,
        session: &ResolutionSession,
        access: RustDeclarationAccessKind,
        setup: impl FnMut(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            SemanticId,
        ) -> Result<()>,
        project: impl FnMut(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            &FactResolutionAnswer,
            &ReadySelectedResolution<'_, '_>,
            SelectedMountTable<'_, '_>,
            &ResolutionSession,
            &CancellationToken,
        ) -> Result<SelectedResolutionOperationOutcome<T>>,
    ) -> Result<SelectedRustCallerReferencesOutcome<T>> {
        assert_eq!(
            point_metrics,
            &ResolutionBatchMetrics::default(),
            "selected Rust point metrics must be fresh and default-valued"
        );
        let cancellation = session.cancellation().unwrap_or(cancellation);
        let mut lifecycle = RustReverseLifecycle {
            selected: self,
            caller,
            access,
            cancellation,
            session,
            context_metrics,
            setup,
            project,
            marker: std::marker::PhantomData,
        };
        use reverse::{ReverseBatch, ReverseSessionReport};
        let outcome = match reverse::confirm_reverse_session(locators, &mut lifecycle)? {
            ReverseBatch::Ready(reports) => SelectedResolutionOperationOutcome::Native(
                reports
                    .into_iter()
                    .map(|report| match report {
                        ReverseSessionReport::Found { meanings, .. } => {
                            SelectedResolutionLocated::Found(
                                meanings
                                    .into_iter()
                                    .flat_map(|(_, answers)| answers)
                                    .collect(),
                            )
                        }
                        ReverseSessionReport::Missing { .. } => SelectedResolutionLocated::Missing,
                    })
                    .collect(),
            ),
            ReverseBatch::Stale(reason) => SelectedResolutionOperationOutcome::Stale(reason),
            ReverseBatch::Unavailable(reason) => {
                SelectedResolutionOperationOutcome::Unavailable(reason)
            }
            ReverseBatch::Cancelled { completion, .. } => {
                SelectedResolutionOperationOutcome::Cancelled(completion)
            }
            ReverseBatch::UnsupportedContext => {
                return Ok(SelectedRustCallerReferencesOutcome::UnsupportedCallerProfile);
            }
            ReverseBatch::Bounded(limit) => match limit {},
            ReverseBatch::TimeStopped => unreachable!("caller session has no file deadline"),
        };
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
                                    &mut |operation, reference| {
                                        Ok(FactDemandResolution::Ready(Box::new(
                                            operation.resolve_reference(reference)?,
                                        )))
                                    },
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
    fn resolve_rust_reference_demand_projection_per_locator(
        &mut self,
        caller: &Path,
        prepared: &RustCallerDemand,
        contexts: SelectedResolutionContextSet,
        locators: &[&SelectedSemanticLocator],
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        setup_session: &ResolutionSession,
    ) -> Result<Vec<BoundedResolution<SelectedRustCallerReferenceOutcome>>> {
        let count = locators.len();
        let operation_cancellation = setup_session.cancellation().unwrap_or(cancellation);
        if !self.ensure_selected_rust_inputs_in_session(operation_cancellation, setup_session)? {
            return Ok(repeat_bounded_resolution(
                count,
                setup_session.finish(()),
                || {
                    SelectedRustCallerReferenceOutcome::Operation(
                        SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                    )
                },
            ));
        }
        note_rust_point_work("search_entry_inputs", setup_session);
        let context_timing = crate::profiling::scope("rust_caller::prepare_context");
        let context = match self.prepare_context_in_session(
            contexts,
            operation_cancellation,
            context_metrics,
            setup_session,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(repeat_bounded_resolution(
                    count,
                    setup_session.finish(()),
                    || {
                        SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                        )
                    },
                ));
            }
        };
        drop(context_timing);
        note_rust_point_work("search_validate_mounts", setup_session);
        let ready = &mut self.ready;
        let (mut results, attempts, completion) = {
            let _crate_memos = ready.crate_stage_memos()?;
            let _scope = ready
                .narrow_forward_scope_to_crates(&prepared.crate_keys, operation_cancellation)?;
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint_timing = crate::profiling::scope("rust_caller::collect_blueprint");
            let blueprint = match ready.collect_blueprint_in_session(
                context,
                operation_cancellation,
                setup_session,
            )? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => {
                    return Ok(repeat_bounded_resolution(
                        count,
                        setup_session.finish(()),
                        || {
                            SelectedRustCallerReferenceOutcome::Operation(
                                SelectedResolutionOperationOutcome::Cancelled(
                                    cancellation_completion.clone(),
                                ),
                            )
                        },
                    ));
                }
            };
            drop(blueprint_timing);
            note_rust_point_work("search_collect_blueprint", setup_session);
            let _resolve_timing = crate::profiling::scope("rust_caller::register_and_resolve");
            if matches!(
                register_selected_rust_caller_context_in_session(
                    ready,
                    caller,
                    &prepared.crate_keys,
                    RustDeclarationAccessKind::Caller,
                    &blueprint,
                    operation_cancellation,
                    setup_session,
                )?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(repeat_bounded_resolution(
                    count,
                    setup_session.finish(()),
                    || {
                        SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                        )
                    },
                ));
            }
            note_rust_point_work("search_register_context", setup_session);
            note_rust_point_work("search_final_authority", setup_session);
            if !setup_session.scope_step() {
                return Ok(repeat_bounded_resolution(
                    count,
                    setup_session.finish(()),
                    || {
                        SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                        )
                    },
                ));
            }
            let shared_work = match setup_session.finish(()) {
                BoundedResolution::Complete { work, .. } => work,
                BoundedResolution::Exceeded { limit, work } => {
                    return Ok((0..count)
                        .map(|_| BoundedResolution::Exceeded { limit, work })
                        .collect());
                }
                BoundedResolution::Cancelled { work } => {
                    return Ok((0..count)
                        .map(|_| BoundedResolution::Cancelled { work })
                        .collect());
                }
            };
            let mut results = Vec::with_capacity(count);
            let mut attempts = Vec::with_capacity(count);
            let mut completion = ResolutionCompletion::Complete;
            for locator in locators {
                let point_session = ResolutionSession::bounded_after_shared_work(
                    budget,
                    Some(cancellation),
                    shared_work,
                );
                let point_cancellation = point_session.cancellation().unwrap_or(cancellation);
                let located = ready.lookup_locators_in_session(
                    &persisted_lexical,
                    locator,
                    point_cancellation,
                    &point_session,
                )?;
                let point_outcome = match located {
                    LocatedSemantics::Missing => Ok(SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Missing,
                    )),
                    LocatedSemantics::Cancelled => Ok(
                        SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                    ),
                    LocatedSemantics::Found(references) => {
                        let arena = RefCell::new(ClosedRelations::default());
                        let source = ClosedForwardSource::new(
                            &observed_lexical,
                            &persisted_lexical,
                            &arena,
                            &point_session,
                            crate::analyzer::resolution::CALLER_ENVIRONMENT,
                        );
                        let forward = PreparedForwardSource::new(
                            ready,
                            &prepared.demand,
                            &observed_lexical,
                            &persisted_lexical,
                        );
                        let mut provider = DemandProvider::new(ForwardProvider::new(
                            &forward,
                            &arena,
                            &point_session,
                            point_cancellation,
                        ));
                        blueprint.with_forward_operation_in_session(
                            &source,
                            &persisted_lexical,
                            &observed_typed,
                            point_cancellation,
                            &point_session,
                            |operation| {
                                operation.enable_completed_root_reuse(
                                    &ready.operation_demand_state,
                                    RustDeclarationAccessKind::Caller as u64,
                                );
                                let mut answers = Vec::with_capacity(references.len());
                                for reference in references {
                                    if !point_session.scope_step()
                                        || point_cancellation.is_cancelled()
                                    {
                                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                            cancelled_completion(),
                                        ));
                                    }
                                    let resolution = match operation
                                        .resolve_reference_by_demand(reference, &mut provider)?
                                    {
                                        FactDemandResolution::Ready(resolution) => *resolution,
                                        FactDemandResolution::Cancelled(completion) => {
                                            return Ok(
                                                SelectedResolutionOperationOutcome::Cancelled(
                                                    completion,
                                                ),
                                            );
                                        }
                                    };
                                    if !point_session.observe_cancellation()
                                        || point_cancellation.is_cancelled()
                                    {
                                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                            cancelled_completion(),
                                        ));
                                    }
                                    match assemble_rust_reference_answer(
                                        &RustReferenceAnswerContext {
                                            ready,
                                            mounts: SelectedMountTable::new(&ready.inventory),
                                            reference,
                                            locator,
                                            session: &point_session,
                                            cancellation: point_cancellation,
                                        },
                                        operation,
                                        resolution,
                                        &mut |operation, reference| {
                                            operation.resolve_reference_by_demand(
                                                reference,
                                                &mut provider,
                                            )
                                        },
                                        &mut project_rust_reference_unit,
                                    )? {
                                        SelectedResolutionOperationOutcome::Native(answer) => {
                                            answers.push(answer)
                                        }
                                        SelectedResolutionOperationOutcome::Unavailable(reason) => {
                                            return Ok(
                                                SelectedResolutionOperationOutcome::Unavailable(
                                                    reason,
                                                ),
                                            );
                                        }
                                        SelectedResolutionOperationOutcome::Stale(reason) => {
                                            return Ok(SelectedResolutionOperationOutcome::Stale(
                                                reason,
                                            ));
                                        }
                                        SelectedResolutionOperationOutcome::Cancelled(
                                            completion,
                                        ) => {
                                            return Ok(
                                                SelectedResolutionOperationOutcome::Cancelled(
                                                    completion,
                                                ),
                                            );
                                        }
                                    }
                                }
                                Ok(SelectedResolutionOperationOutcome::Native(
                                    SelectedResolutionLocated::Found(answers),
                                ))
                            },
                        )
                    }
                };
                let bounded = point_session.finish(point_outcome?);
                match bounded {
                    BoundedResolution::Complete {
                        value: SelectedResolutionOperationOutcome::Native(attempt),
                        work,
                    } => {
                        if let SelectedResolutionLocated::Found(answers) = &attempt {
                            completion = answers.iter().fold(completion, |completion, answer| {
                                completion.combine(answer.resolution.completion())
                            });
                        }
                        attempts.push(attempt);
                        results.push(BoundedResolution::Complete {
                            value: SelectedRustCallerReferenceOutcome::Operation(
                                SelectedResolutionOperationOutcome::Native(
                                    SelectedResolutionLocated::Missing,
                                ),
                            ),
                            work,
                        });
                    }
                    BoundedResolution::Complete { value, work } => {
                        attempts.push(SelectedResolutionLocated::Missing);
                        results.push(BoundedResolution::Complete {
                            value: SelectedRustCallerReferenceOutcome::Operation(value),
                            work,
                        });
                    }
                    BoundedResolution::Exceeded { limit, work } => {
                        attempts.push(SelectedResolutionLocated::Missing);
                        results.push(BoundedResolution::Exceeded { limit, work });
                    }
                    BoundedResolution::Cancelled { work } => {
                        attempts.push(SelectedResolutionLocated::Missing);
                        results.push(BoundedResolution::Cancelled { work });
                    }
                }
            }
            note_rust_point_work("search_answers", setup_session);
            (results, attempts, completion)
        };
        let authoritative = ready.finish(attempts, &completion, cancellation)?;
        match authoritative {
            SelectedResolutionOperationOutcome::Native(attempts) => {
                for (result, attempt) in results.iter_mut().zip(attempts) {
                    if let BoundedResolution::Complete { value, .. } = result
                        && let SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Native(
                                SelectedResolutionLocated::Missing,
                            ),
                        ) = value
                    {
                        *value = SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Native(attempt),
                        );
                    }
                }
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                for result in &mut results {
                    if let BoundedResolution::Complete { value, .. } = result {
                        *value = SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Unavailable(reason.clone()),
                        );
                    }
                }
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                for result in &mut results {
                    if let BoundedResolution::Complete { value, .. } = result {
                        *value = SelectedRustCallerReferenceOutcome::Operation(
                            SelectedResolutionOperationOutcome::Stale(reason.clone()),
                        );
                    }
                }
            }
            SelectedResolutionOperationOutcome::Cancelled(_) => {
                for result in &mut results {
                    let work = result.work();
                    *result = BoundedResolution::Cancelled { work };
                }
            }
        }
        Ok(results)
    }

    #[doc(hidden)]
    pub fn references_to_selected_definition(
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

    #[doc(hidden)]
    pub fn references_to_rust_definition(
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
                        answer.references(),
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

    #[doc(hidden)]
    pub fn stage_selected_reference_batches<S>(
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

    #[doc(hidden)]
    pub fn prepare_context(
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

/// A complete projection may refer to a previously committed request-owned
/// cell. Its full derivation was validated before granting that authority.
struct SelectedContextCellProjection<T> {
    value: T,
    published: Option<crate::analyzer::resolution::SelectedContextPathToken>,
}

impl ReadySelectedResolution<'_, '_> {
    #[doc(hidden)]
    pub fn publish_context_paths(
        &self,
        context: SelectedResolutionContextInputs,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<crate::analyzer::resolution::SelectedContextPathPublicationOutcome> {
        let names = self.shared_names();
        self.publish_context_paths_with_compilers(
            context,
            cancellation,
            session,
            |identities, bridge| {
                Ok(crate::analyzer::resolution::compile_selected_root_bridge(
                    &self.lexical_source(),
                    identities,
                    bridge,
                    &names,
                    cancellation,
                    session,
                )?
                .map(|value| SelectedContextCellProjection {
                    value,
                    published: None,
                }))
            },
            |identities, bridge| {
                Ok(bridge
                    .compile(identities, &self.lexical_source(), cancellation, session)?
                    .map(|value| SelectedContextCellProjection {
                        value,
                        published: None,
                    }))
            },
        )
    }

    /// Compile and publish one descriptor at a time. Request metadata remains
    /// separate from token-specific candidate authority and reverse evidence.
    fn publish_context_paths_with_compilers<R, P>(
        &self,
        context: SelectedResolutionContextInputs,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        mut root_compiler: impl FnMut(
            &SelectedContextIdentities,
            &crate::analyzer::resolution::SelectedRootBridgeDescriptor,
        ) -> Result<Option<SelectedContextCellProjection<R>>>,
        mut package_compiler: impl FnMut(
            &SelectedContextIdentities,
            &crate::analyzer::resolution::SelectedPackageBridgeDescriptor,
        ) -> Result<Option<SelectedContextCellProjection<P>>>,
    ) -> Result<crate::analyzer::resolution::SelectedContextPathPublicationOutcome>
    where
        R: std::borrow::Borrow<crate::analyzer::resolution::SelectedRootBridgeProjection>,
        P: std::borrow::Borrow<(
                CandidatePathIdentity,
                crate::analyzer::resolution::PartialPath,
            )>,
    {
        use crate::analyzer::resolution::{
            SelectedContextPathPublication, SelectedContextPathPublicationOutcome,
        };

        #[cfg(any(test, feature = "test-support"))]
        let work_before = selected_sql_trace::context_publication_work(session);
        let (
            bridges,
            completion,
            declaration_access_source,
            context_owned_gap_identities,
            identities,
            package_bridges,
            go_import_bindings,
        ) = context.into_parts();
        // Resolve descriptor content before SQL publication installs its parent
        // cancellation handler. These immutable keys then remain available to
        // construction and rollback without confusing cancellation with missing
        // authority. The query-owned authority memo retains only demanded keys.
        let source = self.lexical_source();
        for bridge in &bridges {
            if cancellation.is_cancelled() {
                return Ok(SelectedContextPathPublicationOutcome::Cancelled {
                    contextual_reverse_inventory_completion: completion,
                });
            }
            bridge.validate_content_authority(&identities, &source, cancellation)?;
        }
        for bridge in &package_bridges {
            if cancellation.is_cancelled() {
                return Ok(SelectedContextPathPublicationOutcome::Cancelled {
                    contextual_reverse_inventory_completion: completion,
                });
            }
            bridge.validate_content_authority(&identities, &source, cancellation)?;
        }
        for bridge in &go_import_bindings {
            if cancellation.is_cancelled() {
                return Ok(SelectedContextPathPublicationOutcome::Cancelled {
                    contextual_reverse_inventory_completion: completion,
                });
            }
            bridge.validate_content_authority(&identities, &source, cancellation)?;
        }
        let go_package_inventory_complete = *self.go_package_inventory_complete.borrow();
        let go_package_inventory_fragments = self.go_package_inventory_fragments.borrow().clone();
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return Err(StoreError::new(
                "selected root inventory completion contains operation cancellation",
            ));
        }
        // Tokens are freshly allocated for every publication. Hash the full
        // structured path cells instead, including completion, so two equal
        // overlays share demand answers without conflating distinct overlays.
        // This buffer is the result of this one publication and dies here.
        struct ContextSignature(Vec<u8>);
        impl std::hash::Hasher for ContextSignature {
            fn finish(&self) -> u64 {
                let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(&self.0);
                u64::from_le_bytes(
                    digest[..8]
                        .try_into()
                        .expect("a SHA-256 digest has eight bytes"),
                )
            }
            fn write(&mut self, bytes: &[u8]) {
                self.0
                    .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                self.0.extend_from_slice(bytes);
            }
        }
        use std::hash::Hash as _;
        let mut signature = ContextSignature(Vec::new());
        completion.hash(&mut signature);
        context_owned_gap_identities.hash(&mut signature);
        let mut shared = BTreeSet::new();
        let mut local = BTreeSet::new();
        // Only descriptor references live until this one publication ends.
        // Compare full derivations, including completion, before SQL dedup.
        let mut derivations = HashMap::default();
        let names = self.shared_names();
        let token = super::resolution_stage::SelectedResolutionStage::new(&self.inventory)
            .publish_context_paths(cancellation, |writer| {
                for bridge in bridges.iter() {
                    let Some(projection) = root_compiler(&identities, bridge)? else { return Ok(false); };
                    let projected: &crate::analyzer::resolution::SelectedRootBridgeProjection = std::borrow::Borrow::borrow(&projection.value);
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
                    (candidate, path).hash(&mut signature);
                    let offered = match projection.published {
                        Some(source) => writer.reuse(source, candidate)?,
                        None => writer.insert(candidate, path)?,
                    };
                    if !offered { return Ok(false); }
                }
                let mut package_derivations = HashMap::default();
                for bridge in &package_bridges {
                    let Some(projection) = package_compiler(&identities, bridge)? else { return Ok(false); };
                    let (candidate, path): &(CandidatePathIdentity, crate::analyzer::resolution::PartialPath) = std::borrow::Borrow::borrow(&projection.value);
                    let candidate = *candidate;
                    if let Some(previous) = package_derivations.insert(candidate, bridge)
                        && previous != bridge {
                            return Err(StoreError::new(format!(
                                "selected package context has conflicting derivations for {candidate:?}: previous={previous:?}, current={bridge:?}"
                            )));
                        }
                    shared.extend(bridge.shared_identities());
                    (candidate, &path).hash(&mut signature);
                    let offered = match projection.published {
                        Some(source) => writer.reuse(source, candidate)?,
                        None => writer.insert(candidate, path)?,
                    };
                    if !offered { return Ok(false); }
                }
                let mut go_import_derivations = HashMap::default();
                for bridge in &go_import_bindings {
                    let Some((candidate, path)) = bridge.compile(&identities, &self.lexical_source(), cancellation, session)? else {
                        return Ok(false);
                    };
                    if let Some(previous) = go_import_derivations.insert(candidate, bridge)
                        && previous != bridge {
                            return Err(StoreError::new(format!(
                                "selected Go import context has conflicting derivations for {candidate:?}: previous={previous:?}, current={bridge:?}"
                            )));
                        }
                    shared.extend(bridge.shared_identities());
                    (candidate, &path).hash(&mut signature);
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
        #[cfg(any(test, feature = "test-support"))]
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
                selected_sql_trace::context_publication_work(session)
                    .expect("scoped context observation remains enabled"),
            );
        }
        Ok(SelectedContextPathPublicationOutcome::Ready(
            SelectedContextPathPublication {
                token,
                context_digest: brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                    &signature.0,
                ),
                contextual_reverse_inventory_completion: completion,
                go_package_inventory_complete,
                go_package_inventory_fragments,
                declaration_access_source,
                context_owned_gap_identities,
                identities: identities.clone(),
                shared_semantic_identities: shared.into_iter().collect(),
                fragment_local_semantic_identities: local.into_iter().collect(),
            },
        ))
    }

    #[doc(hidden)]
    pub fn collect_blueprint(
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
                        SelectedFactOperationBlueprint::from_publication(publication)
                            .with_selected_demand_state(&self.operation_demand_state),
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

    #[doc(hidden)]
    pub fn register_context(
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
            staged.register_context_owned_semantic(
                reason,
                blueprint.context_owned_semantic_digest(reason)?,
                &self.inventory.shared_names(),
            );
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
        #[cfg(any(test, feature = "test-support"))]
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
        self.register_context_cells_in_session(
            blueprint,
            SelectedContextRegistrationCells {
                shared: blueprint.shared_semantic_identities(),
                boundaries: blueprint.boundary_nodes(),
                gaps: blueprint.context_owned_gap_identities(),
            },
            cancellation,
            session,
        )
    }

    fn register_context_cells_in_session(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        cells: SelectedContextRegistrationCells<'_>,
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
        let registration_work = cells
            .shared
            .len()
            .checked_add(cells.boundaries.len())
            .and_then(|count| count.checked_add(cells.gaps.len()))
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
        for &identity in cells.shared {
            rebaser.register_shared_semantic(identity);
        }
        let names = self.inventory.shared_names();
        for &reason in cells.gaps {
            rebaser.register_context_owned_semantic(
                reason,
                blueprint.context_owned_semantic_digest(reason)?,
                &names,
            );
        }
        for &node in cells.boundaries {
            rebaser.register_context_boundary(node);
        }
        Ok(ContextRegistrationOutcome::Ready)
    }

    #[doc(hidden)]
    pub fn lookup_locator(
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

    #[doc(hidden)]
    pub fn finish<T>(
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
        for publication in self.go_publications.borrow().values() {
            let status = if self.store.uses_single_connection_reads() {
                super::go_package_context::go_context_status_on(
                    self.inventory.connection(),
                    publication,
                    cancellation,
                )?
            } else {
                self.store
                    .go_context_head_status(publication, cancellation)?
            };
            match status {
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
        let Some(snapshot) = selected_overlay_digests(self.project.overlay_content(), cancellation)
        else {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        };
        match validate_content_mount_authority(
            &self.content_mounts,
            &snapshot.digests,
            cancellation,
        ) {
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

#[doc(hidden)]
pub fn selected_macro_capture_digest(
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod selected_sql_trace;

#[cfg(any(test, feature = "test-support"))]
#[path = "resolution_operation_tests.rs"]
#[doc(hidden)]
pub mod tests;

#[cfg(test)]
#[path = "resolution_operation_unit_summary_tests.rs"]
mod unit_summary_tests;

impl ReadySelectedResolution<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn with_workspace_fact_operation<T>(
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
        let source = ClosedForwardSource::new(
            lexical,
            &paths,
            &self.rust_workspace_relations,
            session,
            crate::analyzer::resolution::CALLER_ENVIRONMENT,
        );
        let provider = DemandProvider::new(ForwardProvider::new(
            &prepared,
            &self.rust_workspace_relations,
            session,
            cancellation,
        ));
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
        self.with_workspace_fact_operation(blueprint, lexical, typed, cancellation, session, run)
    }

    #[doc(hidden)]
    pub fn with_rust_workspace_fact_operation<T>(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let session = ResolutionSession::unbounded();
        self.with_workspace_fact_operation(blueprint, lexical, typed, cancellation, &session, run)
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn rust_crate_point_sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    rust_crate_context::sql_pins()
        .into_iter()
        .chain(rust_demand::rows::sql_pins())
        .chain([
            (
                "rust_point_unresolved_trait_impl_files",
                super::RUST_UNRESOLVED_TRAIT_IMPL_FILES_SQL,
                2,
            ),
            (
                "rust_point_item_macro_decisions",
                super::RUST_ITEM_MACRO_DECISIONS_SQL,
                2,
            ),
            (
                "rust_point_selected_macro_item_unit",
                super::selected_macro_item_unit_sql_for_plan(),
                4,
            ),
            (
                "rust_point_summary_importing_files",
                super::rust_unit_summaries::IMPORTING_FILES_FOR_MEMBER_SQL,
                2,
            ),
        ])
        .collect()
}

pub(super) const RUST_GRAPH_DEFINITIONS_SQL: &str =
    "SELECT DISTINCT mount.mount_ordinal, site.semantic_key
 FROM selected_rust_unit_members AS member
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.blob_id=member.blob_id
 AND mount.persisted_relative_path=member.rel_path AND mount.storage_language='rust'
 CROSS JOIN main.resolution_semantic_sites AS site
  ON site.blob_id=member.blob_id AND site.semantic_role='definition'
 CROSS JOIN main.resolution_definition_unit_crosswalks AS unit
  ON unit.blob_id=site.blob_id AND unit.definition_semantic_key=site.semantic_key";

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod heap_pin;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use heap_pin::heap_pin_bytes;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "native_query_plan_go_support.rs"]
pub mod native_query_plan_go_support;

impl<'store, 'input> SelectedResolutionOperation<'store, 'input> {
    #[doc(hidden)]
    pub fn ready(&self) -> &ReadySelectedResolution<'store, 'input> {
        &self.ready
    }
}
