//! Query-local contracts for nominal reverse search.
use super::reverse::*;
use super::*;
use crate::analyzer::resolution::SelectedTypedFactSource;
use brokk_bifrost_core::analyzer::source_facts::{DeclarationAccessBoundary, PackageAccessRegion};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

/// Query-local target facts; no source inventory survives the operation.
pub struct NominalReverseTarget<'a> {
    pub storage_language: &'a str,
    pub semantic: SemanticId,
    pub unit: &'a CodeUnit,
    pub owner: Option<SemanticId>,
    pub package: &'a str,
    pub visibility: Option<DeclaredVisibility>,
    pub boundary: Option<DeclarationAccessBoundary<SemanticId>>,
}

pub enum PeerNaming {
    Closed,
    WithinPackage(PackageAccessRegion),
    Open,
    OpenIncomplete(ResolutionIncompleteReason),
}

pub struct HierarchyRoute {
    pub open_world: bool,
}

/// Query-owned family evidence. Routes only nominate; equivalent definitions
/// additionally authorize a confirmed reference to the authored declaration.
pub struct TargetFamilies {
    pub equivalent_targets: Vec<SemanticId>,
    pub nominations: Vec<NominalReverseFamilyRoute>,
    pub completion: ResolutionCompletion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NominalReverseFamilyRoute {
    pub member_name: String,
    /// Enclosing type spellings, outermost first. Package segments are never
    /// owner spellings: they would nominate every package-qualified site.
    pub owner_segments: Vec<String>,
}

impl TargetFamilies {
    pub(super) fn empty() -> Self {
        Self {
            equivalent_targets: Vec::new(),
            nominations: Vec::new(),
            completion: ResolutionCompletion::Complete,
        }
    }
}

pub(crate) trait NominalReverseTargetRules: Sync {
    fn complete_target_families(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        definitions: &[(SemanticId, SelectedNativeDefinition)],
        families: &mut TargetFamilies,
        cancellation: &CancellationToken,
    ) -> Result<()>;
    fn target_access(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        unit: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<NominalReverseTargetAccess>;
    #[allow(clippy::too_many_arguments)]
    fn import_inventory(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        mount: u32,
        blob: i64,
        lookup: SemanticId,
        target: SemanticId,
        known_sites: &HashSet<brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>>;
    fn file_evaluator(&self) -> &'static dyn ReverseFileEvaluator<Answer = FactResolutionAnswer>;
    fn target_families(
        &self,
        target: &NominalReverseTarget<'_>,
        facts: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
    ) -> Result<TargetFamilies>;
    fn peer_naming(&self, target: &NominalReverseTarget<'_>) -> PeerNaming;
    fn hierarchy_route(&self, target: &NominalReverseTarget<'_>) -> Option<HierarchyRoute>;
    /// Required: complete inventory of languages that can name this target.
    fn candidate_languages(&self) -> &'static [(Language, &'static str)];
    /// Required: whether an import inspection is needed without root demand.
    fn inspect_imports_without_root(&self, storage_language: &str) -> bool;
}

pub(crate) struct NominalReverseTargetAccess {
    pub(crate) visibility: Option<DeclaredVisibility>,
    pub(crate) owner: Option<SemanticId>,
    pub(crate) boundary: Option<DeclarationAccessBoundary<SemanticId>>,
    pub(crate) completion: ResolutionCompletion,
}

pub(crate) type NominalReverseCandidate = ReverseNomination;

#[derive(Debug)]
#[doc(hidden)]
pub struct NominalReverseCandidateSet {
    pub equivalent_targets: Vec<SemanticId>,
    #[doc(hidden)]
    pub target: ReverseTarget,
    #[doc(hidden)]
    pub candidates: Vec<NominalReverseCandidate>,
    #[doc(hidden)]
    pub completion: ResolutionCompletion,
    #[doc(hidden)]
    pub peer_language_inventory_open: bool,
    #[doc(hidden)]
    pub evidence: Box<ReverseEvidence>,
}

#[doc(hidden)]
pub enum NominalReverseCandidateOutcome {
    Ready(NominalReverseCandidateSet),
    /// This target has no identity inside the selected source inventory.
    TargetUncovered(String),
    Unavailable(String),
    Cancelled,
}

#[doc(hidden)]
pub type NominalReverseConfirmedReference = ReverseOwnedReference;

#[doc(hidden)]
pub struct NominalReverseConfirmed {
    pub equivalent_targets: Vec<SemanticId>,
    #[doc(hidden)]
    pub target: SemanticId,
    #[doc(hidden)]
    pub references: Vec<NominalReverseConfirmedReference>,
    #[doc(hidden)]
    pub completion: ResolutionCompletion,
    #[doc(hidden)]
    pub candidate_inventory_complete: bool,
    #[doc(hidden)]
    pub peer_language_inventory_open: bool,
    pub(super) evidence: Box<ReverseEvidence>,
    pub(super) selected_target: ReverseTarget,
    pub(super) nominations: Vec<ReverseNomination>,
}
