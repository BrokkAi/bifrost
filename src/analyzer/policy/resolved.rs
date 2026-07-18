//! Fully loaded, composition-safe policy models.
//!
//! The authoring graph in [`super::definition`] deliberately retains file,
//! catalog, directory, category, and endpoint predicates.  Values in this
//! module are the boundary after those inputs have been reduced to finite,
//! sorted identities and every selector has been lowered to a typed query.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

use crate::analyzer::semantic::WorkspaceRelativePath;
use crate::analyzer::structural::CodeQuery;
use crate::schema_version::SchemaVersionResolution;

use super::canonical_loaded;
use super::definition::*;
use super::identity::*;
use super::source::PolicySourceIdentity;

/// Stable semantic path identifying a loaded dependency declaration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyDependencyPath(PolicySelectorPath);

impl PolicyDependencyPath {
    pub fn new(path: impl AsRef<str>) -> Result<Self, PolicySelectorPathError> {
        PolicySelectorPath::new(path).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for PolicyDependencyPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PolicyDependencyPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PolicyDependencyPath {
    type Err = PolicySelectorPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::new(path)
    }
}

/// Provenance of one resolved selector. It never enters semantic hashes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectorOrigin {
    Document {
        source: PolicySourceIdentity,
    },
    ReferencedFile {
        reference: WorkspaceRelativePath,
        source: PolicySourceIdentity,
        /// Exact pin on the `(rql-file ...)` wrapper, when authored.
        wrapper_authored_schema_version: Option<u32>,
        /// Exact pin in the referenced `(rql ...)` document envelope, when authored.
        document_authored_schema_version: Option<u32>,
    },
    Catalog {
        catalog: ResolvedCatalogIdentity,
    },
}

/// A typed query at its stable policy path after file loading and version resolution.
#[derive(Debug, Clone)]
pub struct ResolvedPolicySelector {
    pub path: PolicySelectorPath,
    pub schema_resolution: SchemaVersionResolution,
    pub query: CodeQuery,
    pub semantic_hash: ResolvedSelectorSemanticHash,
    pub origin: SelectorOrigin,
}

impl ResolvedPolicySelector {
    pub fn try_new(
        path: PolicySelectorPath,
        schema_resolution: SchemaVersionResolution,
        query: CodeQuery,
        origin: SelectorOrigin,
    ) -> Result<Self, LoadedModelError> {
        if u64::from(schema_resolution.version) != query.schema_version {
            return Err(LoadedModelError::SelectorSchemaMismatch {
                path,
                resolution: schema_resolution.version,
                query: query.schema_version,
            });
        }
        let semantic_hash =
            ResolvedSelectorSemanticHash::from_query(schema_resolution.version, &query);
        Ok(Self {
            path,
            schema_resolution,
            query,
            semantic_hash,
            origin,
        })
    }
}

/// Content-addressed identity of a registered catalog version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolvedCatalogIdentity {
    pub name: PolicyId,
    pub version: u32,
    pub semantic_hash: TaintCatalogHash,
}

impl ResolvedCatalogIdentity {
    pub fn try_new(
        name: PolicyId,
        version: u32,
        semantic_hash: TaintCatalogHash,
    ) -> Result<Self, LoadedModelError> {
        if version == 0 {
            return Err(LoadedModelError::ZeroCatalogVersion);
        }
        Ok(Self {
            name,
            version,
            semantic_hash,
        })
    }
}

/// Stable identity shared by every local, catalog, and standalone endpoint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedEndpointIdentity {
    Local {
        policy_id: PolicyId,
        entry_id: TaintEntryId,
    },
    Catalog {
        catalog: ResolvedCatalogIdentity,
        entry_id: TaintEntryId,
    },
    MatchEndpoint {
        endpoint_id: EndpointId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointDefinitionSchemaResolution {
    PolicyDocument { resolution: SchemaVersionResolution },
    CatalogDocument { schema_version: u32 },
}

impl EndpointDefinitionSchemaResolution {
    pub const fn version(&self) -> u32 {
        match self {
            Self::PolicyDocument { resolution } => resolution.version,
            Self::CatalogDocument { schema_version } => *schema_version,
        }
    }
}

/// Diagnostic/presentation and analyzer-bearing endpoint data after composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpointModel {
    pub role: EndpointRole,
    pub display_name: String,
    pub categories: Vec<PolicyCategoryId>,
    pub binding: PolicyEndpointBinding,
    pub taint: Option<EndpointTaintSemantics>,
    pub supersedes: Vec<ResolvedEndpointIdentity>,
}

impl ResolvedEndpointModel {
    pub fn new(
        role: EndpointRole,
        display_name: String,
        mut categories: Vec<PolicyCategoryId>,
        binding: PolicyEndpointBinding,
        taint: Option<EndpointTaintSemantics>,
        mut supersedes: Vec<ResolvedEndpointIdentity>,
    ) -> Self {
        categories.sort();
        categories.dedup();
        supersedes.sort();
        supersedes.dedup();
        Self {
            role,
            display_name,
            categories,
            binding,
            taint,
            supersedes,
        }
    }
}

/// Bounded provenance for a resolved endpoint dependency.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointOrigin {
    PolicyLocal {
        path: PolicyDependencyPath,
    },
    Catalog {
        catalog: ResolvedCatalogIdentity,
    },
    ExactMatch {
        path: PolicyDependencyPath,
        source: PolicySourceIdentity,
    },
    MatchDirectory {
        path: PolicyDependencyPath,
        source: PolicySourceIdentity,
    },
}

/// One endpoint leaf after all authoring-source forms have been normalized.
#[derive(Debug, Clone)]
pub struct ResolvedEndpointDependency {
    pub(crate) identity: ResolvedEndpointIdentity,
    pub(crate) definition_schema: EndpointDefinitionSchemaResolution,
    pub(crate) selector_path: PolicySelectorPath,
    pub(crate) selector_schema: SchemaVersionResolution,
    pub(crate) model: ResolvedEndpointModel,
    pub(crate) semantic_hash: EndpointSemanticHash,
    pub(crate) analysis_projection_hash: EndpointAnalysisProjectionHash,
    pub(crate) origins: Vec<EndpointOrigin>,
}

impl ResolvedEndpointDependency {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        identity: ResolvedEndpointIdentity,
        definition_schema: EndpointDefinitionSchemaResolution,
        selector_path: PolicySelectorPath,
        selector_schema: SchemaVersionResolution,
        model: ResolvedEndpointModel,
        semantic_hash: EndpointSemanticHash,
        analysis_projection_hash: EndpointAnalysisProjectionHash,
        mut origins: Vec<EndpointOrigin>,
    ) -> Self {
        origins.sort();
        origins.dedup();
        Self {
            identity,
            definition_schema,
            selector_path,
            selector_schema,
            model,
            semantic_hash,
            analysis_projection_hash,
            origins,
        }
    }

    pub fn identity(&self) -> &ResolvedEndpointIdentity {
        &self.identity
    }

    pub fn definition_schema(&self) -> &EndpointDefinitionSchemaResolution {
        &self.definition_schema
    }

    pub fn selector_path(&self) -> &PolicySelectorPath {
        &self.selector_path
    }

    pub const fn selector_schema(&self) -> SchemaVersionResolution {
        self.selector_schema
    }

    pub fn model(&self) -> &ResolvedEndpointModel {
        &self.model
    }

    pub const fn semantic_hash(&self) -> EndpointSemanticHash {
        self.semantic_hash
    }

    pub const fn analysis_projection_hash(&self) -> EndpointAnalysisProjectionHash {
        self.analysis_projection_hash
    }

    pub fn origins(&self) -> &[EndpointOrigin] {
        &self.origins
    }

    /// Mint a local or catalog endpoint from its complete typed composed
    /// projection. No caller supplies either endpoint hash.
    pub(crate) fn from_composed_model(
        identity: ResolvedEndpointIdentity,
        definition_schema: EndpointDefinitionSchemaResolution,
        selector: &ResolvedPolicySelector,
        model: ResolvedEndpointModel,
        origins: Vec<EndpointOrigin>,
    ) -> Result<Self, LoadedModelError> {
        match (&identity, &definition_schema) {
            (
                ResolvedEndpointIdentity::Local { .. },
                EndpointDefinitionSchemaResolution::PolicyDocument { .. },
            )
            | (
                ResolvedEndpointIdentity::Catalog { .. },
                EndpointDefinitionSchemaResolution::CatalogDocument { .. },
            ) => {}
            (ResolvedEndpointIdentity::MatchEndpoint { .. }, _) => {
                return invalid("standalone match endpoints must use from_loaded_match_endpoint");
            }
            _ => {
                return invalid(
                    "local/catalog endpoint identity disagrees with its definition schema",
                );
            }
        }
        validate_role_taint(model.role, model.taint.as_ref())?;
        let semantic_hash = EndpointSemanticHash::from_composed_endpoint(
            &identity,
            &definition_schema,
            selector,
            &model,
        );
        let analysis_projection_hash = EndpointAnalysisProjectionHash::from_composed_endpoint(
            &definition_schema,
            selector,
            &model,
        );
        Ok(Self::new(
            identity,
            definition_schema,
            selector.path.clone(),
            selector.schema_resolution,
            model,
            semantic_hash,
            analysis_projection_hash,
            origins,
        ))
    }

    /// Re-key a separately loaded endpoint into one policy while preserving
    /// the full hashes minted from the endpoint's complete source definition.
    pub(crate) fn from_loaded_match_endpoint(
        endpoint: &LoadedEndpoint,
        selector: &ResolvedPolicySelector,
        mut supersedes: Vec<ResolvedEndpointIdentity>,
        origins: Vec<EndpointOrigin>,
    ) -> Result<Self, LoadedModelError> {
        if endpoint.resolved_selector.semantic_hash != selector.semantic_hash {
            return invalid("re-keyed endpoint selector differs from the loaded endpoint");
        }
        supersedes.sort();
        if contains_duplicates(supersedes.iter().cloned()) {
            return invalid("re-keyed endpoint supersedes identities must be unique");
        }
        let expected_supersedes = endpoint
            .definition
            .supersedes
            .iter()
            .map(|endpoint_id| ResolvedEndpointIdentity::MatchEndpoint {
                endpoint_id: endpoint_id.clone(),
            })
            .collect::<Vec<_>>();
        if !same_set(&supersedes, &expected_supersedes) {
            return invalid("re-keyed endpoint supersedes differ from its loaded definition");
        }
        let model = ResolvedEndpointModel::new(
            endpoint.definition.role,
            endpoint.definition.display_name.clone(),
            endpoint.definition.categories.clone(),
            endpoint.definition.binding.clone(),
            endpoint.definition.taint.clone(),
            supersedes,
        );
        Ok(Self::new(
            ResolvedEndpointIdentity::MatchEndpoint {
                endpoint_id: endpoint.definition.id.clone(),
            },
            EndpointDefinitionSchemaResolution::PolicyDocument {
                resolution: endpoint.schema_resolution,
            },
            selector.path.clone(),
            selector.schema_resolution,
            model,
            endpoint.semantic_hash,
            endpoint.analysis_projection_hash,
            origins,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedEndpointManifestEntry {
    pub identity: ResolvedEndpointIdentity,
    pub definition_schema: EndpointDefinitionSchemaResolution,
    pub selector_schema: SchemaVersionResolution,
    pub semantic_hash: EndpointSemanticHash,
    pub analysis_projection_hash: EndpointAnalysisProjectionHash,
}

impl From<&ResolvedEndpointDependency> for ResolvedEndpointManifestEntry {
    fn from(dependency: &ResolvedEndpointDependency) -> Self {
        Self {
            identity: dependency.identity.clone(),
            definition_schema: dependency.definition_schema.clone(),
            selector_schema: dependency.selector_schema,
            semantic_hash: dependency.semantic_hash,
            analysis_projection_hash: dependency.analysis_projection_hash,
        }
    }
}

/// Transactional result of one explicit match-directory dependency.
#[derive(Debug, Clone)]
pub struct ResolvedMatchDirectoryManifest {
    pub(crate) path: PolicyDependencyPath,
    pub(crate) directory: WorkspaceRelativePath,
    pub(crate) scope: DirectoryScope,
    pub(crate) role: Option<EndpointRole>,
    pub(crate) categories: CategoryPredicate,
    pub(crate) selected: Vec<ResolvedEndpointManifestEntry>,
    pub(crate) semantic_hash: MatchSetManifestHash,
}

impl ResolvedMatchDirectoryManifest {
    pub fn try_new(
        path: PolicyDependencyPath,
        directory: WorkspaceRelativePath,
        scope: DirectoryScope,
        role: Option<EndpointRole>,
        categories: CategoryPredicate,
        mut selected: Vec<ResolvedEndpointManifestEntry>,
    ) -> Result<Self, LoadedModelError> {
        selected.sort_by(|left, right| left.identity.cmp(&right.identity));
        if selected
            .windows(2)
            .any(|entries| entries[0].identity == entries[1].identity)
        {
            return Err(LoadedModelError::DuplicateManifestEndpoint);
        }
        let semantic_hash =
            MatchSetManifestHash::from_resolved_selection(scope, role, &categories, &selected);
        Ok(Self {
            path,
            directory,
            scope,
            role,
            categories,
            selected,
            semantic_hash,
        })
    }

    pub fn path(&self) -> &PolicyDependencyPath {
        &self.path
    }

    pub fn directory(&self) -> &WorkspaceRelativePath {
        &self.directory
    }

    pub const fn scope(&self) -> DirectoryScope {
        self.scope
    }

    pub const fn role(&self) -> Option<EndpointRole> {
        self.role
    }

    pub const fn categories(&self) -> &CategoryPredicate {
        &self.categories
    }

    pub fn selected(&self) -> &[ResolvedEndpointManifestEntry] {
        &self.selected
    }

    pub const fn semantic_hash(&self) -> MatchSetManifestHash {
        self.semantic_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedPrecedenceEdge {
    Endpoint {
        dominant: ResolvedEndpointIdentity,
        dominated: ResolvedEndpointIdentity,
    },
    FindingCombination {
        dominant: FindingCombinationId,
        dominated: FindingCombinationId,
    },
    TypestateEvent {
        dominant: TypestateEventId,
        dominated: TypestateEventId,
    },
    TypestateExpectation {
        dominant: TypestateExpectationId,
        dominated: TypestateExpectationId,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyPrecedenceManifest {
    pub edges: Vec<ResolvedPrecedenceEdge>,
}

impl PolicyPrecedenceManifest {
    pub fn new(mut edges: Vec<ResolvedPrecedenceEdge>) -> Self {
        edges.sort();
        edges.dedup();
        Self { edges }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTaintEndpoint<T> {
    pub identity: ResolvedEndpointIdentity,
    pub semantic_hash: EndpointSemanticHash,
    pub analysis_projection_hash: EndpointAnalysisProjectionHash,
    pub definition: T,
    pub origins: Vec<EndpointOrigin>,
}

impl<T> ResolvedTaintEndpoint<T> {
    pub fn new(
        identity: ResolvedEndpointIdentity,
        semantic_hash: EndpointSemanticHash,
        analysis_projection_hash: EndpointAnalysisProjectionHash,
        definition: T,
        mut origins: Vec<EndpointOrigin>,
    ) -> Self {
        origins.sort();
        origins.dedup();
        Self {
            identity,
            semantic_hash,
            analysis_projection_hash,
            definition,
            origins,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTaintSourceDefinition {
    pub display_name: String,
    pub categories: Vec<PolicyCategoryId>,
    pub selector_path: PolicySelectorPath,
    pub bind: PolicyPort,
    pub labels: Vec<TaintLabel>,
    pub evidence: Option<TaintSourceEvidence>,
}

#[derive(Debug, Clone)]
pub struct ResolvedTaintSinkDefinition {
    pub display_name: String,
    pub categories: Vec<PolicyCategoryId>,
    pub selector_path: PolicySelectorPath,
    pub dangerous_operand: PolicyPort,
    pub accepts: Vec<TaintLabel>,
    pub tags: Vec<TaintTag>,
    pub impacts: Vec<TaintImpact>,
}

/// One policy-local or catalog auxiliary taint entry after composition.
///
/// The qualified identity prevents equal entry IDs in different catalogs from
/// aliasing, while `selector_path` closes the entry over the one already
/// lowered query retained by [`LoadedPolicy`].
#[derive(Debug, Clone)]
pub struct ResolvedTaintAuxiliary<T> {
    pub identity: ResolvedEndpointIdentity,
    pub selector_path: PolicySelectorPath,
    pub definition: T,
    pub origins: Vec<EndpointOrigin>,
}

impl<T> ResolvedTaintAuxiliary<T> {
    pub fn new(
        identity: ResolvedEndpointIdentity,
        selector_path: PolicySelectorPath,
        definition: T,
        mut origins: Vec<EndpointOrigin>,
    ) -> Self {
        origins.sort();
        origins.dedup();
        Self {
            identity,
            selector_path,
            definition,
            origins,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTaintSanitizerDefinition {
    pub input: PolicyPort,
    pub output: PolicyPort,
    pub removes: Vec<TaintLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTaintTransformDefinition {
    pub input: PolicyPort,
    pub output: PolicyPort,
    pub removes: Vec<TaintLabel>,
    pub adds: Vec<TaintLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTaintExternalModelDefinition {
    pub transfers: Vec<TaintTransferSpec>,
}

#[derive(Debug, Clone)]
pub struct ResolvedFindingCombination {
    pub id: FindingCombinationId,
    pub source_endpoints: Vec<ResolvedEndpointIdentity>,
    pub sink_endpoints: Vec<ResolvedEndpointIdentity>,
    pub message: String,
    pub severity: Option<PolicySeveritySpec>,
    pub add_classifications: Vec<TaxonomyClassificationSpec>,
    pub supersedes: Vec<FindingCombinationId>,
}

impl ResolvedFindingCombination {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FindingCombinationId,
        mut source_endpoints: Vec<ResolvedEndpointIdentity>,
        mut sink_endpoints: Vec<ResolvedEndpointIdentity>,
        message: String,
        severity: Option<PolicySeveritySpec>,
        mut add_classifications: Vec<TaxonomyClassificationSpec>,
        mut supersedes: Vec<FindingCombinationId>,
    ) -> Self {
        source_endpoints.sort();
        source_endpoints.dedup();
        sink_endpoints.sort();
        sink_endpoints.dedup();
        add_classifications.sort_by(|left, right| {
            (&left.taxonomy, &left.identifier, &left.name).cmp(&(
                &right.taxonomy,
                &right.identifier,
                &right.name,
            ))
        });
        add_classifications.dedup();
        supersedes.sort();
        supersedes.dedup();
        Self {
            id,
            source_endpoints,
            sink_endpoints,
            message,
            severity,
            add_classifications,
            supersedes,
        }
    }
}

/// Finite, set-oriented taint input. It never contains a source/sink pair product.
#[derive(Debug, Clone)]
pub struct ResolvedTaintPolicySpec {
    pub mode: MayMode,
    pub sources: Vec<ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>>,
    pub sinks: Vec<ResolvedTaintEndpoint<ResolvedTaintSinkDefinition>>,
    pub sanitizers: Vec<ResolvedTaintAuxiliary<ResolvedTaintSanitizerDefinition>>,
    pub transforms: Vec<ResolvedTaintAuxiliary<ResolvedTaintTransformDefinition>>,
    pub external_models: Vec<ResolvedTaintAuxiliary<ResolvedTaintExternalModelDefinition>>,
    pub catalogs: Vec<ResolvedCatalogIdentity>,
    pub match_manifests: Vec<ResolvedMatchDirectoryManifest>,
    pub finding_combinations: Vec<ResolvedFindingCombination>,
}

impl ResolvedTaintPolicySpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: MayMode,
        mut sources: Vec<ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>>,
        mut sinks: Vec<ResolvedTaintEndpoint<ResolvedTaintSinkDefinition>>,
        mut sanitizers: Vec<ResolvedTaintAuxiliary<ResolvedTaintSanitizerDefinition>>,
        mut transforms: Vec<ResolvedTaintAuxiliary<ResolvedTaintTransformDefinition>>,
        mut external_models: Vec<ResolvedTaintAuxiliary<ResolvedTaintExternalModelDefinition>>,
        mut catalogs: Vec<ResolvedCatalogIdentity>,
        mut match_manifests: Vec<ResolvedMatchDirectoryManifest>,
        mut finding_combinations: Vec<ResolvedFindingCombination>,
    ) -> Self {
        sources.sort_by(|left, right| left.identity.cmp(&right.identity));
        sinks.sort_by(|left, right| left.identity.cmp(&right.identity));
        sanitizers.sort_by(|left, right| left.identity.cmp(&right.identity));
        transforms.sort_by(|left, right| left.identity.cmp(&right.identity));
        external_models.sort_by(|left, right| left.identity.cmp(&right.identity));
        catalogs.sort();
        catalogs.dedup();
        match_manifests.sort_by(|left, right| left.path.cmp(&right.path));
        finding_combinations.sort_by(|left, right| left.id.cmp(&right.id));
        Self {
            mode,
            sources,
            sinks,
            sanitizers,
            transforms,
            external_models,
            catalogs,
            match_manifests,
            finding_combinations,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTypestatePolicySpec {
    pub mode: MayMode,
    pub subjects: Vec<ResolvedTypestateSubject>,
    pub uncertainty: TypestateUncertaintySpec,
    pub automaton: ResolvedTypestateAutomatonSpec,
    pub endpoint_dependencies: Vec<ResolvedEndpointDependency>,
    pub match_manifests: Vec<ResolvedMatchDirectoryManifest>,
    pub authoring_projection_hash: TypestateAuthoringProjectionHash,
}

impl ResolvedTypestatePolicySpec {
    pub fn try_new(
        mode: MayMode,
        mut subjects: Vec<ResolvedTypestateSubject>,
        uncertainty: TypestateUncertaintySpec,
        mut automaton: ResolvedTypestateAutomatonSpec,
        mut endpoint_dependencies: Vec<ResolvedEndpointDependency>,
        mut match_manifests: Vec<ResolvedMatchDirectoryManifest>,
    ) -> Result<Self, LoadedModelError> {
        subjects.sort_by(|left, right| left.identity.cmp(&right.identity));
        endpoint_dependencies.sort_by(|left, right| left.identity.cmp(&right.identity));
        match_manifests.sort_by(|left, right| left.path.cmp(&right.path));
        automaton.normalize();
        let mut result = Self {
            mode,
            subjects,
            uncertainty,
            automaton,
            endpoint_dependencies,
            match_manifests,
            authoring_projection_hash: TypestateAuthoringProjectionHash::from_bytes([0; 32]),
        };
        result.authoring_projection_hash = TypestateAuthoringProjectionHash::from_spec(&result)?;
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTypestateSubject {
    pub identity: ResolvedEndpointIdentity,
    pub selector_path: PolicySelectorPath,
    pub binding: ResolvedTypestateBinding,
    pub semantic_hash: EndpointSemanticHash,
    pub analysis_projection_hash: EndpointAnalysisProjectionHash,
    pub origins: Vec<EndpointOrigin>,
}

impl ResolvedTypestateSubject {
    pub fn new(
        identity: ResolvedEndpointIdentity,
        selector_path: PolicySelectorPath,
        binding: ResolvedTypestateBinding,
        semantic_hash: EndpointSemanticHash,
        analysis_projection_hash: EndpointAnalysisProjectionHash,
        mut origins: Vec<EndpointOrigin>,
    ) -> Self {
        origins.sort();
        origins.dedup();
        Self {
            identity,
            selector_path,
            binding,
            semantic_hash,
            analysis_projection_hash,
            origins,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTypestateBinding {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex { index: u32 },
    ArgumentName { name: String },
}

#[derive(Debug, Clone)]
pub struct ResolvedTypestateAutomatonSpec {
    pub states: Vec<TypestateStateId>,
    pub initial: TypestateStateId,
    pub accepting_states: Vec<TypestateStateId>,
    pub error_states: Vec<TypestateStateId>,
    pub events: Vec<ResolvedTypestateEventSpec>,
    pub transitions: Vec<TypestateTransitionSpec>,
    pub terminal_expectations: Vec<ResolvedTypestateTerminalExpectationSpec>,
}

impl ResolvedTypestateAutomatonSpec {
    fn normalize(&mut self) {
        self.states.sort();
        self.states.dedup();
        self.accepting_states.sort();
        self.accepting_states.dedup();
        self.error_states.sort();
        self.error_states.dedup();
        self.events.sort_by(|left, right| left.id.cmp(&right.id));
        self.transitions.sort_by(|left, right| {
            (&left.from, &left.on, &left.to).cmp(&(&right.from, &right.on, &right.to))
        });
        self.terminal_expectations
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTypestateEventSpec {
    pub id: TypestateEventId,
    pub trigger: ResolvedTypestateEventTrigger,
    pub applies_to_subjects: Vec<ResolvedEndpointIdentity>,
    pub supersedes: Vec<TypestateEventId>,
}

impl ResolvedTypestateEventSpec {
    pub fn new(
        id: TypestateEventId,
        trigger: ResolvedTypestateEventTrigger,
        mut applies_to_subjects: Vec<ResolvedEndpointIdentity>,
        mut supersedes: Vec<TypestateEventId>,
    ) -> Self {
        applies_to_subjects.sort();
        applies_to_subjects.dedup();
        supersedes.sort();
        supersedes.dedup();
        Self {
            id,
            trigger,
            applies_to_subjects,
            supersedes,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedTypestateEventTrigger {
    Calls {
        selector_path: PolicySelectorPath,
        subject: TypestateCallBinding,
        phase: EndpointObservationPhase,
    },
    MatchEndpoints {
        endpoints: Vec<ResolvedEndpointIdentity>,
        phase: EndpointObservationPhase,
    },
    SemanticEvent {
        event: PolicySemanticEvent,
    },
}

#[derive(Debug, Clone)]
pub struct ResolvedTypestateTerminalExpectationSpec {
    pub id: TypestateExpectationId,
    pub trigger: ResolvedTypestateTerminalTrigger,
    pub applies_to_subjects: Vec<ResolvedEndpointIdentity>,
    pub expected_states: Vec<TypestateStateId>,
    pub supersedes: Vec<TypestateExpectationId>,
}

impl ResolvedTypestateTerminalExpectationSpec {
    pub fn new(
        id: TypestateExpectationId,
        trigger: ResolvedTypestateTerminalTrigger,
        mut applies_to_subjects: Vec<ResolvedEndpointIdentity>,
        mut expected_states: Vec<TypestateStateId>,
        mut supersedes: Vec<TypestateExpectationId>,
    ) -> Self {
        applies_to_subjects.sort();
        applies_to_subjects.dedup();
        expected_states.sort();
        expected_states.dedup();
        supersedes.sort();
        supersedes.dedup();
        Self {
            id,
            trigger,
            applies_to_subjects,
            expected_states,
            supersedes,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedTypestateTerminalTrigger {
    MatchEndpoints {
        endpoints: Vec<ResolvedEndpointIdentity>,
        phase: EndpointObservationPhase,
    },
    SemanticEvent {
        event: PolicySemanticEvent,
    },
}

/// A reusable endpoint document with both presentation and analyzer identities.
#[derive(Debug, Clone)]
pub struct LoadedEndpoint {
    definition: MatchEndpointDefinition,
    source: PolicySourceIdentity,
    source_hash: PolicySourceHash,
    semantic_hash: EndpointSemanticHash,
    analysis_projection_hash: EndpointAnalysisProjectionHash,
    schema_resolution: SchemaVersionResolution,
    resolved_selector: ResolvedPolicySelector,
}

impl LoadedEndpoint {
    /// Registry-only minting seam. Public callers receive immutable loaded
    /// values from `PolicyRegistry`; they cannot attach unverified hashes.
    pub(crate) fn try_new(
        definition: MatchEndpointDefinition,
        source: PolicySourceIdentity,
        source_bytes: &[u8],
        schema_resolution: SchemaVersionResolution,
        resolved_selector: ResolvedPolicySelector,
    ) -> Result<Self, LoadedModelError> {
        if definition.schema_version.version != schema_resolution.version {
            return Err(LoadedModelError::DefinitionSchemaMismatch);
        }
        if resolved_selector.path.as_str() != "/endpoint/selector" {
            return Err(LoadedModelError::UnexpectedEndpointSelectorPath {
                path: resolved_selector.path,
            });
        }
        validate_role_taint(definition.role, definition.taint.as_ref())?;
        validate_authored_selector_resolution(&definition.selector, &resolved_selector)?;
        let semantic_hash =
            EndpointSemanticHash::from_loaded_endpoint(&definition, &resolved_selector)?;
        let analysis_projection_hash =
            EndpointAnalysisProjectionHash::from_loaded_endpoint(&definition, &resolved_selector)?;
        Ok(Self {
            definition,
            source,
            source_hash: PolicySourceHash::from_source_bytes(source_bytes),
            semantic_hash,
            analysis_projection_hash,
            schema_resolution,
            resolved_selector,
        })
    }

    pub fn definition(&self) -> &MatchEndpointDefinition {
        &self.definition
    }

    pub fn source(&self) -> &PolicySourceIdentity {
        &self.source
    }

    pub const fn source_hash(&self) -> PolicySourceHash {
        self.source_hash
    }

    pub const fn semantic_hash(&self) -> EndpointSemanticHash {
        self.semantic_hash
    }

    pub const fn analysis_projection_hash(&self) -> EndpointAnalysisProjectionHash {
        self.analysis_projection_hash
    }

    pub const fn schema_resolution(&self) -> SchemaVersionResolution {
        self.schema_resolution
    }

    pub fn resolved_selector(&self) -> &ResolvedPolicySelector {
        &self.resolved_selector
    }

    pub fn to_canonical_semantic_json(&self) -> serde_json::Value {
        canonical_loaded::loaded_endpoint_semantic_to_json(
            &self.definition,
            &self.resolved_selector,
        )
        .expect("validated loaded endpoint must retain a closed canonical projection")
    }
}

/// A validated policy after every reference and composition dependency is closed.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    definition: PolicyDefinition,
    source: PolicySourceIdentity,
    source_hash: PolicySourceHash,
    semantic_hash: PolicySemanticHash,
    schema_resolution: SchemaVersionResolution,
    resolved_selectors: Vec<ResolvedPolicySelector>,
    selector_origins: Vec<SelectorOrigin>,
    catalogs: Vec<ResolvedCatalogIdentity>,
    endpoint_dependencies: Vec<ResolvedEndpointDependency>,
    match_directory_manifests: Vec<ResolvedMatchDirectoryManifest>,
    precedence_manifest: PolicyPrecedenceManifest,
    resolved_taint: Option<ResolvedTaintPolicySpec>,
    resolved_typestate: Option<ResolvedTypestatePolicySpec>,
}

impl LoadedPolicy {
    #[allow(clippy::too_many_arguments)]
    /// Registry-only minting seam. The public authoring graph is intentionally
    /// constructible, but only the loader/registry may close it into semantic
    /// identity after validating every resolved dependency.
    pub(crate) fn try_new(
        definition: PolicyDefinition,
        source: PolicySourceIdentity,
        source_bytes: &[u8],
        schema_resolution: SchemaVersionResolution,
        mut resolved_selectors: Vec<ResolvedPolicySelector>,
        mut catalogs: Vec<ResolvedCatalogIdentity>,
        mut endpoint_dependencies: Vec<ResolvedEndpointDependency>,
        mut match_directory_manifests: Vec<ResolvedMatchDirectoryManifest>,
        mut precedence_manifest: PolicyPrecedenceManifest,
        resolved_taint: Option<ResolvedTaintPolicySpec>,
        resolved_typestate: Option<ResolvedTypestatePolicySpec>,
    ) -> Result<Self, LoadedModelError> {
        if definition.schema_version.version != schema_resolution.version {
            return Err(LoadedModelError::DefinitionSchemaMismatch);
        }
        validate_resolved_analysis(&definition.analysis, &resolved_taint, &resolved_typestate)?;

        resolved_selectors.sort_by(|left, right| left.path.cmp(&right.path));
        if resolved_selectors
            .windows(2)
            .any(|selectors| selectors[0].path == selectors[1].path)
        {
            return Err(LoadedModelError::DuplicateSelectorPath);
        }
        endpoint_dependencies.sort_by(|left, right| left.identity.cmp(&right.identity));
        if endpoint_dependencies
            .windows(2)
            .any(|dependencies| dependencies[0].identity == dependencies[1].identity)
        {
            return Err(LoadedModelError::DuplicateEndpointIdentity);
        }
        catalogs.sort();
        catalogs.dedup();
        match_directory_manifests.sort_by(|left, right| left.path.cmp(&right.path));
        if match_directory_manifests
            .windows(2)
            .any(|manifests| manifests[0].path == manifests[1].path)
        {
            return Err(LoadedModelError::DuplicateManifestPath);
        }
        precedence_manifest.edges.sort();
        if precedence_manifest
            .edges
            .windows(2)
            .any(|edges| edges[0] == edges[1])
        {
            return Err(LoadedModelError::DuplicatePrecedenceEdge);
        }

        validate_selector_closure(
            &definition,
            &resolved_selectors,
            &endpoint_dependencies,
            resolved_taint.as_ref(),
        )?;
        validate_loaded_policy_model(
            &definition,
            &catalogs,
            &resolved_selectors,
            &endpoint_dependencies,
            &match_directory_manifests,
            &precedence_manifest,
            resolved_taint.as_ref(),
            resolved_typestate.as_ref(),
        )?;

        let analysis = match (&definition.analysis, &resolved_taint, &resolved_typestate) {
            (PolicyAnalysis::Match { .. }, None, None) => ResolvedPolicyAnalysisRef::Match,
            (PolicyAnalysis::Taint { .. }, Some(spec), None) => {
                ResolvedPolicyAnalysisRef::Taint { spec }
            }
            (PolicyAnalysis::Typestate { .. }, None, Some(spec)) => {
                ResolvedPolicyAnalysisRef::Typestate { spec }
            }
            _ => return Err(LoadedModelError::ResolvedAnalysisMismatch),
        };
        let semantic_hash = PolicySemanticHash::from_resolved_policy(
            &definition,
            analysis,
            &resolved_selectors,
            &catalogs,
            &endpoint_dependencies,
            &match_directory_manifests,
            &precedence_manifest,
        )?;
        let selector_origins = resolved_selectors
            .iter()
            .map(|selector| selector.origin.clone())
            .collect();
        Ok(Self {
            definition,
            source,
            source_hash: PolicySourceHash::from_source_bytes(source_bytes),
            semantic_hash,
            schema_resolution,
            resolved_selectors,
            selector_origins,
            catalogs,
            endpoint_dependencies,
            match_directory_manifests,
            precedence_manifest,
            resolved_taint,
            resolved_typestate,
        })
    }

    pub fn definition(&self) -> &PolicyDefinition {
        &self.definition
    }

    pub fn source(&self) -> &PolicySourceIdentity {
        &self.source
    }

    pub const fn source_hash(&self) -> PolicySourceHash {
        self.source_hash
    }

    pub const fn semantic_hash(&self) -> PolicySemanticHash {
        self.semantic_hash
    }

    pub const fn schema_resolution(&self) -> SchemaVersionResolution {
        self.schema_resolution
    }

    pub fn resolved_selectors(&self) -> &[ResolvedPolicySelector] {
        &self.resolved_selectors
    }

    pub fn selector_origins(&self) -> &[SelectorOrigin] {
        &self.selector_origins
    }

    pub fn catalogs(&self) -> &[ResolvedCatalogIdentity] {
        &self.catalogs
    }

    pub fn endpoint_dependencies(&self) -> &[ResolvedEndpointDependency] {
        &self.endpoint_dependencies
    }

    pub fn match_directory_manifests(&self) -> &[ResolvedMatchDirectoryManifest] {
        &self.match_directory_manifests
    }

    pub const fn precedence_manifest(&self) -> &PolicyPrecedenceManifest {
        &self.precedence_manifest
    }

    pub const fn resolved_taint(&self) -> Option<&ResolvedTaintPolicySpec> {
        self.resolved_taint.as_ref()
    }

    pub const fn resolved_typestate(&self) -> Option<&ResolvedTypestatePolicySpec> {
        self.resolved_typestate.as_ref()
    }

    pub fn to_canonical_semantic_json(&self) -> serde_json::Value {
        canonical_loaded::loaded_policy_to_json(self)
            .expect("validated loaded policy must retain a closed canonical projection")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadedModelError {
    DefinitionSchemaMismatch,
    SelectorSchemaMismatch {
        path: PolicySelectorPath,
        resolution: u32,
        query: u64,
    },
    UnexpectedEndpointSelectorPath {
        path: PolicySelectorPath,
    },
    DuplicateSelectorPath,
    MissingSelectorPath {
        path: PolicySelectorPath,
    },
    UnexpectedSelectorPath {
        path: PolicySelectorPath,
    },
    DuplicateEndpointIdentity,
    DuplicateManifestEndpoint,
    DuplicateManifestPath,
    DuplicatePrecedenceEdge,
    SelectorHashMismatch {
        path: PolicySelectorPath,
    },
    ManifestHashMismatch {
        path: PolicyDependencyPath,
    },
    InvalidResolvedModel {
        reason: &'static str,
    },
    PrecedenceCycle {
        domain: &'static str,
    },
    ZeroCatalogVersion,
    ResolvedAnalysisMismatch,
    CanonicalProjection(String),
}

impl fmt::Display for LoadedModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinitionSchemaMismatch => {
                formatter.write_str("definition schema version differs from its loaded resolution")
            }
            Self::SelectorSchemaMismatch {
                path,
                resolution,
                query,
            } => write!(
                formatter,
                "selector {path} resolves schema {resolution}, but its query carries schema {query}"
            ),
            Self::UnexpectedEndpointSelectorPath { path } => {
                write!(
                    formatter,
                    "endpoint selector must use /endpoint/selector, not {path}"
                )
            }
            Self::DuplicateSelectorPath => {
                formatter.write_str("loaded selectors contain a duplicate semantic path")
            }
            Self::MissingSelectorPath { path } => {
                write!(formatter, "loaded policy is missing selector {path}")
            }
            Self::UnexpectedSelectorPath { path } => {
                write!(
                    formatter,
                    "loaded policy contains unexpected selector {path}"
                )
            }
            Self::DuplicateEndpointIdentity => {
                formatter.write_str("loaded endpoint dependencies contain a duplicate identity")
            }
            Self::DuplicateManifestEndpoint => {
                formatter.write_str("match-directory manifest contains a duplicate endpoint")
            }
            Self::DuplicateManifestPath => formatter
                .write_str("loaded policy contains duplicate match-directory dependency paths"),
            Self::DuplicatePrecedenceEdge => {
                formatter.write_str("precedence manifest contains a duplicate edge")
            }
            Self::SelectorHashMismatch { path } => {
                write!(
                    formatter,
                    "loaded selector {path} has a forged semantic hash"
                )
            }
            Self::ManifestHashMismatch { path } => {
                write!(
                    formatter,
                    "match-directory manifest {path} has a forged semantic hash"
                )
            }
            Self::InvalidResolvedModel { reason } => formatter.write_str(reason),
            Self::PrecedenceCycle { domain } => {
                write!(formatter, "{domain} precedence contains a cycle")
            }
            Self::ZeroCatalogVersion => {
                formatter.write_str("resolved catalog version must be at least 1")
            }
            Self::ResolvedAnalysisMismatch => formatter.write_str(
                "resolved taint/typestate value does not match the authored analysis variant",
            ),
            Self::CanonicalProjection(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for LoadedModelError {}

#[allow(clippy::too_many_arguments)]
fn validate_loaded_policy_model(
    definition: &PolicyDefinition,
    catalogs: &[ResolvedCatalogIdentity],
    selectors: &[ResolvedPolicySelector],
    dependencies: &[ResolvedEndpointDependency],
    manifests: &[ResolvedMatchDirectoryManifest],
    precedence: &PolicyPrecedenceManifest,
    resolved_taint: Option<&ResolvedTaintPolicySpec>,
    resolved_typestate: Option<&ResolvedTypestatePolicySpec>,
) -> Result<(), LoadedModelError> {
    for selector in selectors {
        if u64::from(selector.schema_resolution.version) != selector.query.schema_version {
            return Err(LoadedModelError::SelectorSchemaMismatch {
                path: selector.path.clone(),
                resolution: selector.schema_resolution.version,
                query: selector.query.schema_version,
            });
        }
        let expected = ResolvedSelectorSemanticHash::from_query(
            selector.schema_resolution.version,
            &selector.query,
        );
        if selector.semantic_hash != expected {
            return Err(LoadedModelError::SelectorHashMismatch {
                path: selector.path.clone(),
            });
        }
    }

    let selector_by_path: HashMap<_, _> = selectors
        .iter()
        .map(|selector| (&selector.path, selector))
        .collect();
    validate_authored_policy_selectors(definition, &selector_by_path)?;
    let dependency_by_identity: HashMap<_, _> = dependencies
        .iter()
        .map(|dependency| (&dependency.identity, dependency))
        .collect();

    for catalog in catalogs {
        if catalog.version == 0 {
            return invalid("resolved catalog version must be at least 1");
        }
    }
    for dependency in dependencies {
        validate_role_taint(dependency.model.role, dependency.model.taint.as_ref())?;
        if dependency.definition_schema.version() == 0 {
            return invalid("resolved endpoint definition schema must be at least 1");
        }
        if dependency.origins.is_empty() {
            return invalid("resolved endpoint dependency requires provenance");
        }
        if contains_duplicates(dependency.origins.iter().cloned()) {
            return invalid("resolved endpoint origins must be duplicate-free");
        }
        if contains_duplicates(dependency.model.categories.iter().cloned()) {
            return invalid("resolved endpoint categories must be duplicate-free");
        }
        if contains_duplicates(dependency.model.supersedes.iter().cloned()) {
            return invalid("resolved endpoint supersedes must be duplicate-free");
        }
        if dependency.model.supersedes.contains(&dependency.identity) {
            return invalid("resolved endpoint cannot supersede itself");
        }
        let selector = selector_by_path
            .get(&dependency.selector_path)
            .ok_or_else(|| LoadedModelError::MissingSelectorPath {
                path: dependency.selector_path.clone(),
            })?;
        if selector.schema_resolution.version != dependency.selector_schema.version {
            return invalid("endpoint dependency selector schema does not match its selector");
        }
        for target in &dependency.model.supersedes {
            if !dependency_by_identity.contains_key(target) {
                return invalid("endpoint supersedes target is not in the resolved dependency set");
            }
        }
        if let ResolvedEndpointIdentity::Catalog { catalog, .. } = &dependency.identity
            && !catalogs.contains(catalog)
        {
            return invalid("endpoint dependency references a catalog absent from the policy");
        }
    }

    for manifest in manifests {
        if manifest
            .selected
            .windows(2)
            .any(|entries| entries[0].identity >= entries[1].identity)
        {
            return invalid("match-directory manifest entries must be identity-sorted and unique");
        }
        let expected = MatchSetManifestHash::from_resolved_selection(
            manifest.scope,
            manifest.role,
            &manifest.categories,
            &manifest.selected,
        );
        if manifest.semantic_hash != expected {
            return Err(LoadedModelError::ManifestHashMismatch {
                path: manifest.path.clone(),
            });
        }
        for entry in &manifest.selected {
            let dependency = dependency_by_identity.get(&entry.identity).ok_or(
                LoadedModelError::InvalidResolvedModel {
                    reason: "match-directory manifest endpoint is absent from dependencies",
                },
            )?;
            if dependency.definition_schema.version() != entry.definition_schema.version()
                || dependency.selector_schema.version != entry.selector_schema.version
                || dependency.semantic_hash != entry.semantic_hash
                || dependency.analysis_projection_hash != entry.analysis_projection_hash
            {
                return invalid(
                    "match-directory manifest endpoint differs from its resolved dependency",
                );
            }
        }
    }

    match (&definition.analysis, resolved_taint, resolved_typestate) {
        (PolicyAnalysis::Match { .. }, None, None) => {
            if !catalogs.is_empty()
                || !dependencies.is_empty()
                || !manifests.is_empty()
                || !precedence.edges.is_empty()
            {
                return invalid("match policy cannot retain composition dependencies");
            }
        }
        (PolicyAnalysis::Taint { spec: authored }, Some(resolved), None) => {
            validate_resolved_taint(
                &definition.metadata.id,
                authored,
                resolved,
                catalogs,
                dependencies,
                manifests,
            )?;
        }
        (PolicyAnalysis::Typestate { spec: authored }, None, Some(resolved)) => {
            validate_resolved_typestate(
                &definition.metadata.id,
                authored,
                resolved,
                dependencies,
                manifests,
                selectors,
            )?;
        }
        _ => return Err(LoadedModelError::ResolvedAnalysisMismatch),
    }
    validate_precedence(precedence, dependencies, resolved_taint, resolved_typestate)
}

fn validate_resolved_taint(
    policy_id: &PolicyId,
    authored: &TaintPolicySpec,
    resolved: &ResolvedTaintPolicySpec,
    catalogs: &[ResolvedCatalogIdentity],
    dependencies: &[ResolvedEndpointDependency],
    manifests: &[ResolvedMatchDirectoryManifest],
) -> Result<(), LoadedModelError> {
    if authored.mode != resolved.mode {
        return invalid("resolved taint mode differs from the authored policy");
    }
    if resolved.sources.is_empty() || resolved.sinks.is_empty() {
        return invalid("resolved taint policy requires non-empty source and sink sets");
    }
    if contains_duplicates(
        resolved
            .sanitizers
            .iter()
            .map(|entry| entry.identity.clone())
            .chain(
                resolved
                    .transforms
                    .iter()
                    .map(|entry| entry.identity.clone()),
            )
            .chain(
                resolved
                    .external_models
                    .iter()
                    .map(|entry| entry.identity.clone()),
            ),
    ) {
        return invalid("resolved auxiliary taint identities must be globally unique");
    }
    for entry in &resolved.sanitizers {
        validate_resolved_auxiliary(entry, "sanitizers", policy_id, catalogs)?;
    }
    for entry in &resolved.transforms {
        validate_resolved_auxiliary(entry, "transforms", policy_id, catalogs)?;
    }
    for entry in &resolved.external_models {
        validate_resolved_auxiliary(entry, "external_models", policy_id, catalogs)?;
    }
    let endpoint_identities = resolved
        .sources
        .iter()
        .map(|endpoint| endpoint.identity.clone())
        .chain(
            resolved
                .sinks
                .iter()
                .map(|endpoint| endpoint.identity.clone()),
        )
        .collect::<Vec<_>>();
    if contains_duplicates(endpoint_identities.iter().cloned()) {
        return invalid("resolved taint source/sink identities must be globally unique");
    }
    let dependency_identities = dependencies
        .iter()
        .map(|dependency| dependency.identity.clone())
        .collect::<HashSet<_>>();
    if endpoint_identities.iter().cloned().collect::<HashSet<_>>() != dependency_identities {
        return invalid("resolved taint endpoints and dependency identities must match exactly");
    }

    let dependencies_by_identity: HashMap<_, _> = dependencies
        .iter()
        .map(|dependency| (&dependency.identity, dependency))
        .collect();
    for endpoint in &resolved.sources {
        validate_resolved_taint_source(endpoint, &dependencies_by_identity)?;
    }
    for endpoint in &resolved.sinks {
        validate_resolved_taint_sink(endpoint, &dependencies_by_identity)?;
    }

    for source in &authored.sources.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: source.id.clone(),
        };
        let Some(endpoint) = resolved
            .sources
            .iter()
            .find(|endpoint| endpoint.identity == identity)
        else {
            return invalid("authored local taint source is absent from the resolved source set");
        };
        let expected_path = PolicySelectorPath::new(format!(
            "/analysis/sources/entries/{}/selector",
            json_pointer_segment(source.id.as_str())
        ))
        .map_err(|error| LoadedModelError::CanonicalProjection(error.to_string()))?;
        if endpoint.definition.display_name != source.display_name
            || !same_set(&endpoint.definition.categories, &source.categories)
            || endpoint.definition.selector_path != expected_path
            || endpoint.definition.bind != source.bind
            || !same_set(&endpoint.definition.labels, &source.labels)
            || endpoint.definition.evidence != source.evidence
        {
            return invalid("resolved local taint source differs from its authored definition");
        }
    }
    for sink in &authored.sinks.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: sink.id.clone(),
        };
        let Some(endpoint) = resolved
            .sinks
            .iter()
            .find(|endpoint| endpoint.identity == identity)
        else {
            return invalid("authored local taint sink is absent from the resolved sink set");
        };
        let expected_path = PolicySelectorPath::new(format!(
            "/analysis/sinks/entries/{}/selector",
            json_pointer_segment(sink.id.as_str())
        ))
        .map_err(|error| LoadedModelError::CanonicalProjection(error.to_string()))?;
        if endpoint.definition.display_name != sink.display_name
            || !same_set(&endpoint.definition.categories, &sink.categories)
            || endpoint.definition.selector_path != expected_path
            || endpoint.definition.dangerous_operand != sink.dangerous_operand
            || !same_set(&endpoint.definition.accepts, &sink.accepts)
            || !same_set(&endpoint.definition.tags, &sink.tags)
            || !same_set(&endpoint.definition.impacts, &sink.impacts)
        {
            return invalid("resolved local taint sink differs from its authored definition");
        }
    }

    for authored_entry in &authored.sanitizers.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: authored_entry.id.clone(),
        };
        let resolved_entry = resolved
            .sanitizers
            .iter()
            .find(|entry| entry.identity == identity)
            .ok_or(LoadedModelError::InvalidResolvedModel {
                reason: "authored local sanitizer is absent from the resolved sanitizer set",
            })?;
        if resolved_entry.definition.input != authored_entry.input
            || resolved_entry.definition.output != authored_entry.output
            || !same_set(&resolved_entry.definition.removes, &authored_entry.removes)
        {
            return invalid("resolved local sanitizer differs from its authored definition");
        }
    }
    for authored_entry in &authored.transforms.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: authored_entry.id.clone(),
        };
        let resolved_entry = resolved
            .transforms
            .iter()
            .find(|entry| entry.identity == identity)
            .ok_or(LoadedModelError::InvalidResolvedModel {
                reason: "authored local transform is absent from the resolved transform set",
            })?;
        if resolved_entry.definition.input != authored_entry.input
            || resolved_entry.definition.output != authored_entry.output
            || !same_set(&resolved_entry.definition.removes, &authored_entry.removes)
            || !same_set(&resolved_entry.definition.adds, &authored_entry.adds)
        {
            return invalid("resolved local transform differs from its authored definition");
        }
    }
    for authored_entry in &authored.external_models.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: authored_entry.id.clone(),
        };
        let resolved_entry = resolved
            .external_models
            .iter()
            .find(|entry| entry.identity == identity)
            .ok_or(LoadedModelError::InvalidResolvedModel {
                reason:
                    "authored local external model is absent from the resolved external-model set",
            })?;
        if !same_unordered(
            &resolved_entry.definition.transfers,
            &authored_entry.transfers,
        ) {
            return invalid("resolved local external model differs from its authored definition");
        }
    }

    let authored_combinations = authored
        .finding_combinations
        .iter()
        .map(|combination| combination.id.clone())
        .collect::<HashSet<_>>();
    let resolved_combinations = resolved
        .finding_combinations
        .iter()
        .map(|combination| combination.id.clone())
        .collect::<Vec<_>>();
    if contains_duplicates(resolved_combinations.iter().cloned())
        || authored_combinations
            != resolved_combinations
                .iter()
                .cloned()
                .collect::<HashSet<_>>()
    {
        return invalid("resolved finding-combination IDs differ from authored IDs");
    }
    for combination in &resolved.finding_combinations {
        if combination.source_endpoints.is_empty() || combination.sink_endpoints.is_empty() {
            return invalid("resolved finding combination requires non-empty source and sink sets");
        }
        if contains_duplicates(combination.source_endpoints.iter().cloned())
            || contains_duplicates(combination.sink_endpoints.iter().cloned())
            || contains_duplicates(combination.supersedes.iter().cloned())
        {
            return invalid("resolved finding-combination sets must be duplicate-free");
        }
        if !combination.source_endpoints.iter().all(|identity| {
            resolved
                .sources
                .iter()
                .any(|source| source.identity == *identity)
        }) || !combination
            .sink_endpoints
            .iter()
            .all(|identity| resolved.sinks.iter().any(|sink| sink.identity == *identity))
        {
            return invalid("resolved finding combination references an endpoint outside its side");
        }
        let authored_combination = authored
            .finding_combinations
            .iter()
            .find(|candidate| candidate.id == combination.id)
            .expect("resolved combination ID closure checked above");
        if combination.message != authored_combination.message
            || combination.severity != authored_combination.severity
            || !same_unordered(
                &combination.add_classifications,
                &authored_combination.add_classifications,
            )
            || !same_set(&combination.supersedes, &authored_combination.supersedes)
        {
            return invalid(
                "resolved finding-combination presentation differs from authored policy",
            );
        }
    }

    if normalized_catalogs(&resolved.catalogs) != normalized_catalogs(catalogs) {
        return invalid("resolved taint catalog manifest differs from the loaded policy");
    }
    for reference in authored
        .sources
        .include_sets
        .iter()
        .chain(authored.sinks.include_sets.iter())
        .chain(authored.sanitizers.include_sets.iter())
        .chain(authored.transforms.include_sets.iter())
        .chain(authored.external_models.include_sets.iter())
    {
        let catalog = catalogs
            .iter()
            .find(|catalog| catalog.name == reference.name && catalog.version == reference.version);
        let Some(catalog) = catalog else {
            return invalid("authored catalog reference is absent from the resolved catalog set");
        };
        if reference
            .sha256
            .is_some_and(|pin| pin != catalog.semantic_hash)
        {
            return invalid("authored catalog hash pin differs from the resolved catalog");
        }
    }
    if manifest_hashes(&resolved.match_manifests) != manifest_hashes(manifests) {
        return invalid("resolved taint match manifests differ from the loaded policy");
    }
    Ok(())
}

fn validate_resolved_taint_source(
    endpoint: &ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
    dependencies: &HashMap<&ResolvedEndpointIdentity, &ResolvedEndpointDependency>,
) -> Result<(), LoadedModelError> {
    if endpoint.origins.is_empty() || contains_duplicates(endpoint.origins.iter().cloned()) {
        return invalid("resolved taint source requires duplicate-free provenance");
    }
    if endpoint.definition.labels.is_empty()
        || contains_duplicates(endpoint.definition.labels.iter().cloned())
        || contains_duplicates(endpoint.definition.categories.iter().cloned())
    {
        return invalid("resolved taint source labels/categories are invalid");
    }
    let dependency =
        dependencies
            .get(&endpoint.identity)
            .ok_or(LoadedModelError::InvalidResolvedModel {
                reason: "resolved taint source has no endpoint dependency",
            })?;
    let EndpointTaintSemantics::Source { labels, evidence } = dependency
        .model
        .taint
        .as_ref()
        .ok_or(LoadedModelError::InvalidResolvedModel {
            reason: "resolved taint source dependency has no source semantics",
        })?
    else {
        return invalid("resolved taint source dependency has sink semantics");
    };
    if dependency.model.role != EndpointRole::Source
        || endpoint.semantic_hash != dependency.semantic_hash
        || endpoint.analysis_projection_hash != dependency.analysis_projection_hash
        || endpoint.definition.selector_path != dependency.selector_path
        || endpoint.definition.display_name != dependency.model.display_name
        || !same_set(
            &endpoint.definition.categories,
            &dependency.model.categories,
        )
        || endpoint.definition.bind != endpoint_binding_to_port(&dependency.model.binding)
        || !same_set(&endpoint.definition.labels, labels)
        || endpoint.definition.evidence != *evidence
        || !same_set(&endpoint.origins, &dependency.origins)
    {
        return invalid("resolved taint source differs from its endpoint dependency");
    }
    Ok(())
}

fn validate_resolved_taint_sink(
    endpoint: &ResolvedTaintEndpoint<ResolvedTaintSinkDefinition>,
    dependencies: &HashMap<&ResolvedEndpointIdentity, &ResolvedEndpointDependency>,
) -> Result<(), LoadedModelError> {
    if endpoint.origins.is_empty() || contains_duplicates(endpoint.origins.iter().cloned()) {
        return invalid("resolved taint sink requires duplicate-free provenance");
    }
    if endpoint.definition.accepts.is_empty()
        || contains_duplicates(endpoint.definition.accepts.iter().cloned())
        || contains_duplicates(endpoint.definition.categories.iter().cloned())
        || contains_duplicates(endpoint.definition.tags.iter().cloned())
        || contains_duplicates(endpoint.definition.impacts.iter().cloned())
    {
        return invalid("resolved taint sink accepts/categories/tags/impacts are invalid");
    }
    let dependency =
        dependencies
            .get(&endpoint.identity)
            .ok_or(LoadedModelError::InvalidResolvedModel {
                reason: "resolved taint sink has no endpoint dependency",
            })?;
    let EndpointTaintSemantics::Sink {
        accepts,
        tags,
        impacts,
    } = dependency
        .model
        .taint
        .as_ref()
        .ok_or(LoadedModelError::InvalidResolvedModel {
            reason: "resolved taint sink dependency has no sink semantics",
        })?
    else {
        return invalid("resolved taint sink dependency has source semantics");
    };
    if dependency.model.role != EndpointRole::Sink
        || endpoint.semantic_hash != dependency.semantic_hash
        || endpoint.analysis_projection_hash != dependency.analysis_projection_hash
        || endpoint.definition.selector_path != dependency.selector_path
        || endpoint.definition.display_name != dependency.model.display_name
        || !same_set(
            &endpoint.definition.categories,
            &dependency.model.categories,
        )
        || endpoint.definition.dangerous_operand
            != endpoint_binding_to_port(&dependency.model.binding)
        || !same_set(&endpoint.definition.accepts, accepts)
        || !same_set(&endpoint.definition.tags, tags)
        || !same_set(&endpoint.definition.impacts, impacts)
        || !same_set(&endpoint.origins, &dependency.origins)
    {
        return invalid("resolved taint sink differs from its endpoint dependency");
    }
    Ok(())
}

fn validate_resolved_typestate(
    policy_id: &PolicyId,
    authored: &TypestatePolicySpec,
    resolved: &ResolvedTypestatePolicySpec,
    dependencies: &[ResolvedEndpointDependency],
    manifests: &[ResolvedMatchDirectoryManifest],
    selectors: &[ResolvedPolicySelector],
) -> Result<(), LoadedModelError> {
    if resolved.mode != authored.mode || resolved.uncertainty != authored.uncertainty {
        return invalid("resolved typestate mode/uncertainty differs from the authored policy");
    }
    if resolved.subjects.is_empty() {
        return invalid("resolved typestate policy requires at least one subject");
    }
    if contains_duplicates(
        resolved
            .subjects
            .iter()
            .map(|subject| subject.identity.clone()),
    ) {
        return invalid("resolved typestate subject identities must be unique");
    }
    if !same_dependency_manifest(&resolved.endpoint_dependencies, dependencies) {
        return invalid("resolved typestate dependency manifest differs from the loaded policy");
    }
    if manifest_hashes(&resolved.match_manifests) != manifest_hashes(manifests) {
        return invalid("resolved typestate match manifests differ from the loaded policy");
    }
    let dependency_by_identity: HashMap<_, _> = dependencies
        .iter()
        .map(|dependency| (&dependency.identity, dependency))
        .collect();
    let subject_identities: HashSet<_> = resolved
        .subjects
        .iter()
        .map(|subject| subject.identity.clone())
        .collect();
    for subject in &resolved.subjects {
        let dependency = dependency_by_identity.get(&subject.identity).ok_or(
            LoadedModelError::InvalidResolvedModel {
                reason: "resolved typestate subject has no dependency",
            },
        )?;
        if subject.origins.is_empty()
            || contains_duplicates(subject.origins.iter().cloned())
            || dependency.model.role != EndpointRole::Source
            || matches!(
                dependency.model.taint,
                Some(EndpointTaintSemantics::Sink { .. })
            )
            || subject.selector_path != dependency.selector_path
            || subject.semantic_hash != dependency.semantic_hash
            || subject.analysis_projection_hash != dependency.analysis_projection_hash
            || resolved_binding_to_endpoint(&subject.binding) != dependency.model.binding
            || !same_set(&subject.origins, &dependency.origins)
        {
            return invalid("resolved typestate subject differs from its endpoint dependency");
        }
    }
    for authored_subject in &authored.subjects.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: authored_subject.id.clone(),
        };
        if !subject_identities.contains(&identity) {
            return invalid("authored local typestate subject is absent from resolved subjects");
        }
        let resolved_subject = resolved
            .subjects
            .iter()
            .find(|subject| subject.identity == identity)
            .expect("authored subject inclusion checked above");
        if resolved_subject.binding != seed_binding_to_resolved(&authored_subject.subject) {
            return invalid(
                "resolved local typestate subject binding differs from authored binding",
            );
        }
    }

    validate_typestate_automaton(
        &authored.automaton,
        &resolved.automaton,
        &subject_identities,
        &dependency_by_identity,
        selectors,
    )?;
    let expected_hash = TypestateAuthoringProjectionHash::from_spec(resolved)?;
    if resolved.authoring_projection_hash != expected_hash {
        return invalid("resolved typestate authoring projection hash is forged");
    }
    Ok(())
}

fn validate_typestate_automaton(
    authored: &TypestateAutomatonSpec,
    resolved: &ResolvedTypestateAutomatonSpec,
    subject_identities: &HashSet<ResolvedEndpointIdentity>,
    dependencies: &HashMap<&ResolvedEndpointIdentity, &ResolvedEndpointDependency>,
    selectors: &[ResolvedPolicySelector],
) -> Result<(), LoadedModelError> {
    if resolved.states.is_empty()
        || resolved.accepting_states.is_empty()
        || resolved.error_states.is_empty()
        || contains_duplicates(resolved.states.iter().cloned())
        || contains_duplicates(resolved.accepting_states.iter().cloned())
        || contains_duplicates(resolved.error_states.iter().cloned())
    {
        return invalid("resolved typestate state sets are invalid");
    }
    let states: HashSet<_> = resolved.states.iter().cloned().collect();
    let accepting: HashSet<_> = resolved.accepting_states.iter().cloned().collect();
    let errors: HashSet<_> = resolved.error_states.iter().cloned().collect();
    if !states.contains(&resolved.initial)
        || !accepting.is_subset(&states)
        || !errors.is_subset(&states)
        || !accepting.is_disjoint(&errors)
    {
        return invalid("resolved typestate states violate initial/accepting/error closure");
    }
    if !same_set(&resolved.states, &authored.states)
        || resolved.initial != authored.initial
        || !same_set(&resolved.accepting_states, &authored.accepting_states)
        || !same_set(&resolved.error_states, &authored.error_states)
    {
        return invalid("resolved typestate state graph differs from the authored graph");
    }

    let event_ids = resolved
        .events
        .iter()
        .map(|event| event.id.clone())
        .collect::<Vec<_>>();
    if contains_duplicates(event_ids.iter().cloned())
        || event_ids.iter().cloned().collect::<HashSet<_>>()
            != authored
                .events
                .iter()
                .map(|event| event.id.clone())
                .collect()
    {
        return invalid("resolved typestate event IDs differ from authored IDs");
    }
    for event in &resolved.events {
        if contains_duplicates(event.applies_to_subjects.iter().cloned())
            || contains_duplicates(event.supersedes.iter().cloned())
            || !event
                .applies_to_subjects
                .iter()
                .all(|identity| subject_identities.contains(identity))
        {
            return invalid("resolved typestate event subject/supersedes set is invalid");
        }
        validate_event_trigger(&event.trigger, dependencies, selectors)?;
        let authored_event = authored
            .events
            .iter()
            .find(|candidate| candidate.id == event.id)
            .expect("resolved event ID closure checked above");
        if !same_set(&event.supersedes, &authored_event.supersedes)
            || !event_trigger_matches_authored(
                &event.trigger,
                &authored_event.trigger,
                dependencies,
            )
        {
            return invalid("resolved typestate event differs from its authored declaration");
        }
    }

    let expectation_ids = resolved
        .terminal_expectations
        .iter()
        .map(|expectation| expectation.id.clone())
        .collect::<Vec<_>>();
    if contains_duplicates(expectation_ids.iter().cloned())
        || expectation_ids.iter().cloned().collect::<HashSet<_>>()
            != authored
                .terminal_expectations
                .iter()
                .map(|expectation| expectation.id.clone())
                .collect()
    {
        return invalid("resolved typestate expectation IDs differ from authored IDs");
    }
    for expectation in &resolved.terminal_expectations {
        if expectation.expected_states.is_empty()
            || contains_duplicates(expectation.applies_to_subjects.iter().cloned())
            || contains_duplicates(expectation.expected_states.iter().cloned())
            || contains_duplicates(expectation.supersedes.iter().cloned())
            || !expectation
                .applies_to_subjects
                .iter()
                .all(|identity| subject_identities.contains(identity))
            || !expectation
                .expected_states
                .iter()
                .all(|state| accepting.contains(state))
        {
            return invalid("resolved typestate terminal expectation is invalid");
        }
        validate_terminal_trigger(&expectation.trigger, dependencies)?;
        let authored_expectation = authored
            .terminal_expectations
            .iter()
            .find(|candidate| candidate.id == expectation.id)
            .expect("resolved expectation ID closure checked above");
        if !same_set(
            &expectation.expected_states,
            &authored_expectation.expected_states,
        ) || !same_set(&expectation.supersedes, &authored_expectation.supersedes)
            || !terminal_trigger_matches_authored(
                &expectation.trigger,
                &authored_expectation.trigger,
                dependencies,
            )
        {
            return invalid(
                "resolved typestate terminal expectation differs from authored declaration",
            );
        }
    }

    let event_set: HashSet<_> = event_ids.into_iter().collect();
    let mut transition_keys = HashSet::new();
    for transition in &resolved.transitions {
        if !states.contains(&transition.from)
            || !states.contains(&transition.to)
            || !event_set.contains(&transition.on)
            || !transition_keys.insert((transition.from.clone(), transition.on.clone()))
        {
            return invalid("resolved typestate transition is invalid or nondeterministic");
        }
    }
    if resolved.transitions != authored.transitions {
        return invalid("resolved typestate transitions differ from authored transitions");
    }
    Ok(())
}

fn validate_event_trigger(
    trigger: &ResolvedTypestateEventTrigger,
    dependencies: &HashMap<&ResolvedEndpointIdentity, &ResolvedEndpointDependency>,
    selectors: &[ResolvedPolicySelector],
) -> Result<(), LoadedModelError> {
    match trigger {
        ResolvedTypestateEventTrigger::Calls { selector_path, .. } => {
            if !selectors
                .iter()
                .any(|selector| selector.path == *selector_path)
            {
                return Err(LoadedModelError::MissingSelectorPath {
                    path: selector_path.clone(),
                });
            }
        }
        ResolvedTypestateEventTrigger::MatchEndpoints { endpoints, .. } => {
            if endpoints.is_empty()
                || contains_duplicates(endpoints.iter().cloned())
                || !endpoints
                    .iter()
                    .all(|identity| dependencies.contains_key(identity))
            {
                return invalid("resolved typestate endpoint event is empty or unresolved");
            }
        }
        ResolvedTypestateEventTrigger::SemanticEvent { .. } => {}
    }
    Ok(())
}

fn validate_terminal_trigger(
    trigger: &ResolvedTypestateTerminalTrigger,
    dependencies: &HashMap<&ResolvedEndpointIdentity, &ResolvedEndpointDependency>,
) -> Result<(), LoadedModelError> {
    if let ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, .. } = trigger
        && (endpoints.is_empty()
            || contains_duplicates(endpoints.iter().cloned())
            || !endpoints
                .iter()
                .all(|identity| dependencies.contains_key(identity)))
    {
        return invalid("resolved typestate endpoint terminal is empty or unresolved");
    }
    Ok(())
}

fn event_trigger_matches_authored(
    resolved: &ResolvedTypestateEventTrigger,
    authored: &TypestateEventTrigger,
    dependencies: &HashMap<&ResolvedEndpointIdentity, &ResolvedEndpointDependency>,
) -> bool {
    match (resolved, authored) {
        (
            ResolvedTypestateEventTrigger::Calls {
                subject: resolved_subject,
                phase: resolved_phase,
                ..
            },
            TypestateEventTrigger::Calls { subject, phase, .. },
        ) => resolved_subject == subject && resolved_phase == phase,
        (
            ResolvedTypestateEventTrigger::MatchEndpoints { endpoints, phase },
            TypestateEventTrigger::MatchEndpoints {
                role,
                phase: authored_phase,
                ..
            },
        ) => {
            phase == authored_phase
                && endpoints.iter().all(|identity| {
                    dependencies
                        .get(identity)
                        .is_some_and(|dependency| dependency.model.role == *role)
                })
        }
        (
            ResolvedTypestateEventTrigger::SemanticEvent { event: resolved },
            TypestateEventTrigger::SemanticEvent { event: authored },
        ) => resolved == authored,
        _ => false,
    }
}

fn terminal_trigger_matches_authored(
    resolved: &ResolvedTypestateTerminalTrigger,
    authored: &TypestateTerminalTrigger,
    dependencies: &HashMap<&ResolvedEndpointIdentity, &ResolvedEndpointDependency>,
) -> bool {
    match (resolved, authored) {
        (
            ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, phase },
            TypestateTerminalTrigger::MatchEndpoints {
                role,
                phase: authored_phase,
                ..
            },
        ) => {
            phase == authored_phase
                && endpoints.iter().all(|identity| {
                    dependencies
                        .get(identity)
                        .is_some_and(|dependency| dependency.model.role == *role)
                })
        }
        (
            ResolvedTypestateTerminalTrigger::SemanticEvent { event: resolved },
            TypestateTerminalTrigger::SemanticEvent { event: authored },
        ) => resolved == authored,
        _ => false,
    }
}

fn validate_precedence(
    manifest: &PolicyPrecedenceManifest,
    dependencies: &[ResolvedEndpointDependency],
    taint: Option<&ResolvedTaintPolicySpec>,
    typestate: Option<&ResolvedTypestatePolicySpec>,
) -> Result<(), LoadedModelError> {
    let mut expected = Vec::new();
    for dependency in dependencies {
        for dominated in &dependency.model.supersedes {
            expected.push(ResolvedPrecedenceEdge::Endpoint {
                dominant: dependency.identity.clone(),
                dominated: dominated.clone(),
            });
        }
    }
    if let Some(taint) = taint {
        for combination in &taint.finding_combinations {
            for dominated in &combination.supersedes {
                expected.push(ResolvedPrecedenceEdge::FindingCombination {
                    dominant: combination.id.clone(),
                    dominated: dominated.clone(),
                });
            }
        }
    }
    if let Some(typestate) = typestate {
        for event in &typestate.automaton.events {
            for dominated in &event.supersedes {
                expected.push(ResolvedPrecedenceEdge::TypestateEvent {
                    dominant: event.id.clone(),
                    dominated: dominated.clone(),
                });
            }
        }
        for expectation in &typestate.automaton.terminal_expectations {
            for dominated in &expectation.supersedes {
                expected.push(ResolvedPrecedenceEdge::TypestateExpectation {
                    dominant: expectation.id.clone(),
                    dominated: dominated.clone(),
                });
            }
        }
    }
    expected.sort();
    if expected != manifest.edges {
        return invalid("precedence manifest is not the complete resolved supersedes graph");
    }

    validate_edge_domain(
        "endpoint",
        dependencies.iter().map(|item| item.identity.clone()),
        manifest.edges.iter().filter_map(|edge| match edge {
            ResolvedPrecedenceEdge::Endpoint {
                dominant,
                dominated,
            } => Some((dominant.clone(), dominated.clone())),
            _ => None,
        }),
    )?;
    if let Some(taint) = taint {
        validate_edge_domain(
            "finding-combination",
            taint
                .finding_combinations
                .iter()
                .map(|item| item.id.clone()),
            manifest.edges.iter().filter_map(|edge| match edge {
                ResolvedPrecedenceEdge::FindingCombination {
                    dominant,
                    dominated,
                } => Some((dominant.clone(), dominated.clone())),
                _ => None,
            }),
        )?;
    }
    if let Some(typestate) = typestate {
        validate_edge_domain(
            "typestate-event",
            typestate
                .automaton
                .events
                .iter()
                .map(|item| item.id.clone()),
            manifest.edges.iter().filter_map(|edge| match edge {
                ResolvedPrecedenceEdge::TypestateEvent {
                    dominant,
                    dominated,
                } => Some((dominant.clone(), dominated.clone())),
                _ => None,
            }),
        )?;
        validate_edge_domain(
            "typestate-expectation",
            typestate
                .automaton
                .terminal_expectations
                .iter()
                .map(|item| item.id.clone()),
            manifest.edges.iter().filter_map(|edge| match edge {
                ResolvedPrecedenceEdge::TypestateExpectation {
                    dominant,
                    dominated,
                } => Some((dominant.clone(), dominated.clone())),
                _ => None,
            }),
        )?;
    }
    Ok(())
}

fn validate_edge_domain<T>(
    domain: &'static str,
    nodes: impl IntoIterator<Item = T>,
    edges: impl IntoIterator<Item = (T, T)>,
) -> Result<(), LoadedModelError>
where
    T: Clone + Eq + std::hash::Hash,
{
    let nodes = nodes.into_iter().collect::<HashSet<_>>();
    let edges = edges.into_iter().collect::<Vec<_>>();
    let mut indegrees = nodes
        .iter()
        .cloned()
        .map(|node| (node, 0_usize))
        .collect::<HashMap<_, _>>();
    let mut outgoing: HashMap<T, Vec<T>> = HashMap::new();
    for (dominant, dominated) in edges {
        if dominant == dominated || !nodes.contains(&dominant) || !nodes.contains(&dominated) {
            return invalid("precedence edge is self-referential or leaves its domain");
        }
        *indegrees
            .get_mut(&dominated)
            .expect("checked precedence target") += 1;
        outgoing.entry(dominant).or_default().push(dominated);
    }
    let mut stack = indegrees
        .iter()
        .filter_map(|(node, degree)| (*degree == 0).then_some(node.clone()))
        .collect::<Vec<_>>();
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        visited += 1;
        if let Some(targets) = outgoing.get(&node) {
            for target in targets {
                let degree = indegrees
                    .get_mut(target)
                    .expect("checked precedence target");
                *degree -= 1;
                if *degree == 0 {
                    stack.push(target.clone());
                }
            }
        }
    }
    if visited != nodes.len() {
        return Err(LoadedModelError::PrecedenceCycle { domain });
    }
    Ok(())
}

fn validate_role_taint(
    role: EndpointRole,
    taint: Option<&EndpointTaintSemantics>,
) -> Result<(), LoadedModelError> {
    match (role, taint) {
        (EndpointRole::Source, Some(EndpointTaintSemantics::Source { labels, evidence })) => {
            if labels.is_empty() || contains_duplicates(labels.iter().cloned()) {
                return invalid("source endpoint taint labels must be non-empty and unique");
            }
            if evidence.as_ref().is_some_and(|evidence| {
                evidence.trust_boundary.is_none() && evidence.system_entry.is_none()
            }) {
                return invalid("source endpoint evidence must establish at least one fact");
            }
        }
        (
            EndpointRole::Sink,
            Some(EndpointTaintSemantics::Sink {
                accepts,
                tags,
                impacts,
            }),
        ) => {
            if accepts.is_empty()
                || contains_duplicates(accepts.iter().cloned())
                || contains_duplicates(tags.iter().cloned())
                || contains_duplicates(impacts.iter().cloned())
            {
                return invalid("sink endpoint taint sets are incomplete or duplicated");
            }
        }
        (_, None) => {}
        _ => return invalid("endpoint role and taint-semantics variant disagree"),
    }
    Ok(())
}

fn validate_authored_policy_selectors(
    definition: &PolicyDefinition,
    selectors: &HashMap<&PolicySelectorPath, &ResolvedPolicySelector>,
) -> Result<(), LoadedModelError> {
    match &definition.analysis {
        PolicyAnalysis::Match { spec } => {
            validate_authored_selector_at("/analysis/selector", &spec.selector, selectors)?
        }
        PolicyAnalysis::Taint { spec } => {
            for source in &spec.sources.entries {
                validate_authored_selector_at(
                    &format!(
                        "/analysis/sources/entries/{}/selector",
                        json_pointer_segment(source.id.as_str())
                    ),
                    &source.selector,
                    selectors,
                )?;
            }
            for sink in &spec.sinks.entries {
                validate_authored_selector_at(
                    &format!(
                        "/analysis/sinks/entries/{}/selector",
                        json_pointer_segment(sink.id.as_str())
                    ),
                    &sink.selector,
                    selectors,
                )?;
            }
            for sanitizer in &spec.sanitizers.entries {
                validate_authored_selector_at(
                    &format!(
                        "/analysis/sanitizers/entries/{}/selector",
                        json_pointer_segment(sanitizer.id.as_str())
                    ),
                    &sanitizer.selector,
                    selectors,
                )?;
            }
            for transform in &spec.transforms.entries {
                validate_authored_selector_at(
                    &format!(
                        "/analysis/transforms/entries/{}/selector",
                        json_pointer_segment(transform.id.as_str())
                    ),
                    &transform.selector,
                    selectors,
                )?;
            }
            for model in &spec.external_models.entries {
                validate_authored_selector_at(
                    &format!(
                        "/analysis/external_models/entries/{}/selector",
                        json_pointer_segment(model.id.as_str())
                    ),
                    &model.selector,
                    selectors,
                )?;
            }
        }
        PolicyAnalysis::Typestate { spec } => {
            for subject in &spec.subjects.entries {
                validate_authored_selector_at(
                    &format!(
                        "/analysis/subjects/entries/{}/selector",
                        json_pointer_segment(subject.id.as_str())
                    ),
                    &subject.selector,
                    selectors,
                )?;
            }
            for event in &spec.automaton.events {
                if let TypestateEventTrigger::Calls { selector, .. } = &event.trigger {
                    validate_authored_selector_at(
                        &format!(
                            "/analysis/automaton/events/{}/selector",
                            json_pointer_segment(event.id.as_str())
                        ),
                        selector,
                        selectors,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_authored_selector_at(
    path: &str,
    authored: &PolicySelector,
    selectors: &HashMap<&PolicySelectorPath, &ResolvedPolicySelector>,
) -> Result<(), LoadedModelError> {
    let path = PolicySelectorPath::new(path)
        .map_err(|error| LoadedModelError::CanonicalProjection(error.to_string()))?;
    let resolved = selectors
        .get(&path)
        .ok_or_else(|| LoadedModelError::MissingSelectorPath { path: path.clone() })?;
    validate_authored_selector_resolution(authored, resolved)
}

fn validate_authored_selector_resolution(
    authored: &PolicySelector,
    resolved: &ResolvedPolicySelector,
) -> Result<(), LoadedModelError> {
    match authored {
        PolicySelector::Inline { schema, query } => {
            if resolved.schema_resolution.version != schema.version
                || resolved.query.to_canonical_query_plan_json()
                    != query.to_canonical_query_plan_json()
                || !matches!(resolved.origin, SelectorOrigin::Document { .. })
            {
                return invalid("resolved inline selector differs from its authored query");
            }
        }
        PolicySelector::File {
            authored_schema_version,
            path,
        } => {
            let SelectorOrigin::ReferencedFile {
                reference,
                wrapper_authored_schema_version,
                document_authored_schema_version,
                ..
            } = &resolved.origin
            else {
                return invalid("resolved file selector lacks referenced-file provenance");
            };
            if reference != path || wrapper_authored_schema_version != authored_schema_version {
                return invalid(
                    "resolved file selector provenance differs from its authoring wrapper",
                );
            }
            let expected_origin = if document_authored_schema_version.is_some() {
                crate::schema_version::SchemaVersionOrigin::ReferencedDocumentExplicit
            } else if authored_schema_version.is_some() {
                crate::schema_version::SchemaVersionOrigin::Explicit
            } else {
                crate::schema_version::SchemaVersionOrigin::ImplicitCompatible
            };
            let expected_version = document_authored_schema_version.or(*authored_schema_version);
            if resolved.schema_resolution.origin != expected_origin
                || expected_version
                    .is_some_and(|version| version != resolved.schema_resolution.version)
            {
                return invalid("resolved file selector version precedence is inconsistent");
            }
        }
    }
    Ok(())
}

fn endpoint_binding_to_port(binding: &PolicyEndpointBinding) -> PolicyPort {
    match binding {
        PolicyEndpointBinding::MatchedValue => PolicyPort::MatchedValue,
        PolicyEndpointBinding::Receiver => PolicyPort::Receiver,
        PolicyEndpointBinding::ReturnValue => PolicyPort::ReturnValue,
        PolicyEndpointBinding::ArgumentIndex { index } => {
            PolicyPort::ArgumentIndex { index: *index }
        }
        PolicyEndpointBinding::ArgumentName { name } => {
            PolicyPort::ArgumentName { name: name.clone() }
        }
    }
}

fn resolved_binding_to_endpoint(binding: &ResolvedTypestateBinding) -> PolicyEndpointBinding {
    match binding {
        ResolvedTypestateBinding::MatchedValue => PolicyEndpointBinding::MatchedValue,
        ResolvedTypestateBinding::Receiver => PolicyEndpointBinding::Receiver,
        ResolvedTypestateBinding::ReturnValue => PolicyEndpointBinding::ReturnValue,
        ResolvedTypestateBinding::ArgumentIndex { index } => {
            PolicyEndpointBinding::ArgumentIndex { index: *index }
        }
        ResolvedTypestateBinding::ArgumentName { name } => {
            PolicyEndpointBinding::ArgumentName { name: name.clone() }
        }
    }
}

fn seed_binding_to_resolved(binding: &TypestateSeedBinding) -> ResolvedTypestateBinding {
    match binding {
        TypestateSeedBinding::MatchedValue => ResolvedTypestateBinding::MatchedValue,
        TypestateSeedBinding::Receiver => ResolvedTypestateBinding::Receiver,
        TypestateSeedBinding::ReturnValue => ResolvedTypestateBinding::ReturnValue,
        TypestateSeedBinding::ArgumentIndex { index } => {
            ResolvedTypestateBinding::ArgumentIndex { index: *index }
        }
        TypestateSeedBinding::ArgumentName { name } => {
            ResolvedTypestateBinding::ArgumentName { name: name.clone() }
        }
    }
}

fn validate_resolved_auxiliary<T>(
    entry: &ResolvedTaintAuxiliary<T>,
    set: &str,
    policy_id: &PolicyId,
    catalogs: &[ResolvedCatalogIdentity],
) -> Result<(), LoadedModelError> {
    if entry.origins.is_empty() || contains_duplicates(entry.origins.iter().cloned()) {
        return invalid("resolved auxiliary taint entry requires duplicate-free provenance");
    }
    let (expected_path, expected_origin) = match &entry.identity {
        ResolvedEndpointIdentity::Local {
            policy_id: entry_policy_id,
            entry_id,
        } => {
            if entry_policy_id != policy_id {
                return invalid("resolved local auxiliary belongs to a different policy");
            }
            let base = format!(
                "/analysis/{set}/entries/{}",
                json_pointer_segment(entry_id.as_str())
            );
            (
                selector_path(&format!("{base}/selector"))?,
                EndpointOrigin::PolicyLocal {
                    path: PolicyDependencyPath::new(base).map_err(|error| {
                        LoadedModelError::CanonicalProjection(error.to_string())
                    })?,
                },
            )
        }
        ResolvedEndpointIdentity::Catalog { catalog, entry_id } => {
            if !catalogs.contains(catalog) {
                return invalid("resolved auxiliary references a catalog absent from the policy");
            }
            (
                selector_path(&format!(
                    "/dependencies/catalogs/{}@{}/{}/selector",
                    json_pointer_segment(catalog.name.as_str()),
                    catalog.version,
                    json_pointer_segment(entry_id.as_str())
                ))?,
                EndpointOrigin::Catalog {
                    catalog: catalog.clone(),
                },
            )
        }
        ResolvedEndpointIdentity::MatchEndpoint { .. } => {
            return invalid("match endpoints cannot define auxiliary taint entries");
        }
    };
    if entry.selector_path != expected_path {
        return invalid("resolved auxiliary selector path disagrees with its qualified identity");
    }
    if entry.origins.as_slice() != [expected_origin] {
        return invalid("resolved auxiliary provenance disagrees with its qualified identity");
    }
    Ok(())
}

fn normalized_catalogs(catalogs: &[ResolvedCatalogIdentity]) -> Vec<ResolvedCatalogIdentity> {
    let mut catalogs = catalogs.to_vec();
    catalogs.sort();
    catalogs.dedup();
    catalogs
}

fn manifest_hashes(manifests: &[ResolvedMatchDirectoryManifest]) -> Vec<MatchSetManifestHash> {
    let mut hashes = manifests
        .iter()
        .map(|manifest| manifest.semantic_hash)
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    hashes
}

fn same_dependency_manifest(
    left: &[ResolvedEndpointDependency],
    right: &[ResolvedEndpointDependency],
) -> bool {
    let mut left = left
        .iter()
        .map(|dependency| {
            (
                &dependency.identity,
                dependency.semantic_hash,
                dependency.analysis_projection_hash,
            )
        })
        .collect::<Vec<_>>();
    let mut right = right
        .iter()
        .map(|dependency| {
            (
                &dependency.identity,
                dependency.semantic_hash,
                dependency.analysis_projection_hash,
            )
        })
        .collect::<Vec<_>>();
    left.sort();
    right.sort();
    left == right
}

fn same_set<T>(left: &[T], right: &[T]) -> bool
where
    T: Clone + Ord,
{
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn same_unordered<T: PartialEq>(left: &[T], right: &[T]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|value| right.iter().filter(|candidate| *candidate == value).count() == 1)
}

fn contains_duplicates<T>(values: impl IntoIterator<Item = T>) -> bool
where
    T: Eq + std::hash::Hash,
{
    let mut seen = HashSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}

fn invalid<T>(reason: &'static str) -> Result<T, LoadedModelError> {
    Err(LoadedModelError::InvalidResolvedModel { reason })
}

fn validate_resolved_analysis(
    analysis: &PolicyAnalysis,
    taint: &Option<ResolvedTaintPolicySpec>,
    typestate: &Option<ResolvedTypestatePolicySpec>,
) -> Result<(), LoadedModelError> {
    let valid = matches!(
        (analysis, taint, typestate),
        (PolicyAnalysis::Match { .. }, None, None)
            | (PolicyAnalysis::Taint { .. }, Some(_), None)
            | (PolicyAnalysis::Typestate { .. }, None, Some(_))
    );
    valid
        .then_some(())
        .ok_or(LoadedModelError::ResolvedAnalysisMismatch)
}

fn validate_selector_closure(
    definition: &PolicyDefinition,
    selectors: &[ResolvedPolicySelector],
    dependencies: &[ResolvedEndpointDependency],
    resolved_taint: Option<&ResolvedTaintPolicySpec>,
) -> Result<(), LoadedModelError> {
    let mut expected = expected_selector_paths(definition)?;
    expected.extend(
        dependencies
            .iter()
            .map(|dependency| dependency.selector_path.clone()),
    );
    if let Some(spec) = resolved_taint {
        expected.extend(
            spec.sanitizers
                .iter()
                .map(|entry| entry.selector_path.clone()),
        );
        expected.extend(
            spec.transforms
                .iter()
                .map(|entry| entry.selector_path.clone()),
        );
        expected.extend(
            spec.external_models
                .iter()
                .map(|entry| entry.selector_path.clone()),
        );
    }
    let expected: HashSet<_> = expected.into_iter().collect();
    let actual: HashSet<_> = selectors
        .iter()
        .map(|selector| selector.path.clone())
        .collect();
    if let Some(path) = expected.difference(&actual).min().cloned() {
        return Err(LoadedModelError::MissingSelectorPath { path });
    }
    if let Some(path) = actual.difference(&expected).min().cloned() {
        return Err(LoadedModelError::UnexpectedSelectorPath { path });
    }
    Ok(())
}

fn expected_selector_paths(
    definition: &PolicyDefinition,
) -> Result<Vec<PolicySelectorPath>, LoadedModelError> {
    let mut paths = Vec::new();
    match &definition.analysis {
        PolicyAnalysis::Match { .. } => paths.push(selector_path("/analysis/selector")?),
        PolicyAnalysis::Taint { spec } => {
            extend_taint_paths(&mut paths, "sources", &spec.sources.entries)?;
            extend_taint_paths(&mut paths, "sinks", &spec.sinks.entries)?;
            extend_taint_paths(&mut paths, "sanitizers", &spec.sanitizers.entries)?;
            extend_taint_paths(&mut paths, "transforms", &spec.transforms.entries)?;
            extend_taint_paths(&mut paths, "external_models", &spec.external_models.entries)?;
        }
        PolicyAnalysis::Typestate { spec } => {
            for subject in &spec.subjects.entries {
                paths.push(selector_path(&format!(
                    "/analysis/subjects/entries/{}/selector",
                    json_pointer_segment(subject.id.as_str())
                ))?);
            }
            for event in &spec.automaton.events {
                if matches!(event.trigger, TypestateEventTrigger::Calls { .. }) {
                    paths.push(selector_path(&format!(
                        "/analysis/automaton/events/{}/selector",
                        json_pointer_segment(event.id.as_str())
                    ))?);
                }
            }
        }
    }
    Ok(paths)
}

trait SelectorEntry {
    fn selector_entry_id(&self) -> &TaintEntryId;
}

macro_rules! impl_selector_entry {
    ($($type:ty),+ $(,)?) => {
        $(
            impl SelectorEntry for $type {
                fn selector_entry_id(&self) -> &TaintEntryId {
                    &self.id
                }
            }
        )+
    };
}

impl_selector_entry!(
    TaintSourceSpec,
    TaintSinkSpec,
    TaintSanitizerSpec,
    TaintTransformSpec,
    TaintExternalModelSpec,
);

fn extend_taint_paths<T: SelectorEntry>(
    paths: &mut Vec<PolicySelectorPath>,
    set: &str,
    entries: &[T],
) -> Result<(), LoadedModelError> {
    for entry in entries {
        paths.push(selector_path(&format!(
            "/analysis/{set}/entries/{}/selector",
            json_pointer_segment(entry.selector_entry_id().as_str())
        ))?);
    }
    Ok(())
}

fn selector_path(path: &str) -> Result<PolicySelectorPath, LoadedModelError> {
    PolicySelectorPath::new(path)
        .map_err(|error| LoadedModelError::CanonicalProjection(error.to_string()))
}

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::super::source::parse_rqlp_source;
    use super::*;

    #[test]
    fn loaded_policy_rejects_a_forged_selector_hash() {
        let source = include_str!("../../../tests/fixtures/policies/dynamic-eval.rqlp");
        let (definition, resolution, mut selector) = match_policy_parts(source);
        selector.semantic_hash = ResolvedSelectorSemanticHash::from_bytes([0; 32]);

        let error = LoadedPolicy::try_new(
            definition,
            PolicySourceIdentity::new("policy.rqlp"),
            source.as_bytes(),
            resolution,
            vec![selector],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PolicyPrecedenceManifest::default(),
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            LoadedModelError::SelectorHashMismatch { .. }
        ));
    }

    #[test]
    fn loaded_endpoint_rechecks_role_and_taint_coherence() {
        let source =
            include_str!("../../../tests/fixtures/policies/endpoints/http-request-parameter.rqlp");
        let identity = PolicySourceIdentity::new("endpoint.rqlp");
        let parsed = parse_rqlp_source(source, identity.clone()).unwrap();
        let resolution = parsed.schema_resolution();
        let RqlpDocument::Endpoint { definition } = parsed.into_document() else {
            panic!("fixture must be an endpoint");
        };
        let mut definition = *definition;
        let PolicySelector::Inline { schema, query } = &definition.selector else {
            panic!("fixture selector must be inline");
        };
        let selector = ResolvedPolicySelector::try_new(
            PolicySelectorPath::new("/endpoint/selector").unwrap(),
            *schema,
            query.clone(),
            SelectorOrigin::Document {
                source: identity.clone(),
            },
        )
        .unwrap();
        definition.role = EndpointRole::Sink;

        let error = LoadedEndpoint::try_new(
            definition,
            identity,
            source.as_bytes(),
            resolution,
            selector,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            LoadedModelError::InvalidResolvedModel { .. }
        ));
    }

    #[test]
    fn loaded_policy_rejects_duplicate_manifest_dependency_paths() {
        let source = include_str!("../../../tests/fixtures/policies/dynamic-eval.rqlp");
        let (definition, resolution, selector) = match_policy_parts(source);
        let path = PolicyDependencyPath::new("/dependencies/match-directories/shared").unwrap();
        let categories = CategoryPredicate::Any {
            categories: vec![PolicyCategoryId::new("input.user-controlled").unwrap()],
        };
        let first = ResolvedMatchDirectoryManifest::try_new(
            path.clone(),
            WorkspaceRelativePath::new("policies/first").unwrap(),
            DirectoryScope::Recursive,
            Some(EndpointRole::Source),
            categories.clone(),
            Vec::new(),
        )
        .unwrap();
        let second = ResolvedMatchDirectoryManifest::try_new(
            path,
            WorkspaceRelativePath::new("policies/second").unwrap(),
            DirectoryScope::Recursive,
            Some(EndpointRole::Source),
            categories,
            Vec::new(),
        )
        .unwrap();

        let error = LoadedPolicy::try_new(
            definition,
            PolicySourceIdentity::new("policy.rqlp"),
            source.as_bytes(),
            resolution,
            vec![selector],
            Vec::new(),
            Vec::new(),
            vec![first, second],
            PolicyPrecedenceManifest::default(),
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(error, LoadedModelError::DuplicateManifestPath);
    }

    #[test]
    fn precedence_cycle_detection_is_domain_typed() {
        let first = EndpointId::new("bifrost.sources.first").unwrap();
        let second = EndpointId::new("bifrost.sources.second").unwrap();
        let error = validate_edge_domain(
            "endpoint",
            [first.clone(), second.clone()],
            [(first.clone(), second.clone()), (second, first)],
        )
        .unwrap_err();
        assert_eq!(
            error,
            LoadedModelError::PrecedenceCycle { domain: "endpoint" }
        );
    }

    #[test]
    fn catalog_only_auxiliary_taint_entries_contribute_selector_paths() {
        let catalog = ResolvedCatalogIdentity::try_new(
            PolicyId::new("test.catalog").unwrap(),
            1,
            TaintCatalogHash::from_bytes([7; 32]),
        )
        .unwrap();
        let auxiliary = |entry_id: &str, selector_path: &str| {
            (
                ResolvedEndpointIdentity::Catalog {
                    catalog: catalog.clone(),
                    entry_id: TaintEntryId::new(entry_id).unwrap(),
                },
                PolicySelectorPath::new(selector_path).unwrap(),
                vec![EndpointOrigin::Catalog {
                    catalog: catalog.clone(),
                }],
            )
        };
        let (identity, selector_path, origins) = auxiliary(
            "catalog-sanitizer",
            "/dependencies/catalogs/test.catalog@1/catalog-sanitizer/selector",
        );
        let sanitizer = ResolvedTaintAuxiliary::new(
            identity,
            selector_path,
            ResolvedTaintSanitizerDefinition {
                input: PolicyPort::ArgumentIndex { index: 0 },
                output: PolicyPort::ReturnValue,
                removes: vec![TaintLabel::new("unsafe").unwrap()],
            },
            origins,
        );
        let (identity, selector_path, origins) = auxiliary(
            "catalog-transform",
            "/dependencies/catalogs/test.catalog@1/catalog-transform/selector",
        );
        let transform = ResolvedTaintAuxiliary::new(
            identity,
            selector_path,
            ResolvedTaintTransformDefinition {
                input: PolicyPort::ArgumentIndex { index: 0 },
                output: PolicyPort::ReturnValue,
                removes: vec![TaintLabel::new("encoded").unwrap()],
                adds: vec![TaintLabel::new("unsafe").unwrap()],
            },
            origins,
        );
        let (identity, selector_path, origins) = auxiliary(
            "catalog-model",
            "/dependencies/catalogs/test.catalog@1/catalog-model/selector",
        );
        let model = ResolvedTaintAuxiliary::new(
            identity,
            selector_path,
            ResolvedTaintExternalModelDefinition {
                transfers: vec![TaintTransferSpec {
                    from: PolicyPort::ArgumentIndex { index: 0 },
                    to: PolicyPort::ReturnValue,
                    labels: vec![TaintLabel::new("unsafe").unwrap()],
                    effect: TaintTransferEffect::Propagate,
                }],
            },
            origins,
        );
        let spec = ResolvedTaintPolicySpec::new(
            MayMode::May,
            Vec::new(),
            Vec::new(),
            vec![sanitizer],
            vec![transform],
            vec![model],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let paths = [
            spec.sanitizers[0].selector_path.as_str(),
            spec.transforms[0].selector_path.as_str(),
            spec.external_models[0].selector_path.as_str(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        assert!(paths.contains("/dependencies/catalogs/test.catalog@1/catalog-sanitizer/selector"));
        assert!(paths.contains("/dependencies/catalogs/test.catalog@1/catalog-transform/selector"));
        assert!(paths.contains("/dependencies/catalogs/test.catalog@1/catalog-model/selector"));
    }

    fn match_policy_parts(
        source: &str,
    ) -> (
        PolicyDefinition,
        SchemaVersionResolution,
        ResolvedPolicySelector,
    ) {
        let identity = PolicySourceIdentity::new("policy.rqlp");
        let parsed = parse_rqlp_source(source, identity.clone()).unwrap();
        let resolution = parsed.schema_resolution();
        let RqlpDocument::Policy { definition } = parsed.into_document() else {
            panic!("fixture must be a policy");
        };
        let definition = *definition;
        let PolicyAnalysis::Match { spec } = &definition.analysis else {
            panic!("fixture must be a match policy");
        };
        let PolicySelector::Inline { schema, query } = &spec.selector else {
            panic!("fixture selector must be inline");
        };
        let selector = ResolvedPolicySelector::try_new(
            PolicySelectorPath::new("/analysis/selector").unwrap(),
            *schema,
            query.clone(),
            SelectorOrigin::Document { source: identity },
        )
        .unwrap();
        (definition, resolution, selector)
    }
}
