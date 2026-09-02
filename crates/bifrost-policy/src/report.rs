//! Canonical policy report descriptors and load/coordinator diagnostics.

use std::fmt;
use std::mem::size_of;
use std::ops::Range;

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

use brokk_bifrost_analysis::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};

use super::baseline::PolicyBaselineReview;
use super::budget::PolicyBatchBudget;
use super::definition::{
    CategoryPredicate, DirectoryScope, EndpointRole, EndpointTaintSemantics, MatchSetManifestHash,
    PolicyAnalysisType, PolicyEndpointBinding, PolicyId, PolicyLevel, PolicyMessageSpec,
    PolicySelectorPath, PolicySeveritySpec, TaintCatalogHash, TaintSourceEvidence,
    TaintSystemEntry, TaintTrustBoundary,
};
use super::finding::{
    CompletionReasonError, PolicyDiagnostic, PolicyDiagnosticSeverity, PolicyFinding,
    PolicyFindingError, PolicyIncompleteReason, PolicyRun, PolicyRunCompletion, PolicyRunError,
    completion_allows_diagnostic_impact, normalize_policy_diagnostics_bounded,
};
use super::finding_identity::{FindingIdentityStability, PolicyFindingId};
// The reuse review is a report section, so it is re-exported here beside the
// other reviews; it lives with the units it describes.
use super::identity::{EndpointAnalysisProjectionHash, EndpointSemanticHash, PolicySemanticHash};
use super::resolved::{
    EndpointDefinitionSchemaResolution, EndpointOrigin, LoadedPolicy, PolicyPrecedenceManifest,
    ResolvedCatalogIdentity, ResolvedEndpointDependency, ResolvedEndpointIdentity,
    ResolvedEndpointManifestEntry, ResolvedEndpointModel, ResolvedEndpointSelectorSchemas,
    ResolvedMatchDirectoryManifest, ResolvedPrecedenceEdge,
};
use super::retained::{RetainedSize, retained_extra, retained_vec_size_from_parts};
use super::scope::{PolicyScopeReview, compare_scope_reviews};
use super::source::{PolicySourceIdentity, PolicySourceRelatedDiagnostic};
use super::suppression::{PolicyReportEvaluationContext, PolicySuppressionReview};
pub use super::units::{PolicyIncrementalReview, PolicyIncrementalRun};

const MAX_REPORT_TEXT_BYTES: usize = 4_096;
const MAX_REPORT_RELATED_DIAGNOSTICS: usize = 64;
const MAX_POLICY_EXECUTION_STAGES: usize = 8;
const MAX_POLICY_EXECUTION_PROGRESS_IDS: usize = 256;

/// Resolved RQL schema provenance for one selector retained by a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorSchemaVersionResolution {
    path: PolicySelectorPath,
    resolution: SchemaVersionResolution,
}

impl SelectorSchemaVersionResolution {
    pub fn new(path: PolicySelectorPath, resolution: SchemaVersionResolution) -> Self {
        Self { path, resolution }
    }

    pub const fn path(&self) -> &PolicySelectorPath {
        &self.path
    }

    pub const fn resolution(&self) -> SchemaVersionResolution {
        self.resolution
    }
}

impl RetainedSize for SelectorSchemaVersionResolution {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.path))
    }
}

/// Canonical report projection of one fully loaded executable policy.
#[derive(Debug, Clone)]
pub struct PolicyRuleDescriptor {
    policy_id: PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    policy_schema: SchemaVersionResolution,
    selector_schemas: Vec<SelectorSchemaVersionResolution>,
    endpoint_dependencies: Vec<ResolvedEndpointDependency>,
    match_directory_manifests: Vec<ResolvedMatchDirectoryManifest>,
    precedence_manifest: PolicyPrecedenceManifest,
    name: String,
    message: PolicyMessageSpec,
    severity: PolicySeveritySpec,
    description: Option<String>,
    help_uri: Option<String>,
    tags: Vec<String>,
}

impl PolicyRuleDescriptor {
    pub fn from_loaded(policy: &LoadedPolicy) -> Self {
        let metadata = &policy.definition().metadata;
        let mut selector_schemas = policy
            .resolved_selectors()
            .iter()
            .flat_map(|selector| {
                selector.as_query().map_or_else(
                    || {
                        selector
                            .query_bindings()
                            .into_iter()
                            .map(|binding| {
                                SelectorSchemaVersionResolution::new(
                                    PolicySelectorPath::new(&binding.path)
                                        .expect("resolved row binding path is valid"),
                                    binding.schema_resolution,
                                )
                            })
                            .collect::<Vec<_>>()
                    },
                    |(schema, _)| {
                        vec![SelectorSchemaVersionResolution::new(
                            selector.path.clone(),
                            *schema,
                        )]
                    },
                )
            })
            .collect::<Vec<_>>();
        selector_schemas.sort_by(|left, right| left.path.cmp(&right.path));
        tighten_vec(&mut selector_schemas);

        let mut endpoint_dependencies = policy.endpoint_dependencies().to_vec();
        endpoint_dependencies.sort_by(|left, right| left.identity().cmp(right.identity()));
        tighten_vec(&mut endpoint_dependencies);

        let mut match_directory_manifests = policy.match_directory_manifests().to_vec();
        match_directory_manifests.sort_by(|left, right| left.path().cmp(right.path()));
        tighten_vec(&mut match_directory_manifests);

        let mut tags = metadata.tags.clone();
        tags.sort();
        tags.dedup();
        let mut tags = tags.into_iter().map(tight_string).collect::<Vec<_>>();
        tighten_vec(&mut tags);

        Self {
            policy_id: metadata.id.clone(),
            policy_hash: policy.semantic_hash(),
            analysis_type: policy.definition().analysis.analysis_type(),
            policy_schema: policy.schema_resolution(),
            selector_schemas,
            endpoint_dependencies,
            match_directory_manifests,
            precedence_manifest: policy.precedence_manifest().clone(),
            name: tight_string(metadata.name.clone()),
            message: metadata.message.clone(),
            severity: metadata.severity.clone(),
            description: metadata.description.clone().map(tight_string),
            help_uri: metadata.help_uri.clone().map(tight_string),
            tags,
        }
    }

    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub const fn policy_hash(&self) -> PolicySemanticHash {
        self.policy_hash
    }

    pub const fn analysis_type(&self) -> PolicyAnalysisType {
        self.analysis_type
    }

    pub const fn policy_schema(&self) -> SchemaVersionResolution {
        self.policy_schema
    }

    pub fn selector_schemas(&self) -> &[SelectorSchemaVersionResolution] {
        &self.selector_schemas
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

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn message(&self) -> &PolicyMessageSpec {
        &self.message
    }

    pub const fn severity(&self) -> &PolicySeveritySpec {
        &self.severity
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn help_uri(&self) -> Option<&str> {
        self.help_uri.as_deref()
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }
}

impl RetainedSize for PolicyRuleDescriptor {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(retained_extra(&self.selector_schemas))
            .saturating_add(retained_extra(&self.endpoint_dependencies))
            .saturating_add(retained_extra(&self.match_directory_manifests))
            .saturating_add(retained_extra(&self.precedence_manifest))
            .saturating_add(self.name.capacity())
            .saturating_add(retained_extra(&self.message))
            .saturating_add(retained_extra(&self.severity))
            .saturating_add(retained_extra(&self.description))
            .saturating_add(retained_extra(&self.help_uri))
            .saturating_add(retained_extra(&self.tags))
    }
}

impl Serialize for SelectorSchemaVersionResolution {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SelectorSchemaVersionResolution", 2)?;
        state.serialize_field("path", self.path.as_str())?;
        state.serialize_field("resolution", &SchemaResolutionWire(self.resolution))?;
        state.end()
    }
}

impl Serialize for PolicyRuleDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PolicyRuleDescriptor", 14)?;
        state.serialize_field("policy_id", &self.policy_id)?;
        state.serialize_field("policy_hash", &self.policy_hash)?;
        state.serialize_field("analysis_type", &self.analysis_type)?;
        state.serialize_field("policy_schema", &SchemaResolutionWire(self.policy_schema))?;
        state.serialize_field("selector_schemas", &self.selector_schemas)?;
        state.serialize_field(
            "endpoint_dependencies",
            &EndpointDependenciesWire(&self.endpoint_dependencies),
        )?;
        state.serialize_field(
            "match_directory_manifests",
            &MatchDirectoryManifestsWire(&self.match_directory_manifests),
        )?;
        state.serialize_field(
            "precedence_manifest",
            &PrecedenceManifestWire(&self.precedence_manifest),
        )?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("message", &PolicyMessageWire(&self.message))?;
        state.serialize_field("severity", &PolicySeverityWire(&self.severity))?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("help_uri", &self.help_uri)?;
        state.serialize_field("tags", &self.tags)?;
        state.end()
    }
}

struct SchemaResolutionWire(SchemaVersionResolution);

impl Serialize for SchemaResolutionWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SchemaVersionResolution", 2)?;
        state.serialize_field("version", &self.0.version)?;
        state.serialize_field(
            "origin",
            match self.0.origin {
                SchemaVersionOrigin::Explicit => "explicit",
                SchemaVersionOrigin::ImplicitCompatible => "implicit_compatible",
                SchemaVersionOrigin::ReferencedDocumentExplicit => "referenced_document_explicit",
            },
        )?;
        state.end()
    }
}

struct PolicyMessageWire<'a>(&'a PolicyMessageSpec);

impl Serialize for PolicyMessageWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            PolicyMessageSpec::Static { text } => {
                let mut state = serializer.serialize_struct("PolicyMessageSpec", 2)?;
                state.serialize_field("type", "static")?;
                state.serialize_field("text", text)?;
                state.end()
            }
            PolicyMessageSpec::Generated { .. } => {
                let mut state = serializer.serialize_struct("PolicyMessageSpec", 2)?;
                state.serialize_field("type", "generated")?;
                state.serialize_field("relation", "can_reach")?;
                state.end()
            }
        }
    }
}

struct PolicySeverityWire<'a>(&'a PolicySeveritySpec);

impl Serialize for PolicySeverityWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            PolicySeveritySpec::Fixed { level } => {
                let mut state = serializer.serialize_struct("PolicySeveritySpec", 2)?;
                state.serialize_field("type", "fixed")?;
                state.serialize_field("level", policy_level_label(*level))?;
                state.end()
            }
            PolicySeveritySpec::Unrated => {
                let mut state = serializer.serialize_struct("PolicySeveritySpec", 1)?;
                state.serialize_field("type", "unrated")?;
                state.end()
            }
            PolicySeveritySpec::Cvss { when_unscored } => {
                let mut state = serializer.serialize_struct("PolicySeveritySpec", 2)?;
                state.serialize_field("type", "cvss")?;
                state.serialize_field("when_unscored", when_unscored)?;
                state.end()
            }
        }
    }
}

const fn policy_level_label(level: PolicyLevel) -> &'static str {
    match level {
        PolicyLevel::Note => "note",
        PolicyLevel::Warning => "warning",
        PolicyLevel::Error => "error",
    }
}

struct EndpointDependenciesWire<'a>(&'a [ResolvedEndpointDependency]);

impl Serialize for EndpointDependenciesWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for dependency in self.0 {
            sequence.serialize_element(&EndpointDependencyWire(dependency))?;
        }
        sequence.end()
    }
}

struct EndpointDependencyWire<'a>(&'a ResolvedEndpointDependency);

impl Serialize for EndpointDependencyWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0;
        let mut state = serializer.serialize_struct("ResolvedEndpointDependency", 8)?;
        state.serialize_field("identity", &EndpointIdentityWire(value.identity()))?;
        state.serialize_field(
            "definition_schema",
            &EndpointDefinitionSchemaWire(value.definition_schema()),
        )?;
        state.serialize_field("selector_path", value.selector_path().as_str())?;
        match value.selector_schemas() {
            ResolvedEndpointSelectorSchemas::Query(resolution) => {
                state.serialize_field("selector_schema", &SchemaResolutionWire(*resolution))?;
            }
            ResolvedEndpointSelectorSchemas::Rows(bindings) => {
                state.serialize_field("selector_schemas", &EndpointRowSchemasWire(bindings))?;
            }
        }
        state.serialize_field("model", &EndpointModelWire(value.model()))?;
        state.serialize_field("semantic_hash", &DisplayWire(value.semantic_hash()))?;
        state.serialize_field(
            "analysis_projection_hash",
            &DisplayWire(value.analysis_projection_hash()),
        )?;
        state.serialize_field("origins", &EndpointOriginsWire(value.origins()))?;
        state.end()
    }
}

struct EndpointDefinitionSchemaWire<'a>(&'a EndpointDefinitionSchemaResolution);

impl Serialize for EndpointDefinitionSchemaWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            EndpointDefinitionSchemaResolution::PolicyDocument { resolution } => {
                let mut state =
                    serializer.serialize_struct("EndpointDefinitionSchemaResolution", 2)?;
                state.serialize_field("type", "policy_document")?;
                state.serialize_field("resolution", &SchemaResolutionWire(*resolution))?;
                state.end()
            }
            EndpointDefinitionSchemaResolution::CatalogDocument { schema_version } => {
                let mut state =
                    serializer.serialize_struct("EndpointDefinitionSchemaResolution", 2)?;
                state.serialize_field("type", "catalog_document")?;
                state.serialize_field("schema_version", schema_version)?;
                state.end()
            }
        }
    }
}

struct EndpointIdentityWire<'a>(&'a ResolvedEndpointIdentity);

impl Serialize for EndpointIdentityWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            ResolvedEndpointIdentity::Local {
                policy_id,
                entry_id,
            } => {
                let mut state = serializer.serialize_struct("ResolvedEndpointIdentity", 3)?;
                state.serialize_field("type", "local")?;
                state.serialize_field("policy_id", policy_id.as_str())?;
                state.serialize_field("entry_id", entry_id.as_str())?;
                state.end()
            }
            ResolvedEndpointIdentity::Catalog { catalog, entry_id } => {
                let mut state = serializer.serialize_struct("ResolvedEndpointIdentity", 3)?;
                state.serialize_field("type", "catalog")?;
                state.serialize_field("catalog", &CatalogIdentityWire(catalog))?;
                state.serialize_field("entry_id", entry_id.as_str())?;
                state.end()
            }
            ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => {
                let mut state = serializer.serialize_struct("ResolvedEndpointIdentity", 2)?;
                state.serialize_field("type", "match_endpoint")?;
                state.serialize_field("endpoint_id", endpoint_id.as_str())?;
                state.end()
            }
        }
    }
}

struct CatalogIdentityWire<'a>(&'a ResolvedCatalogIdentity);

impl Serialize for CatalogIdentityWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ResolvedCatalogIdentity", 3)?;
        state.serialize_field("name", self.0.name.as_str())?;
        state.serialize_field("version", &self.0.version)?;
        state.serialize_field("semantic_hash", &DisplayWire(self.0.semantic_hash))?;
        state.end()
    }
}

struct EndpointModelWire<'a>(&'a ResolvedEndpointModel);

impl Serialize for EndpointModelWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ResolvedEndpointModel", 6)?;
        state.serialize_field("role", endpoint_role_label(self.0.role))?;
        state.serialize_field("display_name", &self.0.display_name)?;
        state.serialize_field("categories", &IdentifierSlice(&self.0.categories))?;
        state.serialize_field("binding", &EndpointBindingWire(&self.0.binding))?;
        state.serialize_field("taint", &self.0.taint.as_ref().map(EndpointTaintWire))?;
        state.serialize_field("supersedes", &EndpointIdentitiesWire(&self.0.supersedes))?;
        state.end()
    }
}

const fn endpoint_role_label(role: EndpointRole) -> &'static str {
    match role {
        EndpointRole::Source => "source",
        EndpointRole::Sink => "sink",
    }
}

struct EndpointBindingWire<'a>(&'a PolicyEndpointBinding);

impl Serialize for EndpointBindingWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            PolicyEndpointBinding::MatchedValue => tagged_unit(serializer, "matched_value"),
            PolicyEndpointBinding::Receiver => tagged_unit(serializer, "receiver"),
            PolicyEndpointBinding::ReturnValue => tagged_unit(serializer, "return_value"),
            PolicyEndpointBinding::ResultIndex { index } => {
                let mut state = serializer.serialize_struct("PolicyEndpointBinding", 2)?;
                state.serialize_field("type", "result_index")?;
                state.serialize_field("index", index)?;
                state.end()
            }
            PolicyEndpointBinding::ArgumentIndex { index } => {
                let mut state = serializer.serialize_struct("PolicyEndpointBinding", 2)?;
                state.serialize_field("type", "argument_index")?;
                state.serialize_field("index", index)?;
                state.end()
            }
            PolicyEndpointBinding::ArgumentName { name } => {
                let mut state = serializer.serialize_struct("PolicyEndpointBinding", 2)?;
                state.serialize_field("type", "argument_name")?;
                state.serialize_field("name", name)?;
                state.end()
            }
        }
    }
}

fn tagged_unit<S>(serializer: S, kind: &'static str) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("TaggedValue", 1)?;
    state.serialize_field("type", kind)?;
    state.end()
}

struct EndpointTaintWire<'a>(&'a EndpointTaintSemantics);

impl Serialize for EndpointTaintWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            EndpointTaintSemantics::Source { labels, evidence } => {
                let mut state = serializer.serialize_struct("EndpointTaintSemantics", 3)?;
                state.serialize_field("type", "source")?;
                state.serialize_field("labels", &IdentifierSlice(labels))?;
                state
                    .serialize_field("evidence", &evidence.as_ref().map(TaintSourceEvidenceWire))?;
                state.end()
            }
            EndpointTaintSemantics::Sink {
                accepts,
                tags,
                impacts,
            } => {
                let mut state = serializer.serialize_struct("EndpointTaintSemantics", 4)?;
                state.serialize_field("type", "sink")?;
                state.serialize_field("accepts", &IdentifierSlice(accepts))?;
                state.serialize_field("tags", &IdentifierSlice(tags))?;
                state.serialize_field("impacts", &IdentifierSlice(impacts))?;
                state.end()
            }
        }
    }
}

struct TaintSourceEvidenceWire<'a>(&'a TaintSourceEvidence);

impl Serialize for TaintSourceEvidenceWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TaintSourceEvidence", 2)?;
        state.serialize_field(
            "trust_boundary",
            &self.0.trust_boundary.map(trust_boundary_label),
        )?;
        state.serialize_field("system_entry", &self.0.system_entry.map(system_entry_label))?;
        state.end()
    }
}

const fn trust_boundary_label(value: TaintTrustBoundary) -> &'static str {
    match value {
        TaintTrustBoundary::External => "external",
        TaintTrustBoundary::Internal => "internal",
        TaintTrustBoundary::SameTrustZone => "same_trust_zone",
    }
}

const fn system_entry_label(value: TaintSystemEntry) -> &'static str {
    match value {
        TaintSystemEntry::VulnerableSystemNetworkStack => "vulnerable_system_network_stack",
        TaintSystemEntry::DownloadedArtifact => "downloaded_artifact",
        TaintSystemEntry::LocalInput => "local_input",
        TaintSystemEntry::AdjacentNetwork => "adjacent_network",
        TaintSystemEntry::Physical => "physical",
    }
}

struct EndpointOriginsWire<'a>(&'a [EndpointOrigin]);

impl Serialize for EndpointOriginsWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for origin in self.0 {
            sequence.serialize_element(&EndpointOriginWire(origin))?;
        }
        sequence.end()
    }
}

struct EndpointOriginWire<'a>(&'a EndpointOrigin);

impl Serialize for EndpointOriginWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            EndpointOrigin::PolicyLocal { path } => {
                let mut state = serializer.serialize_struct("EndpointOrigin", 2)?;
                state.serialize_field("type", "policy_local")?;
                state.serialize_field("path", path.as_str())?;
                state.end()
            }
            EndpointOrigin::Catalog { catalog } => {
                let mut state = serializer.serialize_struct("EndpointOrigin", 2)?;
                state.serialize_field("type", "catalog")?;
                state.serialize_field("catalog", &CatalogIdentityWire(catalog))?;
                state.end()
            }
            EndpointOrigin::ExactMatch { path, source } => {
                let mut state = serializer.serialize_struct("EndpointOrigin", 3)?;
                state.serialize_field("type", "exact_match")?;
                state.serialize_field("path", path.as_str())?;
                state.serialize_field("source", source)?;
                state.end()
            }
            EndpointOrigin::MatchDirectory { path, source } => {
                let mut state = serializer.serialize_struct("EndpointOrigin", 3)?;
                state.serialize_field("type", "match_directory")?;
                state.serialize_field("path", path.as_str())?;
                state.serialize_field("source", source)?;
                state.end()
            }
        }
    }
}

struct MatchDirectoryManifestsWire<'a>(&'a [ResolvedMatchDirectoryManifest]);

impl Serialize for MatchDirectoryManifestsWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for manifest in self.0 {
            sequence.serialize_element(&MatchDirectoryManifestWire(manifest))?;
        }
        sequence.end()
    }
}

struct MatchDirectoryManifestWire<'a>(&'a ResolvedMatchDirectoryManifest);

impl Serialize for MatchDirectoryManifestWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ResolvedMatchDirectoryManifest", 7)?;
        state.serialize_field("path", self.0.path().as_str())?;
        state.serialize_field("directory", self.0.directory().as_str())?;
        state.serialize_field("scope", directory_scope_label(self.0.scope()))?;
        state.serialize_field("role", &self.0.role().map(endpoint_role_label))?;
        state.serialize_field("categories", &CategoryPredicateWire(self.0.categories()))?;
        state.serialize_field("selected", &ManifestEntriesWire(self.0.selected()))?;
        state.serialize_field("semantic_hash", &DisplayWire(self.0.semantic_hash()))?;
        state.end()
    }
}

const fn directory_scope_label(scope: DirectoryScope) -> &'static str {
    match scope {
        DirectoryScope::Direct => "direct",
        DirectoryScope::Recursive => "recursive",
    }
}

struct CategoryPredicateWire<'a>(&'a CategoryPredicate);

impl Serialize for CategoryPredicateWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            CategoryPredicate::Any { categories } => {
                let mut state = serializer.serialize_struct("CategoryPredicate", 2)?;
                state.serialize_field("type", "any")?;
                state.serialize_field("categories", &IdentifierSlice(categories))?;
                state.end()
            }
            CategoryPredicate::All { categories } => {
                let mut state = serializer.serialize_struct("CategoryPredicate", 2)?;
                state.serialize_field("type", "all")?;
                state.serialize_field("categories", &IdentifierSlice(categories))?;
                state.end()
            }
        }
    }
}

struct ManifestEntriesWire<'a>(&'a [ResolvedEndpointManifestEntry]);

impl Serialize for ManifestEntriesWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            sequence.serialize_element(&ManifestEntryWire(entry))?;
        }
        sequence.end()
    }
}

struct ManifestEntryWire<'a>(&'a ResolvedEndpointManifestEntry);

impl Serialize for ManifestEntryWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ResolvedEndpointManifestEntry", 5)?;
        state.serialize_field("identity", &EndpointIdentityWire(&self.0.identity))?;
        state.serialize_field(
            "definition_schema",
            &EndpointDefinitionSchemaWire(&self.0.definition_schema),
        )?;
        match &self.0.selector_schemas {
            ResolvedEndpointSelectorSchemas::Query(resolution) => {
                state.serialize_field("selector_schema", &SchemaResolutionWire(*resolution))?;
            }
            ResolvedEndpointSelectorSchemas::Rows(bindings) => {
                state.serialize_field("selector_schemas", &EndpointRowSchemasWire(bindings))?;
            }
        }
        state.serialize_field("semantic_hash", &DisplayWire(self.0.semantic_hash))?;
        state.serialize_field(
            "analysis_projection_hash",
            &DisplayWire(self.0.analysis_projection_hash),
        )?;
        state.end()
    }
}

struct EndpointRowSchemasWire<'a>(&'a [super::resolved::ResolvedEndpointRowBindingSchema]);

impl Serialize for EndpointRowSchemasWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for binding in self.0 {
            sequence.serialize_element(&SelectorSchemaVersionResolution::new(
                binding.path.clone(),
                binding.resolution,
            ))?;
        }
        sequence.end()
    }
}

struct PrecedenceManifestWire<'a>(&'a PolicyPrecedenceManifest);

impl Serialize for PrecedenceManifestWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PolicyPrecedenceManifest", 1)?;
        state.serialize_field("edges", &PrecedenceEdgesWire(&self.0.edges))?;
        state.end()
    }
}

struct PrecedenceEdgesWire<'a>(&'a [ResolvedPrecedenceEdge]);

impl Serialize for PrecedenceEdgesWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for edge in self.0 {
            sequence.serialize_element(&PrecedenceEdgeWire(edge))?;
        }
        sequence.end()
    }
}

struct PrecedenceEdgeWire<'a>(&'a ResolvedPrecedenceEdge);

impl Serialize for PrecedenceEdgeWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            ResolvedPrecedenceEdge::Endpoint {
                dominant,
                dominated,
            } => precedence_endpoint(serializer, "endpoint", dominant, dominated),
            ResolvedPrecedenceEdge::FindingCombination {
                dominant,
                dominated,
            } => precedence_ids(
                serializer,
                "finding_combination",
                dominant.as_str(),
                dominated.as_str(),
            ),
            ResolvedPrecedenceEdge::TypestateEvent {
                dominant,
                dominated,
            } => precedence_ids(
                serializer,
                "typestate_event",
                dominant.as_str(),
                dominated.as_str(),
            ),
            ResolvedPrecedenceEdge::TypestateExpectation {
                dominant,
                dominated,
            } => precedence_ids(
                serializer,
                "typestate_expectation",
                dominant.as_str(),
                dominated.as_str(),
            ),
        }
    }
}

fn precedence_endpoint<S>(
    serializer: S,
    kind: &'static str,
    dominant: &ResolvedEndpointIdentity,
    dominated: &ResolvedEndpointIdentity,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("ResolvedPrecedenceEdge", 3)?;
    state.serialize_field("type", kind)?;
    state.serialize_field("dominant", &EndpointIdentityWire(dominant))?;
    state.serialize_field("dominated", &EndpointIdentityWire(dominated))?;
    state.end()
}

fn precedence_ids<S>(
    serializer: S,
    kind: &'static str,
    dominant: &str,
    dominated: &str,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("ResolvedPrecedenceEdge", 3)?;
    state.serialize_field("type", kind)?;
    state.serialize_field("dominant", dominant)?;
    state.serialize_field("dominated", dominated)?;
    state.end()
}

struct EndpointIdentitiesWire<'a>(&'a [ResolvedEndpointIdentity]);

impl Serialize for EndpointIdentitiesWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for identity in self.0 {
            sequence.serialize_element(&EndpointIdentityWire(identity))?;
        }
        sequence.end()
    }
}

struct IdentifierSlice<'a, T>(&'a [T]);

impl<T: AsRef<str>> Serialize for IdentifierSlice<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            sequence.serialize_element(value.as_ref())?;
        }
        sequence.end()
    }
}

struct DisplayWire<T>(T);

impl<T: fmt::Display> Serialize for DisplayWire<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.0)
    }
}

/// Stable byte range in one policy source identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PolicySourceRange {
    start: u64,
    end: u64,
}

impl PolicySourceRange {
    pub fn new(start: u64, end: u64) -> Result<Self, PolicyReportValueError> {
        if start > end {
            return Err(PolicyReportValueError::ReversedSourceRange { start, end });
        }
        Ok(Self { start, end })
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn end(&self) -> u64 {
        self.end
    }
}

impl TryFrom<Range<usize>> for PolicySourceRange {
    type Error = PolicyReportValueError;

    fn try_from(range: Range<usize>) -> Result<Self, Self::Error> {
        Self::new(
            u64::try_from(range.start).map_err(|_| PolicyReportValueError::SourceRangeOverflow)?,
            u64::try_from(range.end).map_err(|_| PolicyReportValueError::SourceRangeOverflow)?,
        )
    }
}

/// One load/coordinator diagnostic in the canonical report document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyReportDiagnostic {
    code: PolicyReportDiagnosticCode,
    severity: PolicyDiagnosticSeverity,
    message: String,
    source: Option<PolicySourceIdentity>,
    byte_range: Option<PolicySourceRange>,
    related: Vec<PolicySourceRelatedDiagnostic>,
}

impl PolicyReportDiagnostic {
    pub fn try_new(
        code: PolicyReportDiagnosticCode,
        severity: PolicyDiagnosticSeverity,
        message: impl Into<String>,
        source: Option<PolicySourceIdentity>,
        byte_range: Option<PolicySourceRange>,
        mut related: Vec<PolicySourceRelatedDiagnostic>,
    ) -> Result<Self, PolicyReportValueError> {
        let message = validate_and_tighten_text(message.into(), "report diagnostic message")?;
        if source.is_none() && byte_range.is_some() {
            return Err(PolicyReportValueError::RangeWithoutSource);
        }
        if related.len() > MAX_REPORT_RELATED_DIAGNOSTICS {
            return Err(PolicyReportValueError::TooManyRelatedDiagnostics {
                max: MAX_REPORT_RELATED_DIAGNOSTICS,
            });
        }
        for item in &mut related {
            item.message = validate_and_tighten_text(
                std::mem::take(&mut item.message),
                "related diagnostic message",
            )?;
            if item.range.start > item.range.end {
                return Err(PolicyReportValueError::ReversedSourceRange {
                    start: u64::try_from(item.range.start).unwrap_or(u64::MAX),
                    end: u64::try_from(item.range.end).unwrap_or(u64::MAX),
                });
            }
        }
        related.sort_by(|left, right| {
            (
                left.source.as_str(),
                left.range.start,
                left.range.end,
                left.message.as_str(),
            )
                .cmp(&(
                    right.source.as_str(),
                    right.range.start,
                    right.range.end,
                    right.message.as_str(),
                ))
        });
        related.dedup();
        tighten_vec(&mut related);
        Ok(Self {
            code,
            severity,
            message,
            source,
            byte_range,
            related,
        })
    }

    pub const fn code(&self) -> PolicyReportDiagnosticCode {
        self.code
    }

    pub const fn severity(&self) -> PolicyDiagnosticSeverity {
        self.severity
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub const fn source(&self) -> Option<&PolicySourceIdentity> {
        self.source.as_ref()
    }

    pub const fn byte_range(&self) -> Option<PolicySourceRange> {
        self.byte_range
    }

    pub fn related(&self) -> &[PolicySourceRelatedDiagnostic] {
        &self.related
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyReportDiagnosticCode {
    WorkspaceSnapshotDeadlineExceeded,
    DiffBaseUnreliable,
    SuppressionLoadFailed,
    SuppressionAuditRetentionExceeded,
    ScopeLoadFailed,
    ScopeAuditRetentionExceeded,
    BaselineLoadFailed,
    BaselineAuditRetentionExceeded,
    PacksLoadFailed,
    PackActivationFailed,
    /// A reviewed model under `.bifrost/semantic-models/` could not be
    /// discovered, compiled, registered, or activated (#2493).
    WorkspaceModelLoadFailed,
    /// A reviewed workspace model is registered but held back by its own
    /// review gate, so it contributes nothing to this run (#2493).
    WorkspaceModelInert,
    PolicyLoadFailed,
    PolicyParseFailed,
    PolicyValidationFailed,
    EndpointParseFailed,
    EndpointValidationFailed,
    NotExecutableEndpoint,
    DuplicatePolicyId,
    DuplicateEndpointId,
    PolicyCountLimit,
    EndpointCountLimit,
    MatchDirectoryLimit,
    MatchDirectoryChangedDuringLoad,
    MatchDirectoryManifestMismatch,
    NonEndpointInMatchDirectory,
    EndpointMissingOrMismatchedTaintSemantics,
    AmbiguousCombinationPrecedence,
    UnsupportedPolicySchemaVersion,
    UnsupportedRqlSchemaVersion,
    ConflictingRqlSchemaVersion,
    ExplicitPolicySchemaVersionRequired,
    ExplicitRqlSchemaVersionRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyReportValueError {
    EmptyText {
        field: &'static str,
    },
    TextTooLong {
        field: &'static str,
        max_bytes: usize,
    },
    UnsafeText {
        field: &'static str,
    },
    ReversedSourceRange {
        start: u64,
        end: u64,
    },
    SourceRangeOverflow,
    RangeWithoutSource,
    TooManyRelatedDiagnostics {
        max: usize,
    },
}

impl fmt::Display for PolicyReportValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyText { field } => write!(formatter, "{field} must not be empty"),
            Self::TextTooLong { field, max_bytes } => {
                write!(formatter, "{field} must be at most {max_bytes} bytes")
            }
            Self::UnsafeText { field } => {
                write!(
                    formatter,
                    "{field} must not contain control or bidi characters"
                )
            }
            Self::ReversedSourceRange { start, end } => {
                write!(formatter, "source range start {start} exceeds end {end}")
            }
            Self::SourceRangeOverflow => formatter.write_str("source range does not fit in u64"),
            Self::RangeWithoutSource => {
                formatter.write_str("a report diagnostic byte range requires a source identity")
            }
            Self::TooManyRelatedDiagnostics { max } => {
                write!(
                    formatter,
                    "a report diagnostic accepts at most {max} related diagnostics"
                )
            }
        }
    }
}

impl std::error::Error for PolicyReportValueError {}

impl RetainedSize for PolicyReportDiagnostic {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.message.capacity())
            .saturating_add(retained_extra(&self.source))
            .saturating_add(retained_extra(&self.related))
    }
}

impl RetainedSize for PolicySourceRelatedDiagnostic {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.source))
            .saturating_add(self.message.capacity())
    }
}

impl Serialize for PolicySourceIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl Serialize for PolicySourceRelatedDiagnostic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PolicySourceRelatedDiagnostic", 3)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("byte_range", &SerializableRange(&self.range))?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

struct SerializableRange<'a>(&'a Range<usize>);

impl Serialize for SerializableRange<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PolicySourceRange", 2)?;
        state.serialize_field("start", &self.0.start)?;
        state.serialize_field("end", &self.0.end)?;
        state.end()
    }
}

fn validate_and_tighten_text(
    value: String,
    field: &'static str,
) -> Result<String, PolicyReportValueError> {
    if value.is_empty() {
        return Err(PolicyReportValueError::EmptyText { field });
    }
    if value.len() > MAX_REPORT_TEXT_BYTES {
        return Err(PolicyReportValueError::TextTooLong {
            field,
            max_bytes: MAX_REPORT_TEXT_BYTES,
        });
    }
    if value.chars().any(is_unsafe_text_character) {
        return Err(PolicyReportValueError::UnsafeText { field });
    }
    Ok(tight_string(value))
}

fn is_unsafe_text_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn tight_string(value: String) -> String {
    value.into_boxed_str().into_string()
}

fn tighten_vec<T>(values: &mut Vec<T>) {
    *values = std::mem::take(values).into_boxed_slice().into_vec();
}

// Retained-size implementations for the exact loaded-policy structures that
// a report descriptor owns. These deliberately count the cloned typed values,
// not a serialized approximation.

impl RetainedSize for PolicyMessageSpec {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Static { text } => text.capacity(),
            Self::Generated { .. } => 0,
        })
    }
}

impl RetainedSize for PolicySeveritySpec {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl RetainedSize for ResolvedCatalogIdentity {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.name))
    }
}

impl RetainedSize for ResolvedEndpointIdentity {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Local {
                policy_id,
                entry_id,
            } => retained_extra(policy_id).saturating_add(retained_extra(entry_id)),
            Self::Catalog { catalog, entry_id } => {
                retained_extra(catalog).saturating_add(retained_extra(entry_id))
            }
            Self::MatchEndpoint { endpoint_id } => retained_extra(endpoint_id),
        })
    }
}

impl RetainedSize for PolicyEndpointBinding {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::ArgumentName { name } => name.capacity(),
            _ => 0,
        })
    }
}

impl RetainedSize for EndpointTaintSemantics {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Source { labels, .. } => retained_extra(labels),
            Self::Sink {
                accepts,
                tags,
                impacts,
            } => retained_extra(accepts)
                .saturating_add(retained_extra(tags))
                .saturating_add(retained_extra(impacts)),
        })
    }
}

impl RetainedSize for ResolvedEndpointModel {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.display_name.capacity())
            .saturating_add(retained_extra(&self.categories))
            .saturating_add(retained_extra(&self.binding))
            .saturating_add(retained_extra(&self.taint))
            .saturating_add(retained_extra(&self.supersedes))
    }
}

impl RetainedSize for EndpointOrigin {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::PolicyLocal { path } => retained_extra(path),
            Self::Catalog { catalog } => retained_extra(catalog),
            Self::ExactMatch { path, source } | Self::MatchDirectory { path, source } => {
                retained_extra(path).saturating_add(retained_extra(source))
            }
        })
    }
}

impl RetainedSize for ResolvedEndpointDependency {
    fn retained_size(&self) -> usize {
        let origins_extra = retained_vec_size_from_parts(self.origins(), self.origins_capacity())
            .saturating_sub(size_of::<Vec<EndpointOrigin>>());
        size_of::<Self>()
            .saturating_add(retained_extra(self.identity()))
            .saturating_add(retained_extra(self.selector_path()))
            .saturating_add(retained_extra(self.model()))
            .saturating_add(origins_extra)
    }
}

impl RetainedSize for ResolvedEndpointManifestEntry {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.identity))
    }
}

impl RetainedSize for CategoryPredicate {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Any { categories } | Self::All { categories } => retained_extra(categories),
        })
    }
}

impl RetainedSize for ResolvedMatchDirectoryManifest {
    fn retained_size(&self) -> usize {
        let selected_extra =
            retained_vec_size_from_parts(self.selected(), self.selected_capacity())
                .saturating_sub(size_of::<Vec<ResolvedEndpointManifestEntry>>());
        size_of::<Self>()
            .saturating_add(retained_extra(self.path()))
            .saturating_add(retained_extra(self.directory()))
            .saturating_add(retained_extra(self.categories()))
            .saturating_add(selected_extra)
    }
}

impl RetainedSize for ResolvedPrecedenceEdge {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Endpoint {
                dominant,
                dominated,
            } => retained_extra(dominant).saturating_add(retained_extra(dominated)),
            Self::FindingCombination {
                dominant,
                dominated,
            } => retained_extra(dominant).saturating_add(retained_extra(dominated)),
            Self::TypestateEvent {
                dominant,
                dominated,
            } => retained_extra(dominant).saturating_add(retained_extra(dominated)),
            Self::TypestateExpectation {
                dominant,
                dominated,
            } => retained_extra(dominant).saturating_add(retained_extra(dominated)),
        })
    }
}

impl RetainedSize for PolicyPrecedenceManifest {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.edges))
    }
}

macro_rules! fixed_report_type_retained_size {
    ($($type:ty),+ $(,)?) => {
        $(
            impl RetainedSize for $type {
                fn retained_size(&self) -> usize {
                    size_of::<Self>()
                }
            }
        )+
    };
}

fixed_report_type_retained_size!(
    SchemaVersionResolution,
    EndpointDefinitionSchemaResolution,
    EndpointSemanticHash,
    EndpointAnalysisProjectionHash,
    MatchSetManifestHash,
    TaintCatalogHash,
    EndpointRole,
    PolicyReportDiagnosticCode,
    PolicySourceRange,
    PolicyStageTiming,
    PolicyDependencyPackActivationMode,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyExecutionStage {
    PolicySelection,
    SuppressionPreflight,
    WorkspaceSnapshot,
    PolicyRegistration,
    PolicyPreparation,
    PolicyEvaluation,
    ReportConstruction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyExecutionTermination {
    DeadlineExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PolicyStageTiming {
    stage: PolicyExecutionStage,
    elapsed_ms: u64,
}

impl PolicyStageTiming {
    pub const fn new(stage: PolicyExecutionStage, elapsed_ms: u64) -> Self {
        Self { stage, elapsed_ms }
    }

    pub fn from_duration(stage: PolicyExecutionStage, elapsed: std::time::Duration) -> Self {
        Self::new(
            stage,
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        )
    }

    pub const fn stage(&self) -> PolicyExecutionStage {
        self.stage
    }

    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PolicyExecutionMetadata {
    total_elapsed_ms: u64,
    stage_timings: Vec<PolicyStageTiming>,
    termination: Option<PolicyExecutionTermination>,
    terminal_stage: Option<PolicyExecutionStage>,
    active_policy_id: Option<PolicyId>,
    completed_policy_ids: Vec<PolicyId>,
    pending_policy_ids: Vec<PolicyId>,
}

impl PolicyExecutionMetadata {
    fn maximum_retained_size(policy_count: usize) -> usize {
        size_of::<Self>()
            .saturating_add(
                MAX_POLICY_EXECUTION_STAGES.saturating_mul(size_of::<PolicyStageTiming>()),
            )
            .saturating_add(
                policy_count
                    .min(MAX_POLICY_EXECUTION_PROGRESS_IDS)
                    .saturating_mul(size_of::<PolicyId>().saturating_add(200)),
            )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        total_elapsed_ms: u64,
        mut stage_timings: Vec<PolicyStageTiming>,
        termination: Option<PolicyExecutionTermination>,
        terminal_stage: Option<PolicyExecutionStage>,
        active_policy_id: Option<PolicyId>,
        mut completed_policy_ids: Vec<PolicyId>,
        mut pending_policy_ids: Vec<PolicyId>,
    ) -> Result<Self, PolicyExecutionMetadataError> {
        if stage_timings.len() > MAX_POLICY_EXECUTION_STAGES {
            return Err(PolicyExecutionMetadataError::TooManyStageTimings {
                max: MAX_POLICY_EXECUTION_STAGES,
            });
        }
        stage_timings.sort_by_key(PolicyStageTiming::stage);
        if stage_timings
            .windows(2)
            .any(|pair| pair[0].stage == pair[1].stage)
        {
            return Err(PolicyExecutionMetadataError::DuplicateStageTiming);
        }
        if termination.is_some() != terminal_stage.is_some() {
            return Err(PolicyExecutionMetadataError::InconsistentTermination);
        }
        if termination.is_none() && (active_policy_id.is_some() || !pending_policy_ids.is_empty()) {
            return Err(PolicyExecutionMetadataError::IncompleteProgressWithoutTermination);
        }

        completed_policy_ids.sort();
        pending_policy_ids.sort();
        if completed_policy_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
            || pending_policy_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(PolicyExecutionMetadataError::DuplicatePolicyProgress);
        }
        let progress_count = completed_policy_ids
            .len()
            .saturating_add(pending_policy_ids.len())
            .saturating_add(usize::from(active_policy_id.is_some()));
        if progress_count > MAX_POLICY_EXECUTION_PROGRESS_IDS {
            return Err(PolicyExecutionMetadataError::TooManyPolicyProgressIds {
                max: MAX_POLICY_EXECUTION_PROGRESS_IDS,
            });
        }
        if completed_policy_ids
            .iter()
            .any(|policy_id| pending_policy_ids.binary_search(policy_id).is_ok())
            || active_policy_id.as_ref().is_some_and(|policy_id| {
                completed_policy_ids.binary_search(policy_id).is_ok()
                    || pending_policy_ids.binary_search(policy_id).is_ok()
            })
        {
            return Err(PolicyExecutionMetadataError::OverlappingPolicyProgress);
        }

        tighten_vec(&mut stage_timings);
        tighten_vec(&mut completed_policy_ids);
        tighten_vec(&mut pending_policy_ids);
        Ok(Self {
            total_elapsed_ms,
            stage_timings,
            termination,
            terminal_stage,
            active_policy_id,
            completed_policy_ids,
            pending_policy_ids,
        })
    }

    pub const fn total_elapsed_ms(&self) -> u64 {
        self.total_elapsed_ms
    }

    pub fn stage_timings(&self) -> &[PolicyStageTiming] {
        &self.stage_timings
    }

    pub const fn termination(&self) -> Option<PolicyExecutionTermination> {
        self.termination
    }

    pub const fn terminal_stage(&self) -> Option<PolicyExecutionStage> {
        self.terminal_stage
    }

    pub const fn active_policy_id(&self) -> Option<&PolicyId> {
        self.active_policy_id.as_ref()
    }

    pub fn completed_policy_ids(&self) -> &[PolicyId] {
        &self.completed_policy_ids
    }

    pub fn pending_policy_ids(&self) -> &[PolicyId] {
        &self.pending_policy_ids
    }
}

impl RetainedSize for PolicyExecutionMetadata {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.active_policy_id))
            .saturating_add(retained_extra(&self.stage_timings))
            .saturating_add(retained_extra(&self.completed_policy_ids))
            .saturating_add(retained_extra(&self.pending_policy_ids))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyExecutionMetadataError {
    TooManyStageTimings { max: usize },
    DuplicateStageTiming,
    InconsistentTermination,
    IncompleteProgressWithoutTermination,
    DuplicatePolicyProgress,
    TooManyPolicyProgressIds { max: usize },
    OverlappingPolicyProgress,
}

impl fmt::Display for PolicyExecutionMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyStageTimings { max } => {
                write!(
                    formatter,
                    "policy execution accepts at most {max} stage timings"
                )
            }
            Self::DuplicateStageTiming => {
                formatter.write_str("policy execution stage timings must be unique")
            }
            Self::InconsistentTermination => formatter.write_str(
                "policy execution termination and terminal stage must be present together",
            ),
            Self::IncompleteProgressWithoutTermination => formatter
                .write_str("active or pending policy progress requires an execution termination"),
            Self::DuplicatePolicyProgress => {
                formatter.write_str("policy execution progress IDs must be unique")
            }
            Self::TooManyPolicyProgressIds { max } => write!(
                formatter,
                "policy execution accepts at most {max} progress policy IDs"
            ),
            Self::OverlappingPolicyProgress => formatter.write_str(
                "policy execution completed, active, and pending policy IDs must not overlap",
            ),
        }
    }
}

impl std::error::Error for PolicyExecutionMetadataError {}

/// Upper bound on retained fixed-finding entries in one diff review.
///
/// The counts always stay exact; only the entry list truncates, mirroring the
/// report's other bounded collections.
pub(crate) const MAX_DIFF_FIXED_FINDINGS: usize = 256;

/// One base-revision finding identity that no head finding matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDiffFixedFinding {
    policy_id: PolicyId,
    finding_id: PolicyFindingId,
}

impl PolicyDiffFixedFinding {
    pub(crate) const fn new(policy_id: PolicyId, finding_id: PolicyFindingId) -> Self {
        Self {
            policy_id,
            finding_id,
        }
    }

    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub const fn finding_id(&self) -> PolicyFindingId {
        self.finding_id
    }
}

impl RetainedSize for PolicyDiffFixedFinding {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.policy_id))
    }
}

/// Top-level audit of one diff-aware evaluation against a base revision.
///
/// When `degraded` is true the base evaluation was unreliable: no per-finding
/// diff decision exists, every head finding gates as if no diff base had been
/// given, and a `diff-base-unreliable` report diagnostic states why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDiffReview {
    base_revision: String,
    base_commit: String,
    degraded: bool,
    new_count: u64,
    persisting_count: u64,
    fixed_count: u64,
    fixed: Vec<PolicyDiffFixedFinding>,
    fixed_truncated: bool,
}

impl PolicyDiffReview {
    pub(crate) fn new(
        base_revision: String,
        base_commit: String,
        degraded: bool,
        new_count: u64,
        persisting_count: u64,
        mut fixed: Vec<PolicyDiffFixedFinding>,
        fixed_count: u64,
    ) -> Self {
        assert!(
            fixed.len() <= MAX_DIFF_FIXED_FINDINGS,
            "diff review retains at most {MAX_DIFF_FIXED_FINDINGS} fixed findings, got {}",
            fixed.len()
        );
        assert!(
            fixed_count >= u64::try_from(fixed.len()).expect("bounded list length fits u64"),
            "diff review fixed_count {fixed_count} is below the retained list length {}",
            fixed.len()
        );
        assert!(
            !degraded || (new_count == 0 && persisting_count == 0 && fixed.is_empty()),
            "a degraded diff review carries no classification: new {new_count}, persisting {persisting_count}, fixed {fixed:?}"
        );
        // Sorted by the caller, not here: the caller truncates to
        // `MAX_DIFF_FIXED_FINDINGS`, so ordering the list after truncation
        // would leave the retained subset itself dependent on the order the
        // caller enumerated its identities in.
        debug_assert!(
            fixed.is_sorted_by(|left, right| (left.policy_id.as_str(), left.finding_id)
                <= (right.policy_id.as_str(), right.finding_id)),
            "diff review fixed findings arrive sorted by (policy_id, finding_id), got {fixed:?}"
        );
        tighten_vec(&mut fixed);
        let fixed_truncated =
            fixed_count > u64::try_from(fixed.len()).expect("bounded list length fits u64");
        Self {
            base_revision,
            base_commit,
            degraded,
            new_count,
            persisting_count,
            fixed_count,
            fixed,
            fixed_truncated,
        }
    }

    pub fn base_revision(&self) -> &str {
        &self.base_revision
    }

    pub fn base_commit(&self) -> &str {
        &self.base_commit
    }

    pub const fn degraded(&self) -> bool {
        self.degraded
    }

    pub const fn new_count(&self) -> u64 {
        self.new_count
    }

    pub const fn persisting_count(&self) -> u64 {
        self.persisting_count
    }

    pub const fn fixed_count(&self) -> u64 {
        self.fixed_count
    }

    pub fn fixed(&self) -> &[PolicyDiffFixedFinding] {
        &self.fixed
    }

    pub const fn fixed_truncated(&self) -> bool {
        self.fixed_truncated
    }
}

impl RetainedSize for PolicyIncrementalRun {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(self.policy_id.as_str().len())
    }
}

impl RetainedSize for PolicyIncrementalReview {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_vec_size_from_parts(
            self.policies(),
            self.policies().len(),
        ))
    }
}

impl RetainedSize for PolicyDiffReview {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.base_revision.capacity())
            .saturating_add(self.base_commit.capacity())
            .saturating_add(retained_extra(&self.fixed))
    }
}

/// Upper bound on retained pack-activation decisions in one review.
///
/// The truncation flag stays exact; only the entry list truncates, mirroring
/// the report's other bounded collections.
pub(crate) const MAX_PACK_ACTIVATION_DECISIONS: usize = 128;
/// Upper bound on per-pack procedure-summary evidence retained in one
/// activation decision. The count remains exact when this list truncates.
pub(crate) const MAX_PACK_PROCEDURE_SUMMARY_EVIDENCE: usize = 128;

/// How one pack or discovered dependency fared at activation (#1868, #1884).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPackDecisionStatus {
    /// The pack activated for this run.
    Selected,
    /// A pack names the dependency but pins another exact version; the
    /// reason names the installed and required versions.
    VersionMismatch,
    /// No pack exists for the dependency.
    Missing,
    /// A pack was found but its compatibility or selector rejected the
    /// workspace evidence.
    Incompatible,
    /// A pack was rejected for another stated reason, for example a disable
    /// control or a required review.
    Rejected,
}

/// How dependency semantic-pack activation was selected for one policy run.
///
/// This is separate from individual pack decisions: a host can own
/// activation without a workspace document, and a configured document can be
/// deliberately empty while still needing an auditable report state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDependencyPackActivationMode {
    /// The host used compatible discovered-pack defaults.
    Default,
    /// The workspace supplied explicit dependency-pack configuration.
    Configured,
    /// Dependency-pack activation was configured but no ecosystems were
    /// selected for this workspace.
    Disabled,
}

/// One activated procedure summary's reachability evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PolicyPackProcedureSummaryEvidence {
    summary_id: String,
    symbol: String,
    match_count: u64,
}

impl PolicyPackProcedureSummaryEvidence {
    pub(crate) fn new(summary_id: String, symbol: String, match_count: u64) -> Self {
        Self {
            summary_id,
            symbol,
            match_count,
        }
    }

    pub fn summary_id(&self) -> &str {
        &self.summary_id
    }

    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    pub const fn match_count(&self) -> u64 {
        self.match_count
    }
}

impl RetainedSize for PolicyPackProcedureSummaryEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.summary_id.capacity())
            .saturating_add(self.symbol.capacity())
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// One pack-activation decision retained for attribution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PolicyPackDecision {
    pack: String,
    status: PolicyPackDecisionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    summary_matches: Vec<PolicyPackProcedureSummaryEvidence>,
    #[serde(skip_serializing_if = "is_false")]
    summary_matches_truncated: bool,
}

impl PolicyPackDecision {
    pub(crate) const fn new(
        pack: String,
        status: PolicyPackDecisionStatus,
        reason: Option<String>,
    ) -> Self {
        Self {
            pack,
            status,
            reason,
            summary_matches: Vec::new(),
            summary_matches_truncated: false,
        }
    }

    pub(crate) fn with_summary_matches(
        mut self,
        mut summary_matches: Vec<PolicyPackProcedureSummaryEvidence>,
    ) -> Self {
        summary_matches.sort();
        summary_matches.dedup();
        self.summary_matches_truncated =
            summary_matches.len() > MAX_PACK_PROCEDURE_SUMMARY_EVIDENCE;
        summary_matches.truncate(MAX_PACK_PROCEDURE_SUMMARY_EVIDENCE);
        tighten_vec(&mut summary_matches);
        self.summary_matches = summary_matches;
        self
    }

    pub fn pack(&self) -> &str {
        &self.pack
    }

    pub const fn status(&self) -> PolicyPackDecisionStatus {
        self.status
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub fn summary_matches(&self) -> &[PolicyPackProcedureSummaryEvidence] {
        &self.summary_matches
    }

    pub const fn summary_matches_truncated(&self) -> bool {
        self.summary_matches_truncated
    }
}

impl RetainedSize for PolicyPackDecision {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.pack.capacity())
            .saturating_add(self.reason.as_ref().map_or(0, String::capacity))
            .saturating_add(retained_extra(&self.summary_matches))
    }
}

/// Top-level audit of semantic-pack activation for one evaluation (#1868).
/// Records whether dependency packs used the absent-document default, an
/// explicit ecosystem configuration, or explicit disablement, and includes
/// reviewed models under `.bifrost/semantic-models/` when that route ran.
/// Intrinsic shipped models alone do not add this optional review (#2493).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyPackActivationReview {
    document_path: String,
    dependency_mode: PolicyDependencyPackActivationMode,
    ecosystems: Vec<String>,
    complete: bool,
    decisions: Vec<PolicyPackDecision>,
    decisions_truncated: bool,
}

impl PolicyPackActivationReview {
    pub(crate) fn new_with_mode(
        document_path: String,
        dependency_mode: PolicyDependencyPackActivationMode,
        ecosystems: Vec<String>,
        complete: bool,
        mut decisions: Vec<PolicyPackDecision>,
    ) -> Self {
        decisions.sort();
        decisions.dedup();
        let decisions_truncated = decisions.len() > MAX_PACK_ACTIVATION_DECISIONS;
        decisions.truncate(MAX_PACK_ACTIVATION_DECISIONS);
        tighten_vec(&mut decisions);
        Self {
            document_path,
            dependency_mode,
            ecosystems,
            complete,
            decisions,
            decisions_truncated,
        }
    }

    pub fn document_path(&self) -> &str {
        &self.document_path
    }

    pub const fn dependency_mode(&self) -> PolicyDependencyPackActivationMode {
        self.dependency_mode
    }

    /// The activated ecosystem labels, in stable order.
    pub fn ecosystems(&self) -> &[String] {
        &self.ecosystems
    }

    /// Whether discovery, preparation, and publication all completed.
    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub fn decisions(&self) -> &[PolicyPackDecision] {
        &self.decisions
    }

    pub const fn decisions_truncated(&self) -> bool {
        self.decisions_truncated
    }
}

impl RetainedSize for PolicyPackActivationReview {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.document_path.capacity())
            .saturating_add(
                self.ecosystems
                    .iter()
                    .map(|ecosystem| size_of::<String>().saturating_add(ecosystem.capacity()))
                    .fold(0_usize, usize::saturating_add),
            )
            .saturating_add(retained_extra(&self.decisions))
    }
}

/// The optional top-level reviews a report attaches when the matching input
/// (a diff base, workspace pack configuration, or a baseline document) is
/// present. Each review stays additive: a report without any of them keeps
/// its exact schema-version-5 shape (#1880, #1868, #1881, #2493).
///
/// Folding the three into one collection gives them a single retained-size
/// accounting site (the `RetainedSize` impl below) instead of a bespoke
/// helper and bespoke arithmetic per field spread across every builder fit
/// path (#1890). A fourth optional review joins by adding a field here, one
/// line to `retained_size`, one accessor, and one typed `set_*` method on
/// `PolicyReportBuilder` -- no other fit path changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PolicyOptionalReviews {
    diff: Option<PolicyDiffReview>,
    incremental: Option<PolicyIncrementalReview>,
    packs: Option<PolicyPackActivationReview>,
    baseline: Option<PolicyBaselineReview>,
}

impl PolicyOptionalReviews {
    const fn diff(&self) -> Option<&PolicyDiffReview> {
        self.diff.as_ref()
    }

    const fn incremental(&self) -> Option<&PolicyIncrementalReview> {
        self.incremental.as_ref()
    }

    const fn packs(&self) -> Option<&PolicyPackActivationReview> {
        self.packs.as_ref()
    }

    const fn baseline(&self) -> Option<&PolicyBaselineReview> {
        self.baseline.as_ref()
    }

    /// Count of the reviews that are present, for the additive field count
    /// in [`PolicyReportDocument`]'s manual `Serialize` impl.
    fn present_count(&self) -> usize {
        usize::from(self.diff.is_some())
            + usize::from(self.incremental.is_some())
            + usize::from(self.packs.is_some())
            + usize::from(self.baseline.is_some())
    }
}

impl RetainedSize for PolicyOptionalReviews {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.diff))
            .saturating_add(retained_extra(&self.incremental))
            .saturating_add(retained_extra(&self.packs))
            .saturating_add(retained_extra(&self.baseline))
    }
}

/// The sole canonical input to every policy-report renderer.
#[derive(Debug, Clone)]
pub struct PolicyReportDocument {
    schema_version: u32,
    evaluation: PolicyReportEvaluationContext,
    execution: PolicyExecutionMetadata,
    rules: Vec<PolicyRuleDescriptor>,
    runs: Vec<PolicyRun>,
    suppressions: Vec<PolicySuppressionReview>,
    scope: Vec<PolicyScopeReview>,
    reviews: PolicyOptionalReviews,
    diagnostics: Vec<PolicyReportDiagnostic>,
    diagnostics_truncated: bool,
    omitted_diagnostics_lower_bound: u64,
    worst_omitted_diagnostic_severity: Option<PolicyDiagnosticSeverity>,
}

impl PolicyReportDocument {
    pub const SCHEMA_VERSION: u32 = 5;

    #[cfg(test)]
    pub(crate) fn try_new(
        rules: Vec<PolicyRuleDescriptor>,
        runs: Vec<PolicyRun>,
        diagnostics: Vec<PolicyReportDiagnostic>,
        diagnostics_truncated: bool,
        omitted_diagnostics_lower_bound: u64,
        worst_omitted_diagnostic_severity: Option<PolicyDiagnosticSeverity>,
    ) -> Result<Self, PolicyReportDocumentError> {
        let options = super::coordinator::PolicyEvaluationOptions::new(
            super::suppression::PolicyEvaluationDate::from_ymd(2026, 7, 27)
                .expect("fixed test date is valid"),
        );
        Self::try_new_with_suppression_audit(
            PolicyReportEvaluationContext::new(
                options.evaluation_date(),
                options
                    .suppressions()
                    .source_states(super::suppression::PolicySuppressionDocumentState::NotFound),
                options.scope(),
                super::scope::PolicyScopeDocumentState::NotFound,
            ),
            rules,
            runs,
            Vec::new(),
            diagnostics,
            diagnostics_truncated,
            omitted_diagnostics_lower_bound,
            worst_omitted_diagnostic_severity,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn try_new_with_suppression_audit(
        evaluation: PolicyReportEvaluationContext,
        rules: Vec<PolicyRuleDescriptor>,
        runs: Vec<PolicyRun>,
        suppressions: Vec<PolicySuppressionReview>,
        diagnostics: Vec<PolicyReportDiagnostic>,
        diagnostics_truncated: bool,
        omitted_diagnostics_lower_bound: u64,
        worst_omitted_diagnostic_severity: Option<PolicyDiagnosticSeverity>,
    ) -> Result<Self, PolicyReportDocumentError> {
        Self::try_new_with_execution(
            evaluation,
            PolicyExecutionMetadata::default(),
            rules,
            runs,
            suppressions,
            Vec::new(),
            PolicyOptionalReviews::default(),
            diagnostics,
            diagnostics_truncated,
            omitted_diagnostics_lower_bound,
            worst_omitted_diagnostic_severity,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new_with_execution(
        evaluation: PolicyReportEvaluationContext,
        execution: PolicyExecutionMetadata,
        mut rules: Vec<PolicyRuleDescriptor>,
        mut runs: Vec<PolicyRun>,
        mut suppressions: Vec<PolicySuppressionReview>,
        mut scope: Vec<PolicyScopeReview>,
        reviews: PolicyOptionalReviews,
        mut diagnostics: Vec<PolicyReportDiagnostic>,
        diagnostics_truncated: bool,
        omitted_diagnostics_lower_bound: u64,
        worst_omitted_diagnostic_severity: Option<PolicyDiagnosticSeverity>,
    ) -> Result<Self, PolicyReportDocumentError> {
        if diagnostics_truncated != (omitted_diagnostics_lower_bound > 0)
            || diagnostics_truncated != worst_omitted_diagnostic_severity.is_some()
        {
            return Err(PolicyReportDocumentError::InconsistentDiagnosticTruncation);
        }

        rules.sort_by(compare_rule_descriptors);
        runs.sort_by(compare_policy_runs);
        suppressions.sort_by(compare_suppression_reviews);
        scope.sort_by(compare_scope_reviews);
        diagnostics.sort_by(compare_report_diagnostics);
        tighten_vec(&mut rules);
        tighten_vec(&mut runs);
        tighten_vec(&mut suppressions);
        tighten_vec(&mut scope);
        tighten_vec(&mut diagnostics);
        validate_rule_run_joins(&rules, &runs)?;
        validate_suppression_joins(&runs, &suppressions)?;
        validate_scope_joins(&runs, &scope)?;
        validate_diff_joins(&runs, reviews.diff())?;
        validate_baseline_joins(&runs, reviews.baseline())?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION,
            evaluation,
            execution,
            rules,
            runs,
            suppressions,
            scope,
            reviews,
            diagnostics,
            diagnostics_truncated,
            omitted_diagnostics_lower_bound,
            worst_omitted_diagnostic_severity,
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn evaluation(&self) -> &PolicyReportEvaluationContext {
        &self.evaluation
    }

    pub const fn execution(&self) -> &PolicyExecutionMetadata {
        &self.execution
    }

    pub(crate) fn replace_execution(&mut self, execution: PolicyExecutionMetadata) {
        self.execution = execution;
    }

    pub fn rules(&self) -> &[PolicyRuleDescriptor] {
        &self.rules
    }

    pub fn runs(&self) -> &[PolicyRun] {
        &self.runs
    }

    pub fn suppressions(&self) -> &[PolicySuppressionReview] {
        &self.suppressions
    }

    pub fn scope(&self) -> &[PolicyScopeReview] {
        &self.scope
    }

    pub const fn diff(&self) -> Option<&PolicyDiffReview> {
        self.reviews.diff()
    }

    /// What this run reused instead of recomputing, when it could reuse
    /// anything at all.
    ///
    /// Additive, like the other reviews: a run without a diff base or with
    /// `--no-incremental` keeps its exact schema-version-5 shape. Nothing here
    /// is a statement about the workspace -- it is a measurement of the run,
    /// which is why it is not a diagnostic, not a work metric, and not part of
    /// what two runs of the same workspace must agree on.
    pub const fn incremental(&self) -> Option<&PolicyIncrementalReview> {
        self.reviews.incremental()
    }

    pub const fn packs(&self) -> Option<&PolicyPackActivationReview> {
        self.reviews.packs()
    }

    pub const fn baseline(&self) -> Option<&PolicyBaselineReview> {
        self.reviews.baseline()
    }

    pub fn diagnostics(&self) -> &[PolicyReportDiagnostic] {
        &self.diagnostics
    }

    pub const fn diagnostics_truncated(&self) -> bool {
        self.diagnostics_truncated
    }

    pub const fn omitted_diagnostics_lower_bound(&self) -> u64 {
        self.omitted_diagnostics_lower_bound
    }

    pub const fn worst_omitted_diagnostic_severity(&self) -> Option<PolicyDiagnosticSeverity> {
        self.worst_omitted_diagnostic_severity
    }
}

impl Serialize for PolicyReportDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // The `diff`, `packs`, and `baseline` fields are additive and
        // serialized only when present, so a report without them keeps its
        // exact schema-version-5 shape.
        let field_count = 11 + self.reviews.present_count();
        let mut state = serializer.serialize_struct("PolicyReportDocument", field_count)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("evaluation", &self.evaluation)?;
        state.serialize_field("execution", &self.execution)?;
        state.serialize_field("rules", &self.rules)?;
        state.serialize_field("runs", &self.runs)?;
        state.serialize_field("suppressions", &self.suppressions)?;
        state.serialize_field("scope", &self.scope)?;
        if let Some(diff) = self.reviews.diff() {
            state.serialize_field("diff", diff)?;
        }
        if let Some(incremental) = self.reviews.incremental() {
            state.serialize_field("incremental", incremental)?;
        }
        if let Some(packs) = self.reviews.packs() {
            state.serialize_field("packs", packs)?;
        }
        if let Some(baseline) = self.reviews.baseline() {
            state.serialize_field("baseline", baseline)?;
        }
        state.serialize_field("diagnostics", &self.diagnostics)?;
        state.serialize_field("diagnostics_truncated", &self.diagnostics_truncated)?;
        state.serialize_field(
            "omitted_diagnostics_lower_bound",
            &self.omitted_diagnostics_lower_bound,
        )?;
        state.serialize_field(
            "worst_omitted_diagnostic_severity",
            &self.worst_omitted_diagnostic_severity,
        )?;
        state.end()
    }
}

impl RetainedSize for PolicyReportDocument {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.evaluation))
            .saturating_add(retained_extra(&self.execution))
            .saturating_add(retained_extra(&self.rules))
            .saturating_add(retained_extra(&self.runs))
            .saturating_add(retained_extra(&self.suppressions))
            .saturating_add(retained_extra(&self.scope))
            .saturating_add(retained_extra(&self.reviews))
            .saturating_add(retained_extra(&self.diagnostics))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyReportDocumentError {
    InconsistentDiagnosticTruncation,
    AmbiguousRuleJoin {
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
    },
    AmbiguousRunJoin {
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
    },
    MissingRun {
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
    },
    MissingRule {
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
    },
    DuplicatePolicyId {
        policy_id: PolicyId,
    },
    AnalysisTypeMismatch {
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
        rule_analysis_type: PolicyAnalysisType,
        run_analysis_type: PolicyAnalysisType,
    },
    DuplicateSuppressionReview {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    MissingSuppressedFinding {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    SuppressedFindingWithoutReview {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    ScopedFindingWithoutReview {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    DiffFindingWithoutReview {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    MissingDiffFindingDecision {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    BaselineFindingWithoutReview {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    BaselineAppliedJoinMismatch {
        attached: u64,
        applied_count: u64,
        result_omitted_count: u64,
    },
}

impl fmt::Display for PolicyReportDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InconsistentDiagnosticTruncation => formatter.write_str(
                "report diagnostic truncation, omitted count, and worst severity are inconsistent",
            ),
            Self::AmbiguousRuleJoin {
                policy_id,
                policy_hash,
            } => write!(
                formatter,
                "report has multiple rule descriptors for {policy_id}@{policy_hash}"
            ),
            Self::AmbiguousRunJoin {
                policy_id,
                policy_hash,
            } => write!(
                formatter,
                "report has multiple policy runs for {policy_id}@{policy_hash}"
            ),
            Self::MissingRun {
                policy_id,
                policy_hash,
            } => write!(
                formatter,
                "report rule {policy_id}@{policy_hash} has no matching run"
            ),
            Self::MissingRule {
                policy_id,
                policy_hash,
            } => write!(
                formatter,
                "report run {policy_id}@{policy_hash} has no matching rule"
            ),
            Self::DuplicatePolicyId { policy_id } => {
                write!(formatter, "report contains duplicate policy ID {policy_id}")
            }
            Self::AnalysisTypeMismatch {
                policy_id,
                policy_hash,
                rule_analysis_type,
                run_analysis_type,
            } => write!(
                formatter,
                "report rule and run {policy_id}@{policy_hash} disagree on analysis type: rule {rule_analysis_type:?}, run {run_analysis_type:?}"
            ),
            Self::DuplicateSuppressionReview {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "report has duplicate suppression reviews for {policy_id} finding {finding_id}"
            ),
            Self::MissingSuppressedFinding {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "applied suppression for {policy_id} finding {finding_id} has no retained result"
            ),
            Self::SuppressedFindingWithoutReview {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "suppressed finding {policy_id} finding {finding_id} has no applied review"
            ),
            Self::ScopedFindingWithoutReview {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "scoped finding {policy_id} finding {finding_id} has no applied scope review"
            ),
            Self::DiffFindingWithoutReview {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "finding {policy_id} finding {finding_id} carries a diff decision without a classifying top-level diff review"
            ),
            Self::MissingDiffFindingDecision {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "diff review classified the report but finding {policy_id} finding {finding_id} has no diff decision"
            ),
            Self::BaselineFindingWithoutReview {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "finding {policy_id} finding {finding_id} carries a baseline decision without a top-level baseline review"
            ),
            Self::BaselineAppliedJoinMismatch {
                attached,
                applied_count,
                result_omitted_count,
            } => write!(
                formatter,
                "report retains {attached} baselined findings but the baseline review applied {applied_count} entries with {result_omitted_count} results omitted"
            ),
        }
    }
}

impl std::error::Error for PolicyReportDocumentError {}

const SKELETON_ALLOWANCE_PER_INPUT: usize = 8 * 1024;
const EMERGENCY_DIAGNOSTIC_ALLOWANCE: usize = 4 * 1024;
const PER_POLICY_INCOMPLETE_REASON_ALLOWANCE: usize = 256;

/// Incrementally bounded, transactionally retaining report assembler.
pub struct PolicyReportBuilder {
    budget: PolicyBatchBudget,
    evaluation: PolicyReportEvaluationContext,
    execution: PolicyExecutionMetadata,
    expected_inputs: usize,
    registered_inputs: usize,
    outstanding_skeleton_allowance: usize,
    emergency_allowance: usize,
    rules: Vec<PolicyRuleDescriptor>,
    runs: Vec<PolicyRun>,
    suppressions: Vec<PolicySuppressionReview>,
    scope: Vec<PolicyScopeReview>,
    reviews: PolicyOptionalReviews,
    diagnostics: Vec<PolicyReportDiagnostic>,
    diagnostics_truncated: bool,
    omitted_diagnostics_lower_bound: u64,
    worst_omitted_diagnostic_severity: Option<PolicyDiagnosticSeverity>,
}

impl PolicyReportBuilder {
    #[cfg(test)]
    pub fn new(
        budget: PolicyBatchBudget,
        expected_inputs: usize,
    ) -> Result<Self, PolicyReportBuilderError> {
        let options = super::coordinator::PolicyEvaluationOptions::new(
            super::suppression::PolicyEvaluationDate::from_ymd(2026, 7, 27)
                .expect("fixed test date is valid"),
        );
        Self::new_with_suppression_audit(
            budget,
            expected_inputs,
            PolicyReportEvaluationContext::new(
                options.evaluation_date(),
                options
                    .suppressions()
                    .source_states(super::suppression::PolicySuppressionDocumentState::NotFound),
                options.scope(),
                super::scope::PolicyScopeDocumentState::NotFound,
            ),
            Vec::new(),
            Vec::new(),
        )
    }

    pub fn new_with_suppression_audit(
        budget: PolicyBatchBudget,
        expected_inputs: usize,
        evaluation: PolicyReportEvaluationContext,
        mut suppressions: Vec<PolicySuppressionReview>,
        mut scope: Vec<PolicyScopeReview>,
    ) -> Result<Self, PolicyReportBuilderError> {
        if expected_inputs > budget.max_policies() {
            return Err(PolicyReportBuilderError::TooManyInputs {
                max: budget.max_policies(),
            });
        }
        let rules = Vec::with_capacity(expected_inputs);
        let runs = Vec::with_capacity(expected_inputs);
        suppressions.sort_by(compare_suppression_reviews);
        if suppressions
            .windows(2)
            .any(|reviews| compare_suppression_reviews(&reviews[0], &reviews[1]).is_eq())
        {
            return Err(PolicyReportBuilderError::DuplicateSuppressionReview);
        }
        tighten_vec(&mut suppressions);
        scope.sort_by(compare_scope_reviews);
        tighten_vec(&mut scope);
        let diagnostics = Vec::with_capacity(expected_inputs);
        let input_skeleton_allowance = expected_inputs
            .checked_mul(SKELETON_ALLOWANCE_PER_INPUT)
            .ok_or(PolicyReportBuilderError::RetainedSizeOverflow)?;
        let outstanding_skeleton_allowance = input_skeleton_allowance
            .checked_add(PolicyExecutionMetadata::maximum_retained_size(
                expected_inputs,
            ))
            .ok_or(PolicyReportBuilderError::RetainedSizeOverflow)?;
        let no_suppressions = Vec::new();
        let no_scope = Vec::new();
        let base_without_suppressions = report_storage_size(
            &evaluation,
            &rules,
            &runs,
            &no_suppressions,
            &no_scope,
            &diagnostics,
        );
        let base = report_storage_size(
            &evaluation,
            &rules,
            &runs,
            &suppressions,
            &scope,
            &diagnostics,
        );
        let preflight_without_suppressions = base_without_suppressions
            .checked_add(outstanding_skeleton_allowance)
            .and_then(|value| value.checked_add(EMERGENCY_DIAGNOSTIC_ALLOWANCE))
            .ok_or(PolicyReportBuilderError::RetainedSizeOverflow)?;
        let preflight = base
            .checked_add(outstanding_skeleton_allowance)
            .and_then(|value| value.checked_add(EMERGENCY_DIAGNOSTIC_ALLOWANCE))
            .ok_or(PolicyReportBuilderError::RetainedSizeOverflow)?;
        if !(suppressions.is_empty() && scope.is_empty())
            && preflight > budget.max_retained_report_bytes()
            && preflight_without_suppressions <= budget.max_retained_report_bytes()
        {
            return Err(
                PolicyReportBuilderError::SuppressionAuditPreflightExceeded {
                    required_bytes: preflight,
                    max_bytes: budget.max_retained_report_bytes(),
                },
            );
        }
        if preflight > budget.max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::SkeletonPreflightExceeded {
                required_bytes: preflight,
                max_bytes: budget.max_retained_report_bytes(),
            });
        }
        Ok(Self {
            budget,
            evaluation,
            execution: PolicyExecutionMetadata::default(),
            expected_inputs,
            registered_inputs: 0,
            outstanding_skeleton_allowance,
            emergency_allowance: EMERGENCY_DIAGNOSTIC_ALLOWANCE,
            rules,
            runs,
            suppressions,
            scope,
            reviews: PolicyOptionalReviews::default(),
            diagnostics,
            diagnostics_truncated: false,
            omitted_diagnostics_lower_bound: 0,
            worst_omitted_diagnostic_severity: None,
        })
    }

    /// Atomically register the rule descriptor and its already bounded minimal run.
    pub fn register_policy(
        &mut self,
        descriptor: PolicyRuleDescriptor,
        mut run: PolicyRun,
    ) -> Result<(), PolicyReportBuilderError> {
        self.ensure_input_slot()?;
        if descriptor.policy_id() != run.policy_id()
            || descriptor.policy_hash() != run.policy_hash()
            || descriptor.analysis_type() != run.analysis_type()
        {
            return Err(PolicyReportBuilderError::RuleRunJoinMismatch);
        }
        if !run.findings().is_empty() {
            return Err(PolicyReportBuilderError::NonMinimalRunSkeleton);
        }
        run.validate_against_budget(self.budget.per_policy())
            .map_err(PolicyReportBuilderError::RunBudgetViolation)?;
        let key = (descriptor.policy_id(), descriptor.policy_hash());
        if self
            .rules
            .iter()
            .any(|rule| rule.policy_id() == key.0 && rule.policy_hash() == key.1)
            || self
                .runs
                .iter()
                .any(|existing| existing.policy_id() == key.0 && existing.policy_hash() == key.1)
        {
            return Err(PolicyReportBuilderError::DuplicatePolicySkeleton);
        }
        if self.rules.iter().any(|rule| rule.policy_id() == key.0)
            || self
                .runs
                .iter()
                .any(|existing| existing.policy_id() == key.0)
        {
            return Err(PolicyReportBuilderError::DuplicatePolicyId {
                policy_id: key.0.clone(),
            });
        }

        let mut rules = self.rules.clone();
        let mut runs = self.runs.clone();
        rules.push(descriptor);
        runs.push(run.clone());
        rules.sort_by(compare_rule_descriptors);
        runs.sort_by(compare_policy_runs);
        tighten_vec(&mut rules);
        tighten_vec(&mut runs);

        let policy_index = rules
            .iter()
            .position(|rule| {
                rule.policy_id() == run.policy_id() && rule.policy_hash() == run.policy_hash()
            })
            .expect("newly inserted descriptor exists");
        let run_index = runs
            .iter()
            .position(|candidate| {
                candidate.policy_id() == run.policy_id()
                    && candidate.policy_hash() == run.policy_hash()
            })
            .expect("newly inserted run exists");
        let policy_bytes = rules[policy_index]
            .retained_size()
            .saturating_add(runs[run_index].retained_size());
        let reserved_policy_bytes = policy_bytes
            .checked_add(PER_POLICY_INCOMPLETE_REASON_ALLOWANCE)
            .ok_or(PolicyReportBuilderError::RetainedSizeOverflow)?;
        if reserved_policy_bytes > self.budget.per_policy().max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::PolicySkeletonExceeded {
                retained_bytes: reserved_policy_bytes,
                max_bytes: self.budget.per_policy().max_retained_report_bytes(),
            });
        }
        run.set_retained_report_bytes(policy_bytes);
        runs[run_index] = run;
        let next_reserved = self
            .outstanding_skeleton_allowance
            .saturating_sub(SKELETON_ALLOWANCE_PER_INPUT);
        self.ensure_batch_fit(&rules, &runs, &self.diagnostics, next_reserved, true)?;
        self.rules = rules;
        self.runs = runs;
        self.consume_input_slot();
        Ok(())
    }

    /// Atomically register the guaranteed primary outcome for a failed input.
    pub fn register_primary_diagnostic(
        &mut self,
        diagnostic: PolicyReportDiagnostic,
    ) -> Result<(), PolicyReportBuilderError> {
        self.ensure_input_slot()?;
        if diagnostic.retained_size() > SKELETON_ALLOWANCE_PER_INPUT {
            return Err(
                PolicyReportBuilderError::PrimaryDiagnosticExceedsSkeletonAllowance {
                    retained_bytes: diagnostic.retained_size(),
                    max_bytes: SKELETON_ALLOWANCE_PER_INPUT,
                },
            );
        }
        let mut diagnostics = self.diagnostics.clone();
        diagnostics.push(diagnostic);
        diagnostics.sort_by(compare_report_diagnostics);
        tighten_vec(&mut diagnostics);
        let next_reserved = self
            .outstanding_skeleton_allowance
            .saturating_sub(SKELETON_ALLOWANCE_PER_INPUT);
        self.ensure_batch_fit(&self.rules, &self.runs, &diagnostics, next_reserved, true)?;
        self.diagnostics = diagnostics;
        self.consume_input_slot();
        Ok(())
    }

    pub fn retain_finding(
        &mut self,
        finding: PolicyFinding,
    ) -> Result<PolicyRetentionOutcome, PolicyReportBuilderError> {
        self.ensure_evaluation_ready()?;
        let run_index = self.find_run_index(finding.policy_id(), finding.policy_hash())?;
        if finding.analysis_type() != self.runs[run_index].analysis_type() {
            return Err(PolicyReportBuilderError::FindingRunJoinMismatch);
        }
        let weak_identity = finding.identity_stability() == FindingIdentityStability::Weak;
        if weak_identity
            && matches!(
                self.runs[run_index].completion(),
                PolicyRunCompletion::Unsupported { .. } | PolicyRunCompletion::Failed { .. }
            )
        {
            return Err(PolicyReportBuilderError::WeakFindingCompletionMismatch);
        }
        if self.runs[run_index]
            .findings()
            .iter()
            .any(|existing| existing.id() == finding.id())
        {
            return Err(PolicyReportBuilderError::DuplicateFindingId);
        }
        if let Err(error) = finding.validate_against_budget(self.budget.per_policy()) {
            if error.is_budget_limit_exceeded() {
                self.record_omitted_finding(
                    run_index,
                    PolicyIncompleteReason::ReportRetentionBudget,
                )?;
                return Ok(PolicyRetentionOutcome::Omitted {
                    reason: PolicyIncompleteReason::ReportRetentionBudget,
                });
            }
            return Err(PolicyReportBuilderError::FindingBudgetViolation(error));
        }

        let per_policy_cap_reached =
            self.runs[run_index].findings().len() >= self.budget.per_policy().max_findings();
        let batch_cap_reached = self.total_findings() >= self.budget.max_total_findings();
        if per_policy_cap_reached || batch_cap_reached {
            self.record_omitted_finding(run_index, PolicyIncompleteReason::BatchFindingLimit)?;
            return Ok(PolicyRetentionOutcome::Omitted {
                reason: PolicyIncompleteReason::BatchFindingLimit,
            });
        }

        let mut candidate_runs = self.runs.clone();
        let mut findings = candidate_runs[run_index].findings().to_vec();
        findings.push(finding);
        candidate_runs[run_index].replace_findings(findings);
        if weak_identity {
            candidate_runs[run_index]
                .mark_inconclusive(PolicyIncompleteReason::StableAnchorUnavailable)?;
        }
        self.refresh_candidate_policy_bytes(&mut candidate_runs, run_index);
        let policy_bytes = self.policy_retained_bytes(&candidate_runs, run_index);
        let policy_fits = policy_bytes
            .checked_add(PER_POLICY_INCOMPLETE_REASON_ALLOWANCE)
            .is_some_and(|bytes| bytes <= self.budget.per_policy().max_retained_report_bytes());
        let batch_fits = report_storage_size(
            &self.evaluation,
            &self.rules,
            &candidate_runs,
            &self.suppressions,
            &self.scope,
            &self.diagnostics,
        )
        .checked_add(self.reviews_extra())
        .and_then(|bytes| bytes.checked_add(self.emergency_allowance))
        .is_some_and(|bytes| bytes <= self.budget.max_retained_report_bytes());
        if !policy_fits || !batch_fits {
            self.record_omitted_finding(run_index, PolicyIncompleteReason::ReportRetentionBudget)?;
            return Ok(PolicyRetentionOutcome::Omitted {
                reason: PolicyIncompleteReason::ReportRetentionBudget,
            });
        }

        self.runs = candidate_runs;
        Ok(PolicyRetentionOutcome::Retained)
    }

    pub fn retain_run_diagnostic(
        &mut self,
        policy_id: &PolicyId,
        policy_hash: PolicySemanticHash,
        diagnostic: PolicyDiagnostic,
    ) -> Result<PolicyRetentionOutcome, PolicyReportBuilderError> {
        self.ensure_evaluation_ready()?;
        let run_index = self.find_run_index(policy_id, policy_hash)?;
        if !completion_allows_diagnostic_impact(
            self.runs[run_index].completion(),
            diagnostic.impact(),
        ) {
            return Err(PolicyReportBuilderError::DiagnosticCompletionMismatch);
        }
        if self.runs[run_index].diagnostics().contains(&diagnostic) {
            return Ok(PolicyRetentionOutcome::Retained);
        }
        let mut candidate_runs = self.runs.clone();
        let mut diagnostics = candidate_runs[run_index].diagnostics().to_vec();
        diagnostics.push(diagnostic);
        // Past the per-policy cap the list is folded to one entry per reason
        // family with the count of the diagnostics it covers, rather than
        // dropping the reasons that sort last (#2356).
        let condensed = normalize_policy_diagnostics_bounded(
            &mut diagnostics,
            self.budget.per_policy().max_diagnostics(),
        );
        candidate_runs[run_index].replace_diagnostics(diagnostics, condensed);
        if condensed {
            candidate_runs[run_index]
                .mark_inconclusive(PolicyIncompleteReason::ReportRetentionBudget)?;
        }
        self.refresh_candidate_policy_bytes(&mut candidate_runs, run_index);
        let policy_fits = self
            .policy_retained_bytes(&candidate_runs, run_index)
            .checked_add(PER_POLICY_INCOMPLETE_REASON_ALLOWANCE)
            .is_some_and(|bytes| bytes <= self.budget.per_policy().max_retained_report_bytes());
        let batch_fits = report_storage_size(
            &self.evaluation,
            &self.rules,
            &candidate_runs,
            &self.suppressions,
            &self.scope,
            &self.diagnostics,
        )
        .checked_add(self.reviews_extra())
        .and_then(|bytes| bytes.checked_add(self.emergency_allowance))
        .is_some_and(|bytes| bytes <= self.budget.max_retained_report_bytes());
        if !policy_fits || !batch_fits {
            let mut omitted_runs = self.runs.clone();
            let retained = omitted_runs[run_index].diagnostics().to_vec();
            omitted_runs[run_index].replace_diagnostics(retained, true);
            omitted_runs[run_index]
                .mark_inconclusive(PolicyIncompleteReason::ReportRetentionBudget)?;
            self.refresh_candidate_policy_bytes(&mut omitted_runs, run_index);
            self.ensure_emergency_update_fits(&omitted_runs, run_index)?;
            self.runs = omitted_runs;
            return Ok(PolicyRetentionOutcome::DiagnosticOmitted);
        }
        self.runs = candidate_runs;
        if condensed {
            return Ok(PolicyRetentionOutcome::DiagnosticOmitted);
        }
        Ok(PolicyRetentionOutcome::Retained)
    }

    pub fn retain_report_diagnostic(
        &mut self,
        diagnostic: PolicyReportDiagnostic,
    ) -> Result<PolicyRetentionOutcome, PolicyReportBuilderError> {
        self.ensure_evaluation_ready()?;
        let severity = diagnostic.severity();
        let mut diagnostics = self.diagnostics.clone();
        diagnostics.push(diagnostic);
        diagnostics.sort_by(compare_report_diagnostics);
        tighten_vec(&mut diagnostics);
        let fits = report_storage_size(
            &self.evaluation,
            &self.rules,
            &self.runs,
            &self.suppressions,
            &self.scope,
            &diagnostics,
        )
        .checked_add(self.reviews_extra())
        .and_then(|bytes| bytes.checked_add(self.emergency_allowance))
        .is_some_and(|bytes| bytes <= self.budget.max_retained_report_bytes());
        if !fits {
            self.diagnostics_truncated = true;
            self.omitted_diagnostics_lower_bound =
                self.omitted_diagnostics_lower_bound.saturating_add(1);
            self.worst_omitted_diagnostic_severity = Some(
                self.worst_omitted_diagnostic_severity
                    .map_or(severity, |current| current.max(severity)),
            );
            return Ok(PolicyRetentionOutcome::DiagnosticOmitted);
        }
        self.diagnostics = diagnostics;
        Ok(PolicyRetentionOutcome::Retained)
    }

    pub fn mark_suppression_result_omitted(
        &mut self,
        policy_id: &PolicyId,
        finding_id: PolicyFindingId,
    ) -> Result<(), PolicyReportBuilderError> {
        let mut matches = self.suppressions.iter().enumerate().filter(|(_, review)| {
            review.policy_id() == policy_id && review.finding_id() == finding_id
        });
        let (index, _) = matches
            .next()
            .ok_or(PolicyReportBuilderError::UnknownSuppressionReview)?;
        if matches.next().is_some() {
            return Err(PolicyReportBuilderError::AmbiguousSuppressionReview);
        }
        let review = &mut self.suppressions[index];
        if !review.applied() {
            return Err(PolicyReportBuilderError::SuppressionReviewNotApplied);
        }
        review.mark_result_omitted();
        Ok(())
    }

    pub fn mark_scope_result_omitted(
        &mut self,
        finding_scope: &super::scope::PolicyFindingScope,
    ) -> Result<(), PolicyReportBuilderError> {
        let mut marked = false;
        for review in self
            .scope
            .iter_mut()
            .filter(|review| review.covers(finding_scope))
        {
            review.mark_result_omitted();
            marked = true;
        }
        if !marked {
            return Err(PolicyReportBuilderError::UnknownScopeReview);
        }
        Ok(())
    }

    pub fn finish(self) -> Result<PolicyReportDocument, PolicyReportBuilderError> {
        if self.registered_inputs != self.expected_inputs {
            return Err(PolicyReportBuilderError::InputsNotFullyRegistered {
                expected: self.expected_inputs,
                registered: self.registered_inputs,
            });
        }
        let document = PolicyReportDocument::try_new_with_execution(
            self.evaluation,
            self.execution,
            self.rules,
            self.runs,
            self.suppressions,
            self.scope,
            self.reviews,
            self.diagnostics,
            self.diagnostics_truncated,
            self.omitted_diagnostics_lower_bound,
            self.worst_omitted_diagnostic_severity,
        )?;
        if document.retained_size() > self.budget.max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::FinalDocumentExceedsBudget {
                retained_bytes: document.retained_size(),
                max_bytes: self.budget.max_retained_report_bytes(),
            });
        }
        Ok(document)
    }

    pub fn set_execution(
        &mut self,
        execution: PolicyExecutionMetadata,
    ) -> Result<(), PolicyReportBuilderError> {
        let retained = report_storage_size(
            &self.evaluation,
            &self.rules,
            &self.runs,
            &self.suppressions,
            &self.scope,
            &self.diagnostics,
        )
        .saturating_add(self.reviews_extra())
        .saturating_add(retained_extra(&execution));
        if retained > self.budget.max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::BatchRetentionExceeded {
                retained_bytes: retained,
                max_bytes: self.budget.max_retained_report_bytes(),
            });
        }
        self.execution = execution;
        Ok(())
    }

    /// Retain the diff review that classifies this report's findings.
    ///
    /// The review is bounded by construction; charging it against the batch
    /// budget keeps every later retention decision aware of its bytes.
    pub fn set_diff(&mut self, diff: PolicyDiffReview) -> Result<(), PolicyReportBuilderError> {
        assert!(
            self.reviews.diff.is_none(),
            "diff review is set at most once"
        );
        self.ensure_review_fits(retained_extra(&diff))?;
        self.reviews.diff = Some(diff);
        Ok(())
    }

    /// Retain the reuse review for this report.
    ///
    /// The review is bounded by the number of policies that ran; charging it
    /// against the batch budget keeps every later retention decision aware of
    /// its bytes, exactly as the diff review is charged.
    pub fn set_incremental(
        &mut self,
        incremental: PolicyIncrementalReview,
    ) -> Result<(), PolicyReportBuilderError> {
        assert!(
            self.reviews.incremental.is_none(),
            "incremental review is set at most once"
        );
        self.ensure_review_fits(retained_extra(&incremental))?;
        self.reviews.incremental = Some(incremental);
        Ok(())
    }

    /// Retain the pack-activation review for this report.
    ///
    /// The review is bounded by construction; charging it against the batch
    /// budget keeps every later retention decision aware of its bytes.
    pub fn set_packs(
        &mut self,
        packs: PolicyPackActivationReview,
    ) -> Result<(), PolicyReportBuilderError> {
        assert!(
            self.reviews.packs.is_none(),
            "pack-activation review is set at most once"
        );
        self.ensure_review_fits(retained_extra(&packs))?;
        self.reviews.packs = Some(packs);
        Ok(())
    }

    /// Retain the baseline review that audits this report's accepted findings.
    ///
    /// The review is bounded by construction; charging it against the batch
    /// budget keeps every later retention decision aware of its bytes.
    pub fn set_baseline(
        &mut self,
        baseline: PolicyBaselineReview,
    ) -> Result<(), PolicyReportBuilderError> {
        assert!(
            self.reviews.baseline.is_none(),
            "baseline review is set at most once"
        );
        self.ensure_review_fits(retained_extra(&baseline))?;
        self.reviews.baseline = Some(baseline);
        Ok(())
    }

    /// Record that a baselined finding's result was dropped by the retention
    /// budget. Only counts change, so no budget re-check is needed.
    pub fn mark_baseline_result_omitted(
        &mut self,
        policy_id: &PolicyId,
        finding_id: PolicyFindingId,
    ) -> Result<(), PolicyReportBuilderError> {
        let baseline = self
            .reviews
            .baseline
            .as_mut()
            .ok_or(PolicyReportBuilderError::UnknownBaselineReview)?;
        baseline.mark_result_omitted(policy_id, finding_id);
        Ok(())
    }

    /// Retained bytes contributed by whichever optional reviews are already
    /// attached. This is the single site every fit path charges for the
    /// diff, packs, and baseline reviews together (#1890): a new review type
    /// only needs a field on [`PolicyOptionalReviews`] plus one line in its
    /// `RetainedSize` impl, not a change here.
    fn reviews_extra(&self) -> usize {
        retained_extra(&self.reviews)
    }

    /// Single accounting site for attaching one of the optional top-level
    /// reviews: the shared budget arithmetic every `set_*` review method
    /// uses to charge its already-attached siblings plus the new review's
    /// own bytes against the batch budget (#1890).
    fn ensure_review_fits(&self, new_review_extra: usize) -> Result<(), PolicyReportBuilderError> {
        let retained = report_storage_size(
            &self.evaluation,
            &self.rules,
            &self.runs,
            &self.suppressions,
            &self.scope,
            &self.diagnostics,
        )
        .saturating_add(retained_extra(&self.execution))
        .saturating_add(self.reviews_extra())
        .saturating_add(new_review_extra);
        if retained > self.budget.max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::BatchRetentionExceeded {
                retained_bytes: retained,
                max_bytes: self.budget.max_retained_report_bytes(),
            });
        }
        Ok(())
    }

    fn ensure_input_slot(&self) -> Result<(), PolicyReportBuilderError> {
        if self.registered_inputs >= self.expected_inputs {
            return Err(PolicyReportBuilderError::UnexpectedInputOutcome);
        }
        Ok(())
    }

    fn consume_input_slot(&mut self) {
        self.registered_inputs += 1;
        self.outstanding_skeleton_allowance = self
            .outstanding_skeleton_allowance
            .saturating_sub(SKELETON_ALLOWANCE_PER_INPUT);
    }

    fn ensure_evaluation_ready(&self) -> Result<(), PolicyReportBuilderError> {
        if self.registered_inputs != self.expected_inputs {
            return Err(PolicyReportBuilderError::EvaluationBeforeSkeletonsComplete);
        }
        Ok(())
    }

    fn ensure_batch_fit(
        &self,
        rules: &Vec<PolicyRuleDescriptor>,
        runs: &Vec<PolicyRun>,
        diagnostics: &Vec<PolicyReportDiagnostic>,
        outstanding_skeleton_allowance: usize,
        preserve_emergency: bool,
    ) -> Result<(), PolicyReportBuilderError> {
        let emergency = if preserve_emergency {
            self.emergency_allowance
        } else {
            0
        };
        let retained = report_storage_size(
            &self.evaluation,
            rules,
            runs,
            &self.suppressions,
            &self.scope,
            diagnostics,
        )
        .checked_add(self.reviews_extra())
        .and_then(|value| value.checked_add(outstanding_skeleton_allowance))
        .and_then(|value| value.checked_add(emergency))
        .ok_or(PolicyReportBuilderError::RetainedSizeOverflow)?;
        if retained > self.budget.max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::BatchRetentionExceeded {
                retained_bytes: retained,
                max_bytes: self.budget.max_retained_report_bytes(),
            });
        }
        Ok(())
    }

    fn find_run_index(
        &self,
        policy_id: &PolicyId,
        policy_hash: PolicySemanticHash,
    ) -> Result<usize, PolicyReportBuilderError> {
        let mut matches =
            self.runs.iter().enumerate().filter(|(_, run)| {
                run.policy_id() == policy_id && run.policy_hash() == policy_hash
            });
        let (index, _) = matches
            .next()
            .ok_or(PolicyReportBuilderError::UnknownPolicyRun)?;
        if matches.next().is_some() {
            return Err(PolicyReportBuilderError::AmbiguousPolicyRun);
        }
        Ok(index)
    }

    fn total_findings(&self) -> usize {
        self.runs
            .iter()
            .map(|run| run.findings().len())
            .fold(0_usize, usize::saturating_add)
    }

    fn record_omitted_finding(
        &mut self,
        run_index: usize,
        reason: PolicyIncompleteReason,
    ) -> Result<(), PolicyReportBuilderError> {
        let mut runs = self.runs.clone();
        runs[run_index].increment_omitted_findings();
        runs[run_index].mark_inconclusive(reason)?;
        self.refresh_candidate_policy_bytes(&mut runs, run_index);
        self.ensure_emergency_update_fits(&runs, run_index)?;
        self.runs = runs;
        Ok(())
    }

    fn ensure_emergency_update_fits(
        &mut self,
        runs: &Vec<PolicyRun>,
        run_index: usize,
    ) -> Result<(), PolicyReportBuilderError> {
        let policy_bytes = self.policy_retained_bytes(runs, run_index);
        if policy_bytes > self.budget.per_policy().max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::EmergencyReservationInvariant);
        }
        let actual = report_storage_size(
            &self.evaluation,
            &self.rules,
            runs,
            &self.suppressions,
            &self.scope,
            &self.diagnostics,
        )
        .saturating_add(self.reviews_extra());
        if actual > self.budget.max_retained_report_bytes() {
            return Err(PolicyReportBuilderError::EmergencyReservationInvariant);
        }
        self.emergency_allowance = self
            .budget
            .max_retained_report_bytes()
            .saturating_sub(actual)
            .min(self.emergency_allowance);
        Ok(())
    }

    fn policy_retained_bytes(&self, runs: &[PolicyRun], run_index: usize) -> usize {
        self.rules
            .iter()
            .find(|rule| {
                rule.policy_id() == runs[run_index].policy_id()
                    && rule.policy_hash() == runs[run_index].policy_hash()
            })
            .map_or(usize::MAX, |rule| {
                rule.retained_size()
                    .saturating_add(runs[run_index].retained_size())
            })
    }

    fn refresh_candidate_policy_bytes(&self, runs: &mut [PolicyRun], run_index: usize) {
        let bytes = self.policy_retained_bytes(runs, run_index);
        runs[run_index].set_retained_report_bytes(bytes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRetentionOutcome {
    Retained,
    Omitted { reason: PolicyIncompleteReason },
    DiagnosticOmitted,
}

#[derive(Debug)]
pub enum PolicyReportBuilderError {
    TooManyInputs {
        max: usize,
    },
    RetainedSizeOverflow,
    SkeletonPreflightExceeded {
        required_bytes: usize,
        max_bytes: usize,
    },
    SuppressionAuditPreflightExceeded {
        required_bytes: usize,
        max_bytes: usize,
    },
    UnexpectedInputOutcome,
    InputsNotFullyRegistered {
        expected: usize,
        registered: usize,
    },
    EvaluationBeforeSkeletonsComplete,
    RuleRunJoinMismatch,
    FindingRunJoinMismatch,
    WeakFindingCompletionMismatch,
    DuplicatePolicyId {
        policy_id: PolicyId,
    },
    DuplicatePolicySkeleton,
    NonMinimalRunSkeleton,
    DuplicateFindingId,
    UnknownPolicyRun,
    AmbiguousPolicyRun,
    DuplicateSuppressionReview,
    UnknownSuppressionReview,
    AmbiguousSuppressionReview,
    SuppressionReviewNotApplied,
    UnknownScopeReview,
    UnknownBaselineReview,
    DiagnosticCompletionMismatch,
    RunBudgetViolation(PolicyRunError),
    FindingBudgetViolation(PolicyFindingError),
    PrimaryDiagnosticExceedsSkeletonAllowance {
        retained_bytes: usize,
        max_bytes: usize,
    },
    PolicySkeletonExceeded {
        retained_bytes: usize,
        max_bytes: usize,
    },
    BatchRetentionExceeded {
        retained_bytes: usize,
        max_bytes: usize,
    },
    EmergencyReservationInvariant,
    FinalDocumentExceedsBudget {
        retained_bytes: usize,
        max_bytes: usize,
    },
    Completion(CompletionReasonError),
    Document(PolicyReportDocumentError),
}

impl From<CompletionReasonError> for PolicyReportBuilderError {
    fn from(error: CompletionReasonError) -> Self {
        Self::Completion(error)
    }
}

impl From<PolicyReportDocumentError> for PolicyReportBuilderError {
    fn from(error: PolicyReportDocumentError) -> Self {
        Self::Document(error)
    }
}

impl fmt::Display for PolicyReportBuilderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyInputs { max } => write!(formatter, "report accepts at most {max} inputs"),
            Self::RetainedSizeOverflow => {
                formatter.write_str("report retained-size arithmetic overflowed")
            }
            Self::SkeletonPreflightExceeded {
                required_bytes,
                max_bytes,
            } => write!(
                formatter,
                "report skeletons require {required_bytes} retained bytes, exceeding {max_bytes}"
            ),
            Self::SuppressionAuditPreflightExceeded {
                required_bytes,
                max_bytes,
            } => write!(
                formatter,
                "suppression audit and report skeletons require {required_bytes} retained bytes, exceeding {max_bytes}"
            ),
            Self::UnexpectedInputOutcome => {
                formatter.write_str("more input outcomes were registered than preflighted")
            }
            Self::InputsNotFullyRegistered {
                expected,
                registered,
            } => write!(
                formatter,
                "report expected {expected} input outcomes but registered {registered}"
            ),
            Self::EvaluationBeforeSkeletonsComplete => formatter.write_str(
                "findings and secondary diagnostics cannot be retained before every input skeleton",
            ),
            Self::RuleRunJoinMismatch => formatter
                .write_str("rule descriptor and run do not share a policy ID/hash/analysis type"),
            Self::FindingRunJoinMismatch => {
                formatter.write_str("finding does not share its run's policy ID/hash/type")
            }
            Self::WeakFindingCompletionMismatch => formatter.write_str(
                "a weak finding cannot be retained by an unsupported or failed policy run",
            ),
            Self::DuplicatePolicyId { policy_id } => {
                write!(
                    formatter,
                    "report policy ID {policy_id} is already registered"
                )
            }
            Self::DuplicatePolicySkeleton => {
                formatter.write_str("policy skeleton join is ambiguous")
            }
            Self::NonMinimalRunSkeleton => {
                formatter.write_str("a registered run skeleton must not already contain findings")
            }
            Self::DuplicateFindingId => {
                formatter.write_str("finding ID is already retained by this run")
            }
            Self::UnknownPolicyRun => formatter.write_str("no policy run matches this ID/hash"),
            Self::AmbiguousPolicyRun => {
                formatter.write_str("multiple policy runs match this ID/hash")
            }
            Self::DuplicateSuppressionReview => {
                formatter.write_str("suppression review keys must be unique")
            }
            Self::UnknownSuppressionReview => {
                formatter.write_str("no suppression review matches this policy and finding")
            }
            Self::AmbiguousSuppressionReview => {
                formatter.write_str("multiple suppression reviews match this policy and finding")
            }
            Self::SuppressionReviewNotApplied => {
                formatter.write_str("only an applied suppression review can omit its result")
            }
            Self::UnknownScopeReview => {
                formatter.write_str("no scope review matches this finding's scope decision")
            }
            Self::UnknownBaselineReview => {
                formatter.write_str("no baseline review is set for this report")
            }
            Self::DiagnosticCompletionMismatch => {
                formatter.write_str("diagnostic impact is not reflected by run completion")
            }
            Self::RunBudgetViolation(error) => {
                write!(
                    formatter,
                    "run skeleton exceeds the builder budget: {error}"
                )
            }
            Self::FindingBudgetViolation(error) => {
                write!(formatter, "finding exceeds the builder budget: {error}")
            }
            Self::PrimaryDiagnosticExceedsSkeletonAllowance {
                retained_bytes,
                max_bytes,
            } => write!(
                formatter,
                "primary diagnostic retains {retained_bytes} bytes, exceeding its {max_bytes}-byte skeleton allowance"
            ),
            Self::PolicySkeletonExceeded {
                retained_bytes,
                max_bytes,
            } => write!(
                formatter,
                "policy skeleton retains {retained_bytes} bytes, exceeding {max_bytes}"
            ),
            Self::BatchRetentionExceeded {
                retained_bytes,
                max_bytes,
            } => write!(
                formatter,
                "report retains or reserves {retained_bytes} bytes, exceeding {max_bytes}"
            ),
            Self::EmergencyReservationInvariant => formatter
                .write_str("reserved emergency capacity could not record an incomplete outcome"),
            Self::FinalDocumentExceedsBudget {
                retained_bytes,
                max_bytes,
            } => write!(
                formatter,
                "final report retains {retained_bytes} bytes, exceeding {max_bytes}"
            ),
            Self::Completion(error) => error.fmt(formatter),
            Self::Document(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicyReportBuilderError {}

fn compare_rule_descriptors(
    left: &PolicyRuleDescriptor,
    right: &PolicyRuleDescriptor,
) -> std::cmp::Ordering {
    (left.policy_id().as_str(), left.policy_hash())
        .cmp(&(right.policy_id().as_str(), right.policy_hash()))
}

fn compare_policy_runs(left: &PolicyRun, right: &PolicyRun) -> std::cmp::Ordering {
    (left.policy_id().as_str(), left.policy_hash())
        .cmp(&(right.policy_id().as_str(), right.policy_hash()))
}

fn compare_suppression_reviews(
    left: &PolicySuppressionReview,
    right: &PolicySuppressionReview,
) -> std::cmp::Ordering {
    (left.policy_id().as_str(), left.finding_id())
        .cmp(&(right.policy_id().as_str(), right.finding_id()))
}

fn compare_report_diagnostics(
    left: &PolicyReportDiagnostic,
    right: &PolicyReportDiagnostic,
) -> std::cmp::Ordering {
    (
        left.code,
        left.severity,
        &left.source,
        &left.byte_range,
        &left.message,
    )
        .cmp(&(
            right.code,
            right.severity,
            &right.source,
            &right.byte_range,
            &right.message,
        ))
        .then_with(|| compare_related_diagnostics(&left.related, &right.related))
}

fn compare_related_diagnostics(
    left: &[PolicySourceRelatedDiagnostic],
    right: &[PolicySourceRelatedDiagnostic],
) -> std::cmp::Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = (
            left.source.as_str(),
            left.range.start,
            left.range.end,
            left.message.as_str(),
        )
            .cmp(&(
                right.source.as_str(),
                right.range.start,
                right.range.end,
                right.message.as_str(),
            ));
        if !ordering.is_eq() {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn validate_rule_run_joins(
    rules: &[PolicyRuleDescriptor],
    runs: &[PolicyRun],
) -> Result<(), PolicyReportDocumentError> {
    for pair in rules.windows(2) {
        if pair[0].policy_id() == pair[1].policy_id()
            && pair[0].policy_hash() != pair[1].policy_hash()
        {
            return Err(PolicyReportDocumentError::DuplicatePolicyId {
                policy_id: pair[0].policy_id().clone(),
            });
        }
        if compare_rule_descriptors(&pair[0], &pair[1]).is_eq() {
            return Err(PolicyReportDocumentError::AmbiguousRuleJoin {
                policy_id: pair[0].policy_id().clone(),
                policy_hash: pair[0].policy_hash(),
            });
        }
    }
    for pair in runs.windows(2) {
        if pair[0].policy_id() == pair[1].policy_id()
            && pair[0].policy_hash() != pair[1].policy_hash()
        {
            return Err(PolicyReportDocumentError::DuplicatePolicyId {
                policy_id: pair[0].policy_id().clone(),
            });
        }
        if compare_policy_runs(&pair[0], &pair[1]).is_eq() {
            return Err(PolicyReportDocumentError::AmbiguousRunJoin {
                policy_id: pair[0].policy_id().clone(),
                policy_hash: pair[0].policy_hash(),
            });
        }
    }
    let mut rule_index = 0;
    let mut run_index = 0;
    while rule_index < rules.len() || run_index < runs.len() {
        match (rules.get(rule_index), runs.get(run_index)) {
            (Some(rule), Some(run)) => match (rule.policy_id().as_str(), rule.policy_hash())
                .cmp(&(run.policy_id().as_str(), run.policy_hash()))
            {
                std::cmp::Ordering::Less => {
                    return Err(PolicyReportDocumentError::MissingRun {
                        policy_id: rule.policy_id().clone(),
                        policy_hash: rule.policy_hash(),
                    });
                }
                std::cmp::Ordering::Greater => {
                    return Err(PolicyReportDocumentError::MissingRule {
                        policy_id: run.policy_id().clone(),
                        policy_hash: run.policy_hash(),
                    });
                }
                std::cmp::Ordering::Equal => {
                    if rule.analysis_type() != run.analysis_type() {
                        return Err(PolicyReportDocumentError::AnalysisTypeMismatch {
                            policy_id: rule.policy_id().clone(),
                            policy_hash: rule.policy_hash(),
                            rule_analysis_type: rule.analysis_type(),
                            run_analysis_type: run.analysis_type(),
                        });
                    }
                    rule_index += 1;
                    run_index += 1;
                }
            },
            (Some(rule), None) => {
                return Err(PolicyReportDocumentError::MissingRun {
                    policy_id: rule.policy_id().clone(),
                    policy_hash: rule.policy_hash(),
                });
            }
            (None, Some(run)) => {
                return Err(PolicyReportDocumentError::MissingRule {
                    policy_id: run.policy_id().clone(),
                    policy_hash: run.policy_hash(),
                });
            }
            (None, None) => break,
        }
    }
    Ok(())
}

fn validate_suppression_joins(
    runs: &[PolicyRun],
    suppressions: &[PolicySuppressionReview],
) -> Result<(), PolicyReportDocumentError> {
    for pair in suppressions.windows(2) {
        if compare_suppression_reviews(&pair[0], &pair[1]).is_eq() {
            return Err(PolicyReportDocumentError::DuplicateSuppressionReview {
                policy_id: pair[0].policy_id().clone(),
                finding_id: pair[0].finding_id(),
            });
        }
    }

    for review in suppressions {
        if review.applied() && !review.result_omitted() {
            let retained = runs
                .iter()
                .find(|run| run.policy_id() == review.policy_id())
                .and_then(|run| {
                    run.findings()
                        .iter()
                        .find(|finding| finding.id() == review.finding_id())
                });
            if retained.and_then(PolicyFinding::suppression).is_none() {
                return Err(PolicyReportDocumentError::MissingSuppressedFinding {
                    policy_id: review.policy_id().clone(),
                    finding_id: review.finding_id(),
                });
            }
        }
    }

    for finding in runs.iter().flat_map(PolicyRun::findings) {
        if finding.suppression().is_some()
            && !suppressions.iter().any(|review| {
                review.policy_id() == finding.policy_id()
                    && review.finding_id() == finding.id()
                    && review.applied()
                    && !review.result_omitted()
            })
        {
            return Err(PolicyReportDocumentError::SuppressedFindingWithoutReview {
                policy_id: finding.policy_id().clone(),
                finding_id: finding.id(),
            });
        }
    }
    Ok(())
}

/// A classifying (non-degraded) diff review and per-finding diff decisions
/// exist exactly together: every retained finding carries a decision when the
/// review classified the report, and none does otherwise.
fn validate_diff_joins(
    runs: &[PolicyRun],
    diff: Option<&PolicyDiffReview>,
) -> Result<(), PolicyReportDocumentError> {
    let classifying = diff.is_some_and(|review| !review.degraded());
    for finding in runs.iter().flat_map(PolicyRun::findings) {
        match (classifying, finding.diff()) {
            (true, None) => {
                return Err(PolicyReportDocumentError::MissingDiffFindingDecision {
                    policy_id: finding.policy_id().clone(),
                    finding_id: finding.id(),
                });
            }
            (false, Some(_)) => {
                return Err(PolicyReportDocumentError::DiffFindingWithoutReview {
                    policy_id: finding.policy_id().clone(),
                    finding_id: finding.id(),
                });
            }
            (true, Some(_)) | (false, None) => {}
        }
    }
    Ok(())
}

/// A baseline review and per-finding baseline decisions exist exactly
/// together: without the review no finding carries a decision, and with it the
/// retained decision count equals the applied entries minus omitted results.
fn validate_baseline_joins(
    runs: &[PolicyRun],
    baseline: Option<&PolicyBaselineReview>,
) -> Result<(), PolicyReportDocumentError> {
    let mut attached = 0_u64;
    for finding in runs.iter().flat_map(PolicyRun::findings) {
        if finding.baseline().is_none() {
            continue;
        }
        if baseline.is_none() {
            return Err(PolicyReportDocumentError::BaselineFindingWithoutReview {
                policy_id: finding.policy_id().clone(),
                finding_id: finding.id(),
            });
        }
        attached = attached.saturating_add(1);
    }
    if let Some(review) = baseline
        && attached
            != review
                .applied_count()
                .saturating_sub(review.result_omitted_count())
    {
        return Err(PolicyReportDocumentError::BaselineAppliedJoinMismatch {
            attached,
            applied_count: review.applied_count(),
            result_omitted_count: review.result_omitted_count(),
        });
    }
    Ok(())
}

fn validate_scope_joins(
    runs: &[PolicyRun],
    scope: &[PolicyScopeReview],
) -> Result<(), PolicyReportDocumentError> {
    for finding in runs.iter().flat_map(PolicyRun::findings) {
        if let Some(finding_scope) = finding.scope() {
            let covered = scope
                .iter()
                .any(|review| review.applied() && review.covers(finding_scope));
            if !covered {
                return Err(PolicyReportDocumentError::ScopedFindingWithoutReview {
                    policy_id: finding.policy_id().clone(),
                    finding_id: finding.id(),
                });
            }
        }
    }
    Ok(())
}

fn report_storage_size(
    evaluation: &PolicyReportEvaluationContext,
    rules: &Vec<PolicyRuleDescriptor>,
    runs: &Vec<PolicyRun>,
    suppressions: &Vec<PolicySuppressionReview>,
    scope: &Vec<PolicyScopeReview>,
    diagnostics: &Vec<PolicyReportDiagnostic>,
) -> usize {
    size_of::<PolicyReportDocument>()
        .saturating_add(retained_extra(evaluation))
        .saturating_add(
            retained_vec_size_from_parts(rules, rules.capacity())
                .saturating_sub(size_of::<Vec<PolicyRuleDescriptor>>()),
        )
        .saturating_add(
            retained_vec_size_from_parts(runs, runs.capacity())
                .saturating_sub(size_of::<Vec<PolicyRun>>()),
        )
        .saturating_add(
            retained_vec_size_from_parts(suppressions, suppressions.capacity())
                .saturating_sub(size_of::<Vec<PolicySuppressionReview>>()),
        )
        .saturating_add(
            retained_vec_size_from_parts(scope, scope.capacity())
                .saturating_sub(size_of::<Vec<PolicyScopeReview>>()),
        )
        .saturating_add(
            retained_vec_size_from_parts(diagnostics, diagnostics.capacity())
                .saturating_sub(size_of::<Vec<PolicyReportDiagnostic>>()),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::PolicyEvaluationOptions;
    use crate::definition::{PolicyAnalysis, PolicySelector, RqlpDocument};
    use crate::finding::{
        FindingCertainty, FindingCompleteness, FindingIncompleteReason, MatchFindingEvidence,
        PolicyByteSpan, PolicyCapability, PolicyDiagnosticCode, PolicyDiagnosticImpact,
        PolicyDisplayRegion, PolicyFailureReason, PolicyFindingEvidence, PolicyQueryProof,
        PolicyQueryProvenance, PolicyQueryResultRef, PolicySourceLocation, PolicyWorkReport,
        ProofMetadata, ProofReason, ProofState,
    };
    use crate::finding_identity::{
        MatchFindingAnchor, MatchResultDomain, OpaqueFindingKey, SourceSliceHash,
    };
    use crate::resolved::{ResolvedPolicySelector, SelectorOrigin};
    use crate::source::parse_rqlp_source;
    use crate::suppression::{
        PolicyEvaluationDate, PolicySuppressionDocumentState, PolicySuppressionMatchState,
        PolicySuppressionOrphanState, PolicySuppressionPolicyHashState,
        PolicySuppressionTemporalState, parse_policy_suppression_document,
    };
    use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
    use serde_json::json;

    fn loaded_match_policy() -> LoadedPolicy {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/policies/dynamic-eval.rqlp"
        ));
        loaded_match_policy_from_source(source)
    }

    fn loaded_match_policy_from_source(source: &str) -> LoadedPolicy {
        let identity = PolicySourceIdentity::new("policy.rqlp");
        let parsed = parse_rqlp_source(source, identity.clone()).unwrap();
        let schema_resolution = parsed.schema_resolution();
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
            SelectorOrigin::Document {
                source: identity.clone(),
            },
        )
        .unwrap();
        LoadedPolicy::try_new(
            definition,
            identity,
            source.as_bytes(),
            schema_resolution,
            vec![selector],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PolicyPrecedenceManifest::default(),
            None,
            None,
        )
        .unwrap()
    }

    fn report_skeleton() -> (PolicyRuleDescriptor, PolicyRun) {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let run = report_run(
            &loaded,
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
        );
        (descriptor, run)
    }

    fn report_run(
        loaded: &LoadedPolicy,
        analysis_type: PolicyAnalysisType,
        completion: PolicyRunCompletion,
    ) -> PolicyRun {
        PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            analysis_type,
            completion,
            Vec::new(),
            Vec::new(),
            false,
            super::super::finding::PolicyWorkReport::default(),
            &super::super::budget::PolicyBudget::default(),
        )
        .unwrap()
    }

    fn report_finding_with_anchor(
        loaded: &LoadedPolicy,
        anchor: MatchFindingAnchor,
        completeness: FindingCompleteness,
    ) -> PolicyFinding {
        report_finding_with_anchor_and_provenance(loaded, anchor, completeness, Vec::new())
    }

    fn report_finding_with_anchor_and_provenance(
        loaded: &LoadedPolicy,
        anchor: MatchFindingAnchor,
        completeness: FindingCompleteness,
        provenance: Vec<PolicyQueryProvenance>,
    ) -> PolicyFinding {
        let path = WorkspaceRelativePath::new("src/app.rs").unwrap();
        PolicyFinding::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            super::super::definition::FindingSeverity::Warning,
            "finding".to_string(),
            super::super::classification::FindingClassification::Unclassified,
            FindingCertainty::Definite,
            completeness,
            PolicySourceLocation::span(
                path,
                PolicyByteSpan::new(0, 1).unwrap(),
                PolicyDisplayRegion::new(1, 1, 1, 2).unwrap(),
            ),
            Vec::new(),
            false,
            0,
            PolicyFindingEvidence::Match {
                evidence: MatchFindingEvidence::try_new(
                    MatchResultDomain::CallSite,
                    anchor,
                    PolicyQueryResultRef::CallSite {
                        location: PolicySourceLocation::span(
                            WorkspaceRelativePath::new("src/app.rs").unwrap(),
                            PolicyByteSpan::new(0, 1).unwrap(),
                            PolicyDisplayRegion::new(1, 1, 1, 2).unwrap(),
                        ),
                        caller_fq_name: "crate::caller".to_string(),
                        caller_identity: None,
                        callee_fq_name: "crate::callee".to_string(),
                        callee_identity: None,
                        proof: PolicyQueryProof::Exact,
                    },
                    provenance,
                    false,
                )
                .unwrap(),
            },
            false,
            0,
            None,
            None,
            ProofMetadata::try_new(
                ProofState::Proven,
                vec![ProofReason::DirectStructuralMatch],
                Vec::new(),
            )
            .unwrap(),
            Vec::new(),
            false,
            0,
            &super::super::budget::PolicyBudget::default(),
        )
        .unwrap()
    }

    fn report_finding(loaded: &LoadedPolicy) -> PolicyFinding {
        let path = WorkspaceRelativePath::new("src/app.rs").unwrap();
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path,
            None,
            Some(SourceSliceHash::from_bytes([4; 32])),
            0,
        )
        .unwrap();
        report_finding_with_anchor(loaded, anchor, FindingCompleteness::Complete)
    }

    fn weak_report_finding(loaded: &LoadedPolicy) -> PolicyFinding {
        let path = WorkspaceRelativePath::new("src/app.rs").unwrap();
        let anchor = MatchFindingAnchor::weak(
            MatchResultDomain::CallSite,
            path,
            OpaqueFindingKey::try_new("test", "weak-finding").unwrap(),
        );
        report_finding_with_anchor(
            loaded,
            anchor,
            FindingCompleteness::partial(vec![FindingIncompleteReason::StableAnchorWeak]).unwrap(),
        )
    }

    #[test]
    fn report_diagnostic_codes_use_the_fixed_kebab_case_wire() {
        assert_eq!(
            serde_json::to_value(PolicyReportDiagnosticCode::UnsupportedPolicySchemaVersion)
                .unwrap(),
            json!("unsupported-policy-schema-version")
        );
        assert_eq!(
            serde_json::to_value(PolicyReportDiagnosticCode::ExplicitRqlSchemaVersionRequired)
                .unwrap(),
            json!("explicit-rql-schema-version-required")
        );
        assert_eq!(
            serde_json::to_value(PolicyReportDiagnosticCode::WorkspaceSnapshotDeadlineExceeded)
                .unwrap(),
            json!("workspace-snapshot-deadline-exceeded")
        );
        assert_eq!(
            serde_json::to_value(PolicyReportDiagnosticCode::PacksLoadFailed).unwrap(),
            json!("packs-load-failed")
        );
        assert_eq!(
            serde_json::to_value(PolicyReportDiagnosticCode::PackActivationFailed).unwrap(),
            json!("pack-activation-failed")
        );
        assert_eq!(
            serde_json::to_value(PolicyReportDiagnosticCode::WorkspaceModelLoadFailed).unwrap(),
            json!("workspace-model-load-failed")
        );
        assert_eq!(
            serde_json::to_value(PolicyReportDiagnosticCode::WorkspaceModelInert).unwrap(),
            json!("workspace-model-inert")
        );
    }

    #[test]
    fn report_diagnostic_normalizes_related_and_requires_source_for_range() {
        assert!(matches!(
            PolicyReportDiagnostic::try_new(
                PolicyReportDiagnosticCode::PolicyLoadFailed,
                PolicyDiagnosticSeverity::Error,
                "failed",
                None,
                Some(PolicySourceRange::new(0, 1).unwrap()),
                Vec::new(),
            ),
            Err(PolicyReportValueError::RangeWithoutSource)
        ));

        let related = PolicySourceRelatedDiagnostic {
            source: PolicySourceIdentity::new("policy.rqlp"),
            range: 2..4,
            message: "detail".to_string(),
        };
        let diagnostic = PolicyReportDiagnostic::try_new(
            PolicyReportDiagnosticCode::PolicyValidationFailed,
            PolicyDiagnosticSeverity::Error,
            "invalid policy",
            Some(PolicySourceIdentity::new("policy.rqlp")),
            Some(PolicySourceRange::new(0, 1).unwrap()),
            vec![related.clone(), related],
        )
        .unwrap();
        assert_eq!(diagnostic.related().len(), 1);
    }

    #[test]
    fn raw_document_assembly_rejects_missing_rule_run_joins() {
        let (descriptor, run) = report_skeleton();
        let error = PolicyReportDocument::try_new(
            vec![descriptor.clone()],
            Vec::new(),
            Vec::new(),
            false,
            0,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyReportDocumentError::MissingRun { .. }
        ));

        let error =
            PolicyReportDocument::try_new(Vec::new(), vec![run], Vec::new(), false, 0, None)
                .unwrap_err();
        assert!(matches!(
            error,
            PolicyReportDocumentError::MissingRule { .. }
        ));
    }

    #[test]
    fn rule_run_joins_reject_an_analysis_type_forged_under_a_real_policy_hash() {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let mismatched_run = report_run(
            &loaded,
            PolicyAnalysisType::Taint,
            PolicyRunCompletion::Complete,
        );

        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        assert!(matches!(
            builder.register_policy(descriptor.clone(), mismatched_run.clone()),
            Err(PolicyReportBuilderError::RuleRunJoinMismatch)
        ));

        let error = PolicyReportDocument::try_new(
            vec![descriptor],
            vec![mismatched_run],
            Vec::new(),
            false,
            0,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyReportDocumentError::AnalysisTypeMismatch {
                rule_analysis_type: PolicyAnalysisType::Match,
                run_analysis_type: PolicyAnalysisType::Taint,
                ..
            }
        ));
    }

    #[test]
    fn canonical_reports_reject_duplicate_policy_ids_even_when_hashes_differ() {
        let first = loaded_match_policy();
        let changed_source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/policies/dynamic-eval.rqlp"
        ))
        .replace(
            "Dynamic evaluation is forbidden",
            "Dynamic evaluation remains forbidden",
        );
        let second = loaded_match_policy_from_source(&changed_source);
        assert_eq!(
            first.definition().metadata.id,
            second.definition().metadata.id
        );
        assert_ne!(first.semantic_hash(), second.semantic_hash());

        let first_descriptor = PolicyRuleDescriptor::from_loaded(&first);
        let second_descriptor = PolicyRuleDescriptor::from_loaded(&second);
        let first_run = report_run(
            &first,
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
        );
        let second_run = report_run(
            &second,
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
        );

        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
        builder
            .register_policy(first_descriptor.clone(), first_run.clone())
            .unwrap();
        assert!(matches!(
            builder.register_policy(second_descriptor.clone(), second_run.clone()),
            Err(PolicyReportBuilderError::DuplicatePolicyId { policy_id })
                if policy_id.as_str() == first.definition().metadata.id.as_str()
        ));

        let error = PolicyReportDocument::try_new(
            vec![first_descriptor, second_descriptor],
            vec![first_run, second_run],
            Vec::new(),
            false,
            0,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyReportDocumentError::DuplicatePolicyId { policy_id }
                if policy_id.as_str() == first.definition().metadata.id.as_str()
        ));
    }

    #[test]
    fn builder_preflights_skeletons_and_emits_schema_five_document() {
        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(1024)
            .unwrap()
            .build()
            .unwrap();
        let tiny = PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(1024)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        assert!(matches!(
            PolicyReportBuilder::new(tiny, 1),
            Err(PolicyReportBuilderError::SkeletonPreflightExceeded { .. })
        ));

        let (descriptor, run) = report_skeleton();
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();
        let document = builder.finish().unwrap();
        assert_eq!(document.schema_version(), 5);
        assert_eq!(document.rules().len(), 1);
        assert_eq!(document.runs().len(), 1);
        assert_eq!(
            document.rules()[0].analysis_type(),
            PolicyAnalysisType::Match
        );
        assert_eq!(
            serde_json::to_value(&document).unwrap()["schema_version"],
            5
        );
        assert_eq!(
            serde_json::to_value(&document).unwrap()["rules"][0]["analysis_type"],
            "match"
        );
    }

    #[test]
    fn schema_five_report_exposes_bounded_deadline_execution_metadata() {
        let first = PolicyId::new("test.first").unwrap();
        let second = PolicyId::new("test.second").unwrap();
        let execution = PolicyExecutionMetadata::try_new(
            5_000,
            vec![
                PolicyStageTiming::new(PolicyExecutionStage::WorkspaceSnapshot, 4_990),
                PolicyStageTiming::new(PolicyExecutionStage::PolicySelection, 10),
            ],
            Some(PolicyExecutionTermination::DeadlineExceeded),
            Some(PolicyExecutionStage::WorkspaceSnapshot),
            None,
            Vec::new(),
            vec![second.clone(), first.clone()],
        )
        .unwrap();
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 0).unwrap();
        builder.set_execution(execution).unwrap();
        let document = builder.finish().unwrap();

        let json = serde_json::to_value(&document).unwrap();
        assert_eq!(json["schema_version"], 5);
        assert_eq!(json["execution"]["termination"], "deadline_exceeded");
        assert_eq!(json["execution"]["terminal_stage"], "workspace_snapshot");
        assert_eq!(
            json["execution"]["stage_timings"][0]["stage"],
            "policy_selection"
        );
        assert_eq!(
            json["execution"]["pending_policy_ids"],
            serde_json::json!([first.as_str(), second.as_str()])
        );
        assert!(document.rules().is_empty());
        assert!(document.runs().is_empty());
    }

    #[test]
    fn execution_metadata_rejects_ambiguous_progress_and_stage_timings() {
        let policy_id = PolicyId::new("test.duplicate").unwrap();
        assert_eq!(
            PolicyExecutionMetadata::try_new(
                1,
                vec![
                    PolicyStageTiming::new(PolicyExecutionStage::PolicySelection, 1),
                    PolicyStageTiming::new(PolicyExecutionStage::PolicySelection, 1),
                ],
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
            ),
            Err(PolicyExecutionMetadataError::DuplicateStageTiming)
        );
        assert_eq!(
            PolicyExecutionMetadata::try_new(
                1,
                Vec::new(),
                Some(PolicyExecutionTermination::DeadlineExceeded),
                Some(PolicyExecutionStage::PolicyEvaluation),
                Some(policy_id.clone()),
                vec![policy_id],
                Vec::new(),
            ),
            Err(PolicyExecutionMetadataError::OverlappingPolicyProgress)
        );
    }

    #[test]
    fn execution_metadata_reservation_covers_maximum_policy_progress() {
        let pending = (0..MAX_POLICY_EXECUTION_PROGRESS_IDS)
            .map(|index| {
                PolicyId::new(format!("test.policy{index:03}.{}", "x".repeat(180))).unwrap()
            })
            .collect::<Vec<_>>();
        let execution = PolicyExecutionMetadata::try_new(
            6,
            vec![
                PolicyStageTiming::new(PolicyExecutionStage::PolicySelection, 1),
                PolicyStageTiming::new(PolicyExecutionStage::WorkspaceSnapshot, 1),
                PolicyStageTiming::new(PolicyExecutionStage::PolicyRegistration, 1),
                PolicyStageTiming::new(PolicyExecutionStage::PolicyPreparation, 1),
                PolicyStageTiming::new(PolicyExecutionStage::PolicyEvaluation, 1),
                PolicyStageTiming::new(PolicyExecutionStage::ReportConstruction, 1),
            ],
            Some(PolicyExecutionTermination::DeadlineExceeded),
            Some(PolicyExecutionStage::PolicyEvaluation),
            None,
            Vec::new(),
            pending,
        )
        .unwrap();

        assert!(
            execution.retained_size()
                <= PolicyExecutionMetadata::maximum_retained_size(
                    MAX_POLICY_EXECUTION_PROGRESS_IDS
                )
        );
    }

    #[test]
    fn builder_distinguishes_suppression_audit_preflight_exhaustion() {
        let finding_id = "1".repeat(64);
        let source = format!(
            r#"{{
                "schema_version": 1,
                "suppressions": [{{
                    "policy_id": "test.dynamic-eval",
                    "finding_id": "{finding_id}",
                    "identity_stability": "strong",
                    "status": "accepted",
                    "reason": "Reviewed compatibility boundary",
                    "accepted_at": "2026-07-01"
                }}]
            }}"#
        );
        let document = parse_policy_suppression_document(&source).unwrap();
        let review = PolicySuppressionReview::new(
            &document.suppressions()[0],
            PolicySuppressionMatchState::StrongFinding,
            PolicySuppressionTemporalState::Current,
            PolicySuppressionPolicyHashState::Unknown,
            PolicySuppressionOrphanState::Resolved,
            Vec::new(),
        );
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date"),
        );
        let evaluation = PolicyReportEvaluationContext::new(
            options.evaluation_date(),
            options
                .suppressions()
                .source_states(PolicySuppressionDocumentState::Loaded),
            options.scope(),
            super::super::scope::PolicyScopeDocumentState::NotFound,
        );
        let rules = Vec::new();
        let runs = Vec::new();
        let suppressions = vec![review.clone()];
        let scope = Vec::new();
        let diagnostics = Vec::new();
        let without_audit = report_storage_size(
            &evaluation,
            &rules,
            &runs,
            &Vec::new(),
            &scope,
            &diagnostics,
        )
        .checked_add(PolicyExecutionMetadata::maximum_retained_size(0))
        .unwrap()
        .checked_add(EMERGENCY_DIAGNOSTIC_ALLOWANCE)
        .unwrap();
        let with_audit = report_storage_size(
            &evaluation,
            &rules,
            &runs,
            &suppressions,
            &scope,
            &diagnostics,
        )
        .checked_add(PolicyExecutionMetadata::maximum_retained_size(0))
        .unwrap()
        .checked_add(EMERGENCY_DIAGNOSTIC_ALLOWANCE)
        .unwrap();
        assert!(with_audit > without_audit);

        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(without_audit)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(without_audit)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        assert!(matches!(
            PolicyReportBuilder::new_with_suppression_audit(
                budget,
                0,
                evaluation,
                vec![review],
                Vec::new(),
            ),
            Err(PolicyReportBuilderError::SuppressionAuditPreflightExceeded {
                required_bytes,
                max_bytes,
            }) if required_bytes == with_audit && max_bytes == without_audit
        ));
    }

    #[test]
    fn identical_failed_inputs_keep_one_primary_outcome_each() {
        let diagnostic = PolicyReportDiagnostic::try_new(
            PolicyReportDiagnosticCode::PolicyLoadFailed,
            PolicyDiagnosticSeverity::Error,
            "failed",
            Some(PolicySourceIdentity::new("same.rqlp")),
            None,
            Vec::new(),
        )
        .unwrap();
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
        builder
            .register_primary_diagnostic(diagnostic.clone())
            .unwrap();
        builder.register_primary_diagnostic(diagnostic).unwrap();
        let document = builder.finish().unwrap();
        assert_eq!(document.diagnostics().len(), 2);
    }

    #[test]
    fn exact_per_policy_reason_reservation_allows_first_finding_omission() {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let run = PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            super::super::definition::PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
            Vec::new(),
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            &super::super::budget::PolicyBudget::default(),
        )
        .unwrap();
        let per_policy_limit = descriptor
            .retained_size()
            .saturating_add(run.retained_size())
            .saturating_add(PER_POLICY_INCOMPLETE_REASON_ALLOWANCE);
        let too_small_per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(per_policy_limit - 1)
            .unwrap()
            .build()
            .unwrap();
        let too_small_budget = PolicyBatchBudget::builder()
            .with_per_policy(too_small_per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut too_small_builder = PolicyReportBuilder::new(too_small_budget, 1).unwrap();
        assert!(matches!(
            too_small_builder.register_policy(descriptor.clone(), run.clone()),
            Err(PolicyReportBuilderError::PolicySkeletonExceeded {
                retained_bytes,
                max_bytes,
            }) if retained_bytes == per_policy_limit && max_bytes == per_policy_limit - 1
        ));

        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(per_policy_limit)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();
        assert_eq!(
            builder.retain_finding(report_finding(&loaded)).unwrap(),
            PolicyRetentionOutcome::Omitted {
                reason: PolicyIncompleteReason::ReportRetentionBudget
            }
        );
        let document = builder.finish().unwrap();
        let run = &document.runs()[0];
        assert!(run.findings().is_empty());
        assert_eq!(run.work().omitted_findings_lower_bound(), 1);
        assert!(matches!(
            run.completion(),
            PolicyRunCompletion::Inconclusive { reasons }
                if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget)
        ));
    }

    #[test]
    fn retaining_weak_finding_marks_complete_run_inconclusive() {
        let loaded = loaded_match_policy();
        let (descriptor, run) = report_skeleton();
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();

        assert_eq!(
            builder
                .retain_finding(weak_report_finding(&loaded))
                .unwrap(),
            PolicyRetentionOutcome::Retained
        );
        let document = builder.finish().unwrap();
        let run = &document.runs()[0];
        assert_eq!(run.findings().len(), 1);
        assert_eq!(
            run.findings()[0].identity_stability(),
            FindingIdentityStability::Weak
        );
        assert!(matches!(
            run.completion(),
            PolicyRunCompletion::Inconclusive { reasons }
                if reasons == &[PolicyIncompleteReason::StableAnchorUnavailable]
        ));
    }

    #[test]
    fn weak_findings_are_rejected_from_terminal_failure_runs_but_strong_findings_survive() {
        let loaded = loaded_match_policy();
        let completions = [
            PolicyRunCompletion::Unsupported {
                capability: PolicyCapability::query_feature(
                    "typescript",
                    "query.unsupported-feature",
                )
                .unwrap(),
            },
            PolicyRunCompletion::failed(vec![PolicyFailureReason::InternalInvariant]).unwrap(),
        ];

        for completion in completions {
            let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
            let run = report_run(&loaded, PolicyAnalysisType::Match, completion.clone());
            let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
            builder.register_policy(descriptor, run).unwrap();

            assert!(matches!(
                builder.retain_finding(weak_report_finding(&loaded)),
                Err(PolicyReportBuilderError::WeakFindingCompletionMismatch)
            ));
            assert_eq!(
                builder.retain_finding(report_finding(&loaded)).unwrap(),
                PolicyRetentionOutcome::Retained
            );

            let document = builder.finish().unwrap();
            assert_eq!(document.runs()[0].completion(), &completion);
            assert_eq!(document.runs()[0].findings().len(), 1);
            assert_eq!(
                document.runs()[0].findings()[0].identity_stability(),
                FindingIdentityStability::Strong
            );
        }
    }

    #[test]
    fn baseline_decisions_require_their_review_at_document_assembly() {
        use super::super::baseline::{PolicyFindingBaseline, parse_policy_baseline_document};
        use super::super::suppression::PolicySuppressionPolicyHashState;

        let loaded = loaded_match_policy();
        let baseline_document = parse_policy_baseline_document(
            &json!({
                "schema_version": 1,
                "reason": "Onboarding acceptance",
                "accepted_at": "2026-08-08",
                "policies": [],
            })
            .to_string(),
        )
        .unwrap();
        let mut finding = report_finding(&loaded);
        finding
            .attach_baseline(PolicyFindingBaseline::new(
                &baseline_document,
                PolicySuppressionPolicyHashState::Matching,
            ))
            .unwrap();

        // A finding carrying a baseline decision without a top-level review
        // is rejected at assembly.
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        builder
            .register_policy(
                PolicyRuleDescriptor::from_loaded(&loaded),
                report_run(
                    &loaded,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::Complete,
                ),
            )
            .unwrap();
        builder.retain_finding(finding.clone()).unwrap();
        assert!(matches!(
            builder.finish(),
            Err(PolicyReportBuilderError::Document(
                PolicyReportDocumentError::BaselineFindingWithoutReview { .. }
            ))
        ));

        // Clearing the decision restores the invariant.
        finding.clear_baseline();
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        builder
            .register_policy(
                PolicyRuleDescriptor::from_loaded(&loaded),
                report_run(
                    &loaded,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::Complete,
                ),
            )
            .unwrap();
        builder.retain_finding(finding).unwrap();
        builder.finish().unwrap();
    }

    #[test]
    fn baseline_generation_excludes_weak_identities_with_an_exact_count() {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let run = report_run(
            &loaded,
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
        );
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();
        let strong = report_finding(&loaded);
        let strong_id = strong.id();
        builder.retain_finding(strong).unwrap();
        builder
            .retain_finding(weak_report_finding(&loaded))
            .unwrap();
        let document = builder.finish().unwrap();

        let (baseline, weak_excluded) =
            super::super::baseline::PolicyBaselineDocument::from_completed_report(
                &document,
                "Onboarding acceptance",
                None,
                super::super::suppression::PolicyEvaluationDate::from_ymd(2026, 8, 8).unwrap(),
            )
            .unwrap();
        assert_eq!(weak_excluded, 1);
        assert_eq!(baseline.entry_count(), 1);
        assert_eq!(baseline.policies()[0].finding_ids(), [strong_id]);
        assert_eq!(
            baseline.policies()[0]
                .policy_hash_at_acceptance()
                .unwrap()
                .as_bytes(),
            loaded.semantic_hash().as_bytes(),
        );
    }

    #[test]
    fn secondary_diagnostic_omission_tracks_count_and_worst_severity() {
        // Large enough for the skeleton, small enough that one full-width
        // diagnostic does not fit: the omission is what this test is about.
        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(6_000)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(6_000)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 0).unwrap();
        for severity in [
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticSeverity::Error,
        ] {
            let diagnostic = PolicyReportDiagnostic::try_new(
                PolicyReportDiagnosticCode::PolicyLoadFailed,
                severity,
                "x".repeat(MAX_REPORT_TEXT_BYTES),
                Some(PolicySourceIdentity::new("secondary.rqlp")),
                None,
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                builder.retain_report_diagnostic(diagnostic).unwrap(),
                PolicyRetentionOutcome::DiagnosticOmitted
            );
        }
        let document = builder.finish().unwrap();
        assert!(document.diagnostics_truncated());
        assert_eq!(document.omitted_diagnostics_lower_bound(), 2);
        assert_eq!(
            document.worst_omitted_diagnostic_severity(),
            Some(PolicyDiagnosticSeverity::Error)
        );
    }

    #[test]
    fn builder_revalidates_run_skeleton_against_its_lower_per_policy_budget() {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let diagnostic = PolicyDiagnostic::try_new(
            PolicyDiagnosticCode::StableAnchorUnavailable,
            PolicyDiagnosticSeverity::Note,
            PolicyDiagnosticImpact::Advisory,
            "advisory",
            None,
            Vec::new(),
        )
        .unwrap();
        let run = PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            super::super::definition::PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
            Vec::new(),
            vec![diagnostic],
            false,
            PolicyWorkReport::default(),
            &super::super::budget::PolicyBudget::default(),
        )
        .unwrap();
        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_diagnostics(0)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();

        assert!(matches!(
            builder.register_policy(descriptor, run),
            Err(PolicyReportBuilderError::RunBudgetViolation(
                PolicyRunError::TooManyDiagnostics { max: 0 }
            ))
        ));
    }

    #[test]
    fn builder_omits_a_finding_that_exceeds_its_lower_nested_budget() {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let run = PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            super::super::definition::PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
            Vec::new(),
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            &super::super::budget::PolicyBudget::default(),
        )
        .unwrap();
        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_evidence_bytes_per_finding(0)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();

        assert_eq!(
            builder.retain_finding(report_finding(&loaded)).unwrap(),
            PolicyRetentionOutcome::Omitted {
                reason: PolicyIncompleteReason::ReportRetentionBudget,
            }
        );
        let document = builder.finish().unwrap();
        let run = &document.runs()[0];
        assert!(run.findings().is_empty());
        assert_eq!(run.work().omitted_findings_lower_bound(), 1);
        assert!(matches!(
            run.completion(),
            PolicyRunCompletion::Inconclusive { reasons }
                if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget)
        ));
    }

    #[test]
    fn an_over_budget_duplicate_finding_does_not_increment_the_omission_count() {
        let loaded = loaded_match_policy();
        let path = WorkspaceRelativePath::new("src/app.rs").unwrap();
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path.clone(),
            None,
            Some(SourceSliceHash::from_bytes([4; 32])),
            0,
        )
        .unwrap();
        let retained =
            report_finding_with_anchor(&loaded, anchor.clone(), FindingCompleteness::Complete);
        let larger_duplicate = report_finding_with_anchor_and_provenance(
            &loaded,
            anchor,
            FindingCompleteness::Complete,
            vec![
                PolicyQueryProvenance::try_new(
                    Vec::new(),
                    PolicyQueryResultRef::file(path),
                    Vec::new(),
                )
                .unwrap(),
            ],
        );
        assert_eq!(retained.id(), larger_duplicate.id());

        let retained_evidence_bytes = retained
            .evidence()
            .retained_size()
            .saturating_add(retained.classification().retained_size())
            .saturating_add(retained.proof().retained_size());
        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_evidence_bytes_per_finding(retained_evidence_bytes)
            .unwrap()
            .build()
            .unwrap();
        assert!(retained.validate_against_budget(&per_policy).is_ok());
        assert!(matches!(
            larger_duplicate.validate_against_budget(&per_policy),
            Err(error) if error.is_budget_limit_exceeded()
        ));

        let budget = PolicyBatchBudget::builder()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let run = report_run(
            &loaded,
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
        );
        let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();
        assert_eq!(
            builder.retain_finding(retained).unwrap(),
            PolicyRetentionOutcome::Retained
        );
        assert!(matches!(
            builder.retain_finding(larger_duplicate),
            Err(PolicyReportBuilderError::DuplicateFindingId)
        ));

        let document = builder.finish().unwrap();
        let run = &document.runs()[0];
        assert_eq!(run.findings().len(), 1);
        assert_eq!(run.work().omitted_findings_lower_bound(), 0);
        assert!(matches!(run.completion(), PolicyRunCompletion::Complete));
    }

    #[test]
    fn retaining_an_identical_diagnostic_at_cap_is_a_no_growth_success() {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let diagnostic = PolicyDiagnostic::try_new(
            PolicyDiagnosticCode::StableAnchorUnavailable,
            PolicyDiagnosticSeverity::Note,
            PolicyDiagnosticImpact::Advisory,
            "advisory",
            None,
            Vec::new(),
        )
        .unwrap();
        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_diagnostics(1)
            .unwrap()
            .build()
            .unwrap();
        let run = PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
            Vec::new(),
            vec![diagnostic.clone()],
            false,
            PolicyWorkReport::default(),
            &per_policy,
        )
        .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();

        assert_eq!(
            builder
                .retain_run_diagnostic(
                    &loaded.definition().metadata.id,
                    loaded.semantic_hash(),
                    diagnostic,
                )
                .unwrap(),
            PolicyRetentionOutcome::Retained
        );
        let document = builder.finish().unwrap();
        let run = &document.runs()[0];
        assert_eq!(run.diagnostics().len(), 1);
        assert!(!run.diagnostics_truncated());
        assert!(matches!(run.completion(), PolicyRunCompletion::Complete));
    }

    #[test]
    fn retaining_a_diagnostic_never_clears_prior_run_truncation() {
        let loaded = loaded_match_policy();
        let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
        let run = PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            super::super::definition::PolicyAnalysisType::Match,
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::ReportRetentionBudget])
                .unwrap(),
            Vec::new(),
            Vec::new(),
            true,
            PolicyWorkReport::default(),
            &super::super::budget::PolicyBudget::default(),
        )
        .unwrap();
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        builder.register_policy(descriptor, run).unwrap();
        let diagnostic = PolicyDiagnostic::try_new(
            PolicyDiagnosticCode::ReportRetentionBudget,
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
            "prior diagnostics were truncated",
            None,
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            builder
                .retain_run_diagnostic(
                    &loaded.definition().metadata.id,
                    loaded.semantic_hash(),
                    diagnostic,
                )
                .unwrap(),
            PolicyRetentionOutcome::Retained
        );
        let document = builder.finish().unwrap();
        assert!(document.runs()[0].diagnostics_truncated());
        assert!(matches!(
            document.runs()[0].completion(),
            PolicyRunCompletion::Inconclusive { reasons }
                if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget)
        ));
    }

    /// Build a batch budget whose retained-bytes ceiling is exactly `bytes`,
    /// with a matching per-policy ceiling so `PolicyBatchBudgetBuilder::build`
    /// accepts it.
    fn batch_budget_capped_at(bytes: usize) -> PolicyBatchBudget {
        let per_policy = super::super::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(bytes)
            .unwrap()
            .build()
            .unwrap();
        PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(bytes)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap()
    }

    /// Retained bytes of an empty schema-version-5 document (no reviews, no
    /// policies, default execution metadata): the base every `set_*` review
    /// method charges a new review's bytes on top of.
    fn empty_document_retained_bytes() -> usize {
        PolicyReportBuilder::new(PolicyBatchBudget::default(), 0)
            .unwrap()
            .finish()
            .unwrap()
            .retained_size()
    }

    /// The smallest `max_retained_report_bytes` a zero-input builder can be
    /// constructed with. Below this, construction itself fails preflight
    /// (it reserves `PolicyExecutionMetadata::maximum_retained_size` and
    /// `EMERGENCY_DIAGNOSTIC_ALLOWANCE` before any review exists), so the
    /// tests below build exactly at this floor and rely on the review's own
    /// bytes, not construction overhead, to trip the batch budget.
    fn minimum_construction_budget() -> usize {
        match PolicyReportBuilder::new(batch_budget_capped_at(0), 0) {
            Err(PolicyReportBuilderError::SkeletonPreflightExceeded { required_bytes, .. }) => {
                required_bytes
            }
            Ok(_) => panic!("a zero-byte budget unexpectedly allowed builder construction"),
            Err(other) => panic!("expected a skeleton preflight floor, got: {other}"),
        }
    }

    // The next three tests pin the single-accounting-site property from
    // #1890: each optional review (diff, packs, baseline) is charged through
    // the same `ensure_review_fits`/`reviews_extra` pair, so a review whose
    // own bytes alone exceed the batch budget is rejected the same way -- a
    // `BatchRetentionExceeded` naming exactly the empty-report bytes plus the
    // review's own bytes -- regardless of which review kind pushed it over.
    // Each review is oversized only in one owned string, kept well above the
    // construction-time preflight floor so it, not that floor, is what trips
    // the budget.

    #[test]
    fn set_diff_over_budget_hits_the_single_review_retention_treatment() {
        let review = PolicyDiffReview::new(
            "x".repeat(10_000),
            "0".repeat(40),
            false,
            1,
            0,
            Vec::new(),
            1,
        );
        let review_extra = retained_extra(&review);
        assert!(review_extra > EMERGENCY_DIAGNOSTIC_ALLOWANCE);

        let empty_bytes = empty_document_retained_bytes();
        let max_bytes = minimum_construction_budget();
        let mut builder = PolicyReportBuilder::new(batch_budget_capped_at(max_bytes), 0).unwrap();
        assert!(matches!(
            builder.set_diff(review),
            Err(PolicyReportBuilderError::BatchRetentionExceeded {
                retained_bytes,
                max_bytes: reported_max,
            }) if retained_bytes == empty_bytes + review_extra && reported_max == max_bytes
        ));
    }

    #[test]
    fn set_packs_over_budget_hits_the_single_review_retention_treatment() {
        let review = PolicyPackActivationReview::new_with_mode(
            "x".repeat(10_000),
            PolicyDependencyPackActivationMode::Default,
            Vec::new(),
            true,
            Vec::new(),
        );
        let review_extra = retained_extra(&review);
        assert!(review_extra > EMERGENCY_DIAGNOSTIC_ALLOWANCE);

        let empty_bytes = empty_document_retained_bytes();
        let max_bytes = minimum_construction_budget();
        let mut builder = PolicyReportBuilder::new(batch_budget_capped_at(max_bytes), 0).unwrap();
        assert!(matches!(
            builder.set_packs(review),
            Err(PolicyReportBuilderError::BatchRetentionExceeded {
                retained_bytes,
                max_bytes: reported_max,
            }) if retained_bytes == empty_bytes + review_extra && reported_max == max_bytes
        ));
    }

    #[test]
    fn set_baseline_over_budget_hits_the_single_review_retention_treatment() {
        use super::super::baseline::parse_policy_baseline_document;

        let document = parse_policy_baseline_document(
            &json!({
                "schema_version": 1,
                "reason": "Onboarding acceptance",
                "accepted_at": "2026-08-08",
                "policies": [],
            })
            .to_string(),
        )
        .unwrap();
        // `document_path` is a raw caller-supplied string, not JSON wire
        // content, so it carries no schema length cap and can stand in for
        // an oversized review here.
        let review = PolicyBaselineReview::new(&"x".repeat(10_000), &document, Vec::new());
        let review_extra = retained_extra(&review);
        assert!(review_extra > EMERGENCY_DIAGNOSTIC_ALLOWANCE);

        let empty_bytes = empty_document_retained_bytes();
        let max_bytes = minimum_construction_budget();
        let mut builder = PolicyReportBuilder::new(batch_budget_capped_at(max_bytes), 0).unwrap();
        assert!(matches!(
            builder.set_baseline(review),
            Err(PolicyReportBuilderError::BatchRetentionExceeded {
                retained_bytes,
                max_bytes: reported_max,
            }) if retained_bytes == empty_bytes + review_extra && reported_max == max_bytes
        ));
    }
}
