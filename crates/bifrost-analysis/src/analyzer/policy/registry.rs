//! Bounded, transactional authority for loaded policies and endpoints.
//!
//! The registry is the only public seam that turns parser-valid RQLP source
//! into [`LoadedPolicy`] and [`LoadedEndpoint`] values. It never discovers
//! files from IDs: workspace access is limited to explicitly supplied paths,
//! referenced RQL selectors, and authored match-directory closures.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;

use crate::analyzer::semantic::WorkspaceRelativePath;
use crate::workspace_document::{WorkspaceDocumentError, WorkspaceRoot};

use super::catalog::{RegisteredTaintCatalog, TaintCatalogRegistry};
use super::composition::{
    CompositionError, CompositionLimits, compose_taint_policy, compose_typestate_policy,
    validate_scanned_endpoint_collection,
};
use super::definition::*;
use super::loading::{
    EndpointClosureError, EndpointDirectoryError, MatchDirectoryLimitError, MatchDirectoryLimits,
    PolicyDocumentLoadError, SelectorLoadError, enumerate_endpoint_directory,
    load_endpoint_closure, read_rqlp_document, resolve_parsed_selector,
};
use super::resolved::*;
use super::source::{
    MAX_RQLP_SOURCE_BYTES, ParsedRqlpDocument, PolicySourceError, PolicySourceIdentity,
    PolicySourceIdentityError, parse_rqlp_source, validate_policy_source_identity,
};

pub const MAX_REGISTERED_POLICIES: usize = 256;
pub const MAX_REGISTERED_ENDPOINTS: usize = 4_096;
pub const MAX_MATCH_DIRECTORIES_PER_POLICY: usize = 64;
pub const MAX_POLICY_MATCH_DIRECTORY_DEPTH: usize = 32;
pub const MAX_POLICY_MATCH_DIRECTORY_CANDIDATES: usize = 4_096;
pub const MAX_POLICY_MATCH_DIRECTORY_ENTRIES: usize = 65_536;
pub const MAX_RETAINED_POLICY_SOURCE_AND_SELECTOR_BYTES: usize = 128 * 1024 * 1024;

/// Per-registry lowerings of the schema-v1 hard ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRegistryLimits {
    max_policies: usize,
    max_endpoints: usize,
    max_match_directories_per_policy: usize,
    max_match_directory_depth: usize,
    max_match_directory_candidates: usize,
    max_match_directory_entries: usize,
    max_retained_source_and_selector_bytes: usize,
}

impl Default for PolicyRegistryLimits {
    fn default() -> Self {
        Self {
            max_policies: MAX_REGISTERED_POLICIES,
            max_endpoints: MAX_REGISTERED_ENDPOINTS,
            max_match_directories_per_policy: MAX_MATCH_DIRECTORIES_PER_POLICY,
            max_match_directory_depth: MAX_POLICY_MATCH_DIRECTORY_DEPTH,
            max_match_directory_candidates: MAX_POLICY_MATCH_DIRECTORY_CANDIDATES,
            max_match_directory_entries: MAX_POLICY_MATCH_DIRECTORY_ENTRIES,
            max_retained_source_and_selector_bytes: MAX_RETAINED_POLICY_SOURCE_AND_SELECTOR_BYTES,
        }
    }
}

impl PolicyRegistryLimits {
    pub const fn max_policies(self) -> usize {
        self.max_policies
    }

    pub const fn max_endpoints(self) -> usize {
        self.max_endpoints
    }

    pub const fn max_match_directories_per_policy(self) -> usize {
        self.max_match_directories_per_policy
    }

    pub const fn max_match_directory_depth(self) -> usize {
        self.max_match_directory_depth
    }

    pub const fn max_match_directory_candidates(self) -> usize {
        self.max_match_directory_candidates
    }

    pub const fn max_match_directory_entries(self) -> usize {
        self.max_match_directory_entries
    }

    pub const fn max_retained_source_and_selector_bytes(self) -> usize {
        self.max_retained_source_and_selector_bytes
    }

    pub fn with_max_policies(mut self, value: usize) -> Result<Self, PolicyRegistryLimitError> {
        validate_registry_limit("max_policies", value, MAX_REGISTERED_POLICIES)?;
        self.max_policies = value;
        Ok(self)
    }

    pub fn with_max_endpoints(mut self, value: usize) -> Result<Self, PolicyRegistryLimitError> {
        validate_registry_limit("max_endpoints", value, MAX_REGISTERED_ENDPOINTS)?;
        self.max_endpoints = value;
        Ok(self)
    }

    pub fn with_max_match_directories_per_policy(
        mut self,
        value: usize,
    ) -> Result<Self, PolicyRegistryLimitError> {
        validate_registry_limit(
            "max_match_directories_per_policy",
            value,
            MAX_MATCH_DIRECTORIES_PER_POLICY,
        )?;
        self.max_match_directories_per_policy = value;
        Ok(self)
    }

    pub fn with_max_match_directory_depth(
        mut self,
        value: usize,
    ) -> Result<Self, PolicyRegistryLimitError> {
        validate_registry_limit(
            "max_match_directory_depth",
            value,
            MAX_POLICY_MATCH_DIRECTORY_DEPTH,
        )?;
        self.max_match_directory_depth = value;
        Ok(self)
    }

    pub fn with_max_match_directory_candidates(
        mut self,
        value: usize,
    ) -> Result<Self, PolicyRegistryLimitError> {
        validate_registry_limit(
            "max_match_directory_candidates",
            value,
            MAX_POLICY_MATCH_DIRECTORY_CANDIDATES,
        )?;
        self.max_match_directory_candidates = value;
        Ok(self)
    }

    pub fn with_max_match_directory_entries(
        mut self,
        value: usize,
    ) -> Result<Self, PolicyRegistryLimitError> {
        validate_registry_limit(
            "max_match_directory_entries",
            value,
            MAX_POLICY_MATCH_DIRECTORY_ENTRIES,
        )?;
        self.max_match_directory_entries = value;
        Ok(self)
    }

    pub fn with_max_retained_source_and_selector_bytes(
        mut self,
        value: usize,
    ) -> Result<Self, PolicyRegistryLimitError> {
        validate_registry_limit(
            "max_retained_source_and_selector_bytes",
            value,
            MAX_RETAINED_POLICY_SOURCE_AND_SELECTOR_BYTES,
        )?;
        self.max_retained_source_and_selector_bytes = value;
        Ok(self)
    }
}

fn validate_registry_limit(
    field: &'static str,
    value: usize,
    hard_maximum: usize,
) -> Result<(), PolicyRegistryLimitError> {
    if value == 0 || value > hard_maximum {
        return Err(PolicyRegistryLimitError {
            field,
            value,
            hard_maximum,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRegistryLimitError {
    pub field: &'static str,
    pub value: usize,
    pub hard_maximum: usize,
}

impl fmt::Display for PolicyRegistryLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must be from 1 through {}, found {}",
            self.field, self.hard_maximum, self.value
        )
    }
}

impl std::error::Error for PolicyRegistryLimitError {}

#[derive(Debug)]
struct RegisteredEndpoint {
    loaded: LoadedEndpoint,
    retained_source_and_selector_bytes: usize,
}

/// Immutable loaded values plus the explicit filesystem/catalog authority
/// under which their semantic hashes were minted.
#[derive(Debug)]
pub struct PolicyRegistry {
    catalogs: Arc<TaintCatalogRegistry>,
    limits: PolicyRegistryLimits,
    workspace_root: Option<WorkspaceRoot>,
    policies: HashMap<PolicyId, LoadedPolicy>,
    endpoints: HashMap<EndpointId, RegisteredEndpoint>,
    retained_endpoint_slots: usize,
    retained_source_and_selector_bytes: usize,
}

impl PolicyRegistry {
    pub fn new_without_workspace(
        catalogs: Arc<TaintCatalogRegistry>,
        limits: PolicyRegistryLimits,
    ) -> Self {
        Self {
            catalogs,
            limits,
            workspace_root: None,
            policies: HashMap::new(),
            endpoints: HashMap::new(),
            retained_endpoint_slots: 0,
            retained_source_and_selector_bytes: 0,
        }
    }

    pub fn new_for_workspace(
        workspace_root: PathBuf,
        catalogs: Arc<TaintCatalogRegistry>,
        limits: PolicyRegistryLimits,
    ) -> Result<Self, PolicyRegistryError> {
        if !workspace_root.is_absolute() {
            return Err(PolicyRegistryError::WorkspaceRootMustBeAbsolute);
        }
        let workspace_root = WorkspaceRoot::open(&workspace_root)?;
        Ok(Self {
            catalogs,
            limits,
            workspace_root: Some(workspace_root),
            policies: HashMap::new(),
            endpoints: HashMap::new(),
            retained_endpoint_slots: 0,
            retained_source_and_selector_bytes: 0,
        })
    }

    pub fn load_policy_path(
        &mut self,
        relative_path: impl AsRef<Path>,
    ) -> Result<&LoadedPolicy, PolicyRegistryError> {
        let loaded = {
            let root = self
                .workspace_root
                .as_ref()
                .ok_or(PolicyRegistryError::WorkspaceAccessUnavailable)?;
            read_rqlp_document(root, relative_path.as_ref())?
        };
        let (_, document, parsed) = loaded.into_parts();
        self.finish_policy_registration(parsed, document.source().as_bytes())
    }

    pub fn register_policy_bytes(
        &mut self,
        identity: PolicySourceIdentity,
        bytes: &[u8],
    ) -> Result<&LoadedPolicy, PolicyRegistryError> {
        validate_policy_source_identity(&identity)?;
        let parsed = parse_policy_bytes(identity, bytes)?;
        self.finish_policy_registration(parsed, bytes)
    }

    pub fn load_endpoint_path(
        &mut self,
        relative_path: impl AsRef<Path>,
    ) -> Result<&LoadedEndpoint, PolicyRegistryError> {
        let loaded = {
            let root = self
                .workspace_root
                .as_ref()
                .ok_or(PolicyRegistryError::WorkspaceAccessUnavailable)?;
            read_rqlp_document(root, relative_path.as_ref())?
        };
        let (_, document, parsed) = loaded.into_parts();
        self.finish_endpoint_registration(parsed, document.source().as_bytes())
    }

    pub fn register_endpoint_bytes(
        &mut self,
        identity: PolicySourceIdentity,
        bytes: &[u8],
    ) -> Result<&LoadedEndpoint, PolicyRegistryError> {
        validate_policy_source_identity(&identity)?;
        let parsed = parse_policy_bytes(identity, bytes)?;
        self.finish_endpoint_registration(parsed, bytes)
    }

    pub fn policies(&self) -> impl ExactSizeIterator<Item = &LoadedPolicy> {
        let mut policies: Vec<_> = self.policies.values().collect();
        policies.sort_by(|left, right| {
            left.definition()
                .metadata
                .id
                .cmp(&right.definition().metadata.id)
        });
        policies.into_iter()
    }

    pub fn endpoints(&self) -> impl ExactSizeIterator<Item = &LoadedEndpoint> {
        let mut endpoints: Vec<_> = self
            .endpoints
            .values()
            .map(|registered| &registered.loaded)
            .collect();
        endpoints.sort_by(|left, right| left.definition().id.cmp(&right.definition().id));
        endpoints.into_iter()
    }

    fn finish_endpoint_registration(
        &mut self,
        parsed: ParsedRqlpDocument,
        source_bytes: &[u8],
    ) -> Result<&LoadedEndpoint, PolicyRegistryError> {
        let closure = load_endpoint_closure(self.workspace_root.as_ref(), parsed, source_bytes)?;
        let (loaded, _, retained_bytes) = closure.into_parts();
        let endpoint_id = loaded.definition().id.clone();
        if self.endpoints.contains_key(&endpoint_id) {
            return Err(PolicyRegistryError::DuplicateEndpointId { endpoint_id });
        }
        let attempted_endpoints = self
            .retained_endpoint_slots
            .checked_add(1)
            .ok_or(PolicyRegistryError::EndpointCountOverflow)?;
        if attempted_endpoints > self.limits.max_endpoints {
            return Err(PolicyRegistryError::EndpointLimitExceeded {
                attempted: attempted_endpoints,
                maximum: self.limits.max_endpoints,
            });
        }
        let attempted_bytes = self.checked_retained_total(retained_bytes)?;
        self.endpoints.insert(
            endpoint_id.clone(),
            RegisteredEndpoint {
                loaded,
                retained_source_and_selector_bytes: retained_bytes,
            },
        );
        self.retained_endpoint_slots = attempted_endpoints;
        self.retained_source_and_selector_bytes = attempted_bytes;
        Ok(&self
            .endpoints
            .get(&endpoint_id)
            .expect("endpoint was inserted transactionally")
            .loaded)
    }

    fn finish_policy_registration(
        &mut self,
        parsed: ParsedRqlpDocument,
        source_bytes: &[u8],
    ) -> Result<&LoadedPolicy, PolicyRegistryError> {
        let definition = match parsed.document() {
            RqlpDocument::Policy { definition } => definition.as_ref().clone(),
            RqlpDocument::Endpoint { .. } => {
                return Err(PolicyRegistryError::WrongDocumentKind {
                    expected: PolicyDocumentKind::Policy,
                });
            }
        };
        let policy_id = definition.metadata.id.clone();
        if self.policies.contains_key(&policy_id) {
            return Err(PolicyRegistryError::DuplicatePolicyId { policy_id });
        }
        let attempted_policies = self
            .policies
            .len()
            .checked_add(1)
            .ok_or(PolicyRegistryError::PolicyCountOverflow)?;
        if attempted_policies > self.limits.max_policies {
            return Err(PolicyRegistryError::PolicyLimitExceeded {
                attempted: attempted_policies,
                maximum: self.limits.max_policies,
            });
        }

        let build = self.build_policy(&parsed, definition, source_bytes)?;
        let attempted_endpoints = self
            .retained_endpoint_slots
            .checked_add(build.endpoint_slots)
            .ok_or(PolicyRegistryError::EndpointCountOverflow)?;
        if attempted_endpoints > self.limits.max_endpoints {
            return Err(PolicyRegistryError::EndpointLimitExceeded {
                attempted: attempted_endpoints,
                maximum: self.limits.max_endpoints,
            });
        }
        let attempted_bytes = self.checked_retained_total(build.retained_bytes)?;
        self.policies.insert(policy_id.clone(), build.loaded);
        self.retained_endpoint_slots = attempted_endpoints;
        self.retained_source_and_selector_bytes = attempted_bytes;
        Ok(self
            .policies
            .get(&policy_id)
            .expect("policy was inserted transactionally"))
    }

    fn checked_retained_total(&self, additional: usize) -> Result<usize, PolicyRegistryError> {
        let attempted = self
            .retained_source_and_selector_bytes
            .checked_add(additional)
            .ok_or(PolicyRegistryError::RetainedByteCountOverflow)?;
        if attempted > self.limits.max_retained_source_and_selector_bytes {
            return Err(PolicyRegistryError::RetainedByteLimitExceeded {
                attempted,
                maximum: self.limits.max_retained_source_and_selector_bytes,
            });
        }
        Ok(attempted)
    }

    fn build_policy(
        &self,
        parsed: &ParsedRqlpDocument,
        definition: PolicyDefinition,
        source_bytes: &[u8],
    ) -> Result<PolicyBuild, PolicyRegistryError> {
        let mut retained_bytes = source_bytes.len();
        self.ensure_local_retained_bytes(retained_bytes)?;
        let mut fixed_selectors = BTreeMap::new();
        let mut dependency_selectors = BTreeMap::new();
        let mut candidate_dependencies = Vec::new();

        let (resolved_taint, resolved_typestate, catalogs, dependencies, manifests, precedence) =
            match &definition.analysis {
                PolicyAnalysis::Match { spec } => {
                    let path = selector_path("/analysis/selector")?;
                    let selector =
                        self.resolve_selector(parsed, path, &spec.selector, &mut retained_bytes)?;
                    insert_selector(&mut fixed_selectors, selector)?;
                    (
                        None,
                        None,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Default::default(),
                    )
                }
                PolicyAnalysis::Taint { spec } => {
                    self.build_local_taint_inputs(
                        parsed,
                        &definition,
                        spec,
                        &mut fixed_selectors,
                        &mut dependency_selectors,
                        &mut candidate_dependencies,
                        &mut retained_bytes,
                    )?;
                    self.build_catalog_taint_inputs(
                        spec,
                        &mut fixed_selectors,
                        &mut dependency_selectors,
                        &mut candidate_dependencies,
                        &mut retained_bytes,
                    )?;
                    let uses = taint_match_uses(spec)?;
                    let match_inputs = self.build_match_inputs(
                        &uses,
                        &mut dependency_selectors,
                        &mut retained_bytes,
                    )?;
                    candidate_dependencies.extend(match_inputs.dependencies);
                    self.validate_candidate_endpoint_count(
                        &candidate_dependencies,
                        fixed_selectors.len(),
                    )?;
                    let composed = compose_taint_policy(
                        &definition.metadata.id,
                        spec,
                        &self.catalogs,
                        &candidate_dependencies,
                        &match_inputs.manifests,
                        self.composition_limits()?,
                    )?;
                    let catalogs = composed.spec.catalogs.clone();
                    let dependencies = composed.endpoint_dependencies;
                    let manifests = composed.spec.match_manifests.clone();
                    (
                        Some(composed.spec),
                        None,
                        catalogs,
                        dependencies,
                        manifests,
                        composed.precedence,
                    )
                }
                PolicyAnalysis::Typestate { spec } => {
                    self.build_local_typestate_inputs(
                        parsed,
                        &definition,
                        spec,
                        &mut fixed_selectors,
                        &mut dependency_selectors,
                        &mut candidate_dependencies,
                        &mut retained_bytes,
                    )?;
                    let uses = typestate_match_uses(spec)?;
                    let match_inputs = self.build_match_inputs(
                        &uses,
                        &mut dependency_selectors,
                        &mut retained_bytes,
                    )?;
                    candidate_dependencies.extend(match_inputs.dependencies);
                    self.validate_candidate_endpoint_count(&candidate_dependencies, 0)?;
                    let composed = compose_typestate_policy(
                        &definition.metadata.id,
                        spec,
                        &self.catalogs,
                        &candidate_dependencies,
                        &match_inputs.manifests,
                        self.composition_limits()?,
                    )?;
                    let dependencies = composed.spec.endpoint_dependencies.clone();
                    let manifests = composed.spec.match_manifests.clone();
                    (
                        None,
                        Some(composed.spec),
                        Vec::new(),
                        dependencies,
                        manifests,
                        composed.precedence,
                    )
                }
            };

        for dependency in &dependencies {
            let selector = dependency_selectors
                .remove(&dependency.selector_path)
                .ok_or_else(|| PolicyRegistryError::MissingDependencySelector {
                    path: dependency.selector_path.clone(),
                })?;
            if dependency.selector_schema.version != selector.schema_resolution.version
                || dependency.selector_path != selector.path
            {
                return Err(PolicyRegistryError::DependencySelectorMismatch {
                    path: dependency.selector_path.clone(),
                });
            }
            insert_selector(&mut fixed_selectors, selector)?;
        }
        let resolved_selectors = fixed_selectors.into_values().collect();
        let auxiliary_slots = if let Some(spec) = resolved_taint.as_ref() {
            spec.sanitizers
                .len()
                .checked_add(spec.transforms.len())
                .and_then(|count| count.checked_add(spec.external_models.len()))
                .ok_or(PolicyRegistryError::EndpointCountOverflow)?
        } else {
            0
        };
        let endpoint_slots = dependencies
            .len()
            .checked_add(auxiliary_slots)
            .ok_or(PolicyRegistryError::EndpointCountOverflow)?;
        let loaded = LoadedPolicy::try_new(
            definition,
            parsed.identity().clone(),
            source_bytes,
            parsed.schema_resolution(),
            resolved_selectors,
            catalogs,
            dependencies,
            manifests,
            precedence,
            resolved_taint,
            resolved_typestate,
        )?;
        Ok(PolicyBuild {
            loaded,
            retained_bytes,
            endpoint_slots,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_local_taint_inputs(
        &self,
        parsed: &ParsedRqlpDocument,
        definition: &PolicyDefinition,
        spec: &TaintPolicySpec,
        fixed_selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        dependency_selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        dependencies: &mut Vec<ResolvedEndpointDependency>,
        retained_bytes: &mut usize,
    ) -> Result<(), PolicyRegistryError> {
        for source in &spec.sources.entries {
            let base = format!(
                "/analysis/sources/entries/{}",
                pointer_segment(source.id.as_str())
            );
            let path = selector_path(format!("{base}/selector"))?;
            let selector = self.resolve_selector(parsed, path, &source.selector, retained_bytes)?;
            let identity = ResolvedEndpointIdentity::Local {
                policy_id: definition.metadata.id.clone(),
                entry_id: source.id.clone(),
            };
            let dependency = ResolvedEndpointDependency::from_composed_model(
                identity,
                EndpointDefinitionSchemaResolution::PolicyDocument {
                    resolution: parsed.schema_resolution(),
                },
                &selector,
                ResolvedEndpointModel::new(
                    EndpointRole::Source,
                    source.display_name.clone(),
                    source.categories.clone(),
                    port_to_endpoint_binding(&source.bind),
                    Some(EndpointTaintSemantics::Source {
                        labels: source.labels.clone(),
                        evidence: source.evidence.clone(),
                    }),
                    Vec::new(),
                ),
                vec![EndpointOrigin::PolicyLocal {
                    path: dependency_path(base)?,
                }],
            )?;
            insert_selector(dependency_selectors, selector)?;
            dependencies.push(dependency);
        }
        for sink in &spec.sinks.entries {
            let base = format!(
                "/analysis/sinks/entries/{}",
                pointer_segment(sink.id.as_str())
            );
            let path = selector_path(format!("{base}/selector"))?;
            let selector = self.resolve_selector(parsed, path, &sink.selector, retained_bytes)?;
            let identity = ResolvedEndpointIdentity::Local {
                policy_id: definition.metadata.id.clone(),
                entry_id: sink.id.clone(),
            };
            let dependency = ResolvedEndpointDependency::from_composed_model(
                identity,
                EndpointDefinitionSchemaResolution::PolicyDocument {
                    resolution: parsed.schema_resolution(),
                },
                &selector,
                ResolvedEndpointModel::new(
                    EndpointRole::Sink,
                    sink.display_name.clone(),
                    sink.categories.clone(),
                    port_to_endpoint_binding(&sink.dangerous_operand),
                    Some(EndpointTaintSemantics::Sink {
                        accepts: sink.accepts.clone(),
                        tags: sink.tags.clone(),
                        impacts: sink.impacts.clone(),
                    }),
                    Vec::new(),
                ),
                vec![EndpointOrigin::PolicyLocal {
                    path: dependency_path(base)?,
                }],
            )?;
            insert_selector(dependency_selectors, selector)?;
            dependencies.push(dependency);
        }
        self.resolve_local_auxiliary_selectors(
            parsed,
            "sanitizers",
            spec.sanitizers
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            fixed_selectors,
            retained_bytes,
        )?;
        self.resolve_local_auxiliary_selectors(
            parsed,
            "transforms",
            spec.transforms
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            fixed_selectors,
            retained_bytes,
        )?;
        self.resolve_local_auxiliary_selectors(
            parsed,
            "external_models",
            spec.external_models
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            fixed_selectors,
            retained_bytes,
        )?;
        Ok(())
    }

    fn resolve_local_auxiliary_selectors<'a>(
        &self,
        parsed: &ParsedRqlpDocument,
        kind: &str,
        entries: impl Iterator<Item = (&'a TaintEntryId, &'a PolicySelector)>,
        selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        retained_bytes: &mut usize,
    ) -> Result<(), PolicyRegistryError> {
        for (id, authored) in entries {
            let path = selector_path(format!(
                "/analysis/{kind}/entries/{}/selector",
                pointer_segment(id.as_str())
            ))?;
            let selector = self.resolve_selector(parsed, path, authored, retained_bytes)?;
            insert_selector(selectors, selector)?;
        }
        Ok(())
    }

    fn build_catalog_taint_inputs(
        &self,
        spec: &TaintPolicySpec,
        fixed_selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        dependency_selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        dependencies: &mut Vec<ResolvedEndpointDependency>,
        retained_bytes: &mut usize,
    ) -> Result<(), PolicyRegistryError> {
        // Catalog storage is independently bounded, but each loaded policy
        // clones the selected typed definitions and queries. Charge one full
        // canonical catalog projection per referenced identity per policy as
        // a conservative bound over every retained selector source and model.
        let mut charged_catalogs = HashSet::new();
        for reference in spec
            .sources
            .include_sets
            .iter()
            .chain(&spec.sinks.include_sets)
            .chain(&spec.sanitizers.include_sets)
            .chain(&spec.transforms.include_sets)
            .chain(&spec.external_models.include_sets)
        {
            let catalog = self.catalogs.resolve(reference)?;
            let identity = resolved_catalog_identity(catalog)?;
            if charged_catalogs.insert(identity) {
                self.charge_local(retained_bytes, catalog.canonical_json().len())?;
            }
        }
        for reference in &spec.sources.include_sets {
            let catalog = self.catalogs.resolve(reference)?;
            for source in &catalog.definition().sources {
                let (identity, selector) = catalog_selector(catalog, &source.id)?;
                let dependency = ResolvedEndpointDependency::from_composed_model(
                    ResolvedEndpointIdentity::Catalog {
                        catalog: identity.clone(),
                        entry_id: source.id.clone(),
                    },
                    EndpointDefinitionSchemaResolution::CatalogDocument {
                        schema_version: catalog.definition().schema_version,
                    },
                    &selector,
                    ResolvedEndpointModel::new(
                        EndpointRole::Source,
                        source.display_name.clone(),
                        source.categories.clone(),
                        port_to_endpoint_binding(&source.bind),
                        Some(EndpointTaintSemantics::Source {
                            labels: source.labels.clone(),
                            evidence: source.evidence.clone(),
                        }),
                        Vec::new(),
                    ),
                    vec![EndpointOrigin::Catalog { catalog: identity }],
                )?;
                insert_selector(dependency_selectors, selector)?;
                dependencies.push(dependency);
            }
        }
        for reference in &spec.sinks.include_sets {
            let catalog = self.catalogs.resolve(reference)?;
            for sink in &catalog.definition().sinks {
                let (identity, selector) = catalog_selector(catalog, &sink.id)?;
                let dependency = ResolvedEndpointDependency::from_composed_model(
                    ResolvedEndpointIdentity::Catalog {
                        catalog: identity.clone(),
                        entry_id: sink.id.clone(),
                    },
                    EndpointDefinitionSchemaResolution::CatalogDocument {
                        schema_version: catalog.definition().schema_version,
                    },
                    &selector,
                    ResolvedEndpointModel::new(
                        EndpointRole::Sink,
                        sink.display_name.clone(),
                        sink.categories.clone(),
                        port_to_endpoint_binding(&sink.dangerous_operand),
                        Some(EndpointTaintSemantics::Sink {
                            accepts: sink.accepts.clone(),
                            tags: sink.tags.clone(),
                            impacts: sink.impacts.clone(),
                        }),
                        Vec::new(),
                    ),
                    vec![EndpointOrigin::Catalog { catalog: identity }],
                )?;
                insert_selector(dependency_selectors, selector)?;
                dependencies.push(dependency);
            }
        }
        self.resolve_catalog_auxiliary_selectors(
            &spec.sanitizers.include_sets,
            |catalog| {
                catalog
                    .definition()
                    .sanitizers
                    .iter()
                    .map(|entry| (&entry.id, &entry.selector))
                    .collect()
            },
            fixed_selectors,
        )?;
        self.resolve_catalog_auxiliary_selectors(
            &spec.transforms.include_sets,
            |catalog| {
                catalog
                    .definition()
                    .transforms
                    .iter()
                    .map(|entry| (&entry.id, &entry.selector))
                    .collect()
            },
            fixed_selectors,
        )?;
        self.resolve_catalog_auxiliary_selectors(
            &spec.external_models.include_sets,
            |catalog| {
                catalog
                    .definition()
                    .external_models
                    .iter()
                    .map(|entry| (&entry.id, &entry.selector))
                    .collect()
            },
            fixed_selectors,
        )?;
        Ok(())
    }

    fn resolve_catalog_auxiliary_selectors(
        &self,
        references: &[CatalogRef],
        entries: impl for<'a> Fn(
            &'a RegisteredTaintCatalog,
        ) -> Vec<(&'a TaintEntryId, &'a PolicySelector)>,
        selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
    ) -> Result<(), PolicyRegistryError> {
        for reference in references {
            let catalog = self.catalogs.resolve(reference)?;
            let identity = resolved_catalog_identity(catalog)?;
            for (id, authored) in entries(catalog) {
                let path = selector_path(format!(
                    "/dependencies/catalogs/{}@{}/{}/selector",
                    pointer_segment(identity.name.as_str()),
                    identity.version,
                    pointer_segment(id.as_str())
                ))?;
                let selector = inline_selector(
                    path,
                    authored,
                    SelectorOrigin::Catalog {
                        catalog: identity.clone(),
                    },
                )?;
                insert_selector(selectors, selector)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_local_typestate_inputs(
        &self,
        parsed: &ParsedRqlpDocument,
        definition: &PolicyDefinition,
        spec: &TypestatePolicySpec,
        fixed_selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        dependency_selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        dependencies: &mut Vec<ResolvedEndpointDependency>,
        retained_bytes: &mut usize,
    ) -> Result<(), PolicyRegistryError> {
        for subject in &spec.subjects.entries {
            let base = format!(
                "/analysis/subjects/entries/{}",
                pointer_segment(subject.id.as_str())
            );
            let path = selector_path(format!("{base}/selector"))?;
            let selector =
                self.resolve_selector(parsed, path, &subject.selector, retained_bytes)?;
            let dependency = ResolvedEndpointDependency::from_composed_model(
                ResolvedEndpointIdentity::Local {
                    policy_id: definition.metadata.id.clone(),
                    entry_id: subject.id.clone(),
                },
                EndpointDefinitionSchemaResolution::PolicyDocument {
                    resolution: parsed.schema_resolution(),
                },
                &selector,
                ResolvedEndpointModel::new(
                    EndpointRole::Source,
                    subject.id.as_str().to_string(),
                    Vec::new(),
                    seed_to_endpoint_binding(&subject.subject),
                    None,
                    Vec::new(),
                ),
                vec![EndpointOrigin::PolicyLocal {
                    path: dependency_path(base)?,
                }],
            )?;
            insert_selector(dependency_selectors, selector)?;
            dependencies.push(dependency);
        }
        for event in &spec.automaton.events {
            if let TypestateEventTrigger::Calls { selector, .. } = &event.trigger {
                let path = selector_path(format!(
                    "/analysis/automaton/events/{}/selector",
                    pointer_segment(event.id.as_str())
                ))?;
                let selector = self.resolve_selector(parsed, path, selector, retained_bytes)?;
                insert_selector(fixed_selectors, selector)?;
            }
        }
        Ok(())
    }

    fn build_match_inputs(
        &self,
        uses: &[MatchUse],
        dependency_selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
        retained_bytes: &mut usize,
    ) -> Result<MatchBuild, PolicyRegistryError> {
        let directory_count = uses
            .iter()
            .filter(|usage| matches!(usage.set, MatchEndpointSetRef::Directory { .. }))
            .count();
        if directory_count > self.limits.max_match_directories_per_policy {
            return Err(PolicyRegistryError::MatchDirectoryLimitExceeded {
                found: directory_count,
                maximum: self.limits.max_match_directories_per_policy,
            });
        }
        if directory_count > 0 && self.workspace_root.is_none() {
            return Err(PolicyRegistryError::WorkspaceAccessUnavailable);
        }

        let mut directories: BTreeMap<DirectoryCacheKey, DirectoryClosure> = BTreeMap::new();
        let mut candidate_count = 0_usize;
        for usage in uses {
            let MatchEndpointSetRef::Directory { reference } = &usage.set else {
                continue;
            };
            let key = DirectoryCacheKey {
                path: reference.path.clone(),
                scope: reference.scope,
            };
            if directories.contains_key(&key) {
                continue;
            }
            let closure = self.load_directory_closure(&key, usage, retained_bytes)?;
            candidate_count = candidate_count
                .checked_add(closure.endpoints.len())
                .ok_or(PolicyRegistryError::EndpointCountOverflow)?;
            if candidate_count > self.limits.max_match_directory_candidates {
                return Err(PolicyRegistryError::MatchDirectoryCandidateLimitExceeded {
                    found: candidate_count,
                    maximum: self.limits.max_match_directory_candidates,
                });
            }
            directories.insert(key, closure);
        }

        let mut dependencies = BTreeMap::new();
        let mut manifests = Vec::new();
        let mut charged_directory_sources = HashSet::new();
        for usage in uses {
            let MatchEndpointSetRef::Directory { reference } = &usage.set else {
                continue;
            };
            let key = DirectoryCacheKey {
                path: reference.path.clone(),
                scope: reference.scope,
            };
            let closure = directories
                .get(&key)
                .expect("each explicit directory was loaded before selection");
            let mut selected = Vec::new();
            for entry in &closure.endpoints {
                let endpoint = &entry.loaded;
                if endpoint.definition().role != usage.role
                    || !category_matches(&reference.categories, &endpoint.definition().categories)
                {
                    continue;
                }
                let charge_key = (endpoint.source().clone(), endpoint.source_hash());
                if charged_directory_sources.insert(charge_key) {
                    self.charge_local(retained_bytes, entry.retained_bytes)?;
                }
                let selector = rekey_endpoint_selector(endpoint)?;
                let dependency = dependency_from_loaded_endpoint(
                    endpoint,
                    &selector,
                    EndpointOrigin::MatchDirectory {
                        path: usage.path.clone(),
                        source: endpoint.source().clone(),
                    },
                )?;
                selected.push(ResolvedEndpointManifestEntry::from(&dependency));
                insert_selector(dependency_selectors, selector)?;
                merge_match_dependency(&mut dependencies, dependency)?;
            }
            let manifest = ResolvedMatchDirectoryManifest::try_new(
                usage.path.clone(),
                reference.path.clone(),
                reference.scope,
                Some(usage.role),
                reference.categories.clone(),
                selected,
            )?;
            if let Some(expected) = reference.manifest_sha256
                && expected != manifest.semantic_hash
            {
                return Err(PolicyRegistryError::MatchDirectoryManifestMismatch {
                    directory: reference.path.clone(),
                    expected,
                    actual: manifest.semantic_hash,
                });
            }
            manifests.push(manifest);
        }

        let mut charged_registered = HashSet::new();
        for usage in uses {
            let MatchEndpointSetRef::Exact { endpoint_ids } = &usage.set else {
                continue;
            };
            for endpoint_id in endpoint_ids {
                if let Some(registered) = self.endpoints.get(endpoint_id) {
                    if charged_registered.insert(endpoint_id.clone()) {
                        self.charge_local(
                            retained_bytes,
                            registered.retained_source_and_selector_bytes,
                        )?;
                    }
                    let selector = rekey_endpoint_selector(&registered.loaded)?;
                    let dependency = dependency_from_loaded_endpoint(
                        &registered.loaded,
                        &selector,
                        EndpointOrigin::ExactMatch {
                            path: usage.path.clone(),
                            source: registered.loaded.source().clone(),
                        },
                    )?;
                    insert_selector(dependency_selectors, selector)?;
                    merge_match_dependency(&mut dependencies, dependency)?;
                }
                for closure in directories.values() {
                    for entry in &closure.endpoints {
                        let endpoint = &entry.loaded;
                        if endpoint.definition().id != *endpoint_id {
                            continue;
                        }
                        let charge_key = (endpoint.source().clone(), endpoint.source_hash());
                        if charged_directory_sources.insert(charge_key) {
                            self.charge_local(retained_bytes, entry.retained_bytes)?;
                        }
                        let selector = rekey_endpoint_selector(endpoint)?;
                        let dependency = dependency_from_loaded_endpoint(
                            endpoint,
                            &selector,
                            EndpointOrigin::ExactMatch {
                                path: usage.path.clone(),
                                source: endpoint.source().clone(),
                            },
                        )?;
                        insert_selector(dependency_selectors, selector)?;
                        merge_match_dependency(&mut dependencies, dependency)?;
                    }
                }
            }
        }
        Ok(MatchBuild {
            dependencies: dependencies.into_values().collect(),
            manifests,
        })
    }

    fn load_directory_closure(
        &self,
        key: &DirectoryCacheKey,
        first_usage: &MatchUse,
        retained_bytes: &mut usize,
    ) -> Result<DirectoryClosure, PolicyRegistryError> {
        let root = self
            .workspace_root
            .as_ref()
            .ok_or(PolicyRegistryError::WorkspaceAccessUnavailable)?;
        let available = self.available_local_bytes(*retained_bytes)?;
        let limits = MatchDirectoryLimits::default()
            .with_max_depth(self.limits.max_match_directory_depth)?
            .with_max_candidates(self.limits.max_match_directory_candidates)?
            .with_max_entries(self.limits.max_match_directory_entries)?
            .with_max_source_bytes(available)?;
        let directory = enumerate_endpoint_directory(root, &key.path, key.scope, limits)?;
        let mut endpoints = Vec::with_capacity(directory.entries().len());
        let mut validation_dependencies = Vec::with_capacity(directory.entries().len());
        let mut transient_bytes = 0_usize;
        let available = self.available_local_bytes(*retained_bytes)?;
        for source in directory.into_entries() {
            let (_, document, parsed) = source.into_parts();
            let closure = load_endpoint_closure(Some(root), parsed, document.source().as_bytes())?;
            let (endpoint, _, retained) = closure.into_parts();
            transient_bytes = transient_bytes
                .checked_add(retained)
                .ok_or(PolicyRegistryError::RetainedByteCountOverflow)?;
            if transient_bytes > available {
                return Err(PolicyRegistryError::RetainedByteLimitExceeded {
                    attempted: self
                        .retained_source_and_selector_bytes
                        .saturating_add(*retained_bytes)
                        .saturating_add(transient_bytes),
                    maximum: self.limits.max_retained_source_and_selector_bytes,
                });
            }
            let selector = rekey_endpoint_selector(&endpoint)?;
            validation_dependencies.push(dependency_from_loaded_endpoint(
                &endpoint,
                &selector,
                EndpointOrigin::MatchDirectory {
                    path: first_usage.path.clone(),
                    source: endpoint.source().clone(),
                },
            )?);
            endpoints.push(DirectoryEndpoint {
                loaded: endpoint,
                retained_bytes: retained,
            });
        }
        validate_scanned_endpoint_collection(&validation_dependencies, self.composition_limits()?)?;
        endpoints.sort_by(|left, right| {
            left.loaded
                .definition()
                .id
                .cmp(&right.loaded.definition().id)
        });
        Ok(DirectoryClosure { endpoints })
    }

    fn resolve_selector(
        &self,
        parsed: &ParsedRqlpDocument,
        path: PolicySelectorPath,
        authored: &PolicySelector,
        retained_bytes: &mut usize,
    ) -> Result<ResolvedPolicySelector, PolicyRegistryError> {
        let loaded = resolve_parsed_selector(self.workspace_root.as_ref(), parsed, path, authored)?;
        if let Some(reference) = loaded.referenced.as_ref() {
            self.charge_local(retained_bytes, reference.document().source().len())?;
        }
        Ok(loaded.selector)
    }

    fn composition_limits(&self) -> Result<CompositionLimits, PolicyRegistryError> {
        Ok(CompositionLimits::default()
            .with_max_endpoints_per_role(self.limits.max_endpoints)?
            .with_max_predicate_endpoints(self.limits.max_endpoints)?)
    }

    fn validate_candidate_endpoint_count(
        &self,
        dependencies: &[ResolvedEndpointDependency],
        auxiliary_slots: usize,
    ) -> Result<(), PolicyRegistryError> {
        let attempted = dependencies
            .len()
            .checked_add(auxiliary_slots)
            .ok_or(PolicyRegistryError::EndpointCountOverflow)?;
        if attempted > self.limits.max_endpoints {
            return Err(PolicyRegistryError::EndpointLimitExceeded {
                attempted,
                maximum: self.limits.max_endpoints,
            });
        }
        Ok(())
    }

    fn available_local_bytes(&self, local: usize) -> Result<usize, PolicyRegistryError> {
        let already = self
            .retained_source_and_selector_bytes
            .checked_add(local)
            .ok_or(PolicyRegistryError::RetainedByteCountOverflow)?;
        self.limits
            .max_retained_source_and_selector_bytes
            .checked_sub(already)
            .ok_or(PolicyRegistryError::RetainedByteLimitExceeded {
                attempted: already,
                maximum: self.limits.max_retained_source_and_selector_bytes,
            })
    }

    fn ensure_local_retained_bytes(&self, local: usize) -> Result<(), PolicyRegistryError> {
        let _ = self.available_local_bytes(local)?;
        Ok(())
    }

    fn charge_local(
        &self,
        local: &mut usize,
        additional: usize,
    ) -> Result<(), PolicyRegistryError> {
        let attempted_local = local
            .checked_add(additional)
            .ok_or(PolicyRegistryError::RetainedByteCountOverflow)?;
        self.ensure_local_retained_bytes(attempted_local)?;
        *local = attempted_local;
        Ok(())
    }
}

struct PolicyBuild {
    loaded: LoadedPolicy,
    retained_bytes: usize,
    endpoint_slots: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DirectoryCacheKey {
    path: WorkspaceRelativePath,
    scope: DirectoryScope,
}

impl PartialOrd for DirectoryCacheKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DirectoryCacheKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .cmp(&other.path)
            .then_with(|| directory_scope_rank(self.scope).cmp(&directory_scope_rank(other.scope)))
    }
}

struct DirectoryClosure {
    endpoints: Vec<DirectoryEndpoint>,
}

struct DirectoryEndpoint {
    loaded: LoadedEndpoint,
    retained_bytes: usize,
}

struct MatchBuild {
    dependencies: Vec<ResolvedEndpointDependency>,
    manifests: Vec<ResolvedMatchDirectoryManifest>,
}

#[derive(Clone)]
struct MatchUse {
    set: MatchEndpointSetRef,
    role: EndpointRole,
    path: PolicyDependencyPath,
}

fn taint_match_uses(spec: &TaintPolicySpec) -> Result<Vec<MatchUse>, PolicyRegistryError> {
    let mut uses = Vec::new();
    extend_set_uses(
        &mut uses,
        &spec.sources.include_matches,
        EndpointRole::Source,
        "/analysis/sources/include-matches",
    )?;
    extend_set_uses(
        &mut uses,
        &spec.sinks.include_matches,
        EndpointRole::Sink,
        "/analysis/sinks/include-matches",
    )?;
    Ok(uses)
}

fn typestate_match_uses(spec: &TypestatePolicySpec) -> Result<Vec<MatchUse>, PolicyRegistryError> {
    let mut uses = Vec::new();
    extend_set_uses(
        &mut uses,
        &spec.subjects.include_matches,
        EndpointRole::Source,
        "/analysis/subjects/include-matches",
    )?;
    for event in &spec.automaton.events {
        if let TypestateEventTrigger::MatchEndpoints { set, role, .. } = &event.trigger {
            uses.push(MatchUse {
                set: set.clone(),
                role: *role,
                path: dependency_path(format!(
                    "/analysis/automaton/events/{}/matches",
                    pointer_segment(event.id.as_str())
                ))?,
            });
        }
    }
    for expectation in &spec.automaton.terminal_expectations {
        if let TypestateTerminalTrigger::MatchEndpoints { set, role, .. } = &expectation.trigger {
            uses.push(MatchUse {
                set: set.clone(),
                role: *role,
                path: dependency_path(format!(
                    "/analysis/automaton/terminal-expectations/{}/on",
                    pointer_segment(expectation.id.as_str())
                ))?,
            });
        }
    }
    Ok(uses)
}

fn extend_set_uses(
    result: &mut Vec<MatchUse>,
    sets: &[MatchEndpointSetRef],
    role: EndpointRole,
    base: &str,
) -> Result<(), PolicyRegistryError> {
    for (index, set) in sets.iter().enumerate() {
        result.push(MatchUse {
            set: set.clone(),
            role,
            path: dependency_path(format!("{base}/{index}"))?,
        });
    }
    Ok(())
}

fn parse_policy_bytes(
    identity: PolicySourceIdentity,
    bytes: &[u8],
) -> Result<ParsedRqlpDocument, PolicyRegistryError> {
    if bytes.len() > MAX_RQLP_SOURCE_BYTES {
        return Err(PolicyRegistryError::SourceTooLarge {
            bytes: bytes.len(),
            maximum: MAX_RQLP_SOURCE_BYTES,
        });
    }
    let source = str::from_utf8(bytes).map_err(|error| PolicyRegistryError::InvalidUtf8 {
        source: identity.clone(),
        valid_up_to: error.valid_up_to(),
    })?;
    parse_rqlp_source(source, identity).map_err(Into::into)
}

fn inline_selector(
    path: PolicySelectorPath,
    authored: &PolicySelector,
    origin: SelectorOrigin,
) -> Result<ResolvedPolicySelector, PolicyRegistryError> {
    let PolicySelector::Inline { schema, query } = authored else {
        return Err(PolicyRegistryError::CatalogFileSelector);
    };
    ResolvedPolicySelector::try_new(path, *schema, query.clone(), origin).map_err(Into::into)
}

fn catalog_selector(
    catalog: &RegisteredTaintCatalog,
    entry_id: &TaintEntryId,
) -> Result<(ResolvedCatalogIdentity, ResolvedPolicySelector), PolicyRegistryError> {
    let identity = resolved_catalog_identity(catalog)?;
    let entry = catalog
        .definition()
        .sources
        .iter()
        .find(|entry| entry.id == *entry_id)
        .map(|entry| &entry.selector)
        .or_else(|| {
            catalog
                .definition()
                .sinks
                .iter()
                .find(|entry| entry.id == *entry_id)
                .map(|entry| &entry.selector)
        })
        .ok_or_else(|| PolicyRegistryError::CatalogEntryMissing {
            catalog: identity.clone(),
            entry_id: entry_id.clone(),
        })?;
    let path = selector_path(format!(
        "/dependencies/catalogs/{}@{}/{}/selector",
        pointer_segment(identity.name.as_str()),
        identity.version,
        pointer_segment(entry_id.as_str())
    ))?;
    let selector = inline_selector(
        path,
        entry,
        SelectorOrigin::Catalog {
            catalog: identity.clone(),
        },
    )?;
    Ok((identity, selector))
}

fn resolved_catalog_identity(
    catalog: &RegisteredTaintCatalog,
) -> Result<ResolvedCatalogIdentity, PolicyRegistryError> {
    ResolvedCatalogIdentity::try_new(
        catalog.identity().name.clone(),
        catalog.identity().version,
        catalog.semantic_hash(),
    )
    .map_err(Into::into)
}

fn rekey_endpoint_selector(
    endpoint: &LoadedEndpoint,
) -> Result<ResolvedPolicySelector, PolicyRegistryError> {
    let path = selector_path(format!(
        "/dependencies/match-endpoints/{}/selector",
        pointer_segment(endpoint.definition().id.as_str())
    ))?;
    ResolvedPolicySelector::try_new(
        path,
        endpoint.resolved_selector().schema_resolution,
        endpoint.resolved_selector().query.clone(),
        endpoint.resolved_selector().origin.clone(),
    )
    .map_err(Into::into)
}

fn dependency_from_loaded_endpoint(
    endpoint: &LoadedEndpoint,
    selector: &ResolvedPolicySelector,
    origin: EndpointOrigin,
) -> Result<ResolvedEndpointDependency, PolicyRegistryError> {
    let supersedes = endpoint
        .definition()
        .supersedes
        .iter()
        .cloned()
        .map(|endpoint_id| ResolvedEndpointIdentity::MatchEndpoint { endpoint_id })
        .collect();
    ResolvedEndpointDependency::from_loaded_match_endpoint(
        endpoint,
        selector,
        supersedes,
        vec![origin],
    )
    .map_err(Into::into)
}

fn insert_selector(
    selectors: &mut BTreeMap<PolicySelectorPath, ResolvedPolicySelector>,
    selector: ResolvedPolicySelector,
) -> Result<(), PolicyRegistryError> {
    if let Some(existing) = selectors.get(&selector.path) {
        if existing.schema_resolution.version == selector.schema_resolution.version
            && existing.semantic_hash == selector.semantic_hash
            && existing.query.to_canonical_query_plan_json()
                == selector.query.to_canonical_query_plan_json()
        {
            return Ok(());
        }
        return Err(PolicyRegistryError::SelectorPathCollision {
            path: selector.path,
        });
    }
    selectors.insert(selector.path.clone(), selector);
    Ok(())
}

fn category_matches(predicate: &CategoryPredicate, categories: &[PolicyCategoryId]) -> bool {
    match predicate {
        CategoryPredicate::Any {
            categories: expected,
        } => expected
            .iter()
            .any(|category| categories.contains(category)),
        CategoryPredicate::All {
            categories: expected,
        } => expected
            .iter()
            .all(|category| categories.contains(category)),
    }
}

fn merge_match_dependency(
    dependencies: &mut BTreeMap<ResolvedEndpointIdentity, ResolvedEndpointDependency>,
    mut incoming: ResolvedEndpointDependency,
) -> Result<(), PolicyRegistryError> {
    let Some(existing) = dependencies.get_mut(&incoming.identity) else {
        dependencies.insert(incoming.identity.clone(), incoming);
        return Ok(());
    };
    if existing.semantic_hash != incoming.semantic_hash
        || existing.analysis_projection_hash != incoming.analysis_projection_hash
        || existing.definition_schema.version() != incoming.definition_schema.version()
        || existing.selector_path != incoming.selector_path
        || existing.selector_schema.version != incoming.selector_schema.version
        || existing.model != incoming.model
    {
        return Err(PolicyRegistryError::EndpointIdentityCollision {
            identity: incoming.identity,
        });
    }
    existing.origins.append(&mut incoming.origins);
    existing.origins.sort();
    existing.origins.dedup();
    let maximum = CompositionLimits::default().max_origins_per_endpoint();
    if existing.origins.len() > maximum {
        return Err(PolicyRegistryError::EndpointOriginLimitExceeded {
            identity: existing.identity.clone(),
            found: existing.origins.len(),
            maximum,
        });
    }
    Ok(())
}

const fn directory_scope_rank(scope: DirectoryScope) -> u8 {
    match scope {
        DirectoryScope::Direct => 0,
        DirectoryScope::Recursive => 1,
    }
}

fn selector_path(path: impl AsRef<str>) -> Result<PolicySelectorPath, PolicyRegistryError> {
    PolicySelectorPath::new(path).map_err(Into::into)
}

fn dependency_path(path: impl AsRef<str>) -> Result<PolicyDependencyPath, PolicyRegistryError> {
    PolicyDependencyPath::new(path)
        .map_err(|error| PolicyRegistryError::SelectorPath(Box::new(error)))
}

fn pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn port_to_endpoint_binding(port: &PolicyPort) -> PolicyEndpointBinding {
    match port {
        PolicyPort::MatchedValue => PolicyEndpointBinding::MatchedValue,
        PolicyPort::Receiver => PolicyEndpointBinding::Receiver,
        PolicyPort::ReturnValue => PolicyEndpointBinding::ReturnValue,
        PolicyPort::ArgumentIndex { index } => {
            PolicyEndpointBinding::ArgumentIndex { index: *index }
        }
        PolicyPort::ArgumentName { name } => {
            PolicyEndpointBinding::ArgumentName { name: name.clone() }
        }
    }
}

fn seed_to_endpoint_binding(binding: &TypestateSeedBinding) -> PolicyEndpointBinding {
    match binding {
        TypestateSeedBinding::MatchedValue => PolicyEndpointBinding::MatchedValue,
        TypestateSeedBinding::Receiver => PolicyEndpointBinding::Receiver,
        TypestateSeedBinding::ReturnValue => PolicyEndpointBinding::ReturnValue,
        TypestateSeedBinding::ArgumentIndex { index } => {
            PolicyEndpointBinding::ArgumentIndex { index: *index }
        }
        TypestateSeedBinding::ArgumentName { name } => {
            PolicyEndpointBinding::ArgumentName { name: name.clone() }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDocumentKind {
    Policy,
    Endpoint,
}

impl fmt::Display for PolicyDocumentKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Policy => "policy",
            Self::Endpoint => "endpoint",
        })
    }
}

#[derive(Debug)]
pub enum PolicyRegistryError {
    WorkspaceRootMustBeAbsolute,
    WorkspaceAccessUnavailable,
    Workspace(Box<WorkspaceDocumentError>),
    InvalidSourceIdentity(PolicySourceIdentityError),
    SourceTooLarge {
        bytes: usize,
        maximum: usize,
    },
    InvalidUtf8 {
        source: PolicySourceIdentity,
        valid_up_to: usize,
    },
    Source(Box<PolicySourceError>),
    DocumentLoad {
        message: String,
    },
    EndpointClosure {
        message: String,
    },
    SelectorLoad {
        message: String,
    },
    Directory {
        message: String,
    },
    MatchDirectoryLimits {
        message: String,
    },
    Composition {
        message: String,
    },
    Model(Box<LoadedModelError>),
    SelectorPath(Box<PolicySelectorPathError>),
    Catalog(Box<super::catalog::CatalogRegistryError>),
    WrongDocumentKind {
        expected: PolicyDocumentKind,
    },
    DuplicatePolicyId {
        policy_id: PolicyId,
    },
    DuplicateEndpointId {
        endpoint_id: EndpointId,
    },
    PolicyLimitExceeded {
        attempted: usize,
        maximum: usize,
    },
    EndpointLimitExceeded {
        attempted: usize,
        maximum: usize,
    },
    MatchDirectoryLimitExceeded {
        found: usize,
        maximum: usize,
    },
    MatchDirectoryCandidateLimitExceeded {
        found: usize,
        maximum: usize,
    },
    RetainedByteLimitExceeded {
        attempted: usize,
        maximum: usize,
    },
    MatchDirectoryManifestMismatch {
        directory: WorkspaceRelativePath,
        expected: MatchSetManifestHash,
        actual: MatchSetManifestHash,
    },
    CatalogFileSelector,
    CatalogEntryMissing {
        catalog: ResolvedCatalogIdentity,
        entry_id: TaintEntryId,
    },
    SelectorPathCollision {
        path: PolicySelectorPath,
    },
    MissingDependencySelector {
        path: PolicySelectorPath,
    },
    DependencySelectorMismatch {
        path: PolicySelectorPath,
    },
    EndpointIdentityCollision {
        identity: ResolvedEndpointIdentity,
    },
    EndpointOriginLimitExceeded {
        identity: ResolvedEndpointIdentity,
        found: usize,
        maximum: usize,
    },
    PolicyCountOverflow,
    EndpointCountOverflow,
    RetainedByteCountOverflow,
}

impl fmt::Display for PolicyRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceRootMustBeAbsolute => {
                formatter.write_str("policy workspace root must be absolute")
            }
            Self::WorkspaceAccessUnavailable => formatter
                .write_str("policy registry has no workspace authority for this path or reference"),
            Self::Workspace(error) => error.fmt(formatter),
            Self::InvalidSourceIdentity(error) => error.fmt(formatter),
            Self::SourceTooLarge { bytes, maximum } => write!(
                formatter,
                "RQLP source contains {bytes} bytes; maximum is {maximum}"
            ),
            Self::InvalidUtf8 {
                source,
                valid_up_to,
            } => write!(
                formatter,
                "RQLP source `{source}` is not UTF-8 at byte {valid_up_to}"
            ),
            Self::Source(error) => error.fmt(formatter),
            Self::DocumentLoad { message }
            | Self::EndpointClosure { message }
            | Self::SelectorLoad { message }
            | Self::Directory { message }
            | Self::MatchDirectoryLimits { message } => formatter.write_str(message),
            Self::Composition { message } => formatter.write_str(message),
            Self::Model(error) => error.fmt(formatter),
            Self::SelectorPath(error) => error.fmt(formatter),
            Self::Catalog(error) => error.fmt(formatter),
            Self::WrongDocumentKind { expected } => {
                write!(formatter, "registration requires a {expected} document")
            }
            Self::DuplicatePolicyId { policy_id } => {
                write!(formatter, "policy ID `{policy_id}` is already registered")
            }
            Self::DuplicateEndpointId { endpoint_id } => {
                write!(
                    formatter,
                    "endpoint ID `{endpoint_id}` is already registered"
                )
            }
            Self::PolicyLimitExceeded { attempted, maximum } => write!(
                formatter,
                "policy registry would contain {attempted} policies; maximum is {maximum}"
            ),
            Self::EndpointLimitExceeded { attempted, maximum } => write!(
                formatter,
                "policy registry would retain {attempted} endpoint values; maximum is {maximum}"
            ),
            Self::MatchDirectoryLimitExceeded { found, maximum } => write!(
                formatter,
                "policy contains {found} match-directory references; maximum is {maximum}"
            ),
            Self::MatchDirectoryCandidateLimitExceeded { found, maximum } => write!(
                formatter,
                "policy match directories contain {found} candidates; maximum is {maximum}"
            ),
            Self::RetainedByteLimitExceeded { attempted, maximum } => write!(
                formatter,
                "policy registry would retain {attempted} source/selector bytes; maximum is {maximum}"
            ),
            Self::MatchDirectoryManifestMismatch {
                directory,
                expected,
                actual,
            } => write!(
                formatter,
                "match-directory `{directory}` manifest pin {expected} does not match {actual}"
            ),
            Self::CatalogFileSelector => {
                formatter.write_str("catalog entries must use inline RQL selectors")
            }
            Self::CatalogEntryMissing { catalog, entry_id } => write!(
                formatter,
                "catalog {} version {} has no endpoint entry `{entry_id}`",
                catalog.name, catalog.version
            ),
            Self::SelectorPathCollision { path } => write!(
                formatter,
                "resolved selector path {path} has conflicting definitions"
            ),
            Self::MissingDependencySelector { path } => {
                write!(
                    formatter,
                    "resolved endpoint dependency is missing selector {path}"
                )
            }
            Self::DependencySelectorMismatch { path } => write!(
                formatter,
                "resolved endpoint dependency selector {path} disagrees with its dependency"
            ),
            Self::EndpointIdentityCollision { identity } => write!(
                formatter,
                "resolved endpoint identity {identity:?} has conflicting definitions"
            ),
            Self::EndpointOriginLimitExceeded {
                identity,
                found,
                maximum,
            } => write!(
                formatter,
                "resolved endpoint {identity:?} has {found} origins; maximum is {maximum}"
            ),
            Self::PolicyCountOverflow => formatter.write_str("policy count overflowed"),
            Self::EndpointCountOverflow => formatter.write_str("endpoint count overflowed"),
            Self::RetainedByteCountOverflow => {
                formatter.write_str("retained source/selector byte count overflowed")
            }
        }
    }
}

impl std::error::Error for PolicyRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error.as_ref()),
            Self::InvalidSourceIdentity(error) => Some(error),
            Self::Source(error) => Some(error.as_ref()),
            Self::Model(error) => Some(error.as_ref()),
            Self::SelectorPath(error) => Some(error.as_ref()),
            Self::Catalog(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

macro_rules! boxed_error_conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for PolicyRegistryError {
            fn from(error: $source) -> Self {
                Self::$variant(Box::new(error))
            }
        }
    };
}

boxed_error_conversion!(WorkspaceDocumentError, Workspace);
boxed_error_conversion!(PolicySourceError, Source);
boxed_error_conversion!(LoadedModelError, Model);
boxed_error_conversion!(PolicySelectorPathError, SelectorPath);
boxed_error_conversion!(super::catalog::CatalogRegistryError, Catalog);

impl From<MatchDirectoryLimitError> for PolicyRegistryError {
    fn from(error: MatchDirectoryLimitError) -> Self {
        Self::MatchDirectoryLimits {
            message: error.to_string(),
        }
    }
}

impl From<CompositionError> for PolicyRegistryError {
    fn from(error: CompositionError) -> Self {
        Self::Composition {
            message: error.to_string(),
        }
    }
}

impl From<PolicyDocumentLoadError> for PolicyRegistryError {
    fn from(error: PolicyDocumentLoadError) -> Self {
        match error {
            PolicyDocumentLoadError::InvalidSourceIdentity { source, .. } => source.into(),
            error => Self::DocumentLoad {
                message: error.to_string(),
            },
        }
    }
}

impl From<EndpointClosureError> for PolicyRegistryError {
    fn from(error: EndpointClosureError) -> Self {
        Self::EndpointClosure {
            message: error.to_string(),
        }
    }
}

impl From<SelectorLoadError> for PolicyRegistryError {
    fn from(error: SelectorLoadError) -> Self {
        Self::SelectorLoad {
            message: error.to_string(),
        }
    }
}

impl From<EndpointDirectoryError> for PolicyRegistryError {
    fn from(error: EndpointDirectoryError) -> Self {
        let message = error.to_string();
        match error {
            EndpointDirectoryError::DepthExceeded { .. }
            | EndpointDirectoryError::CandidateLimitExceeded { .. }
            | EndpointDirectoryError::EntryLimitExceeded { .. }
            | EndpointDirectoryError::SourceByteLimitExceeded { .. } => {
                Self::MatchDirectoryLimits { message }
            }
            _ => Self::Directory { message },
        }
    }
}

impl From<PolicySourceIdentityError> for PolicyRegistryError {
    fn from(error: PolicySourceIdentityError) -> Self {
        Self::InvalidSourceIdentity(error)
    }
}
