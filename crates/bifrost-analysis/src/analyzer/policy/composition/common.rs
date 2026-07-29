//! Shared finite endpoint selection and composition invariants.

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::precedence::{PrecedenceError, PrecedenceGraph};
use crate::analyzer::policy::catalog::{
    CatalogRegistryError, TaintCatalogRegistry, endpoint_binding_to_port, phase_accepts_port,
    typestate_call_binding_to_port,
};
use crate::analyzer::policy::definition::*;
use crate::analyzer::policy::resolved::*;
use crate::schema_version::SchemaVersionOrigin;

pub(crate) const MAX_RESOLVED_ENDPOINTS_PER_ROLE: usize = 4_096;
pub(crate) const MAX_ENDPOINT_ORIGINS: usize = 256;
pub(crate) const MAX_FINDING_COMBINATIONS: usize = 256;
pub(crate) const MAX_RESOLVED_PREDICATE_ENDPOINTS: usize = 4_096;
pub(crate) const MAX_TYPESTATE_EVENTS: usize = 256;
pub(crate) const MAX_TYPESTATE_EXPECTATIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompositionLimits {
    max_endpoints_per_role: usize,
    max_origins_per_endpoint: usize,
    max_finding_combinations: usize,
    max_predicate_endpoints: usize,
    max_typestate_events: usize,
    max_typestate_expectations: usize,
}

impl Default for CompositionLimits {
    fn default() -> Self {
        Self {
            max_endpoints_per_role: MAX_RESOLVED_ENDPOINTS_PER_ROLE,
            max_origins_per_endpoint: MAX_ENDPOINT_ORIGINS,
            max_finding_combinations: MAX_FINDING_COMBINATIONS,
            max_predicate_endpoints: MAX_RESOLVED_PREDICATE_ENDPOINTS,
            max_typestate_events: MAX_TYPESTATE_EVENTS,
            max_typestate_expectations: MAX_TYPESTATE_EXPECTATIONS,
        }
    }
}

impl CompositionLimits {
    pub(crate) const fn max_endpoints_per_role(self) -> usize {
        self.max_endpoints_per_role
    }

    pub(crate) const fn max_origins_per_endpoint(self) -> usize {
        self.max_origins_per_endpoint
    }

    pub(crate) const fn max_finding_combinations(self) -> usize {
        self.max_finding_combinations
    }

    pub(crate) const fn max_typestate_events(self) -> usize {
        self.max_typestate_events
    }

    pub(crate) const fn max_typestate_expectations(self) -> usize {
        self.max_typestate_expectations
    }

    pub(crate) fn with_max_endpoints_per_role(
        mut self,
        value: usize,
    ) -> Result<Self, CompositionError> {
        validate_lowered_limit(
            "max_endpoints_per_role",
            value,
            MAX_RESOLVED_ENDPOINTS_PER_ROLE,
        )?;
        self.max_endpoints_per_role = value;
        Ok(self)
    }

    pub(crate) fn with_max_predicate_endpoints(
        mut self,
        value: usize,
    ) -> Result<Self, CompositionError> {
        validate_lowered_limit(
            "max_predicate_endpoints",
            value,
            MAX_RESOLVED_PREDICATE_ENDPOINTS,
        )?;
        self.max_predicate_endpoints = value;
        Ok(self)
    }
}

fn validate_lowered_limit(
    field: &'static str,
    value: usize,
    hard_maximum: usize,
) -> Result<(), CompositionError> {
    if value == 0 || value > hard_maximum {
        return Err(CompositionError::InvalidLimit {
            field,
            value,
            hard_maximum,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionError {
    InvalidLimit {
        field: &'static str,
        value: usize,
        hard_maximum: usize,
    },
    EndpointLimit {
        role: EndpointRole,
        found: usize,
        maximum: usize,
    },
    OriginLimit {
        identity: ResolvedEndpointIdentity,
        found: usize,
        maximum: usize,
    },
    EndpointIdentityCollision {
        identity: ResolvedEndpointIdentity,
    },
    EndpointHashCollision {
        identity: ResolvedEndpointIdentity,
    },
    DuplicateExactEndpointId {
        endpoint_id: EndpointId,
    },
    ExpectedMatchEndpointIdentity {
        identity: ResolvedEndpointIdentity,
    },
    UnknownExactEndpoint {
        endpoint_id: EndpointId,
    },
    MissingMatchManifest {
        directory: String,
        role: EndpointRole,
    },
    ManifestPinMismatch {
        directory: String,
        expected: MatchSetManifestHash,
        actual: MatchSetManifestHash,
    },
    DuplicateManifestEndpoint {
        path: PolicyDependencyPath,
        identity: ResolvedEndpointIdentity,
    },
    ManifestEndpointMissing {
        path: PolicyDependencyPath,
        identity: ResolvedEndpointIdentity,
    },
    ManifestEndpointMismatch {
        path: PolicyDependencyPath,
        identity: ResolvedEndpointIdentity,
    },
    EndpointRoleMismatch {
        identity: ResolvedEndpointIdentity,
        expected: EndpointRole,
        actual: EndpointRole,
    },
    EndpointMissingOrMismatchedTaintSemantics {
        identity: ResolvedEndpointIdentity,
        expected: EndpointRole,
    },
    CategoryPredicateEmpty,
    CategoryPredicateDuplicate {
        category: PolicyCategoryId,
    },
    PredicateEndpointLimit {
        found: usize,
        maximum: usize,
    },
    EmptyPredicateSelection,
    DuplicatePredicateEndpoint {
        identity: ResolvedEndpointIdentity,
    },
    DanglingEndpointReference {
        identity: ResolvedEndpointIdentity,
    },
    MissingLocalEndpointDependency {
        identity: ResolvedEndpointIdentity,
    },
    MissingCatalogEndpointDependency {
        identity: ResolvedEndpointIdentity,
    },
    EmptyResolvedEndpointSet {
        role: EndpointRole,
    },
    UnsupportedMatchComposition {
        set: &'static str,
    },
    Catalog(CatalogRegistryError),
    EndpointPrecedence(String),
    FindingCombinationPrecedence(String),
    TypestateEventPrecedence(String),
    TypestateExpectationPrecedence(String),
    DuplicateComposedEntry {
        kind: &'static str,
        id: TaintEntryId,
    },
    InvalidObservationPhase {
        phase: EndpointObservationPhase,
        port: PolicyPort,
    },
    InvalidTypestateAutomaton(String),
    LoadedModel(String),
}

impl fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit {
                field,
                value,
                hard_maximum,
            } => write!(
                formatter,
                "{field} must be from 1 through {hard_maximum}, found {value}"
            ),
            Self::EndpointLimit {
                role,
                found,
                maximum,
            } => write!(
                formatter,
                "resolved {role:?} endpoint set contains {found} entries; limit is {maximum}"
            ),
            Self::OriginLimit {
                identity,
                found,
                maximum,
            } => write!(
                formatter,
                "endpoint {identity:?} has {found} origins; limit is {maximum}"
            ),
            Self::EndpointIdentityCollision { identity } => {
                write!(
                    formatter,
                    "endpoint identity {identity:?} has conflicting semantic hashes"
                )
            }
            Self::EndpointHashCollision { identity } => {
                write!(
                    formatter,
                    "endpoint identity {identity:?} has equal hashes but conflicting models"
                )
            }
            Self::DuplicateExactEndpointId { endpoint_id } => {
                write!(formatter, "exact endpoint selection repeats {endpoint_id}")
            }
            Self::ExpectedMatchEndpointIdentity { identity } => write!(
                formatter,
                "scanned endpoint collection contains non-match identity {identity:?}"
            ),
            Self::UnknownExactEndpoint { endpoint_id } => {
                write!(formatter, "exact endpoint {endpoint_id} is not registered")
            }
            Self::MissingMatchManifest { directory, role } => write!(
                formatter,
                "no resolved {role:?} match manifest exists for {directory}"
            ),
            Self::ManifestPinMismatch {
                directory,
                expected,
                actual,
            } => write!(
                formatter,
                "match manifest for {directory} has hash {actual}, not pinned hash {expected}"
            ),
            Self::DuplicateManifestEndpoint { path, identity } => {
                write!(
                    formatter,
                    "match manifest {path} repeats endpoint {identity:?}"
                )
            }
            Self::ManifestEndpointMissing { path, identity } => {
                write!(
                    formatter,
                    "match manifest {path} names unavailable endpoint {identity:?}"
                )
            }
            Self::ManifestEndpointMismatch { path, identity } => write!(
                formatter,
                "match manifest {path} disagrees with loaded endpoint {identity:?}"
            ),
            Self::EndpointRoleMismatch {
                identity,
                expected,
                actual,
            } => write!(
                formatter,
                "endpoint {identity:?} has role {actual:?}, expected {expected:?}"
            ),
            Self::EndpointMissingOrMismatchedTaintSemantics { identity, expected } => write!(
                formatter,
                "endpoint {identity:?} lacks {expected:?} taint semantics"
            ),
            Self::CategoryPredicateEmpty => {
                formatter.write_str("category predicate must contain at least one category")
            }
            Self::CategoryPredicateDuplicate { category } => {
                write!(formatter, "category predicate repeats {category}")
            }
            Self::PredicateEndpointLimit { found, maximum } => write!(
                formatter,
                "endpoint predicate resolves to {found} endpoints; limit is {maximum}"
            ),
            Self::EmptyPredicateSelection => {
                formatter.write_str("endpoint predicate resolves to an empty set")
            }
            Self::DuplicatePredicateEndpoint { identity } => {
                write!(formatter, "endpoint predicate repeats {identity:?}")
            }
            Self::DanglingEndpointReference { identity } => {
                write!(
                    formatter,
                    "endpoint predicate names unselected endpoint {identity:?}"
                )
            }
            Self::MissingLocalEndpointDependency { identity } => {
                write!(
                    formatter,
                    "local endpoint dependency {identity:?} was not loaded"
                )
            }
            Self::MissingCatalogEndpointDependency { identity } => {
                write!(
                    formatter,
                    "catalog endpoint dependency {identity:?} was not loaded"
                )
            }
            Self::EmptyResolvedEndpointSet { role } => {
                write!(
                    formatter,
                    "resolved {role:?} endpoint set must not be empty"
                )
            }
            Self::UnsupportedMatchComposition { set } => {
                write!(
                    formatter,
                    "{set} cannot include match endpoint sets in schema version 1"
                )
            }
            Self::Catalog(error) => error.fmt(formatter),
            Self::EndpointPrecedence(message)
            | Self::FindingCombinationPrecedence(message)
            | Self::TypestateEventPrecedence(message)
            | Self::TypestateExpectationPrecedence(message)
            | Self::InvalidTypestateAutomaton(message)
            | Self::LoadedModel(message) => formatter.write_str(message),
            Self::DuplicateComposedEntry { kind, id } => {
                write!(formatter, "composed {kind} entry repeats ID {id}")
            }
            Self::InvalidObservationPhase { phase, port } => write!(
                formatter,
                "observation phase {phase:?} is invalid for binding {port:?}"
            ),
        }
    }
}

impl std::error::Error for CompositionError {}

impl From<CatalogRegistryError> for CompositionError {
    fn from(error: CatalogRegistryError) -> Self {
        Self::Catalog(error)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EndpointUniverse {
    dependencies: Vec<ResolvedEndpointDependency>,
    positions: HashMap<ResolvedEndpointIdentity, usize>,
    exact_match_positions: HashMap<EndpointId, usize>,
    limits: CompositionLimits,
}

impl EndpointUniverse {
    pub(crate) fn try_new(
        dependencies: &[ResolvedEndpointDependency],
        limits: CompositionLimits,
    ) -> Result<Self, CompositionError> {
        let mut dependencies = dependencies.to_vec();
        dependencies.sort_by(|left, right| {
            left.identity
                .cmp(&right.identity)
                .then_with(|| {
                    definition_resolution_key(&left.definition_schema)
                        .cmp(&definition_resolution_key(&right.definition_schema))
                })
                .then_with(|| {
                    (
                        left.selector_schema.version,
                        origin_rank(left.selector_schema.origin),
                    )
                        .cmp(&(
                            right.selector_schema.version,
                            origin_rank(right.selector_schema.origin),
                        ))
                })
                .then_with(|| left.selector_path.cmp(&right.selector_path))
        });
        let mut merged: Vec<ResolvedEndpointDependency> = Vec::with_capacity(dependencies.len());
        for dependency in dependencies {
            if let Some(existing) = merged.last_mut()
                && existing.identity == dependency.identity
            {
                if existing.semantic_hash != dependency.semantic_hash
                    || existing.analysis_projection_hash != dependency.analysis_projection_hash
                {
                    return Err(CompositionError::EndpointIdentityCollision {
                        identity: dependency.identity,
                    });
                }
                // Version origin is provenance. Explicit and compatible
                // omitted pins resolving to the same effective version must
                // compose idempotently when the semantic hashes agree.
                if existing.definition_schema.version() != dependency.definition_schema.version()
                    || existing.selector_path != dependency.selector_path
                    || existing.selector_schema.version != dependency.selector_schema.version
                    || existing.model != dependency.model
                {
                    return Err(CompositionError::EndpointHashCollision {
                        identity: dependency.identity,
                    });
                }
                existing.origins.extend(dependency.origins);
                existing.origins.sort();
                existing.origins.dedup();
                if existing.origins.len() > limits.max_origins_per_endpoint {
                    return Err(CompositionError::OriginLimit {
                        identity: existing.identity.clone(),
                        found: existing.origins.len(),
                        maximum: limits.max_origins_per_endpoint,
                    });
                }
                continue;
            }
            if dependency.origins.len() > limits.max_origins_per_endpoint {
                return Err(CompositionError::OriginLimit {
                    identity: dependency.identity,
                    found: dependency.origins.len(),
                    maximum: limits.max_origins_per_endpoint,
                });
            }
            merged.push(dependency);
        }

        let positions = merged
            .iter()
            .enumerate()
            .map(|(index, dependency)| (dependency.identity.clone(), index))
            .collect();
        let mut exact_match_positions = HashMap::new();
        for (index, dependency) in merged.iter().enumerate() {
            if let ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } = &dependency.identity
                && exact_match_positions
                    .insert(endpoint_id.clone(), index)
                    .is_some()
            {
                return Err(CompositionError::DuplicateExactEndpointId {
                    endpoint_id: endpoint_id.clone(),
                });
            }
        }
        Ok(Self {
            dependencies: merged,
            positions,
            exact_match_positions,
            limits,
        })
    }

    pub(crate) fn get(
        &self,
        identity: &ResolvedEndpointIdentity,
    ) -> Option<&ResolvedEndpointDependency> {
        self.positions
            .get(identity)
            .map(|index| &self.dependencies[*index])
    }

    pub(crate) fn dependencies_for(
        &self,
        identities: &[ResolvedEndpointIdentity],
    ) -> Vec<ResolvedEndpointDependency> {
        identities
            .iter()
            .filter_map(|identity| self.get(identity).cloned())
            .collect()
    }

    pub(crate) fn select_match_set(
        &self,
        set: &MatchEndpointSetRef,
        expected_role: EndpointRole,
        require_taint: bool,
        manifests: &[ResolvedMatchDirectoryManifest],
    ) -> Result<MatchSelection, CompositionError> {
        let (mut identities, mut selected_manifests) = match set {
            MatchEndpointSetRef::Exact { endpoint_ids } => {
                if endpoint_ids.is_empty() {
                    return Err(CompositionError::EmptyPredicateSelection);
                }
                if endpoint_ids.len() > self.limits.max_predicate_endpoints {
                    return Err(CompositionError::PredicateEndpointLimit {
                        found: endpoint_ids.len(),
                        maximum: self.limits.max_predicate_endpoints,
                    });
                }
                let mut seen = HashSet::with_capacity(endpoint_ids.len());
                let mut identities = Vec::with_capacity(endpoint_ids.len());
                for endpoint_id in endpoint_ids {
                    if !seen.insert(endpoint_id) {
                        return Err(CompositionError::DuplicateExactEndpointId {
                            endpoint_id: endpoint_id.clone(),
                        });
                    }
                    let Some(index) = self.exact_match_positions.get(endpoint_id) else {
                        return Err(CompositionError::UnknownExactEndpoint {
                            endpoint_id: endpoint_id.clone(),
                        });
                    };
                    identities.push(self.dependencies[*index].identity.clone());
                }
                (identities, Vec::new())
            }
            MatchEndpointSetRef::Directory { reference } => {
                validate_category_predicate(&reference.categories)?;
                let mut matching: Vec<_> = manifests
                    .iter()
                    .filter(|manifest| {
                        manifest.directory == reference.path
                            && manifest.scope == reference.scope
                            && manifest.role == Some(expected_role)
                            && equivalent_category_predicates(
                                &manifest.categories,
                                &reference.categories,
                            )
                    })
                    .cloned()
                    .collect();
                matching.sort_by(|left, right| left.path.cmp(&right.path));
                if matching.is_empty() {
                    return Err(CompositionError::MissingMatchManifest {
                        directory: reference.path.as_str().to_string(),
                        role: expected_role,
                    });
                }
                let mut identities = Vec::new();
                for manifest in &matching {
                    if let Some(expected) = reference.manifest_sha256
                        && expected != manifest.semantic_hash
                    {
                        return Err(CompositionError::ManifestPinMismatch {
                            directory: reference.path.as_str().to_string(),
                            expected,
                            actual: manifest.semantic_hash,
                        });
                    }
                    let mut seen = HashSet::with_capacity(manifest.selected.len());
                    for entry in &manifest.selected {
                        if !seen.insert(&entry.identity) {
                            return Err(CompositionError::DuplicateManifestEndpoint {
                                path: manifest.path.clone(),
                                identity: entry.identity.clone(),
                            });
                        }
                        let dependency = self.get(&entry.identity).ok_or_else(|| {
                            CompositionError::ManifestEndpointMissing {
                                path: manifest.path.clone(),
                                identity: entry.identity.clone(),
                            }
                        })?;
                        if dependency.definition_schema.version()
                            != entry.definition_schema.version()
                            || dependency.selector_schema.version != entry.selector_schema.version
                            || dependency.semantic_hash != entry.semantic_hash
                            || dependency.analysis_projection_hash != entry.analysis_projection_hash
                        {
                            return Err(CompositionError::ManifestEndpointMismatch {
                                path: manifest.path.clone(),
                                identity: entry.identity.clone(),
                            });
                        }
                        if !category_predicate_matches(
                            &reference.categories,
                            &dependency.model.categories,
                        ) {
                            return Err(CompositionError::ManifestEndpointMismatch {
                                path: manifest.path.clone(),
                                identity: entry.identity.clone(),
                            });
                        }
                        identities.push(entry.identity.clone());
                    }
                }
                (identities, matching)
            }
        };

        identities.sort();
        identities.dedup();
        if identities.len() > self.limits.max_endpoints_per_role {
            return Err(CompositionError::EndpointLimit {
                role: expected_role,
                found: identities.len(),
                maximum: self.limits.max_endpoints_per_role,
            });
        }
        for identity in &identities {
            self.validate_role_and_taint(identity, expected_role, require_taint)?;
        }
        selected_manifests.sort_by(|left, right| left.path.cmp(&right.path));
        selected_manifests.dedup_by(|left, right| left.path == right.path);
        Ok(MatchSelection {
            identities,
            manifests: selected_manifests,
        })
    }

    pub(crate) fn validate_role_and_taint(
        &self,
        identity: &ResolvedEndpointIdentity,
        expected_role: EndpointRole,
        require_taint: bool,
    ) -> Result<&ResolvedEndpointDependency, CompositionError> {
        let dependency =
            self.get(identity)
                .ok_or_else(|| CompositionError::DanglingEndpointReference {
                    identity: identity.clone(),
                })?;
        if dependency.model.role != expected_role {
            return Err(CompositionError::EndpointRoleMismatch {
                identity: identity.clone(),
                expected: expected_role,
                actual: dependency.model.role,
            });
        }
        if require_taint {
            let matches = matches!(
                (&dependency.model.taint, expected_role),
                (Some(EndpointTaintSemantics::Source { labels, .. }), EndpointRole::Source)
                    if !labels.is_empty()
            ) || matches!(
                (&dependency.model.taint, expected_role),
                (Some(EndpointTaintSemantics::Sink { accepts, .. }), EndpointRole::Sink)
                    if !accepts.is_empty()
            );
            if !matches {
                return Err(
                    CompositionError::EndpointMissingOrMismatchedTaintSemantics {
                        identity: identity.clone(),
                        expected: expected_role,
                    },
                );
            }
        }
        Ok(dependency)
    }

    pub(crate) fn validate_observation(
        &self,
        identity: &ResolvedEndpointIdentity,
        phase: EndpointObservationPhase,
    ) -> Result<(), CompositionError> {
        let dependency =
            self.get(identity)
                .ok_or_else(|| CompositionError::DanglingEndpointReference {
                    identity: identity.clone(),
                })?;
        let port = endpoint_binding_to_port(&dependency.model.binding);
        validate_phase(phase, &port)
    }
}

fn definition_resolution_key(resolution: &EndpointDefinitionSchemaResolution) -> (u8, u32, u8) {
    match resolution {
        EndpointDefinitionSchemaResolution::PolicyDocument { resolution } => {
            (0, resolution.version, origin_rank(resolution.origin))
        }
        EndpointDefinitionSchemaResolution::CatalogDocument { schema_version } => {
            (1, *schema_version, 0)
        }
    }
}

fn origin_rank(origin: SchemaVersionOrigin) -> u8 {
    match origin {
        SchemaVersionOrigin::Explicit => 0,
        SchemaVersionOrigin::ReferencedDocumentExplicit => 1,
        SchemaVersionOrigin::ImplicitCompatible => 2,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MatchSelection {
    pub identities: Vec<ResolvedEndpointIdentity>,
    pub manifests: Vec<ResolvedMatchDirectoryManifest>,
}

pub(crate) fn resolved_catalog_identity(
    catalogs: &TaintCatalogRegistry,
    reference: &CatalogRef,
) -> Result<ResolvedCatalogIdentity, CompositionError> {
    let catalog = catalogs.resolve(reference)?;
    ResolvedCatalogIdentity::try_new(
        catalog.identity().name.clone(),
        catalog.identity().version,
        catalog.semantic_hash(),
    )
    .map_err(|error| CompositionError::LoadedModel(error.to_string()))
}

pub(crate) fn resolve_endpoint_predicate(
    predicate: &EndpointPredicate,
    policy_id: &PolicyId,
    allowed: &[ResolvedEndpointIdentity],
    universe: &EndpointUniverse,
    catalogs: &TaintCatalogRegistry,
) -> Result<Vec<ResolvedEndpointIdentity>, CompositionError> {
    let allowed_set: HashSet<_> = allowed.iter().cloned().collect();
    let mut selected = match predicate {
        EndpointPredicate::Categories { predicate } => {
            validate_category_predicate(predicate)?;
            allowed
                .iter()
                .filter(|identity| {
                    universe.get(identity).is_some_and(|dependency| {
                        category_predicate_matches(predicate, &dependency.model.categories)
                    })
                })
                .cloned()
                .collect()
        }
        EndpointPredicate::Exact { endpoints } => {
            if endpoints.is_empty() {
                return Err(CompositionError::EmptyPredicateSelection);
            }
            let mut values = Vec::with_capacity(endpoints.len());
            for endpoint in endpoints {
                values.push(match endpoint {
                    EndpointRef::Local { entry_id } => ResolvedEndpointIdentity::Local {
                        policy_id: policy_id.clone(),
                        entry_id: entry_id.clone(),
                    },
                    EndpointRef::Catalog { catalog, entry_id } => {
                        ResolvedEndpointIdentity::Catalog {
                            catalog: resolved_catalog_identity(catalogs, catalog)?,
                            entry_id: entry_id.clone(),
                        }
                    }
                    EndpointRef::MatchEndpoint { endpoint_id } => {
                        ResolvedEndpointIdentity::MatchEndpoint {
                            endpoint_id: endpoint_id.clone(),
                        }
                    }
                });
            }
            values
        }
    };
    if selected.len() > universe.limits.max_predicate_endpoints {
        return Err(CompositionError::PredicateEndpointLimit {
            found: selected.len(),
            maximum: universe.limits.max_predicate_endpoints,
        });
    }
    selected.sort();
    if let Some(pair) = selected.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(CompositionError::DuplicatePredicateEndpoint {
            identity: pair[0].clone(),
        });
    }
    if selected.is_empty() {
        return Err(CompositionError::EmptyPredicateSelection);
    }
    for identity in &selected {
        if !allowed_set.contains(identity) {
            return Err(CompositionError::DanglingEndpointReference {
                identity: identity.clone(),
            });
        }
    }
    Ok(selected)
}

pub(crate) fn validate_endpoint_precedence(
    selected: &[ResolvedEndpointIdentity],
    universe: &EndpointUniverse,
) -> Result<
    (
        PrecedenceGraph<ResolvedEndpointIdentity>,
        Vec<ResolvedPrecedenceEdge>,
    ),
    CompositionError,
> {
    let mut edges = Vec::new();
    for identity in selected {
        let dependency =
            universe
                .get(identity)
                .ok_or_else(|| CompositionError::DanglingEndpointReference {
                    identity: identity.clone(),
                })?;
        for dominated in &dependency.model.supersedes {
            let dominated_dependency = universe.get(dominated).ok_or_else(|| {
                CompositionError::EndpointPrecedence(format!(
                    "endpoint {identity:?} supersedes unavailable endpoint {dominated:?}"
                ))
            })?;
            if dominated_dependency.model.role != dependency.model.role {
                return Err(CompositionError::EndpointRoleMismatch {
                    identity: dominated.clone(),
                    expected: dependency.model.role,
                    actual: dominated_dependency.model.role,
                });
            }
            edges.push((identity.clone(), dominated.clone()));
        }
    }
    let graph = PrecedenceGraph::try_new(selected.iter().cloned(), edges).map_err(
        |error: PrecedenceError<ResolvedEndpointIdentity>| {
            CompositionError::EndpointPrecedence(error.to_string())
        },
    )?;
    let manifest = graph
        .edges()
        .iter()
        .map(|(dominant, dominated)| ResolvedPrecedenceEdge::Endpoint {
            dominant: dominant.clone(),
            dominated: dominated.clone(),
        })
        .collect();
    Ok((graph, manifest))
}

/// Validate one complete scanned endpoint collection before any role/category
/// filter is applied. Duplicate endpoint IDs are rejected even when the bytes
/// are identical, and every supersedes edge is checked against the full
/// collection so filtering cannot hide a malformed document.
pub(crate) fn validate_scanned_endpoint_collection(
    dependencies: &[ResolvedEndpointDependency],
    limits: CompositionLimits,
) -> Result<PolicyPrecedenceManifest, CompositionError> {
    let mut endpoint_ids = HashSet::with_capacity(dependencies.len());
    let mut identities = Vec::with_capacity(dependencies.len());
    for dependency in dependencies {
        let ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } = &dependency.identity else {
            return Err(CompositionError::ExpectedMatchEndpointIdentity {
                identity: dependency.identity.clone(),
            });
        };
        if !endpoint_ids.insert(endpoint_id.clone()) {
            return Err(CompositionError::DuplicateExactEndpointId {
                endpoint_id: endpoint_id.clone(),
            });
        }
        identities.push(dependency.identity.clone());
    }
    let universe = EndpointUniverse::try_new(dependencies, limits)?;
    identities.sort();
    let (_, edges) = validate_endpoint_precedence(&identities, &universe)?;
    Ok(PolicyPrecedenceManifest::new(edges))
}

pub(crate) fn validate_category_predicate(
    predicate: &CategoryPredicate,
) -> Result<(), CompositionError> {
    let categories = match predicate {
        CategoryPredicate::Any { categories } | CategoryPredicate::All { categories } => categories,
    };
    if categories.is_empty() {
        return Err(CompositionError::CategoryPredicateEmpty);
    }
    if categories.len() > MAX_POLICY_SET_ITEMS {
        return Err(CompositionError::PredicateEndpointLimit {
            found: categories.len(),
            maximum: MAX_POLICY_SET_ITEMS,
        });
    }
    let mut categories = categories.clone();
    categories.sort();
    if let Some(pair) = categories.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(CompositionError::CategoryPredicateDuplicate {
            category: pair[0].clone(),
        });
    }
    Ok(())
}

pub(crate) fn category_predicate_matches(
    predicate: &CategoryPredicate,
    endpoint_categories: &[PolicyCategoryId],
) -> bool {
    match predicate {
        CategoryPredicate::Any { categories } => categories
            .iter()
            .any(|category| endpoint_categories.contains(category)),
        CategoryPredicate::All { categories } => categories
            .iter()
            .all(|category| endpoint_categories.contains(category)),
    }
}

fn equivalent_category_predicates(left: &CategoryPredicate, right: &CategoryPredicate) -> bool {
    match (left, right) {
        (
            CategoryPredicate::Any {
                categories: left_categories,
            },
            CategoryPredicate::Any {
                categories: right_categories,
            },
        )
        | (
            CategoryPredicate::All {
                categories: left_categories,
            },
            CategoryPredicate::All {
                categories: right_categories,
            },
        ) => {
            let mut left = left_categories.clone();
            let mut right = right_categories.clone();
            left.sort();
            right.sort();
            left == right
        }
        _ => false,
    }
}

pub(crate) fn validate_phase(
    phase: EndpointObservationPhase,
    port: &PolicyPort,
) -> Result<(), CompositionError> {
    if !phase_accepts_port(phase, port) {
        return Err(CompositionError::InvalidObservationPhase {
            phase,
            port: port.clone(),
        });
    }
    Ok(())
}

pub(crate) fn validate_call_phase(
    phase: EndpointObservationPhase,
    binding: &TypestateCallBinding,
) -> Result<(), CompositionError> {
    validate_phase(phase, &typestate_call_binding_to_port(binding))
}

pub(crate) fn endpoint_binding_to_typestate(
    binding: &PolicyEndpointBinding,
) -> ResolvedTypestateBinding {
    match binding {
        PolicyEndpointBinding::MatchedValue => ResolvedTypestateBinding::MatchedValue,
        PolicyEndpointBinding::Receiver => ResolvedTypestateBinding::Receiver,
        PolicyEndpointBinding::ReturnValue => ResolvedTypestateBinding::ReturnValue,
        PolicyEndpointBinding::ArgumentIndex { index } => {
            ResolvedTypestateBinding::ArgumentIndex { index: *index }
        }
        PolicyEndpointBinding::ArgumentName { name } => {
            ResolvedTypestateBinding::ArgumentName { name: name.clone() }
        }
    }
}

pub(crate) fn policy_port_to_endpoint_binding(port: &PolicyPort) -> PolicyEndpointBinding {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::{EndpointAnalysisProjectionHash, EndpointSemanticHash};
    use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};

    fn category(value: &str) -> PolicyCategoryId {
        PolicyCategoryId::new(value).unwrap()
    }

    fn dependency(
        endpoint_id: &str,
        categories: &[&str],
        definition_origin: SchemaVersionOrigin,
        selector_origin: SchemaVersionOrigin,
        origin_path: &str,
    ) -> ResolvedEndpointDependency {
        ResolvedEndpointDependency::new(
            ResolvedEndpointIdentity::MatchEndpoint {
                endpoint_id: EndpointId::new(endpoint_id).unwrap(),
            },
            EndpointDefinitionSchemaResolution::PolicyDocument {
                resolution: SchemaVersionResolution {
                    version: 1,
                    origin: definition_origin,
                },
            },
            PolicySelectorPath::new(format!(
                "/dependencies/match-endpoints/{endpoint_id}/selector"
            ))
            .unwrap(),
            SchemaVersionResolution {
                version: 2,
                origin: selector_origin,
            },
            ResolvedEndpointModel::new(
                EndpointRole::Source,
                endpoint_id.to_string(),
                categories.iter().map(|value| category(value)).collect(),
                PolicyEndpointBinding::ReturnValue,
                None,
                vec![],
            ),
            EndpointSemanticHash::from_bytes([1; 32]),
            EndpointAnalysisProjectionHash::from_bytes([2; 32]),
            vec![EndpointOrigin::PolicyLocal {
                path: PolicyDependencyPath::new(origin_path).unwrap(),
            }],
        )
    }

    #[test]
    fn equal_effective_versions_merge_explicit_and_implicit_origins() {
        let explicit = dependency(
            "request",
            &["input.user"],
            SchemaVersionOrigin::Explicit,
            SchemaVersionOrigin::Explicit,
            "/origins/explicit",
        );
        let implicit = dependency(
            "request",
            &["input.user"],
            SchemaVersionOrigin::ImplicitCompatible,
            SchemaVersionOrigin::ImplicitCompatible,
            "/origins/implicit",
        );
        let universe =
            EndpointUniverse::try_new(&[implicit, explicit], CompositionLimits::default()).unwrap();
        let identity = ResolvedEndpointIdentity::MatchEndpoint {
            endpoint_id: EndpointId::new("request").unwrap(),
        };
        let dependency = universe.get(&identity).unwrap();
        assert_eq!(dependency.origins.len(), 2);
        let EndpointDefinitionSchemaResolution::PolicyDocument { resolution } =
            &dependency.definition_schema
        else {
            panic!("expected policy definition resolution")
        };
        assert_eq!(resolution.origin, SchemaVersionOrigin::Explicit);
        assert_eq!(
            dependency.selector_schema.origin,
            SchemaVersionOrigin::Explicit
        );
    }

    #[test]
    fn category_any_and_all_select_exact_finite_sets() {
        let both = dependency(
            "both",
            &["input.user", "pii"],
            SchemaVersionOrigin::Explicit,
            SchemaVersionOrigin::Explicit,
            "/origins/both",
        );
        let input = dependency(
            "input",
            &["input.user"],
            SchemaVersionOrigin::Explicit,
            SchemaVersionOrigin::Explicit,
            "/origins/input",
        );
        let allowed = vec![both.identity.clone(), input.identity.clone()];
        let universe =
            EndpointUniverse::try_new(&[both, input], CompositionLimits::default()).unwrap();
        let catalogs = TaintCatalogRegistry::new_without_workspace(Default::default());
        let policy_id = PolicyId::new("test.policy").unwrap();

        let any = resolve_endpoint_predicate(
            &EndpointPredicate::Categories {
                predicate: CategoryPredicate::Any {
                    categories: vec![category("pii")],
                },
            },
            &policy_id,
            &allowed,
            &universe,
            &catalogs,
        )
        .unwrap();
        assert_eq!(any.len(), 1);

        let all = resolve_endpoint_predicate(
            &EndpointPredicate::Categories {
                predicate: CategoryPredicate::All {
                    categories: vec![category("input.user"), category("pii")],
                },
            },
            &policy_id,
            &allowed,
            &universe,
            &catalogs,
        )
        .unwrap();
        assert_eq!(all, any);
    }

    #[test]
    fn endpoint_supersedes_cannot_cross_roles() {
        let mut source = dependency(
            "source",
            &["input.user"],
            SchemaVersionOrigin::Explicit,
            SchemaVersionOrigin::Explicit,
            "/origins/source",
        );
        let mut sink = dependency(
            "sink",
            &["output.sensitive"],
            SchemaVersionOrigin::Explicit,
            SchemaVersionOrigin::Explicit,
            "/origins/sink",
        );
        sink.model.role = EndpointRole::Sink;
        source.model.supersedes = vec![sink.identity.clone()];
        let selected = vec![source.identity.clone(), sink.identity.clone()];
        let universe =
            EndpointUniverse::try_new(&[source, sink], CompositionLimits::default()).unwrap();
        assert!(matches!(
            validate_endpoint_precedence(&selected, &universe),
            Err(CompositionError::EndpointRoleMismatch {
                expected: EndpointRole::Source,
                actual: EndpointRole::Sink,
                ..
            })
        ));
    }

    #[test]
    fn scanned_collection_rejects_duplicate_ids_before_filtering() {
        let endpoint = dependency(
            "duplicate",
            &["input.user"],
            SchemaVersionOrigin::Explicit,
            SchemaVersionOrigin::Explicit,
            "/origins/one",
        );
        let mut repeated = endpoint.clone();
        repeated.origins = vec![EndpointOrigin::PolicyLocal {
            path: PolicyDependencyPath::new("/origins/two").unwrap(),
        }];
        assert!(matches!(
            validate_scanned_endpoint_collection(
                &[endpoint, repeated],
                CompositionLimits::default(),
            ),
            Err(CompositionError::DuplicateExactEndpointId { .. })
        ));
    }
}
