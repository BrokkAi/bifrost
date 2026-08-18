use super::*;
use brokk_bifrost_analysis::analyzer::semantic::{
    CandidateCoverage, EvidenceCompleteness, OracleCallContext, ProofStatus, SemanticBudget,
    SemanticOutcome, SemanticRequest, ValueFlowEndpoint, ValueFlowOracle, ValueFlowRelationKind,
    WorkspaceSemanticOracle, cfg_algorithms::derive_procedure_control_dependence,
};
use brokk_bifrost_analysis::analyzer::structural::{
    CodeQueryCompletion, CodeQueryExecutionLimits, execute_workspace_request_with_cancellation,
};
use brokk_bifrost_analysis::analyzer::value_flow::ValueFlowCarrier;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, FilesystemProject, OverlayProject, Project, ProjectFile, WorkspaceAnalyzer,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, path::PathBuf, sync::Arc};

/// Where a workspace's analyzer store lives for the lifetime of one open.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionPersistenceMode {
    /// An in-memory store discarded when the workspace drops. The default, so
    /// existing consumers keep their behavior.
    #[default]
    Ephemeral,
    /// The engine's persistent store (`.bifrost/cache` at the primary
    /// repository root), so extracted facts survive reopen and are shared
    /// with other sessions and linked worktrees of the same checkout.
    Persisted,
}

/// Evidence of the persistence decision one open actually made.
///
/// `engaged` reports what the built store is, not what the caller asked for:
/// the engine degrades a persisted request to an in-memory store when the
/// project offers no persistence root, and that degradation must be visible
/// as data rather than inferred from timing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionStoreReport {
    pub requested: ExtensionPersistenceMode,
    pub engaged: ExtensionPersistenceMode,
    /// The on-disk store the workspace answers from, present exactly when
    /// `engaged` is [`ExtensionPersistenceMode::Persisted`]. For a linked
    /// worktree this is the primary checkout's shared database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_db: Option<Box<str>>,
    /// Degradation record; empty whenever `engaged` matches `requested`.
    pub diagnostics: Box<[ExtensionDiagnostic]>,
}

#[derive(Debug, Clone)]
pub struct ExtensionWorkspaceOptions {
    pub roots: Vec<PathBuf>,
    pub analyzer_config: AnalyzerConfig,
    pub limits: ExtensionLimits,
    pub persistence: ExtensionPersistenceMode,
}
impl ExtensionWorkspaceOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            roots: vec![root.into()],
            analyzer_config: AnalyzerConfig::default(),
            limits: ExtensionLimits::default(),
            persistence: ExtensionPersistenceMode::default(),
        }
    }
    /// Opt this open into the engine's persistent store.
    pub fn persisted(mut self) -> Self {
        self.persistence = ExtensionPersistenceMode::Persisted;
        self
    }
}

#[derive(Debug)]
pub enum ExtensionWorkspaceError {
    InvalidRoots(Box<str>),
    Project(Box<str>),
    Analyzer(Box<str>),
    /// A requested persistent store could not be opened (permissions, a
    /// corrupt database, ...). Deliberately not a silent fallback to the
    /// in-memory store: every other persisted entry point propagates this,
    /// and answering from a cold store while reporting persistence would
    /// misstate the evidence.
    Store(Box<str>),
}
impl fmt::Display for ExtensionWorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExtensionWorkspaceError {}
#[derive(Debug)]
pub enum ExtensionError {
    Compatibility(ExtensionCompatibilityError),
    StaleGeneration {
        expected: WorkspaceGeneration,
        actual: WorkspaceGeneration,
    },
    InvalidRequest(Box<str>),
    Execution(Box<str>),
}
impl fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExtensionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Complete,
    Partial,
    Unsupported,
}
impl CapabilitySupport {
    const fn unsupported() -> Self {
        Self::Unsupported
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageCapabilityReport {
    pub language: Box<str>,
    pub control_flow: CapabilitySupport,
    pub value_dependence: CapabilitySupport,
    /// Typestate is not reachable from this surface yet; the explicit
    /// `Unsupported` row lets extensions distinguish "unsupported here"
    /// from "does not exist" (issue #2328).
    #[serde(default = "CapabilitySupport::unsupported")]
    pub typestate: CapabilitySupport,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationCapability {
    pub id: ExtensionCapabilityId,
    pub stability: ApiStability,
    pub support: CapabilitySupport,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionCapabilityReport {
    pub generation: WorkspaceGeneration,
    pub languages: Box<[LanguageCapabilityReport]>,
    pub operations: Box<[OperationCapability]>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionWorkspaceDescription {
    pub api: ExtensionApiVersion,
    pub generation: WorkspaceGeneration,
    pub capabilities: ExtensionCapabilityReport,
    pub store: ExtensionStoreReport,
    /// Workspace files excluded from analysis at open time (for example
    /// binary content, which cannot enter the UTF-8 source overlay). Recorded
    /// so an extension can distinguish "present but not analyzed" from
    /// "absent"; an empty slice means every listed file was acquired.
    #[serde(default)]
    pub open_diagnostics: Box<[ExtensionDiagnostic]>,
}

pub struct ExtensionWorkspace {
    generation: WorkspaceGeneration,
    capabilities: ExtensionCapabilityReport,
    store: ExtensionStoreReport,
    open_diagnostics: Box<[ExtensionDiagnostic]>,
    analyzer: WorkspaceAnalyzer,
}

impl ExtensionWorkspace {
    pub(crate) fn project_root(&self) -> &std::path::Path {
        self.analyzer.analyzer().project().root()
    }

    pub fn open(options: ExtensionWorkspaceOptions) -> Result<Self, ExtensionWorkspaceError> {
        if options.roots.len() != 1 {
            return Err(ExtensionWorkspaceError::InvalidRoots(
                "API version 1 requires exactly one workspace root".into(),
            ));
        }
        let filesystem = FilesystemProject::new(options.roots[0].clone()).map_err(|error| {
            ExtensionWorkspaceError::Project(error.to_string().into_boxed_str())
        })?;
        let filesystem: Arc<dyn Project> = Arc::new(filesystem);
        let files = filesystem.all_files_shared().map_err(|error| {
            ExtensionWorkspaceError::Project(error.to_string().into_boxed_str())
        })?;
        let frozen = OverlayProject::with_max_bytes(
            Arc::clone(&filesystem),
            options.limits.values().source_bytes as usize,
        );
        let mut open_diagnostics = Vec::new();
        for file in files.iter() {
            let source = match filesystem.read_source(file) {
                Ok(source) => source,
                // Real repositories routinely carry binary assets, and binary
                // content cannot enter the UTF-8 source overlay. Skip the file
                // and record the skip instead of aborting the open: the
                // incompleteness stays visible in the description rather than
                // becoming a silent absence (#2329).
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    open_diagnostics.push(unsupported_content_diagnostic(file));
                    continue;
                }
                Err(error) => {
                    return Err(ExtensionWorkspaceError::Project(
                        error.to_string().into_boxed_str(),
                    ));
                }
            };
            if !frozen.set(file.abs_path(), source) {
                return Err(ExtensionWorkspaceError::Project(
                    format!(
                        "source exceeds extension open limit: {}",
                        file.rel_path().display()
                    )
                    .into_boxed_str(),
                ));
            }
        }
        let project: Arc<dyn Project> = Arc::new(frozen.snapshot());
        let analyzer = match options.persistence {
            ExtensionPersistenceMode::Ephemeral => WorkspaceAnalyzer::build_ephemeral(
                Arc::clone(&project),
                options.analyzer_config.clone(),
            )
            .map_err(|error| {
                ExtensionWorkspaceError::Analyzer(error.to_string().into_boxed_str())
            })?,
            ExtensionPersistenceMode::Persisted => WorkspaceAnalyzer::build_persisted(
                Arc::clone(&project),
                options.analyzer_config.clone(),
            )
            .map_err(|error| ExtensionWorkspaceError::Store(error.to_string().into_boxed_str()))?,
        };
        // Report the store the build actually produced rather than echoing the
        // request: a persisted request against a project with no persistence
        // root degrades to the in-memory store inside the engine, and that
        // decision must surface here as data.
        let store = match (options.persistence, analyzer.persisted_store_path()) {
            (requested, Some(path)) => ExtensionStoreReport {
                requested,
                engaged: ExtensionPersistenceMode::Persisted,
                cache_db: Some(path.to_string_lossy().into_owned().into_boxed_str()),
                diagnostics: Box::new([]),
            },
            (ExtensionPersistenceMode::Persisted, None) => ExtensionStoreReport {
                requested: ExtensionPersistenceMode::Persisted,
                engaged: ExtensionPersistenceMode::Ephemeral,
                cache_db: None,
                diagnostics: Box::new([ExtensionDiagnostic {
                    code: "store.persistence_unavailable".into(),
                    message: "workspace offers no persistence root; \
                              the engine degraded to an in-memory store"
                        .into(),
                    source: None,
                }]),
            },
            (ExtensionPersistenceMode::Ephemeral, None) => ExtensionStoreReport {
                requested: ExtensionPersistenceMode::Ephemeral,
                engaged: ExtensionPersistenceMode::Ephemeral,
                cache_db: None,
                diagnostics: Box::new([]),
            },
        };
        let generation = generation_for(&analyzer, &options.analyzer_config)?;
        let languages = analyzer
            .analyzer()
            .languages()
            .into_iter()
            .map(|language| LanguageCapabilityReport {
                language: format!("{language:?}")
                    .to_ascii_lowercase()
                    .into_boxed_str(),
                control_flow: CapabilitySupport::Complete,
                value_dependence: CapabilitySupport::Partial,
                typestate: CapabilitySupport::Unsupported,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let capabilities = ExtensionCapabilityReport {
            generation: generation.clone(),
            languages,
            operations: vec![
                OperationCapability {
                    id: capability("structural.query"),
                    stability: ApiStability::Stable,
                    support: CapabilitySupport::Complete,
                },
                OperationCapability {
                    id: capability("experimental.semantic.control_flow"),
                    stability: ApiStability::Experimental { since_minor: 0 },
                    support: CapabilitySupport::Complete,
                },
                OperationCapability {
                    id: capability("experimental.semantic.value_dependence"),
                    stability: ApiStability::Experimental { since_minor: 0 },
                    support: CapabilitySupport::Partial,
                },
                // Typestate machinery exists in the engine but has no route on
                // this surface yet. Advertising the operation as `Unsupported`
                // (rather than omitting it) lets extensions distinguish
                // "unsupported here" from "does not exist". Design:
                // .agents/docs/extension-typestate-design-2026-08.md.
                OperationCapability {
                    id: capability("experimental.semantic.typestate"),
                    stability: ApiStability::Experimental { since_minor: 0 },
                    support: CapabilitySupport::Unsupported,
                },
            ]
            .into_boxed_slice(),
        };
        Ok(Self {
            generation,
            capabilities,
            store,
            open_diagnostics: open_diagnostics.into_boxed_slice(),
            analyzer,
        })
    }
    pub fn generation(&self) -> &WorkspaceGeneration {
        &self.generation
    }
    pub fn capabilities(&self) -> &ExtensionCapabilityReport {
        &self.capabilities
    }
    pub fn store(&self) -> &ExtensionStoreReport {
        &self.store
    }
    /// Diagnostics recorded while acquiring workspace source at open time
    /// (currently: files skipped for non-UTF-8 content). Empty when every
    /// listed file was acquired.
    pub fn open_diagnostics(&self) -> &[ExtensionDiagnostic] {
        &self.open_diagnostics
    }
    pub fn describe(&self) -> ExtensionWorkspaceDescription {
        ExtensionWorkspaceDescription {
            api: EXTENSION_API_VERSION,
            generation: self.generation.clone(),
            capabilities: self.capabilities.clone(),
            store: self.store.clone(),
            open_diagnostics: self.open_diagnostics.clone(),
        }
    }
    fn validate(
        &self,
        compatibility: &ExtensionCompatibility,
        expected: &WorkspaceGeneration,
    ) -> Result<(), ExtensionError> {
        negotiate_extension_api(compatibility).map_err(ExtensionError::Compatibility)?;
        if expected != &self.generation {
            return Err(ExtensionError::StaleGeneration {
                expected: expected.clone(),
                actual: self.generation.clone(),
            });
        }
        Ok(())
    }
    pub fn structural_query(
        &self,
        request: StructuralRequest,
        cancellation: &ExtensionCancellation,
    ) -> Result<ExtensionOutcome<StructuralResult>, ExtensionError> {
        self.validate(&request.compatibility, &request.expected_generation)?;
        let values = request.limits.values();
        if cancellation.is_cancelled() {
            return Ok(make_outcome(
                None,
                ExtensionCompletion::Cancelled,
                &self.generation,
                &ExtensionLimits::default(),
                "structural.query",
                ApiStability::Stable,
                ExtensionWork::default(),
            ));
        }
        let limits = CodeQueryExecutionLimits {
            max_pipeline_rows: values.result_items as usize,
            max_scanned_source_bytes: values.source_bytes as usize,
            max_scanned_files: values.semantic_files as usize,
            ..Default::default()
        };
        let response = execute_workspace_request_with_cancellation(
            &self.analyzer,
            &request.query,
            limits,
            cancellation.token(),
        );
        let result = response.result().ok_or_else(|| {
            ExtensionError::InvalidRequest("explain requests do not produce structural rows".into())
        })?;
        let completion = match result.completion() {
            CodeQueryCompletion::Complete => ExtensionCompletion::Complete,
            CodeQueryCompletion::ProvenSubset { .. } => ExtensionCompletion::Unproven,
            CodeQueryCompletion::Incomplete { .. } => ExtensionCompletion::Truncated {
                limit: "structural_execution".into(),
            },
            CodeQueryCompletion::Cancelled => ExtensionCompletion::Cancelled,
            CodeQueryCompletion::Invalid { .. } => {
                return Err(ExtensionError::InvalidRequest(
                    "invalid structural query".into(),
                ));
            }
        };
        let items = result
            .results
            .iter()
            .map(|item| serde_json::to_value(item).expect("query result item serializes"))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let value = StructuralResult { items };
        let work = ExtensionWork {
            result_items: value.items.len() as u64,
            result_bytes: serde_json::to_vec(&value)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0),
            ..Default::default()
        };
        Ok(make_outcome(
            Some(value),
            completion,
            &self.generation,
            &request.limits,
            "structural.query",
            ApiStability::Stable,
            work,
        ))
    }
    pub fn semantic_relations(
        &self,
        request: SemanticRelationRequest,
        cancellation: &ExtensionCancellation,
    ) -> Result<ExtensionOutcome<SemanticRelationSnapshot>, ExtensionError> {
        self.validate(&request.compatibility, &request.expected_generation)?;
        request
            .validate()
            .map_err(|error| ExtensionError::InvalidRequest(error.to_string().into()))?;
        let stability = ApiStability::Experimental { since_minor: 0 };
        let operation = if request
            .relations
            .contains(&SemanticRelationKind::ValueDependence)
        {
            "experimental.semantic.value_dependence"
        } else {
            "experimental.semantic.control_flow"
        };
        if cancellation.is_cancelled() {
            return Ok(make_outcome(
                None,
                ExtensionCompletion::Cancelled,
                &self.generation,
                &ExtensionLimits::default(),
                operation,
                stability,
                ExtensionWork::default(),
            ));
        }
        let Some(SemanticSeed::Source { span: seed }) = request.seeds.first() else {
            return Err(ExtensionError::InvalidRequest(
                "stable-node seeds require a prior snapshot resolver".into(),
            ));
        };
        let root = self.analyzer.analyzer().project().root();
        let file = ProjectFile::new(root.to_path_buf(), seed.path.as_str());
        if self
            .analyzer
            .program_semantics_provider_for_file(&file)
            .is_none()
        {
            return Ok(make_outcome(
                None,
                ExtensionCompletion::Unsupported {
                    capability: capability(operation),
                },
                &self.generation,
                &ExtensionLimits::default(),
                operation,
                stability,
                ExtensionWork::default(),
            ));
        }
        let values = request.limits;
        let mut budget = SemanticBudget::default();
        let mut semantic_request = SemanticRequest::new(&mut budget, cancellation.token());
        let materialized = self
            .analyzer
            .materialize_program_semantics(&file, &mut semantic_request)
            .map_err(|error| ExtensionError::Execution(error.to_string().into_boxed_str()))?;
        let completion = semantic_completion(&materialized);
        let Some(artifact) = materialized.available_value() else {
            return Ok(make_outcome(
                None,
                completion,
                &self.generation,
                &ExtensionLimits::default(),
                operation,
                stability,
                ExtensionWork::default(),
            ));
        };
        let seed_start = u32::try_from(seed.start_utf8_byte)
            .map_err(|_| ExtensionError::InvalidRequest("seed byte offset exceeds u32".into()))?;
        let procedure = artifact
            .procedures()
            .iter()
            .filter(|procedure| {
                let span = procedure.locator().anchor().span();
                span.start_byte() <= seed_start && seed_start <= span.end_byte()
            })
            .min_by_key(|procedure| {
                procedure.locator().anchor().span().end_byte()
                    - procedure.locator().anchor().span().start_byte()
            });
        let Some(procedure) = procedure else {
            return Ok(make_outcome(
                None,
                ExtensionCompletion::Unknown,
                &self.generation,
                &ExtensionLimits::default(),
                operation,
                stability,
                ExtensionWork::default(),
            ));
        };
        let wants_value = request
            .relations
            .contains(&SemanticRelationKind::ValueDependence);
        let mut truncated = procedure.points().len() > values.max_nodes as usize
            || procedure.control_edges().len() > values.max_edges as usize;
        let nodes = procedure
            .points()
            .iter()
            .take(values.max_nodes as usize)
            .enumerate()
            .map(|(local_id, point)| {
                let mapping = procedure
                    .source_mapping(point.source)
                    .expect("validated semantic source mapping");
                let span = mapping.locator.anchor().span();
                SemanticNodeOccurrence {
                    local_id: local_id as u32,
                    stable_id: stable_semantic_id(
                        &self.generation,
                        seed.path.as_str(),
                        span.start_byte(),
                        span.end_byte(),
                        point.id.index(),
                    ),
                    call_context: Box::new([]),
                    span: SourceSpan {
                        path: seed.path.clone(),
                        start_utf8_byte: span.start_byte() as u64,
                        end_utf8_byte: span.end_byte() as u64,
                    },
                    role: "program_point".into(),
                }
            })
            .collect::<Vec<_>>();
        let source_span = |mapping_id| {
            let mapping = procedure
                .source_mapping(mapping_id)
                .expect("validated semantic source mapping");
            let span = mapping.locator.anchor().span();
            SourceSpan {
                path: seed.path.clone(),
                start_utf8_byte: span.start_byte() as u64,
                end_utf8_byte: span.end_byte() as u64,
            }
        };
        let edge_evidence = |edge: &brokk_bifrost_analysis::analyzer::semantic::ControlEdge| {
            let evidence = procedure
                .evidence_row(edge.evidence)
                .expect("validated control-edge evidence");
            let completeness = match &evidence.completeness {
                brokk_bifrost_analysis::analyzer::semantic::EvidenceCompleteness::Complete => {
                    SemanticRelationCompleteness::Complete
                }
                brokk_bifrost_analysis::analyzer::semantic::EvidenceCompleteness::Partial(
                    reason,
                ) => SemanticRelationCompleteness::Partial {
                    reason: reason.clone(),
                },
            };
            SemanticEvidence {
                kind: "control_edge".into(),
                mappings: std::iter::once(source_span(edge.source))
                    .chain(evidence.sources.iter().copied().map(source_span))
                    .collect(),
                proof: SemanticProof::Proven,
                completeness,
            }
        };
        let mut edges = Vec::new();
        if request
            .relations
            .contains(&SemanticRelationKind::ControlFlow)
        {
            edges.extend(
                procedure
                    .control_edges()
                    .iter()
                    .filter(|edge| {
                        edge.source_point.index() < values.max_nodes as usize
                            && edge.target_point.index() < values.max_nodes as usize
                    })
                    .map(|edge| SemanticRelationEdge {
                        source: edge.source_point.index() as u32,
                        target: edge.target_point.index() as u32,
                        kind: SemanticRelationKind::ControlFlow,
                        subtype: Some(edge.kind.label().into()),
                        detail: SemanticRelationDetail::Generic,
                        proof: SemanticProof::Proven,
                        completeness: SemanticRelationCompleteness::Complete,
                        evidence: vec![edge_evidence(edge)].into_boxed_slice(),
                    }),
            );
        }
        let mut relation_boundaries = Vec::new();
        let mut algorithm_work = 0_u64;
        if request
            .relations
            .contains(&SemanticRelationKind::ControlDependence)
        {
            let dependence = derive_procedure_control_dependence(
                procedure,
                usize::try_from(values.max_traversal_steps).unwrap_or(usize::MAX),
                cancellation.token(),
            )
            .map_err(ExtensionError::Execution)?;
            algorithm_work = (dependence.node_visits + dependence.edge_visits) as u64;
            edges.extend(dependence.rows.iter().filter_map(|(edge_id, governed)| {
                let edge = procedure.control_edge(*edge_id)?;
                (edge.source_point.index() < values.max_nodes as usize
                    && governed.index() < values.max_nodes as usize)
                    .then(|| SemanticRelationEdge {
                        source: edge.source_point.index() as u32,
                        target: governed.index() as u32,
                        kind: SemanticRelationKind::ControlDependence,
                        subtype: Some(edge.kind.label().into()),
                        detail: SemanticRelationDetail::Generic,
                        proof: SemanticProof::Proven,
                        completeness: SemanticRelationCompleteness::Complete,
                        evidence: vec![edge_evidence(edge)].into_boxed_slice(),
                    })
            }));
            relation_boundaries.extend(dependence.non_exiting_regions.iter().map(|region| {
                SemanticRelationBoundary {
                    kind: SemanticRelationBoundaryKind::NonExitingRegion,
                    at: region.first().map(|point| point.index() as u32),
                    relations: vec![SemanticRelationKind::ControlDependence].into_boxed_slice(),
                    message: format!(
                        "{} live program points cannot reach a procedure exit",
                        region.len()
                    )
                    .into_boxed_str(),
                    evidence: Box::new([]),
                }
            }));
        }
        if wants_value {
            let procedure_handle = artifact
                .procedure_handle(procedure.id())
                .expect("selected procedure belongs to the materialized artifact");
            let oracle = WorkspaceSemanticOracle::with_limits(
                &self.analyzer,
                brokk_bifrost_analysis::analyzer::semantic::OracleLimits::default(),
            );
            let outcome = oracle
                .procedure_relations(
                    &procedure_handle,
                    &OracleCallContext::empty(),
                    &mut semantic_request,
                )
                .map_err(|error| ExtensionError::Execution(error.to_string().into()))?;
            if let Some(snapshot) = outcome.available_value() {
                truncated |= snapshot.relations().len()
                    > values.max_value_dependence_edges as usize
                    || snapshot.coverage() != CandidateCoverage::Exhaustive;
                for relation in snapshot
                    .relations()
                    .iter()
                    .take(values.max_value_dependence_edges as usize)
                {
                    let point_index = relation.point().id().index();
                    let Some(point_node) = nodes.get(point_index) else {
                        continue;
                    };
                    let source = value_occurrence(
                        relation.source.clone(),
                        point_node,
                        relation.event_index(),
                        true,
                    )?;
                    let target = value_occurrence(
                        relation.target.clone(),
                        point_node,
                        relation.event_index(),
                        false,
                    )?;
                    let proof = match relation.proof {
                        ProofStatus::Proven => SemanticProof::Proven,
                        _ => SemanticProof::Unproven {
                            reason: "semantic value-flow proof is incomplete".into(),
                        },
                    };
                    let completeness = match relation.completeness {
                        EvidenceCompleteness::Complete => SemanticRelationCompleteness::Complete,
                        _ => SemanticRelationCompleteness::Partial {
                            reason: "semantic value-flow evidence is incomplete".into(),
                        },
                    };
                    edges.push(SemanticRelationEdge {
                        source: point_index as u32,
                        target: point_index as u32,
                        kind: SemanticRelationKind::ValueDependence,
                        subtype: None,
                        detail: SemanticRelationDetail::ValueDependence {
                            subtypes: vec![value_subtype(relation.kind)].into_boxed_slice(),
                            source,
                            target,
                            may: if matches!(proof, SemanticProof::Proven) {
                                ValueDependenceMayStatus::Proven
                            } else {
                                ValueDependenceMayStatus::Unproven
                            },
                        },
                        proof: proof.clone(),
                        completeness: completeness.clone(),
                        evidence: vec![SemanticEvidence {
                            kind: "semantic_value_flow".into(),
                            mappings: vec![point_node.span.clone()].into_boxed_slice(),
                            proof,
                            completeness,
                        }]
                        .into_boxed_slice(),
                    });
                }
            }
        }
        let derived_edge_count = edges.len();
        edges.truncate(values.max_edges as usize);
        let work = ExtensionWork {
            semantic_nodes: nodes.len() as u64,
            semantic_edges: edges.len() as u64,
            traversal_steps: algorithm_work,
            ..Default::default()
        };
        let request_digest = request_digest(&request)
            .map_err(|error| ExtensionError::InvalidRequest(error.to_string().into()))?;
        let mut boundaries = if truncated || derived_edge_count > values.max_edges as usize {
            vec![SemanticRelationBoundary {
                kind: SemanticRelationBoundaryKind::NodeLimit,
                at: None,
                relations: request.relations.clone(),
                message: "semantic node or edge limit reached".into(),
                evidence: Box::new([]),
            }]
        } else {
            Vec::new()
        };
        boundaries.extend(relation_boundaries);
        let truncated =
            truncated || derived_edge_count > values.max_edges as usize || !boundaries.is_empty();
        let snapshot = SemanticRelationSnapshot::try_new(
            self.generation.clone(),
            request_digest,
            if truncated {
                SemanticRelationStatus::Partial
            } else {
                SemanticRelationStatus::Complete
            },
            nodes,
            edges,
            boundaries,
        )
        .map_err(|error| ExtensionError::Execution(error.to_string().into()))?;
        Ok(make_outcome(
            Some(snapshot),
            if truncated {
                ExtensionCompletion::Truncated {
                    limit: "semantic_nodes_or_edges".into(),
                }
            } else {
                completion
            },
            &self.generation,
            &ExtensionLimits::default(),
            operation,
            stability,
            work,
        ))
    }
}

fn value_occurrence(
    endpoint: ValueFlowEndpoint,
    node: &SemanticNodeOccurrence,
    event_ordinal: u32,
    definition: bool,
) -> Result<ValueOccurrence, ExtensionError> {
    let projection = format!(
        "{:?}",
        ValueFlowCarrier::from(endpoint)
            .stable_key()
            .map_err(|error| ExtensionError::Execution(error.to_string().into()))?
    );
    let digest = value_carrier_digest(&projection)
        .map_err(|error| ExtensionError::Execution(error.to_string().into()))?;
    Ok(ValueOccurrence {
        node: node.local_id,
        carrier: StableValueCarrier {
            digest,
            projection: projection.into(),
        },
        role: if definition {
            ValueOccurrenceRole::Definition
        } else {
            ValueOccurrenceRole::Use
        },
        phase: if definition {
            ValueObservationPhase::AfterEffects
        } else {
            ValueObservationPhase::BeforeEffects
        },
        event_ordinal,
    })
}

const fn value_subtype(kind: ValueFlowRelationKind) -> ValueDependenceSubtype {
    match kind {
        ValueFlowRelationKind::Assignment => ValueDependenceSubtype::Assignment,
        ValueFlowRelationKind::Parameter => ValueDependenceSubtype::Parameter,
        ValueFlowRelationKind::Receiver => ValueDependenceSubtype::Receiver,
        ValueFlowRelationKind::NormalReturn => ValueDependenceSubtype::NormalReturn,
        ValueFlowRelationKind::ExceptionalReturn => ValueDependenceSubtype::ExceptionalReturn,
        ValueFlowRelationKind::Allocation => ValueDependenceSubtype::Allocation,
        ValueFlowRelationKind::MemoryLoad => ValueDependenceSubtype::FieldLoad,
        ValueFlowRelationKind::MemoryStore => ValueDependenceSubtype::FieldStore,
        ValueFlowRelationKind::Capture => ValueDependenceSubtype::Capture,
        ValueFlowRelationKind::LanguageDefined => ValueDependenceSubtype::LanguageDefined,
    }
}

fn generation_for(
    analyzer: &WorkspaceAnalyzer,
    config: &AnalyzerConfig,
) -> Result<WorkspaceGeneration, ExtensionWorkspaceError> {
    let mut hasher = Sha256::new();
    hasher.update(b"brokk-bifrost-extension-workspace-generation-v1\0");
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(EXTENSION_API_VERSION.major.to_le_bytes());
    hasher.update(format!("{config:?}").as_bytes());
    let project = analyzer.analyzer().project();
    hasher.update(project.root().to_string_lossy().as_bytes());
    for file in project
        .all_files_shared()
        .map_err(|error| ExtensionWorkspaceError::Project(error.to_string().into_boxed_str()))?
        .iter()
    {
        hasher.update([0]);
        hasher.update(file.rel_path().to_string_lossy().as_bytes());
        hasher.update([0]);
        match project.read_source_snapshot(file) {
            Ok(source) => hasher.update(source.source().as_bytes()),
            // A file skipped at open time for binary content still exists in
            // the workspace. Its path plus a fixed marker participate in the
            // generation so adding, removing, or renaming such a file changes
            // the generation even though its content is never analyzed.
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                hasher.update(b"<unsupported-file-content>");
            }
            Err(error) => {
                return Err(ExtensionWorkspaceError::Project(
                    error.to_string().into_boxed_str(),
                ));
            }
        }
    }
    Ok(WorkspaceGeneration::new(
        StableDigest::parse(format!("{:x}", hasher.finalize())).expect("SHA-256 is canonical"),
    ))
}
/// Diagnostic for a workspace file skipped at open time because its content
/// is not valid UTF-8 (binary assets, mixed-encoding files). The span is
/// omitted only when the file's own path cannot be expressed as a normalized
/// relative path; the message always names the file.
fn unsupported_content_diagnostic(file: &ProjectFile) -> ExtensionDiagnostic {
    // Separator-normalized on every platform: `NormalizedRelativePath` rejects
    // backslashes outright, so a raw Windows `rel_path` would lose the span,
    // and the message must name the same slash-form path clients see in spans.
    let rel_path = brokk_bifrost_analysis::path_utils::rel_path_string(file);
    ExtensionDiagnostic {
        code: "workspace.unsupported_file_content".into(),
        message: format!("skipped non-UTF-8 file: {rel_path}").into_boxed_str(),
        source: NormalizedRelativePath::new(&rel_path)
            .ok()
            .map(|path| SourceSpan {
                path,
                start_utf8_byte: 0,
                end_utf8_byte: 0,
            }),
    }
}
fn capability(value: &str) -> ExtensionCapabilityId {
    ExtensionCapabilityId::new(value).expect("static capability is valid")
}
fn stable_semantic_id(
    generation: &WorkspaceGeneration,
    path: &str,
    start: u32,
    end: u32,
    local: usize,
) -> StableDigest {
    StableDigest::from_hash(format!(
        "semantic-node-v1\0{generation}\0{path}\0{start}\0{end}\0{local}"
    ))
}
fn semantic_completion<T>(outcome: &SemanticOutcome<T>) -> ExtensionCompletion {
    match outcome {
        SemanticOutcome::Complete { .. } => ExtensionCompletion::Complete,
        SemanticOutcome::Ambiguous { .. } => ExtensionCompletion::Ambiguous,
        SemanticOutcome::Unknown { .. } => ExtensionCompletion::Unknown,
        SemanticOutcome::Unsupported { capability, .. } => ExtensionCompletion::Unsupported {
            capability: ExtensionCapabilityId::new(format!("semantic.{}", capability.label()))
                .unwrap(),
        },
        SemanticOutcome::Unproven { .. } => ExtensionCompletion::Unproven,
        SemanticOutcome::ExceededBudget { exceeded, .. } => ExtensionCompletion::ExceededBudget {
            dimension: format!("{exceeded:?}").into_boxed_str(),
        },
        SemanticOutcome::Cancelled { .. } => ExtensionCompletion::Cancelled,
    }
}
fn make_outcome<T>(
    value: Option<T>,
    completion: ExtensionCompletion,
    generation: &WorkspaceGeneration,
    limits: &ExtensionLimits,
    operation: &str,
    stability: ApiStability,
    work: ExtensionWork,
) -> ExtensionOutcome<T> {
    ExtensionOutcome {
        completion,
        value,
        metadata: ExtensionResultMetadata {
            api: EXTENSION_API_VERSION,
            operation: capability(operation),
            stability,
            generation: generation.clone(),
            diagnostics: Box::new([]),
            work,
            limits: limits.values(),
            provenance: vec![
                format!("brokk-bifrost-runtime:{}", env!("CARGO_PKG_VERSION")).into_boxed_str(),
            ]
            .into_boxed_slice(),
        },
    }
}

#[derive(Debug, Clone)]
pub struct StructuralRequest {
    pub compatibility: ExtensionCompatibility,
    pub expected_generation: WorkspaceGeneration,
    pub query: CodeQuery,
    pub limits: ExtensionLimits,
}
impl Serialize for StructuralRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            &self.compatibility,
            &self.expected_generation,
            self.query.to_canonical_json(),
            &self.limits,
        )
            .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for StructuralRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (compatibility, expected_generation, query, limits): (
            ExtensionCompatibility,
            WorkspaceGeneration,
            Value,
            ExtensionLimits,
        ) = Deserialize::deserialize(deserializer)?;
        let query = CodeQuery::from_json(&query).map_err(serde::de::Error::custom)?;
        Ok(Self {
            compatibility,
            expected_generation,
            query,
            limits,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralResult {
    pub items: Box<[Value]>,
}

// Persistence tests live here rather than in `tests/extension/` because the
// reuse evidence (extraction/hydration counters) sits on the deliberately
// private `analyzer` field.
#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::structural::StructuralSearchProvider;
    use std::path::Path;

    const SOURCE: &str = "export function answer() { return 42; }\n";

    fn write_project(root: &Path) {
        std::fs::write(root.join("app.ts"), SOURCE).unwrap();
    }

    fn open(root: &Path, persisted: bool) -> ExtensionWorkspace {
        let options = ExtensionWorkspaceOptions::new(root);
        let options = if persisted {
            options.persisted()
        } else {
            options
        };
        ExtensionWorkspace::open(options).unwrap()
    }

    fn provider(workspace: &ExtensionWorkspace) -> &dyn StructuralSearchProvider {
        workspace.analyzer.analyzer().structural_search_providers()[0]
    }

    fn commit_all(repo: &git2::Repository) {
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let signature = git2::Signature::now("bifrost-test", "test@example.invalid").unwrap();
        repo.commit(Some("HEAD"), &signature, &signature, "init", &tree, &[])
            .unwrap();
    }

    #[test]
    fn default_open_stays_ephemeral_and_reports_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_project(&root);
        let workspace = open(&root, false);
        let store = workspace.store();
        assert_eq!(store.requested, ExtensionPersistenceMode::Ephemeral);
        assert_eq!(store.engaged, ExtensionPersistenceMode::Ephemeral);
        assert!(store.cache_db.is_none());
        assert!(store.diagnostics.is_empty());
        assert_eq!(&workspace.describe().store, store);
        assert!(
            !root.join(".bifrost").exists(),
            "an ephemeral open must not create an on-disk cache"
        );
    }

    #[test]
    fn persisted_open_populates_a_cache_the_reopen_hydrates_from() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_project(&root);
        let file = ProjectFile::new(root.clone(), "app.ts");

        let first = open(&root, true);
        let store = first.store().clone();
        assert_eq!(store.requested, ExtensionPersistenceMode::Persisted);
        assert_eq!(store.engaged, ExtensionPersistenceMode::Persisted);
        assert!(store.diagnostics.is_empty());
        let cache_db =
            Path::new(store.cache_db.as_deref().expect("engaged store has a path")).to_path_buf();
        assert!(cache_db.starts_with(root.join(".bifrost/cache")));
        assert!(cache_db.exists(), "the reported store must exist on disk");
        let facts = provider(&first).structural_facts(&file).unwrap();
        assert_eq!(facts.source(), SOURCE);
        let generation = first.generation().clone();
        drop(first);

        // Reuse evidence is counter-based, not timing-based: the reopened
        // provider must answer from a hydrated snapshot without a single
        // parse-and-normalize extraction.
        let second = open(&root, true);
        assert_eq!(second.generation(), &generation);
        assert_eq!(second.store(), &store);
        let provider = provider(&second);
        let hydrated_before = provider.structural_hydration_count();
        let facts = provider.structural_facts(&file).unwrap();
        assert_eq!(facts.source(), SOURCE);
        assert_eq!(
            provider.structural_extraction_count(),
            0,
            "a persisted reopen must reuse the populated cache, not re-extract"
        );
        assert_eq!(provider.structural_hydration_count(), hydrated_before + 1);
    }

    #[test]
    fn linked_worktree_engages_the_primary_checkouts_shared_cache() {
        let temp = tempfile::tempdir().unwrap();
        let primary_root = temp.path().join("primary");
        std::fs::create_dir(&primary_root).unwrap();
        let repo = git2::Repository::init(&primary_root).unwrap();
        write_project(&primary_root);
        commit_all(&repo);
        let linked_root = temp.path().join("linked");
        repo.worktree("linked", &linked_root, None).unwrap();

        let primary = open(&primary_root.canonicalize().unwrap(), true);
        let linked = open(&linked_root.canonicalize().unwrap(), true);
        assert_eq!(linked.store().engaged, ExtensionPersistenceMode::Persisted);
        assert_eq!(
            linked.store().cache_db,
            primary.store().cache_db,
            "a linked worktree must engage the primary checkout's shared cache"
        );
        assert!(
            !linked_root.join(".bifrost").exists(),
            "a linked worktree must not fork a private cache"
        );
    }
}
