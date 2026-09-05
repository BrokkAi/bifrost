use super::typestate::{
    TypestateFindingKind as WireTypestateFindingKind, typestate_request_digest,
};
use super::*;
use brokk_bifrost_analysis::analyzer::semantic::cfg_algorithms::ProcedureControlDependenceStop;
use brokk_bifrost_analysis::analyzer::semantic::{
    AbstractObject, AccessPathRoot, ObjectCardinality, ProcedureHandle, ProgramPointHandle,
    ReturnTransferKind, SemanticCallSite, ValueId, WorkspaceIcfgProvider,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    CandidateCoverage, EvidenceCompleteness, MoveInvalidation, OracleCallContext,
    ProcedureSemantics, ProofStatus, SemanticBudget, SemanticLocator, SemanticOutcome,
    SemanticRequest, SourceMappingId, TransferKind, TransferOperation, ValueFlowEndpoint,
    ValueFlowOracle, ValueFlowRelationKind, ValuePreservation, WorkspaceSemanticOracle,
    cfg_algorithms::derive_procedure_control_dependence,
};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, AnalyzerQueryScope, FilesystemProject, InformationTier, OverlayProject,
    Project, ProjectFile, WorkspaceAnalyzer, common::language_for_file,
};
use brokk_bifrost_flow::dataflow::{
    DataflowRequest, SemanticInputStatus, SolverBudget, SolverTermination, SolverWork,
    SummaryReadRecorder, SummaryWitnessStepKind, WitnessReconstructionLimits,
};
use brokk_bifrost_flow::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, ProductionTypestateExecutionContext,
    ProtocolEventKey, ProtocolExpectationKey, ProtocolSpec, ProtocolStateKey,
    TypestateBindingContext, TypestateBindingPlan, TypestateBindingQuality,
    TypestateEventBindingSpec, TypestateFinding, TypestateFindingCertainty, TypestateFindingKind,
    TypestateFindingLimits, TypestateInitialSeedSpec, TypestateObjectRole,
    TypestateObservationSite, TypestateSubjectClassKey, TypestateSubjectKey,
    TypestateTerminalBindingSpec, TypestateUncertainty, collect_summary_findings_with_limits,
    solve_typestate_with_production_summaries,
};
use brokk_bifrost_flow::{FlowWorkspaceState, value_flow::ValueFlowCarrier};
use brokk_bifrost_rql::{
    CodeQueryCompletion, CodeQueryExecutionLimits, execute_workspace_request_with_cancellation,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt, path::PathBuf, sync::Arc};

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
/// `engaged` reports what the built store is, not what the caller asked for, so
/// a host reads the decision as data instead of inferring it from timing. The
/// engine no longer degrades: a persisted request over a project with no
/// persistence root fails the open with a guided error, so a successful
/// persisted open always reports `Persisted` and a `cache_db`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionStoreReport {
    pub requested: ExtensionPersistenceMode,
    pub engaged: ExtensionPersistenceMode,
    /// The on-disk store the workspace answers from, present exactly when
    /// `engaged` is [`ExtensionPersistenceMode::Persisted`]. For a linked
    /// worktree this is the primary checkout's shared database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_db: Option<Box<str>>,
    /// Degradation record. Retained for wire stability and always empty now
    /// that the engine fails a persisted request it cannot honor instead of
    /// quietly serving an in-memory store.
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
    /// Comparison identity for analyzed workspace content. The derivation does
    /// not add the absolute root or package version; different roots agree
    /// when their literal analyzer configurations agree. Path-bearing configs
    /// can still differ, and this does not replace the local, store-scoped
    /// `generation`.
    pub content_identity: WorkspaceContentIdentity,
    pub capabilities: ExtensionCapabilityReport,
    pub store: ExtensionStoreReport,
    /// Information tiers crossed while the analyzer was constructed by open.
    /// This is separate from per-operation reports, whose scopes begin only
    /// after the workspace exists.
    #[serde(default)]
    pub open_tiers: ExtensionTierReport,
    /// Workspace files excluded from analysis at open time (for example
    /// binary content, which cannot enter the UTF-8 source overlay). Recorded
    /// so an extension can distinguish "present but not analyzed" from
    /// "absent"; an empty slice means every listed file was acquired.
    #[serde(default)]
    pub open_diagnostics: Box<[ExtensionDiagnostic]>,
}

pub struct ExtensionWorkspace {
    generation: WorkspaceGeneration,
    content_identity: WorkspaceContentIdentity,
    capabilities: ExtensionCapabilityReport,
    store: ExtensionStoreReport,
    open_tiers: ExtensionTierReport,
    open_diagnostics: Box<[ExtensionDiagnostic]>,
    analyzer: WorkspaceAnalyzer,
    flow_state: FlowWorkspaceState,
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
        let (analyzer, build_tier_access) = match options.persistence {
            ExtensionPersistenceMode::Ephemeral => {
                WorkspaceAnalyzer::build_ephemeral_with_tier_access_footgun(
                    Arc::clone(&project),
                    options.analyzer_config.clone(),
                )
                .map_err(|error| {
                    ExtensionWorkspaceError::Analyzer(error.to_string().into_boxed_str())
                })?
            }
            ExtensionPersistenceMode::Persisted => {
                WorkspaceAnalyzer::build_persisted_with_tier_access(
                    Arc::clone(&project),
                    options.analyzer_config.clone(),
                )
                .map_err(|error| {
                    ExtensionWorkspaceError::Store(error.to_string().into_boxed_str())
                })?
            }
        };
        // Report the store the build actually produced rather than echoing the
        // request, so the persistence decision surfaces as data. The engine is
        // strict: a persisted build that cannot find a persistence root errors
        // out above rather than returning an in-memory store, so a persisted
        // request that got here has a store path.
        let store = match options.persistence {
            ExtensionPersistenceMode::Persisted => {
                let path = analyzer.persisted_store_path().expect(
                    "a persisted build reaching here has a store path: the engine rejects a \
                     persisted request over a project with no persistence root",
                );
                ExtensionStoreReport {
                    requested: ExtensionPersistenceMode::Persisted,
                    engaged: ExtensionPersistenceMode::Persisted,
                    cache_db: Some(path.to_string_lossy().into_owned().into_boxed_str()),
                    diagnostics: Box::new([]),
                }
            }
            ExtensionPersistenceMode::Ephemeral => ExtensionStoreReport {
                requested: ExtensionPersistenceMode::Ephemeral,
                engaged: ExtensionPersistenceMode::Ephemeral,
                cache_db: None,
                diagnostics: Box::new([]),
            },
        };
        let identities = workspace_identities_for(&analyzer, &options.analyzer_config)?;
        let open_tiers = ExtensionTierReport {
            syntax: build_tier_access.tier_access_count(InformationTier::Syntax) as u64,
            imports: build_tier_access.tier_access_count(InformationTier::Imports) as u64,
            supertypes: build_tier_access.tier_access_count(InformationTier::Supertypes) as u64,
            usage_graph: build_tier_access.tier_access_count(InformationTier::UsageGraph) as u64,
        };
        // Every semantic operation on this surface -- control flow, value
        // dependence, and typestate -- is served by the same per-file
        // execution-semantics provider, so all three rows are derived from
        // whether this workspace actually has one for that language's files.
        // Deriving beats a second hand-maintained table, which is what #2328
        // found wrong with the operation list in the first place.
        let mut semantic_languages = std::collections::BTreeSet::new();
        for file in files.iter() {
            if analyzer.program_semantics_provider_for_file(file).is_some() {
                semantic_languages.insert(language_for_file(file));
            }
        }
        let languages = analyzer
            .analyzer()
            .languages()
            .into_iter()
            .map(|language| {
                let served = semantic_languages.contains(&language);
                LanguageCapabilityReport {
                    language: format!("{language:?}")
                        .to_ascii_lowercase()
                        .into_boxed_str(),
                    control_flow: if served {
                        CapabilitySupport::Complete
                    } else {
                        CapabilitySupport::Unsupported
                    },
                    // `Partial` for both derived operations: the lowering is
                    // present, and how much of it a given procedure supports is
                    // reported per request rather than promised here.
                    value_dependence: if served {
                        CapabilitySupport::Partial
                    } else {
                        CapabilitySupport::Unsupported
                    },
                    typestate: if served {
                        CapabilitySupport::Partial
                    } else {
                        CapabilitySupport::Unsupported
                    },
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let capabilities = ExtensionCapabilityReport {
            generation: identities.generation.clone(),
            languages,
            // Projected from the one published-surface table so the report and
            // `negotiate_extension_api` cannot disagree (#2328).
            operations: PUBLISHED_OPERATIONS
                .iter()
                .map(|operation| OperationCapability {
                    id: capability(operation.id),
                    stability: operation.stability,
                    support: operation.support,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        };
        Ok(Self {
            generation: identities.generation,
            content_identity: identities.content_identity,
            capabilities,
            store,
            open_tiers,
            open_diagnostics: open_diagnostics.into_boxed_slice(),
            analyzer,
            flow_state: FlowWorkspaceState::new(),
        })
    }
    pub fn generation(&self) -> &WorkspaceGeneration {
        &self.generation
    }
    /// Returns the portable identity of this open workspace's frozen content.
    ///
    /// The identity hashes normalized workspace source, the literal analyzer
    /// configuration representation, and a manually versioned content domain;
    /// it does not add the absolute root or package version. External
    /// dependency bytes are represented separately by artifact manifest
    /// dependency fingerprints.
    pub fn content_identity(&self) -> &WorkspaceContentIdentity {
        &self.content_identity
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

    /// Information tiers crossed while constructing this workspace.
    ///
    /// This report is complete when [`Self::open`] returns and is independent
    /// from the per-operation tier reports returned by later requests.
    pub fn open_tiers(&self) -> ExtensionTierReport {
        self.open_tiers
    }
    pub fn describe(&self) -> ExtensionWorkspaceDescription {
        ExtensionWorkspaceDescription {
            api: EXTENSION_API_VERSION,
            generation: self.generation.clone(),
            content_identity: self.content_identity.clone(),
            capabilities: self.capabilities.clone(),
            store: self.store.clone(),
            open_tiers: self.open_tiers,
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
        // Same reason as in `semantic_relations`: the rung report is only
        // truthful for work that ran under a scope this surface holds (#2414).
        let scope =
            AnalyzerQueryScope::with_cancellation(self.analyzer.analyzer(), cancellation.token());
        let response = execute_workspace_request_with_cancellation(
            &self.analyzer,
            &self.flow_state,
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
        Ok(with_tiers(
            make_outcome(
                Some(value),
                completion,
                &self.generation,
                &request.limits,
                "structural.query",
                ApiStability::Stable,
                work,
            ),
            &scope,
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
        // One request boundary around every analyzer read this snapshot makes:
        // it shares request memoization across the whole operation (the #1181
        // fix shape) and, because tier crossings are recorded on every open
        // scope, it is what makes the rung report below observable (#2414).
        let scope =
            AnalyzerQueryScope::with_cancellation(self.analyzer.analyzer(), cancellation.token());
        let root = self.analyzer.analyzer().project().root();
        let file = ProjectFile::new(root.to_path_buf(), seed.path.as_str());
        if self
            .analyzer
            .program_semantics_provider_for_file(&file)
            .is_none()
        {
            return Ok(with_tiers(
                make_outcome(
                    None,
                    ExtensionCompletion::Unsupported {
                        capability: capability(operation),
                    },
                    &self.generation,
                    &ExtensionLimits::default(),
                    operation,
                    stability,
                    ExtensionWork::default(),
                ),
                &scope,
            ));
        }
        let values = request.limits;
        let mut budget_limits = SemanticBudget::default().limits();
        budget_limits.source_bytes = usize::try_from(values.max_source_bytes).unwrap_or(usize::MAX);
        let mut budget = SemanticBudget::new(budget_limits)
            .expect("validated source limit preserves positive semantic budget limits");
        let mut semantic_request = SemanticRequest::new(&mut budget, cancellation.token());
        let materialized = self
            .analyzer
            .materialize_program_semantics(&file, &mut semantic_request)
            .map_err(|error| ExtensionError::Execution(error.to_string().into_boxed_str()))?;
        let completion = semantic_completion(&materialized);
        let source_bytes = materialized.work().source_bytes as u64;
        let Some(artifact) = materialized.available_value() else {
            return Ok(with_tiers(
                make_outcome(
                    None,
                    completion,
                    &self.generation,
                    &ExtensionLimits::default(),
                    operation,
                    stability,
                    ExtensionWork {
                        source_bytes,
                        ..Default::default()
                    },
                ),
                &scope,
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
            return Ok(with_tiers(
                make_outcome(
                    None,
                    ExtensionCompletion::Unknown,
                    &self.generation,
                    &ExtensionLimits::default(),
                    operation,
                    stability,
                    ExtensionWork::default(),
                ),
                &scope,
            ));
        };
        let wants_value = request
            .relations
            .contains(&SemanticRelationKind::ValueDependence);
        // Caller-supplied dimensions this derivation actually exhausted, in the
        // order they were hit. Kept as data rather than one boolean so the
        // result can name the limit to raise (#2412).
        let mut exhausted = ExhaustedBudgets::default();
        if procedure.points().len() > values.max_nodes as usize {
            exhausted.record("max_nodes", SemanticRelationBoundaryKind::NodeLimit);
        }
        if procedure.control_edges().len() > values.max_edges as usize {
            exhausted.record("max_edges", SemanticRelationBoundaryKind::EdgeLimit);
        }
        // Anchors are derived over *every* point of the procedure, in document
        // order, before the node budget is applied: an occurrence ordinal must
        // be a property of the procedure's own text, not of how many nodes this
        // particular request happened to be allowed to emit.
        let source = self
            .analyzer
            .analyzer()
            .project()
            .read_source_snapshot(&file)
            .map_err(|error| ExtensionError::Execution(error.to_string().into_boxed_str()))?;
        let anchors = semantic_node_anchors(procedure, source.source());
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
                let anchor = &anchors[local_id];
                SemanticNodeOccurrence {
                    local_id: local_id as u32,
                    stable_id: stable_semantic_id(&SemanticNodeAnchor {
                        path: seed.path.as_str(),
                        owner: &anchor.owner,
                        slice: &anchor.slice,
                        occurrence_ordinal: anchor.occurrence_ordinal,
                    }),
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
        let source_span = |mapping_id| semantic_source_span(procedure, &seed.path, mapping_id);
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
            // A caller's own work limit is not an execution failure: exhausting
            // it is an answer about that limit, reported as the exhausted
            // dimension rather than as an error (#2412).
            let dependence = match derive_procedure_control_dependence(
                procedure,
                usize::try_from(values.max_traversal_steps).unwrap_or(usize::MAX),
                cancellation.token(),
            ) {
                Ok(dependence) => Some(dependence),
                Err(ProcedureControlDependenceStop::ExceededBudget { .. }) => {
                    exhausted.record(
                        "max_traversal_steps",
                        SemanticRelationBoundaryKind::TraversalStepLimit,
                    );
                    None
                }
                Err(ProcedureControlDependenceStop::Cancelled) => {
                    return Ok(with_tiers(
                        make_outcome(
                            None,
                            ExtensionCompletion::Cancelled,
                            &self.generation,
                            &ExtensionLimits::default(),
                            operation,
                            stability,
                            ExtensionWork::default(),
                        ),
                        &scope,
                    ));
                }
                Err(ProcedureControlDependenceStop::Failed(message)) => {
                    return Err(ExtensionError::Execution(message));
                }
            };
            if let Some(dependence) = dependence {
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
                        reason_summary: None,
                    }
                }));
            }
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
                if snapshot.relations().len() > values.max_value_dependence_edges as usize {
                    exhausted.record(
                        "max_value_dependence_edges",
                        SemanticRelationBoundaryKind::EdgeLimit,
                    );
                }
                // Non-exhaustive candidate coverage is a property of what the
                // value-flow analysis could see, not of any caller limit: it is
                // a frontier, and raising every budget returns it again.
                if snapshot.coverage() != CandidateCoverage::Exhaustive {
                    let semantic_gaps = snapshot
                        .procedure()
                        .semantics()
                        .gaps()
                        .iter()
                        .filter(|gap| {
                            brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::gap_impacts_value_flow(
                                gap,
                            ) && !snapshot.gap_is_discharged(gap.id)
                        })
                        .map(|gap| {
                            let evidence = procedure
                                .evidence_row(gap.evidence)
                                .expect("validated semantic-gap evidence");
                            SemanticGapReason {
                                capability: gap.capability.label().into(),
                                kind: gap.kind.label().into(),
                                impacts: gap
                                    .impacts
                                    .iter()
                                    .map(|impact| impact.label().into())
                                    .collect(),
                                subject: gap.subject.label().into(),
                                detail: gap.detail.clone(),
                                span: source_span(gap.source),
                                evidence: SemanticEvidence {
                                    kind: "semantic_gap".into(),
                                    mappings: evidence
                                        .sources
                                        .iter()
                                        .copied()
                                        .map(source_span)
                                        .collect(),
                                    proof: match &evidence.proof {
                                        ProofStatus::Proven => SemanticProof::Proven,
                                        ProofStatus::Unproven(reason) => {
                                            SemanticProof::Unproven {
                                                reason: reason.clone(),
                                            }
                                        }
                                    },
                                    completeness: match &evidence.completeness {
                                        EvidenceCompleteness::Complete => {
                                            SemanticRelationCompleteness::Complete
                                        }
                                        EvidenceCompleteness::Partial(reason) => {
                                            SemanticRelationCompleteness::Partial {
                                                reason: reason.clone(),
                                            }
                                        }
                                    },
                                },
                            }
                        })
                        .collect::<Vec<_>>();
                    relation_boundaries.push(SemanticRelationBoundary {
                        kind: SemanticRelationBoundaryKind::MissingSemantics,
                        at: None,
                        relations: vec![SemanticRelationKind::ValueDependence].into_boxed_slice(),
                        message: "value-flow candidate coverage is not exhaustive".into(),
                        evidence: Box::new([]),
                        reason_summary: if semantic_gaps.is_empty() {
                            None
                        } else {
                            Some(
                                SemanticGapReasonSummary::new(semantic_gaps).map_err(|error| {
                                    ExtensionError::Execution(error.to_string().into_boxed_str())
                                })?,
                            )
                        },
                    });
                }
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
                            transfer: relation
                                .transfer
                                .map(|transfer| {
                                    value_transfer_detail(
                                        transfer,
                                        procedure,
                                        &seed.path,
                                        &point_node.stable_id,
                                    )
                                })
                                .transpose()?,
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
        if derived_edge_count > values.max_edges as usize {
            exhausted.record("max_edges", SemanticRelationBoundaryKind::EdgeLimit);
        }
        let work = ExtensionWork {
            semantic_nodes: nodes.len() as u64,
            semantic_edges: edges.len() as u64,
            source_bytes,
            traversal_steps: algorithm_work,
            ..Default::default()
        };
        let request_digest = request_digest(&request)
            .map_err(|error| ExtensionError::InvalidRequest(error.to_string().into()))?;
        // A boundary per exhausted dimension, each naming its own limit: the
        // consumer's question is "which number do I raise?", and one synthetic
        // `NodeLimit` saying "node or edge" could not answer it (#2412).
        let mut boundaries = exhausted
            .dimensions
            .iter()
            .map(|dimension| SemanticRelationBoundary {
                kind: dimension.kind,
                at: None,
                relations: request.relations.clone(),
                message: format!("{} exhausted", dimension.limit).into_boxed_str(),
                evidence: Box::new([]),
                reason_summary: None,
            })
            .collect::<Vec<_>>();
        // Frontier boundaries are carried alongside, never folded into the
        // budget verdict: a genuine analysis frontier is the same answer at
        // every budget, so it must not report as truncation.
        let frontier_kinds = distinct_kinds(&relation_boundaries);
        boundaries.extend(relation_boundaries);
        // Precedence when both occurred: budget-bounded wins, because it is the
        // caller-actionable state. The frontier boundaries stay in the snapshot.
        let (status, snapshot_completion) = match (exhausted.dimensions.first(), frontier_kinds) {
            (Some(dimension), _) => (
                SemanticRelationStatus::BudgetBounded,
                ExtensionCompletion::Truncated {
                    limit: dimension.limit.into(),
                },
            ),
            (None, kinds) if !kinds.is_empty() => (
                SemanticRelationStatus::FrontierBounded,
                ExtensionCompletion::FrontierBounded { kinds },
            ),
            (None, _) => (SemanticRelationStatus::Complete, completion),
        };
        let snapshot = SemanticRelationSnapshot::try_new(
            self.generation.clone(),
            request_digest,
            status,
            nodes,
            edges,
            boundaries,
        )
        .map_err(|error| ExtensionError::Execution(error.to_string().into()))?;
        Ok(with_tiers(
            make_outcome(
                Some(snapshot),
                snapshot_completion,
                &self.generation,
                &ExtensionLimits::default(),
                operation,
                stability,
                work,
            ),
            &scope,
        ))
    }

    /// Answer one bounded typestate question about one procedure.
    ///
    /// The caller owns the automaton and every binding: the protocol document
    /// is compiled for this request only, and each observation is a source span
    /// the caller chose. That keeps the boundary handle-free, which is what
    /// made the internal registration model unusable here, and it keeps the
    /// answer bounded -- the analysis root is one procedure, the solver runs
    /// under the request's own budget, and finding and witness retention are
    /// caller limits rather than engine defaults.
    pub fn typestate_check(
        &self,
        request: TypestateRequest,
        cancellation: &ExtensionCancellation,
    ) -> Result<ExtensionOutcome<TypestateSnapshot>, ExtensionError> {
        self.validate(&request.compatibility, &request.expected_generation)?;
        request
            .validate()
            .map_err(|error| ExtensionError::InvalidRequest(error.to_string().into()))?;
        let stability = ApiStability::Experimental { since_minor: 1 };
        let operation = TYPESTATE_OPERATION;
        let echoed = ExtensionLimits::default();
        if !matches!(request.scope, SemanticRelationScope::Procedure) {
            return Err(ExtensionError::InvalidRequest(
                "typestate serves the procedure scope only in this API version".into(),
            ));
        }
        if cancellation.is_cancelled() {
            return Ok(make_outcome(
                None,
                ExtensionCompletion::Cancelled,
                &self.generation,
                &echoed,
                operation,
                stability,
                ExtensionWork::default(),
            ));
        }
        let request_digest = typestate_request_digest(&request)
            .map_err(|error| ExtensionError::Execution(error.to_string().into()))?;
        // Compile before any analysis: an automaton that does not compile is a
        // request error, and rejecting it here keeps a hostile document cheap.
        let protocol_bytes = serde_json::to_vec(&request.protocol)
            .map_err(|error| ExtensionError::InvalidRequest(error.to_string().into()))?;
        let protocol = ProtocolSpec::from_json(&protocol_bytes)
            .map_err(|error| {
                ExtensionError::InvalidRequest(
                    format!("invalid typestate protocol document: {error}").into(),
                )
            })?
            .compile()
            .map_err(|error| {
                ExtensionError::InvalidRequest(
                    format!("typestate protocol does not compile: {error}").into(),
                )
            })?;
        let protocol_hash = StableDigest::parse(protocol.hash().to_string())
            .expect("a protocol hash renders as lower-hex SHA-256");

        // One request boundary around every analyzer read, for the same reason
        // `semantic_relations` opens one: shared request memoization, and a
        // tier report that is only truthful for work under an open scope.
        let scope =
            AnalyzerQueryScope::with_cancellation(self.analyzer.analyzer(), cancellation.token());
        let project_root = self.analyzer.analyzer().project().root();
        let seed_path = request.subject.acquisition.path.clone();
        let file = ProjectFile::new(project_root.to_path_buf(), seed_path.as_str());
        if self
            .analyzer
            .program_semantics_provider_for_file(&file)
            .is_none()
        {
            return Ok(with_tiers(
                make_outcome(
                    None,
                    ExtensionCompletion::Unsupported {
                        capability: capability(operation),
                    },
                    &self.generation,
                    &echoed,
                    operation,
                    stability,
                    ExtensionWork::default(),
                ),
                &scope,
            ));
        }

        let values = request.limits;
        let mut budget_limits = SemanticBudget::default().limits();
        budget_limits.source_bytes = usize::try_from(values.max_source_bytes).unwrap_or(usize::MAX);
        let mut budget = SemanticBudget::new(budget_limits)
            .expect("a validated source limit preserves positive semantic budget limits");
        let materialized = {
            let mut semantic_request = SemanticRequest::new(&mut budget, cancellation.token());
            self.analyzer
                .materialize_program_semantics(&file, &mut semantic_request)
                .map_err(|error| ExtensionError::Execution(error.to_string().into_boxed_str()))?
        };
        let materialize_completion = semantic_completion(&materialized);
        let source_bytes = materialized.work().source_bytes as u64;
        let Some(artifact) = materialized.available_value() else {
            return Ok(with_tiers(
                make_outcome(
                    None,
                    materialize_completion,
                    &self.generation,
                    &echoed,
                    operation,
                    stability,
                    ExtensionWork {
                        source_bytes,
                        ..Default::default()
                    },
                ),
                &scope,
            ));
        };
        let acquisition = &request.subject.acquisition;
        let acquisition_start = u32::try_from(acquisition.start_utf8_byte).map_err(|_| {
            ExtensionError::InvalidRequest("acquisition byte offset exceeds u32".into())
        })?;
        let procedure = artifact
            .procedures()
            .iter()
            .filter(|procedure| {
                let span = procedure.locator().anchor().span();
                span.start_byte() <= acquisition_start && acquisition_start <= span.end_byte()
            })
            .min_by_key(|procedure| {
                procedure.locator().anchor().span().end_byte()
                    - procedure.locator().anchor().span().start_byte()
            });
        let Some(procedure) = procedure else {
            return Ok(with_tiers(
                make_outcome(
                    None,
                    ExtensionCompletion::Unknown,
                    &self.generation,
                    &echoed,
                    operation,
                    stability,
                    ExtensionWork {
                        source_bytes,
                        ..Default::default()
                    },
                ),
                &scope,
            ));
        };
        let root = artifact
            .procedure_handle(procedure.id())
            .expect("a materialized artifact owns every procedure it lists");
        let bindings = lower_typestate_bindings(&protocol, &request, procedure, &root)
            .map_err(|error| ExtensionError::InvalidRequest(error.into()))?;

        let solver_limits = clamp_solver_work(values.max_solver_steps);
        let summaries = self.flow_state.typestate_summaries();
        let summary_reads = SummaryReadRecorder::new(self.analyzer.analyzer());
        let icfg = WorkspaceIcfgProvider::new(&self.analyzer);
        let mut solver_budget = SolverBudget::new(solver_limits);
        let mut dataflow_request = DataflowRequest::new(&mut solver_budget, cancellation.token());
        let solved = solve_typestate_with_production_summaries(
            summaries.as_ref(),
            &summary_reads,
            &root,
            &[],
            &icfg,
            &icfg,
            ProductionTypestateExecutionContext::Workspace,
            &protocol,
            &bindings,
            &mut budget,
            &mut dataflow_request,
        )
        .map_err(|error| ExtensionError::Execution(error.to_string().into_boxed_str()))?;

        let mut boundaries: Vec<TypestateBoundary> = Vec::new();
        match solved.result().result().termination() {
            SolverTermination::FixedPoint => {}
            SolverTermination::Cancelled => boundaries.push(TypestateBoundary {
                kind: TypestateBoundaryKind::Cancelled,
                message: "the typestate solver was cancelled".into(),
                omitted: 0,
            }),
            SolverTermination::ExceededBudget(exceeded) => boundaries.push(TypestateBoundary {
                kind: TypestateBoundaryKind::SolverWorkLimit,
                message: exceeded.to_string().into_boxed_str(),
                omitted: 0,
            }),
        }
        if let SemanticInputStatus::ExceededBudget { exceeded } =
            solved.result().result().coverage().semantic_status()
        {
            boundaries.push(TypestateBoundary {
                kind: TypestateBoundaryKind::SemanticWorkLimit,
                message: exceeded.to_string().into_boxed_str(),
                omitted: 0,
            });
        }
        let reached_rows = solved.result().result().reached().len() as u64;

        let finding_limits = TypestateFindingLimits::with_witness_limits(
            values.max_reached_rows as usize,
            values.max_findings as usize,
            WitnessReconstructionLimits::new(
                values.max_witness_steps as usize,
                values.max_witness_expansions as usize,
            )
            .expect("validated typestate witness limits are positive"),
            values.max_total_witness_expansions as usize,
            usize::try_from(values.max_witness_bytes).unwrap_or(usize::MAX),
        )
        .expect("validated typestate finding limits are within the engine bounds");
        let report = collect_summary_findings_with_limits(
            &protocol,
            &bindings,
            solved.result(),
            finding_limits,
            cancellation.token(),
        )
        .map_err(|error| ExtensionError::Execution(error.to_string().into_boxed_str()))?;

        if report.omitted() > 0 {
            boundaries.push(TypestateBoundary {
                kind: TypestateBoundaryKind::FindingLimit,
                message: "finding retention omitted at least one typestate finding".into(),
                omitted: report.omitted() as u64,
            });
        }
        if !report.analysis_complete() {
            boundaries.push(TypestateBoundary {
                kind: TypestateBoundaryKind::AnalysisIncomplete,
                message: "typestate analysis retained incomplete semantic evidence".into(),
                omitted: 0,
            });
        }

        let mut findings = Vec::with_capacity(report.findings().len());
        let mut omitted_witness_steps = 0_u64;
        for finding in report.findings() {
            let record = project_typestate_finding(&self.analyzer, &protocol, &bindings, finding)?;
            omitted_witness_steps = omitted_witness_steps.saturating_add(
                record
                    .witnesses
                    .iter()
                    .map(|witness| witness.omitted_steps_lower_bound)
                    .sum::<u64>(),
            );
            findings.push(record);
        }
        if omitted_witness_steps > 0 {
            boundaries.push(TypestateBoundary {
                kind: TypestateBoundaryKind::WitnessLimit,
                message: "witness reconstruction omitted at least one step".into(),
                omitted: omitted_witness_steps,
            });
        }

        let cancelled = boundaries
            .iter()
            .any(|boundary| boundary.kind == TypestateBoundaryKind::Cancelled);
        let budget_boundary = boundaries
            .iter()
            .find(|boundary| boundary.kind.is_budget())
            .map(|boundary| boundary.kind);
        let status = if cancelled {
            SemanticRelationStatus::Cancelled
        } else if budget_boundary.is_some() {
            SemanticRelationStatus::BudgetBounded
        } else if boundaries.is_empty() {
            SemanticRelationStatus::Complete
        } else {
            SemanticRelationStatus::FrontierBounded
        };
        // A frontier-bounded typestate answer is `Unproven`, not
        // `FrontierBounded`: the completion envelope's frontier kinds are the
        // relation vocabulary, and this surface's frontier reasons are protocol
        // reasons. Budget exhaustion stays actionable and names its dimension.
        let completion = if cancelled {
            ExtensionCompletion::Cancelled
        } else if let Some(kind) = budget_boundary {
            ExtensionCompletion::Truncated {
                limit: kind.limit_label().into(),
            }
        } else if boundaries.is_empty() {
            materialize_completion
        } else {
            ExtensionCompletion::Unproven
        };
        let snapshot = TypestateSnapshot::try_new(
            self.generation.clone(),
            request_digest,
            protocol_hash,
            status,
            findings,
            boundaries,
        )
        .map_err(|error| ExtensionError::Execution(error.to_string().into()))?;
        let work = ExtensionWork {
            result_items: snapshot.findings.len() as u64,
            result_bytes: encode_typestate_snapshot_json(&snapshot)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0),
            semantic_nodes: reached_rows,
            semantic_edges: bindings.event_bindings().len() as u64,
            source_bytes,
            traversal_steps: 0,
        };
        Ok(with_tiers(
            make_outcome(
                Some(snapshot),
                completion,
                &self.generation,
                &echoed,
                operation,
                stability,
                work,
            ),
            &scope,
        ))
    }
}

/// The per-dimension solver budget one typestate request buys.
///
/// A uniform caller value clamped elementwise to the engine's own limits, so a
/// request can only ever narrow the bound. `a - (a - b)` under saturating
/// subtraction is the elementwise minimum, which keeps the clamp total without
/// a per-dimension setter the work vocabulary deliberately does not have.
fn clamp_solver_work(max_solver_steps: u64) -> SolverWork {
    let requested = SolverWork::uniform(usize::try_from(max_solver_steps).unwrap_or(usize::MAX));
    let engine = SolverWork::default_limits();
    engine.saturating_sub(engine.saturating_sub(requested))
}

/// Every call site one request span names, tightest match first.
///
/// One written call can lower to more than one semantic call site (a Java
/// `finally` body lowers once per completion route), so this returns a set
/// rather than a single site, and a caller's binding applies to all of them.
/// The ranking prefers the smallest call that encloses the span, then the
/// largest call the span itself encloses; nothing is matched by text.
fn call_sites_for_span(
    procedure: &ProcedureSemantics,
    start: u32,
    end: u32,
) -> Vec<&SemanticCallSite> {
    let bounds = |call: &SemanticCallSite| {
        let span = procedure
            .source_mapping(call.source)
            .expect("a validated call site has a source mapping")
            .locator
            .anchor()
            .span();
        (span.start_byte(), span.end_byte())
    };
    let mut enclosing = procedure
        .call_sites()
        .iter()
        .filter(|call| {
            let (call_start, call_end) = bounds(call);
            call_start <= start && end <= call_end
        })
        .collect::<Vec<_>>();
    if !enclosing.is_empty() {
        let tightest = enclosing
            .iter()
            .map(|call| {
                let (call_start, call_end) = bounds(call);
                call_end - call_start
            })
            .min()
            .expect("a nonempty candidate set has a minimum width");
        enclosing.retain(|call| {
            let (call_start, call_end) = bounds(call);
            call_end - call_start == tightest
        });
        return enclosing;
    }
    let mut enclosed = procedure
        .call_sites()
        .iter()
        .filter(|call| {
            let (call_start, call_end) = bounds(call);
            start <= call_start && call_end <= end
        })
        .collect::<Vec<_>>();
    if enclosed.is_empty() {
        return enclosed;
    }
    let widest = enclosed
        .iter()
        .map(|call| {
            let (call_start, call_end) = bounds(call);
            call_end - call_start
        })
        .max()
        .expect("a nonempty candidate set has a maximum width");
    enclosed.retain(|call| {
        let (call_start, call_end) = bounds(call);
        call_end - call_start == widest
    });
    enclosed
}

/// The value one port names at one call site.
fn port_value(call: &SemanticCallSite, port: TypestatePort) -> Option<ValueId> {
    match port {
        TypestatePort::Receiver => call.receiver,
        TypestatePort::Argument { ordinal } => call
            .arguments
            .get(ordinal as usize)
            .map(|argument| argument.value),
        TypestatePort::NormalResult { ordinal } => call.normal_result(ordinal as usize),
    }
}

const fn observation_role(role: TypestateRole) -> TypestateObjectRole {
    match role {
        TypestateRole::MatchedValue => TypestateObjectRole::MatchedValue,
        TypestateRole::AllocationResult => TypestateObjectRole::AllocationResult,
        TypestateRole::Receiver => TypestateObjectRole::Receiver,
        TypestateRole::Argument => TypestateObjectRole::Argument,
        TypestateRole::NormalReturn => TypestateObjectRole::NormalReturn,
        TypestateRole::ExceptionalReturn => TypestateObjectRole::ExceptionalReturn,
        TypestateRole::CurrentObject => TypestateObjectRole::CurrentObject,
    }
}

/// Lower the caller's span-addressed bindings into one engine binding plan.
///
/// Every decision here is the caller's: the tracked object is the value the
/// subject's own port names, each event observes exactly the sites its span
/// resolves to, and terminals observe the root's own exits. Nothing is
/// inferred, so this never introduces an observation the compiled protocol
/// does not declare.
fn lower_typestate_bindings(
    protocol: &CompiledProtocol,
    request: &TypestateRequest,
    procedure: &ProcedureSemantics,
    root: &ProcedureHandle,
) -> Result<TypestateBindingPlan, String> {
    let quality = TypestateBindingQuality::proven_unique();
    let context = TypestateBindingContext::root();
    let span_bounds = |span: &SourceSpan| -> Result<(u32, u32), String> {
        let start = u32::try_from(span.start_utf8_byte)
            .map_err(|_| "a source span byte offset exceeds u32".to_string())?;
        let end = u32::try_from(span.end_utf8_byte)
            .map_err(|_| "a source span byte offset exceeds u32".to_string())?;
        Ok((start, end))
    };

    let (start, end) = span_bounds(&request.subject.acquisition)?;
    let acquisitions = call_sites_for_span(procedure, start, end);
    let [acquisition] = acquisitions.as_slice() else {
        return Err(format!(
            "the typestate subject span names {} call sites; it must name exactly one",
            acquisitions.len()
        ));
    };
    let value = port_value(acquisition, request.subject.port).ok_or_else(|| {
        format!(
            "the typestate subject port {:?} names no value at its acquisition call",
            request.subject.port
        )
    })?;
    let object =
        AbstractObject::new(
            AccessPathRoot::Value(root.value_handle(value).ok_or_else(|| {
                "the subject value is not scoped to the analysis root".to_string()
            })?),
            ObjectCardinality::Singleton,
        )
        .map_err(|error| format!("the typestate subject is not a tracked object: {error}"))?;
    let class = TypestateSubjectClassKey::new(request.subject.class.as_ref())
        .map_err(|error| format!("invalid typestate subject class: {error}"))?;
    let subject_key = TypestateSubjectKey::for_object(class.clone(), &object);

    let point_site = |id| {
        TypestateObservationSite::program_point(
            root.point_handle(id)
                .expect("a materialized procedure owns its own program points"),
            context.clone(),
        )
    };
    let site_for = |site: &TypestateSite| -> Result<Vec<TypestateObservationSite>, String> {
        Ok(match site {
            TypestateSite::ProcedureEntry => vec![point_site(procedure.entry_point())],
            TypestateSite::NormalExit => vec![point_site(procedure.normal_exit_point())],
            TypestateSite::ExceptionalExit => vec![point_site(procedure.exceptional_exit_point())],
            TypestateSite::Call { span, .. } => {
                let (start, end) = span_bounds(span)?;
                let calls = call_sites_for_span(procedure, start, end);
                if calls.is_empty() {
                    return Err(format!(
                        "no call site in the analysis root covers bytes {}..{} of {}",
                        span.start_utf8_byte,
                        span.end_utf8_byte,
                        span.path.as_str()
                    ));
                }
                calls
                    .into_iter()
                    .map(|call| {
                        TypestateObservationSite::call_site(
                            root.call_site_handle(call.id)
                                .expect("a materialized procedure owns its own call sites"),
                            context.clone(),
                        )
                    })
                    .collect()
            }
        })
    };

    let seeds = vec![TypestateInitialSeedSpec::new(
        subject_key.clone(),
        ProtocolStateKey::new(request.subject.initial_state.as_ref())
            .map_err(|error| format!("invalid typestate initial state: {error}"))?,
        point_site(procedure.entry_point()),
        TypestateObjectRole::MatchedValue,
        quality.clone(),
    )];

    let mut events = Vec::new();
    for binding in &request.events {
        let key = ProtocolEventKey::new(binding.event.as_ref())
            .map_err(|error| format!("invalid typestate event key: {error}"))?;
        for site in site_for(&binding.site)? {
            events.push(TypestateEventBindingSpec::new(
                key.clone(),
                subject_key.clone(),
                site,
                binding.order,
                observation_role(binding.role),
                quality.clone(),
            ));
        }
    }

    let mut terminals = Vec::new();
    for binding in &request.terminals {
        let key = ProtocolExpectationKey::new(binding.expectation.as_ref())
            .map_err(|error| format!("invalid typestate expectation key: {error}"))?;
        let point = match binding.exit {
            TypestateExit::Normal => procedure.normal_exit_point(),
            TypestateExit::Exceptional => procedure.exceptional_exit_point(),
        };
        terminals.push(TypestateTerminalBindingSpec::new(
            key,
            subject_key.clone(),
            point_site(point),
            TypestateObjectRole::CurrentObject,
            quality.clone(),
        ));
    }

    TypestateBindingPlan::try_new(
        protocol,
        vec![BoundTypestateSubjectSpec::new(class, object, quality)],
        seeds,
        events,
        terminals,
    )
    .map_err(|error| format!("the typestate bindings do not form a plan: {error:?}"))
}

/// The workspace-relative, slash-normalized span one semantic locator denotes.
fn locator_span(
    analyzer: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Result<SourceSpan, ExtensionError> {
    let root = analyzer.analyzer().project().root();
    let file = ProjectFile::new(root.to_path_buf(), locator.path().as_str());
    let rel_path = brokk_bifrost_analysis::path_utils::rel_path_string(&file);
    let span = locator.anchor().span();
    Ok(SourceSpan {
        path: NormalizedRelativePath::new(&rel_path)
            .map_err(|error| ExtensionError::Execution(error.to_string().into_boxed_str()))?,
        start_utf8_byte: span.start_byte() as u64,
        end_utf8_byte: span.end_byte() as u64,
    })
}

fn point_span(
    analyzer: &WorkspaceAnalyzer,
    handle: &ProgramPointHandle,
) -> Result<SourceSpan, ExtensionError> {
    let semantics = handle.procedure().semantics();
    let point = semantics
        .point(handle.id())
        .expect("a validated witness point resolves in its own procedure");
    let locator = &semantics
        .source_mapping(point.source)
        .expect("a validated witness point has a source mapping")
        .locator;
    locator_span(analyzer, locator)
}

/// Project one engine finding onto the wire, keeping every state, event, and
/// expectation as the caller's own key rather than a dense engine id.
fn project_typestate_finding(
    analyzer: &WorkspaceAnalyzer,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    finding: &TypestateFinding,
) -> Result<TypestateFindingRecord, ExtensionError> {
    let subject = bindings
        .subject(finding.subject())
        .expect("a validated finding subject resolves in its binding plan");
    let state_key = |state| {
        protocol
            .state_key(state)
            .expect("a validated finding state resolves")
            .to_string()
            .into_boxed_str()
    };
    let kind = match finding.kind() {
        TypestateFindingKind::ErrorTransition {
            event, from, to, ..
        } => WireTypestateFindingKind::ErrorTransition {
            event: protocol
                .event(*event)
                .expect("a validated finding event resolves")
                .key()
                .to_string()
                .into_boxed_str(),
            from_state: state_key(*from),
            to_state: state_key(*to),
        },
        TypestateFindingKind::TerminalExpectation {
            expectation,
            actual_states,
            ..
        } => WireTypestateFindingKind::TerminalExpectation {
            expectation: protocol
                .terminal_expectation(*expectation)
                .expect("a validated finding expectation resolves")
                .key()
                .to_string()
                .into_boxed_str(),
            actual_states: actual_states
                .iter()
                .map(|state| state_key(*state))
                .collect(),
        },
    };
    let evidence = finding.evidence();
    let mut witnesses = Vec::with_capacity(finding.witnesses().len());
    for finding_witness in finding.witnesses() {
        let witness = finding_witness.witness();
        let mut steps = Vec::with_capacity(witness.step_count());
        for step in witness.steps() {
            steps.push(TypestateWitnessStep {
                kind: match step.kind() {
                    SummaryWitnessStepKind::Seed => TypestateWitnessStepKind::Seed,
                    SummaryWitnessStepKind::Edge(kind) => TypestateWitnessStepKind::Edge {
                        edge_kind: kind.label().into(),
                    },
                    SummaryWitnessStepKind::EndSummaryGap(kind) => {
                        TypestateWitnessStepKind::EndSummaryGap {
                            return_kind: match kind {
                                ReturnTransferKind::Normal => TypestateReturnKind::Normal,
                                ReturnTransferKind::Exceptional => TypestateReturnKind::Exceptional,
                            },
                        }
                    }
                },
                source: point_span(analyzer, step.source())?,
                target: step
                    .target()
                    .map(|target| point_span(analyzer, target))
                    .transpose()?,
                proof: match step.proof() {
                    ProofStatus::Proven => SemanticProof::Proven,
                    ProofStatus::Unproven(reason) => SemanticProof::Unproven {
                        reason: reason.clone(),
                    },
                },
                completeness: match step.completeness() {
                    EvidenceCompleteness::Complete => SemanticRelationCompleteness::Complete,
                    EvidenceCompleteness::Partial(reason) => {
                        SemanticRelationCompleteness::Partial {
                            reason: reason.clone(),
                        }
                    }
                },
            });
        }
        witnesses.push(TypestateWitnessRecord {
            observed_state: finding_witness
                .observed_state()
                .and_then(|state| protocol.state_key(state))
                .map(|state| state.to_string().into_boxed_str()),
            steps: steps.into_boxed_slice(),
            truncated: witness.truncated(),
            omitted_steps_lower_bound: witness.omitted_steps_lower_bound() as u64,
        });
    }
    Ok(TypestateFindingRecord {
        subject: TypestateSubjectIdentity {
            class: subject.key().class().as_str().into(),
            identity: subject.key().public_canonical_rendering().into_boxed_str(),
        },
        site: locator_span(analyzer, finding.site())?,
        kind,
        certainty: match finding.certainty() {
            TypestateFindingCertainty::May => TypestateCertainty::May,
            TypestateFindingCertainty::Must => TypestateCertainty::Must,
            TypestateFindingCertainty::Inconclusive => TypestateCertainty::Inconclusive,
        },
        evidence: TypestateEvidence {
            path_proven: evidence.path_proven(),
            path_complete: evidence.path_complete(),
            analysis_complete: evidence.analysis_complete(),
            uncertainty: [
                (
                    TypestateUncertainty::AmbiguousDispatch,
                    TypestateUncertaintyKind::AmbiguousDispatch,
                ),
                (
                    TypestateUncertainty::UnknownCall,
                    TypestateUncertaintyKind::UnknownCall,
                ),
                (
                    TypestateUncertainty::ExternalCall,
                    TypestateUncertaintyKind::ExternalCall,
                ),
                (
                    TypestateUncertainty::Escape,
                    TypestateUncertaintyKind::Escape,
                ),
                (
                    TypestateUncertainty::IncompleteAnalysis,
                    TypestateUncertaintyKind::IncompleteAnalysis,
                ),
                (
                    TypestateUncertainty::UnmatchedEvent,
                    TypestateUncertaintyKind::UnmatchedEvent,
                ),
            ]
            .into_iter()
            .filter_map(|(internal, wire)| {
                evidence.uncertainty().contains(internal).then_some(wire)
            })
            .collect(),
            abstained: evidence.abstained(),
        },
        witnesses: witnesses.into_boxed_slice(),
        omitted_witnesses: finding.omitted_witnesses() as u64,
    })
}

/// The caller-supplied dimensions one derivation exhausted, in the order it hit
/// them, deduplicated. The first is the one the result's `limit` label names.
#[derive(Debug, Default)]
struct ExhaustedBudgets {
    dimensions: Vec<ExhaustedDimension>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExhaustedDimension {
    /// The request-limit field name, spelled as the caller spells it.
    limit: &'static str,
    kind: SemanticRelationBoundaryKind,
}

impl ExhaustedBudgets {
    fn record(&mut self, limit: &'static str, kind: SemanticRelationBoundaryKind) {
        debug_assert!(
            kind.is_budget(),
            "an exhausted budget must be reported with a budget boundary kind, got {kind:?}"
        );
        if !self
            .dimensions
            .iter()
            .any(|dimension| dimension.limit == limit)
        {
            self.dimensions.push(ExhaustedDimension { limit, kind });
        }
    }
}

/// The distinct boundary kinds present, sorted, for the frontier completion.
fn distinct_kinds(boundaries: &[SemanticRelationBoundary]) -> Box<[SemanticRelationBoundaryKind]> {
    let mut kinds = boundaries
        .iter()
        .map(|boundary| boundary.kind)
        .collect::<Vec<_>>();
    kinds.sort_unstable();
    kinds.dedup();
    kinds.into_boxed_slice()
}

/// Attaches the rung report (#2414 step 6) an operation's request scope
/// observed. Read at the end of the operation, so it covers every tier
/// crossing the answer paid for.
fn with_tiers<T>(
    mut outcome: ExtensionOutcome<T>,
    scope: &AnalyzerQueryScope<'_>,
) -> ExtensionOutcome<T> {
    outcome.metadata.tiers = ExtensionTierReport {
        syntax: scope.tier_access_count(InformationTier::Syntax) as u64,
        imports: scope.tier_access_count(InformationTier::Imports) as u64,
        supertypes: scope.tier_access_count(InformationTier::Supertypes) as u64,
        usage_graph: scope.tier_access_count(InformationTier::UsageGraph) as u64,
    };
    outcome
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
    let carrier = StableValueCarrier::new(&projection)
        .map_err(|error| ExtensionError::Execution(error.to_string().into()))?;
    Ok(ValueOccurrence {
        node: node.local_id,
        carrier,
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

fn semantic_source_span(
    procedure: &ProcedureSemantics,
    path: &NormalizedRelativePath,
    mapping_id: SourceMappingId,
) -> SourceSpan {
    let mapping = procedure
        .source_mapping(mapping_id)
        .expect("validated semantic source mapping");
    let span = mapping.locator.anchor().span();
    SourceSpan {
        path: path.clone(),
        start_utf8_byte: span.start_byte() as u64,
        end_utf8_byte: span.end_byte() as u64,
    }
}

fn value_transfer_detail(
    transfer: brokk_bifrost_analysis::analyzer::semantic::ValueTransfer,
    procedure: &ProcedureSemantics,
    path: &NormalizedRelativePath,
    point_identity: &StableDigest,
) -> Result<ValueTransfer, ExtensionError> {
    let kind = match transfer.kind {
        TransferKind::Copy => ValueTransferKind::Copy,
        TransferKind::AggregateCopy => ValueTransferKind::AggregateCopy,
        TransferKind::Move { invalidation } => ValueTransferKind::Move {
            invalidation: match invalidation {
                MoveInvalidation::Invalidated => ValueMoveInvalidation::Invalidated,
                MoveInvalidation::Unknown => ValueMoveInvalidation::Unknown,
            },
        },
        TransferKind::Conversion { preservation } => ValueTransferKind::Conversion {
            preservation: match preservation {
                ValuePreservation::Identity => ValueConversionPreservation::Identity,
                ValuePreservation::Preserving => ValueConversionPreservation::Preserving,
                ValuePreservation::Changing => ValueConversionPreservation::Changing,
            },
        },
        TransferKind::Boxing => ValueTransferKind::Boxing,
        TransferKind::Unboxing => ValueTransferKind::Unboxing,
    };
    let operation = match transfer.operation {
        TransferOperation::None => ValueTransferOperation::None,
        TransferOperation::CallSite(call_site) => {
            let call_site = procedure
                .call_site(call_site)
                .expect("validated transfer operation call site");
            let span = semantic_source_span(procedure, path, call_site.source);
            let mut hasher = Sha256::new();
            update_framed(&mut hasher, b"value-transfer-call-site-v1");
            update_framed(&mut hasher, point_identity.as_str().as_bytes());
            update_framed(&mut hasher, span.path.as_str().as_bytes());
            update_framed(&mut hasher, &span.start_utf8_byte.to_be_bytes());
            update_framed(&mut hasher, &span.end_utf8_byte.to_be_bytes());
            ValueTransferOperation::CallSite {
                id: StableDigest::parse(format!("{:x}", hasher.finalize()))
                    .expect("SHA-256 is canonical"),
                span,
            }
        }
        TransferOperation::Unknown => ValueTransferOperation::Unknown,
    };
    Ok(ValueTransfer { kind, operation })
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
        // A handler binding is performed by the language runtime rather than
        // by any expression the program wrote, so it reports as the
        // language-defined transfer family. A container collapse (#2444
        // slice 2) is the same case for the same reason: reading a whole
        // object reads what is inside it, which no single expression in the
        // program spells. The #2103 subtype list is a wire vocabulary a
        // deployed extension host decodes exhaustively; adding a label to it
        // is its own compatibility decision and not part of either slice.
        ValueFlowRelationKind::HandlerBinding
        | ValueFlowRelationKind::ContainerCollapse
        | ValueFlowRelationKind::LanguageDefined => ValueDependenceSubtype::LanguageDefined,
    }
}

struct WorkspaceIdentities {
    generation: WorkspaceGeneration,
    content_identity: WorkspaceContentIdentity,
}

fn workspace_identities_for(
    analyzer: &WorkspaceAnalyzer,
    config: &AnalyzerConfig,
) -> Result<WorkspaceIdentities, ExtensionWorkspaceError> {
    let config_debug = format!("{config:?}");
    let mut generation_hasher = Sha256::new();
    generation_hasher.update(b"brokk-bifrost-extension-workspace-generation-v1\0");
    generation_hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    generation_hasher.update(EXTENSION_API_VERSION.major.to_le_bytes());
    generation_hasher.update(config_debug.as_bytes());

    let mut content_hasher = Sha256::new();
    content_hasher.update(b"brokk-bifrost-extension-workspace-content-v1\0");
    let api_major = EXTENSION_API_VERSION.major.to_le_bytes();
    update_framed(&mut content_hasher, &api_major);
    update_framed(&mut content_hasher, config_debug.as_bytes());

    let project = analyzer.analyzer().project();
    generation_hasher.update(project.root().to_string_lossy().as_bytes());
    let files = project
        .all_files_shared()
        .map_err(|error| ExtensionWorkspaceError::Project(error.to_string().into_boxed_str()))?;
    for file in files.iter() {
        // Keep this stream byte-for-byte compatible with the pre-existing
        // local generation. The portable identity below deliberately uses
        // framed, slash-normalized paths instead.
        generation_hasher.update([0]);
        generation_hasher.update(file.rel_path().to_string_lossy().as_bytes());
        generation_hasher.update([0]);

        content_hasher.update([1]);
        let rel_path = brokk_bifrost_analysis::path_utils::rel_path_string(file);
        update_framed(&mut content_hasher, rel_path.as_bytes());
        match project.read_source_snapshot(file) {
            Ok(source) => {
                let source = source.source().as_bytes();
                generation_hasher.update(source);
                update_framed(&mut content_hasher, source);
            }
            // A file skipped at open time for binary content still exists in
            // the workspace. Its path plus a fixed marker participate in the
            // generation so adding, removing, or renaming such a file changes
            // the generation even though its content is never analyzed.
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                let marker = b"<unsupported-file-content>";
                generation_hasher.update(marker);
                update_framed(&mut content_hasher, marker);
            }
            Err(error) => {
                return Err(ExtensionWorkspaceError::Project(
                    error.to_string().into_boxed_str(),
                ));
            }
        }
    }
    Ok(WorkspaceIdentities {
        generation: WorkspaceGeneration::new(
            StableDigest::parse(format!("{:x}", generation_hasher.finalize()))
                .expect("SHA-256 is canonical"),
        ),
        content_identity: WorkspaceContentIdentity::new(
            StableDigest::parse(format!("{:x}", content_hasher.finalize()))
                .expect("SHA-256 is canonical"),
        ),
    })
}

fn update_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
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
/// The identity anchor of one extension semantic node (#2411).
///
/// Deliberately mirrors `PolicyFindingId::from_match_anchor()`: nothing here is
/// a coordinate or a workspace-wide value, so an edit that does not touch the
/// denoted bytes, the enclosing declaration, or the ordering of identical
/// siblings leaves the id unchanged. Editing the denoted bytes *does* change
/// the id, so an old id can never silently alias a changed node.
struct SemanticNodeAnchor<'a> {
    /// Workspace-relative, slash-normalized path. Never the absolute path and
    /// never the project root, so relocating the checkout is not observable.
    path: &'a str,
    /// The enclosing declaration path, rendered from the node's
    /// `SemanticLocator` declaration segments (kind, name, sibling ordinal).
    /// Segment anchors are excluded: they are byte offsets.
    owner: &'a str,
    /// The exact source bytes the node denotes -- not its offsets.
    slice: &'a str,
    /// Position among otherwise identical anchors (same path, owner and slice)
    /// in document order within the procedure, so byte-identical siblings stay
    /// distinct and an identical earlier insertion shifts only its own
    /// duplicates.
    occurrence_ordinal: u32,
}

fn stable_semantic_id(anchor: &SemanticNodeAnchor<'_>) -> StableDigest {
    let mut hasher = Sha256::new();
    let mut field = |value: &[u8]| {
        let length = u64::try_from(value.len()).expect("usize fits in u64 on supported targets");
        hasher.update(length.to_be_bytes());
        hasher.update(value);
    };
    field(b"semantic-node-v2");
    field(anchor.path.as_bytes());
    field(anchor.owner.as_bytes());
    field(format!("{:x}", Sha256::digest(anchor.slice.as_bytes())).as_bytes());
    field(&anchor.occurrence_ordinal.to_be_bytes());
    StableDigest::parse(format!("{:x}", hasher.finalize())).expect("SHA-256 is canonical")
}

/// The derived anchor parts of one program point, in `points()` order.
struct DerivedNodeAnchor {
    owner: String,
    slice: String,
    occurrence_ordinal: u32,
}

/// Derives the identity anchor of every program point of one procedure.
///
/// Ordinals are assigned in document order over the whole procedure, so a node
/// keeps its ordinal regardless of the request's node budget and regardless of
/// the order `points()` happens to store points in.
fn semantic_node_anchors(procedure: &ProcedureSemantics, source: &str) -> Vec<DerivedNodeAnchor> {
    let mut spans = Vec::with_capacity(procedure.points().len());
    let mut parts = procedure
        .points()
        .iter()
        .map(|point| {
            let mapping = procedure
                .source_mapping(point.source)
                .expect("validated semantic source mapping");
            let span = mapping.locator.anchor().span();
            spans.push((span.start_byte(), span.end_byte()));
            let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
            DerivedNodeAnchor {
                owner: semantic_owner_key(&mapping.locator),
                // A mapped span that is not a char boundary of the current
                // source cannot happen for a materialization of this same
                // revision; an empty slice keeps identity total rather than
                // panicking a caller's request if it ever does.
                slice: source.get(start..end).unwrap_or_default().to_owned(),
                occurrence_ordinal: 0,
            }
        })
        .collect::<Vec<_>>();
    let mut document_order = (0..parts.len()).collect::<Vec<_>>();
    document_order.sort_by_key(|&index| (spans[index], index));
    // Keyed by the digest of the identical-anchor key (owner plus slice) so a
    // procedure with large denoted slices does not carry them twice.
    let mut seen: HashMap<[u8; 32], u32> = HashMap::new();
    for index in document_order {
        let mut hasher = Sha256::new();
        hasher.update((parts[index].owner.len() as u64).to_be_bytes());
        hasher.update(parts[index].owner.as_bytes());
        hasher.update(parts[index].slice.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();
        let ordinal = seen.entry(key).or_insert(0);
        parts[index].occurrence_ordinal = *ordinal;
        *ordinal += 1;
    }
    parts
}

/// Renders one node's enclosing declaration path into the stable owner string
/// the anchor hashes. Only stable parts participate: the segment kind label,
/// the declared name (absent for an anonymous callable), and the sibling
/// ordinal that distinguishes same-shaped siblings. The segment's own
/// `SourceAnchor` is a byte offset and is excluded on purpose.
fn semantic_owner_key(locator: &SemanticLocator) -> String {
    let mut owner = String::new();
    for segment in locator.declaration().segments() {
        if !owner.is_empty() {
            owner.push('/');
        }
        owner.push_str(segment.kind().stable_label());
        owner.push(':');
        owner.push_str(segment.name().unwrap_or("<anonymous>"));
        owner.push('#');
        owner.push_str(&segment.sibling_ordinal().to_string());
    }
    owner
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
            dimension: exceeded.dimension().label().into(),
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
            // Zero reads as "no tier crossing observed"; an operation that ran
            // under a request scope overwrites it through `with_tiers`.
            tiers: ExtensionTierReport::default(),
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
    use brokk_bifrost_analysis::analyzer::structural::StructuralFactProvider;
    use std::{
        path::Path,
        time::{Duration, Instant},
    };

    const SOURCE: &str = "export function answer() { return 42; }\n";
    const SMALL_PERSISTED_OPEN_LATENCY_LIMIT: Duration = Duration::from_secs(5);

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

    fn legacy_generation_for(
        workspace: &ExtensionWorkspace,
        config: &AnalyzerConfig,
    ) -> WorkspaceGeneration {
        let mut hasher = Sha256::new();
        hasher.update(b"brokk-bifrost-extension-workspace-generation-v1\0");
        hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
        hasher.update(EXTENSION_API_VERSION.major.to_le_bytes());
        hasher.update(format!("{config:?}").as_bytes());
        let project = workspace.analyzer.analyzer().project();
        hasher.update(project.root().to_string_lossy().as_bytes());
        for file in project.all_files_shared().unwrap().iter() {
            hasher.update([0]);
            hasher.update(file.rel_path().to_string_lossy().as_bytes());
            hasher.update([0]);
            match project.read_source_snapshot(file) {
                Ok(source) => hasher.update(source.source().as_bytes()),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    hasher.update(b"<unsupported-file-content>");
                }
                Err(error) => panic!("unexpected source read error: {error}"),
            }
        }
        WorkspaceGeneration::new(
            StableDigest::parse(format!("{:x}", hasher.finalize())).expect("SHA-256 is canonical"),
        )
    }

    fn provider(workspace: &ExtensionWorkspace) -> &dyn StructuralFactProvider {
        workspace.analyzer.analyzer().structural_fact_providers()[0]
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
    fn content_identity_is_portable_and_tracks_source_and_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let first_root = temp.path().join("first");
        let second_root = temp.path().join("second");
        std::fs::create_dir_all(&first_root).unwrap();
        std::fs::create_dir_all(&second_root).unwrap();
        write_project(&first_root);
        write_project(&second_root);

        let first_root = first_root.canonicalize().unwrap();
        let second_root = second_root.canonicalize().unwrap();
        let first = open(&first_root, false);
        let second = open(&second_root, false);
        assert_ne!(first.generation(), second.generation());
        assert_eq!(first.content_identity(), second.content_identity());
        let description = first.describe();
        assert_eq!(&description.content_identity, first.content_identity());

        std::fs::write(
            first_root.join("app.ts"),
            "export function answer() { return 43; }\n",
        )
        .unwrap();
        let source_changed = open(&first_root, false);
        assert_ne!(first.content_identity(), source_changed.content_identity());

        let mut options = ExtensionWorkspaceOptions::new(&second_root);
        options.analyzer_config.dispatch_hierarchy_expansion =
            brokk_bifrost_analysis::analyzer::DispatchHierarchyExpansion::CONCRETE_OVERRIDES;
        let configuration_changed = ExtensionWorkspace::open(options).unwrap();
        assert_ne!(
            second.content_identity(),
            configuration_changed.content_identity()
        );
    }

    #[test]
    fn generation_preserves_the_legacy_byte_stream() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_project(&root);
        let config = AnalyzerConfig::default();
        let mut options = ExtensionWorkspaceOptions::new(&root);
        options.analyzer_config = config.clone();
        let workspace = ExtensionWorkspace::open(options).unwrap();

        assert_eq!(
            workspace.generation(),
            &legacy_generation_for(&workspace, &config)
        );
    }

    #[test]
    fn persisted_open_populates_a_cache_the_reopen_hydrates_from() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_project(&root);
        let file = ProjectFile::new(root.clone(), "app.ts");

        let first_started = Instant::now();
        let first = open(&root, true);
        let first_elapsed = first_started.elapsed();
        assert!(
            first_elapsed < SMALL_PERSISTED_OPEN_LATENCY_LIMIT,
            "first persisted open took {first_elapsed:?}; expected under {SMALL_PERSISTED_OPEN_LATENCY_LIMIT:?}"
        );
        let project_root = first.project_root().to_path_buf();
        let store = first.store().clone();
        assert_eq!(store.requested, ExtensionPersistenceMode::Persisted);
        assert_eq!(store.engaged, ExtensionPersistenceMode::Persisted);
        assert!(store.diagnostics.is_empty());
        let cache_db =
            Path::new(store.cache_db.as_deref().expect("engaged store has a path")).to_path_buf();
        assert!(cache_db.starts_with(project_root.join(".bifrost/cache")));
        assert!(cache_db.exists(), "the reported store must exist on disk");
        let facts = provider(&first).structural_facts(&file).unwrap();
        assert_eq!(facts.source(), SOURCE);
        let generation = first.generation().clone();
        drop(first);

        // Reuse evidence is counter-based, not timing-based: the reopened
        // provider must answer from a hydrated snapshot without a single
        // parse-and-normalize extraction.
        let second_started = Instant::now();
        let second = open(&root, true);
        let second_elapsed = second_started.elapsed();
        assert!(
            second_elapsed < SMALL_PERSISTED_OPEN_LATENCY_LIMIT,
            "persisted reopen took {second_elapsed:?}; expected under {SMALL_PERSISTED_OPEN_LATENCY_LIMIT:?}"
        );
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
