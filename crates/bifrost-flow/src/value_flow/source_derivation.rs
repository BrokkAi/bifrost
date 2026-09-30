//! Conservative source-backed normal-result value-flow derivation.
//!
//! This is a fallback producer. The caller must first perform cheap structural
//! declaration identity discovery, resolve the exact applicable installed or
//! fetchable behavior artifact, and call this only for the requested behavior
//! partition that remains missing. This module does not inspect a catalog,
//! fetch artifacts, infer why acquisition did not provide a partition, merge
//! authored facts, or enforce pipeline ordering. The caller retains any
//! partial artifact facts and combines only the requested missing dimensions.
//!
//! The producer copies supplied immutable bytes into a private temporary
//! project and analyzes only that project. The full source
//! closure, exact configuration identity bytes, exact model identity bytes,
//! selected range, and language are bound into one deterministic input digest.
//! The analyzer's public closure API does not expose all ordinary dispatch
//! reads, so the returned read set is a conservative full-input overapprox and
//! its read coverage remains explicitly incomplete.
//!
//! Coverage is only for input-port to normal-return value dependence. A
//! fixed-point solve or an empty transfer list is not enough to claim a
//! complete partition: relevant partial lowering capabilities, semantic gaps,
//! closure coverage, and normal-flow solver boundaries remain frontiers.
//! Heap, exceptional-return, purity, no-throw, captures, and callable behavior
//! are not claimed by this result. Positive transfers remain available when
//! any of those independent coverage checks are incomplete.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::analyzer::semantic::{
    CancellationToken, CandidateCoverage, CapabilitySupport, EvidenceCompleteness,
    LengthDelimitedDigest, ProcedureHandle, ProcedurePortHandle, ProcedurePortKind,
    ProcedureRangeLookupStatus, ProofStatus, SemanticBudget, SemanticCapability, SemanticGapImpact,
    SemanticRequest, SemanticValueKind, SemanticWork, StableDigest, ValueFlowRelationKind,
    procedures_for_source_ranges,
};
use crate::analyzer::{
    AnalyzerConfig, FilesystemProject, Language, LanguageDialect, Project, Range, WorkspaceAnalyzer,
};
use crate::dataflow::{
    DataflowRequest, SemanticInputStatus, SolverBudget, SolverTermination, SolverWork,
    UnmodeledCallBehavior,
};
use crate::value_flow::{
    BindingCoverage, ClosureLimits, DispatchStatus, ValueFlowCarrier, ValueFlowEventKey,
    ValueFlowEventKind, ValueFlowMayStatus, ValueFlowObservationPhase, ValueFlowPlan,
    ValueFlowSinkSpec, ValueFlowSourceSpec, discover_closure, solve_value_flow_with_summaries,
};

const INPUT_IDENTITY_DOMAIN: &[u8] = b"bifrost-source-summary-input-v1";
const NORMAL_RESULT_ORDINAL: u32 = 0;

/// One immutable caller-owned source file, addressed by a workspace-relative
/// path. Source bytes must be valid UTF-8 because the analyzer's source API is
/// text-based; accepted bytes are passed through without lossy conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDerivationFile {
    pub relative_path: PathBuf,
    pub bytes: Arc<[u8]>,
}

/// The caller's exact structural selector for one entrypoint declaration.
/// Names and source-text matching are never used as identity fallbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntrypointRange {
    pub relative_path: PathBuf,
    pub range: Range,
}

/// Inputs to one fallback-only source behavior derivation.
#[derive(Debug, Clone)]
pub struct SourceDerivationInput {
    /// The complete immutable source closure supplied by the caller.
    pub files: Vec<SourceDerivationFile>,
    /// Exact file and byte range chosen by prior structural identity lookup.
    pub entrypoint: SourceEntrypointRange,
    pub language: Language,
    pub analyzer_config: AnalyzerConfig,
    /// Exact stable bytes describing `analyzer_config` for the caller's
    /// configuration scheme.
    pub configuration_identity: Arc<[u8]>,
    /// Exact stable bytes identifying the active semantic model set.
    pub model_identity: Arc<[u8]>,
}

/// Bounds on source closure ingestion, exact-range lookup, and interprocedural
/// closure discovery. Semantic and solver work are bounded by the separately
/// supplied mutable budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceDerivationLimits {
    pub max_source_files: usize,
    pub max_source_bytes: usize,
    pub max_entrypoint_lookup_examined: usize,
    pub max_closure_procedures: usize,
}

impl Default for SourceDerivationLimits {
    fn default() -> Self {
        Self {
            max_source_files: 512,
            max_source_bytes: 8 * 1024 * 1024,
            max_entrypoint_lookup_examined: 100_000,
            max_closure_procedures: 64,
        }
    }
}

/// The independently scoped source partition requested from #3656's native
/// normal-result transfer contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransferPartitionSource {
    InputReceiver,
    InputParameter { ordinal: u32 },
}

/// Coverage state that can be mapped directly to
/// `NormalResultTransferPartition::{Unknown, Partial, Complete}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransferPartitionStatus {
    Unknown,
    Partial,
    Complete,
}

/// Whether the solver retained positive evidence for this input/output pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransferEvidence {
    Proven,
    Unproven,
}

/// One receiver/parameter to normal-result partition. `evidence == None` is
/// not by itself a negative claim: interpret it with `status` and `limitations`.
/// Only partitions with positive solver meetings have evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalResultTransferPartition {
    pub source: TransferPartitionSource,
    pub normal_result: u32,
    pub status: TransferPartitionStatus,
    pub evidence: Option<TransferEvidence>,
    pub limitations: Vec<String>,
    pub provenance: Vec<String>,
}

/// Typed reason a requested normal-result partition remains open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceDerivationFrontier {
    NoExactEntrypoint,
    AmbiguousExactEntrypoint {
        matches: usize,
    },
    IncompleteEntrypointLookup {
        status: ProcedureRangeLookupStatus,
    },
    IncompleteArtifactMaterialization {
        status: SemanticInputStatus,
    },
    SourceBudgetExceeded {
        detail: String,
    },
    ModelSetNotActivated,
    RelevantCapability {
        capability: SemanticCapability,
        support: CapabilitySupport,
    },
    RelevantSemanticGap {
        capability: SemanticCapability,
        impact: SemanticGapImpact,
    },
    IncompleteSemanticInput {
        status: SemanticInputStatus,
    },
    UncoveredCallSite {
        truncated: bool,
        has_uncovered_boundary: bool,
        candidate_coverage: Option<CandidateCoverage>,
    },
    IncompleteDispatch {
        status: SemanticInputStatus,
        candidate_coverage: CandidateCoverage,
    },
    UnavailableDispatch {
        status: SemanticInputStatus,
    },
    DispatchProviderError {
        detail: String,
    },
    IncompleteBinding {
        status: SemanticInputStatus,
    },
    BindingProviderError {
        detail: String,
    },
    IncompleteDiscovery {
        detail: String,
    },
    RecursiveClosure,
    NormalFlowSolverBoundary {
        detail: String,
    },
    SolverCancelled,
    SolverBudgetExceeded {
        detail: String,
    },
    ReadCoverageIncomplete {
        detail: String,
    },
}

/// Read/dependency coverage. All supplied source files are bound as
/// dependencies; exact ordinary-dispatch read observation is unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceReadCoverage {
    ConservativeFullInput { limitations: Vec<String> },
}

/// Exact identity for one supplied source dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDependencyIdentity {
    pub relative_path: PathBuf,
    pub byte_length: usize,
    pub content_digest: StableDigest,
}

/// Work performed by this request. Budget fields report deltas from the
/// caller's supplied budgets, so they remain correct when those budgets are
/// shared across requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceDerivationWork {
    pub supplied_source_files: usize,
    pub supplied_source_bytes: usize,
    pub entrypoint_lookup_examined: usize,
    pub closure_procedures: usize,
    pub skipped_procedures: usize,
    pub closure_truncated: bool,
    pub semantic: SemanticWork,
    pub solver: SolverWork,
}

/// One source-to-summary producer result. It speaks only about normal-result
/// value dependence; callers retain and merge independently acquired facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDerivationResult {
    pub input_digest: StableDigest,
    pub entrypoint: SourceEntrypointStatus,
    pub partitions: Vec<NormalResultTransferPartition>,
    pub status: TransferPartitionStatus,
    pub frontiers: Vec<SourceDerivationFrontier>,
    pub dependencies: Vec<SourceDependencyIdentity>,
    pub read_coverage: SourceReadCoverage,
    pub work: SourceDerivationWork,
}

/// Outcome of exact structural range lookup. `Unique` is the only state that
/// permits behavior derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceEntrypointStatus {
    Unique { identity: StableDigest },
    NoExactMatch,
    Ambiguous { matches: usize },
    Incomplete { status: ProcedureRangeLookupStatus },
}

/// Invalid request, isolated-project, analyzer, planning, or solver failure.
/// Semantic incompleteness after a successful solve is represented in the
/// result's typed frontiers and never erased into an error or empty answer.
#[derive(Debug)]
pub enum SourceDerivationError {
    InvalidInput(String),
    Io(io::Error),
    Analyzer(String),
    Semantic(String),
}

impl std::fmt::Display for SourceDerivationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SourceDerivationError {}

/// Derive the requested normal-result relation from an exact source snapshot.
///
/// The caller must already have resolved exact pack applicability (including
/// configured acquisition). This function never checks or replaces the pack.
pub fn derive_source_normal_result(
    input: &SourceDerivationInput,
    limits: SourceDerivationLimits,
    semantic_budget: &mut SemanticBudget,
    solver_budget: &mut SolverBudget,
    cancellation: &CancellationToken,
) -> Result<SourceDerivationResult, SourceDerivationError> {
    if !matches!(input.language, Language::Python | Language::JavaScript) {
        return Err(SourceDerivationError::InvalidInput(
            "only Python and JavaScript source derivation is supported".to_owned(),
        ));
    }
    if input.files.is_empty() {
        return Err(SourceDerivationError::InvalidInput(
            "the source closure is empty".to_owned(),
        ));
    }
    if input.analyzer_config.python.environment.is_some()
        || !input
            .analyzer_config
            .js_ts
            .dependency_discovery
            .lockfile_paths
            .is_empty()
        || !input
            .analyzer_config
            .js_ts
            .dependency_discovery
            .node_modules_roots
            .is_empty()
    {
        return Err(SourceDerivationError::InvalidInput(
            "dependency discovery roots must not enter the isolated source session".to_owned(),
        ));
    }

    let mut files = BTreeMap::<String, &SourceDerivationFile>::new();
    let mut source_bytes = 0usize;
    for file in &input.files {
        let path = portable_source_path(&file.relative_path)?;
        if files.insert(path.clone(), file).is_some() {
            return Err(SourceDerivationError::InvalidInput(format!(
                "duplicate source path {path}"
            )));
        }
        if std::str::from_utf8(&file.bytes).is_err() {
            return Err(SourceDerivationError::InvalidInput(format!(
                "source path {path} is not UTF-8"
            )));
        }
        source_bytes = source_bytes.saturating_add(file.bytes.len());
    }
    let entrypoint_path = portable_source_path(&input.entrypoint.relative_path)?;
    let Some(entrypoint_file) = files.get(&entrypoint_path) else {
        return Err(SourceDerivationError::InvalidInput(
            "entrypoint source is absent from the supplied closure".to_owned(),
        ));
    };
    if input.entrypoint.range.start_byte >= input.entrypoint.range.end_byte
        || input.entrypoint.range.end_byte > entrypoint_file.bytes.len()
    {
        return Err(SourceDerivationError::InvalidInput(
            "entrypoint range is outside its exact source bytes".to_owned(),
        ));
    }

    let mut identity = LengthDelimitedDigest::new(INPUT_IDENTITY_DOMAIN);
    identity.push(
        LanguageDialect::for_path(input.language, &input.entrypoint.relative_path)
            .stable_label()
            .as_bytes(),
    );
    identity.push(format!("{:?}", input.analyzer_config).as_bytes());
    identity.push(&input.configuration_identity);
    identity.push(&input.model_identity);
    identity.push(entrypoint_path.as_bytes());
    identity.push(&(input.entrypoint.range.start_byte as u64).to_le_bytes());
    identity.push(&(input.entrypoint.range.end_byte as u64).to_le_bytes());
    identity.push(&(limits.max_source_files as u64).to_le_bytes());
    identity.push(&(limits.max_source_bytes as u64).to_le_bytes());
    identity.push(&(limits.max_entrypoint_lookup_examined as u64).to_le_bytes());
    identity.push(&(limits.max_closure_procedures as u64).to_le_bytes());
    identity.push(format!("{:?}", semantic_budget.limits()).as_bytes());
    identity.push(format!("{:?}", solver_budget.limits()).as_bytes());
    let dependencies = files
        .iter()
        .map(|(path, file)| {
            identity.push(path.as_bytes());
            identity.push(&file.bytes);
            SourceDependencyIdentity {
                relative_path: file.relative_path.clone(),
                byte_length: file.bytes.len(),
                content_digest: StableDigest::sha256(&file.bytes),
            }
        })
        .collect::<Vec<_>>();
    let input_digest = identity.finish();
    let semantic_start = semantic_budget.used();
    let solver_start = solver_budget.used();
    let mut result = SourceDerivationResult {
        input_digest,
        entrypoint: SourceEntrypointStatus::NoExactMatch,
        partitions: Vec::new(),
        status: TransferPartitionStatus::Unknown,
        frontiers: Vec::new(),
        dependencies,
        read_coverage: SourceReadCoverage::ConservativeFullInput {
            limitations: vec![
                "ordinary dispatch reads are not individually certified; every supplied source is retained as a dependency".to_owned(),
            ],
        },
        work: SourceDerivationWork {
            supplied_source_files: files.len(),
            supplied_source_bytes: source_bytes,
            entrypoint_lookup_examined: 0,
            closure_procedures: 0,
            skipped_procedures: 0,
            closure_truncated: false,
            semantic: SemanticWork::default(),
            solver: SolverWork::default(),
        },
    };
    result
        .frontiers
        .push(SourceDerivationFrontier::ReadCoverageIncomplete {
            detail: "ordinary dispatch reads are not individually observed".to_owned(),
        });
    if files.len() > limits.max_source_files || source_bytes > limits.max_source_bytes {
        result
            .frontiers
            .push(SourceDerivationFrontier::SourceBudgetExceeded {
                detail: format!(
                    "{} files / {} bytes exceeds {} files / {} bytes",
                    files.len(),
                    source_bytes,
                    limits.max_source_files,
                    limits.max_source_bytes
                ),
            });
        return Ok(result);
    }
    if cancellation.is_cancelled() {
        result
            .frontiers
            .push(SourceDerivationFrontier::SolverCancelled);
        return Ok(result);
    }

    // Materialize only the exact caller-owned bytes in a throwaway project.
    // Filesystem-backed module resolution can then inspect helper paths without
    // ever seeing the application workspace or a mutable package installation.
    let session = tempfile::tempdir().map_err(SourceDerivationError::Io)?;
    for file in files.values() {
        let path = session.path().join(&file.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(SourceDerivationError::Io)?;
        }
        fs::write(&path, &file.bytes).map_err(SourceDerivationError::Io)?;
    }
    for file in files.values() {
        let actual = fs::read(session.path().join(&file.relative_path))
            .map_err(SourceDerivationError::Io)?;
        if actual.as_slice() != file.bytes.as_ref() {
            return Err(SourceDerivationError::InvalidInput(format!(
                "source paths collide on this filesystem: {}",
                file.relative_path.display()
            )));
        }
    }
    let project = FilesystemProject::new(session.path()).map_err(SourceDerivationError::Io)?;
    let project: Arc<dyn Project> = Arc::new(project);
    let mut config = input.analyzer_config.clone();
    config
        .js_ts
        .dependency_discovery
        .discover_workspace_lockfiles = false;
    let languages = BTreeSet::from([input.language]);
    let analyzer = WorkspaceAnalyzer::build_ephemeral_for_languages_footgun(
        Arc::clone(&project),
        config,
        &languages,
    )
    .map_err(|error| SourceDerivationError::Analyzer(error.to_string()))?;
    let entry_file = project
        .file_by_rel_path(&input.entrypoint.relative_path)
        .expect("a supplied source was materialized into the isolated project");
    let artifact = analyzer
        .materialize_program_semantics(
            &entry_file,
            &mut SemanticRequest::new(semantic_budget, cancellation),
        )
        .map_err(|error| SourceDerivationError::Semantic(error.to_string()))?;
    let materialization_status = SemanticInputStatus::from_outcome(&artifact);
    let Some(artifact) = artifact.available_value().cloned() else {
        result.frontiers.push(
            SourceDerivationFrontier::IncompleteArtifactMaterialization {
                status: materialization_status,
            },
        );
        result.work.semantic = semantic_budget.used().saturating_sub(semantic_start);
        return Ok(result);
    };
    if !materialization_status.is_complete() {
        result.frontiers.push(
            SourceDerivationFrontier::IncompleteArtifactMaterialization {
                status: materialization_status,
            },
        );
    }
    let lookup = procedures_for_source_ranges(
        &artifact,
        &[input.entrypoint.range],
        limits.max_entrypoint_lookup_examined,
        cancellation,
    );
    result.work.entrypoint_lookup_examined = lookup.examined;
    if lookup.status != ProcedureRangeLookupStatus::Complete {
        result.entrypoint = SourceEntrypointStatus::Incomplete {
            status: lookup.status,
        };
        result
            .frontiers
            .push(SourceDerivationFrontier::IncompleteEntrypointLookup {
                status: lookup.status,
            });
        result.work.semantic = semantic_budget.used().saturating_sub(semantic_start);
        return Ok(result);
    }
    let exact = lookup
        .handles
        .into_iter()
        .filter(|procedure| {
            let span = procedure.semantics().locator().anchor().span();
            span.start_byte() as usize == input.entrypoint.range.start_byte
                && span.end_byte() as usize == input.entrypoint.range.end_byte
        })
        .collect::<Vec<_>>();
    let root = match exact.as_slice() {
        [] => {
            result
                .frontiers
                .push(SourceDerivationFrontier::NoExactEntrypoint);
            result.work.semantic = semantic_budget.used().saturating_sub(semantic_start);
            return Ok(result);
        }
        [root] => root,
        _ => {
            result.entrypoint = SourceEntrypointStatus::Ambiguous {
                matches: exact.len(),
            };
            result
                .frontiers
                .push(SourceDerivationFrontier::AmbiguousExactEntrypoint {
                    matches: exact.len(),
                });
            result.work.semantic = semantic_budget.used().saturating_sub(semantic_start);
            return Ok(result);
        }
    };
    let mut procedure_identity =
        LengthDelimitedDigest::new(b"bifrost-source-summary-entrypoint-v1");
    root.semantics()
        .locator()
        .push_stable_identity(&mut procedure_identity);
    result.entrypoint = SourceEntrypointStatus::Unique {
        identity: procedure_identity.finish(),
    };
    if !input.model_identity.is_empty() {
        result
            .frontiers
            .push(SourceDerivationFrontier::ModelSetNotActivated);
    }

    derive_selected_procedure(
        &analyzer,
        root,
        limits,
        semantic_budget,
        solver_budget,
        cancellation,
        &mut result,
    )?;
    result.work.semantic = semantic_budget.used().saturating_sub(semantic_start);
    result.work.solver = solver_budget.used().saturating_sub(solver_start);
    result
        .frontiers
        .sort_by_key(|frontier| format!("{frontier:?}"));
    result.frontiers.dedup();
    Ok(result)
}

fn portable_source_path(path: &Path) -> Result<String, SourceDerivationError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(SourceDerivationError::InvalidInput(format!(
            "source path must be a relative path without traversal: {}",
            path.display()
        )));
    }
    let Some(portable) = path.to_str() else {
        return Err(SourceDerivationError::InvalidInput(
            "source path is not UTF-8".to_owned(),
        ));
    };
    if portable.contains('\\') || portable.contains(':') {
        return Err(SourceDerivationError::InvalidInput(format!(
            "source path is not portable: {}",
            path.display()
        )));
    }
    Ok(portable.to_owned())
}

fn derive_selected_procedure(
    analyzer: &WorkspaceAnalyzer,
    root: &ProcedureHandle,
    limits: SourceDerivationLimits,
    semantic_budget: &mut SemanticBudget,
    solver_budget: &mut SolverBudget,
    cancellation: &CancellationToken,
    result: &mut SourceDerivationResult,
) -> Result<(), SourceDerivationError> {
    let closure = match discover_closure(
        analyzer,
        root,
        ClosureLimits {
            max_procedures: limits.max_closure_procedures,
        },
        semantic_budget,
        cancellation,
    ) {
        Ok(closure) => closure,
        Err(error) => {
            result
                .frontiers
                .push(SourceDerivationFrontier::IncompleteDiscovery {
                    detail: error.to_string(),
                });
            return Ok(());
        }
    };
    result.work.closure_procedures = closure.procedures.len();
    result.work.skipped_procedures = closure.skipped.len();
    result.work.closure_truncated = closure.truncated;
    if closure.truncated {
        result
            .frontiers
            .push(SourceDerivationFrontier::IncompleteDiscovery {
                detail: "procedure limit truncated the closure".to_owned(),
            });
    }
    for (_, reason) in &closure.skipped {
        result
            .frontiers
            .push(SourceDerivationFrontier::IncompleteDiscovery {
                detail: format!("skipped procedure: {reason:?}"),
            });
    }
    for boundary in &closure.boundaries {
        result
            .frontiers
            .push(SourceDerivationFrontier::IncompleteDiscovery {
                detail: format!("dispatch boundary: {boundary:?}"),
            });
    }
    for coverage in closure.coverage.values() {
        let candidate_coverage = match &coverage.dispatch {
            DispatchStatus::Resolved { coverage, .. } => Some(*coverage),
            DispatchStatus::Unavailable { .. } | DispatchStatus::ProviderError { .. } => None,
        };
        if coverage.truncated
            || coverage.has_uncovered_boundary
            || candidate_coverage.is_some_and(|coverage| coverage != CandidateCoverage::Exhaustive)
        {
            result
                .frontiers
                .push(SourceDerivationFrontier::UncoveredCallSite {
                    truncated: coverage.truncated,
                    has_uncovered_boundary: coverage.has_uncovered_boundary,
                    candidate_coverage,
                });
        }
        match &coverage.dispatch {
            DispatchStatus::Resolved { status, coverage }
                if !status.is_complete() || *coverage != CandidateCoverage::Exhaustive =>
            {
                result
                    .frontiers
                    .push(SourceDerivationFrontier::IncompleteDispatch {
                        status: *status,
                        candidate_coverage: *coverage,
                    });
            }
            DispatchStatus::Unavailable { status } => result
                .frontiers
                .push(SourceDerivationFrontier::UnavailableDispatch { status: *status }),
            DispatchStatus::ProviderError { detail } => {
                result
                    .frontiers
                    .push(SourceDerivationFrontier::DispatchProviderError {
                        detail: detail.clone(),
                    })
            }
            DispatchStatus::Resolved { .. } => {}
        }
        for binding in &coverage.bindings {
            match binding {
                BindingCoverage::Answered { status } if !status.is_complete() => result
                    .frontiers
                    .push(SourceDerivationFrontier::IncompleteBinding { status: *status }),
                BindingCoverage::ProviderError { detail } => {
                    result
                        .frontiers
                        .push(SourceDerivationFrontier::BindingProviderError {
                            detail: detail.clone(),
                        })
                }
                BindingCoverage::Answered { .. } => {}
            }
        }
    }
    for input in &closure.snapshots {
        if !input.status().is_complete() {
            result
                .frontiers
                .push(SourceDerivationFrontier::IncompleteSemanticInput {
                    status: input.status(),
                });
        }
    }
    for input in &closure.bindings {
        if !input.status().is_complete() {
            result
                .frontiers
                .push(SourceDerivationFrontier::IncompleteSemanticInput {
                    status: input.status(),
                });
        }
    }
    const RELEVANT_CAPABILITIES: [SemanticCapability; 8] = [
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::Values,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::ReturnFlow,
        SemanticCapability::Calls,
    ];
    const RELEVANT_IMPACTS: [SemanticGapImpact; 4] = [
        SemanticGapImpact::DispatchCoverage,
        SemanticGapImpact::CallEvaluation,
        SemanticGapImpact::ReturnTransfer,
        SemanticGapImpact::ValueFlow,
    ];
    for procedure in &closure.procedures {
        for capability in RELEVANT_CAPABILITIES {
            let support = procedure.artifact().capabilities().support(capability);
            if !support.is_complete() {
                result
                    .frontiers
                    .push(SourceDerivationFrontier::RelevantCapability {
                        capability,
                        support,
                    });
            }
        }
        for gap in procedure.semantics().gaps() {
            for impact in RELEVANT_IMPACTS {
                if gap.impacts.contains(impact) {
                    result
                        .frontiers
                        .push(SourceDerivationFrontier::RelevantSemanticGap {
                            capability: gap.capability,
                            impact,
                        });
                }
            }
        }
    }
    let Some(root_snapshot) = closure.root_snapshot else {
        result
            .frontiers
            .push(SourceDerivationFrontier::IncompleteDiscovery {
                detail: "root relation snapshot is unavailable".to_owned(),
            });
        return Ok(());
    };
    // A cyclic discovered call graph cannot certify an absent transfer from
    // this bounded pass, even if the solver reaches a fixed point. Kahn's
    // worklist handles indirect cycles without recursive Rust traversal.
    let indices = closure
        .procedures
        .iter()
        .enumerate()
        .map(|(index, procedure)| (procedure.durable_key(), index))
        .collect::<HashMap<_, _>>();
    let mut edges = vec![Vec::new(); closure.procedures.len()];
    let mut indegrees = vec![0usize; closure.procedures.len()];
    for ((caller, _), coverage) in &closure.coverage {
        let Some(&from) = indices.get(caller) else {
            continue;
        };
        for entered in &coverage.entered {
            let Some(&to) = indices.get(&entered.durable_key()) else {
                continue;
            };
            edges[from].push(to);
            indegrees[to] += 1;
        }
    }
    let mut pending = indegrees
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree == 0).then_some(index))
        .collect::<Vec<_>>();
    let mut drained = 0usize;
    while let Some(from) = pending.pop() {
        drained += 1;
        for &to in &edges[from] {
            indegrees[to] -= 1;
            if indegrees[to] == 0 {
                pending.push(to);
            }
        }
    }
    if drained < closure.procedures.len() {
        result
            .frontiers
            .push(SourceDerivationFrontier::RecursiveClosure);
    }
    let entry_point = root
        .point_handle(root.semantics().entry_point())
        .expect("a live procedure owns its entry point");
    let mut sources = Vec::new();
    let mut source_ordinals = BTreeSet::new();
    for value in root.semantics().values() {
        let source = match value.kind {
            SemanticValueKind::Receiver { .. } => Some(TransferPartitionSource::InputReceiver),
            SemanticValueKind::Parameter { ordinal, .. } => {
                Some(TransferPartitionSource::InputParameter { ordinal })
            }
            _ => None,
        };
        let Some(source) = source else { continue };
        if !source_ordinals.insert(source) {
            continue;
        }
        let port = match source {
            TransferPartitionSource::InputReceiver => ProcedurePortHandle::receiver(root.clone())
                .expect("a receiver value owns a receiver port"),
            TransferPartitionSource::InputParameter { ordinal } => {
                ProcedurePortHandle::parameter(root.clone(), ordinal)
                    .expect("a parameter value owns a parameter port")
            }
        };
        sources.push(ValueFlowSourceSpec::new(
            ValueFlowEventKey::at_point(
                &entry_point,
                sources.len() as u32,
                ValueFlowEventKind::Source,
            )
            .expect("a live entry point yields a source event"),
            entry_point.clone(),
            ValueFlowObservationPhase::BeforeEffects,
            ValueFlowCarrier::Port(port),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        ));
    }
    let mut sinks = Vec::new();
    let mut point_ordinals = BTreeMap::new();
    for relation in closure.snapshots[root_snapshot].value().relations() {
        if relation.kind != ValueFlowRelationKind::NormalReturn {
            continue;
        }
        let ordinal = point_ordinals.entry(relation.point().id()).or_insert(0u32);
        sinks.push(ValueFlowSinkSpec::new(
            ValueFlowEventKey::at_point(relation.point(), *ordinal, ValueFlowEventKind::Sink)
                .expect("a live return point yields a sink event"),
            relation.point().clone(),
            ValueFlowObservationPhase::AfterEffects,
            ValueFlowCarrier::Port(ProcedurePortHandle::normal_return(root.clone())),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        ));
        *ordinal += 1;
    }
    if sinks.is_empty() {
        result
            .frontiers
            .push(SourceDerivationFrontier::IncompleteDiscovery {
                detail: "no normal-return relation was lowered".to_owned(),
            });
    }
    let plan = match ValueFlowPlan::with_call_behavior(
        root.clone(),
        closure.snapshots,
        closure.bindings,
        sources,
        sinks,
        UnmodeledCallBehavior::RequireModel,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            result
                .frontiers
                .push(SourceDerivationFrontier::NormalFlowSolverBoundary {
                    detail: format!("plan rejected: {error}"),
                });
            return Ok(());
        }
    };
    let solved = match solve_value_flow_with_summaries(
        root,
        &analyzer.icfg_provider(),
        &plan,
        semantic_budget,
        &mut DataflowRequest::new(solver_budget, cancellation),
    ) {
        Ok(solved) => solved,
        Err(error) => {
            result
                .frontiers
                .push(SourceDerivationFrontier::NormalFlowSolverBoundary {
                    detail: format!("solve rejected: {error}"),
                });
            return Ok(());
        }
    };
    match solved.result().termination() {
        SolverTermination::FixedPoint => {}
        SolverTermination::Cancelled => result
            .frontiers
            .push(SourceDerivationFrontier::SolverCancelled),
        SolverTermination::ExceededBudget(exceeded) => {
            result
                .frontiers
                .push(SourceDerivationFrontier::SolverBudgetExceeded {
                    detail: exceeded.to_string(),
                })
        }
    }
    if !solved.is_complete() {
        result
            .frontiers
            .push(SourceDerivationFrontier::NormalFlowSolverBoundary {
                detail: "normal-flow discovery was incomplete".to_owned(),
            });
    }
    let mut positive = BTreeMap::new();
    for meeting in solved.meetings() {
        let Some(spec) = plan.source(meeting.source()) else {
            continue;
        };
        let ValueFlowCarrier::Port(port) = spec.carrier() else {
            continue;
        };
        let source = match port.kind() {
            ProcedurePortKind::Receiver => TransferPartitionSource::InputReceiver,
            ProcedurePortKind::Parameter { ordinal } => {
                TransferPartitionSource::InputParameter { ordinal }
            }
            _ => continue,
        };
        let evidence = if meeting.may_status() == ValueFlowMayStatus::Proven {
            TransferEvidence::Proven
        } else {
            TransferEvidence::Unproven
        };
        positive
            .entry(source)
            .and_modify(|existing| {
                if evidence == TransferEvidence::Proven {
                    *existing = evidence;
                }
            })
            .or_insert(evidence);
    }
    let complete = result.frontiers.is_empty() && solved.is_complete();
    result.status = if complete {
        TransferPartitionStatus::Complete
    } else {
        TransferPartitionStatus::Partial
    };
    result.partitions = source_ordinals
        .into_iter()
        .map(|source| NormalResultTransferPartition {
            source,
            normal_result: NORMAL_RESULT_ORDINAL,
            status: result.status,
            evidence: positive.get(&source).copied(),
            limitations: result
                .frontiers
                .iter()
                .map(|frontier| format!("{frontier:?}"))
                .collect(),
            provenance: vec![format!("source-derivation:{}", result.input_digest)],
        })
        .collect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive_at(
        language: Language,
        path: &str,
        source: &str,
        declaration: &str,
    ) -> SourceDerivationResult {
        let start = source
            .find(declaration)
            .expect("fixture has the selected declaration");
        let input = SourceDerivationInput {
            files: vec![SourceDerivationFile {
                relative_path: path.into(),
                bytes: Arc::from(source.as_bytes()),
            }],
            entrypoint: SourceEntrypointRange {
                relative_path: path.into(),
                range: Range {
                    start_byte: start,
                    end_byte: source.len(),
                    start_line: source[..start].lines().count(),
                    end_line: source.lines().count() - 1,
                },
            },
            language,
            analyzer_config: AnalyzerConfig::default(),
            configuration_identity: Arc::from(b"default-config".as_slice()),
            model_identity: Arc::from(b"".as_slice()),
        };
        derive_source_normal_result(
            &input,
            SourceDerivationLimits::default(),
            &mut SemanticBudget::default(),
            &mut SolverBudget::default(),
            &CancellationToken::default(),
        )
        .expect("the isolated source request should run")
    }

    fn derive(language: Language, path: &str, source: &str) -> SourceDerivationResult {
        derive_at(language, path, source, source)
    }

    #[test]
    fn python_identity_return_retains_positive_evidence() {
        let result = derive(Language::Python, "module.py", "def f(x):\n    return x");
        assert!(
            matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
            "{result:?}"
        );
        assert!(
            result.partitions.iter().any(|partition| {
                partition.source == TransferPartitionSource::InputParameter { ordinal: 0 }
                    && partition.evidence.is_some()
            }),
            "{result:?}"
        );
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn javascript_identity_return_retains_positive_evidence() {
        let result = derive(
            Language::JavaScript,
            "module.js",
            "function f(x) { return x; }",
        );
        assert!(
            matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
            "{result:?}"
        );
        assert!(
            result.partitions.iter().any(|partition| {
                partition.source == TransferPartitionSource::InputParameter { ordinal: 0 }
                    && partition.evidence.is_some()
            }),
            "{result:?}"
        );
    }

    #[test]
    fn python_resolved_helper_flow_retains_positive_evidence() {
        let source = "def helper(y):\n    return y\n\ndef f(x):\n    return helper(x)";
        let result = derive_at(Language::Python, "module.py", source, "def f(x):");
        assert!(
            matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
            "{result:?}"
        );
        assert!(result.work.closure_procedures >= 2, "{result:?}");
        assert!(
            result.partitions.iter().any(|partition| {
                partition.source == TransferPartitionSource::InputParameter { ordinal: 0 }
                    && partition.evidence.is_some()
            }),
            "{result:?}"
        );
    }

    #[test]
    fn javascript_resolved_helper_flow_retains_positive_evidence() {
        let source = "function helper(y) { return y; }\nfunction f(x) { return helper(x); }";
        let result = derive_at(Language::JavaScript, "module.js", source, "function f(x)");
        assert!(
            matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
            "{result:?}"
        );
        assert!(result.work.closure_procedures >= 2, "{result:?}");
        assert!(
            result.partitions.iter().any(|partition| {
                partition.source == TransferPartitionSource::InputParameter { ordinal: 0 }
                    && partition.evidence.is_some()
            }),
            "{result:?}"
        );
    }

    #[test]
    fn imported_helper_sources_are_part_of_bounded_closure() {
        let cases = [
            (
                Language::Python,
                "module.py",
                "from helper import helper\ndef f(x):\n    return helper(x)",
                "def f(x):",
                "helper.py",
                "def helper(y):\n    return y",
            ),
            (
                Language::JavaScript,
                "module.js",
                "import { helper } from './helper.js';\nfunction f(x) { return helper(x); }",
                "function f(x)",
                "helper.js",
                "export function helper(y) { return y; }",
            ),
        ];
        for (language, path, source, selector, helper_path, helper_source) in cases {
            let start = source
                .find(selector)
                .expect("fixture declares the selected function");
            let input = SourceDerivationInput {
                files: vec![
                    SourceDerivationFile {
                        relative_path: path.into(),
                        bytes: Arc::from(source.as_bytes()),
                    },
                    SourceDerivationFile {
                        relative_path: helper_path.into(),
                        bytes: Arc::from(helper_source.as_bytes()),
                    },
                ],
                entrypoint: SourceEntrypointRange {
                    relative_path: path.into(),
                    range: Range {
                        start_byte: start,
                        end_byte: source.len(),
                        start_line: source[..start].lines().count(),
                        end_line: source.lines().count() - 1,
                    },
                },
                language,
                analyzer_config: AnalyzerConfig::default(),
                configuration_identity: Arc::from(b"default-config".as_slice()),
                model_identity: Arc::from(b"".as_slice()),
            };
            let result = derive_source_normal_result(
                &input,
                SourceDerivationLimits::default(),
                &mut SemanticBudget::default(),
                &mut SolverBudget::default(),
                &CancellationToken::default(),
            )
            .expect("the isolated source request should run");
            assert!(
                matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
                "{result:?}"
            );
            assert_eq!(result.dependencies.len(), 2);
            assert!(result.work.closure_procedures >= 2, "{result:?}");
            assert!(
                result.partitions.iter().any(|partition| {
                    partition.source == TransferPartitionSource::InputParameter { ordinal: 0 }
                        && partition.evidence.is_some()
                }),
                "{result:?}"
            );
        }
    }

    #[test]
    fn constant_return_does_not_invent_input_flow_or_complete_empty() {
        let result = derive(Language::Python, "module.py", "def f(x):\n    return 42");
        assert!(
            matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
            "{result:?}"
        );
        assert!(
            result
                .partitions
                .iter()
                .all(|partition| partition.evidence.is_none()),
            "{result:?}"
        );
        assert_ne!(
            result.status,
            TransferPartitionStatus::Complete,
            "{result:?}"
        );
        assert!(!result.frontiers.is_empty(), "{result:?}");
    }

    #[test]
    fn unresolved_call_retains_typed_dispatch_frontier() {
        let result = derive(
            Language::Python,
            "module.py",
            "def f(x):\n    return missing_dependency(x)",
        );
        assert!(
            matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
            "{result:?}"
        );
        assert_ne!(
            result.status,
            TransferPartitionStatus::Complete,
            "{result:?}"
        );
        assert!(
            result.frontiers.iter().any(|frontier| matches!(
                frontier,
                SourceDerivationFrontier::UncoveredCallSite { .. }
                    | SourceDerivationFrontier::IncompleteDispatch { .. }
                    | SourceDerivationFrontier::UnavailableDispatch { .. }
            )),
            "{result:?}"
        );
    }

    #[test]
    fn recursive_call_is_a_typed_incomplete_frontier() {
        let result = derive(Language::Python, "module.py", "def f(x):\n    return f(x)");
        assert!(
            matches!(result.entrypoint, SourceEntrypointStatus::Unique { .. }),
            "{result:?}"
        );
        assert!(
            result
                .frontiers
                .contains(&SourceDerivationFrontier::RecursiveClosure),
            "{result:?}"
        );
        assert_ne!(
            result.status,
            TransferPartitionStatus::Complete,
            "{result:?}"
        );
    }

    #[test]
    fn cancellation_preserves_unknown_coverage() {
        let token = CancellationToken::default();
        token.cancel();
        let source = b"def f(x):\n    return x";
        let input = SourceDerivationInput {
            files: vec![SourceDerivationFile {
                relative_path: "module.py".into(),
                bytes: Arc::from(source.as_slice()),
            }],
            entrypoint: SourceEntrypointRange {
                relative_path: "module.py".into(),
                range: Range {
                    start_byte: 0,
                    end_byte: source.len(),
                    start_line: 0,
                    end_line: 1,
                },
            },
            language: Language::Python,
            analyzer_config: AnalyzerConfig::default(),
            configuration_identity: Arc::from(b"default-config".as_slice()),
            model_identity: Arc::from(b"".as_slice()),
        };
        let result = derive_source_normal_result(
            &input,
            SourceDerivationLimits::default(),
            &mut SemanticBudget::default(),
            &mut SolverBudget::default(),
            &token,
        )
        .expect("cancellation produces a typed outcome");
        assert_eq!(result.status, TransferPartitionStatus::Unknown);
        assert!(
            result
                .frontiers
                .contains(&SourceDerivationFrontier::SolverCancelled)
        );
    }

    #[test]
    fn input_identity_is_order_independent_and_sensitive_to_source_and_model() {
        let source = b"def f(x):\n    return x";
        let entry = SourceDerivationFile {
            relative_path: "module.py".into(),
            bytes: Arc::from(source.as_slice()),
        };
        let helper = SourceDerivationFile {
            relative_path: "helper.py".into(),
            bytes: Arc::from(b"answer = 1".as_slice()),
        };
        let mut input = SourceDerivationInput {
            files: vec![entry, helper],
            entrypoint: SourceEntrypointRange {
                relative_path: "module.py".into(),
                range: Range {
                    start_byte: 0,
                    end_byte: source.len(),
                    start_line: 0,
                    end_line: 1,
                },
            },
            language: Language::Python,
            analyzer_config: AnalyzerConfig::default(),
            configuration_identity: Arc::from(b"default-config".as_slice()),
            model_identity: Arc::from(b"model-a".as_slice()),
        };
        let fingerprint = |input: &SourceDerivationInput| {
            derive_source_normal_result(
                input,
                SourceDerivationLimits {
                    max_source_files: 1,
                    ..SourceDerivationLimits::default()
                },
                &mut SemanticBudget::default(),
                &mut SolverBudget::default(),
                &CancellationToken::default(),
            )
            .expect("bounded request yields a digest")
            .input_digest
        };
        let initial = fingerprint(&input);
        let initial_dependencies = derive_source_normal_result(
            &input,
            SourceDerivationLimits {
                max_source_files: 1,
                ..SourceDerivationLimits::default()
            },
            &mut SemanticBudget::default(),
            &mut SolverBudget::default(),
            &CancellationToken::default(),
        )
        .expect("bounded request retains dependencies")
        .dependencies;
        assert_eq!(initial_dependencies.len(), 2);
        input.files.reverse();
        assert_eq!(fingerprint(&input), initial);
        input.files[0].bytes = Arc::from(b"answer = 2".as_slice());
        assert_ne!(fingerprint(&input), initial);
        input.files[0].bytes = Arc::from(b"answer = 1".as_slice());
        input.model_identity = Arc::from(b"model-b".as_slice());
        assert_ne!(fingerprint(&input), initial);
        input.model_identity = Arc::from(b"model-a".as_slice());
        input.configuration_identity = Arc::from(b"different-config".as_slice());
        assert_ne!(fingerprint(&input), initial);
    }

    #[test]
    fn source_budget_never_produces_complete_empty_partition() {
        let input = SourceDerivationInput {
            files: vec![SourceDerivationFile {
                relative_path: "module.py".into(),
                bytes: Arc::from(b"def f(x):\n    return x".as_slice()),
            }],
            entrypoint: SourceEntrypointRange {
                relative_path: "module.py".into(),
                range: Range {
                    start_byte: 0,
                    end_byte: 22,
                    start_line: 0,
                    end_line: 1,
                },
            },
            language: Language::Python,
            analyzer_config: AnalyzerConfig::default(),
            configuration_identity: Arc::from(b"default-config".as_slice()),
            model_identity: Arc::from(b"".as_slice()),
        };
        let result = derive_source_normal_result(
            &input,
            SourceDerivationLimits {
                max_source_bytes: 1,
                ..SourceDerivationLimits::default()
            },
            &mut SemanticBudget::default(),
            &mut SolverBudget::default(),
            &CancellationToken::default(),
        )
        .expect("source budget produces a typed outcome");
        assert_eq!(result.status, TransferPartitionStatus::Unknown);
        assert!(result.partitions.is_empty());
        assert!(result.frontiers.iter().any(|frontier| matches!(
            frontier,
            SourceDerivationFrontier::SourceBudgetExceeded { .. }
        )));
    }
}
