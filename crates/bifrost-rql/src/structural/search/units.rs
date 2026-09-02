//! Per-seed-file query execution: the narrowed execution scope and the entry
//! point one evaluation unit runs through.
//!
//! An incremental policy evaluation executes one unit per seed file instead of
//! one whole-workspace query, so every unit's recorded reads and rendered rows
//! belong to exactly one seed file (issue: impact-sliced `--diff-base`,
//! Milestone 2). Only the seed enumeration is narrowed: a step that asks for
//! callers, importers, descendants, dispatch, or references still sees the
//! whole workspace, because those answers are what make a finding in an
//! unedited file change.

use super::*;
use crate::analyzer::semantic::SemanticBudgetDimension;
use std::path::Path;

/// Which files a query's seed enumeration runs over.
///
/// The default is the whole analyzed file set, which is byte for byte the
/// behavior every existing entry point has. A narrowed scope replaces the
/// enumeration only: `seed_files` is the exact file set the seed scanners
/// consider (still filtered by language and `where_globs`, still ordered by
/// each family's own comparator), and `workspace_files` is the whole-workspace
/// enumeration those scanners still need for answers a slice must not narrow --
/// the structural seed's diagnostic-only language walk and its per-provider
/// file counts. The caller computes `workspace_files` once and hands the same
/// slice to every unit, which is what keeps unit-wise execution linear in the
/// file count instead of quadratic.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodeQueryExecutionScope<'a> {
    seed_files: Option<&'a [ProjectFile]>,
    workspace_files: Option<&'a [ProjectFile]>,
}

impl<'a> CodeQueryExecutionScope<'a> {
    /// Enumerate seeds over the analyzer's whole analyzed file set.
    pub const fn whole_workspace() -> Self {
        Self {
            seed_files: None,
            workspace_files: None,
        }
    }

    /// Enumerate seeds over exactly `seed_files`, with `workspace_files` as the
    /// already-computed whole-workspace enumeration.
    pub const fn for_seed_files(
        seed_files: &'a [ProjectFile],
        workspace_files: &'a [ProjectFile],
    ) -> Self {
        Self {
            seed_files: Some(seed_files),
            workspace_files: Some(workspace_files),
        }
    }

    /// The exact files seed enumeration is restricted to, if any.
    pub const fn seed_files(self) -> Option<&'a [ProjectFile]> {
        self.seed_files
    }

    /// The whole-workspace enumeration, if the caller already computed it.
    pub(super) const fn workspace_files(self) -> Option<&'a [ProjectFile]> {
        self.workspace_files
    }
}

/// Execute one evaluation unit: `query` over exactly `scope`'s seed files.
///
/// This is `execute_code_query_detailed_eager_index` with a seed scope: the
/// `EagerAuto` access mode and full result detail the policy match path uses,
/// so a unit and the whole execution it partitions agree on everything except
/// which files the seed enumeration walked. The result carries each rendered
/// row's dedup key and evidence projection, every budgeted counter lane, and
/// the completion the whole run would derive, which is everything
/// [`merge_unit_rows`] needs.
pub fn execute_code_query_unit(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    scope: CodeQueryExecutionScope<'_>,
) -> UnitExecutionResult {
    let mut row_keys = Vec::new();
    let detailed =
        execute_detailed_unit(analyzer, query, limits, cancellation, scope, &mut row_keys);
    let completion = detailed.result.completion();
    let DetailedCodeQueryResult {
        result,
        work,
        budgeted_work,
        evidence,
        ..
    } = detailed;
    let CodeQueryResult {
        results,
        truncated,
        diagnostics,
        ..
    } = result;
    assert_eq!(
        results.len(),
        row_keys.len(),
        "one dedup key is rendered for every rendered row"
    );
    assert_eq!(
        results.len(),
        evidence.len(),
        "detailed evidence stays aligned with rendered rows"
    );
    let rows = results
        .into_iter()
        .zip(evidence)
        .zip(row_keys)
        .map(|((item, evidence), key)| UnitRow {
            item: UnitRowItem::project(&item),
            evidence: UnitRowEvidence::project(&evidence),
            key,
        })
        .collect();
    UnitExecutionResult {
        rows,
        work,
        budgeted_work,
        completion,
        diagnostics,
        truncated,
    }
}

/// The detailed execution one unit runs, with its rows' dedup keys.
fn execute_detailed_unit(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    scope: CodeQueryExecutionScope<'_>,
    row_keys: &mut Vec<UnitRowKey>,
) -> DetailedCodeQueryResult {
    let query_scope = AnalyzerQueryScope::new(analyzer);
    let token = query_scope.token();
    let access_mode = match benchmark_structural_access_mode() {
        StructuralAccessMode::ScanOnly => StructuralAccessMode::ScanOnly,
        _ => StructuralAccessMode::EagerAuto,
    };
    execute_internal_with_analysis_strategy(
        analyzer,
        token,
        None,
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::ROWS_ONLY,
        None,
        None,
        scope,
        Some(row_keys),
    )
}

/// The dedup identity of one rendered row, over stable identities only.
///
/// This is the projection of the executor's private `PipelineKey`: every arm
/// is rendered over workspace-relative paths, content-derived declaration
/// identities, mount-free semantic wire ids, and the typed keys' own stable
/// fields. Nothing that carries a workspace root or a process-local handle
/// address enters it, so the same row keyed at two different roots -- a head
/// workspace and a base revision exported to a temporary directory -- projects
/// to the same key.
///
/// The rendering is structured rather than concatenated: `arm` names the row
/// family and `parts` are that family's identity fields in a fixed order, so
/// no separator convention can make two different rows compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnitRowKey {
    arm: Box<str>,
    parts: Vec<Box<str>>,
}

impl UnitRowKey {
    /// The row family this key addresses.
    pub fn arm(&self) -> &str {
        &self.arm
    }

    /// The family's identity fields, in the family's own declared order.
    pub fn parts(&self) -> &[Box<str>] {
        &self.parts
    }
}

/// Builder for one `UnitRowKey` arm.
struct UnitRowKeyBuilder {
    arm: &'static str,
    parts: Vec<Box<str>>,
}

/// Start one key arm.
fn key(arm: &'static str) -> UnitRowKeyBuilder {
    UnitRowKeyBuilder {
        arm,
        parts: Vec::new(),
    }
}

impl UnitRowKeyBuilder {
    fn text(mut self, value: impl AsRef<str>) -> Self {
        self.parts.push(Box::from(value.as_ref()));
        self
    }

    /// A component whose only rendering is its variant name.
    ///
    /// Used exclusively for field-less enumerations, whose `Debug` output is
    /// that name. Never for a value that carries a path, a root, or a handle.
    fn variant(self, value: impl std::fmt::Debug) -> Self {
        self.text(format!("{value:?}"))
    }

    fn number(self, value: impl std::fmt::Display) -> Self {
        self.text(value.to_string())
    }

    fn flag(self, value: bool) -> Self {
        self.text(if value { "true" } else { "false" })
    }

    /// A file, as its workspace-relative path: the one spelling of a file that
    /// is the same in every workspace holding the same content.
    fn path(self, file: &ProjectFile) -> Self {
        self.text(rel_path_string(file))
    }

    /// A declaration, as its content-derived declaration id.
    fn declaration(self, unit: &CodeUnit) -> Self {
        self.text(unit.declaration_id().as_str())
    }

    fn range(self, range: Range) -> Self {
        self.text(format!(
            "{}:{}:{}:{}",
            range.start_byte, range.end_byte, range.start_line, range.end_line
        ))
    }

    /// An optional component. `None` renders empty and `Some` renders with a
    /// leading `=`, so no value can collide with the absence of one.
    fn optional(self, value: Option<impl AsRef<str>>) -> Self {
        match value {
            Some(value) => self.text(format!("={}", value.as_ref())),
            None => self.text(""),
        }
    }

    fn declaration_value(self, value: &DeclarationValue) -> Self {
        self.declaration(&value.unit)
            .range(value.range)
            .optional(value.structural_kind.map(NormalizedKind::label))
    }

    fn call_site_value(self, value: &CallSiteValue) -> Self {
        let CallSiteValue(site, binding) = value;
        // A call site is identified by the exact call expression it covers and
        // the two declarations it connects. The argument rows the pipeline key
        // also holds are derived from that same expression, so they cannot
        // separate two rows this rendering equates.
        self.path(&site.file)
            .range(site.range)
            .range(site.callee_range)
            .declaration(&site.caller)
            .declaration(&site.callee)
            .variant(site.kind)
            .text(usage_proof_label(site.proof))
            .optional(site.receiver.map(|range| {
                format!(
                    "{}:{}:{}:{}",
                    range.start_byte, range.end_byte, range.start_line, range.end_line
                )
            }))
            .number(site.arguments.len())
            .variant(binding)
    }

    fn finish(self) -> UnitRowKey {
        UnitRowKey {
            arm: Box::from(self.arm),
            parts: self.parts,
        }
    }
}

/// Project one pipeline dedup key onto stable identities.
///
/// Exhaustive by construction: a new row family cannot reach the merge with a
/// key that silently equals another family's.
pub(super) fn unit_row_key(key_value: &PipelineKey) -> UnitRowKey {
    match key_value {
        PipelineKey::StructuralMatch(file, node) => {
            key("structural_match").path(file).number(node).finish()
        }
        PipelineKey::Declaration(value) => key("declaration").declaration_value(value).finish(),
        PipelineKey::Semantic(value) => semantic_unit_row_key(value),
        PipelineKey::File(file) => key("file").path(file).finish(),
        PipelineKey::ReferenceSite(site) => key("reference_site")
            .path(&site.file)
            .range(site.range)
            .declaration_value(&site.target)
            .optional(
                site.enclosing
                    .as_ref()
                    .map(|enclosing| enclosing.unit.declaration_id().as_str().to_string()),
            )
            .text(site.usage_kind.wire_label())
            .text(usage_proof_label(site.proof))
            .optional(site.reference_kind.map(reference_kind_label))
            .finish(),
        PipelineKey::CallSite(value) => key("call_site").call_site_value(value).finish(),
        PipelineKey::ExpressionSite(value) => key("expression_site")
            .call_site_value(&value.call_site)
            .range(value.range)
            .text(match &value.input {
                ExpressionInput::Receiver => "receiver".to_string(),
                ExpressionInput::Parameter { index, name } => match name {
                    Some(name) => format!("parameter:{index}:{name}"),
                    None => format!("parameter:{index}"),
                },
            })
            .finish(),
        PipelineKey::JsxAttributeValue(id) => key("jsx_attribute_value").text(id).finish(),
        PipelineKey::ReceiverAnalysis(operation, file, range) => key("receiver_analysis")
            .variant(operation)
            .path(file)
            .range(*range)
            .finish(),
        PipelineKey::MemberTargetAnalysis(operation, file, range) => key("member_target_analysis")
            .variant(operation)
            .path(file)
            .range(*range)
            .finish(),
        PipelineKey::ReceiverOutcome(id) => key("receiver_outcome").text(id).finish(),
        PipelineKey::ReceiverEvidence(id) => key("receiver_evidence").text(id).finish(),
        PipelineKey::FieldWriteValue(id) => key("field_write_value").text(id).finish(),
        PipelineKey::CallShape(id) => key("call_shape").text(id).finish(),
        PipelineKey::CallArgumentGroup(id) => key("call_argument_group").text(id).finish(),
        PipelineKey::CallArgument(id) => key("call_argument").text(id).finish(),
        PipelineKey::CallBinding(id) => key("call_binding").text(id).finish(),
        PipelineKey::CallEffect(id) => key("call_effect").text(id).finish(),
        PipelineKey::CallResultContract(id) => key("call_result_contract").text(id).finish(),
        PipelineKey::ResultContractUse(id) => key("result_contract_use").text(id).finish(),
        PipelineKey::ResultContractFailureUse(id) => {
            key("result_contract_failure_use").text(id).finish()
        }
        PipelineKey::NilnessOperation(id) => key("nilness_operation").text(id).finish(),
        PipelineKey::SwitchCoverage(id) => key("switch_coverage").text(id).finish(),
        PipelineKey::DetachedTaskTransfer(id) => key("detached_task_transfer").text(id).finish(),
        PipelineKey::ProcedureEffect(id) => key("procedure_effect").text(id).finish(),
        PipelineKey::CallableSignature(id) => key("callable_signature").text(id).finish(),
        PipelineKey::SignatureParameter(id) => key("signature_parameter").text(id).finish(),
        PipelineKey::DecoratedParameter(id) => key("decorated_parameter").text(id).finish(),
        PipelineKey::CallableApplicability(id) => key("callable_applicability").text(id).finish(),
        PipelineKey::OverloadSelection(id) => key("overload_selection").text(id).finish(),
        PipelineKey::MemberSelection(id) => key("member_selection").text(id).finish(),
        PipelineKey::DispatchOutcome(id) => key("dispatch_outcome").text(id).finish(),
        PipelineKey::DispatchTarget(id) => key("dispatch_target").text(id).finish(),
        PipelineKey::MemberFamily(id) => key("member_family").text(id).finish(),
        PipelineKey::MemberFamilyEdge(id) => key("member_family_edge").text(id).finish(),
        PipelineKey::Occurrence(occurrence) => key("occurrence")
            .path(&occurrence.file)
            .number(occurrence.node)
            .text(occurrence.role.label())
            .finish(),
        PipelineKey::LexicalScope(scope) => key("lexical_scope")
            .path(&scope.file)
            .number(scope.index)
            .finish(),
        PipelineKey::Binding(binding) => key("binding")
            .path(&binding.file)
            .number(binding.index)
            .flag(binding.shadowed)
            .optional(binding.reached_from.as_deref())
            .finish(),
        PipelineKey::ResolutionCandidate(candidate) => key("resolution_candidate")
            .path(&candidate.file)
            .number(candidate.node)
            .text(candidate.role.label())
            .number(candidate.ordinal)
            .finish(),
        PipelineKey::CandidateHop(hop) => key("candidate_hop")
            .path(&hop.file)
            .number(hop.node)
            .text(hop.role.label())
            .number(hop.ordinal)
            .number(hop.hop)
            .finish(),
        PipelineKey::GenerationSite(site) => key("generation_site")
            .path(&site.file)
            .number(site.index)
            .finish(),
        PipelineKey::Export(export) => key("export")
            .path(&export.file)
            .number(export.index)
            .finish(),
        PipelineKey::DeclarationState(state) => key("declaration_state")
            .path(&state.file)
            .number(state.index)
            .finish(),
        PipelineKey::ReferenceEdge(edge) => key("reference_edge")
            .path(&edge.file)
            .number(edge.start_byte)
            .number(edge.end_byte)
            .declaration(&edge.target)
            .optional(edge.reference_kind.map(|kind| kind.to_string()))
            .text(usage_proof_label(edge.proof))
            .text(edge.usage_kind.wire_label())
            .text(edge.site_class.label())
            .text(edge.owner_relation.label())
            .text(edge.provenance.label())
            .finish(),
        PipelineKey::StateEvent(event) => key("state_event")
            .path(&event.file)
            .text(&event.procedure)
            .number(event.event)
            .finish(),
        PipelineKey::FlowRelation(relation) => key("flow_relation")
            .path(&relation.file)
            .text(&relation.procedure)
            .number(relation.relation)
            .finish(),
        PipelineKey::ControlRelation(relation) => key("control_relation")
            .text(&relation.procedure)
            .number(relation.index)
            .finish(),
        PipelineKey::Guard(guard) => key("guard")
            .text(&guard.procedure)
            .number(guard.guard.index())
            .finish(),
        PipelineKey::SourceSet(entity) => key("source_set").text(&entity.id).finish(),
        PipelineKey::BuildTarget(entity) => key("build_target").text(&entity.id).finish(),
        PipelineKey::TopologyEdge(edge) => key("topology_edge").text(&edge.id).finish(),
        PipelineKey::ConcurrentAccessConflict(id) => {
            key("concurrent_access_conflict").text(id).finish()
        }
        PipelineKey::RewritePath(path) => key("rewrite_path")
            .path(&path.file)
            .number(path.index)
            .finish(),
        PipelineKey::QualifiedPath(path) => key("qualified_path")
            .path(&path.file)
            .number(path.terminal_node)
            .finish(),
        PipelineKey::PathSegment(segment) => key("path_segment")
            .path(&segment.file)
            .number(segment.path_terminal_node)
            .number(segment.ordinal)
            .finish(),
    }
}

/// Project one semantic dedup key onto its mount-free wire identity.
///
/// The three handle-bearing arms are keyed by the same public wire ids the
/// rendered rows publish, which fold the artifact's public fingerprint rather
/// than its mount-bearing durable key.
fn semantic_unit_row_key(key_value: &SemanticPipelineKey) -> UnitRowKey {
    match key_value {
        SemanticPipelineKey::Procedure(handle) => key("semantic_procedure")
            .text(semantic::procedure_wire_id(handle))
            .finish(),
        SemanticPipelineKey::ProgramPoint(handle) => key("semantic_program_point")
            .text(semantic::program_point_wire_id(handle))
            .finish(),
        SemanticPipelineKey::ControlEdge(handle) => key("semantic_control_edge")
            .text(semantic::control_edge_wire_id(handle))
            .finish(),
        SemanticPipelineKey::CallResult(id) => key("semantic_call_result").text(id).finish(),
        SemanticPipelineKey::TypestateFinding(id) => {
            key("semantic_typestate_finding").text(id).finish()
        }
        SemanticPipelineKey::TypestateWitness(id) => {
            key("semantic_typestate_witness").text(id).finish()
        }
        SemanticPipelineKey::FlowEndpoint(id) => key("semantic_flow_endpoint").text(id).finish(),
        SemanticPipelineKey::FlowWitness(id) => key("semantic_flow_witness").text(id).finish(),
        SemanticPipelineKey::TaintFinding(id) => key("semantic_taint_finding").text(id).finish(),
    }
}

/// One rendered row's evidence, projected onto values that survive
/// serialization and a change of workspace root.
///
/// This is `DetailedCodeQueryEvidence` with two changes. The `ProjectFile` of
/// every level becomes the workspace-relative path it denotes, because a
/// `ProjectFile` carries an absolute root and a unit produced under one root
/// is reused under another. `decorated_parameter` is dropped: it is
/// runtime-only semantic identity, documented as outside the serializable row
/// model, which is why a plan carrying it classifies as `Whole`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowEvidence {
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub rel_path: Box<str>,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub stable_owner_candidate: Option<CodeQueryStableOwnerCandidate>,
    pub identities: UnitRowIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
    pub provenance: Vec<UnitRowProvenance>,
}

/// One provenance trace of a row, projected like its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowProvenance {
    pub branch: Vec<usize>,
    pub seed: UnitRowProvenanceRef,
    pub steps: Vec<UnitRowProvenanceStep>,
}

/// One step of a provenance trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowProvenanceStep {
    pub op: String,
    pub result: UnitRowProvenanceRef,
    pub via: Option<UnitRowProvenanceRef>,
}

/// One value a provenance trace passed through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowProvenanceRef {
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub rel_path: Box<str>,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub display_range: Option<CodeQueryRange>,
    pub identities: UnitRowIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
}

/// The provenance identities a row or trace value carries.
// Adjacently tagged rather than internally tagged like its siblings: two of
// these variants are newtypes over an optional, and an internally tagged
// newtype variant containing an optional has no map form to write the tag
// into. The alternative -- giving those two variants a named field -- would
// rename the same value at twenty call sites to change one serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "identities", content = "identity", rename_all = "snake_case")]
pub enum UnitRowIdentities {
    None,
    Primary(Option<UnitRowIdentityCandidate>),
    ReferenceTarget(Option<UnitRowIdentityCandidate>),
    Call {
        caller: Option<UnitRowIdentityCandidate>,
        callee: Option<UnitRowIdentityCandidate>,
    },
}

/// One stable owner candidate and the file it was found in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowIdentityCandidate {
    pub rel_path: Box<str>,
    pub candidate: CodeQueryStableOwnerCandidate,
}

impl UnitRowEvidence {
    /// Project one execution's evidence row.
    pub fn project(evidence: &DetailedCodeQueryEvidence) -> Self {
        Self {
            domain: evidence.domain,
            key: evidence.key.clone(),
            rel_path: Box::from(rel_path_string(&evidence.file).as_str()),
            byte_span: evidence.byte_span.clone(),
            stable_owner_candidate: evidence.stable_owner_candidate.clone(),
            identities: UnitRowIdentities::project(&evidence.identities),
            source_slice_sha256: evidence.source_slice_sha256,
            provenance: evidence
                .provenance
                .iter()
                .map(UnitRowProvenance::project)
                .collect(),
        }
    }

    /// Rebuild the executor's evidence row against a workspace root.
    ///
    /// `decorated_parameter` is always `None`: a plan whose rows need it is
    /// never partitioned, so no unit row ever carried one to lose.
    pub fn to_detailed(&self, root: &Path, result_index: usize) -> DetailedCodeQueryEvidence {
        DetailedCodeQueryEvidence {
            result_index,
            domain: self.domain,
            key: self.key.clone(),
            file: ProjectFile::new(root, Path::new(self.rel_path.as_ref())),
            byte_span: self.byte_span.clone(),
            stable_owner_candidate: self.stable_owner_candidate.clone(),
            identities: self.identities.clone().into_detailed(root),
            source_slice_sha256: self.source_slice_sha256,
            provenance: self
                .provenance
                .iter()
                .map(|provenance| provenance.to_detailed(root))
                .collect(),
            decorated_parameter: None,
        }
    }
}

impl UnitRowProvenance {
    /// Project one execution's provenance trace.
    pub fn project(provenance: &DetailedCodeQueryProvenanceEvidence) -> Self {
        Self {
            branch: provenance.branch.clone(),
            seed: UnitRowProvenanceRef::project(&provenance.seed),
            steps: provenance
                .steps
                .iter()
                .map(|step| UnitRowProvenanceStep {
                    op: step.op.clone(),
                    result: UnitRowProvenanceRef::project(&step.result),
                    via: step.via.as_ref().map(UnitRowProvenanceRef::project),
                })
                .collect(),
        }
    }

    fn to_detailed(&self, root: &Path) -> DetailedCodeQueryProvenanceEvidence {
        DetailedCodeQueryProvenanceEvidence {
            branch: self.branch.clone(),
            seed: self.seed.to_detailed(root),
            steps: self
                .steps
                .iter()
                .map(|step| DetailedCodeQueryProvenanceStepEvidence {
                    op: step.op.clone(),
                    result: step.result.to_detailed(root),
                    via: step.via.as_ref().map(|via| via.to_detailed(root)),
                })
                .collect(),
        }
    }
}

impl UnitRowProvenanceRef {
    fn project(reference: &DetailedCodeQueryProvenanceRefEvidence) -> Self {
        Self {
            domain: reference.domain,
            key: reference.key.clone(),
            rel_path: Box::from(rel_path_string(&reference.file).as_str()),
            byte_span: reference.byte_span.clone(),
            display_range: reference.display_range,
            identities: UnitRowIdentities::project(&reference.identities),
            source_slice_sha256: reference.source_slice_sha256,
        }
    }

    fn to_detailed(&self, root: &Path) -> DetailedCodeQueryProvenanceRefEvidence {
        DetailedCodeQueryProvenanceRefEvidence {
            domain: self.domain,
            key: self.key.clone(),
            file: ProjectFile::new(root, Path::new(self.rel_path.as_ref())),
            byte_span: self.byte_span.clone(),
            display_range: self.display_range,
            identities: self.identities.clone().into_detailed(root),
            source_slice_sha256: self.source_slice_sha256,
        }
    }
}

impl UnitRowIdentities {
    fn project(identities: &DetailedCodeQueryProvenanceIdentities) -> Self {
        let candidate = |candidate: &Option<DetailedCodeQueryIdentityCandidate>| {
            candidate
                .as_ref()
                .map(|candidate| UnitRowIdentityCandidate {
                    rel_path: Box::from(rel_path_string(&candidate.file).as_str()),
                    candidate: candidate.candidate.clone(),
                })
        };
        match identities {
            DetailedCodeQueryProvenanceIdentities::None => Self::None,
            DetailedCodeQueryProvenanceIdentities::Primary(value) => {
                Self::Primary(candidate(value))
            }
            DetailedCodeQueryProvenanceIdentities::ReferenceTarget(value) => {
                Self::ReferenceTarget(candidate(value))
            }
            DetailedCodeQueryProvenanceIdentities::Call { caller, callee } => Self::Call {
                caller: candidate(caller),
                callee: candidate(callee),
            },
        }
    }

    fn into_detailed(self, root: &Path) -> DetailedCodeQueryProvenanceIdentities {
        let candidate = |candidate: Option<UnitRowIdentityCandidate>| {
            candidate.map(|candidate| DetailedCodeQueryIdentityCandidate {
                file: ProjectFile::new(root, Path::new(candidate.rel_path.as_ref())),
                candidate: candidate.candidate,
            })
        };
        match self {
            Self::None => DetailedCodeQueryProvenanceIdentities::None,
            Self::Primary(value) => {
                DetailedCodeQueryProvenanceIdentities::Primary(candidate(value))
            }
            Self::ReferenceTarget(value) => {
                DetailedCodeQueryProvenanceIdentities::ReferenceTarget(candidate(value))
            }
            Self::Call { caller, callee } => DetailedCodeQueryProvenanceIdentities::Call {
                caller: candidate(caller),
                callee: candidate(callee),
            },
        }
    }
}

/// One rendered row's public value and provenance, projected onto exactly the
/// fields the policy match adapter reads.
///
/// `CodeQueryResultItem` cannot round-trip: its value tree spells 196 static
/// labels across 118 public wire types, so a `Deserialize` implementation
/// would mean re-interning every one of them. The adapter reads a small,
/// closed subset of that tree -- a domain, a path, a display range, and a
/// handful of per-family identity and status fields -- so a unit's product
/// carries that subset and nothing else. The projection is exhaustive by
/// construction: a new row family cannot reach the adapter as a silently
/// unsupported row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItem {
    pub value: UnitRowItemValue,
    pub provenance: Vec<UnitRowItemProvenance>,
    pub provenance_truncated: bool,
}

impl UnitRowItem {
    /// Project one rendered row.
    pub fn project(item: &CodeQueryResultItem) -> Self {
        Self {
            value: UnitRowItemValue::project(&item.value),
            provenance: item
                .provenance
                .iter()
                .map(UnitRowItemProvenance::project)
                .collect(),
            provenance_truncated: item.provenance_truncated,
        }
    }
}

/// One rendered row's terminal value.
///
/// `Unsupported` is the analysis-only half of the row registry: those domains
/// are refused before any field of theirs is read, so the projection carries
/// none. Every other row is `Presented`, which is the triple every terminal
/// presentation reads (`detailed_domain`, the row's own path, and
/// `display_range`) plus the family's own extra fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "value", rename_all = "snake_case")]
pub enum UnitRowItemValue {
    Unsupported,
    Presented {
        domain: DetailedCodeQueryDomain,
        path: Box<str>,
        range: Option<CodeQueryRange>,
        terminal: UnitRowItemTerminal,
    },
}

/// The per-family fields a presented row carries beyond its domain, path and
/// display range.
///
/// `SourcePosition` is the shared case: a row whose presentation is decided by
/// its domain, path and range alone, and which no terminal result shape names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "terminal_kind", rename_all = "snake_case")]
pub enum UnitRowItemTerminal {
    SourcePosition,
    StructuralMatch {
        kind: Box<str>,
    },
    Declaration {
        kind: Box<str>,
        fq_name: Box<str>,
    },
    File,
    ReferenceSite {
        proof: Box<str>,
        target_fq_name: Box<str>,
        usage_kind: Box<str>,
    },
    CallSite {
        proof: Box<str>,
        caller_fq_name: Box<str>,
        callee_fq_name: Box<str>,
    },
    ExpressionSite {
        input_kind: Box<str>,
        parameter_index: Option<usize>,
        parameter_name: Option<Box<str>>,
    },
    DecoratedParameter {
        id: Box<str>,
        parameter_id: Box<str>,
        terminal: bool,
        completion: Box<str>,
        coverage: Box<str>,
    },
    JsxAttributeValue {
        id: Box<str>,
        ast_id: Box<str>,
        element_identity: Box<str>,
        coverage: Box<str>,
        reason: Option<Box<str>>,
    },
    FieldWriteValue {
        id: Box<str>,
        assignment_ast_id: Box<str>,
        rhs_ast_id: Box<str>,
        receiver_identity_id: Box<str>,
        member_target_id: Box<str>,
        proof: Box<str>,
        completeness: Box<str>,
        coverage: Box<str>,
    },
    CallResult {
        proof: Box<str>,
    },
}

/// Borrow a public row string as the projection's owned form.
fn boxed(value: &str) -> Box<str> {
    Box::from(value)
}

impl UnitRowItemValue {
    fn project(value: &CodeQueryResultValue) -> Self {
        let terminal = match value {
            CodeQueryResultValue::StructuralMatch { value } => {
                UnitRowItemTerminal::StructuralMatch {
                    kind: boxed(value.kind),
                }
            }
            CodeQueryResultValue::Declaration { value } => UnitRowItemTerminal::Declaration {
                kind: boxed(value.kind),
                fq_name: boxed(&value.fq_name),
            },
            CodeQueryResultValue::File { .. } => UnitRowItemTerminal::File,
            CodeQueryResultValue::ReferenceSite { value } => UnitRowItemTerminal::ReferenceSite {
                proof: boxed(value.proof),
                target_fq_name: boxed(&value.target.fq_name),
                usage_kind: boxed(value.usage_kind),
            },
            CodeQueryResultValue::CallSite { value } => UnitRowItemTerminal::CallSite {
                proof: boxed(value.proof),
                caller_fq_name: boxed(&value.caller.fq_name),
                callee_fq_name: boxed(&value.callee.fq_name),
            },
            CodeQueryResultValue::ExpressionSite { value } => UnitRowItemTerminal::ExpressionSite {
                input_kind: boxed(value.input_kind),
                parameter_index: value.parameter_index,
                parameter_name: value.parameter_name.as_deref().map(boxed),
            },
            CodeQueryResultValue::DecoratedParameter { value } => {
                UnitRowItemTerminal::DecoratedParameter {
                    id: boxed(&value.id),
                    parameter_id: boxed(&value.parameter_id),
                    terminal: value.terminal,
                    completion: boxed(value.completion),
                    coverage: boxed(value.coverage),
                }
            }
            CodeQueryResultValue::JsxAttributeValue { value } => {
                UnitRowItemTerminal::JsxAttributeValue {
                    id: boxed(&value.id),
                    ast_id: boxed(&value.ast_id),
                    element_identity: boxed(value.element_identity),
                    coverage: boxed(value.coverage),
                    reason: value.reason.map(boxed),
                }
            }
            CodeQueryResultValue::FieldWriteValue { value } => {
                UnitRowItemTerminal::FieldWriteValue {
                    id: boxed(&value.id),
                    assignment_ast_id: boxed(&value.assignment_ast_id),
                    rhs_ast_id: boxed(&value.rhs_ast_id),
                    receiver_identity_id: boxed(&value.receiver_identity_id),
                    member_target_id: boxed(&value.member_target_id),
                    proof: boxed(value.proof),
                    completeness: boxed(value.completeness),
                    coverage: boxed(value.coverage),
                }
            }
            CodeQueryResultValue::CallResult { value } => UnitRowItemTerminal::CallResult {
                proof: boxed(value.proof),
            },
            CodeQueryResultValue::Occurrence { .. }
            | CodeQueryResultValue::LexicalScope { .. }
            | CodeQueryResultValue::Binding { .. }
            | CodeQueryResultValue::ResolutionCandidate { .. }
            | CodeQueryResultValue::GenerationSite { .. }
            | CodeQueryResultValue::StateEvent { .. }
            | CodeQueryResultValue::RewritePath { .. }
            | CodeQueryResultValue::FlowRelation { .. }
            | CodeQueryResultValue::ControlRelation { .. }
            | CodeQueryResultValue::Guard { .. }
            | CodeQueryResultValue::ReferenceEdge { .. }
            | CodeQueryResultValue::QualifiedPath { .. }
            | CodeQueryResultValue::Export { .. }
            | CodeQueryResultValue::DeclarationState { .. }
            | CodeQueryResultValue::PathSegment { .. }
            | CodeQueryResultValue::SourceSet { .. }
            | CodeQueryResultValue::BuildTarget { .. }
            | CodeQueryResultValue::TopologyEdge { .. } => UnitRowItemTerminal::SourcePosition,
            CodeQueryResultValue::Procedure { .. }
            | CodeQueryResultValue::ProgramPoint { .. }
            | CodeQueryResultValue::ControlEdge { .. }
            | CodeQueryResultValue::TypestateFinding { .. }
            | CodeQueryResultValue::TypestateWitness { .. }
            | CodeQueryResultValue::FlowEndpoint { .. }
            | CodeQueryResultValue::FlowWitness { .. }
            | CodeQueryResultValue::TaintFinding { .. }
            | CodeQueryResultValue::ConcurrentAccessConflict { .. }
            | CodeQueryResultValue::ReceiverAnalysis { .. }
            | CodeQueryResultValue::MemberTargetAnalysis { .. }
            | CodeQueryResultValue::ReceiverOutcome { .. }
            | CodeQueryResultValue::ReceiverEvidence { .. }
            | CodeQueryResultValue::CallShape { .. }
            | CodeQueryResultValue::CallArgumentGroup { .. }
            | CodeQueryResultValue::CallArgument { .. }
            | CodeQueryResultValue::CallBinding { .. }
            | CodeQueryResultValue::CallEffect { .. }
            | CodeQueryResultValue::CallResultContract { .. }
            | CodeQueryResultValue::ResultContractUse { .. }
            | CodeQueryResultValue::ResultContractFailureUse { .. }
            | CodeQueryResultValue::NilnessOperation { .. }
            | CodeQueryResultValue::SwitchCoverage { .. }
            | CodeQueryResultValue::DetachedTaskTransfer { .. }
            | CodeQueryResultValue::ProcedureEffect { .. }
            | CodeQueryResultValue::CallableSignature { .. }
            | CodeQueryResultValue::SignatureParameter { .. }
            | CodeQueryResultValue::CallableApplicability { .. }
            | CodeQueryResultValue::OverloadSelection { .. }
            | CodeQueryResultValue::MemberSelection { .. }
            | CodeQueryResultValue::CandidateHop { .. }
            | CodeQueryResultValue::DispatchOutcome { .. }
            | CodeQueryResultValue::DispatchTarget { .. }
            | CodeQueryResultValue::MemberFamily { .. }
            | CodeQueryResultValue::MemberFamilyEdge { .. } => return Self::Unsupported,
        };
        Self::Presented {
            domain: value.detailed_domain(),
            path: boxed(row_path(value)),
            range: value.display_range(),
            terminal,
        }
    }
}

/// The path a presented row's own terminal presentation compares against the
/// evidence file.
///
/// A topology row's claim is about the build file it read, so that is its
/// path; every other family spells its own source file. Exhaustive, so a new
/// row family must state which of the two it is.
fn row_path(value: &CodeQueryResultValue) -> &str {
    match value {
        CodeQueryResultValue::StructuralMatch { value } => &value.path,
        CodeQueryResultValue::Declaration { value } => &value.path,
        CodeQueryResultValue::File { value } => &value.path,
        CodeQueryResultValue::ReferenceSite { value } => &value.path,
        CodeQueryResultValue::CallSite { value } => &value.path,
        CodeQueryResultValue::ExpressionSite { value } => &value.path,
        CodeQueryResultValue::DecoratedParameter { value } => &value.path,
        CodeQueryResultValue::JsxAttributeValue { value } => &value.path,
        CodeQueryResultValue::FieldWriteValue { value } => &value.path,
        CodeQueryResultValue::CallResult { value } => &value.path,
        CodeQueryResultValue::Occurrence { value } => &value.path,
        CodeQueryResultValue::LexicalScope { value } => &value.path,
        CodeQueryResultValue::Binding { value } => &value.path,
        CodeQueryResultValue::ResolutionCandidate { value } => &value.path,
        CodeQueryResultValue::GenerationSite { value } => &value.path,
        CodeQueryResultValue::StateEvent { value } => &value.path,
        CodeQueryResultValue::RewritePath { value } => &value.path,
        CodeQueryResultValue::FlowRelation { value } => &value.path,
        CodeQueryResultValue::ControlRelation { value } => &value.path,
        CodeQueryResultValue::Guard { value } => &value.path,
        CodeQueryResultValue::ReferenceEdge { value } => &value.path,
        CodeQueryResultValue::QualifiedPath { value } => &value.path,
        CodeQueryResultValue::Export { value } => &value.path,
        CodeQueryResultValue::DeclarationState { value } => &value.path,
        CodeQueryResultValue::PathSegment { value } => &value.path,
        CodeQueryResultValue::SourceSet { value } => &value.build_file,
        CodeQueryResultValue::BuildTarget { value } => &value.build_file,
        CodeQueryResultValue::TopologyEdge { value } => &value.build_file,
        CodeQueryResultValue::Procedure { value } => &value.path,
        CodeQueryResultValue::ProgramPoint { value } => &value.path,
        CodeQueryResultValue::ControlEdge { value } => &value.path,
        CodeQueryResultValue::TypestateFinding { value } => &value.path,
        CodeQueryResultValue::TypestateWitness { value } => &value.path,
        CodeQueryResultValue::FlowEndpoint { value } => &value.path,
        CodeQueryResultValue::FlowWitness { value } => &value.path,
        CodeQueryResultValue::TaintFinding { value } => &value.path,
        CodeQueryResultValue::ConcurrentAccessConflict { value } => &value.path,
        CodeQueryResultValue::ReceiverAnalysis { value } => &value.path,
        CodeQueryResultValue::MemberTargetAnalysis { value } => &value.path,
        CodeQueryResultValue::ReceiverOutcome { value } => &value.path,
        CodeQueryResultValue::ReceiverEvidence { value } => &value.path,
        CodeQueryResultValue::CallShape { value } => &value.path,
        CodeQueryResultValue::CallArgumentGroup { value } => &value.path,
        CodeQueryResultValue::CallArgument { value } => &value.path,
        CodeQueryResultValue::CallBinding { value } => &value.path,
        CodeQueryResultValue::CallEffect { value } => &value.path,
        CodeQueryResultValue::CallResultContract { value } => &value.path,
        CodeQueryResultValue::ResultContractUse { value } => &value.path,
        CodeQueryResultValue::ResultContractFailureUse { value } => &value.path,
        CodeQueryResultValue::NilnessOperation { value } => &value.path,
        CodeQueryResultValue::SwitchCoverage { value } => &value.path,
        CodeQueryResultValue::DetachedTaskTransfer { value } => &value.path,
        CodeQueryResultValue::ProcedureEffect { value } => &value.path,
        CodeQueryResultValue::CallableSignature { value } => &value.path,
        CodeQueryResultValue::SignatureParameter { value } => &value.path,
        CodeQueryResultValue::CallableApplicability { value } => &value.path,
        CodeQueryResultValue::OverloadSelection { value } => &value.path,
        CodeQueryResultValue::MemberSelection { value } => &value.path,
        CodeQueryResultValue::CandidateHop { value } => &value.path,
        CodeQueryResultValue::DispatchOutcome { value } => &value.path,
        CodeQueryResultValue::DispatchTarget { value } => &value.path,
        CodeQueryResultValue::MemberFamily { value } => &value.path,
        CodeQueryResultValue::MemberFamilyEdge { value } => &value.path,
    }
}

/// One provenance trace of a rendered row, projected like the row itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItemProvenance {
    pub branch: Vec<usize>,
    pub seed: UnitRowItemRef,
    pub steps: Vec<UnitRowItemProvenanceStep>,
}

/// One step of a projected provenance trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItemProvenanceStep {
    pub op: Box<str>,
    pub result: UnitRowItemRef,
    pub via: Option<UnitRowItemRef>,
}

/// One value a projected provenance trace passed through.
///
/// `kind` and `path` are the two fields every reference carries and the
/// adapter reads for every family, including the ones it can only publish as
/// unsupported; `value` is the per-family payload of the arms it adapts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItemRef {
    pub kind: Box<str>,
    pub path: Box<str>,
    pub value: UnitRowItemRefValue,
}

/// The per-family fields of one projected provenance reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "ref", rename_all = "snake_case")]
pub enum UnitRowItemRefValue {
    Unsupported,
    StructuralMatch {
        kind: Box<str>,
        node_range: Option<CodeQueryRange>,
    },
    Declaration {
        kind: Box<str>,
        fq_name: Box<str>,
        node_range: Option<CodeQueryRange>,
    },
    File,
    ReferenceSite {
        range: CodeQueryRange,
        target_fq_name: Box<str>,
        usage_kind: Option<Box<str>>,
        proof: Box<str>,
    },
    CallSite {
        range: CodeQueryRange,
        caller_fq_name: Box<str>,
        callee_fq_name: Box<str>,
        proof: Box<str>,
    },
    ExpressionSite {
        range: CodeQueryRange,
        input_kind: Box<str>,
        parameter_index: Option<usize>,
        parameter_name: Option<Box<str>>,
    },
    JsxAttributeValue {
        id: Box<str>,
        ast_id: Box<str>,
        range: CodeQueryRange,
        element_identity: Box<str>,
        coverage: Box<str>,
    },
    MemberTargetAnalysis {
        site_id: Box<str>,
        receiver_range: CodeQueryRange,
        outcome: Box<str>,
        coverage: Box<str>,
        capture: Option<Box<str>>,
    },
    FieldWriteValue {
        id: Box<str>,
        assignment_ast_id: Box<str>,
        rhs_ast_id: Box<str>,
        receiver_identity_id: Box<str>,
        member_target_id: Box<str>,
        range: CodeQueryRange,
        proof: Box<str>,
        completeness: Box<str>,
        coverage: Box<str>,
    },
    ReceiverAnalysis {
        range: CodeQueryRange,
        analysis_kind: Box<str>,
        outcome: Box<str>,
        capture: Option<Box<str>>,
    },
    DecoratedParameter {
        id: Box<str>,
        parameter_id: Box<str>,
        range: CodeQueryRange,
    },
}

impl UnitRowItemProvenance {
    fn project(provenance: &CodeQueryProvenance) -> Self {
        Self {
            branch: provenance.branch.clone(),
            seed: UnitRowItemRef::project(&provenance.seed),
            steps: provenance
                .steps
                .iter()
                .map(|step| UnitRowItemProvenanceStep {
                    op: boxed(step.op),
                    result: UnitRowItemRef::project(&step.result),
                    via: step.via.as_ref().map(UnitRowItemRef::project),
                })
                .collect(),
        }
    }
}

impl UnitRowItemRef {
    fn project(reference: &CodeQueryResultRef) -> Self {
        let value = match reference {
            CodeQueryResultRef::StructuralMatch {
                kind, node_range, ..
            } => UnitRowItemRefValue::StructuralMatch {
                kind: boxed(kind),
                node_range: *node_range,
            },
            CodeQueryResultRef::Declaration {
                kind,
                fq_name,
                node_range,
                ..
            } => UnitRowItemRefValue::Declaration {
                kind: boxed(kind),
                fq_name: boxed(fq_name),
                node_range: *node_range,
            },
            CodeQueryResultRef::File { .. } => UnitRowItemRefValue::File,
            CodeQueryResultRef::ReferenceSite {
                range,
                target_fq_name,
                usage_kind,
                proof,
                ..
            } => UnitRowItemRefValue::ReferenceSite {
                range: *range,
                target_fq_name: boxed(target_fq_name),
                usage_kind: usage_kind.map(boxed),
                proof: boxed(proof),
            },
            CodeQueryResultRef::CallSite {
                range,
                caller_fq_name,
                callee_fq_name,
                proof,
                ..
            } => UnitRowItemRefValue::CallSite {
                range: *range,
                caller_fq_name: boxed(caller_fq_name),
                callee_fq_name: boxed(callee_fq_name),
                proof: boxed(proof),
            },
            CodeQueryResultRef::ExpressionSite {
                range,
                input_kind,
                parameter_index,
                parameter_name,
                ..
            } => UnitRowItemRefValue::ExpressionSite {
                range: *range,
                input_kind: boxed(input_kind),
                parameter_index: *parameter_index,
                parameter_name: parameter_name.as_deref().map(boxed),
            },
            CodeQueryResultRef::JsxAttributeValue {
                id,
                ast_id,
                range,
                element_identity,
                coverage,
                ..
            } => UnitRowItemRefValue::JsxAttributeValue {
                id: boxed(id),
                ast_id: boxed(ast_id),
                range: *range,
                element_identity: boxed(element_identity),
                coverage: boxed(coverage),
            },
            CodeQueryResultRef::MemberTargetAnalysis {
                site_id,
                receiver_range,
                outcome,
                coverage,
                capture,
                ..
            } => UnitRowItemRefValue::MemberTargetAnalysis {
                site_id: boxed(site_id),
                receiver_range: *receiver_range,
                outcome: boxed(outcome),
                coverage: boxed(coverage),
                capture: capture.as_deref().map(boxed),
            },
            CodeQueryResultRef::FieldWriteValue {
                id,
                assignment_ast_id,
                rhs_ast_id,
                receiver_identity_id,
                member_target_id,
                range,
                proof,
                completeness,
                coverage,
                ..
            } => UnitRowItemRefValue::FieldWriteValue {
                id: boxed(id),
                assignment_ast_id: boxed(assignment_ast_id),
                rhs_ast_id: boxed(rhs_ast_id),
                receiver_identity_id: boxed(receiver_identity_id),
                member_target_id: boxed(member_target_id),
                range: *range,
                proof: boxed(proof),
                completeness: boxed(completeness),
                coverage: boxed(coverage),
            },
            CodeQueryResultRef::ReceiverAnalysis {
                range,
                analysis_kind,
                outcome,
                capture,
                ..
            } => UnitRowItemRefValue::ReceiverAnalysis {
                range: *range,
                analysis_kind: boxed(analysis_kind),
                outcome: boxed(outcome),
                capture: capture.as_deref().map(boxed),
            },
            CodeQueryResultRef::DecoratedParameter {
                id,
                parameter_id,
                range,
                ..
            } => UnitRowItemRefValue::DecoratedParameter {
                id: boxed(id),
                parameter_id: boxed(parameter_id),
                range: *range,
            },
            _ => UnitRowItemRefValue::Unsupported,
        };
        Self {
            kind: boxed(reference.kind_label()),
            path: boxed(reference.path()),
            value,
        }
    }
}

/// One rendered row of a unit execution, with the identity a merge deduplicates
/// it by.
///
/// `item` is the row every existing consumer reads; `evidence` is the same
/// evidence the detailed result carries, projected; `key` is the row's dedup
/// identity over stable identities. The three travel together because the
/// policy adapter zips results with evidence positionally, so nothing may
/// reorder one without the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRow {
    pub item: UnitRowItem,
    pub evidence: UnitRowEvidence,
    pub key: UnitRowKey,
}

/// What one evaluation unit produced.
///
/// `work` is the caller-facing measurement and `budgeted_work` the lanes it
/// drops; a merge sums both, because a cap the merge cannot see is a
/// truncation the sliced run cannot detect.
///
/// `Clone` because a published unit is reused by merging its product again on
/// a later run, and the merge consumes what it merges; serde because a
/// published unit outlives its process in the analyzer cache (Milestone 3),
/// where this is the whole of the row's product column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitExecutionResult {
    pub rows: Vec<UnitRow>,
    pub work: CodeQueryExecutionWork,
    pub budgeted_work: CodeQueryBudgetedWork,
    pub completion: CodeQueryCompletion,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub truncated: bool,
}

/// The rows several units produced, merged into the vector one whole execution
/// would have produced.
#[derive(Debug)]
pub struct MergedUnitRows {
    pub items: Vec<UnitRowItem>,
    pub evidence: Vec<UnitRowEvidence>,
    pub work: CodeQueryExecutionWork,
    pub budgeted_work: CodeQueryBudgetedWork,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub truncated: bool,
}

impl MergedUnitRows {
    /// The completion these merged rows support, derived exactly as
    /// `CodeQueryResult::completion` derives one.
    pub fn completion(&self) -> CodeQueryCompletion {
        code_query_completion(self.truncated, &self.diagnostics)
    }

    /// The merged evidence as the executor's own type, against `root`.
    pub fn detailed_evidence(&self, root: &Path) -> Vec<DetailedCodeQueryEvidence> {
        self.evidence
            .iter()
            .enumerate()
            .map(|(result_index, evidence)| evidence.to_detailed(root, result_index))
            .collect()
    }
}

/// Merge the rows of several unit executions of one query into the vector one
/// whole execution would have produced.
///
/// `units` must arrive in seed order -- the order the family's own comparator
/// puts their seed files in, which [`seed_file_order`] and
/// [`structural_seed_file_order`] expose. The whole execution's row vector is
/// the concatenation of its per-seed-file row vectors in exactly that order,
/// deduplicated first-writer-wins, so this reproduces it: a repeated key keeps
/// the first row and merges the later row's provenance traces into it under the
/// same `MAX_PROVENANCE_TRACES` bound the pipeline applies.
///
/// Every counter lane is summed and diagnostics are concatenated in order. The
/// equality this reproduces is claimed only while no cumulative cap was
/// reached, which is what the summed lanes let a caller check.
pub fn merge_unit_rows(units: impl IntoIterator<Item = UnitExecutionResult>) -> MergedUnitRows {
    let mut items: Vec<UnitRowItem> = Vec::new();
    let mut evidence: Vec<UnitRowEvidence> = Vec::new();
    let mut indexes: HashMap<UnitRowKey, usize> = HashMap::default();
    let mut work = CodeQueryExecutionWork::default();
    let mut budgeted_work: Option<CodeQueryBudgetedWork> = None;
    let mut diagnostics: Vec<CodeQueryDiagnostic> = Vec::new();
    let mut truncated = false;

    for unit in units {
        work = work.saturating_add(unit.work);
        budgeted_work = Some(match budgeted_work {
            Some(summed) => summed.saturating_add(&unit.budgeted_work),
            None => unit.budgeted_work,
        });
        diagnostics.extend(unit.diagnostics);
        truncated |= unit.truncated;
        for row in unit.rows {
            match indexes.get(&row.key) {
                Some(&index) => merge_duplicate_row(&mut items[index], &mut evidence[index], row),
                None => {
                    indexes.insert(row.key, items.len());
                    items.push(row.item);
                    evidence.push(row.evidence);
                }
            }
        }
    }

    MergedUnitRows {
        items,
        evidence,
        work,
        budgeted_work: budgeted_work.unwrap_or_default(),
        diagnostics,
        truncated,
    }
}

/// Fold a repeated row into the row that first claimed its key.
///
/// This is `insert_pipeline_row`'s duplicate arm at the rendered level: the
/// first row wins, the later row contributes only its provenance traces, and
/// the same `MAX_PROVENANCE_TRACES` bound decides how many fit and whether the
/// row must report its provenance as truncated. Item and evidence traces are
/// extended together because the policy adapter rejects a row whose two
/// provenance vectors differ in length.
fn merge_duplicate_row(item: &mut UnitRowItem, evidence: &mut UnitRowEvidence, row: UnitRow) {
    debug_assert_eq!(
        item.provenance.len(),
        evidence.provenance.len(),
        "a rendered row's provenance and its evidence provenance are one list"
    );
    let remaining = MAX_PROVENANCE_TRACES.saturating_sub(item.provenance.len());
    if row.item.provenance.len() > remaining {
        item.provenance_truncated = true;
    }
    item.provenance
        .extend(row.item.provenance.into_iter().take(remaining));
    evidence
        .provenance
        .extend(row.evidence.provenance.into_iter().take(remaining));
    item.provenance_truncated |= row.item.provenance_truncated;
}

/// The order the five `analyzed_files()` seed families enumerate files in.
///
/// Exposed so a caller that executes one unit per seed file can put its units
/// in the order the merge requires without restating the comparator.
pub fn seed_file_order(left: &ProjectFile, right: &ProjectFile) -> std::cmp::Ordering {
    left.cmp(right)
}

/// The order the structural seed enumerates files in: the workspace-relative
/// path string, then the language.
///
/// This is deliberately not [`seed_file_order`]: the two comparators can
/// disagree, and a merge must use the family's own.
pub fn structural_seed_file_order(left: &ProjectFile, right: &ProjectFile) -> std::cmp::Ordering {
    rel_path_string(left)
        .cmp(&rel_path_string(right))
        .then_with(|| {
            crate::analyzer::common::language_for_file(left)
                .cmp(&crate::analyzer::common::language_for_file(right))
        })
}

/// The files one plan's seed enumeration walks, in that family's own order.
///
/// A caller that executes one unit per seed file must enumerate exactly the
/// files the whole execution's seed scan would have enumerated, in exactly the
/// order the merge requires. Both answers are properties of the plan's source
/// -- which languages it admits and which comparator its scanner sorts by --
/// so they are stated here rather than restated by every caller.
///
/// `files` is the analyzer's whole analyzed file set. Only the language filter
/// is applied: a seed's `where` globs narrow the enumeration too, but the
/// scanner applies them itself on every unit, and a unit that yields no row
/// still records the reads that prove it yields none.
///
/// A `Set` source has no seed enumeration of its own; it is [`Whole`] by
/// classification and never reaches this function.
///
/// [`Whole`]: crate::query::PlanPartitioning::Whole
pub fn plan_seed_files(plan: &CodeQueryPlan, files: &[ProjectFile]) -> Vec<ProjectFile> {
    let (languages, structural) = match &plan.source {
        CodeQueryPlanSource::Seed(seed) => (seed.languages.as_slice(), true),
        CodeQueryPlanSource::Occurrences(seed) => (seed.languages.as_slice(), false),
        CodeQueryPlanSource::Scopes(seed) => (seed.languages.as_slice(), false),
        CodeQueryPlanSource::Bindings(seed) => (seed.languages.as_slice(), false),
        CodeQueryPlanSource::Paths(seed) => (seed.languages.as_slice(), false),
        CodeQueryPlanSource::GenerationSites(seed) => (seed.languages.as_slice(), false),
        CodeQueryPlanSource::Exports(seed) => (seed.languages.as_slice(), false),
        CodeQueryPlanSource::Set { .. } => {
            unreachable!("a set-sourced plan is classified Whole and has no seed enumeration")
        }
    };
    let mut selected = files
        .iter()
        .filter(|file| {
            languages.is_empty()
                || languages.contains(&crate::analyzer::common::language_for_file(file))
        })
        .cloned()
        .collect::<Vec<_>>();
    if structural {
        selected.sort_by(structural_seed_file_order);
    } else {
        selected.sort_by(seed_file_order);
    }
    selected
}

/// The cumulative cap a merged product reached, if it reached one.
///
/// Every arm names one lane the executor enforces globally over a whole
/// execution. A merge of per-seed executions equals the whole execution only
/// while none of them was reached: at the cap the whole run could have
/// truncated somewhere in its own order, and a sum that over-counts what two
/// units both reached cannot say where. So a caller that sees any arm here
/// must evaluate the whole query instead of merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergedLimit {
    /// At least one unit reported its own truncation.
    UnitTruncated,
    /// The merged rows reached the query's own root limit.
    ResultLimit,
    ScannedFiles,
    ScannedSourceBytes,
    FactNodes,
    PipelineRows,
    StepOutputs,
    SemanticMaterializedFiles,
    SemanticSourceBytes,
    SemanticRetainedBytes,
    SemanticTraversalSteps,
    SemanticRows(SemanticBudgetDimension),
    SemanticBudgetExhausted,
}

impl MergedLimit {
    /// The stable label of this lane, for diagnostics and persisted rows.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::UnitTruncated => "unit_truncated",
            Self::ResultLimit => "result_limit",
            Self::ScannedFiles => "scanned_files",
            Self::ScannedSourceBytes => "scanned_source_bytes",
            Self::FactNodes => "fact_nodes",
            Self::PipelineRows => "pipeline_rows",
            Self::StepOutputs => "step_outputs",
            Self::SemanticMaterializedFiles => "semantic_materialized_files",
            Self::SemanticSourceBytes => "semantic_source_bytes",
            Self::SemanticRetainedBytes => "semantic_retained_bytes",
            Self::SemanticTraversalSteps => "semantic_traversal_steps",
            Self::SemanticRows(_) => "semantic_rows",
            Self::SemanticBudgetExhausted => "semantic_budget_exhausted",
        }
    }
}

impl MergedUnitRows {
    /// Whether any summed lane reached the cap a whole execution enforces.
    ///
    /// `limits` and `result_limit` are the caller's own budget -- the budget
    /// the merged product must be as good as -- not whatever budget each unit
    /// happened to execute under. The comparisons are `>=` rather than `>` at
    /// every lane the executor tests with `>`, because a sum that exactly
    /// reaches a cap is already a sum that cannot prove the whole run had
    /// headroom.
    ///
    /// The lanes are paired the way the executor charges them:
    /// `import_files_resolved` shares `max_scanned_files` with the seed scan,
    /// `provenance_steps` and `import_edges_resolved` share
    /// `max_pipeline_rows` with the pipeline, and `examined_references`
    /// shares `max_fact_nodes` with fact loading.
    pub fn reached_limit(
        &self,
        limits: &CodeQueryExecutionLimits,
        result_limit: usize,
    ) -> Option<MergedLimit> {
        let reached = |lane: u64, cap: usize| lane >= cap as u64;
        if self.truncated {
            return Some(MergedLimit::UnitTruncated);
        }
        if self.items.len() >= result_limit {
            return Some(MergedLimit::ResultLimit);
        }
        if reached(
            self.work
                .scanned_files
                .saturating_add(self.budgeted_work.import_files_resolved),
            limits.max_scanned_files,
        ) {
            return Some(MergedLimit::ScannedFiles);
        }
        if reached(
            self.work.scanned_source_bytes,
            limits.max_scanned_source_bytes,
        ) {
            return Some(MergedLimit::ScannedSourceBytes);
        }
        if reached(
            self.work
                .fact_nodes
                .saturating_add(self.work.examined_references),
            limits.max_fact_nodes,
        ) {
            return Some(MergedLimit::FactNodes);
        }
        if reached(
            self.work
                .pipeline_rows
                .saturating_add(self.budgeted_work.provenance_steps)
                .saturating_add(self.budgeted_work.import_edges_resolved),
            limits.max_pipeline_rows,
        ) {
            return Some(MergedLimit::PipelineRows);
        }
        // The final step's cap is the root limit and every earlier step's is
        // `max_pipeline_rows`; the smaller of the two widens whenever either
        // could have cut a step's output.
        if reached(
            self.budgeted_work.max_step_outputs(),
            result_limit.min(limits.max_pipeline_rows),
        ) {
            return Some(MergedLimit::StepOutputs);
        }
        self.reached_semantic_limit(&limits.semantic)
    }

    /// The semantic half of [`Self::reached_limit`].
    fn reached_semantic_limit(&self, limits: &CodeQuerySemanticLimits) -> Option<MergedLimit> {
        let semantic = &self.work.semantic;
        let reached = |lane: u64, cap: usize| lane >= cap as u64;
        if semantic.budget_exhausted {
            return Some(MergedLimit::SemanticBudgetExhausted);
        }
        if reached(
            semantic.unique_materialized_files,
            limits.max_materialized_files,
        ) {
            return Some(MergedLimit::SemanticMaterializedFiles);
        }
        if reached(semantic.source_bytes, limits.max_source_bytes) {
            return Some(MergedLimit::SemanticSourceBytes);
        }
        if reached(semantic.retained_bytes, limits.max_retained_bytes) {
            return Some(MergedLimit::SemanticRetainedBytes);
        }
        if reached(semantic.traversal_steps, limits.max_traversal_steps) {
            return Some(MergedLimit::SemanticTraversalSteps);
        }
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            let cap = limits
                .rows_per_dimension
                .map_or(limits.max_rows_per_dimension, |rows| rows.get(dimension));
            if reached(semantic_row_work(semantic, dimension), cap) {
                return Some(MergedLimit::SemanticRows(dimension));
            }
        }
        None
    }
}

/// One semantic row lane of a merged product, by the dimension it is capped
/// under.
///
/// The two byte dimensions are not row lanes: `SourceBytes` is capped by
/// `max_source_bytes` and `OwnedTextBytes` by `max_retained_bytes`, both
/// checked by name above. They are matched here rather than caught by a
/// wildcard so that a new dimension fails to compile until it is priced.
fn semantic_row_work(work: &CodeQuerySemanticWork, dimension: SemanticBudgetDimension) -> u64 {
    use SemanticBudgetDimension as Dimension;
    match dimension {
        Dimension::SourceBytes => work.source_bytes,
        Dimension::Procedures => work.procedures,
        Dimension::Blocks => work.blocks,
        Dimension::ProgramPoints => work.program_points,
        Dimension::Values => work.values,
        Dimension::Allocations => work.allocations,
        Dimension::CallSites => work.call_sites,
        Dimension::MemoryLocations => work.memory_locations,
        Dimension::Captures => work.captures,
        Dimension::SourceMappings => work.source_mappings,
        Dimension::Evidence => work.evidence,
        Dimension::Gaps => work.gaps,
        Dimension::Events => work.events,
        Dimension::ControlEdges => work.control_edges,
        Dimension::NestedEntries => work.nested_entries,
        Dimension::OwnedTextBytes => work.retained_bytes,
    }
}
