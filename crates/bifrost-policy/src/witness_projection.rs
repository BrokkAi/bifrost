use crate::finding::{BoundedWitness, WitnessStep, WitnessStepKind, WitnessStepProvenance};
use crate::finding_identity::WitnessId;
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::ProjectFile;
use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::SelectedTupleBinding;
use brokk_bifrost_analysis::analyzer::semantic::SemanticLocator;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    SelectedPatternProjection, WorkspaceSemanticOracle,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    ProcedureId, SemanticArtifact, SemanticBudget, SemanticOutcome, SemanticRequest,
    WorkspaceRelativePath,
};
use brokk_bifrost_flow::dataflow::{SummaryWitness, SummaryWitnessStepKind};
use brokk_bifrost_flow::taint::output_product::OutputWitnessRow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

/// The run-scoped inputs for looking up admitted pattern binders while witnesses
/// are projected: the run's cancellation, its semantic execution budget, and the
/// answers already found. One lookup serves every witness of the same binder, so
/// a finding with many witnesses does not re-materialize its source file.
pub(super) struct PatternProvenance<'a> {
    cancellation: &'a CancellationToken,
    budget: RefCell<&'a mut SemanticBudget>,
    memo: RefCell<HashMap<SemanticLocator, WitnessStepProvenance>>,
    /// Each file's binders, indexed once, so a witness finds its candidate
    /// without scanning every procedure of the file again.
    binders: RefCell<HashMap<WorkspaceRelativePath, Arc<BinderIndex>>>,
    /// Set when a lookup stopped before it could prove or refute the admission.
    /// The caller marks the finding partial; the stop is never memoized, so a
    /// later lookup tries again.
    unavailable: Cell<bool>,
    reasons: RefCell<Vec<String>>,
}

impl<'a> PatternProvenance<'a> {
    pub(super) fn new(cancellation: &'a CancellationToken, budget: &'a mut SemanticBudget) -> Self {
        Self {
            cancellation,
            budget: RefCell::new(budget),
            memo: RefCell::new(HashMap::new()),
            binders: RefCell::new(HashMap::new()),
            unavailable: Cell::new(false),
            reasons: RefCell::new(Vec::new()),
        }
    }

    /// Note that a finding is partial when any of its origin sites is one whose
    /// admission lookup was stopped at compile time, keeping the stop's reason.
    /// It reads the finding's sources, not its retained witnesses, so a finding
    /// with no witness (a witness limit of zero, or an origin without one) is
    /// marked too.
    pub(super) fn note_stopped_sources<'s>(
        &self,
        origin_sites: impl IntoIterator<Item = &'s SemanticLocator>,
        stopped: &[(SemanticLocator, String)],
    ) {
        for site in origin_sites {
            if let Ok(index) = stopped.binary_search_by(|(held, _)| held.cmp(site)) {
                self.unavailable.set(true);
                self.record_reason(&stopped[index].1);
            }
        }
    }

    /// Keep the reason a lookup could not decide, bounded: at most eight
    /// distinct reasons of 256 bytes each per batch.
    fn record_reason(&self, reason: &str) {
        const MAX_REASONS: usize = 8;
        const MAX_REASON_BYTES: usize = 256;
        let mut end = reason.len().min(MAX_REASON_BYTES);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        let reason = &reason[..end];
        let mut reasons = self.reasons.borrow_mut();
        if reasons.len() < MAX_REASONS && !reasons.iter().any(|held| held == reason) {
            reasons.push(reason.to_owned());
        }
    }

    /// The reasons recorded since the last call, in the order they arose.
    pub(super) fn take_reasons(&self) -> Vec<String> {
        std::mem::take(&mut *self.reasons.borrow_mut())
    }

    /// Whether any lookup since the last call stopped without an answer.
    pub(super) fn take_unavailable(&self) -> bool {
        self.unavailable.replace(false)
    }

    /// The provenance of a binder the plan's binding admitted. `None` with the
    /// unavailable flag set means the lookup could not decide.
    fn lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        source_site: &SemanticLocator,
    ) -> Result<Option<WitnessStepProvenance>, String> {
        if let Some(found) = self.memo.borrow().get(source_site) {
            return Ok(Some(found.clone()));
        }
        let looked_up = {
            let mut budget = self.budget.borrow_mut();
            admitted_pattern_provenance(
                workspace,
                source_site,
                self.cancellation,
                &mut budget,
                &self.binders,
            )?
        };
        match looked_up {
            Ok(found) => {
                self.memo
                    .borrow_mut()
                    .insert(source_site.clone(), found.clone());
                Ok(Some(found))
            }
            Err(reason) => {
                self.unavailable.set(true);
                self.record_reason(&reason);
                Ok(None)
            }
        }
    }
}

/// Bound a written import chain to the report's evidence limits: at most eight
/// entries and 128 bytes each, with the declaration (the last entry) kept
/// whole. The flag says whether anything was shortened.
fn bound_import_chain(chain: &[String]) -> (Vec<String>, bool) {
    const MAX_ENTRIES: usize = 8;
    let mut truncated = false;
    let mut kept: Vec<&String> = if chain.len() > MAX_ENTRIES {
        truncated = true;
        chain[..MAX_ENTRIES - 1]
            .iter()
            .chain(chain.last())
            .collect()
    } else {
        chain.iter().collect()
    };
    let last = kept.len().saturating_sub(1);
    let bounded = kept
        .drain(..)
        .enumerate()
        .map(|(index, entry)| {
            let limit = crate::classification::MAX_REPORT_IDENTIFIER_BYTES;
            if index == last || entry.len() <= limit {
                return entry.clone();
            }
            truncated = true;
            let mut end = limit;
            while !entry.is_char_boundary(end) {
                end -= 1;
            }
            entry[..end].to_owned()
        })
        .collect();
    (bounded, truncated)
}

/// Where each guarded pattern binder of one file is: its source location to
/// the procedure ids and candidate ordinals that bind it. Two entries for one
/// location are an ambiguity the provenance refuses. The index holds keys only,
/// never a procedure handle: a handle pins its whole semantic artifact against
/// the shared resident budget, which a cache living until the batch ends would
/// do for every file it indexed.
type BinderIndex = HashMap<SemanticLocator, Vec<(ProcedureId, u32)>>;

#[cfg(test)]
thread_local! {
    /// Binder indexes built on this thread, for the tests that count them.
    static BINDER_INDEX_BUILDS: Cell<usize> = const { Cell::new(0) };
}

/// The file's semantic artifact, through the run's budget. `Err` is the reason
/// the file's semantics could not be had; the outer `Err` is a cancellation.
fn pattern_artifact(
    workspace: &WorkspaceAnalyzer,
    path: &WorkspaceRelativePath,
    cancellation: &CancellationToken,
    request: &mut SemanticRequest<'_>,
) -> Result<Result<Arc<SemanticArtifact>, String>, String> {
    let file = ProjectFile::new(workspace.analyzer().project().root(), path.as_path());
    let outcome = workspace.materialize_program_semantics(&file, request);
    // A cancellation is the only failure that propagates; everything else
    // leaves the witness without provenance and the finding partial.
    if cancellation.is_cancelled() {
        return Err("pattern witness projection was cancelled".to_owned());
    }
    // The provider's error text is kept as the reason the finding is partial.
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => return Ok(Err(format!("semantic provider failed: {error}"))),
    };
    // A budget stop is not "no admitted pattern": report it, do not memoize it.
    if matches!(outcome, SemanticOutcome::ExceededBudget { .. }) {
        return Ok(Err("semantic budget exhausted".to_owned()));
    }
    Ok(outcome
        .available_value()
        .map(Arc::clone)
        .ok_or_else(|| "program semantics unavailable".to_owned()))
}

/// Index one artifact's guarded pattern binders.
fn index_binders(artifact: &SemanticArtifact) -> BinderIndex {
    #[cfg(test)]
    BINDER_INDEX_BUILDS.with(|builds| builds.set(builds.get() + 1));
    let mut index = BinderIndex::new();
    for procedure in artifact.procedures() {
        for candidate in procedure.guarded_pattern_projections() {
            if let Some(mapping) = procedure.source_mapping(candidate.binder_source) {
                index
                    .entry(mapping.locator.clone())
                    .or_default()
                    .push((procedure.id(), candidate.ordinal));
            }
        }
    }
    index
}

/// Re-select the exact binder at report projection. The receipt's source and
/// declaration reads enter the current policy read ledger, including a stored
/// Output row replay; no persisted witness index can masquerade as a virtual
/// event. Only a site the plan's binding admitted comes here, so a lookup that
/// cannot find or re-prove it fails closed: `Err` carries why the lookup could
/// not decide (a budget stop, a limit, or a binder that is no longer found).
/// The file's binder keys are indexed on the first witness and reused for the
/// rest, and only the one candidate at the site is admitted. The artifact is
/// taken through the budgeted, cached materialization on every lookup and not
/// kept past it, so it follows the normal residency rules.
fn admitted_pattern_provenance(
    workspace: &WorkspaceAnalyzer,
    source_site: &SemanticLocator,
    cancellation: &CancellationToken,
    budget: &mut SemanticBudget,
    binders: &RefCell<HashMap<WorkspaceRelativePath, Arc<BinderIndex>>>,
) -> Result<Result<WitnessStepProvenance, String>, String> {
    // Only a Rust source file has guarded pattern candidates.
    if source_site
        .path()
        .as_path()
        .extension()
        .is_none_or(|e| e != "rs")
    {
        return Ok(Err("the source is not a Rust file".to_owned()));
    }
    let mut request = SemanticRequest::new(budget, cancellation);
    let artifact =
        match pattern_artifact(workspace, source_site.path(), cancellation, &mut request)? {
            Ok(artifact) => artifact,
            Err(reason) => return Ok(Err(reason)),
        };
    let cached = binders.borrow().get(source_site.path()).map(Arc::clone);
    let index = match cached {
        Some(index) => index,
        None => {
            let index = Arc::new(index_binders(&artifact));
            binders
                .borrow_mut()
                .insert(source_site.path().clone(), Arc::clone(&index));
            index
        }
    };
    let oracle = WorkspaceSemanticOracle::new(workspace);
    let mut records: Vec<SelectedPatternProjection> = Vec::new();
    for (id, ordinal) in index.get(source_site).map_or(&[][..], Vec::as_slice) {
        let Some(handle) = artifact.procedure_handle(*id) else {
            return Ok(Err("the binder's procedure is no longer found".to_owned()));
        };
        match oracle.selected_pattern_projection_at(&handle, *ordinal, &mut request) {
            Ok(Some(record)) => records.push(record),
            Ok(None) => return Err("pattern witness projection was cancelled".to_owned()),
            Err(error) => return Ok(Err(format!("semantic provider failed: {error}"))),
        }
    }
    Ok(provenance_from_records(workspace, source_site, &records))
}

/// The provenance of the one record that admitted `source_site`. Two records
/// for one site are ambiguous, and a record that is not admitted, lacks a read
/// the report needs, or builds provenance the report cannot carry, gives
/// nothing: in each case the witness keeps its ordinary form and the caller
/// marks the finding partial.
fn provenance_from_records<'a>(
    workspace: &WorkspaceAnalyzer,
    source_site: &SemanticLocator,
    records: impl IntoIterator<Item = &'a SelectedPatternProjection>,
) -> Result<WitnessStepProvenance, String> {
    let mut records = records.into_iter();
    let record = records
        .next()
        .ok_or_else(|| "the binder was not found again".to_owned())?;
    if records.next().is_some() {
        return Err("the binder's admission is ambiguous".to_owned());
    }
    let binding = match &record.binding {
        SelectedTupleBinding::Admitted(binding) => binding,
        SelectedTupleBinding::Unavailable(cause) => {
            return Err(format!("admission unavailable: {}", cause.reason()));
        }
        SelectedTupleBinding::Rejected { reason, .. } => {
            return Err(format!("the binder is no longer admitted: {reason}"));
        }
    };
    record.replay_reads(workspace);
    let reads = &binding.reads;
    let (import_chain, bounded) = bound_import_chain(&reads.import_chain);
    let provenance = WitnessStepProvenance::AdmittedPatternProjection {
        pack_digest: reads
            .selected_pack_digest
            .clone()
            .ok_or("the admission has no pack digest")?,
        record_id: reads
            .selected_record_id
            .clone()
            .ok_or("the admission has no declaration record")?,
        constructor: reads
            .selected_constructor
            .clone()
            .ok_or("the admission has no constructor declaration")?,
        import_chain,
        import_chain_truncated: bounded,
        import_route_complete: reads.import_route_complete,
        position: binding.ordinal,
        layout_arity: reads
            .layout
            .as_ref()
            .ok_or("the admission has no tuple layout")?
            .arity,
        field_id: binding.field_id.clone(),
        binder: super::semantic_identity::policy_location(workspace, source_site)
            .map_err(|error| format!("the binder has no report location: {error}"))?,
        receipt_digest: *record.receipt_id().as_bytes(),
    };
    if crate::finding::admitted_pattern_provenance_is_valid(&provenance) {
        Ok(provenance)
    } else {
        Err("the provenance is outside the report's bounds".to_owned())
    }
}

pub(super) fn project_summary_witness(
    workspace: &WorkspaceAnalyzer,
    witness: &SummaryWitness,
    id: WitnessId,
    max_steps: usize,
    max_bytes: usize,
    labels: impl Fn(&SummaryWitnessStepKind) -> (WitnessStepKind, &'static str),
) -> Result<Option<BoundedWitness>, String> {
    project_summary_witness_with_source(
        workspace, None, witness, id, max_steps, max_bytes, None, labels,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn project_summary_witness_with_source(
    workspace: &WorkspaceAnalyzer,
    provenance: Option<&PatternProvenance<'_>>,
    witness: &SummaryWitness,
    id: WitnessId,
    max_steps: usize,
    max_bytes: usize,
    source_site: Option<&SemanticLocator>,
    labels: impl Fn(&SummaryWitnessStepKind) -> (WitnessStepKind, &'static str),
) -> Result<Option<BoundedWitness>, String> {
    let steps = project_summary_witness_steps_with_source(
        workspace,
        provenance,
        witness,
        &id,
        max_steps,
        max_bytes,
        source_site,
        labels,
    )?;
    if steps.is_empty() {
        return Ok(None);
    }
    let omitted = witness
        .omitted_steps_lower_bound()
        .saturating_add(witness.steps().len().saturating_sub(steps.len()));
    BoundedWitness::try_new(
        id,
        steps,
        omitted > 0,
        u64::try_from(omitted).unwrap_or(u64::MAX),
    )
    .map(Some)
    .map_err(|error| error.to_string())
}

pub(super) fn project_summary_witness_steps(
    workspace: &WorkspaceAnalyzer,
    witness: &SummaryWitness,
    id: &WitnessId,
    max_steps: usize,
    max_bytes: usize,
    labels: impl Fn(&SummaryWitnessStepKind) -> (WitnessStepKind, &'static str),
) -> Result<Vec<WitnessStep>, String> {
    project_summary_witness_steps_with_source(
        workspace, None, witness, id, max_steps, max_bytes, None, labels,
    )
}

#[allow(clippy::too_many_arguments)]
fn project_summary_witness_steps_with_source(
    workspace: &WorkspaceAnalyzer,
    provenance: Option<&PatternProvenance<'_>>,
    witness: &SummaryWitness,
    id: &WitnessId,
    max_steps: usize,
    max_bytes: usize,
    source_site: Option<&SemanticLocator>,
    labels: impl Fn(&SummaryWitnessStepKind) -> (WitnessStepKind, &'static str),
) -> Result<Vec<WitnessStep>, String> {
    let mut steps = Vec::new();
    let admitted = match (provenance, source_site) {
        (Some(provenance), Some(site)) => provenance.lookup(workspace, site)?,
        _ => None,
    };
    for step in witness.steps().iter().take(max_steps) {
        let (kind, label) = labels(&step.kind());
        let locator = if step.kind() == SummaryWitnessStepKind::Seed {
            // The plan admitted this binder, so its site is the source even
            // when the provenance could not be rebuilt.
            source_site
                .unwrap_or_else(|| super::semantic_identity::program_point_locator(step.source()))
        } else {
            step.receiver_operand()
                .unwrap_or_else(|| super::semantic_identity::program_point_locator(step.source()))
        };
        steps.push(
            WitnessStep::try_new_with_provenance(
                kind,
                Some(super::semantic_identity::policy_location(
                    workspace, locator,
                )?),
                label,
                Vec::new(),
                if step.kind() == SummaryWitnessStepKind::Seed {
                    admitted.clone()
                } else {
                    step.summary()
                        .map(|summary| WitnessStepProvenance::ProcedureSummary {
                            fingerprint: summary.fingerprint().to_string(),
                        })
                },
            )
            .map_err(|error| error.to_string())?,
        );
        let candidate = BoundedWitness::try_new(id.clone(), steps.clone(), true, 1)
            .map_err(|error| error.to_string())?;
        if usize::try_from(candidate.retained_bytes()).unwrap_or(usize::MAX) > max_bytes {
            steps.pop();
            break;
        }
    }
    Ok(steps)
}

pub(super) fn project_output_witness(
    workspace: &WorkspaceAnalyzer,
    provenance: &PatternProvenance<'_>,
    witness: &OutputWitnessRow,
    id: WitnessId,
    max_steps: usize,
    max_bytes: usize,
    source_site: Option<&SemanticLocator>,
) -> Result<Option<BoundedWitness>, String> {
    let mut steps = Vec::new();
    let admitted = source_site
        .map(|site| provenance.lookup(workspace, site))
        .transpose()?
        .flatten();
    for step in witness.steps.iter().take(max_steps) {
        let (kind, label) = if step.kind == "seed" {
            (WitnessStepKind::Source, "taint source")
        } else if step.kind.starts_with("end_summary_gap:") {
            (WitnessStepKind::Return, "taint summary boundary")
        } else if step.kind == "edge:modeled_receiver" {
            (WitnessStepKind::Propagation, "receiver operand")
        } else {
            debug_assert!(step.kind.starts_with("edge:"));
            (WitnessStepKind::Propagation, "taint propagation")
        };
        let source = if let Some(site) = source_site.filter(|_| step.kind == "seed") {
            site.clone()
        } else {
            step.modeled_receiver_operand()
                .unwrap_or(&step.source)
                .clone()
                .decode()
                .map_err(|error| format!("{error:?}"))?
        };
        steps.push(
            WitnessStep::try_new_with_provenance(
                kind,
                Some(super::semantic_identity::policy_location(
                    workspace, &source,
                )?),
                label,
                Vec::new(),
                if step.kind == "seed" {
                    admitted.clone()
                } else {
                    step.summary_fingerprint.as_ref().map(|fingerprint| {
                        WitnessStepProvenance::ProcedureSummary {
                            fingerprint: fingerprint.clone(),
                        }
                    })
                },
            )
            .map_err(|error| error.to_string())?,
        );
        let candidate = BoundedWitness::try_new(id.clone(), steps.clone(), true, 1)
            .map_err(|error| error.to_string())?;
        if usize::try_from(candidate.retained_bytes()).unwrap_or(usize::MAX) > max_bytes {
            steps.pop();
            break;
        }
    }
    if steps.is_empty() {
        return Ok(None);
    }
    let omitted = witness
        .omitted_steps_lower_bound
        .saturating_add(witness.steps.len().saturating_sub(steps.len()));
    BoundedWitness::try_new(
        id,
        steps,
        omitted > 0,
        u64::try_from(omitted).unwrap_or(u64::MAX),
    )
    .map(Some)
    .map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::AnalyzerConfig;
    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticWork;

    const POEM_PACK: &str = include_str!(
        "../../bifrost-rql/src/structural/search/tests/fixtures/rust-poem-g3-test-only.json"
    );
    pub(crate) const CARGO: &str =
        "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n";

    pub(crate) fn workspace(
        files: &[(&str, &str)],
    ) -> (
        crate::inline_project::BuiltInlineTestProject,
        WorkspaceAnalyzer,
    ) {
        let mut builder = InlineTestProject::new();
        for (path, text) in files {
            builder = builder.file(*path, *text);
        }
        let project = builder.build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("workspace");
        (project, workspace)
    }

    fn first_procedure(workspace: &WorkspaceAnalyzer, path: &str) -> SemanticLocator {
        let file = ProjectFile::new(workspace.analyzer().project().root(), path);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        workspace
            .materialize_program_semantics(&file, &mut request)
            .expect("semantic materialization")
            .available_value()
            .expect("semantic artifact")
            .procedures()
            .first()
            .expect("one procedure")
            .locator()
            .clone()
    }

    /// The first guarded pattern binder of `path`, as the witness source site.
    fn first_binder(workspace: &WorkspaceAnalyzer, path: &str) -> SemanticLocator {
        all_binders(workspace, path).remove(0)
    }

    /// Every guarded pattern binder of `path`, as witness source sites.
    fn all_binders(workspace: &WorkspaceAnalyzer, path: &str) -> Vec<SemanticLocator> {
        let file = ProjectFile::new(workspace.analyzer().project().root(), path);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let outcome = workspace
            .materialize_program_semantics(&file, &mut request)
            .expect("semantic materialization");
        let artifact = outcome.available_value().expect("semantic artifact");
        let sites: Vec<SemanticLocator> = artifact
            .procedures()
            .iter()
            .flat_map(|procedure| {
                procedure
                    .guarded_pattern_projections()
                    .iter()
                    .filter_map(|candidate| procedure.source_mapping(candidate.binder_source))
                    .map(|mapping| mapping.locator.clone())
            })
            .collect();
        assert!(!sites.is_empty(), "a procedure with a pattern binder");
        sites
    }

    pub(crate) fn activate_poem_pack(
        workspace: &WorkspaceAnalyzer,
    ) -> std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot>
    {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
            SemanticModelActivationRequest, SemanticModelRuntimeLimits,
            SemanticModelRuntimeOutcome, SemanticPackCatalog, SessionPackSource,
            SessionPackSourceKind, SourceFormat, acquire_active_semantic_models, compile_source,
        };
        let pack = compile_source(
            SourceFormat::Json,
            POEM_PACK.as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("Poem test pack compiles: {diagnostics:#?}"));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:witness-provenance".to_owned(),
                },
            )
            .expect("register Poem test pack");
        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: env!("CARGO_PKG_VERSION").parse().expect("version"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "rust".to_owned(),
                    ecosystem: "cargo".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        match activation {
            SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
            other => panic!("Poem test pack activates: {other:#?}"),
        }
    }

    fn reads_digest(workspace: &WorkspaceAnalyzer, run: impl FnOnce()) -> [u8; 32] {
        let ((), receipt) = QueryReadReceipt::capture(workspace.analyzer(), run);
        *receipt.digest().as_bytes()
    }

    #[test]
    fn only_a_rust_source_site_reads_for_pattern_provenance() {
        let (_project, workspace) = workspace(&[
            ("app.py", "def handler(value):\n    return value\n"),
            ("Cargo.toml", CARGO),
            ("src/lib.rs", "pub fn handler() {}\n"),
        ]);
        let python = first_procedure(&workspace, "app.py");
        let rust = first_procedure(&workspace, "src/lib.rs");
        let no_reads = reads_digest(&workspace, || ());
        let lookup = |site: &SemanticLocator| {
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let mut found = None;
            let digest = reads_digest(&workspace, || {
                found = Some(
                    admitted_pattern_provenance(
                        &workspace,
                        site,
                        &cancellation,
                        &mut budget,
                        &RefCell::new(HashMap::new()),
                    )
                    .expect("lookup"),
                );
            });
            (digest, found.expect("lookup ran"))
        };

        let (python_reads, python_found) = lookup(&python);
        assert!(python_found.is_err());
        assert_eq!(python_reads, no_reads, "a Python source performs no reads");

        let (rust_reads, rust_found) = lookup(&rust);
        assert!(rust_found.is_err());
        assert_ne!(rust_reads, no_reads, "a Rust source is looked up");
    }

    #[test]
    fn a_cancelled_run_stops_pattern_provenance() {
        let (_project, workspace) = workspace(&[
            ("Cargo.toml", CARGO),
            ("src/lib.rs", "pub fn handler() {}\n"),
        ]);
        let site = first_procedure(&workspace, "src/lib.rs");
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&cancelled, &mut budget);
        let error = context
            .lookup(&workspace, &site)
            .expect_err("a cancelled run must not project");
        assert!(error.contains("cancelled"), "{error}");
    }

    #[test]
    fn an_admitted_binder_is_memoized_and_a_stopped_lookup_is_not() {
        let source =
            "use poem::web::Query;\npub fn handler(Query(name): Query<String>) { let _ = name; }\n";
        let (_project, workspace) = workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", source)]);
        let snapshot = activate_poem_pack(&workspace);
        let _scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
        let site = first_binder(&workspace, "src/lib.rs");
        let no_reads = reads_digest(&workspace, || ());

        // The first lookup proves the admission; the second is the memo.
        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&live, &mut budget);
        let mut first = None;
        let first_reads = reads_digest(&workspace, || {
            first = Some(context.lookup(&workspace, &site).expect("first lookup"));
        });
        assert!(
            matches!(
                first,
                Some(Some(
                    WitnessStepProvenance::AdmittedPatternProjection { .. }
                ))
            ),
            "{first:?}"
        );
        assert_ne!(first_reads, no_reads, "the first lookup reads");
        assert!(!context.take_unavailable());
        let second_reads = reads_digest(&workspace, || {
            assert!(context.lookup(&workspace, &site).expect("memo").is_some());
        });
        assert_eq!(second_reads, no_reads, "the second lookup is the memo");
        drop(context);

        // A budget stop is "unavailable", flagged, and never memoized: the next
        // lookup under a live budget still proves the admission.
        let (_other_project, other) =
            self::workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", source)]);
        let other_snapshot = activate_poem_pack(&other);
        let _other_scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                other.analyzer(),
                Some(other_snapshot),
            );
        let mut limits = SemanticWork::default_limits();
        limits.source_bytes = 1;
        let mut tiny = SemanticBudget::new(limits).expect("a one-byte source budget");
        let stopped = PatternProvenance::new(&live, &mut tiny);
        assert!(stopped.lookup(&other, &site).expect("lookup").is_none());
        assert!(stopped.take_unavailable(), "a budget stop must be flagged");
        assert!(!stopped.take_unavailable(), "the flag is taken once");
        assert!(stopped.memo.borrow().is_empty(), "a stop is not memoized");
    }

    #[test]
    fn every_handler_of_a_file_shares_one_binder_index() {
        let mut source = String::from("use poem::web::Query;\n");
        for index in 0..4 {
            source.push_str(&format!(
                "pub fn handler{index}(Query(name): Query<String>) {{ let _ = name; }}\n"
            ));
        }
        let (_project, workspace) = workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", &source)]);
        let snapshot = activate_poem_pack(&workspace);
        let _scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
        let sites = all_binders(&workspace, "src/lib.rs");
        assert_eq!(sites.len(), 4, "one binder per handler: {sites:?}");

        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&live, &mut budget);
        let before = BINDER_INDEX_BUILDS.with(Cell::get);
        for site in &sites {
            assert!(
                matches!(
                    context.lookup(&workspace, site),
                    Ok(Some(
                        WitnessStepProvenance::AdmittedPatternProjection { .. }
                    ))
                ),
                "{site:?}"
            );
        }
        assert_eq!(
            BINDER_INDEX_BUILDS.with(Cell::get) - before,
            1,
            "four distinct binders of one file index its binders once"
        );
        assert!(!context.take_unavailable());
    }

    #[test]
    fn an_indexed_file_does_not_pin_its_artifact() {
        let handlers = |prefix: &str| {
            let mut source = String::from("use poem::web::Query;\n");
            for index in 0..2 {
                source.push_str(&format!(
                    "pub fn {prefix}{index}(Query(name): Query<String>) {{ let _ = name; }}\n"
                ));
            }
            source
        };
        let (first, second) = (handlers("a"), handlers("b"));
        let (_project, workspace) = workspace(&[
            ("Cargo.toml", CARGO),
            ("src/lib.rs", &format!("mod other;\n{first}")),
            ("src/other.rs", &second),
        ]);
        let snapshot = activate_poem_pack(&workspace);
        let _scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
        let held_by = |path: &str| {
            let file = ProjectFile::new(workspace.analyzer().project().root(), path);
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let mut request = SemanticRequest::new(&mut budget, &cancellation);
            let outcome = workspace
                .materialize_program_semantics(&file, &mut request)
                .expect("materialization");
            // The count includes the one this call holds.
            Arc::strong_count(outcome.available_value().expect("artifact"))
        };
        let before = (held_by("src/lib.rs"), held_by("src/other.rs"));

        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&live, &mut budget);
        let builds = BINDER_INDEX_BUILDS.with(Cell::get);
        for site in all_binders(&workspace, "src/lib.rs")
            .iter()
            .chain(&all_binders(&workspace, "src/other.rs"))
        {
            assert!(
                matches!(context.lookup(&workspace, site), Ok(Some(_))),
                "{site:?}"
            );
        }
        assert_eq!(
            BINDER_INDEX_BUILDS.with(Cell::get) - builds,
            2,
            "each file is indexed once"
        );
        assert_eq!(
            (held_by("src/lib.rs"), held_by("src/other.rs")),
            before,
            "the context keeps no reference to an artifact it indexed"
        );
    }

    #[test]
    fn a_stopped_lookup_keeps_the_admitted_binder_as_the_source_location() {
        use brokk_bifrost_flow::taint::output_product::{
            OutputCompletenessRow, OutputLocatorRow, OutputProofRow, OutputWitnessRow,
            OutputWitnessStepRow, OutputWitnessStepState,
        };
        let source =
            "use poem::web::Query;\npub fn handler(Query(name): Query<String>) { let _ = name; }\n";
        let (_project, workspace) = workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", source)]);
        let snapshot = activate_poem_pack(&workspace);
        let _scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
        let binder = first_binder(&workspace, "src/lib.rs");
        let enclosing = first_procedure(&workspace, "src/lib.rs");
        assert_ne!(binder, enclosing);
        let seed = OutputWitnessStepRow {
            kind: "seed".to_owned(),
            summary_fingerprint: None,
            typed: OutputWitnessStepState::None,
            source: OutputLocatorRow::encode(&enclosing),
            source_point: 0,
            target: None,
            target_point: None,
            origin: None,
            boundary: None,
            proof: OutputProofRow::Proven,
            completeness: OutputCompletenessRow::Complete,
            input_fact: 0,
            output_fact: 0,
        };
        let row = OutputWitnessRow {
            proven: true,
            complete: true,
            steps: vec![seed],
            truncation_cause: None,
            omitted_steps_lower_bound: 0,
            alternatives_truncated: false,
            retained_bytes: 0,
            evidence_expansions: 0,
        };

        // A budget that stops the provenance lookup must not move the source
        // to the enclosing program point the compile did not key it by.
        // A fresh workspace, so the file's artifact is not already cached and
        // the budget is charged.
        let (_other_project, other) =
            self::workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", source)]);
        let other_snapshot = activate_poem_pack(&other);
        let _other_scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                other.analyzer(),
                Some(other_snapshot),
            );
        let live = CancellationToken::default();
        let mut limits = SemanticWork::default_limits();
        limits.source_bytes = 1;
        let mut tiny = SemanticBudget::new(limits).expect("a one-byte source budget");
        let context = PatternProvenance::new(&live, &mut tiny);
        let projected = project_output_witness(
            &other,
            &context,
            &row,
            WitnessId::try_new("bifrost", "stopped").expect("witness id"),
            8,
            1 << 20,
            Some(&binder),
        )
        .expect("projection")
        .expect("a witness");
        assert!(context.take_unavailable(), "the lookup was stopped");
        let [step] = projected.steps() else {
            panic!("one seed step: {projected:?}");
        };
        assert!(step.provenance().is_none(), "no provenance was rebuilt");
        assert_eq!(
            step.location(),
            Some(&super::super::semantic_identity::policy_location(&other, &binder).unwrap()),
            "the source stays at the admitted binder"
        );
    }

    #[test]
    fn an_import_chain_is_bounded_without_losing_its_declaration() {
        let chain = vec![
            "Q".to_owned(),
            "poem.web.Query".to_owned(),
            "poem.web.query.Query".to_owned(),
        ];
        assert_eq!(bound_import_chain(&chain), (chain.clone(), false));

        let long = "é".repeat(100);
        let chain = vec![long, "poem.web.query.Query".to_owned()];
        let (bounded, truncated) = bound_import_chain(&chain);
        assert!(truncated);
        assert!(bounded[0].len() <= 128 && bounded[0].chars().all(|c| c == 'é'));
        assert_eq!(bounded[1], "poem.web.query.Query");

        let many = (0..12)
            .map(|index| format!("hop{index}"))
            .collect::<Vec<_>>();
        let (bounded, truncated) = bound_import_chain(&many);
        assert!(truncated && bounded.len() == 8);
        assert_eq!(bounded.last(), many.last(), "the declaration stays last");
    }

    fn provenance_with(
        record_id: String,
        constructor: &str,
        field_id: String,
        chain: Vec<String>,
    ) -> WitnessStepProvenance {
        use crate::{PolicyByteSpan, PolicyDisplayRegion, PolicySourceLocation};
        use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
        WitnessStepProvenance::AdmittedPatternProjection {
            pack_digest: "0".repeat(64),
            record_id,
            constructor: constructor.to_owned(),
            import_chain: chain,
            import_chain_truncated: false,
            import_route_complete: true,
            position: 0,
            layout_arity: 1,
            field_id,
            binder: PolicySourceLocation::span(
                WorkspaceRelativePath::new("src/lib.rs").unwrap(),
                PolicyByteSpan::new(1, 2).unwrap(),
                PolicyDisplayRegion::new(1, 2, 1, 3).unwrap(),
            ),
            receipt_digest: [7; 32],
        }
    }

    #[test]
    fn every_pack_valid_declaration_id_is_reportable() {
        use crate::finding::admitted_pattern_provenance_is_valid as valid;
        use brokk_bifrost_analysis::analyzer::semantic_model::MAX_STABLE_ID_BYTES;
        let chain = |last: &str| vec!["Q".to_owned(), last.to_owned()];
        let long = "a".repeat(MAX_STABLE_ID_BYTES);
        // A declaration identifier at the pack format's limit is carried whole.
        assert!(valid(&provenance_with(
            long.clone(),
            &long,
            long.clone(),
            chain(&long)
        )));
        // A qualified declaration name is bounded as pack text, not as a stable
        // ID, so a kilobyte-long one is reportable too.
        let name = "q".repeat(1_024);
        assert!(valid(&provenance_with(
            "r".to_owned(),
            &name,
            "f".to_owned(),
            chain(&name)
        )));
        // Past the pack's own limit, or empty, it is not provenance.
        let too_long = "a".repeat(MAX_STABLE_ID_BYTES + 1);
        assert!(!valid(&provenance_with(
            too_long.clone(),
            "c",
            "f".to_owned(),
            chain("c")
        )));
        assert!(!valid(&provenance_with(
            "r".to_owned(),
            "c",
            String::new(),
            chain("c")
        )));
        // A written route entry before the declaration keeps the report's
        // shorter limit; the producer shortens it first.
        let written = vec!["w".repeat(129), "c".to_owned()];
        assert!(!valid(&provenance_with(
            "r".to_owned(),
            "c",
            "f".to_owned(),
            written
        )));
        let (bounded, truncated) = bound_import_chain(&["w".repeat(129), "c".to_owned()]);
        assert!(truncated);
        assert!(valid(&provenance_with(
            "r".to_owned(),
            "c",
            "f".to_owned(),
            bounded
        )));
    }

    #[test]
    fn two_records_for_one_site_are_ambiguous_and_give_no_provenance() {
        let source =
            "use poem::web::Query;\npub fn handler(Query(name): Query<String>) { let _ = name; }\n";
        let (_project, workspace) = workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", source)]);
        let snapshot = activate_poem_pack(&workspace);
        let _scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
        let site = first_binder(&workspace, "src/lib.rs");
        let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let outcome = workspace
            .materialize_program_semantics(&file, &mut request)
            .expect("materialization");
        let artifact = outcome.available_value().expect("artifact");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.guarded_pattern_projections().is_empty())
            .expect("pattern procedure");
        let handle = artifact.procedure_handle(procedure.id()).expect("handle");
        let selected = WorkspaceSemanticOracle::new(&workspace)
            .selected_pattern_projections_where(&handle, &mut request, |_| true)
            .expect("selection")
            .expect("not cancelled");
        let record = &selected[0];

        assert!(provenance_from_records(&workspace, &site, [record]).is_ok());
        assert!(
            provenance_from_records(&workspace, &site, [record, record]).is_err(),
            "two records for one site must not pick one"
        );
        assert!(provenance_from_records(&workspace, &site, []).is_err());
    }

    #[test]
    fn a_stopped_source_marks_the_finding_without_any_retained_witness() {
        let (_project, workspace) = workspace(&[
            ("Cargo.toml", CARGO),
            ("src/lib.rs", "pub fn handler() {}\npub fn other() {}\n"),
        ]);
        let procedures = {
            let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let mut request = SemanticRequest::new(&mut budget, &cancellation);
            let outcome = workspace
                .materialize_program_semantics(&file, &mut request)
                .expect("materialization");
            outcome
                .available_value()
                .expect("artifact")
                .procedures()
                .iter()
                .map(|procedure| procedure.locator().clone())
                .collect::<Vec<_>>()
        };
        let [stopped_site, other_site] = procedures.as_slice() else {
            panic!("two procedures");
        };
        let stopped = [(
            stopped_site.clone(),
            "formal type exceeds the alias budget".to_owned(),
        )];
        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&live, &mut budget);

        // No witness is involved: the finding's origin sites alone decide.
        context.note_stopped_sources([other_site], &stopped);
        assert!(!context.take_unavailable());
        context.note_stopped_sources([other_site, stopped_site], &stopped);
        assert!(context.take_unavailable());
        assert!(!context.take_unavailable(), "taken once");
        context.note_stopped_sources(std::iter::empty(), &stopped);
        assert!(!context.take_unavailable());
        // The stop's reason is kept for the run's diagnostic, bounded and once.
        context.note_stopped_sources([stopped_site, stopped_site], &stopped);
        assert_eq!(
            context.take_reasons(),
            ["formal type exceeds the alias budget"]
        );
    }

    #[test]
    fn a_re_exported_constructor_is_incomplete_without_being_shortened() {
        let source = "mod web { pub use poem::web::Query as PoemQuery; }\nuse crate::web::PoemQuery;\n\
             pub fn handler(PoemQuery(name): PoemQuery<String>) { let _ = name; }\n";
        let (_project, workspace) = workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", source)]);
        let snapshot = activate_poem_pack(&workspace);
        let _scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
        let site = first_binder(&workspace, "src/lib.rs");
        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&live, &mut budget);
        let Some(WitnessStepProvenance::AdmittedPatternProjection {
            import_chain,
            import_chain_truncated,
            import_route_complete,
            ..
        }) = context.lookup(&workspace, &site).expect("lookup")
        else {
            panic!("a re-exported constructor still carries provenance");
        };
        assert!(
            import_chain
                .iter()
                .any(|hop| hop == "crate::web::PoemQuery")
        );
        assert!(!import_chain_truncated, "nothing was shortened");
        assert!(
            !import_route_complete,
            "the re-export's inner hops are not shown"
        );
    }

    #[test]
    fn a_provider_error_is_kept_as_the_reason_the_finding_is_partial() {
        // A site found in one workspace, looked up in another whose source file
        // is gone: the provider cannot materialize it.
        let source =
            "use poem::web::Query;\npub fn handler(Query(name): Query<String>) { let _ = name; }\n";
        let (_project, workspace) = workspace(&[("Cargo.toml", CARGO), ("src/lib.rs", source)]);
        let site = first_binder(&workspace, "src/lib.rs");
        let (_empty_project, empty) = workspace_without_sources();
        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&live, &mut budget);
        assert!(
            context
                .lookup(&empty, &site)
                .expect("no cancellation")
                .is_none()
        );
        assert!(context.take_unavailable());
        let reasons = context.take_reasons();
        let [reason] = reasons.as_slice() else {
            panic!("one reason: {reasons:?}");
        };
        assert!(!reason.is_empty() && reason.len() <= 256, "{reason}");
        assert!(
            reason.contains("provider failed") || reason.contains("unavailable"),
            "the reason names what failed: {reason}"
        );
    }

    fn workspace_without_sources() -> (
        crate::inline_project::BuiltInlineTestProject,
        WorkspaceAnalyzer,
    ) {
        workspace(&[("Cargo.toml", CARGO)])
    }

    #[test]
    fn reasons_are_bounded_in_number_and_length() {
        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let context = PatternProvenance::new(&live, &mut budget);
        for index in 0..20 {
            context.record_reason(&format!("{index}{}", "é".repeat(400)));
        }
        let reasons = context.take_reasons();
        assert_eq!(reasons.len(), 8);
        assert!(reasons.iter().all(|reason| reason.len() <= 256));
    }
}
