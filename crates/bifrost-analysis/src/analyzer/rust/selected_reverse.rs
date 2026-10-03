//! Selected Rust caller queries with demand-driven resolution and exact proofs.

use super::RustAnalyzer;
use super::selected_projection::{RustSelectedReferenceFile, rust_selected_usage_kind};
use crate::CancellationToken;
use crate::analyzer::resolution::ResolutionCompletion;
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
    SelectedRustReverseBatchOutcome, SelectedRustReverseQueries, SelectedRustTargetReferences,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::store::{Result, StoreError};
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, EdgeSite, ReferenceEdgeRow,
    classify_owner_relation,
};
use crate::analyzer::structural::{EdgeProvenance, SiteClass};
use crate::analyzer::usages::UsageProof;
use crate::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};

#[derive(Debug)]
pub enum RustSelectedReverseOutcome<T> {
    Ready(T),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

/// Diagnostic work after selected context construction. This is not total
/// operation work: topology, prefixes, SQL and file admission are not measured.
/// Source paths record successful materialization, not failed read attempts.
/// Target metrics cover returned answers; unfinished target evaluation is not
/// represented by an invented zero-work answer.
#[cfg(test)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RustSelectedReverseWork {
    pub(crate) targets: Vec<(
        CodeUnit,
        crate::analyzer::resolution::FactReverseResolutionMetrics,
    )>,
    pub(crate) definition_mount_reads: usize,
    pub(crate) classification_sources: Vec<ProjectFile>,
}

pub trait RustSelectedReverseQueries {
    fn candidate_files(&mut self, targets: &[CodeUnit]) -> Result<Option<HashSet<ProjectFile>>>;
    /// Query one frontier batch. None is an operational stop, whose typed
    /// reason is retained by the enclosing selected operation.
    fn inverse_for(&mut self, targets: &[CodeUnit]) -> Result<Option<Vec<EdgeDerivationResult>>>;

    #[cfg(test)]
    fn work_report(&self) -> RustSelectedReverseWork;

    #[cfg(test)]
    fn begin_sql_work_trace(&self);

    #[cfg(test)]
    fn finish_sql_work_trace(&self) -> (usize, usize);

    fn incoming_calls_for(
        &mut self,
        targets: &[CodeUnit],
        limits: crate::analyzer::usages::call_relations::CallRelationLimits,
    ) -> Result<Option<Vec<crate::analyzer::usages::call_relations::CallRelationResult>>>;
}

struct RustReverseProjection<'query, 'analyzer> {
    rust: &'analyzer RustAnalyzer,
    queries: &'query mut dyn SelectedRustReverseQueries,
    cancellation: &'query CancellationToken,
    generation: u64,
    files: HashMap<ProjectFile, RustSelectedReferenceFile<'analyzer>>,
    #[cfg(test)]
    work: RustSelectedReverseWork,
}

impl RustSelectedReverseQueries for RustReverseProjection<'_, '_> {
    fn candidate_files(&mut self, targets: &[CodeUnit]) -> Result<Option<HashSet<ProjectFile>>> {
        self.queries.candidate_files(targets)
    }
    #[cfg(test)]
    fn work_report(&self) -> RustSelectedReverseWork {
        RustSelectedReverseWork {
            definition_mount_reads: self.queries.definition_mount_read_count(),
            ..self.work.clone()
        }
    }

    #[cfg(test)]
    fn begin_sql_work_trace(&self) {
        self.queries.begin_sql_work_trace();
    }

    #[cfg(test)]
    fn finish_sql_work_trace(&self) -> (usize, usize) {
        self.queries.finish_sql_work_trace()
    }

    fn incoming_calls_for(
        &mut self,
        targets: &[CodeUnit],
        limits: crate::analyzer::usages::call_relations::CallRelationLimits,
    ) -> Result<Option<Vec<crate::analyzer::usages::call_relations::CallRelationResult>>> {
        let answers = match self.queries.references_to(targets)? {
            SelectedRustReverseBatchOutcome::Ready(answers) => answers,
            SelectedRustReverseBatchOutcome::Unavailable(_)
            | SelectedRustReverseBatchOutcome::Cancelled => return Ok(None),
        };
        let mut results = Vec::with_capacity(answers.len());
        for answer in answers {
            let target = answer.target.clone();
            let mut references = Vec::new();
            let rows = self.project_references(answer, |reference| references.push(reference))?;
            let Some(result) = super::native_call_projection::project_rust_rich_call_relation(
                self.rust,
                &target,
                &rows,
                &references,
                self.queries,
                limits,
                self.cancellation,
            )?
            else {
                return Ok(None);
            };
            results.push(result);
        }
        Ok(Some(results))
    }

    fn inverse_for(&mut self, targets: &[CodeUnit]) -> Result<Option<Vec<EdgeDerivationResult>>> {
        let answers = match self.queries.references_to(targets)? {
            SelectedRustReverseBatchOutcome::Ready(answers) => answers,
            SelectedRustReverseBatchOutcome::Unavailable(_)
            | SelectedRustReverseBatchOutcome::Cancelled => return Ok(None),
        };
        let mut results = Vec::with_capacity(answers.len());
        for answer in answers {
            if self.cancellation.is_cancelled() {
                return Ok(None);
            }
            results.push(self.project(answer)?);
        }
        // File classifiers belong to this frontier request, including their
        // structural snapshots and interval indexes. Adaptive callers retain
        // projected edges, not the classifiers of previous frontiers.
        self.files = HashMap::default();
        Ok(Some(results))
    }
}

impl RustReverseProjection<'_, '_> {
    fn project(&mut self, answer: SelectedRustTargetReferences) -> Result<EdgeDerivationResult> {
        self.project_references(answer, |_| {})
    }

    fn project_references(
        &mut self,
        answer: SelectedRustTargetReferences,
        mut retain_reference: impl FnMut(crate::analyzer::resolution::SemanticId),
    ) -> Result<EdgeDerivationResult> {
        #[cfg(test)]
        self.work
            .targets
            .push((answer.target.clone(), answer.metrics));
        debug_assert_eq!(
            answer.metrics.published_reference_count(),
            answer.search.source_sites().len(),
            "reverse source projection must preserve every published reference"
        );
        let bindings = answer
            .bindings
            .iter()
            .map(|binding| (binding.reference(), binding))
            .collect::<HashMap<_, _>>();
        let mut reasons = Vec::new();
        // `InverseIndexResolutionIncomplete` says the site inventory may be
        // missing sites; it does not say that an enumerated site is undecided.
        // The search completion is exactly the inventory's gaps: a blob whose
        // references could not be enumerated, a candidate site dropped by an
        // owned forward rejection, a budget stop before every blob was
        // confirmed. A site that was enumerated and attributed publishes its
        // own doubt through its row's `proof`, so an incomplete binding on a
        // retained site leaves the inventory complete and the site unproven.
        if answer.search.completion() != &ResolutionCompletion::Complete {
            reasons.push(EdgeIncompleteReason::InverseIndexResolutionIncomplete);
            if matches!(
                answer.search.completion(),
                ResolutionCompletion::Incomplete(completion_reasons)
                    if completion_reasons.iter().any(|reason| matches!(
                        reason,
                        crate::analyzer::resolution::ResolutionIncompleteReason::TimeBudgetExceeded(_)
                    ))
            ) {
                reasons.push(EdgeIncompleteReason::TimeBudgetExceeded);
            }
        }
        let mut edges = Vec::with_capacity(answer.search.source_sites().len());
        for site in answer.search.source_sites() {
            if self.cancellation.is_cancelled() {
                break;
            }
            let binding = bindings.get(&site.reference()).ok_or_else(|| {
                StoreError::new(format!(
                    "selected reverse site {} has no forward binding evidence",
                    site.reference()
                ))
            })?;
            let Some(metadata) = site.metadata() else {
                if !reasons.contains(&EdgeIncompleteReason::InverseIndexMetadataIncomplete) {
                    reasons.push(EdgeIncompleteReason::InverseIndexMetadataIncomplete);
                }
                continue;
            };
            let enclosing = match site.enclosing() {
                Some(owner) => owner.cloned(),
                None => {
                    if !reasons.contains(&EdgeIncompleteReason::InverseIndexMetadataIncomplete) {
                        reasons.push(EdgeIncompleteReason::InverseIndexMetadataIncomplete);
                    }
                    None
                }
            };
            if !self.files.contains_key(site.file()) {
                let source = self.rust.indexed_source(site.file()).ok_or_else(|| {
                    StoreError::new(format!(
                        "selected Rust reverse site has no indexed source for {:?}",
                        site.file()
                    ))
                })?;
                #[cfg(test)]
                self.work.classification_sources.push(site.file().clone());
                self.files.insert(
                    site.file().clone(),
                    RustSelectedReferenceFile::new(self.rust, site.file(), &source),
                );
            }
            let file = self
                .files
                .get(site.file())
                .expect("selected reference file was installed");
            let owner_relation =
                classify_owner_relation(self.rust, enclosing.as_ref(), &answer.target);
            let reference_kind = if binding.type_identity_observation() {
                Some(crate::analyzer::usages::ReferenceKind::SelfTypeAlias)
            } else {
                file.classifier.as_ref().and_then(|classifier| {
                    classifier.classify_reference_kind(
                        metadata.start_byte(),
                        metadata.end_byte(),
                        &answer.target,
                    )
                })
            };
            let ast_id = file.classifier.as_ref().and_then(|classifier| {
                classifier.ast_id(metadata.start_byte(), metadata.end_byte())
            });
            retain_reference(site.reference());
            edges.push(ReferenceEdgeRow {
                site: EdgeSite {
                    file: site.file().clone(),
                    range: file.range(metadata.start_byte(), metadata.end_byte()),
                    ast_id,
                    enclosing,
                },
                target: answer.target.clone(),
                reference_kind,
                proof: if (binding.definitions().len() == 1
                    || (binding.type_bound_receiver() && !binding.definitions().is_empty()))
                    && binding.completion() == &ResolutionCompletion::Complete
                {
                    UsageProof::Proven
                } else {
                    UsageProof::Unproven
                },
                usage_kind: rust_selected_usage_kind(metadata, owner_relation, &answer.target),
                site_class: SiteClass::UseSite,
                owner_relation,
                provenance: EdgeProvenance::Inverse,
                generation: self.generation,
            });
        }
        Ok(EdgeDerivationResult {
            edges,
            completeness: if reasons.is_empty() {
                EdgeCompleteness::Complete
            } else {
                EdgeCompleteness::Incomplete { reasons }
            },
            provenance: EdgeProvenance::Inverse,
            generation: self.generation,
        })
    }
}

/// Stage an adaptive reverse consumer inside one selected operation. The
/// callback must return its staged result; only Ready authorizes its use.
pub fn with_rust_selected_reverse_queries<T>(
    rust: &RustAnalyzer,
    cancellation: &CancellationToken,
    run: impl FnOnce(&mut dyn RustSelectedReverseQueries) -> Result<T>,
) -> RustSelectedReverseOutcome<T> {
    with_rust_selected_reverse_reference_admission(rust, None, cancellation, run)
}

/// Bound result-site discovery to admitted files without removing definitions,
/// imports, or receiver producers in the rest of the selected workspace.
pub(crate) fn with_rust_selected_reverse_queries_in_files<T>(
    rust: &RustAnalyzer,
    admitted_files: &HashSet<ProjectFile>,
    cancellation: &CancellationToken,
    run: impl FnOnce(&mut dyn RustSelectedReverseQueries) -> Result<T>,
) -> RustSelectedReverseOutcome<T> {
    with_rust_selected_reverse_reference_admission(rust, Some(admitted_files), cancellation, run)
}

fn with_rust_selected_reverse_reference_admission<T>(
    rust: &RustAnalyzer,
    admitted_files: Option<&HashSet<ProjectFile>>,
    cancellation: &CancellationToken,
    run: impl FnOnce(&mut dyn RustSelectedReverseQueries) -> Result<T>,
) -> RustSelectedReverseOutcome<T> {
    let _timing = crate::profiling::scope("rust_selected::reverse_queries");
    if cancellation.is_cancelled() {
        return RustSelectedReverseOutcome::Cancelled;
    }
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return RustSelectedReverseOutcome::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return RustSelectedReverseOutcome::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return RustSelectedReverseOutcome::Cancelled;
        }
        Err(error) => return RustSelectedReverseOutcome::StoreError(error.to_string()),
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let open_timing = crate::profiling::scope("rust_selected::reverse_open");
    let operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return RustSelectedReverseOutcome::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return RustSelectedReverseOutcome::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return RustSelectedReverseOutcome::Cancelled;
        }
        Err(error) => return RustSelectedReverseOutcome::StoreError(error.to_string()),
    };
    drop(open_timing);
    let _query_timing = crate::profiling::scope("rust_selected::reverse_frontier_queries");
    let generation = rust.inner.project().analysis_generation();
    let query = |queries: &mut dyn SelectedRustReverseQueries| {
        run(&mut RustReverseProjection {
            rust,
            queries,
            cancellation,
            generation,
            files: HashMap::default(),
            #[cfg(test)]
            work: RustSelectedReverseWork::default(),
        })
    };
    let result = operation.with_rust_row_reverse_queries(
        admitted_files,
        cancellation,
        |root, locators| confirm_rust_reverse_references(rust, root, locators, cancellation),
        query,
    );
    match result {
        Ok(SelectedResolutionOperationOutcome::Native(value)) => {
            RustSelectedReverseOutcome::Ready(value)
        }
        Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
            RustSelectedReverseOutcome::Unavailable(format!("{reason:?}"))
        }
        Ok(SelectedResolutionOperationOutcome::Stale(reason)) => {
            RustSelectedReverseOutcome::Stale(format!("{reason:?}"))
        }
        Ok(SelectedResolutionOperationOutcome::Cancelled(_)) => {
            RustSelectedReverseOutcome::Cancelled
        }
        Err(error) => RustSelectedReverseOutcome::StoreError(error.to_string()),
    }
}

/// Confirm every candidate site of one blob in one point request.
///
/// The sites share a caller file, so they share its macro frontier, crate
/// context, demand inventory and blueprint. One request per blob pays for
/// those once; one request per site paid for them once per site, and opened a
/// selected resolution operation each time.
fn confirm_rust_reverse_references(
    rust: &RustAnalyzer,
    root: &std::path::Path,
    locators: &[&crate::analyzer::resolution::SelectedSemanticLocator],
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::store::resolution_operation::RustReverseConfirmation> {
    use crate::analyzer::store::resolution_operation::{
        RustReverseConfirmation, SelectedResolutionLocated, SelectedRustCallerReferencesOutcome,
    };
    use crate::analyzer::usages::get_definition::BoundedResolution;
    let _timing = crate::profiling::scope("rust_selected::reverse_confirm_blob");
    let open_timing = crate::profiling::scope("rust_selected::reverse_confirm_open");
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
    {
        SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } => (masks, content_mounts),
        SelectedResolutionOverlayInputsOutcome::Cancelled => {
            return Ok(RustReverseConfirmation::Cancelled);
        }
        SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
            return Err(StoreError::new(format!(
                "reverse confirmation unavailable: {reason:?}"
            )));
        }
        SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
            return Err(StoreError::new(format!(
                "reverse confirmation stale: {reason:?}"
            )));
        }
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(RustReverseConfirmation::Cancelled);
        }
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Err(StoreError::new(format!(
                "reverse confirmation unavailable: {reason:?}"
            )));
        }
        SelectedResolutionOperationOpenOutcome::Stale(reason) => {
            return Err(StoreError::new(format!(
                "reverse confirmation stale: {reason:?}"
            )));
        }
    };
    drop(open_timing);
    #[cfg(test)]
    operation.attach_active_reverse_sql_work_trace();
    // Each site keeps the accumulating allowance it had as its own request.
    // Batching sites must change what the reverse pays, not what it is
    // allowed to prove.
    let sites = locators.len().max(1);
    let mut budget =
        brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default();
    budget.max_summary_expansions = budget.max_summary_expansions.saturating_mul(sites);
    budget.max_scope_nodes = budget.max_scope_nodes.saturating_mul(sites);
    let answer = operation.confirm_rust_references_for_caller_bounded(
        root,
        locators,
        budget,
        cancellation,
        &mut SelectedResolutionContextMetrics,
        &mut crate::analyzer::resolution::ResolutionBatchMetrics::default(),
    );
    let answer = answer?;
    match answer {
        BoundedResolution::Cancelled { .. } => Ok(RustReverseConfirmation::Cancelled),
        // The receiver-analysis budget is a bound the analysis declares and
        // enforces, not a store failure. It leaves this candidate blob's sites
        // unproven and says so; the caller keeps every other blob's answers.
        BoundedResolution::Exceeded { .. } => Ok(RustReverseConfirmation::Bounded),
        BoundedResolution::Complete { value, .. } => match value {
            SelectedRustCallerReferencesOutcome::Operation(
                SelectedResolutionOperationOutcome::Native(located),
            ) => located
                .into_iter()
                .map(|located| match located {
                    SelectedResolutionLocated::Found(answers) => Ok(answers),
                    SelectedResolutionLocated::Missing => Err(StoreError::new(
                        "reverse candidate has no forward reference",
                    )),
                })
                .collect::<Result<Vec<_>>>()
                .map(RustReverseConfirmation::Confirmed),
            SelectedRustCallerReferencesOutcome::Operation(
                SelectedResolutionOperationOutcome::Cancelled(_),
            ) => Ok(RustReverseConfirmation::Cancelled),
            SelectedRustCallerReferencesOutcome::Operation(
                SelectedResolutionOperationOutcome::Unavailable(reason),
            ) => Err(StoreError::new(format!(
                "reverse confirmation unavailable: {reason:?}"
            ))),
            SelectedRustCallerReferencesOutcome::Operation(
                SelectedResolutionOperationOutcome::Stale(reason),
            ) => Err(StoreError::new(format!(
                "reverse confirmation stale: {reason:?}"
            ))),
            SelectedRustCallerReferencesOutcome::UnsupportedCallerProfile => Err(StoreError::new(
                "reverse confirmation caller profile unavailable",
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::{
        reset_selected_fact_operation_construction_count_for_test,
        selected_fact_operation_construction_count_for_test,
    };
    use crate::inline_project::InlineTestProject;

    fn assert_crate_point(files: &[(&str, &str)], caller: &str, start: usize, name: &str) {
        let mut builder = InlineTestProject::with_language(Language::Rust);
        for (path, source) in files {
            builder = builder.file(*path, *source);
        }
        let fixture = builder.build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        assert!(!rust.declarations(&fixture.file(caller)).is_empty());
        let locator = crate::analyzer::resolution::SelectedSemanticLocator::for_reference_range(
            "rust",
            caller,
            start,
            start + name.len(),
        );
        // Production confirmation obtains FILE_CRATES through
        // rust_crate_container_sources and merges rust_crate_context for every key.
        let confirmation = confirm_rust_reverse_references(
            &rust,
            std::path::Path::new(caller),
            &[&locator],
            &CancellationToken::new(),
        )
        .unwrap();
        let crate::analyzer::store::resolution_operation::RustReverseConfirmation::Confirmed(
            mut answers,
        ) = confirmation
        else {
            panic!("point confirmation");
        };
        let answers = answers.remove(0);
        assert!(!answers.is_empty());
        for answer in answers {
            eprintln!(
                "crate point {caller}:{start}: definitions={:?}, binding={:?}, enumeration={:?}, inventory_details={:?}",
                answer.definitions,
                answer.resolution.binding(),
                answer.enumeration,
                answer.inventory_details,
            );
            assert_eq!(answer.definitions.len(), 1, "exact physical point target");
            assert_eq!(
                answer.resolution.binding().completion(),
                &ResolutionCompletion::Complete,
                "crate-key point must completely confirm the reverse candidate"
            );
        }
    }

    #[test]
    fn reverse_crate_point_same_package_bin() {
        assert_crate_point(
            &[
                (
                    "Cargo.toml",
                    "[package]\nname='import_model_weights'\nversion='0.1.0'\nedition='2021'\n",
                ),
                (
                    "src/lib.rs",
                    "pub mod inference; pub use inference::infer;\n",
                ),
                ("src/inference.rs", "pub fn infer() {}\n"),
                (
                    "src/bin/safetensors.rs",
                    "use import_model_weights::infer;\nfn main() { infer(); }\n",
                ),
            ],
            "src/bin/safetensors.rs",
            45,
            "infer",
        );
    }

    #[test]
    fn reverse_crate_point_explicit_bench() {
        assert_crate_point(
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=['crates/*']\nresolver='3'\n[workspace.package]\nedition='2024'\n",
                ),
                (
                    "crates/parser-dep/Cargo.toml",
                    "[package]\nname='parser-dep'\nversion='0.1.0'\nedition.workspace=true\n",
                ),
                (
                    "crates/parser-dep/src/lib.rs",
                    "pub mod decoder { pub struct Encoding; }\n",
                ),
                (
                    "crates/benches/Cargo.toml",
                    "[package]\nname='benches'\nversion='0.1.0'\nedition.workspace=true\n[dev-dependencies]\nparser_dep={package='parser-dep',path='../parser-dep'}\n[[bench]]\nname='routes'\nharness=false\n",
                ),
                (
                    "crates/benches/benches/routes.rs",
                    "fn exercise(_: ::parser_dep::decoder::Encoding) {}\n",
                ),
            ],
            "crates/benches/benches/routes.rs",
            38,
            "Encoding",
        );
    }

    #[test]
    fn reverse_crate_point_imported_impl_owner() {
        assert_crate_point(
            &[
                (
                    "Cargo.toml",
                    "[package]\nname='imported-impl'\nversion='0.1.0'\n",
                ),
                (
                    "src/lib.rs",
                    "pub mod model; mod implementation; mod consumer;\n",
                ),
                ("src/model.rs", "pub struct Builder;\n"),
                (
                    "src/implementation.rs",
                    "use crate::model::Builder;\nimpl Builder { pub(crate) fn build() -> Self { Self } }\n",
                ),
                (
                    "src/consumer.rs",
                    "use crate::model::Builder;\nfn call() { let _ = Builder::build(); }\n",
                ),
                (
                    "src/main.rs",
                    "struct Builder; impl Builder { fn build() -> Self { Self } }\nfn call() { let _ = Builder::build(); }\n",
                ),
            ],
            "src/consumer.rs",
            56,
            "build",
        );
    }

    #[test]
    fn reverse_crate_point_alias_owner() {
        assert_crate_point(
            &[
                (
                    "src/lib.rs",
                    "pub struct Foo; impl Foo { pub fn new() -> Self { Self } }\npub type Alias = Foo; mod consumer;\n",
                ),
                (
                    "src/consumer.rs",
                    "use crate::Alias;\nfn call() { let _ = Alias::new(); }\n",
                ),
                (
                    "src/main.rs",
                    "struct Other; impl Other { fn new() -> Self { Self } }\ntype Alias = Other; fn decoy() { let _ = Alias::new(); }\n",
                ),
            ],
            "src/consumer.rs",
            45,
            "new",
        );
    }

    #[test]
    fn reverse_usages_retained_bytes_are_independent_of_workspace_size() {
        use crate::analyzer::store::resolution_operation::heap_pin_bytes;
        let measurements = [4, 32].map(|files| {
            let mut builder = InlineTestProject::with_language(Language::Rust).file(
                "Cargo.toml",
                "[package]\nname='heap'\nversion='0.1.0'\nedition='2021'\n",
            );
            let mut root = "pub fn target() {} pub fn caller() { target(); }\n".to_owned();
            for index in 0..files {
                root.push_str(&format!("mod decoy{index};\n"));
                builder = builder.file(
                    format!("src/decoy{index}.rs"),
                    format!("pub fn unrelated{index}() {{}}\n"),
                );
            }
            let fixture = builder.file("src/lib.rs", root).build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let target = rust
                .declarations(&fixture.file("src/lib.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .unwrap();
            // Account for the existing explicitly capped shared-name cache.
            let shared_names = rust
                .inner
                .analyzer_store()
                .resolution_shared_name_cache()
                .clone();
            let shared_names_before = shared_names.allocated_bytes();
            let outcome =
                with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                    let before = heap_pin_bytes();
                    let rows = queries.inverse_for(&[target])?;
                    assert!(
                        rows.as_ref().is_some_and(|rows| rows[0].edges.len() == 1),
                        "{rows:?}"
                    );
                    drop(rows);
                    Ok((
                        heap_pin_bytes() - before,
                        heap_pin_bytes(),
                        crate::analyzer::store::reader_eviction_bytes_for_test(),
                        shared_names.allocated_bytes() - shared_names_before,
                    ))
                });
            let RustSelectedReverseOutcome::Ready((
                request_growth,
                before_drop,
                eviction_before_drop,
                cache_growth,
            )) = outcome
            else {
                panic!("{outcome:?}")
            };
            let cache_release =
                crate::analyzer::store::reader_eviction_bytes_for_test() - eviction_before_drop;
            let total_release = before_drop - heap_pin_bytes();
            // ReaderPool::checkin evicts the idle point reader with this same
            // selection. That shared cache is not owned by the outer request.
            // Count its actual destructor releases separately, using the same
            // allocator counter, rather than attributing them to this request.
            (
                files,
                request_growth,
                total_release - cache_release,
                cache_release,
                cache_growth,
            )
        });
        eprintln!(
            "reverse Rust bytes (files, request growth, request-owned releases, shared reader eviction releases, capped cache growth): {measurements:?}"
        );
        // The request-owned release is no longer a proxy for retention, and it
        // grows with the workspace on purpose. `ReadySelectedResolution::drop`
        // trims the operation rebaser to its transient mounts before handing
        // the operation back, so a request now frees the identity inventory it
        // built instead of leaving it on the reader: with the trim this release
        // is 40,906 bytes at four unrelated files and 120,284 at thirty-two,
        // and without it 15,806 and 18,768. What must not grow is what survives
        // that release, outside the byte-capped interior cache.
        let retained_outside = measurements.map(|row| (row.1 - row.4) - row.2);
        assert!(
            retained_outside[1] <= retained_outside[0] + 4096,
            "workspace growth must not retain inventory: {retained_outside:?} from {measurements:?}"
        );
        // The live heap one request occupies outside the capped caches is
        // what the whole-selection completion sweep grew: it produced
        // and pinned one interior per selected mount, about 5.5 MiB of real
        // heap each, so a workspace eight times larger cost eight times the
        // peak, and none of it was released while the source held them. The
        // cache is the only structure that may still hold one entry per file,
        // and its explicit cap is what bounds that.
        let files_added = measurements[1].0 - measurements[0].0;
        let outside_cache = measurements.map(|row| row.1 - row.4);
        assert!(
            outside_cache[1] <= outside_cache[0] + 32 * 1024,
            "a reverse request's live heap outside the capped caches must not grow with {files_added} unrelated files: {measurements:?}"
        );
    }

    #[test]
    fn reverse_request_sql_work_is_bounded_by_target_rows() {
        let measurements = [4, 32].map(|files| {
            let mut builder = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[workspace]\nmembers=['api','client']\nresolver='2'\n",
                )
                .file(
                    "api/Cargo.toml",
                    "[package]\nname='api'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file(
                    "api/src/lib.rs",
                    "#[macro_export]\nmacro_rules! target { () => { () }; }\n",
                )
                .file(
                    "client/Cargo.toml",
                    "[package]\nname='client'\nversion='0.1.0'\nedition='2021'\n[dependencies]\napi={path='../api'}\n",
                )
                .file(
                    "client/src/lib.rs",
                    "use api::target;\npub fn caller() { target!(); }\n",
                );
            for index in 0..files {
                builder = builder.file(
                    format!("isolated/unrelated{index}.rs"),
                    format!("pub fn decoy{index}() {{}}\n"),
                );
            }
            let fixture = builder.build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let target = rust
                .declarations(&fixture.file("api/src/lib.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target" && unit.is_macro())
                .expect("target declaration");
            let result =
                with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                    queries.begin_sql_work_trace();
                    let rows = queries.inverse_for(&[target])?;
                    let sql_work = queries.finish_sql_work_trace();
                    assert!(
                        rows.as_ref().is_some_and(|rows| rows[0].edges.len() == 2),
                        "{rows:?}"
                    );
                    Ok(sql_work)
                });
            let RustSelectedReverseOutcome::Ready(sql_work) = result else {
                panic!("{result:?}")
            };
            (files, sql_work.0, sql_work.1)
        });
        eprintln!("reverse request SQL work (files, statements, rows): {measurements:?}");
        assert_eq!(
            measurements[0].2, measurements[1].2,
            "unrelated inventory must not add reverse rows: {measurements:?}"
        );
        // Statements are exact too. They were not: while the interior was the
        // only candidate-coverage reader, `lazy_candidate_completion` asked
        // every selected mount whether its candidates were complete before any
        // request read a match, which cost one statement and one produced
        // interior per unrelated file. The direction's unconditional box now
        // comes from `resolution_candidate_gap_headers` in one indexed query,
        // so an unrelated file adds neither.
        assert_eq!(
            measurements[0].1, measurements[1].1,
            "unrelated inventory must not add reverse statements: {measurements:?}"
        );
    }

    fn assert_target_call_point_status(
        rust: &RustAnalyzer,
        file: &ProjectFile,
        source: &str,
        expected: crate::analyzer::usages::get_definition::DefinitionLookupStatus,
    ) {
        use crate::analyzer::languages::BoundedReceiverQuery;
        use crate::analyzer::usages::get_definition::{BoundedResolution, ResolvedReferenceSite};

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut pending = vec![tree.root_node()];
        let mut calls = 0;
        while let Some(node) = pending.pop() {
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
            if node.kind() != "call_expression" {
                continue;
            }
            let function = node.child_by_field_name("function").unwrap();
            if function.utf8_text(source.as_bytes()).unwrap() != "target" {
                continue;
            }
            calls += 1;
            let site = ResolvedReferenceSite {
                path: crate::path_utils::rel_path_string(file),
                text: "target".to_owned(),
                range: crate::analyzer::Range {
                    start_byte: function.start_byte(),
                    end_byte: function.end_byte(),
                    start_line: function.start_position().row,
                    end_line: function.end_position().row,
                },
                focus_start_byte: function.start_byte(),
                focus_end_byte: function.end_byte(),
            };
            let result = super::super::native_points::resolve_rust_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: rust,
                    file,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
            );
            let BoundedResolution::Complete { value, .. } = result else {
                panic!("native point operation must finish: {result:?}");
            };
            assert_eq!(value.status, expected, "{source}: {value:?}");
        }
        assert_eq!(calls, 1);
    }

    #[test]
    fn self_type_observations_follow_renamed_generic_owners_with_exact_proof() {
        use crate::analyzer::usages::ReferenceKind;

        let source = "pub mod types { pub struct Service<T> { pub value: T } }\n\
use types::Service as Renamed;\n\
impl<T> Renamed<T> {\n\
    fn new(value: T) -> Self { Self { value } }\n\
    fn pass(value: Self) -> Self { Self::new(value.value) }\n\
}\n\
struct Other;\n\
impl Other { fn new() -> Self { loop {} } }\n\
trait Abstract { fn unknown() -> Self; }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", source)
            .build();
        // Reopening exercises persisted observation rows as well as fresh lowering.
        for _ in 0..2 {
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let target = rust
                .declarations(&fixture.file("src/lib.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "Service")
                .unwrap();
            let result =
                with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                    queries.inverse_for(std::slice::from_ref(&target))
                });
            let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
                panic!("transfer observations must be available: {result:?}");
            };
            let self_hits = rows[0]
                .edges
                .iter()
                .filter(|edge| {
                    &source[edge.site.range.start_byte..edge.site.range.end_byte] == "Self"
                })
                .collect::<Vec<_>>();
            let mut lines = self_hits
                .iter()
                .map(|edge| edge.site.range.start_line)
                .collect::<Vec<_>>();
            lines.sort_unstable();
            assert_eq!(lines, vec![4, 4, 5, 5, 5], "{rows:?}");
            assert!(
                self_hits.iter().all(|edge| edge.proof == UsageProof::Proven
                    && edge.reference_kind == Some(ReferenceKind::SelfTypeAlias)),
                "{self_hits:?}"
            );
        }
    }

    #[test]
    fn scoped_reverse_keeps_foreign_reexports_and_excludes_other_source_inventory() {
        use crate::analyzer::structural::EdgeAxis;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"scoped_reverse\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod provider; pub mod barrel; pub mod caller; pub mod excluded;",
            )
            .file("src/provider.rs", "pub fn target() {}")
            .file("src/barrel.rs", "pub use crate::provider::target;")
            .file(
                "src/caller.rs",
                "pub fn caller() { crate::barrel::target(); }",
            )
            .file(
                "src/excluded.rs",
                // A module mount keeps the token tree unenumerable; a bare `unknown_macro!()`
                // no longer leaves the reference inventory incomplete.
                "pub fn excluded() { crate::provider::target(); unknown_macro! { mod generated; } }",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/provider.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        for (files, expected_edges, complete) in [
            (HashSet::from_iter([fixture.file("src/caller.rs")]), 1, true),
            (
                HashSet::from_iter([fixture.file("src/excluded.rs")]),
                1,
                false,
            ),
            (HashSet::default(), 0, true),
        ] {
            let result = with_rust_selected_reverse_queries_in_files(
                &rust,
                &files,
                &CancellationToken::new(),
                |queries| queries.inverse_for(std::slice::from_ref(&target)),
            );
            let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
                panic!("scoped reverse lookup must be available: {result:?}");
            };
            assert_eq!(rows[0].edges.len(), expected_edges, "{rows:?}");
            assert_eq!(
                rows[0].covers(EdgeAxis::InverseProjection),
                complete,
                "{rows:?}"
            );
            assert!(
                rows[0].edges.iter().all(|edge| {
                    files.contains(&edge.site.file) && edge.proof == UsageProof::Proven
                }),
                "{rows:?}"
            );
        }

        let files = HashSet::from_iter([fixture.file("src/caller.rs")]);
        let cancellation = CancellationToken::new();
        let cancelled =
            with_rust_selected_reverse_queries_in_files(&rust, &files, &cancellation, |queries| {
                let rows = queries.inverse_for(std::slice::from_ref(&target))?;
                cancellation.cancel();
                Ok(rows)
            });
        assert!(
            matches!(cancelled, RustSelectedReverseOutcome::Cancelled),
            "{cancelled:?}"
        );
    }

    #[test]
    fn scoped_reverse_uses_prepared_overlay_reference_inventory() {
        use crate::analyzer::structural::EdgeAxis;
        use std::sync::Arc;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"scoped_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod caller; pub fn target() {}")
            .file("src/caller.rs", "pub fn caller() { crate::target(); }")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let target = disk
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(
            fixture.file("src/caller.rs").abs_path(),
            "pub fn caller() {}".to_owned()
        ));
        let prepared = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            prepared
                .declarations(&fixture.file("src/caller.rs"))
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        let files = HashSet::from_iter([fixture.file("src/caller.rs")]);
        let result = with_rust_selected_reverse_queries_in_files(
            &prepared,
            &files,
            &CancellationToken::new(),
            |queries| queries.inverse_for(std::slice::from_ref(&target)),
        );
        let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
            panic!("prepared overlay must be selected: {result:?}");
        };
        assert!(rows[0].edges.is_empty(), "{rows:?}");
        assert!(rows[0].covers(EdgeAxis::InverseProjection), "{rows:?}");

        assert!(overlay.set(
            fixture.file("src/caller.rs").abs_path(),
            // A module mount keeps the token tree unenumerable; a bare `unknown_macro!()`
            // no longer leaves the reference inventory incomplete.
            "pub fn caller() { unknown_macro! { mod generated; } }".to_owned(),
        ));
        let prepared = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            prepared
                .declarations(&fixture.file("src/caller.rs"))
                .iter()
                .any(|unit| unit.identifier() == "caller")
        );
        for (files, complete) in [(files, false), (HashSet::default(), true)] {
            let result = with_rust_selected_reverse_queries_in_files(
                &prepared,
                &files,
                &CancellationToken::new(),
                |queries| queries.inverse_for(std::slice::from_ref(&target)),
            );
            let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
                panic!("prepared overlay must be selected: {result:?}");
            };
            assert!(rows[0].edges.is_empty(), "{rows:?}");
            assert_eq!(
                rows[0].covers(EdgeAxis::InverseProjection),
                complete,
                "{rows:?}"
            );
        }
    }

    #[test]
    fn issue_3769_overlay_replaces_stale_field_with_call_and_back() {
        use crate::analyzer::structural::EdgeAxis;
        use crate::analyzer::usages::ReferenceKind;
        use std::sync::Arc;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"field_method_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod caller;\npub struct Widget { pub name: u8 }\nimpl Widget { pub fn name(&self) {} }\n",
            )
            .file(
                "src/caller.rs",
                "use crate::Widget;\npub fn caller(widget: Widget) { let _field = widget.name; }\n",
            )
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let target = disk
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "name" && unit.is_function())
            .expect("the inherent method declaration");
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        let caller = fixture.file("src/caller.rs");
        let files = HashSet::from_iter([caller.clone()]);

        assert!(overlay.set(
            caller.abs_path(),
            "use crate::Widget;\npub fn caller(widget: Widget) { let _field = widget.name; widget.name(); }\n"
                .to_owned(),
        ));
        let prepared = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            prepared
                .declarations(&caller)
                .iter()
                .any(|unit| unit.identifier() == "caller"),
            "prepared declarations trigger the overlay update"
        );
        let method_reverse = with_rust_selected_reverse_queries_in_files(
            &prepared,
            &files,
            &CancellationToken::new(),
            |queries| {
                let candidates = queries.candidate_files(std::slice::from_ref(&target))?;
                let rows = queries.inverse_for(std::slice::from_ref(&target))?;
                Ok((candidates, rows, queries.work_report()))
            },
        );
        let RustSelectedReverseOutcome::Ready((Some(candidates), Some(rows), work)) =
            method_reverse
        else {
            panic!("the fresh overlay call must be indexed: {method_reverse:?}");
        };
        assert!(candidates.contains(&caller), "{candidates:?}");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].edges.len(), 1, "{rows:?}");
        assert_eq!(
            rows[0].edges[0].reference_kind,
            Some(ReferenceKind::MethodCall),
            "the stale persisted field cannot erase the fresh method call: {rows:?}"
        );
        assert!(rows[0].edges[0].proof == UsageProof::Proven, "{rows:?}");
        assert!(rows[0].covers(EdgeAxis::InverseProjection), "{rows:?}");
        let metrics = &work
            .targets
            .iter()
            .find(|(measured_target, _)| measured_target == &target)
            .expect("target reverse-work metrics")
            .1;
        assert_eq!(metrics.full_fact_evaluation_count(), 1, "{metrics:?}");

        assert!(
            overlay.set(
                caller.abs_path(),
                "use crate::Widget;\npub fn caller(widget: Widget) { let _field = widget.name; }\n"
                    .to_owned(),
            )
        );
        let prepared = disk.clone_with_project(Arc::new(overlay.snapshot()));
        assert!(
            prepared
                .declarations(&caller)
                .iter()
                .any(|unit| unit.identifier() == "caller"),
            "prepared declarations trigger the updated field-only overlay"
        );
        let field_reverse = with_rust_selected_reverse_queries_in_files(
            &prepared,
            &files,
            &CancellationToken::new(),
            |queries| {
                let candidates = queries.candidate_files(std::slice::from_ref(&target))?;
                let rows = queries.inverse_for(std::slice::from_ref(&target))?;
                Ok((candidates, rows, queries.work_report()))
            },
        );
        let RustSelectedReverseOutcome::Ready((Some(candidates), Some(rows), work)) = field_reverse
        else {
            panic!("the fresh overlay field must be indexed: {field_reverse:?}");
        };
        assert!(candidates.contains(&caller), "{candidates:?}");
        assert!(rows[0].edges.is_empty(), "{rows:?}");
        assert!(rows[0].covers(EdgeAxis::InverseProjection), "{rows:?}");
        let metrics = &work
            .targets
            .iter()
            .find(|(measured_target, _)| measured_target == &target)
            .expect("target reverse-work metrics")
            .1;
        assert_eq!(
            metrics.full_fact_evaluation_count(),
            0,
            "the new ordinary field requires no forward confirmation: {metrics:?}"
        );
    }

    #[test]
    fn scoped_reverse_import_sites_keep_proof_with_an_unrelated_item_macro() {
        use crate::analyzer::structural::EdgeAxis;
        use crate::analyzer::usages::UsageHitKind;

        for hidden_source in ["pub fn noise() {}", "unknown_macro!();"] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", "[package]\nname = \"scoped_import\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
                .file("src/lib.rs", "pub mod api; pub mod hidden; use crate::api::target; pub fn caller() { target(); }")
                .file("src/api.rs", "pub fn target() {}")
                .file("src/hidden.rs", hidden_source)
                .build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            assert_target_call_point_status(
                &rust,
                &fixture.file("src/lib.rs"),
                "pub mod api; pub mod hidden; use crate::api::target; pub fn caller() { target(); }",
                crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
            );
            let target = rust
                .declarations(&fixture.file("src/api.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .unwrap();
            let admitted = HashSet::from_iter([fixture.file("src/lib.rs")]);
            let result = with_rust_selected_reverse_queries_in_files(
                &rust,
                &admitted,
                &CancellationToken::new(),
                |queries| queries.inverse_for(std::slice::from_ref(&target)),
            );
            let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
                panic!("scoped import lookup must be available: {result:?}");
            };
            assert!(
                rows[0].covers(EdgeAxis::InverseProjection),
                "{hidden_source}: {rows:?}"
            );
            assert_eq!(rows[0].edges.len(), 2, "{rows:?}");
            assert!(
                rows[0]
                    .edges
                    .iter()
                    .all(|edge| edge.proof == UsageProof::Proven),
                "{rows:?}"
            );
            assert_eq!(
                rows[0]
                    .edges
                    .iter()
                    .filter(|edge| edge.usage_kind == UsageHitKind::Import)
                    .count(),
                1,
                "{rows:?}"
            );
        }
    }

    #[test]
    fn macro_scope_uncertainty_survives_imports_of_its_declarations() {
        use crate::analyzer::structural::EdgeAxis;

        for import in ["use crate::api::target;", "use crate::api::*;"] {
            let caller_source = format!("pub mod api; {import} pub fn caller() {{ target(); }}");
            // The macro's token tree must hold a group that does not parse as an
            // expression: an item-position token tree is enumerated for
            // references (lane PM), so an empty or fully parsed one leaves the
            // reference inventory complete and only the macro's own
            // declaration gap remains. `=>` keeps the enumeration gap alive.
            let api_source = "pub fn target() {} unknown_macro!(=>); pub fn inside() { target(); }";
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"macro_scope\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .file("src/lib.rs", &caller_source)
                .file("src/api.rs", api_source)
                .build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            for (path, source) in [
                ("src/lib.rs", caller_source.as_str()),
                ("src/api.rs", api_source),
            ] {
                // The call's forward answer is exact: an item the unknown
                // macro expands to cannot declare a second `target` in `api`
                // without a duplicate-definition error, and the caller's
                // import (named or glob) reaches the declared one. The
                // uncertainty is the reverse one checked below: the expansion
                // may use `target`.
                assert_target_call_point_status(
                    &rust,
                    &fixture.file(path),
                    source,
                    crate::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                );
            }
            let target = rust
                .declarations(&fixture.file("src/api.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .unwrap();
            // The macro's uncertainty is the reverse inventory's, not the
            // proof of the sites that exist. `src/api.rs` holds the macro,
            // whose token tree has a group that could not be enumerated, so
            // its own reference enumeration may be missing a site and the
            // answer is incomplete. `src/lib.rs` holds no macro: both of its
            // sites are enumerated, so its inventory is complete. Each site
            // that exists is proven: the expansion cannot declare a second
            // `target` for it to bind instead.
            for (admitted_file, enumeration_complete) in
                [("src/lib.rs", true), ("src/api.rs", false)]
            {
                let admitted = HashSet::from_iter([fixture.file(admitted_file)]);
                let result = with_rust_selected_reverse_queries_in_files(
                    &rust,
                    &admitted,
                    &CancellationToken::new(),
                    |queries| queries.inverse_for(std::slice::from_ref(&target)),
                );
                let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
                    panic!("macro scope lookup must retain its boundary: {result:?}");
                };
                assert_eq!(
                    rows[0].covers(EdgeAxis::InverseProjection),
                    enumeration_complete,
                    "{import} in {admitted_file}: {rows:?}"
                );
                assert!(!rows[0].edges.is_empty(), "{rows:?}");
                assert!(
                    rows[0]
                        .edges
                        .iter()
                        .all(|edge| edge.proof == UsageProof::Proven),
                    "{import} in {admitted_file}: {rows:?}"
                );
            }
        }
    }

    #[test]
    fn adaptive_reverse_frontiers_confirm_each_site_and_keep_exact_owners() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"reverse\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub fn target() {}\npub fn middle() { target(); }\npub fn caller() { middle(); }\npub fn unrelated() {}\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let target = declarations
            .iter()
            .find(|unit| unit.short_name() == "target")
            .unwrap();
        reset_selected_fact_operation_construction_count_for_test();
        let result =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                let first = queries
                    .inverse_for(std::slice::from_ref(target))?
                    .expect("first frontier");
                assert_eq!(first.len(), 1);
                let first_rows = &first[0].edges;
                assert_eq!(first_rows.len(), 1, "{first_rows:?}");
                assert_eq!(first_rows[0].proof, UsageProof::Proven);
                let middle = first_rows[0].site.enclosing.as_ref().expect("exact caller");
                assert_eq!(middle.short_name(), "middle");
                let second = queries
                    .inverse_for(std::slice::from_ref(middle))?
                    .expect("adaptive frontier");
                assert_eq!(second[0].edges.len(), 1, "{second:?}");
                assert_eq!(
                    second[0].edges[0]
                        .site
                        .enclosing
                        .as_ref()
                        .unwrap()
                        .short_name(),
                    "caller"
                );
                assert_eq!(second[0].edges[0].proof, UsageProof::Proven);
                Ok((first, second))
            });
        assert!(
            matches!(result, RustSelectedReverseOutcome::Ready(_)),
            "{result:?}"
        );
        assert_eq!(
            selected_fact_operation_construction_count_for_test(),
            2,
            "two adaptive frontiers each construct one Stage 2 fact operation through crate-row confirmation"
        );
    }

    #[test]
    fn issue_3769_method_usage_scan_skips_field_only_blobs_and_keeps_method_values() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"field_method_usage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod calls;\npub mod fields;\npub struct Widget { pub name: fn() }\nimpl Widget { pub fn name(&self) {} }\n",
            )
            .file(
                "src/fields.rs",
                // `(widget.name)()` leaves a parenthesized computed callee.
                // `lower_call_reference_result` sends that callee through
                // `add_local_gap(UnsupportedExpression)`, preserving an
                // enumeration gap even though the inner field reference is
                // independently proved to be a field.
                "use crate::Widget;\npub fn field_only(widget: Widget) {\n    let _field = widget.name;\n    (widget.name)();\n}\n",
            )
            .file(
                "src/calls.rs",
                "use crate::Widget;\npub fn method_sites(widget: Widget) {\n    widget.name();\n    let _method = Widget::name;\n}\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "name" && unit.is_function())
            .expect("the inherent method declaration");

        // The field-only blob is still in the candidate inventory. It must be
        // removed before point confirmation, while its file remains part of
        // the selected inventory assembled before the filter.
        let reverse =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                let candidates = queries.candidate_files(std::slice::from_ref(&target))?;
                let rows = queries.inverse_for(std::slice::from_ref(&target))?;
                Ok((candidates, rows, queries.work_report()))
            });
        let RustSelectedReverseOutcome::Ready((Some(candidates), Some(rows), work)) = reverse
        else {
            panic!("selected method reverse lookup must be available: {reverse:?}");
        };
        assert!(
            candidates.contains(&fixture.file("src/fields.rs")),
            "the field-only blob must be a reverse candidate before filtering: {candidates:?}"
        );
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(
            !rows[0].covers(crate::analyzer::structural::EdgeAxis::InverseProjection),
            "the callable-field enumeration gap is preserved: {rows:?}"
        );
        assert_eq!(rows[0].edges.len(), 2, "{rows:?}");
        let metrics = &work
            .targets
            .iter()
            .find(|(measured_target, _)| measured_target == &target)
            .expect("target reverse-work metrics")
            .1;
        assert_eq!(
            metrics.full_fact_evaluation_count(),
            1,
            "only the blob with method-shaped references needs confirmation: {metrics:?}"
        );

        let admitted = rust
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let scan = super::super::native_usages::find_native_usages(
            &rust,
            std::slice::from_ref(&target),
            &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(&admitted),
            10,
        );
        let crate::analyzer::usages::outcome::GraphUsageOutcome::Resolved(
            scan_result @ crate::analyzer::usages::FuzzyResult::Incomplete { .. },
        ) = scan
        else {
            panic!("the callable-field inventory gap must remain visible: {scan:?}");
        };
        let hits = scan_result.all_hits();
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(
            hits.iter()
                .any(|hit| hit.snippet.contains("widget.name();")),
            "the real receiver call remains a hit: {hits:?}"
        );
        assert!(
            hits.iter().any(|hit| hit.snippet.contains("Widget::name")),
            "the qualified method value remains a hit: {hits:?}"
        );
        assert!(
            hits.iter()
                .all(|hit| !hit.snippet.contains("(widget.name)()")
                    && !hit.snippet.contains("let _field = widget.name;")),
            "ordinary and callable fields are not method usages: {hits:?}"
        );

        let field = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "name" && unit.is_field())
            .expect("the same-named field declaration");
        let field_scan = super::super::native_usages::find_native_usages(
            &rust,
            std::slice::from_ref(&field),
            &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(&admitted),
            10,
        );
        let crate::analyzer::usages::outcome::GraphUsageOutcome::Resolved(
            field_result @ crate::analyzer::usages::FuzzyResult::Incomplete { .. },
        ) = field_scan
        else {
            panic!("the field target keeps the same inventory gap: {field_scan:?}");
        };
        let field_hits = field_result.all_hits();
        assert_eq!(field_hits.len(), 2, "{field_hits:?}");
        assert!(
            field_hits
                .iter()
                .any(|hit| hit.snippet.contains("let _field = widget.name;")),
            "ordinary field reads remain field usages: {field_hits:?}"
        );
        assert!(
            field_hits
                .iter()
                .any(|hit| hit.snippet.contains("(widget.name)();")),
            "callable field reads remain field usages: {field_hits:?}"
        );
    }

    #[test]
    fn issue_3769_trait_qualified_method_value_is_retained() {
        use crate::analyzer::usages::FuzzyResult;
        use crate::analyzer::usages::outcome::GraphUsageOutcome;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"trait_method_value\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod caller;\npub trait Named { fn label(&self); }\npub struct Widget;\nimpl Named for Widget { fn label(&self) {} }\n",
            )
            .file(
                "src/caller.rs",
                "use crate::{Named, Widget};\npub fn method_value() { let _method = <Widget as Named>::label; }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let targets = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .filter(|unit| unit.identifier() == "label" && unit.is_function())
            .collect::<Vec<_>>();
        assert!(
            !targets.is_empty(),
            "the trait and impl method declarations exist"
        );
        let admitted = rust
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let scan = super::super::native_usages::find_native_usages(
            &rust,
            &targets,
            &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(&admitted),
            10,
        );
        let GraphUsageOutcome::Resolved(scan_result @ FuzzyResult::Success { .. }) = scan else {
            panic!("a trait-qualified method value is a complete usage: {scan:?}");
        };
        assert!(
            scan_result
                .all_hits()
                .iter()
                .any(|hit| hit.snippet.contains("<Widget as Named>::label")),
            "the trait-qualified method value remains a hit: {scan_result:?}"
        );
    }

    #[test]
    fn issue_3769_excluded_field_only_locator_does_not_hide_file_inventory_gaps() {
        use crate::analyzer::structural::EdgeAxis;
        use crate::analyzer::usages::FuzzyResult;
        use crate::analyzer::usages::outcome::GraphUsageOutcome;

        let label = "unknown attribute";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"field_inventory_gap\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod fields;\npub struct Widget { pub name: u8 }\nimpl Widget { pub fn name(&self) {} }\n",
            )
            .file(
                "src/fields.rs",
                "use crate::Widget;\n#[unknown_attribute]\npub struct MayBeTransformed;\npub fn field_only(widget: Widget) { let _field = widget.name; }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "name" && unit.is_function())
            .expect("the inherent method declaration");
        let reverse =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                let candidates = queries.candidate_files(std::slice::from_ref(&target))?;
                let rows = queries.inverse_for(std::slice::from_ref(&target))?;
                Ok((candidates, rows, queries.work_report()))
            });
        let RustSelectedReverseOutcome::Ready((Some(candidates), Some(rows), work)) = reverse
        else {
            panic!("{label}: selected reverse query must be available: {reverse:?}");
        };
        assert!(
            candidates.contains(&fixture.file("src/fields.rs")),
            "{label}: the excluded field is the file's last target-name candidate: {candidates:?}"
        );
        let metrics = &work
            .targets
            .iter()
            .find(|(measured_target, _)| measured_target == &target)
            .expect("target reverse-work metrics")
            .1;
        assert_eq!(
            metrics.full_fact_evaluation_count(),
            0,
            "{label}: the final field locator needs no forward confirmation: {metrics:?}"
        );
        assert!(rows[0].edges.is_empty(), "{label}: {rows:?}");
        assert!(
            !rows[0].covers(EdgeAxis::InverseProjection),
            "{label}: excluded field must not erase the file's inventory gap: {rows:?}"
        );

        let admitted = rust
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let scan = super::super::native_usages::find_native_usages(
            &rust,
            std::slice::from_ref(&target),
            &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(&admitted),
            10,
        );
        let GraphUsageOutcome::Resolved(FuzzyResult::Incomplete { .. }) = scan else {
            panic!("{label}: excluding the final locator must preserve file uncertainty: {scan:?}");
        };
    }

    #[test]
    fn issue_3769_unknown_macro_uncertainty_survives_field_shaped_arguments() {
        use crate::analyzer::usages::FuzzyResult;
        use crate::analyzer::usages::outcome::GraphUsageOutcome;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"field_macro_uncertainty\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod caller;\npub struct Widget { pub name: fn() }\nimpl Widget { pub fn name(&self) {} }\n",
            )
            .file(
                "src/caller.rs",
                "use crate::Widget;\npub fn caller(widget: Widget) { unknown_macro!(widget.name); }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "name" && unit.is_function())
            .expect("the inherent method declaration");
        let reverse =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                let rows = queries.inverse_for(std::slice::from_ref(&target))?;
                Ok((rows, queries.work_report()))
            });
        let RustSelectedReverseOutcome::Ready((Some(_rows), work)) = reverse else {
            panic!("unknown macro reverse lookup must be available: {reverse:?}");
        };
        let metrics = &work
            .targets
            .iter()
            .find(|(measured_target, _)| measured_target == &target)
            .expect("the guessed macro site must be measured")
            .1;
        assert_eq!(
            metrics.issued_reference_seed_count(),
            1,
            "the parseable macro argument is the only candidate site in its blob: {metrics:?}"
        );
        assert_eq!(
            metrics.full_fact_evaluation_count(),
            1,
            "the guessed field-shaped macro site must reach confirmation: {metrics:?}"
        );
        let admitted = rust
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let scan = super::super::native_usages::find_native_usages(
            &rust,
            std::slice::from_ref(&target),
            &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(&admitted),
            10,
        );
        let GraphUsageOutcome::Resolved(FuzzyResult::Incomplete { .. }) = scan else {
            panic!("unknown macro arguments must keep method usage coverage uncertain: {scan:?}");
        };
    }

    #[test]
    fn issue_3769_unresolved_receiver_field_does_not_leave_method_doubt() {
        use crate::analyzer::usages::FuzzyResult;
        use crate::analyzer::usages::outcome::GraphUsageOutcome;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"unresolved_receiver_field\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod caller;\npub struct Widget;\nimpl Widget { pub fn name(&self) {} }\n",
            )
            .file(
                "src/caller.rs",
                "pub fn caller<T>(value: T) { let _field = value.name; }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "name" && unit.is_function())
            .expect("the inherent method declaration");
        let reverse =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                let candidates = queries.candidate_files(std::slice::from_ref(&target))?;
                let rows = queries.inverse_for(std::slice::from_ref(&target))?;
                Ok((candidates, rows, queries.work_report()))
            });
        let RustSelectedReverseOutcome::Ready((Some(candidates), Some(rows), work)) = reverse
        else {
            panic!("generic receiver reverse lookup must be available: {reverse:?}");
        };
        assert!(
            candidates.contains(&fixture.file("src/caller.rs")),
            "the unresolved receiver field is nominated before filtering: {candidates:?}"
        );
        assert!(rows[0].edges.is_empty(), "{rows:?}");
        assert!(
            rows[0].covers(crate::analyzer::structural::EdgeAxis::InverseProjection),
            "{rows:?}"
        );
        let metrics = &work
            .targets
            .iter()
            .find(|(measured_target, _)| measured_target == &target)
            .expect("target reverse-work metrics")
            .1;
        assert_eq!(
            metrics.full_fact_evaluation_count(),
            0,
            "a structurally ordinary field with an unresolved receiver does not need method confirmation: {metrics:?}"
        );

        let admitted = rust
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let scan = super::super::native_usages::find_native_usages(
            &rust,
            std::slice::from_ref(&target),
            &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(&admitted),
            10,
        );
        let GraphUsageOutcome::Resolved(scan_result @ FuzzyResult::Success { .. }) = scan else {
            panic!("the excluded field must not leave unresolved method doubt: {scan:?}");
        };
        assert!(scan_result.all_hits().is_empty(), "{scan_result:?}");
    }

    #[test]
    fn issue_3769_malformed_method_scope_remains_incomplete_after_field_exclusion() {
        use crate::analyzer::usages::FuzzyResult;
        use crate::analyzer::usages::outcome::GraphUsageOutcome;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"field_malformed_scope\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod caller;\npub struct Widget { pub name: fn() }\nimpl Widget { pub fn name(&self) {} }\n",
            )
            .file(
                "src/caller.rs",
                "use crate::Widget;\npub fn caller(widget: Widget) {\n    let _field = widget.name;\n    let broken = ;\n    widget.name();\n}\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "name" && unit.is_function())
            .expect("the inherent method declaration");
        let admitted = rust
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let scan = super::super::native_usages::find_native_usages(
            &rust,
            std::slice::from_ref(&target),
            &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(&admitted),
            10,
        );
        assert!(
            matches!(
                &scan,
                GraphUsageOutcome::Resolved(FuzzyResult::Incomplete { .. })
            ),
            "field exclusion must not turn a recovered Rust scope into complete evidence: {scan:?}"
        );
    }

    /// B2. Reverse confirmation costs one point request per candidate blob,
    /// whatever the number of candidate sites in it.
    ///
    /// Every site of a file needs the same macro frontier, crate context,
    /// demand inventory and blueprint, and a point request is what builds
    /// them. Confirming site by site rebuilt all of it per site and opened a
    /// selected resolution operation each time; on the Bifrost corpus the
    /// reverse frontiers that completed took 22 to 543 seconds each and the
    /// query never finished.
    #[test]
    fn reverse_confirmation_costs_one_demand_per_candidate_blob() {
        let measure = |calls: usize| {
            let mut caller = String::from("use crate::target;\n");
            for index in 0..calls {
                caller.push_str(&format!("pub fn call_{index}() {{ target(); }}\n"));
            }
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"blob-demand\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .file("src/lib.rs", "pub mod caller;\npub fn target() {}\n")
                .file("src/caller.rs", &caller)
                .build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let target = rust
                .declarations(&fixture.file("src/lib.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .expect("the target declaration");
            reset_selected_fact_operation_construction_count_for_test();
            let result =
                with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                    queries.inverse_for(&[target])
                });
            let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
                panic!("reverse must be ready: {result:?}");
            };
            (
                rows[0].edges.len(),
                selected_fact_operation_construction_count_for_test(),
            )
        };
        let one = measure(1);
        let many = measure(8);
        eprintln!("reverse confirmation (edges, point operations): {one:?} then {many:?}");
        // The import is a usage too, so a file with n calls has n + 1 sites.
        assert_eq!(one.0, 2, "one call and its import: {one:?}");
        assert_eq!(many.0, 9, "eight calls and their import: {many:?}");
        assert_eq!(
            one.1, many.1,
            "eight candidate sites in one blob cost what one costs: {one:?} then {many:?}"
        );
        assert!(one.1 > 0, "the fixture must confirm something: {one:?}");
    }

    #[test]
    fn reverse_bare_module_paths_obey_lexical_type_shadowing() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"prefix\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub mod provider;\nuse crate::provider::api;\npub fn caller() { api::target(); }\npub fn shadow<api>() { api::target(); }\n")
            .file("src/provider.rs", "pub mod api { pub fn target() {} }\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/provider.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target" && unit.owner_identifier() == Some("api"))
            .unwrap();
        let result =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[target])
            });
        let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
            panic!("native module-prefix lookup must be available: {result:?}");
        };
        assert_eq!(rows[0].edges.len(), 1, "{rows:?}");
        let edge = &rows[0].edges[0];
        assert_eq!(edge.site.enclosing.as_ref().unwrap().short_name(), "caller");
        assert_eq!(edge.proof, UsageProof::Proven, "{edge:?}");
    }

    #[test]
    fn reverse_mixed_module_and_type_prefixes_retain_both_targets() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"mixed-prefix\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod modules;\npub mod types;\nuse crate::modules::Api;\nuse crate::types::Api;\npub fn caller() { Api::target(); }\n",
            )
            .file("src/modules.rs", "pub mod Api { pub fn target() {} }\n")
            .file(
                "src/types.rs",
                "pub struct Api;\nimpl Api { pub fn target() {} }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        // This deliberately models the structured ambiguous-prefix workload;
        // the duplicate import is allowed in the analyzer's facts even though
        // rustc would reject the program as an ordinary source build.
        let module_target = rust
            .declarations(&fixture.file("src/modules.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target" && unit.owner_identifier() == Some("Api"))
            .expect("module target declaration");
        let type_target = rust
            .declarations(&fixture.file("src/types.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target" && unit.owner_identifier() == Some("Api"))
            .expect("inherent type target declaration");

        let result =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[module_target.clone(), type_target.clone()])
            });
        let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
            panic!("mixed module/type prefix lookup must be available: {result:?}");
        };
        assert_eq!(rows.len(), 2, "{rows:?}");
        let edges = rows.iter().flat_map(|row| &row.edges).collect::<Vec<_>>();
        assert_eq!(edges.len(), 2, "{rows:?}");
        let targets = edges
            .iter()
            .map(|edge| edge.target.clone())
            .collect::<Vec<_>>();
        assert!(targets.contains(&module_target), "{targets:?}");
        assert!(targets.contains(&type_target), "{targets:?}");
        for edge in edges {
            assert_eq!(edge.proof, UsageProof::Unproven, "{edge:?}");
            assert_eq!(edge.site.enclosing.as_ref().unwrap().identifier(), "caller");
        }
    }

    #[test]
    fn reverse_private_inherent_methods_use_canonical_requester_modules() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"private-member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub mod model {\n",
                    "    pub struct Service;\n",
                    "    impl Service {\n",
                    "        fn target(&self) {}\n",
                    "        pub fn inside(&self) { self.target(); }\n",
                    "    }\n",
                    "    pub mod child {\n",
                    "        pub fn descendant(value: crate::model::Service) { value.target(); }\n",
                    "    }\n",
                    "}\n",
                    "pub fn outside(value: crate::model::Service) { value.target(); }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("private inherent method declaration");
        let result =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[target])
            });
        let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
            panic!("private member reverse lookup must be available: {result:?}");
        };
        assert_eq!(rows.len(), 1, "{rows:?}");
        let edges = &rows[0].edges;
        let owners = edges
            .iter()
            .map(|edge| {
                assert_eq!(edge.proof, UsageProof::Proven, "{edge:?}");
                edge.site
                    .enclosing
                    .as_ref()
                    .expect("callable-owned reference")
                    .identifier()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            owners,
            std::collections::BTreeSet::from(["descendant", "inside"]),
            "{rows:?}"
        );
        assert_eq!(edges.len(), 2, "{rows:?}");
    }

    #[test]
    fn reverse_inherent_methods_keep_resolved_owner_identity() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"inherent\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub mod unrelated;\npub struct Widget;\npub struct Other;\nimpl Widget { pub fn alpha(&self) {} }\nimpl Widget { pub fn beta(&self) {} }\nimpl Other { pub fn alpha(&self) {} }\npub fn caller(widget: Widget) { widget.alpha(); widget.beta(); }\n")
            .file("src/unrelated.rs", "pub fn unrelated() {}\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let methods = declarations
            .iter()
            .filter(|unit| matches!(unit.identifier(), "alpha" | "beta"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 3, "{declarations:?}");
        let result =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&methods)
            });
        let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
            panic!("inherent reverse lookup must be available: {result:?}");
        };
        let edges = rows.iter().flat_map(|row| &row.edges).collect::<Vec<_>>();
        assert_eq!(edges.len(), 2, "{rows:?}");
        for edge in edges {
            assert_eq!(edge.proof, UsageProof::Proven, "{edge:?}");
            assert_eq!(edge.site.enclosing.as_ref().unwrap().short_name(), "caller");
        }
    }

    #[test]
    fn reverse_edges_preserve_ambiguity_outside_the_queried_target() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"ambiguous\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub mod left;\npub mod right;\nuse crate::left::*;\nuse crate::right::*;\npub fn caller() { target(); }\n")
            .file("src/left.rs", "pub fn target() {}\n")
            .file("src/right.rs", "pub fn target() {}\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/left.rs"))
            .into_iter()
            .find(|unit| unit.short_name() == "target")
            .unwrap();
        let result =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(std::slice::from_ref(&target))
            });
        let RustSelectedReverseOutcome::Ready(Some(rows)) = result else {
            panic!("ambiguous lookup must retain a native candidate: {result:?}");
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].edges.len(), 1, "{rows:?}");
        assert_eq!(rows[0].edges[0].target, target);
        assert_eq!(rows[0].edges[0].proof, UsageProof::Unproven);
    }

    #[test]
    fn reverse_late_cancellation_discards_staged_frontiers_and_retries() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"cancel\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn target() {}\npub fn caller() { target(); }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.short_name() == "target")
            .unwrap();
        let cancellation = CancellationToken::new();
        let cancelled = with_rust_selected_reverse_queries(&rust, &cancellation, |queries| {
            let rows = queries
                .inverse_for(std::slice::from_ref(&target))?
                .expect("first query");
            assert!(!rows[0].edges.is_empty());
            cancellation.cancel();
            Ok(rows)
        });
        assert!(
            matches!(cancelled, RustSelectedReverseOutcome::Cancelled),
            "{cancelled:?}"
        );
        let retry =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(std::slice::from_ref(&target))
            });
        assert!(
            matches!(retry, RustSelectedReverseOutcome::Ready(Some(ref rows)) if rows[0].edges.len() == 1),
            "{retry:?}"
        );
    }

    #[test]
    fn ignored_missing_reverse_target_cannot_authorize_a_staged_result() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"missing\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub fn target() {}\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let missing = CodeUnit::file_scope(fixture.file("src/lib.rs"));
        let result =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                assert!(queries.inverse_for(&[missing])?.is_none());
                Ok("must not publish")
            });
        assert!(
            matches!(result, RustSelectedReverseOutcome::Unavailable(_)),
            "{result:?}"
        );
    }
}
