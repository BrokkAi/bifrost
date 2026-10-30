//! Native usage-result preparation; production routing remains unchanged.

use brokk_bifrost_analysis::analyzer::usages::native_result::{
    NativeUsageAdmission, NativeUsageDiagnostics, NativeUsageFile, NativeUsageOrigin,
    NativeUsagePending, NativeUsageProjection, NativeUsageSite, project_pending_files,
    unique_targets,
};

use std::ops::ControlFlow;

use crate::analyzer::rust::RustAnalyzer;

use crate::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

use crate::analyzer::rust::selected_reverse::RustSelectedReverseQueries;

use crate::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;

use crate::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries_in_files;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REVERSE_TARGETS_PER_BATCH;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse_nomination::ReverseCandidateSet as RustReverseCandidateSet;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_core::analyzer::usages::model::UsageHit;

use brokk_bifrost_core::analyzer::usages::model::UsageProof;

use brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

use brokk_bifrost_analysis::analyzer::usages::traits::PreparedUsageQuery;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

#[derive(Default)]
pub struct RustNativeUsageStrategy;

impl RustNativeUsageStrategy {
    pub const fn new() -> Self {
        Self
    }
}

/// What the prepare phase enumerated, kept for the find phase to borrow.
///
/// The candidate sets are the expensive part of a reverse query: enumerating
/// one walks the target's export, import and glob routes through SQL. Prepare
/// runs in its own selected operation and find in another, so a find that
/// enumerated again would pay for every set twice. The sets are plain data,
/// not handles into the prepare operation.
///
/// Each operation captures the project's analysis generation when it opens and
/// checks it again when it finishes, but nothing carries one operation's value
/// to the other. The candidate sets hold locators and topology ids that mean
/// something only under the generation they were enumerated in, so the find
/// phase asserts that its operation captured the same one. Request analyzers
/// use frozen snapshots and disk projects report 0, so a mismatch is a broken
/// design assumption, not an input to handle.
struct PreparedNativeUsageQuery {
    /// The analysis generation the prepare operation captured.
    generation: u64,
    /// The distinct overloads prepared, in order; `candidate_sets` is parallel.
    targets: Vec<CodeUnit>,
    candidate_sets: Vec<RustReverseCandidateSet>,
    files: HashSet<ProjectFile>,
}

impl GraphUsageAnalyzer for RustNativeUsageStrategy {
    /// The selected native inventory carries real proof tiers: a site this
    /// strategy retains as unproven, or a candidate it drops from the totals,
    /// is a gap in a list it claims to enumerate completely.
    fn proof_authority(&self) -> UsageProofAuthority {
        UsageProofAuthority::Native
    }

    fn prepare_usage_query(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        _candidate_files: &HashSet<ProjectFile>,
        cancellation: &CancellationToken,
    ) -> Option<Box<dyn PreparedUsageQuery>> {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        let targets = unique_targets(overloads);
        let RustSelectedReverseOutcome::Ready((generation, Some(candidate_sets))) =
            with_rust_selected_reverse_queries(rust, cancellation, |queries| {
                Ok((
                    queries.analysis_generation(),
                    queries.candidate_sets(&targets)?,
                ))
            })
        else {
            return None;
        };
        let root = rust.inner.project().root();
        let files = targets
            .iter()
            .zip(&candidate_sets)
            .flat_map(|(target, set)| set.files(root, target))
            .collect();
        Some(Box::new(PreparedNativeUsageQuery {
            generation,
            targets,
            candidate_sets,
            files,
        }))
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        with_native_rust(analyzer, overloads, |rust| {
            find_native_usages(rust, overloads, scan_scope, max_usages)
        })
    }
}

impl PreparedUsageQuery for PreparedNativeUsageQuery {
    fn candidate_files(&self) -> &HashSet<ProjectFile> {
        &self.files
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        with_native_rust(analyzer, overloads, |rust| {
            execute_native_usages_with(
                rust,
                overloads,
                scan_scope,
                max_usages,
                |queries, targets| {
                    assert_eq!(
                        targets,
                        self.targets.as_slice(),
                        "the find phase answers the overloads the prepare phase enumerated"
                    );
                    assert_eq!(
                        queries.analysis_generation(),
                        self.generation,
                        "the candidate sets were enumerated under another analysis generation \
                         than the find operation captured: the project moved between the \
                         prepare and find operations, so the sets' locators and topology ids \
                         may be stale"
                    );
                    Ok(Some(self.candidate_sets.as_slice()))
                },
            )
            .outcome
        })
    }
}

/// Run `find` on the selected Rust analyzer, or say why there is none.
fn with_native_rust(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    find: impl FnOnce(&RustAnalyzer) -> GraphUsageOutcome,
) -> GraphUsageOutcome {
    let Some(primary) = overloads.first() else {
        return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
    };
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return DIAGNOSTICS.failure(
            primary,
            "native_resolution_unavailable",
            "selected Rust analyzer is unavailable".into(),
        );
    };
    find(rust)
}

const DIAGNOSTICS: NativeUsageDiagnostics = NativeUsageDiagnostics {
    strategy: "rust_native",
    cancelled_reason: "native usage query was cancelled",
};

/// Preserve canonical target buckets, proofs and editor reference roles. Only
/// the outer selected-operation outcome can release the provisional result.
#[doc(hidden)]
pub fn find_native_usages(
    rust: &RustAnalyzer,
    targets: &[CodeUnit],
    scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> GraphUsageOutcome {
    execute_native_usages(rust, targets, scope, max_usages).outcome
}

struct NativeUsageExecution {
    outcome: GraphUsageOutcome,
    #[cfg(test)]
    work: NativeUsageWork,
}

/// Observation only; neither provisional work nor its absence authorizes an
/// answer. Prefix/topology construction, SQL and source admission are excluded.
#[cfg(test)]
#[derive(Debug, Default, PartialEq, Eq)]
struct NativeUsageWork {
    reverse: crate::analyzer::rust::selected_reverse::RustSelectedReverseWork,
    /// Successful source reads on snippet cache misses, including a source
    /// later rejected by the authority check. Failed read attempts are excluded.
    snippet_sources: Vec<ProjectFile>,
}

/// Answer without prepared sets: each target's set is enumerated once, inside
/// the same selected operation that queries it.
fn execute_native_usages(
    rust: &RustAnalyzer,
    targets: &[CodeUnit],
    scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> NativeUsageExecution {
    execute_native_usages_with(rust, targets, scope, max_usages, |queries, targets| {
        queries.candidate_sets(targets)
    })
}

/// `sets_for` yields the sets of the distinct targets, in order: either
/// enumerated inside the operation, or borrowed from a prepare phase.
fn execute_native_usages_with<Sets: AsRef<[RustReverseCandidateSet]>>(
    rust: &RustAnalyzer,
    targets: &[CodeUnit],
    scope: &UsageScanScope<'_>,
    max_usages: usize,
    sets_for: impl FnOnce(
        &mut dyn RustSelectedReverseQueries,
        &[CodeUnit],
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<Sets>>,
) -> NativeUsageExecution {
    #[cfg(test)]
    let mut work = NativeUsageWork::default();
    let outcome = (|| {
        let Some(primary) = targets.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let fallback_cancellation = CancellationToken::new();
        let cancellation = scope.cancellation().unwrap_or(&fallback_cancellation);
        let targets = unique_targets(targets);
        let outcome = with_rust_selected_reverse_queries_in_files(
            rust,
            scope.candidate_files(),
            cancellation,
            |queries| {
                let result = (|| {
                    let Some(candidate_sets) = sets_for(&mut *queries, &targets)? else {
                        return Ok(None);
                    };
                    let candidate_sets = candidate_sets.as_ref();
                    assert_eq!(
                        targets.len(),
                        candidate_sets.len(),
                        "every distinct target has one candidate set"
                    );
                    let mut pending = NativeUsagePending::new(&targets);
                    let mut target_start = 0;
                    for target_batch in targets.chunks(MAX_REVERSE_TARGETS_PER_BATCH) {
                        let Some(answers) = queries.inverse_for_candidates(
                            target_batch,
                            &candidate_sets[target_start..target_start + target_batch.len()],
                        )?
                        else {
                            return Ok(None);
                        };
                        assert_eq!(target_batch.len(), answers.len());
                        for (batch_offset, (target, answer)) in
                            target_batch.iter().zip(answers).enumerate()
                        {
                            let target_index = target_start + batch_offset;
                            if let EdgeCompleteness::Incomplete { reasons } = &answer.completeness {
                                pending.diagnostics.push(DIAGNOSTICS.diagnostic(
                                    target,
                                    if reasons.contains(
                                        &brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason::TimeBudgetExceeded,
                                    ) {
                                        "time_budget"
                                    } else {
                                        "native_reference_inventory_incomplete"
                                    },
                                    format!(
                                        "selected reference enumeration is incomplete: {reasons:?}"
                                    ),
                                ));
                            }
                            if let ControlFlow::Break(()) = pending
                                .queue_target_edges::<RustUsageProjection<'_, '_>>(
                                    target_index,
                                    answer.edges,
                                    scope,
                                    cancellation,
                                )
                            {
                                return Ok(None);
                            }
                            if (target.is_class() || target.is_field())
                                && let Some(implementations) = rust
                                    .rust_trait_member_implementations(target)
                                    .map_err(|error| {
                                        brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                                    "Rust trait member implementation lookup failed for {}: {error:?}",
                                            target.fq_name()
                                        ))
                                    })?
                            {
                                for implementation in implementations {
                                    let file = implementation.source().clone();
                                    if !scope.allows(&file) {
                                        continue;
                                    }
                                    for range in rust.ranges_of(&implementation) {
                                        pending.push(file.clone(),
                                            NativeUsageSite {
                                                target_index,
                                                hit: UsageHit::new(file.clone(), range.start_line, range.start_byte, range.end_byte, implementation.clone(), 1.0, "").into_override_declaration(),
                                                origin: NativeUsageOrigin::SupplementalDeclaration,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                        target_start += target_batch.len();
                    }

                    let syntax_scope = AnalyzerQueryScope::with_cancellation(rust, cancellation);
                    let mut projection = RustUsageProjection {
                        rust,
                        queries: &mut *queries,
                        syntax_scope: &syntax_scope,
                        cancellation,
                        #[cfg(test)]
                        snippet_sources: &mut work.snippet_sources,
                    };
                    project_pending_files(&mut projection, pending, scope, max_usages, cancellation)
                })();
                #[cfg(test)]
                {
                    work.reverse = queries.work_report();
                }
                result
            },
        );
        let (kind, reason) = match outcome {
            RustSelectedReverseOutcome::Ready(Some(result)) => {
                return GraphUsageOutcome::Resolved(result);
            }
            RustSelectedReverseOutcome::Ready(None) => {
                assert!(
                    cancellation.is_cancelled(),
                    "stopped native usage is not publishable"
                );
                return DIAGNOSTICS.cancelled(primary);
            }
            RustSelectedReverseOutcome::Cancelled => return DIAGNOSTICS.cancelled(primary),
            RustSelectedReverseOutcome::Stale(reason) => ("stale_selected_source", reason),
            RustSelectedReverseOutcome::Unavailable(reason) => {
                ("native_resolution_unavailable", reason)
            }
            RustSelectedReverseOutcome::StoreError(reason) => ("native_store_error", reason),
        };
        DIAGNOSTICS.failure(primary, kind, reason)
    })();
    NativeUsageExecution {
        outcome,
        #[cfg(test)]
        work,
    }
}

struct RustUsageProjection<'a, 'scope> {
    rust: &'a RustAnalyzer,
    queries: &'a mut dyn RustSelectedReverseQueries,
    syntax_scope: &'a AnalyzerQueryScope<'scope>,
    cancellation: &'a CancellationToken,
    #[cfg(test)]
    snippet_sources: &'a mut Vec<ProjectFile>,
}

impl NativeUsageProjection for RustUsageProjection<'_, '_> {
    type Context =
        std::sync::Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>;
    type Error = brokk_bifrost_analysis::analyzer::store::StoreError;

    fn admit_edge(
        target: &CodeUnit,
        edge: &brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceEdgeRow,
        scope: &UsageScanScope<'_>,
    ) -> bool {
        assert_eq!(&edge.target, target);
        assert!(scope.allows(&edge.site.file));
        true
    }
    fn load_file(
        &mut self,
        file: &ProjectFile,
        _pending: &[NativeUsageSite],
    ) -> Result<NativeUsageFile<Self::Context>, Self::Error> {
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::SelectedNativeSourceError;
        let source = self
            .rust
            .inner
            .selected_native_usage_source(file, || {
                #[cfg(test)]
                if _pending
                    .iter()
                    .any(|hit| hit.origin == NativeUsageOrigin::ReferenceEdge)
                {
                    self.snippet_sources.push(file.clone());
                }
            })
            .map_err(|error| {
                brokk_bifrost_analysis::analyzer::store::StoreError::new(match error {
                    SelectedNativeSourceError::Unavailable => {
                        format!("selected usage source is unavailable for {file}")
                    }
                    SelectedNativeSourceError::Stale => {
                        format!("selected usage source changed for {file}")
                    }
                })
            })?;
        let prepared = self
            .rust
            .prepared_syntax(self.syntax_scope.token(), file)
            .ok_or_else(|| {
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "selected usage syntax is unavailable for {file}"
                ))
            })?;
        if prepared.source() != source {
            return Err(brokk_bifrost_analysis::analyzer::store::StoreError::new(
                format!("selected usage syntax source changed for {file}"),
            ));
        }

        Ok(NativeUsageFile::new(source, prepared))
    }

    fn presentation(
        &mut self,
        file: &ProjectFile,
        loaded: &NativeUsageFile<Self::Context>,
        _target: &CodeUnit,
        site: &mut NativeUsageSite,
    ) -> Result<NativeUsageAdmission, Self::Error> {
        let activation = crate::analyzer::rust::site_activation::rust_site_activation(
            Some(loaded.context.tree()),
            &loaded.source,
            site.hit.start_offset..site.hit.end_offset,
            |condition| {
                self.queries.rust_cfg_activation_for_caller_under_site_cfg(
                    file.rel_path(),
                    condition,
                    self.cancellation,
                )
            },
        )?;
        let Some(activation) = activation else {
            return Ok(NativeUsageAdmission::Stopped);
        };
        let (proof, reason_kind) = match activation {
            crate::analyzer::rust::site_activation::RustSiteActivation::NoNode => {
                return Err(brokk_bifrost_analysis::analyzer::store::StoreError::new(
                    format!(
                        "Rust usage hit has no syntax node: {file}:{}..{}",
                        site.hit.start_offset, site.hit.end_offset
                    ),
                ));
            }
            crate::analyzer::rust::site_activation::RustSiteActivation::Inactive => {
                return Ok(NativeUsageAdmission::Excluded);
            }
            crate::analyzer::rust::site_activation::RustSiteActivation::Active => {
                (site.hit.proof, None)
            }
            crate::analyzer::rust::site_activation::RustSiteActivation::Unknown { .. } => {
                (UsageProof::Unproven, Some("unknown_activation"))
            }
        };

        site.hit.proof = proof;
        site.hit.reason_kind = reason_kind.map(str::to_owned);
        Ok(NativeUsageAdmission::Retain)
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::native_usages::*;
    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::Language;

    /// A definition whose only reference arrives through the crate root's own
    /// exposure -- a glob import, or a named barrel re-export -- must be
    /// answered, and the answer must not depend on whether the crate root
    /// opens with a blank line.
    ///
    /// Lane REV isolated this as a complete empty reverse answer. The cause
    /// was neither the reverse nor the exposure: a file-scope import's owner
    /// extent was measured from the source text (`0..len`) while the file's
    /// root module scope was measured from the parse tree, whose `source_file`
    /// node starts at the first token. In a file that opens with a blank line
    /// the two disagreed by one byte, `selected_context` found no owner scope
    /// for the import, and dropped its root route, its bridge and every
    /// reference that arrives through it -- in both directions.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "76ae6f046f6d: root exposure, rather than file bytes, owns file-scope imports"
    )]
    fn native_usage_follows_root_exposure_whatever_the_root_file_opens_with() {
        for lead in ["", "\n", "\n\n", "// root\n"] {
            for (label, files) in [
                (
                    "glob",
                    vec![
                        (
                            "src/lib.rs",
                            format!(
                                "{lead}mod service;\nuse crate::service::*;\npub fn run() {{ let _ = Foo; let _ = Hidden; }}\n"
                            ),
                        ),
                        (
                            "src/service.rs",
                            "pub struct Foo;\nstruct Hidden;\n".to_owned(),
                        ),
                    ],
                ),
                (
                    "barrel",
                    vec![
                        (
                            "src/lib.rs",
                            format!("{lead}mod service;\nmod consumer;\npub use service::Foo;\n"),
                        ),
                        (
                            "src/consumer.rs",
                            "use crate::Foo;\npub fn run() { let _ = Foo; }\n".to_owned(),
                        ),
                        ("src/service.rs", "pub struct Foo;\n".to_owned()),
                    ],
                ),
            ] {
                let label = format!("{label}/{}", lead.escape_debug());
                let mut builder = InlineTestProject::with_language(Language::Rust).file(
                    "Cargo.toml",
                    "[package]\nname = \"exposure\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                );
                for (path, source) in &files {
                    builder = builder.file(path, source.clone());
                }
                let fixture = builder.build();
                let rust = RustAnalyzer::from_project(fixture.project().clone());
                let target = rust
                    .declarations(&fixture.file("src/service.rs"))
                    .into_iter()
                    .find(|unit| unit.identifier() == "Foo")
                    .expect("target declaration");
                let admitted = rust
                    .get_analyzed_files()
                    .into_iter()
                    .collect::<HashSet<_>>();
                let outcome = find_native_usages(
                    &rust,
                    std::slice::from_ref(&target),
                    &UsageScanScope::new(&admitted),
                    100,
                );
                let GraphUsageOutcome::Resolved(result) = outcome else {
                    panic!("{label}: native usage must resolve: {outcome:?}");
                };
                let FuzzyResult::Success { .. } = &result else {
                    panic!("{label}: the answer must be complete: {result:?}");
                };
                let value_sites = result
                    .all_hits()
                    .into_iter()
                    .filter(|hit| hit.proof == UsageProof::Proven)
                    .map(|hit| (hit.file.rel_path().to_path_buf(), hit.line))
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    value_sites.len(),
                    1,
                    "{label}: exactly the exposure-reached use site is proven: {result:?}"
                );
            }
        }
    }

    /// The usages path enumerates each target's candidate set once. Prepare
    /// and find are separate selected operations, and find used to enumerate
    /// the same sets again: four enumerations for a two-target request.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "9e0ebc694953: the usages path enumerated every candidate set in prepare and again in find"
    )]
    fn the_usages_path_enumerates_each_targets_candidate_set_once() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::candidate_set_enumerations_for_test;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::reset_candidate_set_enumerations_for_test;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"usage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub mod api;\nuse crate::api::{first, second};\npub fn caller() { first(); second(); }\n")
            .file("src/api.rs", "pub fn first() {}\npub fn second() {}\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let targets = ["first", "second"].map(|name| {
            rust.declarations(&fixture.file("src/api.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == name)
                .unwrap()
        });
        let admitted = HashSet::from_iter([fixture.file("src/lib.rs")]);

        reset_candidate_set_enumerations_for_test();
        let prepared = RustNativeUsageStrategy
            .prepare_usage_query(
                &rust,
                &targets,
                &HashSet::default(),
                &CancellationToken::new(),
            )
            .expect("native Rust candidate inventory");
        assert_eq!(candidate_set_enumerations_for_test(), 2, "prepare");
        let result =
            prepared.find_graph_usages(&rust, &targets, &UsageScanScope::new(&admitted), 10);
        assert_eq!(
            candidate_set_enumerations_for_test(),
            2,
            "find borrows the prepared sets"
        );
        let GraphUsageOutcome::Resolved(result @ FuzzyResult::Success { .. }) = result else {
            panic!("both calls must resolve: {result:?}");
        };
        assert_eq!(result.all_hits().len(), 2, "{result:?}");

        reset_candidate_set_enumerations_for_test();
        let unprepared = find_native_usages(&rust, &targets, &UsageScanScope::new(&admitted), 10);
        assert_eq!(
            candidate_set_enumerations_for_test(),
            2,
            "without a prepare phase, find enumerates once itself"
        );
        let GraphUsageOutcome::Resolved(unprepared @ FuzzyResult::Success { .. }) = unprepared
        else {
            panic!("both calls must resolve: {unprepared:?}");
        };
        assert_eq!(unprepared.all_hits().len(), 2, "{unprepared:?}");
    }

    /// The prepared sets are valid only under the generation they were
    /// enumerated in. A live overlay project, unlike the frozen snapshots
    /// requests use, can move between the prepare and find operations.
    #[test]
    #[should_panic(expected = "the project moved between the prepare and find operations")]
    fn a_find_under_a_moved_generation_does_not_use_the_prepared_sets() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"usage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn target() {}\npub fn caller() { target(); }\n",
            )
            .build();
        let overlay = std::sync::Arc::new(
            brokk_bifrost_core::analyzer::project::OverlayProject::new(fixture.project_dyn()),
        );
        let rust = RustAnalyzer::new(fixture.project_dyn()).clone_with_project(overlay.clone());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        let admitted = HashSet::from_iter([fixture.file("src/lib.rs")]);
        let prepared = RustNativeUsageStrategy
            .prepare_usage_query(
                &rust,
                std::slice::from_ref(&target),
                &HashSet::default(),
                &CancellationToken::new(),
            )
            .expect("native Rust candidate inventory");
        assert!(overlay.set(fixture.file("notes.txt").abs_path(), "moved\n".to_owned()));
        prepared.find_graph_usages(
            &rust,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&admitted),
            10,
        );
    }

    #[test]
    fn native_usage_work_materializes_target_sites_without_decoy_sources_or_duplicate_demands() {
        // Match #2112: unrelated imports share the target's defining file, so
        // file admission and target declaration inventory legitimately grow.
        // This pins actual projection work, not topology, SQL or admission cost.
        for decoy_count in [0, 32] {
            let mut target_source = "pub struct UnsizedHandler;\n".to_owned();
            let mut lib_source = "pub mod target;\npub mod consumer;\n".to_owned();
            let mut builder = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"native_work\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .file(
                    "src/consumer.rs",
                    "use crate::target::UnsizedHandler;\npub fn make() { let _ = UnsizedHandler; }\n",
                );
            let mut decoys = Vec::new();
            for index in 0..decoy_count {
                let path = format!("src/decoy_{index}.rs");
                target_source.push_str(&format!("pub struct Other{index};\n"));
                lib_source.push_str(&format!("pub mod decoy_{index};\n"));
                builder = builder.file(
                    &path,
                    format!(
                        "use crate::target::Other{index};\npub fn make() {{ let _ = Other{index}; }}\n"
                    ),
                );
                decoys.push(path);
            }
            let fixture = builder
                .file("src/lib.rs", lib_source)
                .file("src/target.rs", target_source)
                .build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let target = rust
                .declarations(&fixture.file("src/target.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "UnsizedHandler")
                .expect("target declaration");
            // Admit every Rust file, including all decoys. An excluded file
            // cannot make this source-materialization regression pass vacuously.
            let admitted = rust
                .get_analyzed_files()
                .into_iter()
                .collect::<HashSet<_>>();
            assert_eq!(admitted.len(), decoy_count + 3);
            for path in &decoys {
                assert!(admitted.contains(&fixture.file(path)));
            }
            let scope = UsageScanScope::new(&admitted);
            let single = execute_native_usages(&rust, std::slice::from_ref(&target), &scope, 1000);
            let repeated =
                execute_native_usages(&rust, &[target.clone(), target.clone()], &scope, 1000);
            let GraphUsageOutcome::Resolved(single_result @ FuzzyResult::Success { .. }) =
                single.outcome
            else {
                panic!("native target query must complete: {:?}", single.outcome);
            };
            let GraphUsageOutcome::Resolved(repeated_result @ FuzzyResult::Success { .. }) =
                repeated.outcome
            else {
                panic!(
                    "duplicate target query must complete: {:?}",
                    repeated.outcome
                );
            };
            let hits = single_result.all_hits();
            assert_eq!(hits.len(), 1, "{hits:?}");
            assert!(
                hits.iter()
                    .all(|hit| hit.file == fixture.file("src/consumer.rs")
                        && hit.proof == UsageProof::Proven)
            );
            let (
                FuzzyResult::Success {
                    hits_by_overload: single_hits,
                    unproven_by_overload: single_unproven,
                    unproven_total_by_overload: single_totals,
                },
                FuzzyResult::Success {
                    hits_by_overload: repeated_hits,
                    unproven_by_overload: repeated_unproven,
                    unproven_total_by_overload: repeated_totals,
                },
            ) = (&single_result, &repeated_result)
            else {
                unreachable!("both outcomes were checked above")
            };
            assert_eq!(
                (single_hits, single_unproven, single_totals),
                (repeated_hits, repeated_unproven, repeated_totals),
                "duplicate targets preserve all result evidence"
            );
            assert_eq!(
                single.work, repeated.work,
                "duplicate targets must perform the same measured native work"
            );
            assert_eq!(
                single.work.reverse.definition_mount_reads, 1,
                "one persisted target mount is actually loaded: {:?}",
                single.work
            );
            assert_eq!(
                single.work.reverse.targets.len(),
                1,
                "one canonical target query: {:?}",
                single.work
            );
            let (measured_target, metrics) = &single.work.reverse.targets[0];
            assert_eq!(measured_target, &target);
            assert!(metrics.demanded_definition_count() > 0, "{metrics:?}");
            assert!(metrics.raw_reverse_batch_count() > 0, "{metrics:?}");
            assert!(metrics.issued_reference_seed_count() > 0, "{metrics:?}");
            assert!(metrics.published_reference_count() > 0, "{metrics:?}");
            let allowed = HashSet::from_iter([
                fixture.file("src/lib.rs"),
                fixture.file("src/target.rs"),
                fixture.file("src/consumer.rs"),
            ]);
            for files in [
                &single.work.reverse.classification_sources,
                &single.work.snippet_sources,
            ] {
                let distinct = files.iter().collect::<HashSet<_>>();
                assert!(
                    distinct.len() <= 3,
                    "projection materialized too many files: {files:?}"
                );
                assert_eq!(
                    distinct.len(),
                    files.len(),
                    "a phase must materialize each source only once: {files:?}"
                );
                assert!(
                    files.contains(&fixture.file("src/consumer.rs")),
                    "consumer source must actually be materialized: {files:?}"
                );
                assert!(
                    files.iter().all(|file| allowed.contains(file)),
                    "unrelated imports must not materialize decoy source: {files:?}"
                );
            }
        }
    }

    #[test]
    fn native_usage_keeps_foreign_targets_editor_roles_and_admitted_inventory() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"usage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub mod api;\npub mod hidden;\nuse crate::api::target;\npub fn caller() { target(); }\n")
            .file("src/api.rs", "pub fn target() {}\n")
            .file("src/hidden.rs", "unknown_macro!();\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/api.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        let admitted = HashSet::from_iter([fixture.file("src/lib.rs")]);
        let prepared = RustNativeUsageStrategy
            .prepare_usage_query(
                &rust,
                std::slice::from_ref(&target),
                &HashSet::default(),
                &CancellationToken::new(),
            )
            .expect("native Rust candidate inventory");
        assert!(
            prepared
                .candidate_files()
                .contains(&fixture.file("src/lib.rs"))
        );
        assert!(
            !prepared
                .candidate_files()
                .contains(&fixture.file("src/hidden.rs"))
        );
        let result = prepared.find_graph_usages(
            &rust,
            &[target.clone(), target.clone()],
            &UsageScanScope::new(&admitted),
            10,
        );
        let GraphUsageOutcome::Resolved(result @ FuzzyResult::Success { .. }) = result else {
            panic!("admitted caller must have complete native usages: {result:?}");
        };
        assert_eq!(result.all_hits().len(), 1, "{result:?}");
        assert!(
            result
                .all_hits_including_imports()
                .iter()
                .any(|hit| hit.kind
                    == brokk_bifrost_core::analyzer::usages::model::UsageHitKind::Import),
            "{result:?}"
        );
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = result
        else {
            unreachable!()
        };
        assert_eq!(hits_by_overload.len(), 1);
        assert!(
            hits_by_overload[&target].iter().all(
                |hit| hit.file == fixture.file("src/lib.rs") && hit.proof == UsageProof::Proven
            )
        );
    }

    /// A reverse request is not narrowed by the forward crate scope.
    ///
    /// A forward Rust request binds only inside its crate's dependency
    /// closure, and `temp.selected_resolution_scope_mounts` is what enforces
    /// that. The reverse question is the opposite one -- which references
    /// elsewhere point at this definition -- and its answers live in crates
    /// that depend on the definition's, never in its dependencies. The reverse
    /// routes therefore never narrow that scope, and this is the pin: a usage
    /// of a provider crate's function, written in a crate that depends on it,
    /// is still found.

    #[test]
    fn native_usage_retains_proven_calls_without_certifying_incomplete_inventory() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"usage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            // A module mount keeps the token tree unenumerable; a bare `unknown_macro!()`
            // no longer leaves the reference inventory incomplete.
            .file("src/lib.rs", "pub fn target() {}\npub fn caller() { target(); }\npub fn opaque() { unknown_macro! { mod generated; } }\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        let admitted = HashSet::from_iter([fixture.file("src/lib.rs")]);
        let result = find_native_usages(&rust, &[target], &UsageScanScope::new(&admitted), 10);
        let GraphUsageOutcome::Resolved(result @ FuzzyResult::Incomplete { .. }) = result else {
            panic!("native inventory gap must remain explicit: {result:?}");
        };
        assert_eq!(result.all_hits().len(), 1, "{result:?}");
        assert!(
            result
                .all_hits()
                .iter()
                .all(|hit| hit.proof == UsageProof::Proven)
        );
        assert!(result.into_either().is_err());
    }

    #[test]
    fn a_reverse_request_still_finds_a_usage_in_a_dependent_crate() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['provider','consumer']\nresolver='2'\n",
            )
            .file(
                "provider/Cargo.toml",
                "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("provider/src/lib.rs", "pub fn target() {}\n")
            .file(
                "consumer/Cargo.toml",
                "[package]\nname='consumer'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={path='../provider'}\n",
            )
            .file(
                "consumer/src/lib.rs",
                "use provider::target;\npub fn caller() { target(); }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let target = rust
            .declarations(&fixture.file("provider/src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("the provider declares target");
        let admitted = HashSet::from_iter([fixture.file("consumer/src/lib.rs")]);
        let prepared = RustNativeUsageStrategy
            .prepare_usage_query(
                &rust,
                std::slice::from_ref(&target),
                &HashSet::default(),
                &CancellationToken::new(),
            )
            .expect("native Rust candidate inventory");
        assert!(
            prepared
                .candidate_files()
                .contains(&fixture.file("consumer/src/lib.rs")),
            "the dependent crate's file is a reverse candidate: {:?}",
            prepared.candidate_files()
        );
        let result = prepared.find_graph_usages(
            &rust,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&admitted),
            10,
        );
        let GraphUsageOutcome::Resolved(result @ FuzzyResult::Success { .. }) = result else {
            panic!("a usage in a dependent crate must resolve: {result:?}");
        };
        assert!(
            result
                .all_hits()
                .iter()
                .any(|hit| hit.file == fixture.file("consumer/src/lib.rs")
                    && hit.proof == UsageProof::Proven),
            "the call in the dependent crate is a proven hit: {result:?}"
        );
    }

    #[test]
    fn native_usage_cancellation_and_hit_cap_never_publish_complete_empty_results() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"usage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
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
            .find(|unit| unit.identifier() == "target")
            .unwrap();
        let admitted = HashSet::from_iter([fixture.file("src/lib.rs")]);
        let execution = execute_native_usages(
            &rust,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&admitted),
            0,
        );
        assert_eq!(execution.work.reverse.targets.len(), 1);
        assert!(!execution.work.snippet_sources.is_empty());
        let result = execution.outcome;
        assert!(
            matches!(
                result,
                GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites { limit: 0, .. })
            ),
            "{result:?}"
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let execution = execute_native_usages(
            &rust,
            &[target],
            &UsageScanScope::with_cancellation(&admitted, &cancellation),
            10,
        );
        assert_eq!(execution.work, NativeUsageWork::default());
        let result = execution.outcome;
        assert!(
            matches!(result, GraphUsageOutcome::TerminalFailure(ref diagnostic) if diagnostic.reason_kind == "cancelled"),
            "{result:?}"
        );
    }
}

#[cfg(test)]
mod receiver_route_agreement_tests {

    use crate::analyzer::rust::native_usages::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use crate::analyzer::rust::native_graph::RustNativeWorkspaceGraphOutcome;

    use crate::analyzer::rust::native_graph::build_rust_native_workspace_graph_for_files;
    use crate::inline_project::InlineTestProject;

    /// The forward workspace projection must not disprove a call site the
    /// reverse route keeps as unproven.
    ///
    /// DC-C: `project_fact_reference_target` mapped a callable binding with no
    /// targets to status `Complete`, so `value.activate()` on a receiver whose
    /// member set the route never enumerated left no trace in the graph --
    /// no edge, no unproven count, no gap -- and the bulk dead-code bucket
    /// proved the target dead from a graph that could not represent the doubt.
    /// The reverse route calls the same site unproven. The two routes are
    /// checked here against one another on both receiver shapes, so neither can
    /// drift into disproving a site the other retains.
    ///
    /// The routes do not agree on a count. The reverse names the target it was
    /// asked about and can retain a site for it by name; the forward enumerates
    /// a site's targets and has none to name, so it reports the gap instead of
    /// an unproven row. That asymmetry is the reverse index's name-keyed
    /// nomination, not a projection defect, and it is why this asserts the
    /// forward abstains rather than that it counts.
    ///
    /// The third shape was once a decided absence: a receiver resolved to one
    /// exact type whose indexed impls lack the member. That premise was wrong.
    /// Rust cannot close a nominal type's member surface -- a blanket impl
    /// (which leaves no crate row), a derive, a `Deref` target or a trait from
    /// an unindexed crate can each supply the member -- and the producer
    /// declares the surface open for every qualified reference. So the forward
    /// answer is an open boundary with its reason named, the reverse keeps the
    /// site unproven, and the two routes still agree. What the rows can prove
    /// stays decided: a module-qualified call names the module's items, which
    /// are all rows (`a_method_the_indexed_rows_cannot_supply_is_an_open_boundary`).
    #[test]
    fn neither_route_disproves_a_call_site_whose_receiver_it_cannot_resolve() {
        for (label, receiver_source, unproven_sites) in [
            (
                "trait-object receiver",
                "trait Runner {}\n\nfn execute(value: Box<dyn Runner>) {\n    value.activate();\n}\n",
                1,
            ),
            (
                "generic receiver",
                "fn execute<T>(value: T) {\n    value.activate();\n}\n",
                1,
            ),
            (
                "exact receiver without the member",
                "pub struct Other {}\n\nfn execute(value: Other) {\n    value.activate();\n}\n",
                1,
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"receiver_agreement\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .file("src/lib.rs", "pub mod service;\n")
                .file(
                    "src/service.rs",
                    format!(
                        "pub struct Service {{}}\n\nimpl Service {{\n    pub fn activate(&self) {{}}\n}}\n\n{receiver_source}"
                    ),
                )
                .build();
            let rust = RustAnalyzer::from_project(fixture.project().clone());
            let target = rust
                .declarations(&fixture.file("src/service.rs"))
                .into_iter()
                .find(|unit| unit.identifier() == "activate")
                .expect("target declaration");
            let admitted = rust
                .get_analyzed_files()
                .into_iter()
                .collect::<HashSet<_>>();

            let outcome = find_native_usages(
                &rust,
                std::slice::from_ref(&target),
                &UsageScanScope::new(&admitted),
                100,
            );
            let GraphUsageOutcome::Resolved(reverse) = outcome else {
                panic!("{label}: the reverse route must resolve: {outcome:?}");
            };
            let unproven = match &reverse {
                FuzzyResult::Success {
                    unproven_total_by_overload,
                    ..
                }
                | FuzzyResult::Incomplete {
                    unproven_total_by_overload,
                    ..
                } => unproven_total_by_overload.values().sum::<usize>(),
                other => panic!("{label}: unexpected reverse answer: {other:?}"),
            };
            assert_eq!(
                unproven, unproven_sites,
                "{label}: the reverse route's unproven site count: {reverse:?}"
            );

            let roots = admitted.iter().cloned().collect::<Vec<_>>();
            let projection = build_rust_native_workspace_graph_for_files(
                &rust,
                &roots,
                64,
                &CancellationToken::new(),
            )
            .expect("workspace graph projection");
            let projection = match (projection, unproven_sites) {
                (RustNativeWorkspaceGraphOutcome::Incomplete(projection), 1) => projection,
                (RustNativeWorkspaceGraphOutcome::Complete(projection), 0) => projection,
                (RustNativeWorkspaceGraphOutcome::Incomplete(projection), _)
                | (RustNativeWorkspaceGraphOutcome::Complete(projection), _) => panic!(
                    "{label}: the forward projection must abstain exactly where the reverse keeps a site unproven: {:?}",
                    projection.forward_completeness
                ),
                _ => panic!("{label}: the forward projection must be available"),
            };
            assert!(
                projection.edges.iter().all(|edge| {
                    projection.nodes[edge.to].primary.declaration_id() != target.declaration_id()
                }),
                "{label}: an unresolved receiver must not produce a proven edge to activate; independent parameter-type references remain valid: {:?}",
                projection
                    .edges
                    .iter()
                    .map(|edge| (
                        &projection.nodes[edge.from].primary,
                        &projection.nodes[edge.to].primary,
                    ))
                    .collect::<Vec<_>>()
            );
        }
    }
}
