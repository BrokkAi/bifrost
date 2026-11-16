//! Request-local native reverse projection shared by usages and selected inverse.
//!
//! Inverse queries use all selected Python files with the reverse scan-site and
//! per-caller confirmation budgets. They impose no separate file-count budget;
//! usages admission applies M1's file/source budgets before consuming its prepared result.

use super::{
    PythonAnalyzer,
    native_request::{PythonNativeOpen, open_python_native_request},
};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::python_reverse::{
    PythonNativeReverseResult, PythonReverseLimits,
};
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError};
use brokk_bifrost_analysis::analyzer::store_bridge::fact_reference_edges::fact_reference_receiver_channels;
use brokk_bifrost_analysis::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, EdgeSite, ReferenceEdgeRow,
    SelectedInverseIndexOutcome, SelectedInverseReferenceProvider, SelectedReferenceFileProjection,
    classify_owner_relation,
};
use brokk_bifrost_analysis::analyzer::structural::selected_inverse::{
    LazySelectedInverse, SelectedInverseAdapter, SelectedInverseFailure,
};
use brokk_bifrost_analysis::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::structural::edges::{EdgeProvenance, SiteClass};
use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;
#[cfg(test)]
use brokk_bifrost_core::analyzer::usages::model::UsageProof;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(super) struct PythonReverseProjection {
    pub targets: Vec<(CodeUnit, EdgeDerivationResult)>,
    pub query_obligations: Vec<String>,
}

/// One conversion for both consumers. Site proof is independent of target completeness.
pub(super) fn project_reverse(
    python: &PythonAnalyzer,
    result: PythonNativeReverseResult,
) -> Result<PythonReverseProjection> {
    let generation = python.inner.project().analysis_generation();
    let mut answers = Vec::new();
    // "Cannot answer this target" and "did not reach it because the batch
    // stopped" are different facts for a consumer, so they keep distinct kinds.
    let missing = result
        .unavailable
        .into_iter()
        .map(|target| (target, "python_reverse_target_unavailable"))
        .chain(
            result
                .unprocessed
                .into_iter()
                .map(|target| (target, "python_reverse_target_unprocessed")),
        );
    for (missing, reason_kind) in missing {
        answers.push((
            missing.target,
            EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::UsageAnalysisFailed {
                    reason_kind: reason_kind.into(),
                    reason: missing.reason,
                }],
                EdgeProvenance::Inverse,
                generation,
            ),
        ));
    }
    for target in result.targets {
        let mut reasons = Vec::new();
        if !target.complete {
            reasons.push(EdgeIncompleteReason::UsageAnalysisFailed {
                reason_kind: "python_reverse_inventory_incomplete".into(),
                reason: format!("{:?}", target.obligations),
            });
        }
        let mut files = BTreeMap::<_, Vec<_>>::new();
        for site in target.sites.into_iter().filter(|site| !site.excluded) {
            files.entry(site.path.clone()).or_default().push(site);
        }
        let definition_spans = python
            .ranges(&target.target)
            .into_iter()
            .map(|range| (target.target.source().clone(), range))
            .collect::<Vec<_>>();
        let declaration_sites = definition_spans
            .iter()
            .map(|(_, range)| (range.start_byte, range.end_byte))
            .collect::<HashSet<_>>();
        let mut edges = Vec::new();
        for (path, sites) in files {
            let file = ProjectFile::new(python.inner.project().root(), path);
            let projected =
                SelectedReferenceFileProjection::new(python, python, &file, |source| {
                    python
                        .inner
                        .source_matches_selected_native_content(&file, source)
                })?;
            let Some(classifier) = projected.state.classifier.as_ref() else {
                return Err(StoreError::new(format!(
                    "selected Python reference facts unavailable: {file}"
                )));
            };
            for site in sites {
                // A receiver assignment's admitted field declaration is the
                // attribute token itself. Its RHS read has a distinct range.
                if target.target.is_field()
                    && file == *target.target.source()
                    && declaration_sites.contains(&(site.start, site.end))
                {
                    continue;
                }
                // Query-wide environment assumptions stay in diagnostics; only
                // obligations attached to this site can block its edge proof.
                let obligations_outstanding = !site.obligations.is_empty();
                let (proof, obligations_block_proof) = brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::selected_reverse_proof(
                    site.certain && !site.potential && !site.undecided,
                    obligations_outstanding,
                );
                if obligations_block_proof
                    && !reasons
                        .contains(&EdgeIncompleteReason::InverseIndexQueryObligationsOutstanding)
                {
                    reasons.push(EdgeIncompleteReason::InverseIndexQueryObligationsOutstanding);
                }
                let range = projected.state.range(site.start, site.end);
                let owner = python.enclosing_code_unit(&file, &range);
                let owner_relation =
                    classify_owner_relation(python, owner.as_ref(), &target.target);
                let mut edge = ReferenceEdgeRow {
                    dispatch_extensibility: None,
                    site: EdgeSite {
                        file: file.clone(),
                        range,
                        ast_id: classifier.ast_id(site.start, site.end),
                        enclosing: owner,
                    },
                    target: target.target.clone(),
                    reference_kind: classifier.classify_reference_facets(
                        site.start,
                        site.end,
                        &target.target,
                    ),
                    proof,
                    ambiguous_candidate: false,
                    usage_kind: if classifier
                        .is_import_binding_reference(&file, site.start, site.end)
                    {
                        UsageHitKind::Import
                    } else if site.receiver_origins.iter().any(|origin| {
                        fact_reference_receiver_channels(Some(*origin)).includes_self_receiver()
                    }) {
                        UsageHitKind::SelfReceiver
                    } else {
                        UsageHitKind::Reference
                    },
                    site_class: SiteClass::UseSite,
                    owner_relation,
                    provenance: EdgeProvenance::Inverse,
                    generation,
                };
                edge.classify_target_self_reference(&definition_spans);
                edges.push(edge);
            }
        }
        answers.push((
            target.target,
            EdgeDerivationResult {
                edges,
                completeness: if reasons.is_empty() {
                    EdgeCompleteness::Complete
                } else {
                    EdgeCompleteness::Incomplete { reasons }
                },
                provenance: EdgeProvenance::Inverse,
                generation,
            },
        ));
    }
    Ok(PythonReverseProjection {
        targets: answers,
        query_obligations: result.query_obligations,
    })
}

pub(super) fn open_failure(open: PythonNativeOpen<'_>) -> SelectedInverseFailure {
    match open {
        PythonNativeOpen::Unavailable {
            kind: "native_stale",
            message,
        } => SelectedInverseFailure::Stale(format!("native_stale: {message}")),
        PythonNativeOpen::Unavailable { kind, message } => {
            SelectedInverseFailure::Unavailable(format!("{kind}: {message}"))
        }
        PythonNativeOpen::Cancelled => SelectedInverseFailure::Cancelled,
        PythonNativeOpen::Ready(_) => unreachable!("ready request is not a failure"),
    }
}

struct PythonInverseAdapter {
    python: Box<PythonAnalyzer>,
}
impl SelectedInverseAdapter for PythonInverseAdapter {
    fn admit(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(u64, Self), SelectedInverseFailure> {
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer).ok_or_else(|| {
            SelectedInverseFailure::Unavailable("selected Python analyzer unavailable".into())
        })?;
        match open_python_native_request(python, cancellation)
            .map_err(|error| SelectedInverseFailure::StoreError(error.to_string()))?
        {
            PythonNativeOpen::Ready(_) => {}
            other => return Err(open_failure(other)),
        }
        Ok((
            python.inner.project().analysis_generation(),
            Self {
                python: Box::new(python.clone()),
            },
        ))
    }
    fn current_generation(&self) -> u64 {
        self.python.inner.project().analysis_generation()
    }
    fn query(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Option<EdgeDerivationResult>, SelectedInverseFailure> {
        let python = &self.python;
        let request = match open_python_native_request(python, cancellation)
            .map_err(|error| SelectedInverseFailure::StoreError(error.to_string()))?
        {
            PythonNativeOpen::Ready(request) => request,
            other => return Err(open_failure(other)),
        };
        let files = python.analyzed_files().into_iter().collect();
        let scope = UsageScanScope::with_cancellation(&files, cancellation);
        let result = request
            .operation
            .python_reverse_targets_in_scope(
                &request.environment,
                std::slice::from_ref(target),
                &scope,
                PythonReverseLimits::default(),
            )
            .map_err(|error| SelectedInverseFailure::StoreError(error.to_string()))?;
        if cancellation.is_cancelled() {
            return Err(SelectedInverseFailure::Cancelled);
        }
        if !result.unavailable.is_empty() {
            return Ok(None);
        }
        let projected = project_reverse(python, result)
            .map_err(|error| SelectedInverseFailure::StoreError(error.to_string()))?;
        Ok(projected.targets.into_iter().next().map(|(_, mut answer)| {
            for obligation in &projected.query_obligations {
                let kind = obligation
                    .split_once(':')
                    .map_or(obligation.as_str(), |(kind, _)| kind);
                if super::query_reason_is_scope(kind) {
                    continue;
                }
                let reason = EdgeIncompleteReason::UsageAnalysisFailed {
                    reason_kind: kind.into(),
                    reason: obligation.clone(),
                };
                match &mut answer.completeness {
                    EdgeCompleteness::Complete => {
                        answer.completeness = EdgeCompleteness::Incomplete {
                            reasons: vec![reason],
                        };
                    }
                    EdgeCompleteness::Incomplete { reasons } => reasons.push(reason),
                }
            }
            answer
        }))
    }
}

pub(super) struct PythonNativeSelectedInverseProvider;
impl SelectedInverseReferenceProvider for PythonNativeSelectedInverseProvider {
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
    ) -> SelectedInverseIndexOutcome {
        let cancellation = cancellation.cloned().unwrap_or_default();
        match LazySelectedInverse::<PythonInverseAdapter>::build(analyzer, &cancellation) {
            Ok(index) => SelectedInverseIndexOutcome::Ready(Arc::new(index)),
            Err(failure) => failure.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::Language;
    use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
    use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::{
        PythonSummaryCoverage, PythonUncoveredCause,
    };
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: Lane R review found that an undecided candidate demoted a certain site of the same target"
    )]
    fn certain_site_stays_proven_when_another_candidate_is_undecided() {
        let fixture = InlineTestProject::with_language(Language::Python)
            .file("model.py", "def pick(): pass\n")
            .file(
                "client.py",
                "from model import pick\npick()\ndef candidate(obj, name):\n    return getattr(obj, \"pi\" + name)\n",
            )
            .build();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let file = ProjectFile::new(fixture.root(), "model.py");
        let target = python
            .top_level_declarations(&file)
            .into_iter()
            .find(|target| target.short_name() == "pick")
            .unwrap();
        let cancellation = CancellationToken::new();
        let PythonNativeOpen::Ready(request) =
            open_python_native_request(python, &cancellation).unwrap()
        else {
            panic!("native fixture must open");
        };
        let files = python.analyzed_files().into_iter().collect();
        let scope = UsageScanScope::with_cancellation(&files, &cancellation);
        let result = request
            .operation
            .python_reverse_targets(
                &request.environment,
                std::slice::from_ref(&target),
                &scope,
                PythonReverseLimits::default(),
                &ResolutionSession::unbounded(),
            )
            .unwrap();
        assert_eq!(result.targets.len(), 1);
        let answer = &result.targets[0];
        assert!(!answer.complete);
        assert!(answer.sites.iter().any(|site| site.undecided));
        assert!(
            answer.sites.iter().any(|site| {
                site.certain && !site.potential && !site.undecided && !site.excluded
            }),
            "{}",
            result.render()
        );
        let projected = project_reverse(python, result).unwrap();
        let (_, answer) = &projected.targets[0];
        assert!(!answer.completeness.is_complete());
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.proof == UsageProof::Proven)
        );
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.proof == UsageProof::Unproven)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: Lane R review found that every unknown-name member operation nominated every target"
    )]
    fn unknown_member_names_do_not_nominate_but_matching_prefixes_do() {
        let fixture = InlineTestProject::with_language(Language::Python)
            .file(
                "sample.py",
                "def matching(): pass\ndef unrelated(): pass\ndef probe(obj, name):\n    getattr(obj, name)\n    getattr(obj, \"mat\" + name)\n",
            )
            .build();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let file = ProjectFile::new(fixture.root(), "sample.py");
        let declarations = python.top_level_declarations(&file);
        let targets = ["matching", "unrelated"].map(|name| {
            declarations
                .iter()
                .find(|target| target.short_name() == name)
                .unwrap()
                .clone()
        });
        let cancellation = CancellationToken::new();
        let PythonNativeOpen::Ready(request) =
            open_python_native_request(python, &cancellation).unwrap()
        else {
            panic!("native fixture must open");
        };
        let files = python.analyzed_files().into_iter().collect();
        let scope = UsageScanScope::with_cancellation(&files, &cancellation);
        let result = request
            .operation
            .python_reverse_targets(
                &request.environment,
                &targets,
                &scope,
                PythonReverseLimits::default(),
                &ResolutionSession::unbounded(),
            )
            .unwrap();
        assert_eq!(result.targets.len(), 2, "both target queries must run");
        let matching = result
            .targets
            .iter()
            .find(|answer| answer.target == targets[0])
            .unwrap();
        assert_eq!(
            matching.sites.len(),
            1,
            "only the matching prefix nominates a site"
        );
        assert!(matching.sites[0].undecided);
        assert!(!matching.sites[0].certain);
        let unrelated = result
            .targets
            .iter()
            .find(|answer| answer.target == targets[1])
            .unwrap();
        assert!(
            unrelated.sites.is_empty(),
            "an unknown name does not reference an unrelated target"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "b3230a984acc: #5658 reverse budget exhaustion lost its named cause"
    )]
    fn scan_stop_retains_unprocessed_targets_and_sites() {
        let fixture = InlineTestProject::with_language(Language::Python)
            .file("model.py", "class Widget: pass\nclass Other: pass\n")
            .file("a.py", "from model import Widget\nx = Widget()\n")
            .file("b.py", "from model import Widget\ny = Widget()\n")
            .build();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let file = ProjectFile::new(fixture.root(), "model.py");
        let declarations = python.top_level_declarations(&file);
        let targets = ["Widget", "Other"].map(|name| {
            declarations
                .iter()
                .find(|target| target.short_name() == name)
                .unwrap()
                .clone()
        });
        let cancellation = CancellationToken::new();
        let PythonNativeOpen::Ready(request) =
            open_python_native_request(python, &cancellation).unwrap()
        else {
            panic!("native fixture must open");
        };
        let files = python.analyzed_files().into_iter().collect();
        let scope = UsageScanScope::with_cancellation(&files, &cancellation);
        let bounded = ResolutionSession::bounded(
            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..Default::default()
            },
            Some(&cancellation),
        );
        let stopped = request
            .operation
            .python_reverse_targets(
                &request.environment,
                &targets,
                &scope,
                PythonReverseLimits::default(),
                &bounded,
            )
            .unwrap();
        assert!(!stopped.targets[0].complete);
        assert!(
            stopped.targets[0].obligations.iter().any(|reason| {
                reason == "python_reverse_resolution_budget_exceeded:scope_nodes"
            })
        );
        let session = ResolutionSession::unbounded();
        let result = request
            .operation
            .python_reverse_targets(
                &request.environment,
                &targets,
                &scope,
                PythonReverseLimits { max_sites: 1 },
                &session,
            )
            .unwrap();
        assert_eq!(result.targets.len(), 1, "first target must actually run");
        assert_eq!(
            result.targets[0]
                .sites
                .iter()
                .filter(|site| !site.excluded)
                .count(),
            1
        );
        assert!(!result.targets[0].complete);
        assert!(result.nominated_paths.iter().any(|path| path == "a.py"));
        assert!(result.nominated_paths.iter().any(|path| path == "b.py"));
        assert_eq!(result.unprocessed.len(), 1);
        assert_eq!(result.unprocessed[0].target, targets[1]);
        assert_eq!(result.unprocessed[0].reason, "python_reverse_scan_limit");
        let projected = project_reverse(python, result).unwrap();
        assert_eq!(projected.query_obligations.len(), 1);
        let answers = projected.targets;
        assert_eq!(answers.len(), 2);
        assert!(
            answers
                .iter()
                .all(|(_, answer)| !answer.completeness.is_complete())
        );
        let (_, answer) = answers
            .iter()
            .find(|(target, _)| target == &targets[0])
            .unwrap();
        assert!(!answer.edges.is_empty());
        assert_eq!(answer.edges.len(), 1);
        let (_, unprocessed) = answers
            .iter()
            .find(|(target, _)| target == &targets[1])
            .unwrap();
        assert!(unprocessed.edges.is_empty());
        let EdgeCompleteness::Incomplete { reasons } = &unprocessed.completeness else {
            panic!("an unprocessed target must be incomplete");
        };
        assert!(
            matches!(
                reasons.as_slice(),
                [EdgeIncompleteReason::UsageAnalysisFailed { reason_kind, reason }]
                    if reason_kind == "python_reverse_target_unprocessed"
                        && reason == "python_reverse_scan_limit"
            ),
            "{reasons:?}"
        );
    }

    /// What a reverse query for `model.pick` reports after unsaved edits.
    struct OverlayReverse {
        coverage: PythonSummaryCoverage,
        complete: bool,
        obligations: Vec<String>,
        /// Paths of every retained (not excluded) site, sorted.
        sites: Vec<String>,
        positions: Vec<String>,
    }

    fn overlay_fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Python)
            .file("model.py", "def pick(): pass\n")
            .file(
                "client.py",
                "from model import pick\ndef run():\n    pick()\n",
            )
            .file(
                "other.py",
                "from model import pick\ndef run():\n    pick()\n",
            )
            .build()
    }

    fn reverse_pick(workspace: &WorkspaceAnalyzer, root: &std::path::Path) -> OverlayReverse {
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let target = python
            .top_level_declarations(&ProjectFile::new(root, "model.py"))
            .into_iter()
            .find(|target| target.short_name() == "pick")
            .unwrap();
        let cancellation = CancellationToken::new();
        let PythonNativeOpen::Ready(request) =
            open_python_native_request(python, &cancellation).unwrap()
        else {
            panic!("native fixture must open");
        };
        let files = python.analyzed_files().into_iter().collect();
        let scope = UsageScanScope::with_cancellation(&files, &cancellation);
        let result = request
            .operation
            .python_reverse_targets(
                &request.environment,
                std::slice::from_ref(&target),
                &scope,
                PythonReverseLimits::default(),
                &ResolutionSession::unbounded(),
            )
            .unwrap();
        let answer = &result.targets[0];
        let mut sites = answer
            .sites
            .iter()
            .filter(|site| !site.excluded)
            .map(|site| site.path.clone())
            .collect::<Vec<_>>();
        sites.sort();
        sites.dedup();
        let mut positions = answer
            .sites
            .iter()
            .filter(|site| !site.excluded)
            .map(|site| format!("{}:{}..{}", site.path, site.start, site.end))
            .collect::<Vec<_>>();
        positions.sort();
        OverlayReverse {
            positions,
            coverage: request.environment.coverage.clone(),
            complete: answer.complete,
            obligations: answer.obligations.clone(),
            sites,
        }
    }

    fn overlay_reverse(edits: &[(&str, &str)]) -> OverlayReverse {
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        let fixture = overlay_fixture();
        let base =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        for (name, source) in edits {
            assert!(overlay.set(fixture.file(name).abs_path(), (*source).to_owned()));
        }
        let workspace = base.clone_with_project(Arc::new(overlay.snapshot()));
        reverse_pick(&workspace, fixture.root())
    }

    fn mentions(answer: &OverlayReverse, label: &str) -> bool {
        answer
            .obligations
            .iter()
            .any(|obligation| obligation.contains(label))
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11536: an overlay replacement absent from the persisted Python summary panicked reverse nomination"
    )]
    fn overlay_surface_change_stays_a_required_context_and_reports_the_uncovered_member() {
        let answer = overlay_reverse(&[(
            "client.py",
            "from model import pick\ndef run():\n    pick()\ndef added(): pass\n",
        )]);
        assert_eq!(
            answer.coverage.uncovered(),
            [("client.py".to_owned(), PythonUncoveredCause::InputChanged)]
        );
        assert!(answer.coverage.retained().is_empty());
        assert!(!answer.complete);
        assert!(
            mentions(&answer, "python_summary_uncovered:client.py:input_changed"),
            "{:?}",
            answer.obligations
        );
        // Both callers stay represented: the replaced one is nominated and keeps
        // its context, the unchanged one is not dropped.
        assert_eq!(answer.sites, ["client.py", "other.py"]);
    }

    #[test]
    fn overlay_with_equal_member_input_is_retained_and_joinable() {
        let answer = overlay_reverse(&[(
            "client.py",
            "from model import pick\ndef run():\n    pick()\n    pick()\n",
        )]);
        assert_eq!(answer.coverage.retained(), ["client.py"]);
        assert!(answer.coverage.uncovered().is_empty());
        assert!(answer.complete, "{:?}", answer.obligations);
        assert!(answer.coverage.unusable().is_empty());
        assert_eq!(answer.sites, ["client.py", "other.py"]);
    }

    #[test]
    fn covered_comment_overlay_matches_cold_edited_content() {
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        let fixture = overlay_fixture();
        let base =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let edited = "# moved positions\n\nfrom model import pick\ndef run():\n    pick()\n";
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(fixture.file("client.py").abs_path(), edited.to_owned()));
        let snapshot: Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            Arc::new(overlay.snapshot());
        let warm = base.clone_with_project(Arc::clone(&snapshot));
        let cold =
            WorkspaceAnalyzer::build_ephemeral_footgun(snapshot, Default::default()).unwrap();
        let warm = reverse_pick(&warm, fixture.root());
        let cold = reverse_pick(&cold, fixture.root());
        assert_eq!(warm.coverage.retained(), ["client.py"]);
        let start = edited.rfind("pick()").unwrap();
        assert!(
            warm.positions
                .contains(&format!("client.py:{start}..{}", start + 4)),
            "{:?}",
            warm.positions
        );
        assert!(warm.complete, "{:?}", warm.obligations);
        assert_eq!(
            (warm.complete, warm.sites, warm.positions),
            (cold.complete, cold.sites, cold.positions)
        );

        // A function-local import is a row of the member's surface (the
        // imports relation), so adding one inside a body changes the
        // MemberInput fingerprint: the replacement is not covered, and the
        // answer stays incomplete instead of reusing the persisted rows,
        // which do not list the new import.
        let edited = "from model import pick\ndef run():\n    pick()\n    from model import pick\n    pick()\n";
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(fixture.file("client.py").abs_path(), edited.to_owned()));
        let snapshot: Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            Arc::new(overlay.snapshot());
        let warm = reverse_pick(&base.clone_with_project(snapshot), fixture.root());
        assert!(
            warm.coverage.retained().is_empty(),
            "a new function-local import must not be covered: {:?}",
            warm.coverage.retained()
        );
        assert!(!warm.complete, "{:?} {:?}", warm.sites, warm.obligations);
    }

    #[test]
    fn overlay_added_file_is_represented_and_incomplete() {
        let answer = overlay_reverse(&[(
            "added.py",
            "from model import pick\ndef run():\n    pick()\n",
        )]);
        assert_eq!(
            answer.coverage.uncovered(),
            [("added.py".to_owned(), PythonUncoveredCause::Added)]
        );
        assert!(!answer.complete);
        assert!(mentions(&answer, "python_summary_uncovered:added.py:added"));
        assert_eq!(answer.sites, ["added.py", "client.py", "other.py"]);
    }

    #[test]
    fn removed_path_keeps_the_mask_obligation() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
            SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionOverlayMask,
        };
        let fixture = overlay_fixture();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::new();
        let mut environment = {
            let PythonNativeOpen::Ready(request) =
                open_python_native_request(python, &cancellation).unwrap()
            else {
                panic!("native fixture must open")
            };
            request.environment
        };
        let snapshots = python.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("python", Language::Python)];
        let masks = [SelectedResolutionOverlayMask::removal(
            "python",
            "client.py",
        )];
        let input = SelectedResolutionOperationInput::new(
            python.inner.project(),
            python.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_analyzer(python);
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = python
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("removal selection must open")
        };
        environment.coverage = operation
            .python_summary_coverage(environment.summary)
            .unwrap();
        assert_eq!(
            environment.coverage.uncovered(),
            [("client.py".to_owned(), PythonUncoveredCause::Removed)]
        );
        assert_eq!(environment.coverage.unusable(), [("client.py", "removed")]);
        let target = python
            .top_level_declarations(&fixture.file("model.py"))
            .into_iter()
            .find(|target| target.short_name() == "pick")
            .unwrap();
        let files = python.analyzed_files().into_iter().collect();
        let scope = UsageScanScope::with_cancellation(&files, &cancellation);
        let result = operation
            .python_reverse_targets(
                &environment,
                &[target],
                &scope,
                PythonReverseLimits::default(),
                &ResolutionSession::unbounded(),
            )
            .unwrap();
        assert!(!result.targets[0].complete);
        assert!(
            result.targets[0]
                .obligations
                .iter()
                .any(|reason| reason.contains("python_summary_uncovered:client.py:removed")),
            "{:?}",
            result.targets[0].obligations
        );
    }

    /// Definition of the `pick()` call in `client.py` after unsaved edits:
    /// (targets, binding is complete, named reason details).
    fn overlay_definition(edits: &[(&str, &str)]) -> (usize, bool, Vec<String>) {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
            SelectedResolutionLocated, SelectedResolutionOperationOutcome,
        };
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
        let fixture = overlay_fixture();
        let base =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        let mut client = "from model import pick\ndef run():\n    pick()\n".to_owned();
        for (name, source) in edits {
            assert!(overlay.set(fixture.file(name).abs_path(), (*source).to_owned()));
            if *name == "client.py" {
                client = (*source).to_owned();
            }
        }
        let workspace = base.clone_with_project(Arc::new(overlay.snapshot()));
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::new();
        let PythonNativeOpen::Ready(mut request) =
            open_python_native_request(python, &cancellation).unwrap()
        else {
            panic!("native fixture must open");
        };
        let start = client.rfind("pick()").unwrap();
        let outcome = request
            .operation
            .python_definition_at(
                &request.environment,
                &ProjectFile::new(fixture.root(), "client.py"),
                start..start + "pick".len(),
                &ResolutionSession::unbounded(),
            )
            .unwrap();
        let BoundedResolution::Complete {
            value:
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)),
            ..
        } = outcome
        else {
            panic!("the definition query answers");
        };
        let binding = answer.reference.answer.binding();
        (
            binding.targets().len(),
            binding.completion()
                == &brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete,
            answer
                .reference
                .named_reasons
                .iter()
                .map(|(kind, detail)| format!("{kind}:{detail}"))
                .collect(),
        )
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11536: a definition query in an overlay-replaced file answered Complete with no definition"
    )]
    fn definition_in_an_overlay_replaced_file_is_incomplete_not_absent() {
        let (targets, complete, _) = overlay_definition(&[]);
        assert_eq!((targets, complete), (1, true), "control: no overlay");
        let (targets, complete, reasons) = overlay_definition(&[(
            "client.py",
            "# comment\nfrom model import pick\ndef run():\n    pick()\n",
        )]);
        assert_eq!((targets, complete), (1, true), "{reasons:?}");
        let (_, complete, reasons) = overlay_definition(&[(
            "client.py",
            "from model import pick\ndef added(): pass\ndef run():\n    pick()\n",
        )]);
        assert!(!complete, "an uncovered file cannot answer Complete");
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("python_summary_uncovered:client.py:input_changed")),
            "{reasons:?}"
        );
    }

    /// The product definition entry for the `pick()` call in `client.py`.
    fn overlay_definition_status(edit: Option<&str>) -> (DefinitionLookupStatus, usize) {
        use super::super::native_request::definition_lookup::PythonReceiverRequest;
        use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
        use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
        let fixture = overlay_fixture();
        let base =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        let mut client = "from model import pick\ndef run():\n    pick()\n".to_owned();
        if let Some(edit) = edit {
            assert!(overlay.set(fixture.file("client.py").abs_path(), edit.to_owned()));
            client = edit.to_owned();
        }
        let workspace = base.clone_with_project(Arc::new(overlay.snapshot()));
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::new();
        let file = ProjectFile::new(fixture.root(), "client.py");
        let start = client.rfind("pick()").unwrap();
        let site = ResolvedReferenceSite {
            path: "client.py".into(),
            text: "pick".into(),
            range: brokk_bifrost_core::analyzer::Range {
                start_byte: start,
                end_byte: start + 4,
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start,
            focus_end_byte: start + 4,
        };
        let mut request = PythonReceiverRequest::open(python, &cancellation);
        let BoundedResolution::Complete {
            value: (outcome, _),
            ..
        } = request.resolve_definition_with_call_evidence_bounded(BoundedReceiverQuery {
            analyzer: workspace.analyzer(),
            file: &file,
            source: &client,
            tree: None,
            site: &site,
            budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
            cancellation: Some(&cancellation),
        })
        else {
            panic!("the definition lookup answers");
        };
        (outcome.status, outcome.definitions.len())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11536: the product definition lookup in an overlay-replaced file reported a resolved or empty answer"
    )]
    fn product_definition_lookup_in_an_overlay_replaced_file_is_not_resolved() {
        let (status, definitions) = overlay_definition_status(None);
        assert_eq!((status, definitions), (DefinitionLookupStatus::Resolved, 1));
        let (status, definitions) = overlay_definition_status(Some(
            "from model import pick\ndef added(): pass\ndef run():\n    pick()\n",
        ));
        assert_eq!(
            (status, definitions),
            (DefinitionLookupStatus::Incomplete, 0)
        );
    }

    /// The store-level definition answer for the last `needle` in `client.py` after
    /// unsaved edits of other files: (binding complete, keyword outcome,
    /// selected external imports, definitions).
    fn definition_with_overlay(
        files: &[(&str, &str)],
        edits: &[(&str, &str)],
        needle: &str,
    ) -> (bool, &'static str, usize, usize) {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
            SelectedNativeDefinitions, SelectedNativeNamedArgument, SelectedResolutionLocated,
            SelectedResolutionOperationOutcome,
        };
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
        let mut builder = InlineTestProject::with_language(Language::Python);
        for (name, source) in files {
            builder = builder.file(*name, *source);
        }
        let fixture = builder.build();
        let base =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        for (name, source) in edits {
            assert!(overlay.set(fixture.file(name).abs_path(), (*source).to_owned()));
        }
        let workspace = base.clone_with_project(Arc::new(overlay.snapshot()));
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::new();
        let PythonNativeOpen::Ready(mut request) =
            open_python_native_request(python, &cancellation).unwrap()
        else {
            panic!("native fixture must open");
        };
        let client = files
            .iter()
            .find(|(name, _)| *name == "client.py")
            .unwrap()
            .1;
        let start = client.rfind(needle).unwrap();
        let outcome = request
            .operation
            .python_definition_at(
                &request.environment,
                &ProjectFile::new(fixture.root(), "client.py"),
                start..start + needle.len(),
                &ResolutionSession::unbounded(),
            )
            .unwrap();
        let BoundedResolution::Complete {
            value:
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)),
            ..
        } = outcome
        else {
            panic!("the definition query answers");
        };
        let keyword = match &answer.reference.named_argument {
            None => "none",
            Some(SelectedNativeNamedArgument::Resolved(..)) => "resolved",
            Some(SelectedNativeNamedArgument::Incomplete(_)) => "incomplete",
            Some(SelectedNativeNamedArgument::Absent(_)) => "absent",
        };
        let definitions = match &answer.reference.definitions {
            SelectedNativeDefinitions::Ready(units) => units.len(),
            _ => usize::MAX,
        };
        (
            answer.reference.answer.binding().completion()
                == &brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete,
            keyword,
            answer.selected_external_imports.len(),
            definitions,
        )
    }

    // Another file's new surface leaves the summary stale for every consumer.
    const OTHER: (&str, &str) = ("other.py", "x = 1\n");
    const OTHER_EDIT: (&str, &str) = ("other.py", "x = 1\ny = 2\n");

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11536: a keyword argument definition bypassed the coverage obligation"
    )]
    fn keyword_definition_carries_the_coverage_obligation() {
        let files = [
            ("model.py", "def pick(option=1): pass\n"),
            (
                "client.py",
                "from model import pick\ndef run():\n    pick(option=1)\n",
            ),
            OTHER,
        ];
        let (complete, keyword, _, definitions) = definition_with_overlay(&files, &[], "option");
        assert_eq!(
            (complete, keyword, definitions),
            (true, "resolved", 0),
            "control"
        );
        let (complete, keyword, _, _) = definition_with_overlay(&files, &[OTHER_EDIT], "option");
        assert!(!complete);
        assert_eq!(
            keyword, "incomplete",
            "a keyword definition is never Resolved or Absent"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11536: an uncovered summary still admitted an external import identity"
    )]
    fn external_import_definition_carries_the_coverage_obligation() {
        let files = [("client.py", "import numpy\nnumpy.array()\n"), OTHER];
        let (_, _, imports, _) = definition_with_overlay(&files, &[], "numpy");
        assert_eq!(
            imports, 1,
            "control: the unchanged provider-open import is admitted"
        );
        let (complete, _, imports, _) = definition_with_overlay(&files, &[OTHER_EDIT], "numpy");
        assert!(!complete);
        assert_eq!(
            imports, 0,
            "an uncovered summary cannot admit an external identity"
        );
    }

    #[test]
    fn refreshing_the_edited_file_recovers_summary_coverage() {
        let fixture = overlay_fixture();
        let base =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let before = reverse_pick(&base, fixture.root());
        assert!(before.coverage.unusable().is_empty());
        let edited = "from model import pick\ndef run():\n    pick()\ndef added(): pass\n";
        std::fs::write(fixture.file("client.py").abs_path(), edited).unwrap();
        let refreshed = base.update(&std::collections::BTreeSet::from([
            fixture.file("client.py")
        ]));
        let after = reverse_pick(&refreshed, fixture.root());
        assert!(after.coverage.unusable().is_empty());
        assert!(!mentions(&after, "python_summary_uncovered"));
        assert_eq!(after.sites, before.sites);
    }
}
