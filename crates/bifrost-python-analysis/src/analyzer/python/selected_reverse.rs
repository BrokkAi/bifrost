//! Request-local native reverse projection shared by usages and selected inverse.
//!
//! Inverse queries use all selected Python files with the reverse scan-site and
//! session budgets. They impose no separate file-count budget; usages admission
//! applies M1's file/source budgets before consuming its prepared result.

use super::{
    PythonAnalyzer,
    native_request::{PythonNativeOpen, open_python_native_request},
};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::python_reverse::{
    PythonNativeReverseResult, PythonReverseLimits,
};
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError};
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
use brokk_bifrost_core::analyzer::structural::edges::{EdgeProvenance, OwnerRelation, SiteClass};
use brokk_bifrost_core::analyzer::usages::model::{UsageHitKind, UsageProof};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use brokk_bifrost_core::cancellation::CancellationToken;
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
                let range = projected.state.range(site.start, site.end);
                let owner = python.enclosing_code_unit(&file, &range);
                let owner_relation =
                    classify_owner_relation(python, owner.as_ref(), &target.target);
                let mut edge = ReferenceEdgeRow {
                    site: EdgeSite {
                        file: file.clone(),
                        range,
                        ast_id: classifier.ast_id(site.start, site.end),
                        enclosing: owner,
                    },
                    target: target.target.clone(),
                    reference_kind: classifier.classify_reference_kind(
                        site.start,
                        site.end,
                        &target.target,
                    ),
                    proof: if site.certain && !site.potential && !site.undecided {
                        UsageProof::Proven
                    } else {
                        UsageProof::Unproven
                    },
                    ambiguous_candidate: false,
                    usage_kind: if owner_relation == OwnerRelation::SelfReference {
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
        let session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(cancellation));
        let result = request
            .operation
            .python_reverse_targets(
                &request.environment,
                std::slice::from_ref(target),
                &scope,
                PythonReverseLimits::default(),
                &session,
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
            for kind in [
                "python_environment_open",
                "python_unknown_placement",
                "python_dynamic_receiver_mutation_open",
            ] {
                let obligations = projected
                    .query_obligations
                    .iter()
                    .filter(|label| label.starts_with(kind))
                    .collect::<Vec<_>>();
                if obligations.is_empty() {
                    continue;
                }
                let reason = EdgeIncompleteReason::UsageAnalysisFailed {
                    reason_kind: kind.into(),
                    reason: format!("{obligations:?}"),
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

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: Lane R review found that an undecided candidate demoted a certain site of the same target"
    )]
    fn certain_site_stays_proven_when_another_candidate_is_undecided() {
        if !super::super::trial_native_python_selected() {
            return;
        }
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
        if !super::super::trial_native_python_selected() {
            return;
        }
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
    fn scan_stop_retains_unprocessed_targets_and_sites() {
        if !super::super::trial_native_python_selected() {
            return;
        }
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
}
