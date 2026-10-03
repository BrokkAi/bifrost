//! Test-support route for native Go forward usage over selected reverse rows.

use super::GoAnalyzer;
use super::selected_reverse::{GoSelectedReverseOutcome, go_selected_inverse_for};
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::structural::reference_edges::EdgeCompleteness;
use crate::analyzer::usages::UsageProof;
use crate::analyzer::usages::outcome::GraphUsageOutcome;
use crate::analyzer::usages::{
    FuzzyResult, GraphUsageAnalyzer, UsageAnalysisDiagnostic, UsageHit, UsageHitSurface,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, resolve_analyzer};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use std::collections::BTreeSet;

/// Native Go forward-usage discovery through the selected reference index.
/// The type is test-support only until the Go consumer cutover is approved.
#[derive(Default)]
pub struct GoNativeUsageStrategy;

impl GoNativeUsageStrategy {
    pub const fn new() -> Self {
        Self
    }
}

impl GraphUsageAnalyzer for GoNativeUsageStrategy {
    fn proof_authority(&self) -> crate::analyzer::usages::UsageProofAuthority {
        crate::analyzer::usages::UsageProofAuthority::Native
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(primary) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return GraphUsageOutcome::TerminalFailure(diagnostic(
                primary,
                "native_resolution_unavailable",
                "selected Go analyzer is unavailable".into(),
            ));
        };
        let cancellation = scan_scope.cancellation().cloned().unwrap_or_default();
        let mut hits_by_overload = HashMap::default();
        let mut unproven_by_overload = HashMap::default();
        let mut unproven_total_by_overload = HashMap::default();
        let mut diagnostics = Vec::new();
        let mut external_hits = BTreeSet::new();
        let mut sources = HashMap::<ProjectFile, (String, Box<[usize]>)>::default();
        let mut seen_targets = HashSet::default();
        for target in overloads {
            if !seen_targets.insert(target) {
                continue;
            }
            if cancellation.is_cancelled() {
                return GraphUsageOutcome::TerminalFailure(diagnostic(
                    primary,
                    "cancelled",
                    "native Go usage query was cancelled".into(),
                ));
            }
            let answer = match go_selected_inverse_for(go, target, &cancellation) {
                GoSelectedReverseOutcome::Ready(answer) => answer,
                GoSelectedReverseOutcome::Unavailable(reason) => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "native_resolution_unavailable",
                        reason,
                    ));
                }
                GoSelectedReverseOutcome::Stale(reason) => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "stale_selected_source",
                        reason,
                    ));
                }
                GoSelectedReverseOutcome::Cancelled => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "cancelled",
                        "native Go usage query was cancelled".into(),
                    ));
                }
                GoSelectedReverseOutcome::StoreError(reason) => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "native_store_error",
                        reason,
                    ));
                }
            };
            if let EdgeCompleteness::Incomplete { reasons } = &answer.completeness {
                diagnostics.push(diagnostic(
                    target,
                    "native_reference_inventory_incomplete",
                    format!("selected Go reference inventory is incomplete: {reasons:?}"),
                ));
            }
            let mut hits = BTreeSet::new();
            let mut unproven = BTreeSet::new();
            for edge in answer.edges {
                if cancellation.is_cancelled() {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "cancelled",
                        "native Go usage query was cancelled".into(),
                    ));
                }
                if !scan_scope.allows(&edge.site.file) {
                    continue;
                }
                if !sources.contains_key(&edge.site.file) {
                    let Some(source) = go.indexed_source(&edge.site.file) else {
                        return GraphUsageOutcome::TerminalFailure(diagnostic(
                            primary,
                            "native_source_unavailable",
                            format!(
                                "selected Go usage source is unavailable: {}",
                                edge.site.file
                            ),
                        ));
                    };
                    if !go
                        .inner
                        .source_matches_selected_native_content(&edge.site.file, &source)
                    {
                        return GraphUsageOutcome::TerminalFailure(diagnostic(
                            primary,
                            "stale_selected_source",
                            format!("selected Go usage source changed: {}", edge.site.file),
                        ));
                    }
                    let line_starts = compute_line_starts(&source).into_boxed_slice();
                    sources.insert(edge.site.file.clone(), (source, line_starts));
                }
                let (source, line_starts) = sources
                    .get(&edge.site.file)
                    .expect("selected Go usage source was admitted");
                let snippet = crate::text_utils::trimmed_snippet_around_line(
                    source,
                    line_starts,
                    edge.site.range.start_line.saturating_sub(1),
                    0,
                );
                let owner = edge
                    .site
                    .enclosing
                    .clone()
                    .unwrap_or_else(|| CodeUnit::file_scope(edge.site.file.clone()));
                let mut hit = UsageHit::new(
                    edge.site.file,
                    edge.site.range.start_line,
                    edge.site.range.start_byte,
                    edge.site.range.end_byte,
                    owner,
                    if edge.proof == UsageProof::Proven {
                        1.0
                    } else {
                        0.0
                    },
                    snippet,
                );
                hit.kind = edge.usage_kind;
                hit.proof = edge.proof;
                hit.reference_kind = edge.reference_kind;
                if hit.proof == UsageProof::Proven {
                    if hit.kind.included_in(UsageHitSurface::ExternalUsages) {
                        external_hits.insert(hit.clone());
                    }
                    hits.insert(hit);
                } else {
                    unproven.insert(hit);
                }
            }
            let FuzzyResult::Success {
                hits_by_overload: proven,
                unproven_by_overload: uncertain,
                unproven_total_by_overload: totals,
            } = FuzzyResult::success_with_unproven(target.clone(), hits, unproven)
            else {
                unreachable!("success constructor produces Success");
            };
            hits_by_overload.extend(proven);
            unproven_by_overload.extend(uncertain);
            unproven_total_by_overload.extend(totals);
        }
        if external_hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: primary.short_name().to_owned(),
                total_callsites: external_hits.len(),
                limit: max_usages,
                sample_hits: external_hits.into_iter().take(max_usages).collect(),
            });
        }
        GraphUsageOutcome::Resolved(if diagnostics.is_empty() {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            }
        } else {
            FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
                diagnostics,
            }
        })
    }
}

fn diagnostic(target: &CodeUnit, kind: &str, reason: String) -> UsageAnalysisDiagnostic {
    UsageAnalysisDiagnostic {
        fq_name: target.fq_name().to_string(),
        strategy: "go_native".into(),
        reason_kind: kind.into(),
        reason,
    }
}
