//! Test-support native Java forward usage over selected inverse references.

use super::JavaAnalyzer;
use super::selected_reverse::{JavaSelectedReverseOutcome, java_selected_inverse_detailed_for};
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, ReferenceSiteClassifier};
use crate::analyzer::usages::UsageProof;
use crate::analyzer::usages::outcome::GraphUsageOutcome;
use crate::analyzer::usages::{
    FuzzyResult, GraphUsageAnalyzer, UsageAnalysisDiagnostic, UsageHit, UsageHitSurface,
};
use crate::analyzer::{CodeUnit, CodeUnitIndex, IAnalyzer, ProjectFile, resolve_analyzer};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use std::collections::BTreeSet;

/// Native Java forward-usage discovery. This remains test-support only until
/// the JVM consumer cutover is approved.
#[derive(Default)]
pub struct JavaNativeUsageStrategy;

impl JavaNativeUsageStrategy {
    pub const fn new() -> Self {
        Self
    }
}

impl GraphUsageAnalyzer for JavaNativeUsageStrategy {
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
        let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
            return GraphUsageOutcome::TerminalFailure(diagnostic(
                primary,
                "native_resolution_unavailable",
                "selected Java analyzer is unavailable".into(),
            ));
        };
        let cancellation = scan_scope.cancellation().cloned().unwrap_or_default();
        let mut hits_by_overload = HashMap::default();
        let mut unproven_by_overload = HashMap::default();
        let mut unproven_total_by_overload = HashMap::default();
        let mut diagnostics = Vec::new();
        let mut external_hits = BTreeSet::new();
        let constructor_targets = overloads
            .iter()
            .filter(|target| {
                java.signature_metadata(target)
                    .iter()
                    .any(|metadata| metadata.callable_is_constructor())
            })
            .cloned()
            .collect::<HashSet<_>>();
        let mut sources = HashMap::<
            ProjectFile,
            (String, Box<[usize]>, Option<ReferenceSiteClassifier<'_>>),
        >::default();
        let mut seen_targets = HashSet::default();
        for target in overloads {
            if !seen_targets.insert(target) {
                continue;
            }
            if cancellation.is_cancelled() {
                return GraphUsageOutcome::TerminalFailure(diagnostic(
                    primary,
                    "cancelled",
                    "native Java usage query was cancelled".into(),
                ));
            }
            let answer = match java_selected_inverse_detailed_for(java, target, &cancellation) {
                JavaSelectedReverseOutcome::Ready(answer) => answer,
                JavaSelectedReverseOutcome::Unavailable(reason) => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "native_resolution_unavailable",
                        reason,
                    ));
                }
                JavaSelectedReverseOutcome::Stale(reason) => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "stale_selected_source",
                        reason,
                    ));
                }
                JavaSelectedReverseOutcome::Cancelled => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "cancelled",
                        "native Java usage query was cancelled".into(),
                    ));
                }
                JavaSelectedReverseOutcome::StoreError(reason) => {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "native_store_error",
                        reason,
                    ));
                }
            };
            if let EdgeCompleteness::Incomplete { reasons } = &answer.edges.completeness {
                diagnostics.push(diagnostic(
                    target,
                    "native_reference_inventory_incomplete",
                    format!("selected Java reference inventory is incomplete: {reasons:?}"),
                ));
            }
            if answer.peer_language_inventory_open {
                diagnostics.push(diagnostic(
                    target,
                    "native_java_peer_languages_omitted",
                    "native Java inverse references cover Java files only; selected Kotlin or Scala source can name this Java target".into(),
                ));
            }
            let mut hits = BTreeSet::new();
            let mut unproven = BTreeSet::new();
            for edge in answer.edges.edges {
                if cancellation.is_cancelled() {
                    return GraphUsageOutcome::TerminalFailure(diagnostic(
                        primary,
                        "cancelled",
                        "native Java usage query was cancelled".into(),
                    ));
                }
                if !scan_scope.allows(&edge.site.file) {
                    continue;
                }
                if !sources.contains_key(&edge.site.file) {
                    let Some(source) = java.indexed_source(&edge.site.file) else {
                        return GraphUsageOutcome::TerminalFailure(diagnostic(
                            primary,
                            "native_source_unavailable",
                            format!(
                                "selected Java usage source is unavailable: {}",
                                edge.site.file
                            ),
                        ));
                    };
                    if !java
                        .inner
                        .source_matches_selected_native_content(&edge.site.file, &source)
                    {
                        return GraphUsageOutcome::TerminalFailure(diagnostic(
                            primary,
                            "stale_selected_source",
                            format!("selected Java usage source changed: {}", edge.site.file),
                        ));
                    }
                    let line_starts = compute_line_starts(&source).into_boxed_slice();
                    let classifier = ReferenceSiteClassifier::new(java, &edge.site.file);
                    sources.insert(edge.site.file.clone(), (source, line_starts, classifier));
                }
                let (source, line_starts, classifier) = sources
                    .get(&edge.site.file)
                    .expect("selected Java usage source was admitted");
                let usage_range = if constructor_targets.contains(target) {
                    classifier
                        .as_ref()
                        .and_then(|classifier| {
                            classifier.call_range_containing_reference(
                                edge.site.range.start_byte,
                                edge.site.range.end_byte,
                            )
                        })
                        .unwrap_or(edge.site.range)
                } else {
                    edge.site.range
                };
                let snippet = crate::text_utils::trimmed_snippet_around_line(
                    source,
                    line_starts,
                    usage_range.start_line.saturating_sub(1),
                    0,
                );
                let owner = edge
                    .site
                    .enclosing
                    .clone()
                    .unwrap_or_else(|| CodeUnit::file_scope(edge.site.file.clone()));
                let mut hit = UsageHit::new(
                    edge.site.file,
                    usage_range.start_line,
                    usage_range.start_byte,
                    usage_range.end_byte,
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
        let result = if diagnostics.is_empty() {
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
        };
        GraphUsageOutcome::Resolved(result)
    }
}

fn diagnostic(target: &CodeUnit, kind: &str, reason: String) -> UsageAnalysisDiagnostic {
    UsageAnalysisDiagnostic {
        fq_name: target.fq_name().to_string(),
        strategy: "java_native".into(),
        reason_kind: kind.into(),
        reason,
    }
}
