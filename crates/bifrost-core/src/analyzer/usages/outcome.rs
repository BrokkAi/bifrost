use crate::analyzer::CodeUnit;
use crate::analyzer::usages::model::{
    FuzzyResult, UsageAnalysisDiagnostic, UsageHit, UsageHitSurface,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub enum GraphUsageOutcome {
    Resolved(FuzzyResult),
    FallbackSafe(UsageAnalysisDiagnostic),
    #[allow(dead_code)]
    TerminalFailure(UsageAnalysisDiagnostic),
}

impl GraphUsageOutcome {
    pub fn fallback_safe(
        fq_name: impl Into<String>,
        reason: GraphFailureReason,
        strategy: &'static str,
    ) -> Self {
        Self::FallbackSafe(usage_diagnostic(fq_name, reason, strategy))
    }

    #[allow(dead_code)]
    pub fn terminal_failure(
        fq_name: impl Into<String>,
        reason: GraphFailureReason,
        strategy: &'static str,
    ) -> Self {
        Self::TerminalFailure(usage_diagnostic(fq_name, reason, strategy))
    }

    pub fn into_fuzzy_result(self) -> FuzzyResult {
        match self {
            GraphUsageOutcome::Resolved(result) => result,
            GraphUsageOutcome::FallbackSafe(diagnostic)
            | GraphUsageOutcome::TerminalFailure(diagnostic) => FuzzyResult::Failure {
                fq_name: diagnostic.fq_name,
                reason_kind: diagnostic.reason_kind,
                reason: diagnostic.reason,
            },
        }
    }
}

fn usage_diagnostic(
    fq_name: impl Into<String>,
    reason: GraphFailureReason,
    strategy: &'static str,
) -> UsageAnalysisDiagnostic {
    reason.diagnostic(fq_name, strategy)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphFailureReason {
    UnsupportedTargetLanguage(&'static str),
    MissingAnalyzerCapability(&'static str),
    UnsupportedTargetShape(&'static str),
    NoGraphSeed(&'static str),
}

impl GraphFailureReason {
    /// This reason as a standalone diagnostic, for the per-candidate scans that
    /// hand their declination to [`union_candidate_usages`] instead of
    /// returning a [`GraphUsageOutcome`] of their own.
    pub fn diagnostic(
        self,
        fq_name: impl Into<String>,
        strategy: &'static str,
    ) -> UsageAnalysisDiagnostic {
        UsageAnalysisDiagnostic {
            fq_name: fq_name.into(),
            strategy: strategy.to_string(),
            reason_kind: self.kind().to_string(),
            reason: self.message(strategy),
        }
    }

    fn kind(self) -> &'static str {
        match self {
            GraphFailureReason::UnsupportedTargetLanguage(_) => "unsupported_target_language",
            GraphFailureReason::MissingAnalyzerCapability(_) => "missing_analyzer_capability",
            GraphFailureReason::UnsupportedTargetShape(_) => "unsupported_target_shape",
            GraphFailureReason::NoGraphSeed(_) => "no_graph_seed",
        }
    }

    fn message(self, strategy: &'static str) -> String {
        let detail = match self {
            GraphFailureReason::UnsupportedTargetLanguage(message)
            | GraphFailureReason::MissingAnalyzerCapability(message)
            | GraphFailureReason::UnsupportedTargetShape(message)
            | GraphFailureReason::NoGraphSeed(message) => message,
        };
        format!("{strategy}: {detail}")
    }
}

/// What one candidate declaration of a usage query's target group accounts for:
/// the sites its scan proved, and the sites it could only suspect.
#[derive(Debug, Default)]
pub struct CandidateUsageHits {
    pub hits: BTreeSet<UsageHit>,
    pub unproven_hits: BTreeSet<UsageHit>,
}

/// Resolve one usage query across every candidate declaration in `overloads`.
///
/// Forward resolution legitimately hands a usage query a whole group of
/// declarations one reference can name: four vendored copies of the same
/// bootstrap class, a module shipped under both `dist/` and `src/`, the same
/// item declared by two copies of a module. Each copy sees a different part of
/// the answer, so scanning only the first one (#1779) reports whatever that copy
/// proves and drops every site its siblings own -- which candidate sorts first
/// then decides whether a real call site is reported at all.
///
/// `scan` runs until every candidate is visited or the deduplicated external
/// hit union proves the cap exceeded. `Err` is that candidate declining to answer
/// (no graph seed, wrong language, no analyzer): the group's answer is a
/// fallback-safe diagnostic only when *every* candidate declines, because one
/// candidate's declination must not discard the sites another proved.
pub fn union_candidate_usages(
    overloads: &[CodeUnit],
    max_usages: usize,
    mut scan: impl FnMut(&CodeUnit) -> Result<CandidateUsageHits, UsageAnalysisDiagnostic>,
) -> GraphUsageOutcome {
    let Some(primary) = overloads.first() else {
        return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
    };

    let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
    let mut unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
    let mut declined: Option<UsageAnalysisDiagnostic> = None;
    let mut scanned_any = false;
    let mut external_hit_count = 0;
    for candidate in overloads {
        match scan(candidate) {
            Ok(candidate_hits) => {
                scanned_any = true;
                // `UsageHit` keys on the site -- file, byte range, enclosing
                // declaration -- so a site two candidates both see collapses to
                // one entry here, carrying the classification of whichever
                // candidate recorded it first.
                for hit in candidate_hits.hits {
                    let external = hit.kind.included_in(UsageHitSurface::ExternalUsages);
                    if hits.insert(hit) && external {
                        external_hit_count += 1;
                    }
                }
                unproven_hits.extend(candidate_hits.unproven_hits);
            }
            Err(diagnostic) => {
                declined.get_or_insert(diagnostic);
            }
        }
        if external_hit_count > max_usages {
            break;
        }
    }

    if !scanned_any {
        return GraphUsageOutcome::FallbackSafe(
            declined.expect("every candidate of a non-empty group declined with a diagnostic"),
        );
    }

    // A site one candidate proved is proven for the group, whatever a sibling
    // candidate could only suspect about it. Hit equality ignores `proof`, so
    // the same site can arrive on both channels; the proven reading wins and
    // the site is reported once.
    unproven_hits.retain(|hit| !hits.contains(hit));

    if external_hit_count > max_usages {
        return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
            short_name: primary.short_name().to_string(),
            total_callsites: external_hit_count,
            limit: max_usages,
            sample_hits: hits.into_iter().take(max_usages).collect(),
        });
    }
    GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
        primary.clone(),
        hits,
        unproven_hits,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::ProjectFile;
    use crate::analyzer::model::CodeUnitType;
    use crate::analyzer::usages::model::UsageHit;

    fn unit(name: &str) -> CodeUnit {
        CodeUnit::new(
            ProjectFile::new(std::env::temp_dir(), format!("{name}.rs")),
            CodeUnitType::Function,
            "pkg",
            name,
        )
    }

    fn hit(site: usize, enclosing: &CodeUnit) -> UsageHit {
        UsageHit::new(
            enclosing.source().clone(),
            1,
            site,
            site + 1,
            enclosing.clone(),
            1.0,
            "call",
        )
    }

    #[test]
    fn candidate_union_stops_at_deduplicated_external_cap() {
        let candidates = [unit("a"), unit("b"), unit("must_not_scan")];
        let enclosing = unit("caller");
        let mut scans = 0;
        let outcome = union_candidate_usages(&candidates, 1, |candidate| {
            scans += 1;
            assert_ne!(candidate.identifier(), "must_not_scan");
            let site = usize::from(candidate.identifier() == "b");
            Ok(CandidateUsageHits {
                hits: BTreeSet::from([hit(site, &enclosing)]),
                unproven_hits: BTreeSet::new(),
            })
        });

        assert_eq!(scans, 2);
        let GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
            total_callsites,
            sample_hits,
            ..
        }) = outcome
        else {
            panic!("expected capped result");
        };
        assert_eq!(total_callsites, 2);
        assert_eq!(sample_hits.len(), 1);
    }

    #[test]
    fn duplicate_candidate_hits_do_not_trip_the_cap() {
        let candidates = [unit("a"), unit("b")];
        let enclosing = unit("caller");
        let duplicate = hit(0, &enclosing);
        let outcome = union_candidate_usages(&candidates, 1, |_| {
            Ok(CandidateUsageHits {
                hits: BTreeSet::from([duplicate.clone()]),
                unproven_hits: BTreeSet::new(),
            })
        });
        assert!(matches!(
            outcome,
            GraphUsageOutcome::Resolved(FuzzyResult::Success { .. })
        ));
    }
}
