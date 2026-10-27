//! Request-local projection of native inverse references into usage results.
//! Pending sites and admitted source live only for one usages request; each
//! file context is dropped before the next file is admitted.

use crate::analyzer::structural::reference_edges::ReferenceEdgeRow;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::usages::model::{
    FuzzyResult, UsageAnalysisDiagnostic, UsageHit, UsageHitSurface, UsageProof,
};
use brokk_bifrost_core::analyzer::usages::outcome::{CandidateUsageHits, GraphUsageOutcome};
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::text_utils::{compute_line_starts, trimmed_snippet_around_line};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

pub struct NativeUsageSite {
    pub target_index: usize,
    pub hit: UsageHit,
    pub origin: NativeUsageOrigin,
}

#[derive(PartialEq, Eq)]
pub enum NativeUsageOrigin {
    ReferenceEdge,
    SupplementalDeclaration,
}

pub struct NativeUsageFile<T> {
    pub source: String,
    pub line_starts: Box<[usize]>,
    pub context: T,
}

impl<T> NativeUsageFile<T> {
    pub fn new(source: String, context: T) -> Self {
        let line_starts = compute_line_starts(&source).into_boxed_slice();
        Self {
            source,
            line_starts,
            context,
        }
    }
}

pub fn unique_targets(targets: &[CodeUnit]) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    targets
        .iter()
        .filter(|target| seen.insert(*target))
        .cloned()
        .collect()
}

pub enum NativeUsageAdmission {
    Retain,
    Excluded,
    Stopped,
}

pub trait NativeUsageProjection {
    type Context;
    type Error;

    fn load_file(
        &mut self,
        file: &ProjectFile,
        pending: &[NativeUsageSite],
    ) -> Result<NativeUsageFile<Self::Context>, Self::Error>;
    fn admit_edge(_target: &CodeUnit, edge: &ReferenceEdgeRow, scope: &UsageScanScope<'_>) -> bool {
        scope.allows(&edge.site.file)
    }
    fn presentation(
        &mut self,
        file: &ProjectFile,
        loaded: &NativeUsageFile<Self::Context>,
        target: &CodeUnit,
        site: &mut NativeUsageSite,
    ) -> Result<NativeUsageAdmission, Self::Error> {
        let _ = (file, loaded, target, site);
        Ok(NativeUsageAdmission::Retain)
    }
}

pub struct NativeUsagePending<'a> {
    targets: &'a [CodeUnit],
    files: BTreeMap<ProjectFile, Vec<NativeUsageSite>>,
    pub diagnostics: Vec<UsageAnalysisDiagnostic>,
}

impl<'a> NativeUsagePending<'a> {
    pub fn new(targets: &'a [CodeUnit]) -> Self {
        Self {
            targets,
            files: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn push(&mut self, file: ProjectFile, site: NativeUsageSite) {
        self.files.entry(file).or_default().push(site);
    }

    pub fn queue_target_edges<P: NativeUsageProjection>(
        &mut self,
        target_index: usize,
        edges: impl IntoIterator<Item = ReferenceEdgeRow>,
        scope: &UsageScanScope<'_>,
        cancellation: &CancellationToken,
    ) -> ControlFlow<()> {
        for edge in edges {
            if cancellation.is_cancelled() {
                return ControlFlow::Break(());
            }
            if !P::admit_edge(&self.targets[target_index], &edge, scope) {
                continue;
            }
            let file = edge.site.file;
            let owner = edge
                .site
                .enclosing
                .unwrap_or_else(|| CodeUnit::file_scope(file.clone()));
            let range = edge.site.range;
            let mut hit = UsageHit::new(
                file.clone(),
                range.start_line,
                range.start_byte,
                range.end_byte,
                owner,
                0.0,
                "",
            );
            hit.proof = edge.proof;
            hit.kind = edge.usage_kind;
            hit.reference_kind = edge.reference_kind;
            self.push(
                file,
                NativeUsageSite {
                    target_index,
                    hit,
                    origin: NativeUsageOrigin::ReferenceEdge,
                },
            );
        }
        ControlFlow::Continue(())
    }
}

pub fn project_pending_files<P: NativeUsageProjection>(
    projection: &mut P,
    pending: NativeUsagePending<'_>,
    scope: &UsageScanScope<'_>,
    max_usages: usize,
    cancellation: &CancellationToken,
) -> Result<Option<FuzzyResult>, P::Error> {
    let primary = pending
        .targets
        .first()
        .expect("nonempty native usage targets");
    let mut hits = (0..pending.targets.len())
        .map(|_| CandidateUsageHits::default())
        .collect::<Vec<_>>();
    let mut external = BTreeSet::new();
    for (file, sites) in pending.files {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let loaded = projection.load_file(&file, &sites)?;
        for mut site in sites {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            match projection.presentation(
                &file,
                &loaded,
                &pending.targets[site.target_index],
                &mut site,
            )? {
                NativeUsageAdmission::Retain => {}
                NativeUsageAdmission::Excluded => continue,
                NativeUsageAdmission::Stopped => return Ok(None),
            }
            let mut hit = site.hit;
            hit.snippet = trimmed_snippet_around_line(
                &loaded.source,
                &loaded.line_starts,
                hit.line.saturating_sub(1),
                0,
            );
            hit.confidence = if hit.proof == UsageProof::Proven {
                1.0
            } else {
                0.0
            };
            let bucket = &mut hits[site.target_index];
            if hit.proof == UsageProof::Proven {
                if site.origin == NativeUsageOrigin::ReferenceEdge
                    && hit.kind.included_in(UsageHitSurface::ExternalUsages)
                {
                    external.insert(hit.clone());
                }
                bucket.hits.insert(hit);
            } else {
                bucket.unproven_hits.insert(hit);
            }
        }
    }
    if external.len() > max_usages {
        return Ok(Some(FuzzyResult::TooManyCallsites {
            short_name: primary.short_name().to_owned(),
            total_callsites: external.len(),
            limit: max_usages,
            sample_hits: external.into_iter().take(max_usages).collect(),
        }));
    }
    let mut hits_by_overload = HashMap::default();
    let mut unproven_by_overload = HashMap::default();
    let mut unproven_total_by_overload = HashMap::default();
    for (target, hits) in pending.targets.iter().zip(hits) {
        let FuzzyResult::Success {
            hits_by_overload: proven,
            unproven_by_overload: uncertain,
            unproven_total_by_overload: totals,
        } = FuzzyResult::success_with_unproven_limit(
            target.clone(),
            hits.hits,
            hits.unproven_hits,
            scope.max_unproven(),
        )
        else {
            unreachable!("success constructor produces Success");
        };
        hits_by_overload.extend(proven);
        unproven_by_overload.extend(uncertain);
        unproven_total_by_overload.extend(totals);
    }
    Ok(Some(if pending.diagnostics.is_empty() {
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
            diagnostics: pending.diagnostics,
        }
    }))
}

pub struct NativeUsageDiagnostics {
    pub strategy: &'static str,
    pub cancelled_reason: &'static str,
}

impl NativeUsageDiagnostics {
    pub fn diagnostic(
        &self,
        target: &CodeUnit,
        kind: &str,
        reason: String,
    ) -> UsageAnalysisDiagnostic {
        UsageAnalysisDiagnostic {
            fq_name: target.fq_name().to_string(),
            strategy: self.strategy.into(),
            reason_kind: kind.into(),
            reason,
        }
    }
    pub fn failure(&self, target: &CodeUnit, kind: &str, reason: String) -> GraphUsageOutcome {
        GraphUsageOutcome::TerminalFailure(self.diagnostic(target, kind, reason))
    }
    pub fn cancelled(&self, target: &CodeUnit) -> GraphUsageOutcome {
        self.failure(target, "cancelled", self.cancelled_reason.into())
    }
}
