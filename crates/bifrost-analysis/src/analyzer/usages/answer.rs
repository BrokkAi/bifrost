//! The complete, replayable answer to a usage question.

use super::finder::{CandidateFilesSample, QueryResult, UsageQueryCompletion};
use super::model::{
    FuzzyResult, ReferenceKind, UsageAnalysisDiagnostic, UsageHit, UsageProof, UsageProofAuthority,
};
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{CodeUnit, ProjectFile};
use std::collections::BTreeSet;

/// Witness that this overload's answer was exhaustive, with no execution or
/// retained-evidence cut. Only the shared query classifier constructs it.
#[derive(Debug, Clone, Copy)]
pub struct CompleteUsageAnswer {
    _private: (),
}

impl QueryResult {
    pub fn complete_answer(&self, overload: &CodeUnit) -> Option<CompleteUsageAnswer> {
        if !self.has_complete_coverage() {
            return None;
        }
        let FuzzyResult::Success {
            unproven_by_overload,
            unproven_total_by_overload,
            ..
        } = &self.result
        else {
            return None;
        };
        let total = unproven_total_by_overload
            .get(overload)
            .copied()
            .unwrap_or_default();
        if total > unproven_by_overload.get(overload).map_or(0, BTreeSet::len) {
            return None;
        }
        Some(CompleteUsageAnswer { _private: () })
    }
}

/// A dependency digest exists only for an exhaustive answer. Refused answers
/// remain available to their current caller, with all diagnostic evidence.
#[doc(hidden)]
pub fn reusable_usage_answer_digest(
    query: &QueryResult,
    overload: &CodeUnit,
) -> Option<StableDigest> {
    query.complete_answer(overload)?;
    Some(usage_answer_digest(query, overload))
}

/// Canonical usage dependency for one overload. Execution coverage and native
/// proof tiers are part of the answer, including when no site was retained.
/// Paths and declaration identities exclude the workspace mount.
#[doc(hidden)]
pub fn usage_answer_digest(query: &QueryResult, overload: &CodeUnit) -> StableDigest {
    let QueryResult {
        candidate_files_budget_exhausted,
        source_byte_refusal,
        unavailable_sources,
        completion,
        candidate_files,
        candidate_files_truncated,
        source_bytes_truncated,
        scanned_source_bytes,
        candidate_files_sample,
        result,
        proof_authority,
        graph_failure,
    } = query;
    let mut hasher = CanonicalHasher::new(b"bifrost-read-ledger:usage-answer:v2");
    hasher.field("overload", overload.declaration_id().as_str().as_bytes());
    match query.complete_answer(overload) {
        Some(CompleteUsageAnswer { _private: () }) => hasher.value(b"complete"),
        None => {
            hasher.value(b"refused");
            hasher.field(
                "completion",
                match completion {
                    UsageQueryCompletion::Complete => b"complete",
                    UsageQueryCompletion::Cancelled => b"cancelled",
                    UsageQueryCompletion::CandidateFilesBudgetExhausted => {
                        b"candidate_files_budget_exhausted"
                    }
                    UsageQueryCompletion::SourceBytesBudgetExhausted => {
                        b"source_bytes_budget_exhausted"
                    }
                },
            );
            // These witnesses are consumed only for refused answers. Complete
            // receipt identities are unchanged, and refused answers cannot be reused.
            hasher.field(
                "candidate_files_budget_exhausted",
                &[*candidate_files_budget_exhausted as u8],
            );
            match source_byte_refusal {
                Some((consumed, limit, attempted)) => {
                    hasher.value(b"source_byte_refusal");
                    hasher.field("consumed", &(*consumed as u64).to_be_bytes());
                    hasher.field("limit", &(*limit as u64).to_be_bytes());
                    hasher.field("attempted", &(*attempted as u64).to_be_bytes());
                }
                None => hasher.value(b"no_source_byte_refusal"),
            }
            hash_paths(
                &mut hasher,
                "unavailable_sources",
                unavailable_sources.iter(),
            );
            hash_paths(&mut hasher, "candidate_files", candidate_files.iter());
            hasher.field(
                "candidate_files_truncated",
                &[*candidate_files_truncated as u8],
            );
            // Not implied by completion: a byte refusal outranks a file
            // refusal there, but both can hold at once.
            hasher.field(
                "candidate_files_budget_exhausted",
                &[*candidate_files_budget_exhausted as u8],
            );
            hasher.field("source_bytes_truncated", &[*source_bytes_truncated as u8]);
            hasher.field(
                "scanned_source_bytes",
                &(*scanned_source_bytes as u64).to_be_bytes(),
            );
            match candidate_files_sample {
                None => hasher.value(b"no_candidate_sample"),
                Some(CandidateFilesSample {
                    scanned,
                    omitted,
                    omitted_count,
                }) => {
                    hasher.value(b"candidate_sample");
                    hash_paths(&mut hasher, "scanned", scanned.iter());
                    hash_paths(&mut hasher, "omitted", omitted.iter());
                    hasher.field("omitted_count", &(*omitted_count as u64).to_be_bytes());
                }
            }
            match graph_failure {
                None => hasher.value(b"no_graph_failure"),
                Some(diagnostic) => {
                    hasher.value(b"graph_failure");
                    hash_diagnostic(&mut hasher, diagnostic);
                }
            }
        }
    }
    hasher.field(
        "proof_authority",
        match proof_authority {
            UsageProofAuthority::Legacy => b"legacy",
            UsageProofAuthority::Native => b"native",
        },
    );
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        }
        | FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
            diagnostics: _,
        } => {
            match result {
                FuzzyResult::Incomplete { diagnostics, .. } => {
                    hasher.value(b"incomplete");
                    let mut diagnostics = diagnostics.iter().collect::<Vec<_>>();
                    diagnostics
                        .sort_by_key(|d| (&d.fq_name, &d.strategy, &d.reason_kind, &d.reason));
                    hasher.sequence("diagnostics", &diagnostics, |h, d| hash_diagnostic(h, d));
                }
                _ => hasher.value(b"success"),
            }
            hash_hits(&mut hasher, "proven", hits_by_overload.get(overload));
            hash_hits(&mut hasher, "unproven", unproven_by_overload.get(overload));
            hasher.field(
                "unproven_total",
                &(unproven_total_by_overload
                    .get(overload)
                    .copied()
                    .unwrap_or_default() as u64)
                    .to_be_bytes(),
            );
        }
        FuzzyResult::Failure {
            fq_name,
            reason_kind,
            reason,
        } => {
            hasher.value(b"failure");
            hasher.field("fq_name", fq_name.as_bytes());
            hasher.field("reason_kind", reason_kind.as_bytes());
            hasher.field("reason", reason.as_bytes());
        }
        FuzzyResult::TooManyCallsites {
            short_name,
            total_callsites,
            limit,
            sample_hits,
        } => {
            hasher.value(b"too_many_callsites");
            hasher.field("short_name", short_name.as_bytes());
            hasher.field("total_callsites", &(*total_callsites as u64).to_be_bytes());
            hasher.field("limit", &(*limit as u64).to_be_bytes());
            hash_hits(&mut hasher, "sample_hits", Some(sample_hits));
        }
    }
    StableDigest::from_array(hasher.finish())
}

fn hash_paths<'a>(
    hasher: &mut CanonicalHasher,
    name: &str,
    files: impl Iterator<Item = &'a ProjectFile>,
) {
    let mut paths = files
        .map(crate::path_utils::rel_path_string)
        .collect::<Vec<_>>();
    paths.sort();
    hasher.sequence(name, &paths, |h, path| h.value(path.as_bytes()));
}

fn hash_diagnostic(hasher: &mut CanonicalHasher, diagnostic: &UsageAnalysisDiagnostic) {
    let UsageAnalysisDiagnostic {
        fq_name,
        strategy,
        reason_kind,
        reason,
    } = diagnostic;
    hasher.field("fq_name", fq_name.as_bytes());
    hasher.field("strategy", strategy.as_bytes());
    hasher.field("reason_kind", reason_kind.as_bytes());
    hasher.field("reason", reason.as_bytes());
}

fn hash_hits(hasher: &mut CanonicalHasher, name: &str, hits: Option<&BTreeSet<UsageHit>>) {
    // Positions order sites, as in callers/callees, but are not semantic
    // equality inputs. Public coordinates have separate file dependencies.
    let mut sites = hits
        .into_iter()
        .flatten()
        .map(|hit| (crate::path_utils::rel_path_string(&hit.file), hit))
        .collect::<Vec<_>>();
    sites.sort_by(|(left_path, left), (right_path, right)| {
        left_path
            .cmp(right_path)
            .then_with(|| left.start_offset.cmp(&right.start_offset))
            .then_with(|| left.end_offset.cmp(&right.end_offset))
            .then_with(|| {
                left.enclosing
                    .declaration_id()
                    .cmp(&right.enclosing.declaration_id())
            })
    });
    let ranked = sites.into_iter().enumerate().collect::<Vec<_>>();
    hasher.sequence(name, &ranked, |h, (rank, (path, hit))| {
        let UsageHit {
            file: _,
            line: _,
            start_offset: _,
            end_offset: _,
            enclosing,
            confidence,
            snippet: _,
            kind,
            proof,
            reason_kind,
            reference_kind,
        } = hit;
        h.field("file", path.as_bytes());
        h.field("rank", &(*rank as u64).to_be_bytes());
        h.field("enclosing", enclosing.declaration_id().as_str().as_bytes());
        h.field("confidence", &confidence.to_bits().to_be_bytes());
        h.field("kind", kind.wire_label().as_bytes());
        h.field(
            "proof",
            match proof {
                UsageProof::Proven => b"proven",
                UsageProof::Unproven => b"unproven",
            },
        );
        match reason_kind {
            None => h.value(b"no_reason"),
            Some(reason) => h.field("reason", reason.as_bytes()),
        }
        for facet in ReferenceKind::ALL {
            h.value(&[
                reference_kind.known().contains(facet) as u8,
                reference_kind.undecided().contains(facet) as u8,
            ]);
        }
    });
}
