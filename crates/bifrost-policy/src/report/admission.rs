//! Deterministic max-min allocation of retained finding presence and detail.
use super::*;

const OMISSION_DIMENSIONS: [&str; 4] = [
    "policy/evaluator_retention",
    "policy/findings",
    "policy/retained_report_bytes",
    "batch/retained_report_bytes",
];

fn priority(finding: &PolicyFinding) -> u8 {
    if finding.is_explicitly_accepted() {
        0
    } else if finding.baseline().is_none() {
        1
    } else {
        2
    }
}

struct Candidate {
    full: PolicyFinding,
    presence: usize,
    detail: usize,
    tier: u8,
    valid: bool,
    full_valid: bool,
    retain: bool,
    retain_detail: bool,
}

struct LevelCandidate {
    position: usize,
    bytes: usize,
    eligible: bool,
}

impl PolicyReportBuilder {
    /// All policy shells must be registered before submitting the candidate set.
    /// Returns every omitted record so the coordinator can maintain its audits.
    pub fn retain_policy_findings(
        &mut self,
        policies: Vec<Vec<PolicyFinding>>,
    ) -> Result<Vec<PolicyFinding>, PolicyReportBuilderError> {
        self.ensure_evaluation_ready()?;
        assert!(
            self.runs.iter().all(|run| run.findings().is_empty()),
            "batch admission requires finding-free registered shells"
        );
        let mut candidates: Vec<Vec<Candidate>> =
            (0..self.runs.len()).map(|_| Vec::new()).collect();
        for findings in policies {
            let Some(first) = findings.first() else {
                continue;
            };
            let index = self.find_run_index(first.policy_id(), first.policy_hash())?;
            for full in findings {
                if full.policy_id() != self.runs[index].policy_id()
                    || full.policy_hash() != self.runs[index].policy_hash()
                    || full.analysis_type() != self.runs[index].analysis_type()
                {
                    return Err(PolicyReportBuilderError::FindingRunJoinMismatch);
                }
                if full.identity_stability() == FindingIdentityStability::Weak
                    && matches!(
                        self.runs[index].completion(),
                        PolicyRunCompletion::Unsupported { .. }
                            | PolicyRunCompletion::Failed { .. }
                    )
                {
                    return Err(PolicyReportBuilderError::WeakFindingCompletionMismatch);
                }
                let full_valid = match full.validate_against_budget(self.budget.per_policy()) {
                    Ok(()) => true,
                    Err(error) if error.is_budget_limit_exceeded() => false,
                    Err(error) => {
                        return Err(PolicyReportBuilderError::FindingBudgetViolation(error));
                    }
                };
                let mut stripped = full.clone();
                stripped.omit_optional_detail();
                let valid = match stripped.validate_against_budget(self.budget.per_policy()) {
                    Ok(()) => true,
                    Err(error) if error.is_budget_limit_exceeded() => false,
                    Err(error) => {
                        return Err(PolicyReportBuilderError::FindingBudgetViolation(error));
                    }
                };
                let presence = stripped.retained_size();
                let detail = full.retained_size().saturating_sub(presence);
                let tier = priority(&full);
                candidates[index].push(Candidate {
                    full,
                    presence,
                    detail,
                    tier,
                    valid,
                    full_valid,
                    retain: false,
                    retain_detail: false,
                });
            }
        }
        for policy in &mut candidates {
            policy.sort_by(|left, right| {
                crate::acceptance::retention_order(left.tier, &left.full)
                    .cmp(&crate::acceptance::retention_order(right.tier, &right.full))
                    .then_with(|| {
                        serde_json::to_vec(&left.full)
                            .expect("finding serializes")
                            .cmp(&serde_json::to_vec(&right.full).expect("finding serializes"))
                    })
            });
        }
        // These are the same identities and metadata shapes the builder retains.
        // Unused envelope storage remains slack; it is never redistributed.
        let mut metadata = Vec::with_capacity(candidates.len());
        for (run, policy) in self.runs.iter().zip(&candidates) {
            if policy.is_empty() {
                metadata.push(0);
                continue;
            }
            let mut envelope = run.clone();
            envelope.reserve_admission_metadata(
                &policy.iter().map(|c| &c.full).collect::<Vec<_>>(),
                &OMISSION_DIMENSIONS,
            );
            metadata.push(envelope.retained_size().saturating_sub(run.retained_size()));
        }
        let base = report_storage_size(
            &self.evaluation,
            &self.rules,
            &self.runs,
            &self.suppressions,
            &self.scope,
            &self.diagnostics,
        )
        .saturating_add(self.reviews_extra())
        .saturating_add(self.outstanding_skeleton_allowance)
        .saturating_add(self.emergency_allowance);
        let reserved = metadata.iter().copied().fold(0usize, usize::saturating_add);
        let mut batch_left = self
            .budget
            .max_retained_report_bytes()
            .saturating_sub(base.saturating_add(reserved));
        let mut policy_left = self
            .runs
            .iter()
            .enumerate()
            .map(|(i, _)| {
                self.budget
                    .per_policy()
                    .max_retained_report_bytes()
                    .saturating_sub(
                        self.policy_retained_bytes(&self.runs, i)
                            .saturating_add(metadata[i])
                            .saturating_add(PER_POLICY_INCOMPLETE_REASON_ALLOWANCE),
                    )
            })
            .collect::<Vec<_>>();
        // An unfunded upper bound leaves no finding allowance. The ordinary
        // builder check below still permits a zero prefix whose actual refusal
        // metadata fits within the budget and preserves emergency capacity.
        let mut blocked = vec![false; candidates.len()];
        let mut omitted_dimensions = vec![None; candidates.len()];
        let mut reached_byte_limits = vec![[false; 2]; candidates.len()];
        for tier in 0..3 {
            let levels = candidates
                .iter()
                .enumerate()
                .map(|(i, policy)| {
                    if blocked[i] {
                        return Vec::new();
                    }
                    policy
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.tier == tier)
                        .map(|(j, c)| LevelCandidate {
                            position: j,
                            bytes: c.presence,
                            eligible: c.valid && j < self.budget.per_policy().max_findings(),
                        })
                        .collect()
                })
                .collect::<Vec<Vec<LevelCandidate>>>();
            let admitted = allocate_level(&levels, &mut policy_left, &mut batch_left);
            for (i, selected) in admitted.iter().enumerate() {
                for candidate in &levels[i][..*selected] {
                    candidates[i][candidate.position].retain = true;
                }
                if let Some(next) = levels[i].get(*selected) {
                    let j = next.position;
                    let candidate = &candidates[i][j];
                    if candidate.valid && j < self.budget.per_policy().max_findings() {
                        reached_byte_limits[i][0] |= candidate.presence > policy_left[i];
                        reached_byte_limits[i][1] |= candidate.presence > batch_left;
                    }
                    omitted_dimensions[i] = Some(if !candidate.valid {
                        "policy/retained_report_bytes"
                    } else if j >= self.budget.per_policy().max_findings() {
                        "policy/findings"
                    } else if candidate.presence > policy_left[i] {
                        "policy/retained_report_bytes"
                    } else {
                        "batch/retained_report_bytes"
                    });
                    blocked[i] = true;
                }
            }
        }
        let levels = candidates
            .iter()
            .map(|policy| {
                policy
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.retain)
                    .map(|(j, c)| LevelCandidate {
                        position: j,
                        bytes: c.detail,
                        eligible: c.full_valid,
                    })
                    .collect()
            })
            .collect::<Vec<Vec<LevelCandidate>>>();
        let admitted = allocate_level(&levels, &mut policy_left, &mut batch_left);
        for (i, selected) in admitted.iter().enumerate() {
            for candidate in &levels[i][..*selected] {
                candidates[i][candidate.position].retain_detail = true;
            }
            if let Some(candidate) = levels[i].get(*selected) {
                reached_byte_limits[i][0] |=
                    !candidate.eligible || candidate.bytes > policy_left[i];
                reached_byte_limits[i][1] |= candidate.eligible && candidate.bytes > batch_left;
            }
        }
        let mut omitted = Vec::new();
        // One ordinary builder admission per policy prefix. No report clones or
        // per-finding whole-report size walks occur on this path.
        let mut batch_bytes = base;
        for (index, policy) in candidates.into_iter().enumerate() {
            if policy.is_empty() {
                continue;
            }
            let mut original_counts = std::collections::HashMap::new();
            for candidate in &policy {
                *original_counts.entry(candidate.full.id()).or_insert(0usize) += 1;
            }
            let count = policy.iter().filter(|c| c.retain).count();
            let old_size = self.runs[index].retained_size();
            let mut run = self.runs[index].clone();
            let mut retained = Vec::with_capacity(count);
            let mut dropped = Vec::new();
            let dimension = omitted_dimensions[index];
            let mut detail_omitted = false;
            for candidate in policy {
                if candidate.retain {
                    if candidate.full.identity_stability() == FindingIdentityStability::Weak {
                        run.mark_inconclusive(PolicyIncompleteReason::StableAnchorUnavailable);
                    }
                    let mut finding = candidate.full;
                    if !candidate.retain_detail {
                        detail_omitted |= finding.omit_optional_detail();
                    }
                    retained.push(finding);
                } else {
                    dropped.push(candidate.full);
                }
            }
            run.replace_findings(retained);
            if detail_omitted {
                run.record_detail_retention();
            }
            for (dimension, reached) in [
                (
                    "policy/retained_report_bytes",
                    reached_byte_limits[index][0],
                ),
                ("batch/retained_report_bytes", reached_byte_limits[index][1]),
            ] {
                if reached {
                    run.record_budget_refusal(dimension);
                }
            }
            if let Some(dimension) = dimension {
                run.work_mut()
                    .add_retention_omitted_findings_for_dimension(dimension, dropped.len() as u64);
                run.record_budget_refusal(dimension);
                run.mark_inconclusive(if dimension == "policy/findings" {
                    PolicyIncompleteReason::BatchFindingLimit
                } else {
                    PolicyIncompleteReason::ReportRetentionBudget
                });
            }
            run.reconcile_subject_findings(&original_counts, self.budget.per_policy())
                .map_err(PolicyReportBuilderError::RunBudgetViolation)?;
            let descriptor_bytes = self
                .policy_retained_bytes(&self.runs, index)
                .saturating_sub(old_size);
            let policy_bytes = descriptor_bytes.saturating_add(run.retained_size());
            let next_batch = batch_bytes
                .saturating_sub(old_size)
                .saturating_add(run.retained_size());
            let refusal = self.prefix_size_refusal(policy_bytes, next_batch);
            debug_assert!(
                count == 0 || refusal.is_none(),
                "computed policy prefix exceeded the builder budget"
            );
            match refusal {
                Some(error) if count == 0 => return Err(error),
                None => {
                    run.set_retained_report_bytes(policy_bytes);
                    self.runs[index] = run;
                    batch_bytes = next_batch;
                }
                Some(_) => {
                    // Ordinary release refusal: retain the shell, drop the proposed
                    // prefix, and count those records under the first refusing cap.
                    let dimension =
                        if policy_bytes > self.budget.per_policy().max_retained_report_bytes() {
                            "policy/retained_report_bytes"
                        } else {
                            "batch/retained_report_bytes"
                        };
                    dropped.extend(run.take_findings());
                    run.work_mut()
                        .add_retention_omitted_findings_for_dimension(dimension, count as u64);
                    run.record_budget_refusal(dimension);
                    run.mark_inconclusive(PolicyIncompleteReason::ReportRetentionBudget);
                    run.reconcile_subject_findings(&original_counts, self.budget.per_policy())
                        .map_err(PolicyReportBuilderError::RunBudgetViolation)?;
                    batch_bytes = batch_bytes
                        .saturating_sub(old_size)
                        .saturating_add(run.retained_size());
                    let policy_bytes = descriptor_bytes.saturating_add(run.retained_size());
                    if let Some(error) = self.prefix_size_refusal(policy_bytes, batch_bytes) {
                        return Err(error);
                    }
                    run.set_retained_report_bytes(policy_bytes);
                    self.runs[index] = run;
                }
            }
            omitted.extend(dropped);
        }
        Ok(omitted)
    }

    fn prefix_size_refusal(
        &self,
        policy_bytes: usize,
        batch_bytes: usize,
    ) -> Option<PolicyReportBuilderError> {
        if policy_bytes > self.budget.per_policy().max_retained_report_bytes() {
            Some(PolicyReportBuilderError::PolicySkeletonExceeded {
                retained_bytes: policy_bytes,
                max_bytes: self.budget.per_policy().max_retained_report_bytes(),
            })
        } else if batch_bytes > self.budget.max_retained_report_bytes() {
            Some(PolicyReportBuilderError::BatchRetentionExceeded {
                retained_bytes: batch_bytes,
                max_bytes: self.budget.max_retained_report_bytes(),
            })
        } else {
            None
        }
    }
}

/// Allocate integer-byte max-min shares, then redistribute indivisible slack
/// in policy identity order. Each policy consumes an ordered prefix only.
fn allocate_level(
    levels: &[Vec<LevelCandidate>],
    policy_left: &mut [usize],
    batch_left: &mut usize,
) -> Vec<usize> {
    let mut demands = levels
        .iter()
        .enumerate()
        .map(|(i, level)| {
            let demand = level
                .iter()
                .fold(0usize, |sum, candidate| sum.saturating_add(candidate.bytes));
            (i, demand.min(policy_left[i]))
        })
        .collect::<Vec<_>>();
    demands.sort_by_key(|&(i, demand)| (demand, i));
    let mut shares = vec![0; levels.len()];
    let mut remaining = *batch_left;
    for (position, &(i, demand)) in demands.iter().enumerate() {
        let k = demands.len() - position;
        if demand <= remaining / k {
            shares[i] = demand;
            remaining -= demand;
        } else {
            let share = remaining / k;
            let remainder = remaining % k;
            let mut identities = demands[position..]
                .iter()
                .map(|&(i, _)| i)
                .collect::<Vec<_>>();
            identities.sort_unstable();
            for (j, i) in identities.into_iter().enumerate() {
                shares[i] = share + usize::from(j < remainder);
            }
            break;
        }
    }
    let mut admitted = vec![0; levels.len()];
    for (i, level) in levels.iter().enumerate() {
        for candidate in level {
            let bytes = candidate.bytes;
            if !candidate.eligible || bytes > shares[i] {
                break;
            }
            shares[i] -= bytes;
            policy_left[i] -= bytes;
            *batch_left -= bytes;
            admitted[i] += 1;
        }
    }
    loop {
        let mut progress = false;
        for (i, level) in levels.iter().enumerate() {
            if let Some(candidate) = level.get(admitted[i])
                && candidate.eligible
                && candidate.bytes <= policy_left[i]
                && candidate.bytes <= *batch_left
            {
                policy_left[i] -= candidate.bytes;
                *batch_left -= candidate.bytes;
                admitted[i] += 1;
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    admitted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_count_refusal_does_not_inflate_byte_demand() {
        // Under a one-finding count cap, demands are still 2k, 11k and 18k.
        // Max-min shares are 2k, 9k and 9k. The last policy's first finding
        // fits its share; the middle policy's 11k finding cannot consume the
        // 10k left after prefix admission, even though it is first in slack order.
        let levels = [vec![1000, 1000], vec![11000], vec![9000, 9000]]
            .into_iter()
            .map(|sizes| {
                sizes
                    .into_iter()
                    .enumerate()
                    .map(|(position, bytes)| LevelCandidate {
                        position,
                        bytes,
                        eligible: position == 0,
                    })
                    .collect()
            })
            .collect::<Vec<_>>();
        let mut policy_left = vec![30000; 3];
        let mut batch_left = 20000;
        assert_eq!(
            allocate_level(&levels, &mut policy_left, &mut batch_left),
            [1, 0, 1]
        );
        assert_eq!(batch_left, 10000);
    }
}
