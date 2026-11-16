//! Conservative acceptance candidates used only to order evaluator retention.
use crate::baseline::{PolicyBaselineDocument, PolicyBaselinePolicyRecord};
use crate::definition::PolicyCategoryId;
use crate::inline_suppression::InlineDirectiveScan;
use crate::scope::{PolicyScopeDocument, PolicyScopeEntry};
use crate::suppression::{PolicySuppressionDocument, PolicySuppressionRecord};
use crate::{PolicyFinding, PolicyFindingId, PolicyId};

/// Borrowed request configuration. Candidate indices and inline scans are
/// prepared only when the evaluator has to discard finding identities.
pub struct AcceptanceHint<'a> {
    policy_id: &'a PolicyId,
    exact: Option<&'a PolicySuppressionDocument>,
    baseline: Option<&'a PolicyBaselineDocument>,
    scope: Option<&'a PolicyScopeDocument>,
    categories: &'a [PolicyCategoryId],
    inline: &'a InlineDirectiveScan<'a>,
}
impl<'a> AcceptanceHint<'a> {
    pub(crate) fn new(
        policy_id: &'a PolicyId,
        exact: Option<&'a PolicySuppressionDocument>,
        baseline: Option<&'a PolicyBaselineDocument>,
        scope: Option<&'a PolicyScopeDocument>,
        categories: &'a [PolicyCategoryId],
        inline: &'a InlineDirectiveScan<'a>,
    ) -> Self {
        Self {
            policy_id,
            exact,
            baseline,
            scope,
            categories,
            inline,
        }
    }
    pub(crate) fn prepare(&self) -> PreparedAcceptanceHint<'_> {
        PreparedAcceptanceHint::new(
            self.policy_id,
            self.exact,
            self.baseline,
            self.scope,
            self.categories,
            self.inline,
        )
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn tier(&self, finding: &PolicyFinding) -> u8 {
        self.prepare().tier(finding)
    }
}

/// Request-local candidate matches for one policy. Confirmations and audit
/// rollback belong to report construction, so a hint never grants acceptance.
pub(crate) struct PreparedAcceptanceHint<'a> {
    exact: std::collections::HashMap<PolicyFindingId, &'a PolicySuppressionRecord>,
    baseline: Option<&'a PolicyBaselinePolicyRecord>,
    scopes: Vec<&'a PolicyScopeEntry>,
    categories: &'a [PolicyCategoryId],
    inline: &'a InlineDirectiveScan<'a>,
}

impl<'a> PreparedAcceptanceHint<'a> {
    pub(crate) fn new(
        policy_id: &PolicyId,
        exact: Option<&'a PolicySuppressionDocument>,
        baseline: Option<&'a PolicyBaselineDocument>,
        scope: Option<&'a PolicyScopeDocument>,
        categories: &'a [PolicyCategoryId],
        inline: &'a InlineDirectiveScan<'a>,
    ) -> Self {
        Self {
            exact: exact
                .into_iter()
                .flat_map(|doc| doc.suppressions())
                .filter(|record| record.policy_id() == policy_id)
                .map(|record| (record.finding_id(), record))
                .collect(),
            baseline: baseline.and_then(|doc| {
                doc.policies()
                    .iter()
                    .find(|record| record.policy_id() == policy_id)
            }),
            scopes: scope
                .into_iter()
                .flat_map(|doc| doc.scopes())
                .filter(|entry| entry.matches_policy(policy_id, categories))
                .collect(),
            categories,
            inline,
        }
    }

    pub(crate) fn tier(&self, finding: &PolicyFinding) -> u8 {
        if self
            .exact
            .get(&finding.id())
            .is_some_and(|record| record.candidate_matches(finding))
            || self.scopes.iter().any(|entry| {
                entry.matches(
                    finding.primary().path(),
                    finding.policy_id(),
                    self.categories,
                )
            })
            || self.inline.candidate_matches(finding)
        {
            0
        } else if self
            .baseline
            .is_some_and(|record| record.candidate_matches(finding))
        {
            2
        } else {
            1
        }
    }
}

pub(crate) fn retention_order(tier: u8, finding: &PolicyFinding) -> (u8, PolicyFindingId) {
    (tier, finding.id())
}
