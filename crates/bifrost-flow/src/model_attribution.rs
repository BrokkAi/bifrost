//! Bounded, order-independent provenance for facts used by a derivation.

/// Canonical top-k contributors and a conservative distinct-count lower bound.
/// The marker is independent of detail retention, including a zero cap.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct BoundedContributors<T> {
    pub approximate_contributed: bool,
    pub contributors: Vec<T>,
    pub total_lower_bound: usize,
    pub truncated: bool,
}

impl<T> Default for BoundedContributors<T> {
    fn default() -> Self {
        Self {
            approximate_contributed: false,
            contributors: Vec::new(),
            total_lower_bound: 0,
            truncated: false,
        }
    }
}

impl<T: Ord + Clone> BoundedContributors<T> {
    pub fn from_full(mut contributors: Vec<T>, cap: usize) -> Self {
        contributors.sort();
        contributors.dedup();
        let total_lower_bound = contributors.len();
        let truncated = total_lower_bound > cap;
        contributors.truncate(cap);
        Self {
            approximate_contributed: total_lower_bound > 0,
            contributors,
            total_lower_bound,
            truncated,
        }
    }

    pub fn merge(&self, other: &Self, cap: usize) -> Self {
        let mut union = self.contributors.clone();
        union.extend(other.contributors.iter().cloned());
        union.sort();
        union.dedup();
        let truncated = self.truncated || other.truncated || union.len() > cap;
        union.truncate(cap);
        let total_lower_bound = self
            .total_lower_bound
            .max(other.total_lower_bound)
            .max(union.len().saturating_add(usize::from(truncated)));
        Self {
            approximate_contributed: self.approximate_contributed || other.approximate_contributed,
            contributors: union,
            total_lower_bound,
            truncated,
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.approximate_contributed
            && self.contributors.is_empty()
            && !self.truncated
            && self.total_lower_bound == 0
    }

    pub fn validate(&self) -> bool {
        self.contributors.windows(2).all(|pair| pair[0] < pair[1])
            && self.total_lower_bound >= self.contributors.len()
            && self.truncated == (self.omitted_at_least() > 0)
            && (!self.truncated || self.total_lower_bound > self.contributors.len())
            && (self.approximate_contributed
                || self.contributors.is_empty() && self.total_lower_bound == 0 && !self.truncated)
            && (!self.approximate_contributed || !self.contributors.is_empty() || self.truncated)
    }

    pub fn contributors_complete(&self) -> bool {
        !self.truncated
    }

    pub fn omitted_at_least(&self) -> usize {
        self.total_lower_bound
            .max(
                self.contributors
                    .len()
                    .saturating_add(usize::from(self.truncated)),
            )
            .saturating_sub(self.contributors.len())
    }
}

/// Causal role of one selected approximate semantic-model record.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ModelContributorRole {
    Source,
    Sink,
    Summary,
    Declaration,
    Store,
}

/// The selected record's activation provenance, captured at derivation time.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ModelContributor {
    pub role: ModelContributorRole,
    pub pack_digest: String,
    pub record_id: String,
    pub built_from: String,
    pub resolved: String,
    pub direction: String,
    /// Canonical snake-case labels from the selected 1a approximation claim.
    pub mismatch_kinds: Vec<String>,
    pub selection_rule_id: String,
    pub selection_rule_version: u32,
}

pub type ModelReceipt = BoundedContributors<ModelContributor>;

impl ModelContributor {
    fn same_record_key(&self, other: &Self) -> bool {
        self.role == other.role
            && self.pack_digest == other.pack_digest
            && self.record_id == other.record_id
            && self.built_from == other.built_from
            && self.resolved == other.resolved
            && self.direction == other.direction
    }

    fn valid_reason(&self) -> bool {
        let (Ok(built), Ok(resolved)) = (
            semver::Version::parse(&self.built_from),
            semver::Version::parse(&self.resolved),
        ) else {
            return false;
        };
        let expected_direction = match built.cmp(&resolved) {
            std::cmp::Ordering::Less => "older_artifact",
            std::cmp::Ordering::Greater => "newer_artifact",
            std::cmp::Ordering::Equal => "same_version",
        };
        !self.pack_digest.is_empty()
            && !self.record_id.is_empty()
            && self.direction == expected_direction
            && self.selection_rule_id == "cargo-compatible-nearest"
            && self.selection_rule_version == 1
            && (built == resolved || !self.mismatch_kinds.is_empty())
            && self.mismatch_kinds.windows(2).all(|pair| pair[0] < pair[1])
            && self.mismatch_kinds.iter().all(|kind| {
                matches!(
                    kind.as_str(),
                    "version_nearby" | "feature_superset" | "format_converted"
                )
            })
    }
}

pub fn model_receipt_valid(receipt: &ModelReceipt) -> bool {
    receipt.validate()
        && receipt
            .contributors
            .iter()
            .all(ModelContributor::valid_reason)
        && receipt
            .contributors
            .windows(2)
            .all(|pair| !pair[0].same_record_key(&pair[1]) || pair[0] == pair[1])
}

pub fn model_receipt_from_full(
    mut contributors: Vec<ModelContributor>,
    cap: usize,
) -> ModelReceipt {
    contributors.sort();
    assert!(contributors.iter().all(ModelContributor::valid_reason));
    assert!(
        contributors
            .windows(2)
            .all(|pair| { !pair[0].same_record_key(&pair[1]) || pair[0] == pair[1] }),
        "one selected model record has conflicting approximation reasons"
    );
    ModelReceipt::from_full(contributors, cap)
}

pub fn model_receipt_merge(left: &ModelReceipt, right: &ModelReceipt, cap: usize) -> ModelReceipt {
    assert!(model_receipt_valid(left) && model_receipt_valid(right));
    for a in &left.contributors {
        for b in &right.contributors {
            assert!(
                !a.same_record_key(b) || a == b,
                "one selected model record has conflicting approximation reasons"
            );
        }
    }
    left.merge(right, cap)
}

/// Maximum detail retained inside a reusable summary value.
pub const SUMMARY_RECEIPT_CAP: usize = 16;

pub fn model_receipt_heap_bytes(receipt: &ModelReceipt) -> usize {
    receipt.contributors.capacity() * std::mem::size_of::<ModelContributor>()
        + receipt
            .contributors
            .iter()
            .map(|item| {
                item.pack_digest.capacity()
                    + item.record_id.capacity()
                    + item.built_from.capacity()
                    + item.resolved.capacity()
                    + item.direction.capacity()
                    + item.mismatch_kinds.capacity() * std::mem::size_of::<String>()
                    + item
                        .mismatch_kinds
                        .iter()
                        .map(String::capacity)
                        .sum::<usize>()
                    + item.selection_rule_id.capacity()
            })
            .sum::<usize>()
}

/// Policy binds endpoint identities to these existing flow IDs after plan construction.
/// Values are selected-record receipts, never scans of the loaded model set.
#[derive(Debug, Clone, Default)]
pub struct TaintModelReceiptInputs {
    pub sources: std::collections::HashMap<crate::value_flow::ValueFlowSourceId, ModelReceipt>,
    pub sinks: std::collections::HashMap<crate::value_flow::ValueFlowSinkId, ModelReceipt>,
    pub summaries: std::collections::HashMap<crate::analyzer::semantic::StableDigest, ModelReceipt>,
    /// Policy-local transform relations selected through an approximate
    /// record, keyed like the plan's local transform bindings. The relation
    /// exists only because that record selected its call, so every class it
    /// carries depends on the record.
    pub local_transforms: std::collections::HashMap<
        (
            crate::analyzer::semantic::ProgramPointHandle,
            crate::value_flow::ValueFlowCarrierId,
            crate::value_flow::ValueFlowCarrierId,
        ),
        ModelReceipt,
    >,
}

#[cfg(test)]
mod tests {
    use super::BoundedContributors;

    #[test]
    fn selected_record_rejects_conflicting_reasons_before_zero_cap() {
        let first = super::ModelContributor {
            role: super::ModelContributorRole::Summary,
            pack_digest: "a".repeat(64),
            record_id: "same-record".into(),
            built_from: "0.4.23".into(),
            resolved: "0.4.25".into(),
            direction: "older_artifact".into(),
            mismatch_kinds: vec!["version_nearby".into()],
            selection_rule_id: "cargo-compatible-nearest".into(),
            selection_rule_version: 1,
        };
        let mut conflicting = first.clone();
        conflicting.mismatch_kinds = vec!["format_converted".into()];
        assert!(
            std::panic::catch_unwind(|| {
                super::model_receipt_from_full(vec![first, conflicting], 0)
            })
            .is_err()
        );
    }

    #[test]
    fn model_receipt_rejects_invalid_or_inconsistent_versions() {
        let mut contributor = super::ModelContributor {
            role: super::ModelContributorRole::Summary,
            pack_digest: "a".repeat(64),
            record_id: "record".into(),
            built_from: "0.4.23".into(),
            resolved: "0.4.25".into(),
            direction: "older_artifact".into(),
            mismatch_kinds: vec!["version_nearby".into()],
            selection_rule_id: "cargo-compatible-nearest".into(),
            selection_rule_version: 1,
        };
        let valid = super::model_receipt_from_full(vec![contributor.clone()], 16);
        assert!(super::model_receipt_valid(&valid));
        contributor.built_from = "0.4.25".into();
        contributor.direction = "same_version".into();
        contributor.mismatch_kinds.clear();
        let same_version = super::model_receipt_from_full(vec![contributor.clone()], 16);
        assert!(super::model_receipt_valid(&same_version));
        contributor.built_from = "0.4.23".into();
        contributor.direction = "older_artifact".into();
        let mut missing_reason = valid.clone();
        missing_reason.contributors[0] = contributor.clone();
        assert!(!super::model_receipt_valid(&missing_reason));
        contributor.mismatch_kinds.push("version_nearby".into());
        for (built, resolved, direction) in [
            ("bad", "0.4.25", "older_artifact"),
            ("0.4.23", "bad", "older_artifact"),
            ("0.4.23", "0.4.25", "newer_artifact"),
            ("0.4.25", "0.4.23", "older_artifact"),
            ("0.4.23", "0.4.23", "older_artifact"),
        ] {
            contributor.built_from = built.into();
            contributor.resolved = resolved.into();
            contributor.direction = direction.into();
            let mut invalid = valid.clone();
            invalid.contributors[0] = contributor.clone();
            assert!(!super::model_receipt_valid(&invalid));
        }
    }

    fn full(mask: usize) -> Vec<usize> {
        (0..6).filter(|bit| mask & (1 << bit) != 0).collect()
    }

    #[test]
    fn bounded_model_attribution_merge_properties() {
        for cap in 0..=3 {
            for a in 1..16 {
                for b in 1..16 {
                    for c in 1..16 {
                        let aa = BoundedContributors::from_full(full(a), cap);
                        let bb = BoundedContributors::from_full(full(b), cap);
                        let cc = BoundedContributors::from_full(full(c), cap);
                        let left = aa.merge(&bb, cap).merge(&cc, cap);
                        let right = aa.merge(&bb.merge(&cc, cap), cap);
                        assert_eq!(left, right);
                        assert_eq!(aa.merge(&bb, cap), bb.merge(&aa, cap));
                        assert_eq!(aa.merge(&aa, cap), aa);
                        let mut oracle = full(a);
                        oracle.extend(full(b));
                        oracle.extend(full(c));
                        oracle.sort();
                        oracle.dedup();
                        assert_eq!(left.contributors, oracle[..oracle.len().min(cap)]);
                        assert!(left.contributors.len() + left.omitted_at_least() <= oracle.len());
                    }
                }
            }
        }
    }

    #[test]
    fn random_model_attribution_lineage_properties() {
        for cap in 0..=5 {
            for seed in 1..=128_u64 {
                let mut state = seed;
                let mut next = || {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    state
                };
                let mut raw = Vec::new();
                for _ in 0..7 {
                    let leaf = full(next() as usize & 63);
                    if !leaf.is_empty() {
                        raw.push(leaf);
                    }
                }
                if raw.is_empty() {
                    continue;
                }
                raw.push(raw[0].clone());
                let mut oracle = raw.iter().flatten().copied().collect::<Vec<_>>();
                oracle.sort();
                oracle.dedup();
                let leaves = raw
                    .into_iter()
                    .map(|leaf| BoundedContributors::from_full(leaf, cap))
                    .collect::<Vec<_>>();
                let expected = leaves
                    .iter()
                    .skip(1)
                    .fold(leaves[0].clone(), |acc, item| acc.merge(item, cap));
                for _ in 0..8 {
                    let mut tree = leaves.clone();
                    while tree.len() > 1 {
                        let a = next() as usize % tree.len();
                        let left = tree.swap_remove(a);
                        let b = next() as usize % tree.len();
                        let right = tree.swap_remove(b);
                        tree.push(left.merge(&right, cap));
                    }
                    let got = tree.pop().unwrap();
                    assert_eq!(got, expected);
                    assert_eq!(got.contributors, oracle[..oracle.len().min(cap)]);
                    assert!(got.contributors.len() + got.omitted_at_least() <= oracle.len());
                }
            }
        }
    }
}
