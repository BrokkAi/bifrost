//! Per-class causal receipts for the taint IDE product lattice.

use std::collections::BTreeMap;

use super::TaintClassSet;
use super::client::TaintEdgeFunction;
use super::model::TaintClassId;
use crate::model_attribution::{ModelReceipt, SUMMARY_RECEIPT_CAP, model_receipt_merge};

type ClassReceipts = Option<Box<[(TaintClassId, ModelReceipt)]>>;
type PairReceipts = Option<Box<[((TaintClassId, TaintClassId), ModelReceipt)]>>;

fn add<K: Ord>(map: &mut BTreeMap<K, ModelReceipt>, key: K, receipt: &ModelReceipt) {
    if receipt.is_empty() {
        return;
    }
    map.entry(key)
        .and_modify(|previous| {
            *previous = model_receipt_merge(previous, receipt, SUMMARY_RECEIPT_CAP)
        })
        .or_insert_with(|| receipt.clone());
}

fn finish<K>(map: BTreeMap<K, ModelReceipt>) -> Option<Box<[(K, ModelReceipt)]>> {
    (!map.is_empty()).then(|| map.into_iter().collect::<Vec<_>>().into_boxed_slice())
}

fn lookup<'a, K: Ord>(
    rows: &'a Option<Box<[(K, ModelReceipt)]>>,
    key: &K,
) -> Option<&'a ModelReceipt> {
    let rows = rows.as_ref()?;
    rows.binary_search_by_key(&key, |row| &row.0)
        .ok()
        .map(|index| &rows[index].1)
}

/// The IDE value: exact classes plus canonical sparse per-class receipts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributedTaintValue {
    pub classes: TaintClassSet,
    receipts: ClassReceipts,
}

impl AttributedTaintValue {
    pub fn exact(classes: TaintClassSet) -> Self {
        Self {
            classes,
            receipts: None,
        }
    }

    pub(crate) fn receipt(&self, class: TaintClassId) -> Option<&ModelReceipt> {
        lookup(&self.receipts, &class)
    }

    pub fn receipt_for_classes(&self, classes: &TaintClassSet) -> ModelReceipt {
        let mut receipt = ModelReceipt::default();
        for class in classes.iter_dense() {
            if let Some(item) = self.receipt(class) {
                receipt = model_receipt_merge(&receipt, item, SUMMARY_RECEIPT_CAP);
            }
        }
        receipt
    }

    pub fn meet(&self, other: &Self) -> Self {
        let classes = self.classes.union(&other.classes);
        let mut receipts = BTreeMap::new();
        for rows in [&self.receipts, &other.receipts].into_iter().flatten() {
            for (class, receipt) in rows.iter() {
                add(&mut receipts, *class, receipt);
            }
        }
        debug_assert!(receipts.keys().all(|class| classes.contains_dense(*class)));
        Self {
            classes,
            receipts: finish(receipts),
        }
    }

    pub fn retained_heap_bytes(&self) -> usize {
        self.classes.retained_heap_bytes()
            + self.receipts.as_ref().map_or(0, |rows| {
                std::mem::size_of_val(rows.as_ref())
                    + rows
                        .iter()
                        .map(|(_, receipt)| {
                            crate::model_attribution::model_receipt_heap_bytes(receipt)
                        })
                        .sum::<usize>()
            })
    }
}

/// One affine relation with receipts on individual input/output pairs and
/// generated output classes. Exact relations keep both maps absent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributedTaintFunction {
    pub base: TaintEdgeFunction,
    pairs: PairReceipts,
    generated: ClassReceipts,
}

impl AttributedTaintFunction {
    pub fn exact(base: TaintEdgeFunction) -> Self {
        Self {
            base,
            pairs: None,
            generated: None,
        }
    }

    pub fn has_model_receipts(&self) -> bool {
        self.pairs.is_some() || self.generated.is_some()
    }

    pub(crate) fn pair_receipts(&self) -> &[((TaintClassId, TaintClassId), ModelReceipt)] {
        self.pairs.as_deref().unwrap_or(&[])
    }

    pub(crate) fn generated_receipts(&self) -> &[(TaintClassId, ModelReceipt)] {
        self.generated.as_deref().unwrap_or(&[])
    }

    pub(crate) fn from_receipt_rows(
        base: TaintEdgeFunction,
        pairs: Vec<((TaintClassId, TaintClassId), ModelReceipt)>,
        generated: Vec<(TaintClassId, ModelReceipt)>,
    ) -> Self {
        assert!(pairs.windows(2).all(|rows| rows[0].0 < rows[1].0));
        assert!(generated.windows(2).all(|rows| rows[0].0 < rows[1].0));
        assert!(pairs.iter().all(|((source, target), receipt)| {
            !receipt.is_empty()
                && crate::model_attribution::model_receipt_valid(receipt)
                && base.output_for(*source).contains_dense(*target)
        }));
        assert!(generated.iter().all(|(target, receipt)| {
            !receipt.is_empty()
                && crate::model_attribution::model_receipt_valid(receipt)
                && base.generated().contains_dense(*target)
        }));
        Self {
            base,
            pairs: (!pairs.is_empty()).then(|| pairs.into_boxed_slice()),
            generated: (!generated.is_empty()).then(|| generated.into_boxed_slice()),
        }
    }

    pub(crate) fn retained_heap_bytes(&self) -> usize {
        self.base.retained_heap_bytes()
            + self.pairs.as_ref().map_or(0, |rows| {
                std::mem::size_of_val(rows.as_ref())
                    + rows
                        .iter()
                        .map(|(_, receipt)| {
                            crate::model_attribution::model_receipt_heap_bytes(receipt)
                        })
                        .sum::<usize>()
            })
            + self.generated.as_ref().map_or(0, |rows| {
                std::mem::size_of_val(rows.as_ref())
                    + rows
                        .iter()
                        .map(|(_, receipt)| {
                            crate::model_attribution::model_receipt_heap_bytes(receipt)
                        })
                        .sum::<usize>()
            })
    }

    pub fn with_model_receipt(mut self, receipt: &ModelReceipt) -> Self {
        if receipt.is_empty() {
            return self;
        }
        let mut pairs = self
            .pairs
            .as_ref()
            .map_or_else(BTreeMap::new, |rows| rows.iter().cloned().collect());
        let mut generated = self
            .generated
            .as_ref()
            .map_or_else(BTreeMap::new, |rows| rows.iter().cloned().collect());
        for source in 0..self.base.class_count() {
            let source = TaintClassId::try_from_index(source).expect("validated class count");
            for target in self.base.output_for(source).iter_dense() {
                add(&mut pairs, (source, target), receipt);
            }
        }
        for target in self.base.generated().iter_dense() {
            add(&mut generated, target, receipt);
        }
        self.pairs = finish(pairs);
        self.generated = finish(generated);
        self
    }

    /// A source record introduces only generated classes. Its implicit
    /// pass-through is a solver convenience, not evidence from that record.
    pub fn with_generated_receipt(mut self, receipt: &ModelReceipt) -> Self {
        if receipt.is_empty() {
            return self;
        }
        let mut generated = self
            .generated
            .as_ref()
            .map_or_else(BTreeMap::new, |rows| rows.iter().cloned().collect());
        for target in self.base.generated().iter_dense() {
            add(&mut generated, target, receipt);
        }
        self.generated = finish(generated);
        self
    }

    fn pair(&self, source: TaintClassId, target: TaintClassId) -> Option<&ModelReceipt> {
        lookup(&self.pairs, &(source, target))
    }

    pub fn apply(&self, value: &AttributedTaintValue) -> AttributedTaintValue {
        let classes = self.base.apply(&value.classes);
        if value.receipts.is_none() && self.pairs.is_none() && self.generated.is_none() {
            return AttributedTaintValue::exact(classes);
        }
        let mut receipts = BTreeMap::new();
        for source in value.classes.iter_dense() {
            for target in self.base.output_for(source).iter_dense() {
                if let Some(receipt) = value.receipt(source) {
                    add(&mut receipts, target, receipt);
                }
                if let Some(receipt) = self.pair(source, target) {
                    add(&mut receipts, target, receipt);
                }
            }
        }
        if let Some(generated) = &self.generated {
            for (target, receipt) in generated.iter() {
                add(&mut receipts, *target, receipt);
            }
        }
        debug_assert!(receipts.keys().all(|class| classes.contains_dense(*class)));
        AttributedTaintValue {
            classes,
            receipts: finish(receipts),
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        let base = self.base.meet(&other.base);
        let mut pairs = BTreeMap::new();
        let mut generated = BTreeMap::new();
        for rows in [&self.pairs, &other.pairs].into_iter().flatten() {
            for (key, receipt) in rows.iter() {
                add(&mut pairs, *key, receipt);
            }
        }
        for rows in [&self.generated, &other.generated].into_iter().flatten() {
            for (key, receipt) in rows.iter() {
                add(&mut generated, *key, receipt);
            }
        }
        Self {
            base,
            pairs: finish(pairs),
            generated: finish(generated),
        }
    }

    pub fn compose(&self, second: &Self) -> Self {
        let base = self.base.compose(&second.base);
        if self.pairs.is_none()
            && self.generated.is_none()
            && second.pairs.is_none()
            && second.generated.is_none()
        {
            return Self::exact(base);
        }
        let mut pairs = BTreeMap::new();
        let mut generated = BTreeMap::new();
        for source in 0..self.base.class_count() {
            let source = TaintClassId::try_from_index(source).expect("validated class count");
            for intermediate in self.base.output_for(source).iter_dense() {
                for target in second.base.output_for(intermediate).iter_dense() {
                    if let Some(receipt) = self.pair(source, intermediate) {
                        add(&mut pairs, (source, target), receipt);
                    }
                    if let Some(receipt) = second.pair(intermediate, target) {
                        add(&mut pairs, (source, target), receipt);
                    }
                }
            }
        }
        for intermediate in self.base.generated().iter_dense() {
            for target in second.base.output_for(intermediate).iter_dense() {
                if let Some(receipt) = lookup(&self.generated, &intermediate) {
                    add(&mut generated, target, receipt);
                }
                if let Some(receipt) = second.pair(intermediate, target) {
                    add(&mut generated, target, receipt);
                }
            }
        }
        if let Some(rows) = &second.generated {
            for (target, receipt) in rows.iter() {
                add(&mut generated, *target, receipt);
            }
        }
        Self {
            base,
            pairs: finish(pairs),
            generated: finish(generated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_attribution::{ModelContributor, ModelContributorRole};
    use crate::taint::{SourceClassId, TaintUniverse};

    fn contributor(id: usize) -> ModelReceipt {
        crate::model_attribution::model_receipt_from_full(
            vec![ModelContributor {
                role: ModelContributorRole::Summary,
                pack_digest: "a".repeat(64),
                record_id: format!("r{id}"),
                built_from: "0.4.23".into(),
                resolved: "0.4.25".into(),
                direction: "older_artifact".into(),
                mismatch_kinds: vec!["version_nearby".into()],
                selection_rule_id: "cargo-compatible-nearest".into(),
                selection_rule_version: 1,
            }],
            SUMMARY_RECEIPT_CAP,
        )
    }

    #[test]
    fn per_class_receipts_obey_edge_function_laws() {
        let labels = ["alpha", "beta", "gamma"].map(|name| SourceClassId::new(name).unwrap());
        let universe = TaintUniverse::new(labels.to_vec()).unwrap();
        let set = |mask: usize| {
            universe
                .class_set(
                    labels
                        .iter()
                        .enumerate()
                        .filter_map(|(index, label)| (mask & (1 << index) != 0).then_some(label)),
                )
                .unwrap()
        };
        let mut state = 17_u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state as usize
        };
        for _ in 0..256 {
            let mut make_function = |id| {
                let generated = set(next() & 7);
                let identity = next() & 1 != 0;
                let overrides = (0..3)
                    .map(|index| (universe.class_id(&labels[index]).unwrap(), set(next() & 7)))
                    .collect();
                let base = TaintEdgeFunction::from_canonical_parts(
                    &universe, generated, identity, overrides,
                )
                .unwrap();
                let mut function = AttributedTaintFunction::exact(base);
                if next() & 1 != 0 {
                    function = function.with_model_receipt(&contributor(id));
                }
                function
            };
            let first = make_function(1);
            let second = make_function(2);
            let input = set(next() & 7);
            let mut receipts = BTreeMap::new();
            for class in input.iter_dense() {
                if next() & 1 != 0 {
                    add(&mut receipts, class, &contributor(class.index()));
                }
            }
            let value = AttributedTaintValue {
                classes: input,
                receipts: finish(receipts),
            };
            assert_eq!(
                first.compose(&second).apply(&value),
                second.apply(&first.apply(&value))
            );
            assert_eq!(
                first.meet(&second).apply(&value),
                first.apply(&value).meet(&second.apply(&value))
            );
        }
    }

    #[test]
    fn exact_class_is_not_marked_by_neighbor_and_kill_drops_receipt() {
        let labels = ["alpha", "beta", "gamma"].map(|name| SourceClassId::new(name).unwrap());
        let universe = TaintUniverse::new(labels.to_vec()).unwrap();
        let class = |index| universe.class_set([&labels[index]]).unwrap();
        let mut receipts = BTreeMap::new();
        add(
            &mut receipts,
            universe.class_id(&labels[1]).unwrap(),
            &contributor(1),
        );
        let input = AttributedTaintValue {
            classes: class(0).union(&class(1)),
            receipts: finish(receipts),
        };
        assert!(input.receipt_for_classes(&class(0)).is_empty());
        assert!(input.receipt_for_classes(&class(1)).approximate_contributed);
        let killed =
            AttributedTaintFunction::exact(TaintEdgeFunction::kill(&class(1))).apply(&input);
        assert!(killed.receipt_for_classes(&class(0)).is_empty());
        assert!(
            !killed
                .classes
                .contains_dense(universe.class_id(&labels[1]).unwrap())
        );
        let generated = AttributedTaintFunction::exact(TaintEdgeFunction::generate(&class(0)))
            .with_generated_receipt(&contributor(2));
        let output = generated.apply(&AttributedTaintValue::exact(class(1)));
        assert!(
            output
                .receipt_for_classes(&class(0))
                .approximate_contributed
        );
        assert!(output.receipt_for_classes(&class(1)).is_empty());
    }
}
