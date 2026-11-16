//! Request-root trait discovery; every hit replays its transitive inputs.

use super::{SemanticModelOverlay, SemanticModelSymbol};
use crate::analyzer::IAnalyzer;
use crate::analyzer::usages::common::{QueryReadMemo, query_memo_value, query_read_memo};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct OverlayIdentity(u64);
impl OverlayIdentity {
    pub(super) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(
            NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .expect("overlay identity exhausted"),
        )
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    // Covers immutable activation/model set, generated records, anchors,
    // cargo/reexport state and the decoded indexes. Never an allocation address.
    overlay: OverlayIdentity,
    // Unscoped discovery can consult the live JVM request owner as well as
    // activation-owned Rust rows. Bind before every lookup, including a hit.
    reader: Option<crate::analyzer::store::model_catalog::ReaderBinding>,
    name: String,
}

/// Its distinct type registers one memo in QueryRequestMemos. That registry
/// resets at request-root teardown, including cancellation and unwinding.
#[doc(hidden)]
pub struct ModeledTraitOwnersMemo {
    values: QueryReadMemo<Key, Vec<Arc<SemanticModelSymbol>>>,
}
impl Default for ModeledTraitOwnersMemo {
    fn default() -> Self {
        Self {
            values: query_read_memo(),
        }
    }
}
impl ModeledTraitOwnersMemo {
    #[doc(hidden)]
    pub fn owners(
        &self,
        overlay: &SemanticModelOverlay,
        analyzer: &dyn IAnalyzer,
        name: &str,
    ) -> Vec<Arc<SemanticModelSymbol>> {
        if analyzer
            .active_query_cancellation()
            .is_some_and(|token| token.is_cancelled())
        {
            return overlay.trait_owners_with_callable_member(name);
        }
        let Ok(reader) = overlay.request_owner_binding(overlay.row_source.is_some()) else {
            return overlay.trait_owners_with_callable_member(name);
        };
        let key = Key {
            overlay: overlay.identity,
            reader,
            name: name.to_owned(),
        };
        self.get(analyzer, &key, || {
            analyzer.record_read(crate::analyzer::ReadKey::Models(
                crate::analyzer::semantic::StableDigest::sha256(overlay.active_model_set_hash()),
            ));
            let _timing = crate::profiling::scope("modeled_trait_owners::fill");
            overlay.trait_owners_with_callable_member(name)
        })
    }
}

impl ModeledTraitOwnersMemo {
    fn get(
        &self,
        analyzer: &dyn IAnalyzer,
        key: &Key,
        build: impl FnOnce() -> Vec<Arc<SemanticModelSymbol>>,
    ) -> Vec<Arc<SemanticModelSymbol>> {
        query_memo_value(&self.values, analyzer, key, || {
            let owners = build();
            if analyzer
                .active_query_cancellation()
                .is_some_and(|token| token.is_cancelled())
            {
                analyzer.record_query_incomplete(crate::analyzer::QueryReadIncomplete::Cancelled);
            }
            owners
        })
        .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::overlay::test_support::{class, overlay};
    use crate::analyzer::{
        AnalyzerQueryScope, MultiAnalyzer, QueryReadIncomplete, ReadKey, capture_query_reads,
    };
    use brokk_bifrost_test_macros::hardwon;
    use std::cell::Cell;

    fn key(overlay: &SemanticModelOverlay, name: &str) -> Key {
        Key {
            overlay: overlay.identity,
            reader: None,
            name: name.into(),
        }
    }

    #[test]
    #[hardwon("#11957: repeated trait discovery rebuilt the same owner sets thousands of times")]
    fn trait_owner_memo_pins_2271_requests_to_12_computations() {
        let analyzer = MultiAnalyzer::default();
        let mut root = class("model.Trait", "rust");
        root.kind = super::super::SemanticModelSymbolKind::Trait;
        let mut symbols = vec![root.clone()];
        for name in 0..12 {
            for ordinal in 0..53 {
                let mut member = class(&format!("model.Trait.m{name}_{ordinal}"), "rust");
                member.kind = super::super::SemanticModelSymbolKind::Method;
                member.name = format!("m{name}");
                member.owner_id = Some(root.id.clone());
                symbols.push(member);
            }
        }
        let model = overlay(symbols, vec![]);
        let cold = (0..12)
            .map(|n| model.trait_owners_with_callable_member(&format!("m{n}")))
            .collect::<Vec<_>>();
        let memo = ModeledTraitOwnersMemo::default();
        let fills = Cell::new(0);
        for n in 0..2271 {
            let name = format!("m{}", n % 12);
            let answer = memo.get(&analyzer, &key(&model, &name), || {
                fills.set(fills.get() + 1);
                model.trait_owners_with_callable_member(&name)
            });
            assert_eq!(answer, cold[n % 12]);
            assert_eq!(answer.len(), 1);
        }
        assert_eq!(fills.get(), 12);
        let mut changed_reader = key(&model, "m0");
        changed_reader.reader = Some(crate::analyzer::store::model_catalog::ReaderBinding(
            [1; 32],
        ));
        assert!(
            memo.get(&analyzer, &changed_reader, Vec::new).is_empty(),
            "a different selected reader cannot reuse an owner set"
        );
        let other = overlay(vec![], vec![]);
        assert!(
            memo.owners(&other, &analyzer, "m0").is_empty(),
            "a new overlay never reuses an old allocation's key"
        );
    }

    #[test]
    #[hardwon("#11957: a trait-owner hit must replay read keys and typed incomplete evidence")]
    fn trait_owner_memo_replays_reads_and_incomplete_results() {
        let analyzer = MultiAnalyzer::default();
        let memo = ModeledTraitOwnersMemo::default();
        let model = overlay(vec![], vec![]);
        let request = key(&model, "missing");
        let read = ReadKey::index(
            crate::analyzer::read_ledger::IndexFamily::DefinitionExact,
            "trait-owner-input",
        );
        let gap = QueryReadIncomplete::SemanticEvidenceGap("missing trait evidence".into());
        {
            let _scope = AnalyzerQueryScope::for_advisory_read(&analyzer);
            assert!(
                memo.get(&analyzer, &request, || {
                    analyzer.record_read(read.clone());
                    analyzer.record_query_incomplete(gap.clone());
                    vec![]
                })
                .is_empty()
            );
        }
        for _ in 0..2 {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            let (owners, receipt) = capture_query_reads(&analyzer, || {
                memo.get(&analyzer, &request, || {
                    panic!("warm incomplete owner set rebuilt")
                })
            });
            assert!(owners.is_empty());
            assert_eq!(receipt.keys(), vec![read.clone()]);
            assert_eq!(scope.captured_read_incompleteness(), vec![gap.clone()]);
        }
    }

    #[test]
    #[hardwon(
        "#11957: cancelled and execution-dependent trait-owner results must not survive a fill"
    )]
    fn trait_owner_memo_refuses_operational_results() {
        let analyzer = MultiAnalyzer::default();
        let memo = ModeledTraitOwnersMemo::default();
        let model = overlay(vec![], vec![]);
        let request = key(&model, "from");
        let fills = Cell::new(0);
        for _ in 0..2 {
            let _scope = AnalyzerQueryScope::for_advisory_read(&analyzer);
            memo.get(&analyzer, &request, || {
                fills.set(fills.get() + 1);
                analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
                vec![]
            });
        }
        assert_eq!(fills.get(), 2);
        for _ in 0..2 {
            let _scope = AnalyzerQueryScope::for_advisory_read(&analyzer);
            memo.get(&analyzer, &request, || {
                fills.set(fills.get() + 1);
                analyzer.record_budget_dependences(1);
                vec![]
            });
        }
        assert_eq!(fills.get(), 4);
        memo.get(&analyzer, &request, || {
            fills.set(fills.get() + 1);
            vec![]
        });
        memo.get(&analyzer, &request, || {
            panic!("complete empty answer was not retained")
        });
        assert_eq!(fills.get(), 5);
    }
}
