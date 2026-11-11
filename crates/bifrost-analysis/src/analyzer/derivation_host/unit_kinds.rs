//! Snapshot-bound Rust stratum-zero derivations.
use std::sync::Arc;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_semantic::analyzer::semantic::derivation::{
    Computed, DerivationAuthority, DerivationFrame, DerivationKind, DerivationKindId,
    DerivationQuestion, DerivationRevision, ReuseValidity, UnavailableCause, Verification,
};
use brokk_bifrost_store::analyzer::store::unit_summaries::UnitLive;

/// The host supplies reads against the selected reader and snapshot for each demand.
/// #9737 M3 G: open a RecomputeOnCurrency attribution scope at these SQL calls
/// when the core attribution module is merged into this lane.
pub type UnitSummaryRead = Arc<dyn Fn(&[u8; 32]) -> Result<UnitLive, String> + Send + Sync>;
pub type RustUnitSetRead = Arc<dyn Fn() -> Result<Vec<(String, [u8; 32])>, String> + Send + Sync>;
pub struct UnitSummaryKind {
    pub read: UnitSummaryRead,
}
impl DerivationKind for UnitSummaryKind {
    type Key = [u8; 32];
    type Output = [u8; 32];
    const ID: DerivationKindId = DerivationKindId("derivation:unit_summary:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            true,
            false,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(key: &Self::Key) -> DerivationQuestion {
        DerivationQuestion {
            language: Some(Language::Rust),
            subject: Some(*key),
            rel_path: None,
            name: None,
        }
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        if q.language == Some(Language::Rust) && q.rel_path.is_none() && q.name.is_none() {
            q.subject
        } else {
            None
        }
    }
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        key: &Self::Key,
    ) -> Computed<Self::Output> {
        let digest = match (self.read)(key) {
            Ok(UnitLive::Present { output_digest }) => output_digest,
            Ok(UnitLive::Absent) => {
                let mut hash = CanonicalHasher::new(b"bifrost-derivation:unit-summary-absent:v1");
                hash.field("language", b"rust");
                hash.field("unit-key", key);
                hash.finish()
            }
            Err(error) => return Computed::Unavailable(UnavailableCause::Failed(error.into())),
        };
        Computed::Available {
            value: digest,
            complete: true,
            validity: ReuseValidity::Reusable,
        }
    }
    fn output_projection(value: &Self::Output, hash: &mut CanonicalHasher) {
        hash.value(value);
    }
}

pub struct RustUnitSetKind {
    pub read: RustUnitSetRead,
}
impl DerivationKind for RustUnitSetKind {
    type Key = u8;
    type Output = [u8; 32];
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_set:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            false,
            false,
            false,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(_: &Self::Key) -> DerivationQuestion {
        DerivationQuestion {
            language: Some(Language::Rust),
            subject: None,
            rel_path: None,
            name: None,
        }
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        if q.language == Some(Language::Rust)
            && q.subject.is_none()
            && q.rel_path.is_none()
            && q.name.is_none()
        {
            Some(0)
        } else {
            None
        }
    }
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        _: &Self::Key,
    ) -> Computed<Self::Output> {
        let Ok(mut members) = (self.read)() else {
            return Computed::Unavailable(UnavailableCause::ValidationFailed);
        };
        let digest = rust_unit_set_digest(&mut members);
        Computed::Available {
            value: digest,
            complete: true,
            validity: ReuseValidity::Reusable,
        }
    }
    fn output_projection(value: &Self::Output, hash: &mut CanonicalHasher) {
        hash.value(value);
    }
}

fn rust_unit_set_digest(members: &mut [(String, [u8; 32])]) -> [u8; 32] {
    members.sort_unstable();
    let mut hash = CanonicalHasher::new(b"bifrost-derivation:rust-unit-set:v1");
    for (name, key) in members {
        hash.field("crate-name", name.as_bytes());
        hash.field("unit-key", key);
    }
    hash.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::retention_budget::{RetainedBytes, RetentionBudget};
    use brokk_bifrost_semantic::analyzer::semantic::derivation::{
        BaseInputs, CaptureHook, CaptureReceipt, Demanded, DerivationEngine, NotReusableCause,
    };
    use brokk_bifrost_semantic::analyzer::semantic::read_ledger::ReadKey;
    use std::sync::Mutex;

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct Revision(u64);
    impl RetainedBytes for Revision {
        fn retained_bytes(&self) -> usize {
            std::mem::size_of::<Self>()
        }
    }
    impl DerivationRevision for Revision {
        fn is_established(&self) -> bool {
            true
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct Authority;
    impl RetainedBytes for Authority {
        fn retained_bytes(&self) -> usize {
            std::mem::size_of::<Self>()
        }
    }
    impl DerivationAuthority for Authority {
        fn retention_refusal(&self) -> Option<NotReusableCause> {
            None
        }
    }
    struct Capture;
    impl CaptureHook<Revision, Authority> for Capture {
        fn capture(&self, _: &Revision, _: &Authority, work: &mut dyn FnMut()) -> CaptureReceipt {
            work();
            CaptureReceipt {
                reads: Vec::new(),
                unattributed: 0,
                execution_dependences: Vec::new(),
                reuse_refusals: Vec::new(),
                persistence_refusals: 0,
                stable_reasons: Vec::new(),
            }
        }
        fn report_unattributed(&self) {}
        fn report_execution_dependence(&self, _: NotReusableCause) {}
        fn report_reuse_refusal(&self, _: NotReusableCause) {}
        fn report_persistence_refusals(&self, _: usize) {}
        fn replay_reasons(&self, _: &[String]) {}
        fn record(&self, _: ReadKey) {}
    }
    struct Inputs;
    impl BaseInputs<Revision, Authority> for Inputs {
        fn unchanged(&self, _: &ReadKey, _: &Revision, _: &Revision, _: &Authority) -> bool {
            false
        }
    }

    #[test]
    fn negative_membership_answer_changes_when_unit_appears() {
        let members = Arc::new(Mutex::new(Vec::new()));
        let kind = RustUnitSetKind {
            read: Arc::new({
                let members = members.clone();
                move || Ok(members.lock().unwrap().clone())
            }),
        };
        let engine = DerivationEngine::new(
            &RetentionBudget::new(1_000_000),
            Arc::new(Capture),
            Arc::new(Inputs),
        );
        engine.register(kind);
        let Demanded::Available {
            identity: absent, ..
        } = engine.demand::<RustUnitSetKind>(&0, Revision(0), Authority)
        else {
            panic!("missing empty membership answer")
        };
        members
            .lock()
            .unwrap()
            .push(("new_crate".to_owned(), [7; 32]));
        let Demanded::Available {
            identity: present, ..
        } = engine.demand::<RustUnitSetKind>(&0, Revision(1), Authority)
        else {
            panic!("missing added membership answer")
        };
        assert_ne!(absent, present);
    }
}
