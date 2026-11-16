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
            reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
        }
    }
    fn output_projection(value: &Self::Output, hash: &mut CanonicalHasher) {
        hash.value(value);
    }
}
