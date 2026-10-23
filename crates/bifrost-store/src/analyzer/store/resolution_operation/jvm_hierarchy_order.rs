//! Declared JVM supertype precedence for the shared hierarchy cursor.
//!
//! This policy reads only structured edge kinds, ordinal heads and shared tail
//! membership. The driver owns expansion, deduplication and cancellation.
use crate::analyzer::resolution::{
    HierarchyLinearizationPolicy, HierarchyOrderBudget, HierarchyOrderDecision,
    HierarchyOrderFrontier, HierarchyOrderPolicyId, HierarchySequenceRole, HierarchyTailMembership,
    ResolutionCompletion,
};
use crate::analyzer::store::Result as StoreResult;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind;

#[derive(Debug)]
pub(super) struct JvmDeclaredOrder;

pub(super) static JVM_DECLARED_ORDER: JvmDeclaredOrder = JvmDeclaredOrder;

impl HierarchyLinearizationPolicy for JvmDeclaredOrder {
    fn identity(&self) -> HierarchyOrderPolicyId {
        HierarchyOrderPolicyId(0x4a56_4d01)
    }

    fn next(
        &self,
        frontier: &HierarchyOrderFrontier<'_>,
        budget: &mut HierarchyOrderBudget<'_>,
    ) -> StoreResult<HierarchyOrderDecision> {
        let first = frontier
            .heads
            .first()
            .expect("the driver supplies a nonempty merge frontier");
        let mut candidates = frontier.heads.iter().collect::<Vec<_>>();
        candidates.sort_by_key(|head| match head.role {
            HierarchySequenceRole::Base { kind, ordinal, .. } => (
                match kind {
                    Some(
                        ResolutionSupertypeKind::Superclass
                        | ResolutionSupertypeKind::ImplicitSuperclass,
                    ) => 0,
                    _ => 1,
                },
                ordinal,
            ),
            HierarchySequenceRole::DeclaredBases => (2, 0),
        });
        for candidate in candidates {
            let mut blocked = false;
            let mut unknown = None;
            for head in frontier.heads {
                if !budget.step() {
                    // Ordering has no authority to synthesize an aggregate reason.
                    return Ok(HierarchyOrderDecision::Incomplete {
                        completion: ResolutionCompletion::Complete,
                        provenance: candidate.provenance,
                    });
                }
                match frontier.tail_contains(head.sequence, candidate.owner, budget) {
                    HierarchyTailMembership::Present => {
                        blocked = true;
                        break;
                    }
                    HierarchyTailMembership::Absent => {}
                    HierarchyTailMembership::Unknown => {
                        unknown.get_or_insert(head);
                    }
                }
            }
            if !blocked {
                if let Some(head) = unknown {
                    return Ok(match head.role {
                        HierarchySequenceRole::Base { reference, .. } => {
                            HierarchyOrderDecision::RequireBase {
                                reference,
                                provenance: head.provenance,
                            }
                        }
                        HierarchySequenceRole::DeclaredBases => {
                            HierarchyOrderDecision::Incomplete {
                                completion: ResolutionCompletion::Complete,
                                provenance: head.provenance,
                            }
                        }
                    });
                }
                return Ok(HierarchyOrderDecision::Emit {
                    owner: candidate.owner,
                    advance: frontier
                        .heads
                        .iter()
                        .filter(|head| head.owner == candidate.owner)
                        .map(|head| head.sequence)
                        .collect(),
                    provenance: candidate.provenance,
                });
            }
        }
        // An inconsistent declared merge cannot certify an order. Its existing
        // provider evidence remains the sole source of aggregate incompleteness.
        Ok(HierarchyOrderDecision::Incomplete {
            completion: ResolutionCompletion::Complete,
            provenance: first.provenance,
        })
    }
}
