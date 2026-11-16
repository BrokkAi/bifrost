//! Lowering-owned proof of one procedure's complete normal-return domain.
//!
//! The adapter-wide capability remains a coarse language default. This local
//! certificate is available only for Rust, whose lowering has been audited to
//! publish omitted control as local gaps. It is query-local and never stored.

use super::super::*;
use crate::analyzer::semantic::workspace_oracle::common::{Interruption, WorkStager};
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;

// The weak receipt follows this traversal's lexical lifetime on every exit.
fn retain_return_traversal(
    staged: &mut WorkStager,
    points: usize,
    edges: usize,
) -> Result<std::sync::Arc<()>, Interruption> {
    let census = SemanticWork {
        nested_entries: points.saturating_add(edges).saturating_add(1),
        ..SemanticWork::default()
    };
    let owner = std::sync::Arc::new(());
    staged.admit(census)?;
    staged.budget.track_replay_holder(&owner, census);
    Ok(owner)
}

/// Only the lowering owner can construct this certificate. Its lifetime is
/// bounded by the query that supplied the immutable procedure and return row.
#[doc(hidden)]
pub struct NormalReturnDomainCertificate<'procedure> {
    _procedure: &'procedure ProcedureHandle,
    _returned: &'procedure ValueFlowRelation,
}

/// Certify the represented return as the entire normal-return domain. This
/// does not certify value-flow, heap population, aliases or exceptional exits.
#[doc(hidden)]
pub fn certify_normal_return_domain<'procedure>(
    procedure: &'procedure ProcedureHandle,
    returned: &'procedure ValueFlowRelation,
    staged: &mut WorkStager,
    cancellation: &CancellationToken,
) -> Result<Option<NormalReturnDomainCertificate<'procedure>>, Interruption> {
    if cancellation.is_cancelled() {
        return Err(Interruption::Cancelled);
    }
    if procedure.artifact().key().language() != SemanticLanguage::Standard(Language::Rust)
        || !procedure
            .artifact()
            .capabilities()
            .is_complete(SemanticCapability::NormalExitBoundary)
        || returned.point.procedure() != procedure
        || returned.kind != ValueFlowRelationKind::NormalReturn
        || !matches!(&returned.target, ValueFlowEndpoint::Port(port)
            if *port == ProcedurePortHandle::normal_return(procedure.clone()))
        || !returned
            .proof
            .establishes_complete_evidence(&returned.completeness)
    {
        return Ok(None);
    }
    let semantics = procedure.semantics();
    if !semantics.incomplete_facts().is_empty() {
        return Ok(None);
    }
    // Visit the producer's compressed cleanup representation explicitly so
    // looking for the first logical omission remains charged and cancellable.
    let cleanup = semantics.cleanup_chains();
    for anchor in cleanup.anchors() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            events: 1,
            ..SemanticWork::default()
        });
        if anchor.purpose != CleanupAnchorPurpose::Completion {
            continue;
        }
        for entry in cleanup.anchor_actions(anchor) {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            staged.charge_work(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            });
            if entry.incomplete.is_some() {
                return Ok(None);
            }
        }
    }
    for gap in semantics.gaps() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            gaps: 1,
            ..SemanticWork::default()
        });
        // In particular, an opaque macro's control gap and an async body's
        // DeferredExecution gap cannot be discharged as ordinary call gaps.
        if !matches!(
            gap.capability,
            SemanticCapability::Calls | SemanticCapability::CallableReferences
        ) {
            return Ok(None);
        }
    }
    let ValueFlowEndpoint::Value(source) = &returned.source else {
        return Ok(None);
    };
    // The retained relation names a ValueFlow::Return event, not the distinct
    // ProcedureReturn marker. Match the marker to that event's RETURN TARGET,
    // not to its incoming source or the relation's event ordinal.
    staged.charge_work(SemanticWork {
        events: 1,
        ..SemanticWork::default()
    });
    let Some(event) = semantics
        .point(returned.point.id())
        .and_then(|point| point.events.get(returned.event_index as usize))
    else {
        return Ok(None);
    };
    let SemanticEffect::ValueFlow {
        kind: ValueFlowKind::Return,
        source: value,
        target,
    } = event.effect
    else {
        return Ok(None);
    };
    if value != source.id() {
        return Ok(None);
    }
    let mut marker = None;
    for point in semantics.points() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            program_points: 1,
            ..SemanticWork::default()
        });
        for event in &point.events {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            staged.charge_work(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            });
            if let SemanticEffect::ProcedureReturn { value } = event.effect
                && marker.replace((point.id, value)).is_some()
            {
                return Ok(None);
            }
        }
    }
    if marker != Some((returned.point.id(), Some(target))) {
        return Ok(None);
    }
    // All paths to the normal exit must cross the represented return point.
    // Exceptional exits, including panics/unwinding, are not normal returns.
    // Seen contains at most P points; the stack holds at most E+1 entries.
    // Reserve before either allocation, including the initial entry point.
    let _resident_rows = retain_return_traversal(
        staged,
        semantics.points().len(),
        semantics.control_edges().len(),
    )?;
    let mut pending = vec![semantics.entry_point()];
    let mut seen = HashSet::default();
    let mut reaches_return = false;
    while let Some(point) = pending.pop() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        if !seen.insert(point) {
            continue;
        }
        staged.charge_work(SemanticWork {
            program_points: 1,
            ..SemanticWork::default()
        });
        if point == semantics.normal_exit_point() {
            return Ok(None);
        }
        if point == returned.point.id() {
            reaches_return = true;
            continue;
        }
        for (_, edge) in semantics.cfg().successor_edges(point) {
            staged.charge_work(SemanticWork {
                control_edges: 1,
                ..SemanticWork::default()
            });
            pending.push(edge.target_point);
        }
    }
    Ok(reaches_return.then_some(NormalReturnDomainCertificate {
        _procedure: procedure,
        _returned: returned,
    }))
}

#[cfg(test)]
mod resident_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#11547: normal-return traversal scratch bypassed resident refusal")]
    fn normal_return_traversal_resident_lifetime() {
        let cancellation = CancellationToken::default();
        let mut limits = SemanticBudget::default().limits();
        limits.nested_entries = 20;
        let mut budget = SemanticBudget::new(limits).unwrap();
        let mut staged = WorkStager::new(&SemanticRequest::new(&mut budget, &cancellation));
        let traversal = retain_return_traversal(&mut staged, 8, 8).unwrap();
        assert_eq!(staged.budget.resident().nested_entries, 17);
        assert_eq!(staged.budget.resident_peak().nested_entries, 17);
        assert!(matches!(
            retain_return_traversal(&mut staged, 2, 1),
            Err(Interruption::Budget(_))
        ));
        drop(traversal);
        assert_eq!(staged.budget.resident().nested_entries, 0);
        assert_eq!(staged.budget.resident_peak().nested_entries, 17);
        let reused = retain_return_traversal(&mut staged, 10, 9).unwrap();
        drop(reused);
        assert_eq!(staged.budget.resident().nested_entries, 0);
    }
}
