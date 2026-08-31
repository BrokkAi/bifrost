use std::collections::HashSet;
use std::sync::Arc;

use super::super::ir::{ProcedureHandle, SemanticArtifact};
use super::model::{
    AbstractLocation, AbstractObject, AccessPath, AccessPathAtPoint, AccessPathRoot,
    AccessSelector, AliasQuery, CallResultHandle, FreshObjectPublicationQuery, IndexSelector,
    MemoryStoreHandle, OracleCallContext, StoreAtPoint, ValueAtPoint,
};
use super::relation::{
    OracleRelationHandle, OracleRelationOwner, OracleRelationRecord, OracleRelationSubject,
};
use super::value_flow::{ValueFlowEndpoint, ValueFlowRelation};

impl AccessPathRoot {
    /// Visit every exact semantic artifact allocation retained by this root.
    ///
    /// A call-result root owns whole relation arenas through each relation
    /// handle, not only the selected records. The traversal therefore visits
    /// every arena owner and record once per exact arena allocation. It uses
    /// pointer identity to break shared-arena cycles and an explicit stack so
    /// deeply nested heap relations cannot consume the Rust call stack.
    pub fn for_each_retained_artifact(&self, visit: impl FnMut(&Arc<SemanticArtifact>)) {
        visit_retained_artifacts(RetainedNode::AccessRoot(self), visit);
    }
}

impl AbstractLocation {
    /// Visit every exact semantic artifact allocation retained by this
    /// location's object identity, path root, and selectors.
    ///
    /// The object identity and path root are both visited even though the
    /// constructor requires them to name the same object. Call-result
    /// equality deliberately excludes audit provenance, so equal roots can
    /// retain distinct relation arenas.
    pub fn for_each_retained_artifact(&self, visit: impl FnMut(&Arc<SemanticArtifact>)) {
        visit_retained_artifacts(RetainedNode::Location(self), visit);
    }
}

enum RetainedNode<'a> {
    Procedure(&'a ProcedureHandle),
    CallContext(&'a OracleCallContext),
    CallResult(&'a CallResultHandle),
    AccessRoot(&'a AccessPathRoot),
    AccessPath(&'a AccessPath),
    AccessAtPoint(&'a AccessPathAtPoint),
    Object(&'a AbstractObject),
    Location(&'a AbstractLocation),
    ValueAtPoint(&'a ValueAtPoint),
    Alias(&'a AliasQuery),
    PublicationQuery(&'a FreshObjectPublicationQuery),
    MemoryStore(&'a MemoryStoreHandle),
    StoreAtPoint(&'a StoreAtPoint),
    Relation(&'a OracleRelationHandle),
    RelationOwner(&'a OracleRelationOwner),
    RelationRecord(&'a OracleRelationRecord),
    ValueFlow(&'a ValueFlowRelation),
    ValueFlowEndpoint(&'a ValueFlowEndpoint),
}

fn visit_retained_artifacts<'a>(
    root: RetainedNode<'a>,
    mut visit: impl FnMut(&Arc<SemanticArtifact>),
) {
    let mut stack = vec![root];
    let mut visited_relation_arenas = HashSet::new();

    while let Some(node) = stack.pop() {
        match node {
            RetainedNode::Procedure(procedure) => visit(procedure.artifact()),
            RetainedNode::CallContext(context) => {
                for call in context.calls().iter().rev() {
                    stack.push(RetainedNode::Procedure(call.procedure()));
                }
            }
            RetainedNode::CallResult(result) => {
                for relation in result.return_relations().iter().rev() {
                    stack.push(RetainedNode::ValueFlow(relation));
                }
                stack.push(RetainedNode::Relation(result.binding_relation()));
                for relation in result.dispatch_provenance().iter().rev() {
                    stack.push(RetainedNode::Relation(relation));
                }
                stack.push(RetainedNode::CallContext(result.callee_context()));
                stack.push(RetainedNode::CallContext(result.caller_context()));
                stack.push(RetainedNode::Procedure(result.callee()));
                stack.push(RetainedNode::Procedure(result.result().procedure()));
                stack.push(RetainedNode::Procedure(result.call().procedure()));
            }
            RetainedNode::AccessRoot(root) => match root {
                AccessPathRoot::Value(value) => {
                    stack.push(RetainedNode::Procedure(value.procedure()));
                }
                AccessPathRoot::CallResult(result) => {
                    stack.push(RetainedNode::CallResult(result));
                }
                AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
                    stack.push(RetainedNode::Procedure(port.procedure()));
                }
                AccessPathRoot::Allocation(allocation) => {
                    stack.push(RetainedNode::Procedure(allocation.procedure()));
                }
                AccessPathRoot::LexicalCell(location) => {
                    stack.push(RetainedNode::Procedure(location.procedure()));
                }
                AccessPathRoot::Static(locator)
                | AccessPathRoot::TypeSummary(locator)
                | AccessPathRoot::ModuleObject(locator)
                | AccessPathRoot::External(locator) => visit(locator.scope()),
            },
            RetainedNode::AccessPath(path) => {
                for selector in path.selectors().iter().rev() {
                    match selector {
                        AccessSelector::Field(field) => visit(field.scope()),
                        AccessSelector::Index(IndexSelector::Exact(index)) => {
                            stack.push(RetainedNode::Procedure(index.procedure()));
                        }
                        AccessSelector::Index(IndexSelector::Any) => {}
                    }
                }
                stack.push(RetainedNode::AccessRoot(path.root()));
            }
            RetainedNode::AccessAtPoint(access) => {
                stack.push(RetainedNode::CallContext(access.context()));
                stack.push(RetainedNode::Procedure(access.point().procedure()));
                stack.push(RetainedNode::AccessPath(access.path()));
            }
            RetainedNode::Object(object) => {
                stack.push(RetainedNode::AccessRoot(object.identity()));
            }
            RetainedNode::Location(location) => {
                stack.push(RetainedNode::AccessPath(location.path()));
                stack.push(RetainedNode::Object(location.object()));
            }
            RetainedNode::ValueAtPoint(value) => {
                stack.push(RetainedNode::CallContext(value.context()));
                stack.push(RetainedNode::Procedure(value.point().procedure()));
                stack.push(RetainedNode::Procedure(value.value().procedure()));
            }
            RetainedNode::Alias(query) => {
                stack.push(RetainedNode::AccessAtPoint(query.right()));
                stack.push(RetainedNode::AccessAtPoint(query.left()));
            }
            RetainedNode::PublicationQuery(query) => {
                stack.push(RetainedNode::CallContext(query.context()));
                stack.push(RetainedNode::Procedure(query.observation().procedure()));
                stack.push(RetainedNode::Procedure(query.ownership_start().procedure()));
                stack.push(RetainedNode::Object(query.object()));
            }
            RetainedNode::MemoryStore(store) => {
                stack.push(RetainedNode::Procedure(store.value().procedure()));
                stack.push(RetainedNode::Procedure(store.location().procedure()));
                stack.push(RetainedNode::Procedure(store.point().procedure()));
            }
            RetainedNode::StoreAtPoint(store) => {
                if let Some(base) = store.base() {
                    stack.push(RetainedNode::ValueAtPoint(base));
                }
                stack.push(RetainedNode::ValueAtPoint(store.value()));
                stack.push(RetainedNode::AccessAtPoint(store.target()));
                stack.push(RetainedNode::MemoryStore(store.store()));
            }
            RetainedNode::Relation(relation) => {
                if !visited_relation_arenas.insert(relation.arena_identity()) {
                    continue;
                }
                let arena = relation.arena();
                for record in arena.records().iter().rev() {
                    stack.push(RetainedNode::RelationRecord(record));
                }
                stack.push(RetainedNode::RelationOwner(arena.owner()));
            }
            RetainedNode::RelationOwner(owner) => match owner {
                OracleRelationOwner::Dispatch(call) => {
                    stack.push(RetainedNode::Procedure(call.procedure()));
                }
                OracleRelationOwner::ProcedureValueFlow { procedure, context } => {
                    stack.push(RetainedNode::CallContext(context));
                    stack.push(RetainedNode::Procedure(procedure));
                }
                OracleRelationOwner::CallBinding {
                    call,
                    callee,
                    context,
                } => {
                    stack.push(RetainedNode::CallContext(context));
                    stack.push(RetainedNode::Procedure(callee));
                    stack.push(RetainedNode::Procedure(call.procedure()));
                }
                OracleRelationOwner::PointsTo(value) => {
                    stack.push(RetainedNode::ValueAtPoint(value));
                }
                OracleRelationOwner::Locations(access) => {
                    stack.push(RetainedNode::AccessAtPoint(access));
                }
                OracleRelationOwner::Alias(query) => {
                    stack.push(RetainedNode::Alias(query));
                }
                OracleRelationOwner::FreshObjectPublications(query) => {
                    stack.push(RetainedNode::PublicationQuery(query));
                }
                OracleRelationOwner::StrongUpdate(store) => {
                    stack.push(RetainedNode::StoreAtPoint(store));
                }
            },
            RetainedNode::RelationRecord(record) => {
                if let Some(OracleRelationSubject::DispatchCandidate(candidate)) = record.subject()
                {
                    stack.push(RetainedNode::Procedure(candidate));
                }
                for evidence in record.evidence().iter().rev() {
                    stack.push(RetainedNode::Procedure(evidence.procedure()));
                }
            }
            RetainedNode::ValueFlow(relation) => {
                stack.push(RetainedNode::ValueFlowEndpoint(&relation.target));
                stack.push(RetainedNode::ValueFlowEndpoint(&relation.source));
                stack.push(RetainedNode::Relation(&relation.id));
                stack.push(RetainedNode::Procedure(relation.point().procedure()));
            }
            RetainedNode::ValueFlowEndpoint(endpoint) => match endpoint {
                ValueFlowEndpoint::Value(value) => {
                    stack.push(RetainedNode::Procedure(value.procedure()));
                }
                ValueFlowEndpoint::Port(port) => {
                    stack.push(RetainedNode::Procedure(port.procedure()));
                }
                ValueFlowEndpoint::Location(location) => {
                    stack.push(RetainedNode::Location(location));
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::ir::tests::{capabilities, key, minimal_procedure};
    use crate::analyzer::semantic::{
        EvidenceHandle, OracleLimits, OracleRelationArena, OracleRelationId, ProcedureId,
    };

    fn fixture_artifact() -> Arc<SemanticArtifact> {
        let key = key();
        Arc::new(
            SemanticArtifact::try_new(
                key.clone(),
                capabilities(&[]),
                vec![minimal_procedure(&key, ProcedureId::new(0), "retained", 1)],
            )
            .expect("minimal retained-artifact visitor fixture"),
        )
    }

    #[test]
    fn relation_handle_visits_unselected_sibling_record_artifacts_by_exact_allocation() {
        let selected_artifact = fixture_artifact();
        let sibling_artifact = fixture_artifact();
        assert_eq!(selected_artifact.key(), sibling_artifact.key());
        assert!(!Arc::ptr_eq(&selected_artifact, &sibling_artifact));
        let selected = selected_artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("selected fixture procedure");
        let sibling = sibling_artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("sibling fixture procedure");
        let arena = OracleRelationArena::new(
            OracleRelationOwner::ProcedureValueFlow {
                procedure: selected.clone(),
                context: OracleCallContext::empty(),
            },
            vec![
                OracleRelationRecord::dispatch_candidate(
                    selected,
                    std::iter::empty::<EvidenceHandle>(),
                    OracleLimits::default(),
                )
                .expect("selected fixture record"),
                OracleRelationRecord::dispatch_candidate(
                    sibling,
                    std::iter::empty::<EvidenceHandle>(),
                    OracleLimits::default(),
                )
                .expect("sibling fixture record"),
            ],
            OracleLimits::default(),
        )
        .expect("bounded fixture relation arena");
        let relation = arena
            .handle(OracleRelationId::new(0))
            .expect("selected fixture handle");
        assert!(matches!(
            relation.record().subject(),
            Some(OracleRelationSubject::DispatchCandidate(candidate))
                if Arc::ptr_eq(candidate.artifact(), &selected_artifact)
        ));
        assert!(matches!(
            arena
                .handle(OracleRelationId::new(1))
                .expect("unselected sibling fixture handle")
                .record()
                .subject(),
            Some(OracleRelationSubject::DispatchCandidate(candidate))
                if Arc::ptr_eq(candidate.artifact(), &sibling_artifact)
        ));

        let mut selected_allocation_only = true;
        visit_retained_artifacts(RetainedNode::Relation(&relation), |artifact| {
            selected_allocation_only &= Arc::ptr_eq(artifact, &selected_artifact);
        });
        assert!(
            !selected_allocation_only,
            "the selected handle owns its unselected sibling record's distinct artifact allocation"
        );

        let mut exact_window_covered = true;
        visit_retained_artifacts(RetainedNode::Relation(&relation), |artifact| {
            exact_window_covered &= Arc::ptr_eq(artifact, &selected_artifact)
                || Arc::ptr_eq(artifact, &sibling_artifact);
        });
        assert!(exact_window_covered);
    }
}
