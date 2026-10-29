//! Bounded Java subtype evidence over activated declaration facts.

use super::*;
// Preserve the overlay path even when names arrive through the parent glob.
#[allow(unused_imports)]
pub use brokk_bifrost_semantic::analyzer::semantic_model::overlay::java_hierarchy::*;
impl SemanticModelOverlay {
    #[doc(hidden)]
    pub fn java_reference_widening(
        &self,
        source: &Arc<SemanticModelSymbol>,
        target: &SemanticModelSymbol,
        max_visits: usize,
        cancellation: Option<&crate::CancellationToken>,
    ) -> JavaHierarchyAnswer {
        self.java_widening_with_hierarchy(
            source,
            target,
            max_visits,
            cancellation,
            |current| {
                let (parameters, edges) = self
                    .java_hierarchy
                    .get(&current.id)
                    .ok_or(JavaHierarchyIncomplete::MissingHierarchy)?;
                if !parameters.is_empty() {
                    return Err(JavaHierarchyIncomplete::GenericSubstitution);
                }
                Ok((
                    edges.clone(),
                    current.provenance.completeness == SemanticModelCompleteness::Complete,
                ))
            },
            |ty| match ty {
                TypeRef::Named {
                    name, arguments, ..
                } if arguments.is_empty() => Some(name),
                TypeRef::Declared { id, arguments, .. } if arguments.is_empty() => Some(id),
                _ => None,
            },
        )
    }

    /// Nominal erasure evidence for invocation conversion. The indexed owner's
    /// supertype inventory is independent of callable-family completeness.
    /// Generic argument compatibility remains the invocation consumer's job.
    pub fn java_erased_reference_widening(
        &self,
        active: &ResolvedActiveSemanticModels,
        source: &Arc<SemanticModelSymbol>,
        target: &SemanticModelSymbol,
        max_visits: usize,
        cancellation: Option<&crate::CancellationToken>,
    ) -> JavaHierarchyAnswer {
        self.java_widening_with_hierarchy(
            source,
            target,
            max_visits,
            cancellation,
            |current| {
                let owner = owner_declaration(active, current)
                    .ok_or(JavaHierarchyIncomplete::MissingHierarchy)?;
                let inventory = owner
                    .jvm_inventory
                    .as_ref()
                    .ok_or(JavaHierarchyIncomplete::MissingHierarchy)?;
                Ok((inventory.supertypes.clone(), inventory.supertypes_complete))
            },
            |ty| match ty {
                TypeRef::Named { name, .. } => Some(name),
                TypeRef::Declared { id, .. } => Some(id),
                _ => None,
            },
        )
    }

    fn java_widening_with_hierarchy(
        &self,
        source: &Arc<SemanticModelSymbol>,
        target: &SemanticModelSymbol,
        max_visits: usize,
        cancellation: Option<&crate::CancellationToken>,
        hierarchy: impl Fn(
            &SemanticModelSymbol,
        ) -> Result<(Vec<HierarchyFact>, bool), JavaHierarchyIncomplete>,
        edge_name: impl Fn(&TypeRef) -> Option<&str>,
    ) -> JavaHierarchyAnswer {
        let mut answer = JavaHierarchyAnswer {
            witness: None,
            incomplete: Vec::new(),
        };
        let mut pending = VecDeque::from([(
            Arc::clone(source),
            vec![source.provenance.clone()],
            Vec::new(),
        )]);
        let mut seen = HashSet::default();
        let mut visited = 0;
        let mut edge_visits = 0;
        while let Some((current, path, path_edges)) = pending.pop_front() {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                answer.incomplete.push(JavaHierarchyIncomplete::Cancelled);
                break;
            }
            if !seen.insert(current.id.clone()) {
                continue;
            }
            if visited == max_visits {
                answer
                    .incomplete
                    .push(JavaHierarchyIncomplete::BudgetExhausted);
                break;
            }
            visited += 1;
            if current.provenance.ambiguous || target.provenance.ambiguous {
                answer.incomplete.push(JavaHierarchyIncomplete::Ambiguous);
                continue;
            }
            if current.language != "java"
                || target.language != "java"
                || !matches!(
                    current.kind,
                    SemanticModelSymbolKind::Class | SemanticModelSymbolKind::Interface
                )
                || !matches!(
                    target.kind,
                    SemanticModelSymbolKind::Class | SemanticModelSymbolKind::Interface
                )
            {
                answer
                    .incomplete
                    .push(JavaHierarchyIncomplete::MissingHierarchy);
                continue;
            }
            let (edges, complete) = match hierarchy(&current) {
                Ok(evidence) => evidence,
                Err(reason) => {
                    answer.incomplete.push(reason);
                    continue;
                }
            };
            if current.id == target.id {
                answer.witness.get_or_insert(JavaHierarchyWitness {
                    declarations: path,
                    edges: path_edges,
                });
                continue;
            }
            if !complete {
                answer
                    .incomplete
                    .push(JavaHierarchyIncomplete::MissingHierarchy);
            }
            for edge in &edges {
                if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                    answer.incomplete.push(JavaHierarchyIncomplete::Cancelled);
                    pending.clear();
                    break;
                }
                if edge_visits == max_visits {
                    answer
                        .incomplete
                        .push(JavaHierarchyIncomplete::BudgetExhausted);
                    break;
                }
                edge_visits += 1;
                if !matches!(
                    edge.hierarchy_kind,
                    HierarchyKind::Extends | HierarchyKind::Implements
                ) {
                    continue;
                }
                let Some(name) = edge_name(&edge.target) else {
                    answer
                        .incomplete
                        .push(JavaHierarchyIncomplete::GenericSubstitution);
                    continue;
                };
                let resolved = self.resolve_edge_target(name, "java", HierarchyTargetShape::Type);
                if let Some(defect) = resolved.defect {
                    answer
                        .incomplete
                        .push(if defect == SemanticModelEdgeDefect::Ambiguous {
                            JavaHierarchyIncomplete::Ambiguous
                        } else {
                            JavaHierarchyIncomplete::MissingHierarchy
                        });
                    continue;
                }
                let [next] = resolved.records.as_slice() else {
                    answer.incomplete.push(JavaHierarchyIncomplete::Ambiguous);
                    continue;
                };
                let mut next_path = path.clone();
                next_path.push(next.provenance.clone());
                let mut next_edges = path_edges.clone();
                next_edges.push(edge.clone());
                pending.push_back((Arc::clone(next), next_path, next_edges));
            }
        }
        let mut unique = Vec::new();
        for reason in answer.incomplete {
            if !unique.contains(&reason) {
                unique.push(reason);
            }
        }
        answer.incomplete = unique;
        answer
    }
}
