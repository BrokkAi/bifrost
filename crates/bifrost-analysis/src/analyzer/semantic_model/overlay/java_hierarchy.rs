//! Bounded Java subtype evidence over activated declaration facts.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaHierarchyIncomplete {
    MissingHierarchy,
    Ambiguous,
    GenericSubstitution,
    BudgetExhausted,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaHierarchyWitness {
    /// Exact declaration provenance, in source-to-supertype order.
    pub declarations: Vec<SemanticModelProvenance>,
    pub edges: Vec<HierarchyFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaHierarchyAnswer {
    pub witness: Option<JavaHierarchyWitness>,
    /// Enumeration completeness is independent of a positive path witness.
    pub incomplete: Vec<JavaHierarchyIncomplete>,
}

impl SemanticModelOverlay {
    pub(crate) fn java_reference_widening(
        &self,
        source: &SemanticModelSymbol,
        target: &SemanticModelSymbol,
        max_visits: usize,
        cancellation: Option<&crate::CancellationToken>,
    ) -> JavaHierarchyAnswer {
        let mut answer = JavaHierarchyAnswer {
            witness: None,
            incomplete: Vec::new(),
        };
        let mut pending = VecDeque::from([(source, vec![source.provenance.clone()], Vec::new())]);
        let mut seen = HashSet::default();
        let mut visited = 0;
        let mut edge_visits = 0;
        while let Some((current, path, path_edges)) = pending.pop_front() {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                answer.incomplete.push(JavaHierarchyIncomplete::Cancelled);
                break;
            }
            if !seen.insert(current.id.as_str()) {
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
            let Some((parameters, edges)) = self.java_hierarchy.get(&current.id) else {
                answer
                    .incomplete
                    .push(JavaHierarchyIncomplete::MissingHierarchy);
                continue;
            };
            if !parameters.is_empty() {
                answer
                    .incomplete
                    .push(JavaHierarchyIncomplete::GenericSubstitution);
                continue;
            }
            if current.id == target.id {
                answer.witness.get_or_insert(JavaHierarchyWitness {
                    declarations: path,
                    edges: path_edges,
                });
                continue;
            }
            if current.provenance.completeness != SemanticModelCompleteness::Complete {
                answer
                    .incomplete
                    .push(JavaHierarchyIncomplete::MissingHierarchy);
            }
            for edge in edges {
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
                let name = match &edge.target {
                    TypeRef::Named {
                        name, arguments, ..
                    } if arguments.is_empty() => name,
                    TypeRef::Declared { id, arguments, .. } if arguments.is_empty() => id,
                    _ => {
                        answer
                            .incomplete
                            .push(JavaHierarchyIncomplete::GenericSubstitution);
                        continue;
                    }
                };
                let resolved = self.resolve_edge_target(name, "java");
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
                pending.push_back((next, next_path, next_edges));
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
