//! Deterministic validation and querying of explicit `supersedes` graphs.
//!
//! Edges point from the dominant declaration to the declaration it
//! supersedes. The graph never derives precedence from source order,
//! categories, paths, or selector text.

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecedenceError<K> {
    DuplicateNode { node: K },
    DanglingEdge { dominant: K, dominated: K },
    SelfEdge { node: K },
    Cycle { nodes: Vec<K> },
    UnknownCandidate { node: K },
    AmbiguousWinners { winners: Vec<K> },
}

impl<K: fmt::Debug> fmt::Display for PrecedenceError<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateNode { node } => write!(formatter, "duplicate precedence node {node:?}"),
            Self::DanglingEdge {
                dominant,
                dominated,
            } => write!(
                formatter,
                "precedence edge {dominant:?} -> {dominated:?} names an unknown node"
            ),
            Self::SelfEdge { node } => {
                write!(
                    formatter,
                    "precedence node {node:?} cannot supersede itself"
                )
            }
            Self::Cycle { nodes } => write!(
                formatter,
                "precedence graph contains a cycle through {nodes:?}"
            ),
            Self::UnknownCandidate { node } => {
                write!(
                    formatter,
                    "precedence candidate {node:?} is not in the graph"
                )
            }
            Self::AmbiguousWinners { winners } => {
                write!(formatter, "precedence has incomparable winners {winners:?}")
            }
        }
    }
}

impl<K: fmt::Debug> std::error::Error for PrecedenceError<K> {}

/// A validated finite DAG with stable node and edge order.
#[derive(Debug, Clone)]
pub struct PrecedenceGraph<K> {
    nodes: Vec<K>,
    positions: HashMap<K, usize>,
    outgoing: Vec<Vec<usize>>,
    edges: Vec<(K, K)>,
}

impl<K> PrecedenceGraph<K>
where
    K: Clone + Eq + Hash + Ord,
{
    pub fn try_new(
        nodes: impl IntoIterator<Item = K>,
        edges: impl IntoIterator<Item = (K, K)>,
    ) -> Result<Self, PrecedenceError<K>> {
        let mut nodes: Vec<_> = nodes.into_iter().collect();
        nodes.sort();
        if let Some(pair) = nodes.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(PrecedenceError::DuplicateNode {
                node: pair[0].clone(),
            });
        }

        let positions: HashMap<_, _> = nodes
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, node)| (node, index))
            .collect();
        let mut edges: Vec<_> = edges.into_iter().collect();
        edges.sort();
        edges.dedup();
        let mut outgoing = vec![Vec::new(); nodes.len()];
        let mut indegrees = vec![0_usize; nodes.len()];

        for (dominant, dominated) in &edges {
            if dominant == dominated {
                return Err(PrecedenceError::SelfEdge {
                    node: dominant.clone(),
                });
            }
            let Some(&dominant_index) = positions.get(dominant) else {
                return Err(PrecedenceError::DanglingEdge {
                    dominant: dominant.clone(),
                    dominated: dominated.clone(),
                });
            };
            let Some(&dominated_index) = positions.get(dominated) else {
                return Err(PrecedenceError::DanglingEdge {
                    dominant: dominant.clone(),
                    dominated: dominated.clone(),
                });
            };
            outgoing[dominant_index].push(dominated_index);
            indegrees[dominated_index] += 1;
        }
        for successors in &mut outgoing {
            successors.sort_unstable();
            successors.dedup();
        }

        // Kahn's algorithm is iterative and stable because the ready stack is
        // maintained in reverse index order.
        let mut ready: Vec<_> = indegrees
            .iter()
            .enumerate()
            .filter_map(|(index, degree)| (*degree == 0).then_some(index))
            .collect();
        ready.sort_unstable_by(|left, right| right.cmp(left));
        let mut visited = 0_usize;
        while let Some(index) = ready.pop() {
            visited += 1;
            for &successor in &outgoing[index] {
                indegrees[successor] -= 1;
                if indegrees[successor] == 0 {
                    ready.push(successor);
                    ready.sort_unstable_by(|left, right| right.cmp(left));
                }
            }
        }
        if visited != nodes.len() {
            let cycle_nodes = indegrees
                .iter()
                .enumerate()
                .filter(|(_, degree)| **degree > 0)
                .map(|(index, _)| nodes[index].clone())
                .collect();
            return Err(PrecedenceError::Cycle { nodes: cycle_nodes });
        }

        Ok(Self {
            nodes,
            positions,
            outgoing,
            edges,
        })
    }

    pub fn edges(&self) -> &[(K, K)] {
        &self.edges
    }

    /// Return whether `dominant` transitively supersedes `dominated`.
    pub fn dominates(&self, dominant: &K, dominated: &K) -> bool {
        let (Some(&start), Some(&target)) =
            (self.positions.get(dominant), self.positions.get(dominated))
        else {
            return false;
        };
        if start == target {
            return false;
        }

        let mut seen = vec![false; self.nodes.len()];
        let mut stack = vec![start];
        seen[start] = true;
        while let Some(index) = stack.pop() {
            for &successor in self.outgoing[index].iter().rev() {
                if successor == target {
                    return true;
                }
                if !seen[successor] {
                    seen[successor] = true;
                    stack.push(successor);
                }
            }
        }
        false
    }

    /// Select the one non-superseded candidate, if the candidate set is
    /// non-empty. An incomparable live set is an explicit ambiguity.
    pub fn unique_winner(
        &self,
        candidates: impl IntoIterator<Item = K>,
    ) -> Result<Option<K>, PrecedenceError<K>> {
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        candidates.sort();
        candidates.dedup();
        for candidate in &candidates {
            if !self.positions.contains_key(candidate) {
                return Err(PrecedenceError::UnknownCandidate {
                    node: candidate.clone(),
                });
            }
        }

        let winners: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                !candidates
                    .iter()
                    .any(|other| other != *candidate && self.dominates(other, candidate))
            })
            .cloned()
            .collect();
        match winners.as_slice() {
            [] => Ok(None),
            [winner] => Ok(Some(winner.clone())),
            _ => Err(PrecedenceError::AmbiguousWinners { winners }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_dangling_edges_and_cycles() {
        assert!(matches!(
            PrecedenceGraph::try_new(["a"], [("a", "missing")]),
            Err(PrecedenceError::DanglingEdge { .. })
        ));
        assert!(matches!(
            PrecedenceGraph::try_new(["a", "b"], [("a", "b"), ("b", "a")]),
            Err(PrecedenceError::Cycle { .. })
        ));
    }

    #[test]
    fn finds_transitive_unique_winner_and_rejects_incomparable_winners() {
        let graph = PrecedenceGraph::try_new(
            ["broad", "specific", "most-specific", "other"],
            [("specific", "broad"), ("most-specific", "specific")],
        )
        .unwrap();
        assert!(graph.dominates(&"most-specific", &"broad"));
        assert_eq!(
            graph
                .unique_winner(["broad", "specific", "most-specific"])
                .unwrap(),
            Some("most-specific")
        );
        assert!(matches!(
            graph.unique_winner(["specific", "other"]),
            Err(PrecedenceError::AmbiguousWinners { .. })
        ));
    }
}
