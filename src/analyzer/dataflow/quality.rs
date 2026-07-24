//! Concrete path-quality tracking.

use crate::analyzer::semantic::{EvidenceCompleteness, IcfgEdge, ProofStatus};

/// Proof and completeness retained from one concrete reached path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathQuality {
    proven: bool,
    complete: bool,
}

impl PathQuality {
    pub const PROVEN_COMPLETE: Self = Self::new(true, true);
    pub const PROVEN_PARTIAL: Self = Self::new(true, false);
    pub const UNPROVEN_COMPLETE: Self = Self::new(false, true);
    pub const UNPROVEN_PARTIAL: Self = Self::new(false, false);
    const ALL: [Self; 4] = [
        Self::PROVEN_COMPLETE,
        Self::PROVEN_PARTIAL,
        Self::UNPROVEN_COMPLETE,
        Self::UNPROVEN_PARTIAL,
    ];

    const fn new(proven: bool, complete: bool) -> Self {
        Self { proven, complete }
    }

    pub const fn is_proven(self) -> bool {
        self.proven
    }

    pub const fn is_complete(self) -> bool {
        self.complete
    }

    /// Conjoin the proof and completeness of two concrete path segments.
    ///
    /// Summary tabulation keeps a callee path relative to its own entry. A
    /// matched return uses this operation to reattach the exact incoming-call
    /// prefix without joining proof from one path with completeness from
    /// another.
    pub(crate) const fn conjoin(self, other: Self) -> Self {
        Self {
            proven: self.proven && other.proven,
            complete: self.complete && other.complete,
        }
    }

    /// Retain this path's quality through one owned semantic edge profile.
    pub(crate) fn through_evidence(
        self,
        proof: &ProofStatus,
        completeness: &EvidenceCompleteness,
    ) -> Self {
        Self {
            proven: self.proven && matches!(proof, ProofStatus::Proven),
            complete: self.complete && matches!(completeness, EvidenceCompleteness::Complete),
        }
    }

    pub(crate) fn through_edge(self, edge: &IcfgEdge) -> Self {
        self.through_evidence(&edge.proof, &edge.completeness)
    }

    const fn dominates(self, other: Self) -> bool {
        (!other.proven || self.proven) && (!other.complete || self.complete)
    }

    const fn strictly_dominates(self, other: Self) -> bool {
        (self.proven != other.proven || self.complete != other.complete) && self.dominates(other)
    }
}

/// The component-wise nondominated concrete path qualities for one state.
///
/// `PROVEN_PARTIAL` and `UNPROVEN_COMPLETE` are incomparable and therefore
/// may coexist. Keeping both is necessary because edge conjunction can make
/// either one the stronger continuation later; combining their axes would
/// invent a path quality that no concrete path established.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathQualityFrontier {
    bits: u8,
}

impl PathQualityFrontier {
    pub(crate) const fn singleton(quality: PathQuality) -> Self {
        Self {
            bits: quality_bit(quality),
        }
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    pub const fn contains(self, quality: PathQuality) -> bool {
        self.bits & quality_bit(quality) != 0
    }

    pub const fn has_proven_path(self) -> bool {
        self.contains(PathQuality::PROVEN_COMPLETE) || self.contains(PathQuality::PROVEN_PARTIAL)
    }

    pub const fn has_complete_path(self) -> bool {
        self.contains(PathQuality::PROVEN_COMPLETE) || self.contains(PathQuality::UNPROVEN_COMPLETE)
    }

    pub const fn has_proven_complete_path(self) -> bool {
        self.contains(PathQuality::PROVEN_COMPLETE)
    }

    /// Insert one concrete path quality and discard only qualities it
    /// component-wise dominates. Returns whether the frontier changed.
    pub(crate) fn insert(&mut self, candidate: PathQuality) -> bool {
        if self.iter().any(|existing| existing.dominates(candidate)) {
            return false;
        }

        let before = self.bits;
        for existing in PathQuality::ALL {
            if candidate.strictly_dominates(existing) {
                self.bits &= !quality_bit(existing);
            }
        }
        self.bits |= quality_bit(candidate);
        self.bits != before
    }

    pub fn iter(self) -> impl Iterator<Item = PathQuality> {
        PathQuality::ALL
            .into_iter()
            .filter(move |quality| self.contains(*quality))
    }
}

const fn quality_bit(quality: PathQuality) -> u8 {
    let index = (quality.proven as u8) * 2 + quality.complete as u8;
    1 << index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{ControlEdgeKind, IcfgEdgeKind, IcfgNodeId};

    #[test]
    fn path_quality_frontier_preserves_incomparable_paths() {
        let mut frontier = PathQualityFrontier::default();

        assert!(frontier.insert(PathQuality::PROVEN_PARTIAL));
        assert!(frontier.insert(PathQuality::UNPROVEN_COMPLETE));
        assert_eq!(
            frontier.iter().collect::<Vec<_>>(),
            vec![PathQuality::PROVEN_PARTIAL, PathQuality::UNPROVEN_COMPLETE]
        );
        assert!(frontier.has_proven_path());
        assert!(frontier.has_complete_path());
        assert!(!frontier.has_proven_complete_path());
    }

    #[test]
    fn proven_complete_path_dominates_the_entire_frontier() {
        let mut frontier = PathQualityFrontier::default();
        frontier.insert(PathQuality::PROVEN_PARTIAL);
        frontier.insert(PathQuality::UNPROVEN_COMPLETE);

        assert!(frontier.insert(PathQuality::PROVEN_COMPLETE));
        assert_eq!(
            frontier.iter().collect::<Vec<_>>(),
            vec![PathQuality::PROVEN_COMPLETE]
        );
    }

    #[test]
    fn incomparable_paths_are_reduced_only_after_edge_conjunction() {
        let mut frontier = PathQualityFrontier::default();
        frontier.insert(PathQuality::PROVEN_PARTIAL);
        frontier.insert(PathQuality::UNPROVEN_COMPLETE);
        let edge = IcfgEdge {
            source: IcfgNodeId::new(0),
            target: IcfgNodeId::new(1),
            kind: IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Normal),
            origin: None,
            proof: ProofStatus::Unproven("test suffix".into()),
            completeness: EvidenceCompleteness::Complete,
        };

        let mut after_edge = PathQualityFrontier::default();
        for quality in frontier.iter() {
            after_edge.insert(quality.through_edge(&edge));
        }

        assert_eq!(
            after_edge.iter().collect::<Vec<_>>(),
            vec![PathQuality::UNPROVEN_COMPLETE]
        );
    }

    #[test]
    fn concrete_path_segments_conjoin_component_wise() {
        assert_eq!(
            PathQuality::PROVEN_PARTIAL.conjoin(PathQuality::UNPROVEN_COMPLETE),
            PathQuality::UNPROVEN_PARTIAL
        );
        assert_eq!(
            PathQuality::PROVEN_COMPLETE.through_evidence(
                &ProofStatus::Unproven("test evidence".into()),
                &EvidenceCompleteness::Complete,
            ),
            PathQuality::UNPROVEN_COMPLETE
        );
    }
}
