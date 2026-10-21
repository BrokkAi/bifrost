/// Resource counted by the bounded structural admission proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDimension {
    SourceBytes,
    Nodes,
    Depth,
    SpanBytes,
    ExcludedNodes,
}

/// Why source admission refused a file, distinct from I/O, cancellation,
/// and parser timeouts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceAdmissionRefusal {
    Binary,
    ProofRejected,
    StructuralLine {
        limit: usize,
        observed: usize,
    },
    Budget {
        dimension: AdmissionDimension,
        limit: usize,
        observed: usize,
    },
}

impl std::fmt::Display for SourceAdmissionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source admission refused: {self:?}")
    }
}

impl SourceAdmissionRefusal {
    /// Whether consumers may omit this source while reporting incomplete inventory.
    pub fn is_intrinsic_source_rejection(&self) -> bool {
        matches!(
            self,
            Self::Binary | Self::StructuralLine { .. } | Self::Budget { .. }
        )
    }
}
