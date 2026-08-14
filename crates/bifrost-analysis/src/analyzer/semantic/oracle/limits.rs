use std::fmt;

/// Public values accepted by [`OracleLimits::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OracleLimitValues {
    pub dispatch_targets: usize,
    pub objects_per_value: usize,
    pub access_path_length: usize,
    pub alias_breadth: usize,
    /// Maximum number of point-sensitive observations retained when a source
    /// range is projected into semantic values and program points.
    pub source_observations: usize,
    pub call_context_depth: usize,
    /// Maximum number of transitive value-summary edges followed by one heap
    /// trace before the retained candidate set becomes truncated.
    pub summary_depth: usize,
    pub call_binding_entries: usize,
    pub provenance_records: usize,
    pub evidence_handles: usize,
}

impl OracleLimitValues {
    pub const fn uniform(value: usize) -> Self {
        Self {
            dispatch_targets: value,
            objects_per_value: value,
            access_path_length: value,
            alias_breadth: value,
            source_observations: value,
            call_context_depth: value,
            summary_depth: value,
            call_binding_entries: value,
            provenance_records: value,
            evidence_handles: value,
        }
    }
}

/// One invalid oracle-limit dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvalidOracleLimits {
    dimension: &'static str,
}

impl InvalidOracleLimits {
    pub const fn dimension(self) -> &'static str {
        self.dimension
    }
}

impl fmt::Display for InvalidOracleLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "oracle limit `{}` must be positive",
            self.dimension
        )
    }
}

impl std::error::Error for InvalidOracleLimits {}

/// Positive finite bounds shared by dispatch, value-flow, and heap queries.
///
/// These limits bound retained answer shapes and semantic expansion depth.
/// [`crate::analyzer::semantic::SemanticBudget`] independently bounds total
/// traversal and materialization work. Roots, selectors, and paths are
/// currently owned inline by bounded candidates rather than by a long-lived
/// interner, so their retention is covered by the candidate, provenance, and
/// path-length limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OracleLimits {
    values: OracleLimitValues,
}

impl OracleLimits {
    pub fn new(values: OracleLimitValues) -> Result<Self, InvalidOracleLimits> {
        let dimensions = [
            ("dispatch_targets", values.dispatch_targets),
            ("objects_per_value", values.objects_per_value),
            ("access_path_length", values.access_path_length),
            ("alias_breadth", values.alias_breadth),
            ("source_observations", values.source_observations),
            ("call_context_depth", values.call_context_depth),
            ("summary_depth", values.summary_depth),
            ("call_binding_entries", values.call_binding_entries),
            ("provenance_records", values.provenance_records),
            ("evidence_handles", values.evidence_handles),
        ];
        for (dimension, value) in dimensions {
            if value == 0 {
                return Err(InvalidOracleLimits { dimension });
            }
        }
        Ok(Self { values })
    }

    pub fn uniform(value: usize) -> Result<Self, InvalidOracleLimits> {
        Self::new(OracleLimitValues::uniform(value))
    }

    pub const fn values(self) -> OracleLimitValues {
        self.values
    }

    pub const fn dispatch_targets(self) -> usize {
        self.values.dispatch_targets
    }

    pub const fn objects_per_value(self) -> usize {
        self.values.objects_per_value
    }

    pub const fn access_path_length(self) -> usize {
        self.values.access_path_length
    }

    pub const fn alias_breadth(self) -> usize {
        self.values.alias_breadth
    }

    pub const fn source_observations(self) -> usize {
        self.values.source_observations
    }

    pub const fn call_context_depth(self) -> usize {
        self.values.call_context_depth
    }

    pub const fn summary_depth(self) -> usize {
        self.values.summary_depth
    }

    pub const fn call_binding_entries(self) -> usize {
        self.values.call_binding_entries
    }

    pub const fn provenance_records(self) -> usize {
        self.values.provenance_records
    }

    pub const fn evidence_handles(self) -> usize {
        self.values.evidence_handles
    }
}

impl Default for OracleLimits {
    fn default() -> Self {
        Self::new(OracleLimitValues {
            dispatch_targets: 1_024,
            objects_per_value: 256,
            access_path_length: 8,
            alias_breadth: 1_024,
            source_observations: 1_024,
            call_context_depth: 2,
            // Match the established receiver-analysis expansion budget now
            // that this limit governs real reaching-definition traversal.
            summary_depth: 64,
            call_binding_entries: 4_096,
            provenance_records: 4_096,
            evidence_handles: 4_096,
        })
        .expect("default oracle limits are positive")
    }
}
