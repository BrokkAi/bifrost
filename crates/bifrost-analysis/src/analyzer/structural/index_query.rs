//! Query-neutral inputs and observations for structural posting lookups.

use super::{NormalizedKind, Role};

/// One conjunctive source-anchor requirement. A source containing none of the
/// alternatives cannot satisfy the caller's lookup.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceAnchorGroup {
    alternatives: Vec<String>,
}

impl SourceAnchorGroup {
    pub fn new(alternatives: Vec<String>) -> Self {
        debug_assert!(!alternatives.is_empty());
        Self { alternatives }
    }

    pub fn alternatives(&self) -> &[String] {
        &self.alternatives
    }

    pub fn may_match_source(&self, source: &str) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| source.contains(alternative))
    }
}

/// One positive, representation-neutral posting term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralPostingTerm {
    Kinds(Vec<NormalizedKind>),
    ExactName(Vec<String>),
    RoleName { role: Role, names: Vec<String> },
    KwargKeyword(String),
}

impl StructuralPostingTerm {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Kinds(_) => "kind",
            Self::ExactName(_) => "name",
            Self::RoleName { .. } => "role_name",
            Self::KwargKeyword(_) => "kwarg",
        }
    }
}

/// Positive constraints available to a structural posting implementation.
#[derive(Debug, Clone, Default)]
pub struct StructuralAccessRequirements {
    terms: Vec<StructuralPostingTerm>,
}

impl StructuralAccessRequirements {
    pub fn new(terms: Vec<StructuralPostingTerm>) -> Self {
        Self { terms }
    }

    pub fn terms(&self) -> &[StructuralPostingTerm] {
        &self.terms
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(terms: Vec<StructuralPostingTerm>) -> Self {
        Self::new(terms)
    }
}

/// Storage-independent access path chosen for one provider scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralAccessPathKind {
    ScanOnly,
    Posting,
}

impl StructuralAccessPathKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ScanOnly => "scan_only",
            Self::Posting => "posting",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralPostingEstimate {
    pub label: &'static str,
    pub candidate_facts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralAccessPathEstimate {
    pub kind: StructuralAccessPathKind,
    pub provider_files: u64,
    pub scoped_files: u64,
    pub scoped_fact_nodes: u64,
    pub candidate_files: u64,
    pub candidate_facts: u64,
    pub selected_terms: Vec<StructuralPostingEstimate>,
    pub source_verification_required: bool,
    pub cache_ready_before_lookup: bool,
}

pub const fn supports_exact_role_name_posting(role: Role) -> bool {
    matches!(role, Role::Callee | Role::Module)
}
