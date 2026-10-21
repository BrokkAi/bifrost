use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConversionUnknown {
    UnsupportedLanguage,
    UnresolvedSignature,
    UnresolvedSourceType,
    UnresolvedTargetType,
    AmbiguousBinding,
    GenericSubstitution,
    UnsupportedConversion,
    UnsupportedExpression,
    IncompleteHierarchy,
    BudgetExhausted,
    Cancelled,
    /// Another actual prevents establishing applicability of this signature.
    SignatureApplicability,
}

impl ConversionUnknown {
    pub const LABELS: &'static [&'static str] = &[
        "unsupported_language",
        "unresolved_signature",
        "unresolved_source_type",
        "unresolved_target_type",
        "ambiguous_binding",
        "generic_substitution",
        "unsupported_conversion",
        "unsupported_expression",
        "incomplete_hierarchy",
        "budget_exhausted",
        "cancelled",
        "signature_applicability",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::UnsupportedLanguage => "unsupported_language",
            Self::UnresolvedSignature => "unresolved_signature",
            Self::UnresolvedSourceType => "unresolved_source_type",
            Self::UnresolvedTargetType => "unresolved_target_type",
            Self::AmbiguousBinding => "ambiguous_binding",
            Self::GenericSubstitution => "generic_substitution",
            Self::UnsupportedConversion => "unsupported_conversion",
            Self::UnsupportedExpression => "unsupported_expression",
            Self::IncompleteHierarchy => "incomplete_hierarchy",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Cancelled => "cancelled",
            Self::SignatureApplicability => "signature_applicability",
        }
    }
}
