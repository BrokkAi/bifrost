/// How completely a call, reference, or boundary lookup answered the question
/// dispatch asked. `workspace_oracle::dispatch` reports this as its
/// `SemanticOutcome` variant; the external-reference probe reports it as one
/// chain link (#1885) alongside the boundary and trace evidence the same
/// lookup produced, so the two must read one mapping rather than two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(crate::analyzer::semantic::SemanticCapability),
    Truncated,
    Cancelled,
}
