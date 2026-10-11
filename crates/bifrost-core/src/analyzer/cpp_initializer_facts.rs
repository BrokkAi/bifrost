//! Structured C/C++ local-initializer candidate rows.
//!
//! The syntax producer lives in `brokk-bifrost-analysis`; these language
//! facts are kept in core so the row shape has one owner and can be shared by
//! the query layer without depending on parser implementation details.

use super::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppInitializerAccessKind {
    Read,
    Assignment,
    Increment,
    AddressOnly,
    Unevaluated,
}

impl CppInitializerAccessKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Assignment => "assignment",
            Self::Increment => "increment",
            Self::AddressOnly => "address_only",
            Self::Unevaluated => "unevaluated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppInitializerSyntaxVerdict {
    Supported,
    Excluded,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CppInitializerCandidate {
    /// The complete declaration node, which is the source anchor used by the
    /// C++ lowering's establishment event.
    pub declaration_range: Range,
    pub initializer_range: Range,
    pub access_range: Range,
    pub access_kind: CppInitializerAccessKind,
    pub verdict: CppInitializerSyntaxVerdict,
    pub storage_kind: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct CppInitializerCandidates {
    pub rows: Vec<CppInitializerCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}
