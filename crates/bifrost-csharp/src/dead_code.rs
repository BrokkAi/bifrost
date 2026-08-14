//! The three C# predicates behind the dead-code bulk route.
//!
//! `CSharpDeadCodeBulk` (the `DeadCodeBulkProof` impl) stays in
//! `brokk-bifrost-analysis` because the SPI trait is analysis-owned; what
//! disqualifies a C# candidate is language knowledge and lives here.

use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language};

pub fn csharp_constructor_candidate(index: &dyn CodeUnitIndex, candidate: &CodeUnit) -> bool {
    candidate.is_function()
        && index
            .parent_of(candidate)
            .is_some_and(|parent| candidate.identifier() == parent.identifier())
}

pub fn csharp_unsafe_using_member_forms_present(index: &dyn CodeUnitIndex) -> bool {
    index
        .project()
        .analyzable_files(Language::CSharp)
        .is_ok_and(|files| {
            files.into_iter().any(|file| {
                file.read_to_string()
                    .is_ok_and(|source| csharp_source_has_unsafe_using_member_form(&source))
            })
        })
}

pub fn csharp_source_has_unsafe_using_member_form(source: &str) -> bool {
    static STATIC_USING_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?m)^\s*(?:global\s+)?using\s+static\b")
            .expect("valid csharp static using regex")
    });
    static ALIAS_USING_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?m)^\s*(?:global\s+)?using\s+[A-Za-z_][A-Za-z0-9_]*\s*=")
            .expect("valid csharp alias using regex")
    });
    STATIC_USING_RE.is_match(source) || ALIAS_USING_RE.is_match(source)
}
