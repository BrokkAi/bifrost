//! Engine configuration layered over the immutable store epoch.
use crate::analyzer::Language;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use crate::analyzer::source_admission::SourceAdmissionPolicy;
use tree_sitter::Language as TsLanguage;

/// Returns the analysis epoch for a language as a hex string.
///
/// The immutable grammar/query base is cached. The source-admission policy is
/// folded outside that cache on each call, for every language, so a later
/// analyzer construction observes the current policy and a policy change
/// re-indexes the files it may admit or refuse differently (#10694).
/// Always pass the canonical parser for `language`.
#[doc(hidden)]
pub fn epoch_for(language: Language, ts_language: &TsLanguage) -> String {
    epoch_for_policy(language, ts_language, SourceAdmissionPolicy::current())
}

fn epoch_for_policy(
    language: Language,
    ts_language: &TsLanguage,
    policy: SourceAdmissionPolicy,
) -> String {
    let base = crate::analyzer::store::epoch::base_epoch_for(language, ts_language);
    // #5408 bound C++ generations to the admission policy; #4479 added
    // JavaScript and TypeScript, and #10694 every language.
    let mut hasher = CanonicalHasher::new(b"bifrost-admission-analysis-epoch:v1");
    hasher.field("grammar_query_base", base.as_bytes());
    policy.hash_identity(&mut hasher);
    lower_hex_string(&hasher.finish())
}

#[cfg(test)]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#5408: cached grammar epoch concealed later C++ admission settings"
)]
fn configured_structural_line_epoch_reuses_base_without_caching_policy() {
    let cpp = tree_sitter_cpp::LANGUAGE.into();
    let default = SourceAdmissionPolicy::from_setting(None);
    let explicit = SourceAdmissionPolicy::from_setting(Some("16000"));
    let unlimited = SourceAdmissionPolicy::from_setting(Some("0"));
    let first = epoch_for_policy(Language::Cpp, &cpp, default);
    assert_ne!(first, epoch_for_policy(Language::Cpp, &cpp, explicit));
    assert_ne!(first, epoch_for_policy(Language::Cpp, &cpp, unlimited));
    assert_eq!(first, epoch_for_policy(Language::Cpp, &cpp, default));
    assert_eq!(
        first,
        epoch_for_policy(
            Language::Cpp,
            &cpp,
            SourceAdmissionPolicy::from_setting(Some("invalid"))
        )
    );
    assert_eq!(
        epoch_for_policy(Language::Cpp, &cpp, explicit),
        epoch_for_policy(
            Language::Cpp,
            &cpp,
            SourceAdmissionPolicy::from_setting(Some(" 016000 "))
        )
    );
    let rust = tree_sitter_rust::LANGUAGE.into();
    assert_ne!(
        epoch_for_policy(Language::Rust, &rust, default),
        epoch_for_policy(Language::Rust, &rust, explicit)
    );
    let python = tree_sitter_python::LANGUAGE.into();
    assert_ne!(
        epoch_for_policy(Language::Python, &python, default),
        epoch_for_policy(Language::Python, &python, explicit)
    );
    assert_eq!(
        epoch_for_policy(Language::Python, &python, default),
        epoch_for_policy(
            Language::Python,
            &python,
            SourceAdmissionPolicy::from_setting(Some("invalid"))
        )
    );
}
