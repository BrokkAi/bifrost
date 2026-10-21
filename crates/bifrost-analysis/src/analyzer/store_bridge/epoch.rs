//! Engine configuration layered over the immutable store epoch.
use crate::analyzer::Language;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use crate::analyzer::source_admission::SourceAdmissionPolicy;
use std::borrow::Cow;
use tree_sitter::Language as TsLanguage;

/// Returns the analysis epoch for a language as a hex string.
///
/// The immutable grammar/query base is cached. C++ and Python configuration is
/// folded outside that cache on each call, so a later analyzer construction observes
/// the current policy. Other languages retain their existing borrowed epoch.
/// Always pass the canonical parser for `language`.
#[doc(hidden)]
pub fn epoch_for(language: Language, ts_language: &TsLanguage) -> Cow<'static, str> {
    let policy = if matches!(language, Language::Cpp | Language::Python) {
        SourceAdmissionPolicy::current()
    } else {
        SourceAdmissionPolicy::from_setting(None)
    };
    epoch_for_policy(language, ts_language, policy)
}

fn epoch_for_policy(
    language: Language,
    ts_language: &TsLanguage,
    policy: SourceAdmissionPolicy,
) -> Cow<'static, str> {
    let base = crate::analyzer::store::epoch::base_epoch_for(language, ts_language);
    if matches!(language, Language::Cpp | Language::Python) {
        let domain: &[u8] = match language {
            Language::Cpp => b"bifrost-configured-cpp-analysis-epoch:v1",
            Language::Python => b"bifrost-configured-python-analysis-epoch:v1",
            _ => unreachable!("only structural-line adapters have configured epochs"),
        };
        let mut hasher = CanonicalHasher::new(domain);
        hasher.field("grammar_query_base", base.as_bytes());
        policy.hash_identity(&mut hasher);
        Cow::Owned(lower_hex_string(&hasher.finish()))
    } else {
        Cow::Borrowed(base)
    }
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
