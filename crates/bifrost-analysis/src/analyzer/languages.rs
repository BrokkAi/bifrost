//! Language capability registry.
//!
//! Framework code (code that serves every language) reaches per-language behavior
//! through [`language_support`] instead of naming a language module or matching on
//! `Language` itself. The match below is exhaustive with no wildcard arm, so adding a
//! `Language` variant fails to compile until it is registered.
//!
//! [`LanguageSupport`] grows one method per capability as
//! `.agents/plans/analysis-language-registry-spi.md` converts each dispatch list.
//! Methods land with the milestone that consumes them, so this surface is deliberately
//! smaller than the plan's eventual one.

use crate::analyzer::usages::{GraphUsageAnalyzer, UsageAnalyzer};
use crate::analyzer::{
    Language, cpp, csharp, go, java, js_ts, kotlin, php, python, ruby, rust, scala,
};

pub(crate) trait LanguageSupport: Send + Sync {
    /// The `Language` variant this support serves. Must equal the registry match key.
    fn language(&self) -> Language;

    /// Graph-backed usage strategy driving the `UsageFinder` query path.
    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer;

    /// Precise per-symbol usage strategy for dead-code analysis, or `None` when the
    /// language proves its candidates through a whole-workspace bulk edge build
    /// instead. `None` is not "unimplemented": a candidate that reaches the per-symbol
    /// path without a strategy is skipped as inconclusive, so this must stay `None`
    /// for the languages the bulk paths own.
    ///
    /// Migrates into `DeadCodeSupport` in milestone 1c of the ExecPlan, which absorbs
    /// the rest of the dead-code edge builds along with it.
    fn dead_code_strategy(&self) -> Option<&'static dyn UsageAnalyzer> {
        None
    }
}

pub(crate) fn language_support(language: Language) -> Option<&'static dyn LanguageSupport> {
    let support: Option<&'static dyn LanguageSupport> = match language {
        Language::None => None,
        Language::Java => Some(&java::JavaSupport),
        Language::Go => Some(&go::GoSupport),
        Language::Cpp => Some(&cpp::CppSupport),
        Language::JavaScript => Some(&js_ts::JavascriptSupport),
        Language::TypeScript => Some(&js_ts::TypescriptSupport),
        Language::Python => Some(&python::PythonSupport),
        Language::Rust => Some(&rust::RustSupport),
        Language::Php => Some(&php::PhpSupport),
        Language::Scala => Some(&scala::ScalaSupport),
        Language::CSharp => Some(&csharp::CSharpSupport),
        Language::Ruby => Some(&ruby::RubySupport),
        Language::Kotlin => Some(&kotlin::KotlinSupport),
    };
    debug_assert!(
        support.is_none_or(|support| support.language() == language),
        "registry arm for {language:?} is served by a support reporting {:?}",
        support.map(LanguageSupport::language)
    );
    support
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compiler exhaustiveness proves every `Language` has an arm; it cannot prove the
    /// arm is wired to the matching support. Folded into milestone 1f's registry
    /// invariants test.
    #[test]
    fn every_analyzable_language_resolves_to_its_own_support() {
        for language in [
            Language::Java,
            Language::Go,
            Language::Cpp,
            Language::JavaScript,
            Language::TypeScript,
            Language::Python,
            Language::Rust,
            Language::Php,
            Language::Scala,
            Language::CSharp,
            Language::Ruby,
            Language::Kotlin,
        ] {
            let support = language_support(language)
                .unwrap_or_else(|| panic!("{language:?} must be registered"));
            assert_eq!(support.language(), language);
        }
        assert!(language_support(Language::None).is_none());
    }
}
