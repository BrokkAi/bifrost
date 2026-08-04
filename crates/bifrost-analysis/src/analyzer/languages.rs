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

use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, RustTypeLookupCache,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::usages::{GraphUsageAnalyzer, UsageAnalyzer};
use crate::analyzer::{
    AnalyzerDefinitionLookup, ForwardQueryProvider, IAnalyzer, Language, ProjectFile, cpp, csharp,
    go, java, js_ts, kotlin, php, python, ruby, rust, scala,
};
use crate::cancellation::CancellationToken;

pub(crate) trait LanguageSupport: Send + Sync {
    /// The `Language` variant this support serves. Must equal the registry match key.
    fn language(&self) -> Language;

    /// Graph-backed usage strategy driving the `UsageFinder` query path.
    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer;

    /// This language's analyzer inside `analyzer`, viewed as a forward-query provider.
    /// Each support owns the downcast to its own concrete analyzer; `None` means the
    /// workspace does not analyze this language, which callers treat as an empty result
    /// rather than a failure.
    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider>;

    /// Separator between a package name and its parent. Only Go and C++ differ from the
    /// dotted default.
    fn package_separator(&self) -> &'static str {
        "."
    }

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

    /// Bounded structural receiver resolution, or `None` when receiver queries for this
    /// language take another route (Java runs a resolution session, JS/TS runs its own
    /// syntax-index path) or are unsupported entirely.
    ///
    /// This is the single owner of the structural-receiver capability: the receiver query
    /// gate admits exactly the languages that answer `Some` here, so an absent resolver
    /// yields the `receiver_analysis_language_unsupported` report rather than reaching a
    /// dispatch that cannot serve it.
    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        None
    }

    /// Unbounded `get_type_by_location` resolution, or `None` when the language has no
    /// type lookup implementation. Absence is reported to the caller as
    /// `TypeLookupStatus::UnsupportedLanguage`, not as a silent empty result.
    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        None
    }
}

/// The pair of bounded resolvers a structural receiver query needs. One trait rather than
/// two independent capabilities: a language that can answer one and not the other would
/// leave the receiver query with half an implementation part-way through a report.
pub(crate) trait StructuralReceiverResolver: Send + Sync {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome>;

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome>;
}

#[derive(Clone, Copy)]
pub(crate) struct BoundedReceiverQuery<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) file: &'a ProjectFile,
    pub(crate) source: &'a str,
    pub(crate) tree: Option<&'a tree_sitter::Tree>,
    pub(crate) site: &'a ResolvedReferenceSite,
    pub(crate) budget: ReceiverAnalysisBudget,
    pub(crate) cancellation: Option<&'a CancellationToken>,
}

pub(crate) trait TypeLookupResolver: Send + Sync {
    fn resolve_type(&self, query: TypeLookupQuery<'_>) -> TypeLookupOutcome;
}

/// Every input the per-language type resolvers draw on. They consume different subsets:
/// the JVM, Scala and JS/TS resolvers need the batch's definition lookup (and set its
/// language first), Rust needs the batch's type cache, JS/TS needs the dialect. Passing
/// the whole batch state keeps that a property of each resolver rather than a mode the
/// caller has to select.
pub(crate) struct TypeLookupQuery<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) support: &'a AnalyzerDefinitionLookup<'a>,
    pub(crate) file: &'a ProjectFile,
    pub(crate) language: Language,
    pub(crate) source: &'a str,
    pub(crate) tree: Option<&'a tree_sitter::Tree>,
    pub(crate) site: &'a ResolvedReferenceSite,
    pub(crate) rust_cache: &'a mut RustTypeLookupCache,
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
