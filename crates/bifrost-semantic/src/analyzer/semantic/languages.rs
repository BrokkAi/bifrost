use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::model::Language;

/// Static language rules available before analyzer construction.
#[doc(hidden)]
pub fn language_knowledge(language: Language) -> Option<&'static dyn LanguageKnowledge> {
    match language {
        Language::None => None,
        Language::Rust => Some(&brokk_bifrost_rust::RustKnowledge),
        Language::Python => Some(&brokk_bifrost_python::PythonKnowledge),
        Language::Cpp => Some(&brokk_bifrost_cpp::CppKnowledge),
        Language::CSharp => Some(&brokk_bifrost_csharp::CSharpKnowledge),
        Language::Ruby => Some(&brokk_bifrost_ruby::RubyKnowledge),
        Language::Php => Some(&brokk_bifrost_php::PhpKnowledge),
        Language::Go => Some(&brokk_bifrost_go::GoKnowledge),
        Language::JavaScript => Some(&brokk_bifrost_js_ts::JavascriptKnowledge),
        Language::TypeScript => Some(&brokk_bifrost_js_ts::TypescriptKnowledge),
        Language::Java => Some(&brokk_bifrost_jvm::JavaKnowledge),
        Language::Kotlin => Some(&brokk_bifrost_jvm::KotlinKnowledge),
        Language::Scala => Some(&brokk_bifrost_jvm::ScalaKnowledge),
    }
}

/// Whether a call written in `caller` may select an external callee that
/// `declaring` declares. A resolver-owned callee identity names the callee's
/// declaring language, which is the caller's own unless the caller calls
/// another language's declarations directly.
#[doc(hidden)]
pub fn calls_external_declarations_of(caller: Language, declaring: Language) -> bool {
    caller == declaring
        || language_knowledge(caller).is_some_and(|knowledge| {
            knowledge
                .external_declaration_languages()
                .contains(&declaring)
        })
}
