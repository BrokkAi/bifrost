use crate::RustAnalyzer;
use brokk_bifrost_analysis::analyzer::{Language, TestProject};
use std::path::Path;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_analyzer(root: &Path) -> RustAnalyzer {
    RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
}

// Test surfaces expose the production proof vocabulary without adding a second
// implementation or making the facade depend on the language crate directly.
pub use brokk_bifrost_rust::graph_support::{
    RustFactSource, RustGlobNameAbsence, RustGlobNamespace,
};
pub use brokk_bifrost_rust::macro_matcher::{StandardMacroIdentity, StandardMacroOwner};

pub fn standard_macro_identity_at(
    analyzer: &RustAnalyzer,
    file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    source: &str,
    byte: usize,
) -> StandardMacroIdentity {
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    use brokk_bifrost_rust::macro_matcher::{ExportedMacroDefinitions, standard_macro_identity};
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust grammar");
    let tree = parser.parse(source, None).expect("macro probe syntax");
    let mut invocation = tree
        .root_node()
        .descendant_for_byte_range(byte, byte + 1)
        .expect("macro token");
    while invocation.kind() != "macro_invocation" {
        invocation = invocation
            .parent()
            .expect("token belongs to macro invocation");
    }
    let scope = AnalyzerQueryScope::new(analyzer);
    let walks = brokk_bifrost_rust::usage_walks::RustUsageWalks::new(analyzer, scope.token())
        .expect("macro probe routes");
    let exported = ExportedMacroDefinitions::from_root(tree.root_node(), source);
    standard_macro_identity(
        analyzer,
        &walks,
        file,
        invocation,
        source,
        Some(&exported),
        invocation,
        &[],
    )
}
