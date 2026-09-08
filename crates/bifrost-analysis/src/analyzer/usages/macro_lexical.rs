//! Query-local macro declarations shared by navigation and authoritative inverse.

use super::cpp_graph::with_cpp_graph_source;
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::{DeclarationKind, IAnalyzer, ProjectFile, Range};
use crate::hash::HashSet;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_cpp::graph::resolver::{
    MacroLexicalBindingKind, MacroLexicalReferences, VisibilityIndex,
};
use tree_sitter::Node;

/// Resolve a source token to the source-written macro formal or local.
/// Invocation-specific receiver types are deliberately absent from this target.
pub fn macro_lexical_definition(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> Option<LexicalDefinition> {
    let binding = with_cpp_graph_source(analyzer, |graph| {
        let cpp = graph.cpp?;
        let roots = HashSet::from_iter([file.clone()]);
        let visibility = VisibilityIndex::build(cpp, graph.token, &graph, &roots);
        visibility.macro_lexical_binding(file, root, source, start_byte, end_byte)
    })?;
    lexical_definition(analyzer, binding)
}

pub(crate) fn lexical_definition(
    analyzer: &dyn IAnalyzer,
    binding: brokk_bifrost_cpp::graph::resolver::MacroLexicalBinding,
) -> Option<LexicalDefinition> {
    let definition_source = analyzer.indexed_source(&binding.definition)?;
    let line_starts = compute_line_starts(&definition_source);
    let range = |bytes: std::ops::Range<usize>| Range {
        start_byte: bytes.start,
        end_byte: bytes.end,
        start_line: line_column_for_offset(&definition_source, &line_starts, bytes.start).0,
        end_line: line_column_for_offset(&definition_source, &line_starts, bytes.end).0,
    };
    Some(LexicalDefinition {
        source_file: Some(binding.definition),
        identifier: binding.name,
        kind: match binding.kind {
            MacroLexicalBindingKind::Parameter => DeclarationKind::Parameter,
            MacroLexicalBindingKind::Local => DeclarationKind::LocalVariable,
        },
        name_range: range(binding.name_range),
        declaration_range: range(binding.declaration_range),
    })
}

/// Enumerate structured macro lexical references in one admitted source file.
/// Callers own file/source/result budgets and retain cancellation/truncation.
pub fn macro_lexical_references(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    max_references: usize,
    cancelled: impl FnMut() -> bool,
) -> MacroLexicalReferences {
    with_cpp_graph_source(analyzer, |graph| {
        let Some(cpp) = graph.cpp else {
            return MacroLexicalReferences::default();
        };
        let roots = HashSet::from_iter([file.clone()]);
        let visibility = VisibilityIndex::build(cpp, graph.token, &graph, &roots);
        visibility.macro_lexical_references(file, root, source, max_references, cancelled)
    })
}

/// A macro can reach its defining file and files that transitively include it.
/// Reuse the structured import graph used by ordinary reference discovery.
pub fn macro_lexical_candidate_files(
    analyzer: &dyn IAnalyzer,
    definition_file: &ProjectFile,
    cancellation: &crate::cancellation::CancellationToken,
) -> Vec<ProjectFile> {
    use crate::analyzer::{AnalyzerQueryScope, Language, QueryScope};
    let files = analyzer.analyzed_files_for_language(Language::Cpp);
    let Some(imports) = analyzer.import_analysis_provider() else {
        return files;
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let seeds = HashSet::from_iter([definition_file.clone()]);
    let mut candidates = super::candidates::find_transitive_importers_with_cancellation(
        files,
        imports,
        scope.token(),
        &seeds,
        cancellation,
    );
    candidates.insert(definition_file.clone());
    let mut candidates = candidates.into_iter().collect::<Vec<_>>();
    candidates.sort();
    candidates
}
