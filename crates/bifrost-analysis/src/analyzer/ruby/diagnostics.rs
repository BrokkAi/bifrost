//! Ruby's semantic diagnostics: the downcast that produces the arguments.
//!
//! The pass itself is [`brokk_bifrost_ruby::diagnostics`]. Unlike Go's,
//! Python's and PHP's it routes through the *graph* semantic index rather than a
//! `BoundedDefinitionLookup`, so it moved with `graph::resolver` and takes the
//! same `RubyGraphSource` the scans do.

use crate::analyzer::usages::ruby_graph::with_ruby_graph_source;
use crate::analyzer::{IAnalyzer, ProjectFile, RubyAnalyzer, resolve_analyzer};
use brokk_bifrost_ruby::diagnostics::RubySemanticDiagnostic;

pub(crate) fn collect_ruby_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<RubySemanticDiagnostic> {
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return Vec::new();
    };
    with_ruby_graph_source(analyzer, |graph| {
        brokk_bifrost_ruby::diagnostics::collect_ruby_semantic_diagnostics(
            graph, ruby, file, source,
        )
    })
}
