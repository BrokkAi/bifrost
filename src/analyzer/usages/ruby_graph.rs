//! Ruby usage resolution.
//!
//! Ruby is dynamically typed, so a call's receiver type is usually unknown
//! statically. This strategy therefore resolves usages by **method/constant
//! name**: it scans candidate files for call sites whose method name (for
//! method targets) or constant references (for class/module/constant targets)
//! match the target's identifier. This is the conventional static model for
//! Ruby tooling — it favors finding all real call sites over precise
//! receiver-type disambiguation, which Ruby's dynamic dispatch does not expose.

use crate::analyzer::ruby::parse_ruby_tree;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, language_for_target, usage_hit};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::HashSet;
use crate::text_utils::{
    compute_line_starts, find_line_index_for_offset, trimmed_snippet_around_line,
};
use std::collections::BTreeSet;
use tree_sitter::Node;

#[derive(Default)]
pub struct RubyUsageGraphStrategy;

impl RubyUsageGraphStrategy {
    pub fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Ruby
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        if language_for_target(target) != Language::Ruby {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Ruby"),
                "RubyUsageGraphStrategy",
            );
        }

        let identifier = target.identifier().to_string();
        if identifier.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::success(
                target.clone(),
                BTreeSet::new(),
            ));
        }
        let match_kind = MatchKind::for_target(target);

        // Always scan the defining file plus the narrowed candidate set.
        let mut scan_files = candidate_files.clone();
        scan_files.insert(target.source().clone());

        let mut hits = BTreeSet::new();
        for file in &scan_files {
            let Ok(source) = analyzer.project().read_source(file) else {
                continue;
            };
            let Some(tree) = parse_ruby_tree(&source) else {
                continue;
            };
            let line_starts = compute_line_starts(&source);
            collect_reference_hits(
                analyzer,
                file,
                &source,
                &line_starts,
                tree.root_node(),
                match_kind,
                &identifier,
                &mut hits,
            );
        }

        // Drop references that resolve back to the target's own declaration.
        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| hit.enclosing != *target)
            .collect();

        if hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
    }
}

impl UsageAnalyzer for RubyUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        self.find_graph_usages(analyzer, overloads, candidate_files, max_usages)
            .into_fuzzy_result()
    }
}

#[derive(Clone, Copy)]
enum MatchKind {
    /// A method/function target: match `call` nodes by method name.
    Method,
    /// A class/module/constant target: match `constant` references by name.
    Constant,
}

impl MatchKind {
    fn for_target(target: &CodeUnit) -> Self {
        if target.is_function() {
            MatchKind::Method
        } else {
            MatchKind::Constant
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_reference_hits(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    root: Node<'_>,
    match_kind: MatchKind,
    identifier: &str,
    hits: &mut BTreeSet<UsageHit>,
) {
    walk_named_tree_preorder(root, true, |node| {
        let reference = match match_kind {
            MatchKind::Method => method_call_reference(node, source, identifier),
            MatchKind::Constant => constant_reference(node, source, identifier),
        };
        if let Some(reference) = reference {
            record_hit(analyzer, file, source, line_starts, reference, hits);
        }
        WalkControl::Continue
    });
}

/// Returns the method-name node of a `call` whose method matches `identifier`.
fn method_call_reference<'tree>(
    node: Node<'tree>,
    source: &str,
    identifier: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "call" {
        return None;
    }
    let method = node.child_by_field_name("method")?;
    (node_text(method, source) == identifier).then_some(method)
}

/// Returns a `constant` reference node matching `identifier`, skipping the
/// constant that names a `class`/`module` definition (that is the declaration,
/// not a usage).
fn constant_reference<'tree>(
    node: Node<'tree>,
    source: &str,
    identifier: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "constant" || node_text(node, source) != identifier {
        return None;
    }
    if let Some(parent) = node.parent()
        && matches!(parent.kind(), "class" | "module")
    {
        return None;
    }
    Some(node)
}

fn record_hit(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    node: Node<'_>,
    hits: &mut BTreeSet<UsageHit>,
) {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    if start_byte >= end_byte {
        return;
    }
    let line_idx = find_line_index_for_offset(line_starts, start_byte);
    let snippet = trimmed_snippet_around_line(source, line_starts, line_idx, SNIPPET_CONTEXT_LINES);
    let range = Range {
        start_byte,
        end_byte,
        start_line: line_idx,
        end_line: line_idx,
    };
    let Some(enclosing) = analyzer.enclosing_code_unit(file, &range) else {
        return;
    };
    hits.insert(usage_hit(
        file, line_idx, start_byte, end_byte, enclosing, snippet,
    ));
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
