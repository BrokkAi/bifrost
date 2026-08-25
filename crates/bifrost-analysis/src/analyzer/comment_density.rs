//! Language-independent comment-density support for tree-sitter analyzers.
//!
//! The declaration graph is already normalized behind [`IAnalyzer`]. This
//! module parses only enough syntax to identify real comment nodes, then
//! assigns each comment to the deepest declaration that structurally contains
//! it. That keeps the metric available to every parsed language without
//! duplicating comment token handling in each language adapter.

use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::tree_sitter_analyzer::{
    WalkControl, expanded_comment_start, walk_tree_preorder,
};
use crate::analyzer::{
    CodeUnit, CommentDensityStats, IAnalyzer, Language, ProjectFile, SummaryFileProjection,
    parser_language_for_path,
};
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;
use tree_sitter::Parser;

/// Compute density for a declaration in any language with a registered parser.
pub(crate) fn for_code_unit(
    analyzer: &(impl IAnalyzer + ?Sized),
    code_unit: &CodeUnit,
) -> Option<CommentDensityStats> {
    let file = code_unit.source();
    let projection = analyzer.summary_file_projection(file);
    let source = analyzer
        .indexed_source(file)
        .or_else(|| analyzer.project().read_source(file).ok())?;
    let density = analyze_file(analyzer, file, &source, projection.as_deref())?;
    build_roll_up_stats(code_unit, &density)
}

/// Compute density for every user-visible top-level declaration in `file`.
pub(crate) fn by_top_level(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
) -> Vec<CommentDensityStats> {
    let projection = analyzer.summary_file_projection(file);
    let Some(source) = analyzer
        .indexed_source(file)
        .or_else(|| analyzer.project().read_source(file).ok())
    else {
        return Vec::new();
    };
    let Some(density) = analyze_file(analyzer, file, &source, projection.as_deref()) else {
        return Vec::new();
    };
    projection
        .map(|projection| projection.top_level_declarations.clone())
        .unwrap_or_else(|| analyzer.top_level_declarations(file))
        .into_iter()
        .filter(|code_unit| !code_unit.is_module() && !code_unit.is_synthetic())
        .filter_map(|code_unit| build_roll_up_stats(&code_unit, &density))
        .collect()
}

fn analyze_file(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
    projection: Option<&SummaryFileProjection>,
) -> Option<DensityFile> {
    let language = language_for_file(file);
    if language == Language::None || is_unparseable_source(source) {
        return None;
    }
    let grammar = parser_language_for_path(language, file.rel_path())?;
    let mut parser = Parser::new();
    parser
        .set_language(&grammar)
        .expect("registered parser grammar must load");
    let tree = parser.parse(source, None)?;
    let mut comments = Vec::new();
    walk_tree_preorder(tree.root_node(), true, |node| {
        if node.kind().ends_with("comment") {
            comments.push(node);
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });

    // Analyzer range and child lookups may hydrate persisted file state. Build
    // the declaration view once per file instead of repeating those lookups
    // for every comment in the file.
    let declarations = projection.map_or_else(
        || collect_declarations_from_analyzer(analyzer, language, source, file),
        |projection| collect_declarations_from_projection(projection, language, source, file),
    );
    let mut aggregates: HashMap<String, (u32, u32)> = HashMap::default();
    for comment in comments {
        let start = comment.start_byte();
        let end = comment.end_byte();
        let Some((code_unit, range)) = enclosing_declaration(&declarations, start, end) else {
            continue;
        };
        let lines = (comment
            .end_position()
            .row
            .saturating_sub(comment.start_position().row)
            + 1) as u32;
        let counts = aggregates.entry(code_unit.fq_name()).or_default();
        if end <= range.declaration_start {
            counts.0 += lines;
        } else {
            counts.1 += lines;
        }
    }
    Some(DensityFile {
        declarations,
        aggregates,
    })
}

struct DensityFile {
    declarations: Vec<DensityDeclaration>,
    aggregates: HashMap<String, (u32, u32)>,
}

struct DensityDeclaration {
    code_unit: CodeUnit,
    depth: usize,
    ranges: Vec<DensityRange>,
    children: Vec<usize>,
    span_lines: u32,
}

struct DensityRange {
    start: usize,
    declaration_start: usize,
    end: usize,
}

fn collect_declarations_from_analyzer(
    analyzer: &(impl IAnalyzer + ?Sized),
    language: Language,
    source: &str,
    file: &ProjectFile,
) -> Vec<DensityDeclaration> {
    let mut declarations = Vec::new();
    let mut pending: Vec<(CodeUnit, usize, Option<usize>)> = analyzer
        .top_level_declarations(file)
        .into_iter()
        .map(|code_unit| (code_unit, 0, None))
        .collect();
    while let Some((code_unit, depth, parent)) = pending.pop() {
        // A package/namespace unit reachable from this file can fan out to
        // declarations in other files (Java package members). Their ranges are
        // byte offsets into those files' sources, so containment checks
        // against this file's comments are meaningless; skip them and their
        // (equally foreign) subtrees.
        if code_unit.source() != file {
            continue;
        }
        let raw_ranges = analyzer.ranges(&code_unit);
        let span_lines = raw_ranges
            .iter()
            .map(|range| (range.end_line.saturating_sub(range.start_line) + 1) as u32)
            .sum();
        let ranges = raw_ranges
            .into_iter()
            .map(|range| DensityRange {
                start: expanded_comment_start(language, source, range.start_byte),
                declaration_start: range.start_byte,
                end: range.end_byte,
            })
            .collect();
        let index = declarations.len();
        declarations.push(DensityDeclaration {
            code_unit,
            depth,
            ranges,
            children: Vec::new(),
            span_lines,
        });
        if let Some(parent) = parent {
            declarations[parent].children.push(index);
        }
        pending.extend(
            analyzer
                .direct_children(&declarations[index].code_unit)
                .into_iter()
                .map(|child| (child, depth + 1, Some(index))),
        );
    }
    declarations
}

fn collect_declarations_from_projection(
    projection: &SummaryFileProjection,
    language: Language,
    source: &str,
    file: &ProjectFile,
) -> Vec<DensityDeclaration> {
    let mut declarations = Vec::new();
    let mut pending: Vec<(CodeUnit, usize, Option<usize>)> = projection
        .top_level_declarations
        .iter()
        .cloned()
        .map(|code_unit| (code_unit, 0, None))
        .collect();
    while let Some((code_unit, depth, parent)) = pending.pop() {
        if code_unit.source() != file {
            continue;
        }
        let raw_ranges = projection
            .ranges
            .get(&code_unit)
            .cloned()
            .unwrap_or_default();
        let span_lines = raw_ranges
            .iter()
            .map(|range| (range.end_line.saturating_sub(range.start_line) + 1) as u32)
            .sum();
        let ranges = raw_ranges
            .into_iter()
            .map(|range| DensityRange {
                start: expanded_comment_start(language, source, range.start_byte),
                declaration_start: range.start_byte,
                end: range.end_byte,
            })
            .collect();
        let index = declarations.len();
        declarations.push(DensityDeclaration {
            code_unit,
            depth,
            ranges,
            children: Vec::new(),
            span_lines,
        });
        if let Some(parent) = parent {
            declarations[parent].children.push(index);
        }
        if let Some(children) = projection.children.get(&declarations[index].code_unit) {
            pending.extend(
                children
                    .iter()
                    .cloned()
                    .map(|child| (child, depth + 1, Some(index))),
            );
        }
    }
    declarations
}

fn enclosing_declaration(
    declarations: &[DensityDeclaration],
    start: usize,
    end: usize,
) -> Option<(&CodeUnit, &DensityRange)> {
    if start > end {
        return None;
    }
    let mut best: Option<(&DensityDeclaration, &DensityRange)> = None;
    for declaration in declarations {
        let Some(range) = declaration
            .ranges
            .iter()
            .filter(|range| start >= range.start && end <= range.end)
            .min_by_key(|range| range.end.saturating_sub(range.start))
        else {
            continue;
        };
        if best.is_none_or(|(best, _)| declaration.depth > best.depth) {
            best = Some((declaration, range));
        }
    }
    best.map(|(declaration, range)| (&declaration.code_unit, range))
}

fn build_roll_up_stats(code_unit: &CodeUnit, density: &DensityFile) -> Option<CommentDensityStats> {
    let index = density
        .declarations
        .iter()
        .position(|declaration| declaration.code_unit == *code_unit)?;
    let declaration = &density.declarations[index];
    let (header, inline) = own_counts(code_unit, &density.aggregates);
    let mut rolled_header = header;
    let mut rolled_inline = inline;
    let mut rolled_span = declaration.span_lines;

    if code_unit.is_class() {
        let mut pending = declaration.children.clone();
        while let Some(child) = pending.pop() {
            let child = &density.declarations[child];
            let (child_header, child_inline) = own_counts(&child.code_unit, &density.aggregates);
            rolled_header += child_header;
            rolled_inline += child_inline;
            rolled_span += child.span_lines;
            if child.code_unit.is_class() {
                pending.extend(child.children.iter().copied());
            }
        }
    }

    Some(CommentDensityStats {
        fq_name: code_unit.fq_name(),
        relative_path: rel_path_string(code_unit.source()),
        header_comment_lines: header,
        inline_comment_lines: inline,
        span_lines: declaration.span_lines,
        rolled_up_header_comment_lines: rolled_header,
        rolled_up_inline_comment_lines: rolled_inline,
        rolled_up_span_lines: rolled_span,
    })
}

fn own_counts(code_unit: &CodeUnit, aggregates: &HashMap<String, (u32, u32)>) -> (u32, u32) {
    aggregates
        .get(&code_unit.fq_name())
        .copied()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::AnalyzerFixture;

    fn assert_projection_matches_direct(
        path: &str,
        source: &str,
        fq_name: &str,
    ) -> CommentDensityStats {
        let fixture = AnalyzerFixture::new(&[(path, source)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), path);
        let code_unit = analyzer
            .get_definitions(fq_name)
            .into_iter()
            .find(|unit| unit.source() == &file)
            .unwrap_or_else(|| panic!("expected `{fq_name}` in `{path}`"));
        let projection = analyzer
            .summary_file_projection(&file)
            .expect("fixture analyzer should provide a summary projection");
        let projected = analyze_file(analyzer, &file, source, Some(&projection))
            .and_then(|density| build_roll_up_stats(&code_unit, &density))
            .expect("projected comment density");
        let direct = analyze_file(analyzer, &file, source, None)
            .and_then(|density| build_roll_up_stats(&code_unit, &density))
            .expect("direct comment density");
        assert_eq!(projected, direct);
        projected
    }

    #[test]
    fn javascript_projection_preserves_imported_module_attribution() {
        let stats = assert_projection_matches_direct(
            "response.js",
            "var dep = require('dep');\n\
             function send(body) {\n\
               // settings\n\
               return dep(body);\n\
             }\n",
            "send",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (0, 0)
        );
    }

    #[test]
    fn typescript_projection_preserves_imported_module_attribution() {
        let stats = assert_projection_matches_direct(
            "Ky.ts",
            "import type {Options} from './types.js';\n\
             function cloneRetryOptions(options: Options): Options {\n\
               // clone before mutation\n\
               return {...options};\n\
             }\n",
            "cloneRetryOptions",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (0, 0)
        );
    }

    #[test]
    fn scala_projection_filters_synthetic_children_for_attribution() {
        let stats = assert_projection_matches_direct(
            "Elem.scala",
            "/** Element header. */\n\
             class Elem(val name: String) {\n\
               // class implementation note\n\
               val label: String = name\n\
             }\n",
            "Elem",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (0, 0)
        );
        assert!(stats.span_lines > 0);
    }

    #[test]
    fn kotlin_projection_filters_synthetic_children_for_attribution() {
        let stats = assert_projection_matches_direct(
            "ResultRow.kt",
            "/** Row header. */\n\
             class ResultRow(private val values: List<Any>) {\n\
               // row implementation note\n\
               val size: Int = values.size\n\
             }\n",
            "ResultRow",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (0, 0)
        );
        assert!(stats.span_lines > 0);
    }
}
