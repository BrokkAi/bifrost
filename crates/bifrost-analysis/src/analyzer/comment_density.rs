//! Language-independent comment-density support for tree-sitter analyzers.
//!
//! The declaration graph is already normalized behind [`IAnalyzer`]. This
//! module parses only enough syntax to identify real comment nodes, then
//! assigns each comment to the deepest declaration that structurally contains
//! it. That keeps the metric available to every parsed language without
//! duplicating comment token handling in each language adapter.

use std::sync::Arc;

use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::tree_sitter_analyzer::{
    WalkControl, expanded_comment_start, walk_tree_preorder,
};

use crate::analyzer::{
    CodeUnit, CommentDensityStats, IAnalyzer, Language, ProjectFile, Range, SummaryFileProjection,
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
    let (_, density) = analyze_file_from_analyzer(analyzer, file)?;
    build_roll_up_stats(code_unit, &density)
}

/// Compute density for every user-visible top-level declaration in `file`.
pub(crate) fn by_top_level(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
) -> Vec<CommentDensityStats> {
    let Some((projection, density)) = analyze_file_from_analyzer(analyzer, file) else {
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

fn analyze_file_from_analyzer(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
) -> Option<(Option<Arc<SummaryFileProjection>>, DensityFile)> {
    let projection = analyzer.summary_file_projection(file);
    let source = analyzer
        .indexed_source(file)
        .or_else(|| analyzer.project().read_source(file).ok())?;
    let density = analyze_file(analyzer, file, &source, projection.as_deref())?;
    Some((projection, density))
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
    let tree = crate::analyzer::repaired_grammar_gap_tree(language, source, tree);
    let mut comments = Vec::new();
    let mut primary_constructor_ranges = Vec::new();
    let mut class_parameter_ranges = Vec::new();
    walk_tree_preorder(tree.root_node(), true, |node| {
        if node.kind() == "primary_constructor" {
            primary_constructor_ranges.push((node.start_byte(), node.end_byte()));
            for parameter in brokk_bifrost_core::analyzer::tree_walk::named_children_iter(node)
                .filter(|child| child.kind() == "class_parameter")
            {
                class_parameter_ranges.push((
                    parameter.start_byte(),
                    parameter.end_byte(),
                    node.start_byte(),
                ));
            }
        }
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
    let top_level_declarations = projection.map_or_else(
        || analyzer.top_level_declarations(file),
        |projection| projection.top_level_declarations.clone(),
    );
    let declarations = collect_declarations(
        top_level_declarations,
        |code_unit| {
            projection.map_or_else(
                || analyzer.ranges(code_unit),
                |projection| {
                    projection
                        .ranges
                        .get(code_unit)
                        .cloned()
                        .unwrap_or_default()
                },
            )
        },
        |code_unit| {
            projection.map_or_else(
                || analyzer.direct_children(code_unit),
                |projection| {
                    projection
                        .children
                        .get(code_unit)
                        .cloned()
                        .unwrap_or_default()
                },
            )
        },
        language,
        source,
        file,
        &primary_constructor_ranges,
        &class_parameter_ranges,
    );
    // Key by the full CodeUnit identity, not the FQ name: overloads (such as
    // a Kotlin primary and secondary constructor) share an FQ name but are
    // distinct declarations, and a class roll-up visits each of them.
    let mut aggregates: HashMap<CodeUnit, (u32, u32)> = HashMap::default();
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
        let counts = aggregates.entry(code_unit.clone()).or_default();
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
    aggregates: HashMap<CodeUnit, (u32, u32)>,
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
    /// The primary constructor's range is also the owning class header. Keep
    /// it for roll-ups, but attribute its comments to the class scope.
    exclude_from_attribution: bool,
}

#[allow(clippy::too_many_arguments)]
fn collect_declarations(
    top_level_declarations: Vec<CodeUnit>,
    mut ranges_for: impl FnMut(&CodeUnit) -> Vec<Range>,
    mut children_for: impl FnMut(&CodeUnit) -> Vec<CodeUnit>,
    language: Language,
    source: &str,
    file: &ProjectFile,
    primary_constructor_ranges: &[(usize, usize)],
    class_parameter_ranges: &[(usize, usize, usize)],
) -> Vec<DensityDeclaration> {
    let mut declarations = Vec::new();
    let mut pending: Vec<(CodeUnit, usize, Option<usize>)> = top_level_declarations
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
        let raw_ranges = ranges_for(&code_unit);
        let is_constructor =
            is_kotlin_primary_constructor(&code_unit, &raw_ranges, primary_constructor_ranges);
        let span_lines = raw_ranges
            .iter()
            .map(|range| (range.end_line.saturating_sub(range.start_line) + 1) as u32)
            .sum();
        let ranges = raw_ranges
            .into_iter()
            .map(|range| DensityRange {
                start: expanded_density_range_start(
                    language,
                    source,
                    range.start_byte,
                    range.end_byte,
                    class_parameter_ranges,
                ),
                declaration_start: range.start_byte,
                end: range.end_byte,
                exclude_from_attribution: is_constructor
                    && is_primary_constructor_range(
                        range.start_byte,
                        range.end_byte,
                        primary_constructor_ranges,
                    ),
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
            children_for(&declarations[index].code_unit)
                .into_iter()
                .map(|child| (child, depth + 1, Some(index))),
        );
    }
    declarations
}

fn expanded_density_range_start(
    language: Language,
    source: &str,
    start_byte: usize,
    end_byte: usize,
    class_parameter_ranges: &[(usize, usize, usize)],
) -> usize {
    let expanded = expanded_comment_start(language, source, start_byte);
    class_parameter_ranges
        .iter()
        .find_map(|&(parameter_start, parameter_end, primary_start)| {
            (start_byte == parameter_start && end_byte == parameter_end)
                .then_some(expanded.max(primary_start))
        })
        .unwrap_or(expanded)
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
        if range.exclude_from_attribution {
            continue;
        }
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

fn own_counts(code_unit: &CodeUnit, aggregates: &HashMap<CodeUnit, (u32, u32)>) -> (u32, u32) {
    aggregates.get(code_unit).copied().unwrap_or_default()
}

fn is_kotlin_primary_constructor(
    code_unit: &CodeUnit,
    ranges: &[crate::analyzer::Range],
    primary_constructor_ranges: &[(usize, usize)],
) -> bool {
    code_unit.is_function()
        && ranges.iter().any(|range| {
            is_primary_constructor_range(
                range.start_byte,
                range.end_byte,
                primary_constructor_ranges,
            )
        })
}

fn is_primary_constructor_range(
    start: usize,
    end: usize,
    primary_constructor_ranges: &[(usize, usize)],
) -> bool {
    primary_constructor_ranges
        .iter()
        .any(|&(primary_start, primary_end)| start == primary_start && end == primary_end)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_projection_matches_direct(
    path: &str,
    source: &str,
    fq_name: &str,
) -> CommentDensityStats {
    let fixture = crate::test_support::AnalyzerFixture::new(&[(path, source)]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnitType, ProjectFile};

    fn unit(kind: CodeUnitType, name: &str) -> CodeUnit {
        let root = if cfg!(windows) {
            r"C:\workspace"
        } else {
            "/workspace"
        };
        CodeUnit::new(ProjectFile::new(root, "src/A.kt"), kind, "", name)
    }

    #[test]
    fn class_rollup_descends_into_nested_classes() {
        let outer = unit(CodeUnitType::Class, "Outer");
        let nested = unit(CodeUnitType::Class, "Inner");
        let method = unit(CodeUnitType::Function, "method");
        let density = DensityFile {
            declarations: vec![
                DensityDeclaration {
                    code_unit: outer.clone(),
                    depth: 0,
                    ranges: vec![],
                    children: vec![1],
                    span_lines: 1,
                },
                DensityDeclaration {
                    code_unit: nested.clone(),
                    depth: 1,
                    ranges: vec![],
                    children: vec![2],
                    span_lines: 1,
                },
                DensityDeclaration {
                    code_unit: method.clone(),
                    depth: 2,
                    ranges: vec![],
                    children: vec![],
                    span_lines: 1,
                },
            ],
            aggregates: [(method, (2, 3))].into_iter().collect(),
        };
        let stats = build_roll_up_stats(&outer, &density).unwrap();
        assert_eq!(stats.rolled_up_span_lines, 3);
    }
}
