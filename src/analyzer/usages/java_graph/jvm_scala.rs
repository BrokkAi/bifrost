use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, language_for_file, usage_hit};
use crate::analyzer::usages::java_graph::extractor::ScanState;
use crate::analyzer::usages::java_graph::resolver::{TargetKind, TargetSpec};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::scala_graph::syntax::{
    dotted_qualifier_before, has_ancestor_kind, is_identifier_node, is_type_like_reference,
    node_text, scala_import_path,
};
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, ImportAnalysisProvider, Language, MultiAnalyzer,
    ProjectFile, Range, ScalaAnalyzer,
};
use crate::hash::HashSet;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset, snippet_around_line};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub(super) fn scan_scala_files_for_java_type(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded || spec.kind != TargetKind::Type {
        return;
    }
    let Some(scala) = resolve_scala_analyzer(analyzer) else {
        return;
    };

    for file in candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Scala)
    {
        scan_scala_file(analyzer, scala, file, spec, state);
        if *state.limit_exceeded {
            break;
        }
    }
}

fn resolve_scala_analyzer(analyzer: &dyn IAnalyzer) -> Option<&ScalaAnalyzer> {
    if let Some(scala) = (analyzer as &dyn std::any::Any).downcast_ref::<ScalaAnalyzer>() {
        return Some(scala);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Scala) {
        Some(AnalyzerDelegate::Scala(scala)) => Some(scala),
        _ => None,
    }
}

fn scan_scala_file(
    analyzer: &dyn IAnalyzer,
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    if file.is_binary().unwrap_or(true) {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let target_name = spec.owner.identifier();
    let target_fq_name = spec.owner.fq_name();
    if !source.contains(target_name) && !source.contains(&target_fq_name) {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };

    let line_starts = compute_line_starts(&source);
    let visibility = Visibility::for_file(scala, file, spec);
    let mut ctx = ScalaJavaScanCtx {
        analyzer,
        scala,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        visibility,
        type_shadow_scopes: vec![HashSet::default()],
        max_usages: state.max_usages,
        hits: state.hits,
        raw_match_count: state.raw_match_count,
        limit_exceeded: state.limit_exceeded,
    };
    scan_node(tree.root_node(), &mut ctx);
}

struct Visibility {
    visible_type_names: HashSet<String>,
}

impl Visibility {
    fn for_file(scala: &ScalaAnalyzer, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let target_package = spec.owner.package_name();
        let target_name = spec.owner.identifier();
        let target_fq_name = spec.owner.fq_name();
        let mut visible_type_names = HashSet::default();

        if is_top_level_type(&spec.owner)
            && scala_file_package(scala, file).as_deref() == Some(target_package)
        {
            visible_type_names.insert(target_name.to_string());
        }

        for import in scala.import_info_of(file) {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                if path == target_package {
                    visible_type_names.insert(target_name.to_string());
                }
                continue;
            }
            if path == target_fq_name {
                visible_type_names.insert(
                    import
                        .identifier
                        .as_deref()
                        .unwrap_or(target_name)
                        .to_string(),
                );
            }
        }

        Self { visible_type_names }
    }

    fn contains(&self, name: &str) -> bool {
        self.visible_type_names.contains(name)
    }
}

struct ScalaJavaScanCtx<'a, 'state> {
    analyzer: &'a dyn IAnalyzer,
    scala: &'a ScalaAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    visibility: Visibility,
    type_shadow_scopes: Vec<HashSet<String>>,
    max_usages: usize,
    hits: &'state mut BTreeSet<UsageHit>,
    raw_match_count: &'state mut usize,
    limit_exceeded: &'state mut bool,
}

fn scan_node(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if *ctx.limit_exceeded {
        return;
    }
    seed_type_shadow(node, ctx);
    let enters_scope = enters_local_scope(node);
    if enters_scope {
        ctx.type_shadow_scopes.push(HashSet::default());
    }
    if is_identifier_node(node) {
        maybe_record_java_type_hit(node, ctx);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }
    if enters_scope {
        ctx.type_shadow_scopes.pop();
    }
}

fn maybe_record_java_type_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if has_ancestor_kind(node, "import_declaration") || is_declaration_name(node) {
        return;
    }

    let text = node_text(node, ctx.source).trim_end_matches('$');
    if text.is_empty() {
        return;
    }

    let target_name = ctx.spec.owner.identifier();
    let proven = if text == target_name {
        if let Some(qualifier) = dotted_qualifier_before(node, ctx.source) {
            qualifier_matches_target_owner(&qualifier, ctx.spec)
        } else {
            ctx.visibility.contains(text)
                && !is_type_shadowed(ctx, text)
                && is_type_like_reference(node, ctx.source)
        }
    } else {
        ctx.visibility.contains(text)
            && !is_type_shadowed(ctx, text)
            && is_type_like_reference(node, ctx.source)
    };

    if proven {
        push_scala_hit(node, ctx);
    }
}

fn push_scala_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    *ctx.raw_match_count += 1;
    if *ctx.limit_exceeded {
        return;
    }

    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let Some(enclosing) = ctx
        .analyzer
        .enclosing_code_unit(ctx.file, &range)
        .or_else(|| nearest_scala_declaration(ctx.scala, ctx.file))
    else {
        return;
    };

    let line_idx = range.start_line;
    ctx.hits.insert(usage_hit(
        ctx.file,
        line_idx,
        range.start_byte,
        range.end_byte,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

fn nearest_scala_declaration(scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<CodeUnit> {
    scala.declarations(file).next().cloned()
}

fn scala_file_package(scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<String> {
    scala
        .declarations(file)
        .next()
        .map(|unit| unit.package_name().to_string())
}

fn is_top_level_type(target: &CodeUnit) -> bool {
    !target.short_name().contains('.')
}

fn nested_owner_qualifier(target: &CodeUnit) -> Option<&str> {
    target.short_name().rsplit_once('.').map(|(owner, _)| owner)
}

fn qualifier_matches_target_owner(qualifier: &str, spec: &TargetSpec) -> bool {
    if is_top_level_type(&spec.owner) {
        return qualifier == spec.owner.package_name();
    }

    let Some(owner_qualifier) = nested_owner_qualifier(&spec.owner) else {
        return false;
    };
    qualifier == owner_qualifier
        || qualifier == format!("{}.{}", spec.owner.package_name(), owner_qualifier)
}

fn seed_type_shadow(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if !matches!(
        node.kind(),
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
    ) {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name, ctx.source).trim_end_matches('$');
    if !name.is_empty()
        && ctx.visibility.contains(name)
        && let Some(scope) = ctx.type_shadow_scopes.last_mut()
    {
        scope.insert(name.to_string());
    }
}

fn enters_local_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function"
    )
}

fn is_type_shadowed(ctx: &ScalaJavaScanCtx<'_, '_>, name: &str) -> bool {
    ctx.type_shadow_scopes
        .iter()
        .rev()
        .any(|scope| scope.contains(name))
}

fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
}
