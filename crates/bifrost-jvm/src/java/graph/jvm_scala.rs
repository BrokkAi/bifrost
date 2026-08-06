use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::{
    compute_line_starts, find_line_index_for_offset, snippet_around_line,
};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

use crate::java::graph::extractor::ScanState;
use crate::java::graph::resolver::{TargetKind, TargetSpec};
use crate::scala::graph::syntax::{
    call_site_shape_for_reference, has_ancestor_kind, is_identifier_node, is_type_like_reference,
    member_qualifier, member_qualifier_node, node_text, scala_import_path,
    scala_pattern_binder_names, stable_type_qualifier,
};
use crate::scala::graph_support::ScalaSource;

pub fn scan_scala_files_for_java_target(
    owners: &dyn CodeUnitIndex,
    scala: &dyn ScalaSource,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
    cancellation: Option<&CancellationToken>,
) {
    if *state.limit_exceeded || matches!(spec.kind, TargetKind::Constructor) {
        return;
    }

    for file in candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Scala)
    {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        scan_scala_file(owners, scala, file, spec, state);
        if *state.limit_exceeded || cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
    }
}

fn scan_scala_file(
    owners: &dyn CodeUnitIndex,
    scala: &dyn ScalaSource,
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
        .set_language(&crate::scala::language::LANGUAGE.into())
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
        owners,
        scala,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        visibility,
        type_shadow_scopes: vec![HashSet::default()],
        term_shadow_scopes: vec![HashSet::default()],
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
    fn for_file(scala: &dyn ScalaSource, file: &ProjectFile, spec: &TargetSpec) -> Self {
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
            let Some(path) = scala_import_path(&import) else {
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
    owners: &'a dyn CodeUnitIndex,
    scala: &'a dyn ScalaSource,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    visibility: Visibility,
    type_shadow_scopes: Vec<HashSet<String>>,
    term_shadow_scopes: Vec<HashSet<String>>,
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
    seed_term_shadow(node, ctx);
    let enters_scope = enters_local_scope(node);
    if enters_scope {
        ctx.type_shadow_scopes.push(HashSet::default());
        ctx.term_shadow_scopes.push(HashSet::default());
    }
    if is_identifier_node(node) {
        match ctx.spec.kind {
            TargetKind::Type => maybe_record_java_type_hit(node, ctx),
            TargetKind::Method => maybe_record_java_static_method_hit(node, ctx),
            TargetKind::Field => maybe_record_java_static_field_hit(node, ctx),
            TargetKind::Constructor => {}
        }
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
        ctx.term_shadow_scopes.pop();
    }
}

fn maybe_record_java_type_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if has_ancestor_kind(node, "import_declaration") {
        if java_type_import_owner_matches_target(node, ctx) {
            push_scala_hit(node, ctx);
        }
        return;
    }
    if is_declaration_name(node) {
        return;
    }

    let text = node_text(node, ctx.source).trim_end_matches('$');
    if text.is_empty() {
        return;
    }

    let target_name = ctx.spec.owner.identifier();
    let proven = if text == target_name {
        if let Some(qualifier) =
            member_qualifier(node, ctx.source).or_else(|| stable_type_qualifier(node, ctx.source))
        {
            qualifier_matches_target_owner(&qualifier, ctx.spec)
        } else if is_explicit_static_receiver_simple_name(node, ctx) {
            true
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

fn java_type_import_owner_matches_target(node: Node<'_>, ctx: &ScalaJavaScanCtx<'_, '_>) -> bool {
    if node_text(node, ctx.source).trim_end_matches('$') != ctx.spec.owner.identifier() {
        return false;
    }
    let mut ancestor = node.parent();
    let import = loop {
        let Some(current) = ancestor else {
            return false;
        };
        if current.kind() == "import_declaration" {
            break current;
        }
        ancestor = current.parent();
    };
    let mut segments = Vec::new();
    let mut cursor = import.walk();
    for child in import.named_children(&mut cursor).filter(|child| {
        matches!(
            child.kind(),
            "identifier" | "type_identifier" | "operator_identifier"
        )
    }) {
        let segment = node_text(child, ctx.source).trim();
        if segment.is_empty() {
            return false;
        }
        if segment != "_root_" {
            segments.push(segment.to_string());
        }
        if child == node {
            let path = segments.join(".");
            return path == ctx.spec.owner.fq_name()
                || scala_file_package(ctx.scala, ctx.file).is_some_and(|package| {
                    format!("{package}.{path}") == ctx.spec.owner.fq_name()
                });
        }
    }
    false
}

fn is_explicit_static_receiver_simple_name(node: Node<'_>, ctx: &ScalaJavaScanCtx<'_, '_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression"
            && parent.child_by_field_name("value") == Some(node)
            && ctx
                .visibility
                .contains(node_text(node, ctx.source).trim_end_matches('$'))
            && !is_type_shadowed(ctx, node_text(node, ctx.source).trim_end_matches('$'))
            && !is_term_shadowed(ctx, node_text(node, ctx.source).trim_end_matches('$'))
    })
}

fn maybe_record_java_static_field_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if is_target_member_identifier(node, ctx)
        && scala_static_receiver_matches_target_owner(node, ctx)
    {
        push_scala_hit(node, ctx);
    }
}

fn maybe_record_java_static_method_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if !is_target_member_identifier(node, ctx)
        || !scala_static_receiver_matches_target_owner(node, ctx)
    {
        return;
    }
    let Some(call_shape) = call_site_shape_for_reference(node) else {
        return;
    };
    if call_shape.type_arguments_only || call_shape.lists.len() != 1 {
        return;
    }
    let Some(expected_arities) = ctx.spec.callable_arities.as_ref() else {
        return;
    };
    let actual_arity = call_shape.lists[0].arity;
    if expected_arities
        .iter()
        .copied()
        .any(|expected| expected.accepts(actual_arity))
    {
        push_scala_hit(node, ctx);
    }
}

fn is_target_member_identifier(node: Node<'_>, ctx: &ScalaJavaScanCtx<'_, '_>) -> bool {
    if has_ancestor_kind(node, "import_declaration") || is_declaration_name(node) {
        return false;
    }
    if node_text(node, ctx.source).trim_end_matches('$') != ctx.spec.member_name {
        return false;
    }
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node)
    })
}

fn scala_static_receiver_matches_target_owner(
    node: Node<'_>,
    ctx: &ScalaJavaScanCtx<'_, '_>,
) -> bool {
    let Some(receiver) = member_qualifier_node(node) else {
        return false;
    };
    let receiver_text = node_text(receiver, ctx.source)
        .trim()
        .trim_end_matches('$')
        .to_string();
    if receiver_text.is_empty() {
        return false;
    }
    if receiver_text == ctx.spec.owner.fq_name() {
        return true;
    }
    ctx.visibility.contains(&receiver_text)
        && !is_term_shadowed(ctx, &receiver_text)
        && !is_type_shadowed(ctx, &receiver_text)
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
        .owners
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
    if brokk_bifrost_core::analyzer::usages::common::external_usage_hit_count(ctx.hits)
        > ctx.max_usages
    {
        *ctx.limit_exceeded = true;
    }
}

fn nearest_scala_declaration(scala: &dyn ScalaSource, file: &ProjectFile) -> Option<CodeUnit> {
    scala.declarations(file).into_iter().next()
}

fn scala_file_package(scala: &dyn ScalaSource, file: &ProjectFile) -> Option<String> {
    scala
        .declarations(file)
        .into_iter()
        .next()
        .map(|unit| unit.package_name().to_string())
}

fn is_top_level_type(target: &CodeUnit) -> bool {
    !target.short_name().contains('.')
}

fn nested_owner_qualifier(target: &CodeUnit) -> Option<&str> {
    target.short_name().rsplit_once('.').map(|(owner, _)| owner) // fqname-M4: package-less short_name owner; fq.parent() would render the package-qualified owner
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

fn seed_term_shadow(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    match node.kind() {
        "parameter" | "class_parameter" | "function_definition" => {
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            insert_term_shadow(name, ctx);
        }
        "val_definition" | "var_definition" => {
            let Some(pattern) = node.child_by_field_name("pattern") else {
                return;
            };
            for name in scala_pattern_binder_names(pattern, ctx.source) {
                if let Some(scope) = ctx.term_shadow_scopes.last_mut() {
                    scope.insert(name.to_string());
                }
            }
        }
        _ => {}
    }
}

fn insert_term_shadow(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    let name = node_text(node, ctx.source).trim();
    if !name.is_empty()
        && let Some(scope) = ctx.term_shadow_scopes.last_mut()
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

fn is_term_shadowed(ctx: &ScalaJavaScanCtx<'_, '_>, name: &str) -> bool {
    ctx.term_shadow_scopes
        .iter()
        .rev()
        .any(|scope| scope.contains(name))
}

fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
}
