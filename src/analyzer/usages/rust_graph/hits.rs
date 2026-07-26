use crate::analyzer::rust::{RustReferenceNamespace, rust_focused_use_path};
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, usage_hit};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::rust_graph::extractor::{ScanCtx, rust_reference_namespace};
use crate::analyzer::usages::rust_graph::resolver::{
    RustDefinitionProvider, RustTokenPathRole, lexical_explicit_import_fqn,
    resolve_rust_token_tree_paths, rust_unique_nominal_reference_namespace,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_range};
use std::collections::BTreeSet;
use tree_sitter::Node;

pub(super) fn record_module_qualified_hits(root: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                record_scoped_identifier_hit(node, ctx)
            }
            "scoped_use_list" | "use_wildcard"
                if ctx.target_is_module || ctx.target_is_path_qualifier =>
            {
                record_use_tree_prefix_hit(node, ctx)
            }
            "token_tree" => record_token_tree_qualified_hits(node, ctx),
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn record_token_tree_qualified_hits(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "use_declaration") {
        return;
    }
    for segment in
        resolve_rust_token_tree_paths(ctx.rust, ctx.support, ctx.refs, ctx.file, ctx.source, node)
    {
        let segments = path_segment_texts(&segment.path, ctx.source);
        let namespace = match segment.role {
            RustTokenPathRole::Prefix => RustReferenceNamespace::PathPrefix,
            RustTokenPathRole::Call => RustReferenceNamespace::Value,
            RustTokenPathRole::Macro => RustReferenceNamespace::Macro,
            RustTokenPathRole::Value => {
                let Some(namespace) =
                    rust_unique_nominal_reference_namespace(ctx.rust, ctx.support, &segment.fqn)
                else {
                    continue;
                };
                namespace
            }
        };
        let root_shadowed = path_root_shadowed(&segment.path, ctx);
        if !segments.is_empty()
            && !root_shadowed
            && (ctx.matches_unique_resolved_fqn_in_namespace(&segment.fqn, namespace)
                || ctx.matches_path(
                    &segments,
                    segment.node.start_byte(),
                    namespace,
                    root_shadowed,
                    false,
                ))
        {
            record_target_segment(segment.node, false, ctx);
        }
    }
}

fn record_scoped_identifier_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let in_use_declaration = has_ancestor_kind(node, "use_declaration");
    if ctx.target_is_module || ctx.target_is_path_qualifier {
        record_scoped_target_segment_hit(node, in_use_declaration, ctx);
        return;
    }
    if in_use_declaration {
        return;
    }

    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(path) = rust_path_segments(node) else {
        return;
    };
    let segments = path_segment_texts(&path, ctx.source);
    let root_shadowed = path_root_shadowed(&path, ctx);
    if !ctx.matches_path(
        &segments,
        node.start_byte(),
        rust_reference_namespace(node),
        root_shadowed,
        rust_path_is_leading_absolute(node),
    ) && (root_shadowed || !structured_path_matches_unique_target(node, ctx))
    {
        return;
    }

    let start = name.start_byte();
    let end = name.end_byte();
    if let Some(enclosing) =
        member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    {
        push_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    }
}

fn record_scoped_target_segment_hit(
    node: Node<'_>,
    in_use_declaration: bool,
    ctx: &mut ScanCtx<'_>,
) {
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if in_use_declaration {
        if focused_use_path_matches(path, RustReferenceNamespace::PathPrefix, ctx) {
            if let Some(segment) = rust_path_segments(path).and_then(|path| path.last().copied()) {
                record_target_segment(segment, true, ctx);
            }
            // A module can contain an item with the same name as the module itself,
            // as in `future::maybe_done::miri_tests` importing
            // `super::maybe_done`. Forward lookup exposes the terminal import token
            // under the enclosing module identity. Once the structured prefix has
            // proven that exact module, preserve the same identity for its matching
            // terminal token without widening unrelated import paths.
            if ctx.target_is_module && node_text(name, ctx.source) == ctx.target_identifier() {
                record_target_segment(name, true, ctx);
            }
        }
    } else {
        let Some(path_segments) = rust_path_segments(path) else {
            return;
        };
        let path_text = path_segment_texts(&path_segments, ctx.source);
        let root_shadowed = path_root_shadowed(&path_segments, ctx);
        if (ctx.matches_path(
            &path_text,
            path.start_byte(),
            RustReferenceNamespace::PathPrefix,
            root_shadowed,
            rust_path_is_leading_absolute(path),
        ) || (!root_shadowed && structured_path_matches_unique_target(path, ctx)))
            && let Some(segment) = path_segments.last().copied()
        {
            record_target_segment(segment, false, ctx);
        }
    }

    if in_use_declaration {
        if focused_use_path_matches(node, rust_reference_namespace(node), ctx) {
            record_target_segment(name, true, ctx);
        }
    } else {
        let Some(full_segments) = rust_path_segments(node) else {
            return;
        };
        let full_text = path_segment_texts(&full_segments, ctx.source);
        let root_shadowed = path_root_shadowed(&full_segments, ctx);
        if ctx.matches_path(
            &full_text,
            node.start_byte(),
            rust_reference_namespace(node),
            root_shadowed,
            rust_path_is_leading_absolute(node),
        ) || (!root_shadowed && structured_path_matches_unique_target(node, ctx))
        {
            record_target_segment(name, false, ctx);
        }
    }
}

fn structured_path_matches_unique_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    structured_scoped_type_fqn(node, ctx).is_some_and(|fqn| ctx.matches_unique_resolved_fqn(&fqn))
}

fn structured_scoped_type_fqn(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    if node.kind() != "scoped_type_identifier"
        && !(node.kind() == "scoped_identifier" && ctx.target_is_path_qualifier)
    {
        return None;
    }
    let path = node.child_by_field_name("path")?;
    let name = node.child_by_field_name("name")?;
    let owner_fqn = lexical_explicit_import_fqn(ctx.rust, ctx.support, ctx.file, ctx.source, path);
    if let Some(owner_fqn) = owner_fqn {
        let owners = ctx
            .support
            .fqn(&owner_fqn)
            .into_iter()
            .filter(|candidate| {
                candidate.is_module() || candidate.is_class() || ctx.rust.is_type_alias(candidate)
            })
            .filter(|candidate| {
                ctx.rust
                    .usage_declaration_visible_at(candidate, ctx.file, path.start_byte())
            })
            .collect::<BTreeSet<_>>();
        if owners.len() != 1 {
            return None;
        }
        let fqns: BTreeSet<_> = RustDefinitionProvider::members_for_owner_name(
            ctx.support,
            &owner_fqn,
            node_text(name, ctx.source),
        )
        .into_iter()
        .filter(|candidate| {
            ctx.rust
                .usage_declaration_visible_at(candidate, ctx.file, name.start_byte())
        })
        .map(|candidate| candidate.fq_name())
        .collect();
        if fqns.len() == 1 {
            return fqns.into_iter().next();
        }
    }
    None
}

fn record_use_tree_prefix_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let path = if node.kind() == "scoped_use_list" {
        node.child_by_field_name("path")
    } else {
        first_named_child(node)
    };
    let Some(path) = path else {
        return;
    };
    if focused_use_path_matches(path, RustReferenceNamespace::PathPrefix, ctx)
        && let Some(segment) = rust_path_segments(path).and_then(|path| path.last().copied())
    {
        record_target_segment(segment, true, ctx);
    }
}

fn focused_use_path_matches(
    focused: Node<'_>,
    namespace: RustReferenceNamespace,
    ctx: &ScanCtx<'_>,
) -> bool {
    let Some(path) = rust_focused_use_path(focused, ctx.source) else {
        return false;
    };
    let segments = path.segments.iter().map(String::as_str).collect::<Vec<_>>();
    ctx.matches_path(
        &segments,
        focused.start_byte(),
        namespace,
        ctx.path_root_shadowed_at(node_text(path.root, ctx.source), path.root.start_byte()),
        // A focused node inside `use ::dep::{nested::Item}` stops at the
        // enclosing `scoped_use_list`, so walking upward from `focused` loses
        // the leading `::`. The reconstructed path's root is the outer `dep`
        // path and still carries that syntax.
        rust_path_is_leading_absolute(path.root),
    )
}

pub(super) fn rust_path_segments(mut node: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut reversed = Vec::new();
    loop {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                reversed.push(node.child_by_field_name("name")?);
                let Some(path) = node.child_by_field_name("path") else {
                    if node.child(0).is_some_and(|child| child.kind() == "::") {
                        break;
                    }
                    return None;
                };
                node = path;
            }
            "generic_type" => node = node.child_by_field_name("type")?,
            "generic_function" => node = node.child_by_field_name("function")?,
            "identifier" | "type_identifier" | "self" | "super" | "crate" => {
                reversed.push(node);
                break;
            }
            _ => return None,
        }
    }
    reversed.reverse();
    Some(reversed)
}

pub(super) fn rust_path_is_leading_absolute(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent()
        && matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier" | "generic_type" | "generic_function"
        )
    {
        node = parent;
    }
    loop {
        match node.kind() {
            "generic_type" => {
                let Some(inner) = node.child_by_field_name("type") else {
                    return false;
                };
                node = inner;
            }
            "generic_function" => {
                let Some(inner) = node.child_by_field_name("function") else {
                    return false;
                };
                node = inner;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(path) = node.child_by_field_name("path") {
                    node = path;
                } else {
                    return node.child(0).is_some_and(|child| child.kind() == "::");
                }
            }
            _ => return false,
        }
    }
}

fn path_segment_texts<'a>(path: &[Node<'_>], source: &'a str) -> Vec<&'a str> {
    path.iter()
        .map(|node| node_text(*node, source))
        .map(|segment| {
            if segment == "$crate" {
                "crate"
            } else {
                segment
            }
        })
        .collect()
}

fn path_root_shadowed(path: &[Node<'_>], ctx: &ScanCtx<'_>) -> bool {
    path.first().is_some_and(|root| {
        let name = node_text(*root, ctx.source);
        ctx.path_root_shadowed_at(name, root.start_byte())
    })
}

fn record_target_segment(segment: Node<'_>, in_use_declaration: bool, ctx: &mut ScanCtx<'_>) {
    if in_use_declaration {
        record_import_hit(segment, ctx);
        return;
    }
    let start = segment.start_byte();
    let end = segment.end_byte();
    if let Some(enclosing) =
        member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    {
        push_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    }
}

fn has_ancestor_kind(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
}

/// Text of `node`, normalizing away a leading `r#` raw-identifier escape when
/// `node` is one of tree-sitter-rust's identifier leaf kinds, so a usage site
/// like `self.r#type` compares equal to the (also-normalized) declaration
/// name `type` (#1128). See
/// `crate::analyzer::rust::declarations::rust_node_text` for the extraction
/// side of the same normalization.
fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_ident_text(
        node,
        source,
        true,
        &crate::analyzer::common::RUST_IDENTIFIER_SIGIL,
    )
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

pub(super) fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let end = node.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

pub(super) fn record_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let end = node.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
    reclassify_import_hit_at(ctx.hits, ctx.file, start, end);
}

pub(super) fn member_hit_enclosing(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    line_starts: &[usize],
    start: usize,
    end: usize,
) -> Option<CodeUnit> {
    analyzer.enclosing_code_unit(
        file,
        &Range {
            start_byte: start,
            end_byte: end,
            start_line: find_line_index_for_offset(line_starts, start),
            end_line: find_line_index_for_offset(line_starts, end),
        },
    )
}

pub(super) fn push_member_hit(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_member_hit_with_kind(
        file,
        source,
        line_starts,
        start,
        end,
        enclosing,
        hits,
        false,
    );
}

pub(super) fn push_unproven_member_hit(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    let start_line = find_line_index_for_offset(line_starts, start);
    hits.insert(
        usage_hit(
            file,
            start_line,
            start,
            end,
            enclosing,
            trimmed_snippet_around_range(source, line_starts, start, end, SNIPPET_CONTEXT_LINES),
        )
        .into_unproven(),
    );
}

pub(super) fn push_self_receiver_member_hit(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_member_hit_with_kind(file, source, line_starts, start, end, enclosing, hits, true);
}

#[allow(clippy::too_many_arguments)]
fn push_member_hit_with_kind(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
    self_receiver: bool,
) {
    let start_line = find_line_index_for_offset(line_starts, start);
    let hit = usage_hit(
        file,
        start_line,
        start,
        end,
        enclosing,
        trimmed_snippet_around_range(source, line_starts, start, end, SNIPPET_CONTEXT_LINES),
    );
    hits.insert(if self_receiver {
        hit.into_self_receiver()
    } else {
        hit
    });
}
