use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::php_graph::hits::{push_hit, push_hit_range};
use crate::analyzer::usages::php_graph::resolver::{
    PhpHierarchyIndex, TargetKind, TargetSpec, is_const_declaration_name, is_function_call_name,
    is_function_declaration_name, is_member_or_scoped_access_name, is_object_creation_type_name,
    qualified_candidate_text, receiver_is_enclosing_subtype, receiver_type_matches,
    static_receiver_matches,
};
use crate::analyzer::{
    IAnalyzer, PhpAnalyzer, PhpFileContext, ProjectFile, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
use crate::text_utils::compute_line_starts;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

pub(super) fn scan_file(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hierarchy: &PhpHierarchyIndex,
    hits: &mut BTreeSet<UsageHit>,
) {
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };

    let ctx = php.file_context_from_source(file, &source);

    let line_starts = compute_line_starts(&source);
    if matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
        scan_member_patterns(
            tree.root_node(),
            analyzer,
            file,
            &source,
            &line_starts,
            &ctx,
            hierarchy,
            spec,
            hits,
        );
    } else {
        scan_node(
            tree.root_node(),
            analyzer,
            file,
            &source,
            &line_starts,
            &ctx,
            spec,
            hits,
        );
    }
}

static PARAMETER_VARIABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"[(,]\s*(?P<type>\\?[A-Za-z_][A-Za-z0-9_\\]*(?:\|\\?[A-Za-z_][A-Za-z0-9_\\]*)?)\s+\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)",
    )
    .expect("valid PHP parameter-variable regex")
});

static ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[^;]+);")
        .expect("valid PHP assignment regex")
});

static INSTANCE_MEMBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*->\s*(?P<member>[A-Za-z_][A-Za-z0-9_]*)\b")
        .expect("valid PHP instance member regex")
});

static STATIC_MEMBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<recv>\\?[A-Za-z_][A-Za-z0-9_\\]*)\s*::\s*\$?(?P<member>[A-Za-z_][A-Za-z0-9_]*)\b",
    )
    .expect("valid PHP static member regex")
});

#[allow(clippy::too_many_arguments)]
fn scan_node(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    if node.kind() == "namespace_use_declaration" || node.kind() == "comment" {
        return;
    }

    if matches!(node.kind(), "namespace_name" | "qualified_name") {
        handle_candidate(node, analyzer, file, source, line_starts, ctx, spec, hits);
        return;
    }

    if matches!(node.kind(), "name" | "variable_name") {
        handle_candidate(node, analyzer, file, source, line_starts, ctx, spec, hits);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, analyzer, file, source, line_starts, ctx, spec, hits);
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_candidate(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    match spec.kind {
        TargetKind::Type => {
            if candidate_resolves_to_type(node, source, ctx, &spec.target_fq_name) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Constructor => {
            if is_constructor_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Method | TargetKind::Field => {}
        TargetKind::Constant => {
            if node.kind() != "namespace_name" && is_constant_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Function => {
            if node.kind() != "namespace_name" && is_function_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
    }
}

fn candidate_resolves_to_type(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    target_fq_name: &str,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    resolve_php_type(&raw, ctx).is_some_and(|fq| fq == target_fq_name)
}

fn is_constructor_reference(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    spec: &TargetSpec,
) -> bool {
    let Some(owner) = spec.owner_fq_name.as_deref() else {
        return false;
    };
    if !is_reference_context(node) {
        return false;
    }
    if !is_object_creation_type_name(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    resolve_php_type(&raw, ctx).is_some_and(|fq| fq == owner)
}

fn is_constant_reference(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    spec: &TargetSpec,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    if is_function_call_name(node)
        || is_member_or_scoped_access_name(node)
        || is_const_declaration_name(node)
    {
        return false;
    }
    resolve_php_constant(&raw, ctx).is_some_and(|fq| fq == spec.target_fq_name)
}

fn is_function_reference(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    spec: &TargetSpec,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    if !is_function_call_name(node) {
        return false;
    }
    if is_member_or_scoped_access_name(node) || is_function_declaration_name(node) {
        return false;
    }
    resolve_php_function(&raw, ctx).is_some_and(|fq| fq == spec.target_fq_name)
}

fn is_reference_context(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "namespace_use_declaration"
                | "comment"
                | "string"
                | "encapsed_string"
                | "string_value"
                | "heredoc"
                | "nowdoc"
        ) {
            return false;
        }
        parent = current.parent();
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn scan_member_patterns(
    root: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    if !matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
        return;
    }
    let Some(owner) = spec.owner_fq_name.as_deref() else {
        return;
    };
    for (scope_start, scope_end) in member_scope_ranges(root) {
        let Some(scope_source) = source.get(scope_start..scope_end) else {
            continue;
        };
        scan_instance_members_in_order(
            scope_start,
            scope_source,
            analyzer,
            file,
            source,
            line_starts,
            ctx,
            hierarchy,
            owner,
            spec,
            hits,
        );
    }

    for captures in STATIC_MEMBER_RE.captures_iter(source) {
        let Some(receiver) = captures.name("recv") else {
            continue;
        };
        let member = captures.name("member").expect("member capture");
        if member.as_str() != spec.member_name {
            continue;
        }
        if !static_receiver_matches(
            analyzer,
            file,
            member.start(),
            member.end(),
            line_starts,
            receiver.as_str(),
            owner,
            ctx,
            hierarchy,
        ) {
            continue;
        }
        push_hit_range(
            member.start(),
            member.end(),
            analyzer,
            file,
            source,
            line_starts,
            spec,
            hits,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_instance_members_in_order(
    scope_start: usize,
    scope_source: &str,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    full_source: &str,
    line_starts: &[usize],
    ctx: &PhpFileContext,
    hierarchy: &PhpHierarchyIndex,
    owner: &str,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let mut engine = LocalInferenceEngine::default();
    let header = scope_source
        .split_once('{')
        .map(|(header, _)| header)
        .unwrap_or(scope_source);
    seed_parameter_receivers(header, ctx, &mut engine);

    let mut events = Vec::new();
    for captures in ASSIGNMENT_RE.captures_iter(scope_source) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let Some(lhs) = captures.name("lhs") else {
            continue;
        };
        let Some(rhs) = captures.name("rhs") else {
            continue;
        };
        events.push(MemberScanEvent::Assignment {
            start: whole.start(),
            lhs_start: lhs.start(),
            lhs_end: lhs.end(),
            rhs_start: rhs.start(),
            rhs_end: rhs.end(),
        });
    }
    for captures in INSTANCE_MEMBER_RE.captures_iter(scope_source) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let Some(var) = captures.name("var") else {
            continue;
        };
        let Some(member) = captures.name("member") else {
            continue;
        };
        if member.as_str() != spec.member_name {
            continue;
        }
        events.push(MemberScanEvent::InstanceMember {
            start: whole.start(),
            receiver_start: var.start(),
            receiver_end: var.end(),
            member_start: member.start(),
            member_end: member.end(),
        });
    }
    events.sort_by_key(MemberScanEvent::start);

    for event in events {
        match event {
            MemberScanEvent::Assignment {
                lhs_start,
                lhs_end,
                rhs_start,
                rhs_end,
                ..
            } => {
                let Some(lhs) = scope_source.get(lhs_start..lhs_end) else {
                    continue;
                };
                let Some(rhs) = scope_source.get(rhs_start..rhs_end) else {
                    continue;
                };
                apply_receiver_assignment(lhs, rhs.trim(), ctx, &mut engine);
            }
            MemberScanEvent::InstanceMember {
                receiver_start,
                receiver_end,
                member_start,
                member_end,
                ..
            } => {
                let absolute_start = scope_start + member_start;
                let absolute_end = scope_start + member_end;
                let Some(receiver) = scope_source.get(receiver_start..receiver_end) else {
                    continue;
                };
                let receiver_matches = if receiver == "this" {
                    receiver_is_enclosing_subtype(
                        analyzer,
                        file,
                        absolute_start,
                        absolute_end,
                        line_starts,
                        owner,
                        hierarchy,
                    )
                } else {
                    precise_receiver_type(&engine, receiver)
                        .is_some_and(|fq| receiver_type_matches(&fq, owner, hierarchy))
                };
                if receiver_matches {
                    push_hit_range(
                        absolute_start,
                        absolute_end,
                        analyzer,
                        file,
                        full_source,
                        line_starts,
                        spec,
                        hits,
                    );
                }
            }
        }
    }
}

enum MemberScanEvent {
    Assignment {
        start: usize,
        lhs_start: usize,
        lhs_end: usize,
        rhs_start: usize,
        rhs_end: usize,
    },
    InstanceMember {
        start: usize,
        receiver_start: usize,
        receiver_end: usize,
        member_start: usize,
        member_end: usize,
    },
}

impl MemberScanEvent {
    fn start(&self) -> usize {
        match self {
            Self::Assignment { start, .. } | Self::InstanceMember { start, .. } => *start,
        }
    }
}

fn seed_parameter_receivers(
    header: &str,
    ctx: &PhpFileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    for captures in PARAMETER_VARIABLE_RE.captures_iter(header) {
        let Some(type_match) = captures.name("type") else {
            continue;
        };
        let Some(var_match) = captures.name("var") else {
            continue;
        };
        if let Some(fq) = resolve_php_type(type_match.as_str(), ctx) {
            engine.seed_symbol(var_match.as_str(), fq);
        }
    }
}

fn apply_receiver_assignment(
    lhs: &str,
    rhs: &str,
    ctx: &PhpFileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    if let Some(type_name) = rhs.strip_prefix("new ").and_then(read_leading_type_name)
        && let Some(fq) = resolve_php_type(type_name, ctx)
    {
        engine.seed_symbol(lhs, fq);
        return;
    }
    if let Some(rhs_var) = rhs.strip_prefix('$').and_then(read_leading_variable_name) {
        engine.alias_symbol(lhs, rhs_var);
        return;
    }
    engine.declare_shadow(lhs);
}

fn precise_receiver_type(engine: &LocalInferenceEngine<String>, receiver: &str) -> Option<String> {
    match engine.resolve_symbol(receiver) {
        SymbolResolution::Precise(targets) if targets.len() == 1 => targets.into_iter().next(),
        SymbolResolution::Unknown | SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => {
            None
        }
    }
}

fn member_scope_ranges(root: Node<'_>) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    collect_member_scope_ranges(root, &mut ranges);
    ranges.sort_unstable();

    let mut scoped = Vec::new();
    let mut cursor = 0;
    for (start, end) in ranges {
        if cursor < start {
            scoped.push((cursor, start));
        }
        scoped.push((start, end));
        cursor = cursor.max(end);
    }
    if cursor < root.end_byte() {
        scoped.push((cursor, root.end_byte()));
    }
    scoped
}

fn collect_member_scope_ranges(node: Node<'_>, ranges: &mut Vec<(usize, usize)>) {
    match node.kind() {
        "function_definition" | "method_declaration" | "anonymous_function_creation" => {
            ranges.push((node.start_byte(), node.end_byte()));
            return;
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_member_scope_ranges(child, ranges);
    }
}

fn read_leading_type_name(value: &str) -> Option<&str> {
    let end = value
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '\\'))
        .map(|(idx, ch)| idx + ch.len_utf8())
        .last()
        .unwrap_or(0);
    (end > 0).then(|| &value[..end])
}

fn read_leading_variable_name(value: &str) -> Option<&str> {
    let end = value
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
        .map(|(idx, ch)| idx + ch.len_utf8())
        .last()
        .unwrap_or(0);
    (end > 0).then(|| &value[..end])
}
