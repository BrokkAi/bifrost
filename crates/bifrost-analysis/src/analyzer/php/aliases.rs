use crate::hash::HashMap;
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::Node;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhpUseAliases {
    pub type_aliases: HashMap<String, String>,
    pub function_aliases: HashMap<String, String>,
    pub const_aliases: HashMap<String, String>,
}

impl PhpUseAliases {
    pub(super) fn extend(&mut self, other: Self) {
        self.type_aliases.extend(other.type_aliases);
        self.function_aliases.extend(other.function_aliases);
        self.const_aliases.extend(other.const_aliases);
    }

    pub fn merged(&self) -> HashMap<String, String> {
        let mut aliases = self.type_aliases.clone();
        aliases.extend(self.function_aliases.clone());
        aliases.extend(self.const_aliases.clone());
        aliases
    }
}

#[derive(Debug, Clone)]
pub struct PhpFileContext {
    pub namespace: String,
    pub aliases: PhpUseAliases,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhpUseKind {
    Type,
    Function,
    Const,
}

/// Builds the PHP namespace/import context visible at `byte` directly from the
/// parser tree. `step` is invoked before every syntax node inspected so bounded
/// callers can stop without returning a partially collected alias map.
pub(crate) fn php_file_context_from_tree_at(
    root: Node<'_>,
    source: &str,
    byte: usize,
    mut step: impl FnMut() -> bool,
) -> Option<PhpFileContext> {
    let mut namespace = String::new();
    let mut scope = root;
    let mut scope_start = 0usize;
    let mut scope_end = byte;

    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if child.kind() != "namespace_definition" {
            continue;
        }
        let body = child.child_by_field_name("body");
        if let Some(body) = body
            && body.start_byte() <= byte
            && byte < body.end_byte()
        {
            namespace = child
                .child_by_field_name("name")
                .and_then(|name| php_path_from_node(name, source, &mut step))
                .unwrap_or_default();
            scope = body;
            scope_start = body.start_byte();
            scope_end = byte;
            break;
        }
        if body.is_none() && child.start_byte() <= byte {
            namespace = child
                .child_by_field_name("name")
                .and_then(|name| php_path_from_node(name, source, &mut step))
                .unwrap_or_default();
            scope_start = child.end_byte();
            scope_end = byte;
            continue;
        }
        if child.start_byte() > byte {
            scope_end = scope_end.min(child.start_byte());
            break;
        }
    }

    let mut aliases = PhpUseAliases::default();
    let mut cursor = scope.walk();
    for child in scope.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if child.start_byte() < scope_start || child.start_byte() >= scope_end {
            continue;
        }
        if child.kind() == "namespace_definition" && scope.id() == root.id() {
            break;
        }
        if child.kind() != "namespace_use_declaration" {
            continue;
        }
        let parsed = php_use_aliases_from_node(child, source, &mut step)?;
        aliases.extend(parsed);
    }

    Some(PhpFileContext { namespace, aliases })
}

fn php_use_aliases_from_node(
    declaration: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpUseAliases> {
    if !step() {
        return None;
    }
    let default_kind = php_use_kind(declaration.child_by_field_name("type"), source);
    let body = declaration.child_by_field_name("body");
    let prefix = if body.is_some() {
        let mut cursor = declaration.walk();
        let mut prefix = None;
        for child in declaration.named_children(&mut cursor) {
            if !step() {
                return None;
            }
            if child.kind() == "namespace_name" {
                prefix = php_path_segments(child, source, step);
                break;
            }
        }
        prefix.unwrap_or_default()
    } else {
        Vec::new()
    };

    let clause_parent = body.unwrap_or(declaration);
    let mut aliases = PhpUseAliases::default();
    let mut cursor = clause_parent.walk();
    for clause in clause_parent.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if clause.kind() != "namespace_use_clause" {
            continue;
        }
        php_add_use_clause(clause, source, &prefix, default_kind, &mut aliases, step)?;
    }
    Some(aliases)
}

fn php_add_use_clause(
    clause: Node<'_>,
    source: &str,
    prefix: &[String],
    default_kind: PhpUseKind,
    aliases: &mut PhpUseAliases,
    step: &mut impl FnMut() -> bool,
) -> Option<()> {
    let alias_node = clause.child_by_field_name("alias");
    let mut imported = None;
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if alias_node.is_some_and(|alias| alias.id() == child.id()) {
            continue;
        }
        if matches!(child.kind(), "name" | "qualified_name" | "namespace_name") {
            imported = php_path_segments(child, source, step);
            break;
        }
    }
    let mut imported = imported?;
    if imported.is_empty() {
        return Some(());
    }
    if !prefix.is_empty() {
        let mut full = Vec::with_capacity(prefix.len() + imported.len());
        full.extend(prefix.iter().cloned());
        full.append(&mut imported);
        imported = full;
    }
    let local = if let Some(alias) = alias_node {
        if !step() {
            return None;
        }
        php_leaf_text(alias, source)?.to_string()
    } else {
        imported.last()?.clone()
    };
    let imported = imported.join(".");
    match php_use_kind(clause.child_by_field_name("type"), source) {
        PhpUseKind::Type if default_kind != PhpUseKind::Type => match default_kind {
            PhpUseKind::Function => aliases.function_aliases.insert(local, imported),
            PhpUseKind::Const => aliases.const_aliases.insert(local, imported),
            PhpUseKind::Type => unreachable!(),
        },
        PhpUseKind::Type => aliases.type_aliases.insert(local, imported),
        PhpUseKind::Function => aliases.function_aliases.insert(local, imported),
        PhpUseKind::Const => aliases.const_aliases.insert(local, imported),
    };
    Some(())
}

fn php_use_kind(node: Option<Node<'_>>, source: &str) -> PhpUseKind {
    match node.and_then(|node| node.utf8_text(source.as_bytes()).ok()) {
        Some(kind) if kind.eq_ignore_ascii_case("function") => PhpUseKind::Function,
        Some(kind) if kind.eq_ignore_ascii_case("const") => PhpUseKind::Const,
        _ => PhpUseKind::Type,
    }
}

fn php_path_from_node(
    node: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<String> {
    php_path_segments(node, source, step).map(|segments| segments.join("."))
}

fn php_path_segments(
    node: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if !step() {
            return None;
        }
        if current.kind() == "name" {
            if let Some(text) = php_leaf_text(current, source)
                && !text.is_empty()
            {
                segments.push(text.to_string());
            }
            continue;
        }
        for index in (0..current.named_child_count()).rev() {
            if !step() {
                return None;
            }
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    Some(segments)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhpStructuredPath {
    segments: Vec<String>,
    absolute: bool,
    namespace_relative: bool,
}

/// Resolves one precise nominal PHP type directly from its parser nodes.
///
/// This intentionally rejects nullable, union, intersection, DNF, and primitive
/// types. Those forms describe an open set (or no workspace class at all), so
/// choosing one arm would manufacture precision for bounded receiver analysis.
pub(crate) fn resolve_php_type_node(
    mut node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    mut step: impl FnMut() -> bool,
) -> Option<String> {
    loop {
        if !step() {
            return None;
        }
        match node.kind() {
            "named_type" => {
                let child = php_only_named_child(node, &mut step)?;
                if !matches!(child.kind(), "name" | "qualified_name") {
                    return None;
                }
                node = child;
            }
            "name" | "qualified_name" | "namespace_name" | "fully_qualified_name" => break,
            "optional_type"
            | "union_type"
            | "intersection_type"
            | "disjunctive_normal_form_type"
            | "primitive_type"
            | "bottom_type" => return None,
            _ => return None,
        }
    }

    let path = php_structured_path(node, source, &mut step)?;
    resolve_php_structured_path(path, ctx, &ctx.aliases.type_aliases, &mut step)
}

/// Resolves one literal PHP function name from parser structure. Dynamic
/// callable expressions deliberately remain unsupported.
pub(crate) fn resolve_php_function_node(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    mut step: impl FnMut() -> bool,
) -> Option<String> {
    if !matches!(
        node.kind(),
        "name" | "qualified_name" | "namespace_name" | "fully_qualified_name"
    ) {
        return None;
    }
    let path = php_structured_path(node, source, &mut step)?;
    resolve_php_structured_path(path, ctx, &ctx.aliases.function_aliases, &mut step)
}

/// Resolves one literal PHP constant name from parser structure and maps the
/// public namespace path to Bifrost's module-constant declaration identity.
pub(crate) fn resolve_php_constant_node(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    mut step: impl FnMut() -> bool,
) -> Option<String> {
    if !matches!(
        node.kind(),
        "name" | "qualified_name" | "namespace_name" | "fully_qualified_name"
    ) {
        return None;
    }
    let path = php_structured_path(node, source, &mut step)?;
    let public = resolve_php_structured_path(path, ctx, &ctx.aliases.const_aliases, &mut step)?;
    step().then(|| module_constant_fq(&public))
}

fn php_only_named_child<'tree>(
    node: Node<'tree>,
    step: &mut impl FnMut() -> bool,
) -> Option<Node<'tree>> {
    let mut only = None;
    for index in 0..node.named_child_count() {
        if !step() {
            return None;
        }
        let child = node.named_child(index)?;
        if only.replace(child).is_some() {
            return None;
        }
    }
    only
}

fn php_structured_path(
    node: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpStructuredPath> {
    if !step() {
        return None;
    }
    let absolute = php_path_has_leading_separator(node, step)?;
    let segments = php_path_segments(node, source, step)?;
    if segments.is_empty() {
        return None;
    }
    let namespace_relative =
        !absolute && segments[0].eq_ignore_ascii_case("namespace") && segments.len() > 1;
    Some(PhpStructuredPath {
        segments,
        absolute,
        namespace_relative,
    })
}

fn php_path_has_leading_separator(
    mut node: Node<'_>,
    step: &mut impl FnMut() -> bool,
) -> Option<bool> {
    loop {
        if !step() {
            return None;
        }
        let Some(first) = node.child(0) else {
            return Some(false);
        };
        if !step() {
            return None;
        }
        match first.kind() {
            "\\" => return Some(true),
            "qualified_name" | "namespace_name" | "fully_qualified_name" => node = first,
            _ => return Some(false),
        }
    }
}

fn resolve_php_structured_path(
    path: PhpStructuredPath,
    ctx: &PhpFileContext,
    aliases: &HashMap<String, String>,
    step: &mut impl FnMut() -> bool,
) -> Option<String> {
    let segments = if path.namespace_relative {
        path.segments.get(1..)?
    } else {
        path.segments.as_slice()
    };
    let first = segments.first()?;
    if matches!(
        first.to_ascii_lowercase().as_str(),
        "self" | "static" | "parent"
    ) {
        return None;
    }

    if path.absolute {
        return php_join_structured_segments("", segments, step);
    }
    if path.namespace_relative {
        return php_join_structured_segments(&ctx.namespace, segments, step);
    }
    if !step() {
        return None;
    }
    if let Some(imported) = aliases.get(first) {
        return php_join_structured_segments(imported, &segments[1..], step);
    }
    php_join_structured_segments(&ctx.namespace, segments, step)
}

fn php_join_structured_segments(
    prefix: &str,
    segments: &[String],
    step: &mut impl FnMut() -> bool,
) -> Option<String> {
    let mut resolved = prefix.to_string();
    for segment in segments {
        if !step() {
            return None;
        }
        if !resolved.is_empty() {
            resolved.push('.');
        }
        resolved.push_str(segment);
    }
    (!resolved.is_empty()).then_some(resolved)
}

fn php_leaf_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    node.utf8_text(source.as_bytes()).ok().map(str::trim)
}

static PHP_USE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^use\s+[^;]+;").expect("valid PHP use regex"));

pub fn parse_php_use_aliases_from_source(source: &str) -> PhpUseAliases {
    let mut aliases = PhpUseAliases::default();
    for matched in PHP_USE_RE.find_iter(source) {
        aliases.extend(parse_php_use_aliases_by_kind(matched.as_str()));
    }
    aliases
}

pub fn parse_php_use_aliases_by_kind(raw: &str) -> PhpUseAliases {
    let mut text = raw.trim().trim_end_matches(';').trim();
    let Some(rest) = text.strip_prefix("use ") else {
        return PhpUseAliases::default();
    };
    text = rest.trim();

    let (default_kind, text) = if let Some(rest) = text.strip_prefix("function ") {
        (PhpUseKind::Function, rest.trim())
    } else if let Some(rest) = text.strip_prefix("const ") {
        (PhpUseKind::Const, rest.trim())
    } else {
        (PhpUseKind::Type, text)
    };

    let mut aliases = PhpUseAliases::default();
    if text.is_empty() {
        return aliases;
    }

    if let Some((prefix, group)) = text.split_once('{') {
        let prefix = prefix.trim().trim_end_matches('\\');
        let group = group.trim_end_matches('}').trim();
        for part in group.split(',') {
            add_php_use_alias(prefix, part.trim(), default_kind, &mut aliases);
        }
        return aliases;
    }

    add_php_use_alias("", text, default_kind, &mut aliases);
    aliases
}

pub fn parse_php_use_aliases(raw: &str) -> HashMap<String, String> {
    parse_php_use_aliases_by_kind(raw).merged()
}

fn add_php_use_alias(
    prefix: &str,
    raw_part: &str,
    default_kind: PhpUseKind,
    aliases: &mut PhpUseAliases,
) {
    if raw_part.is_empty() {
        return;
    }
    let (kind, raw_part) = if let Some(rest) = raw_part.strip_prefix("function ") {
        (PhpUseKind::Function, rest.trim())
    } else if let Some(rest) = raw_part.strip_prefix("const ") {
        (PhpUseKind::Const, rest.trim())
    } else {
        (default_kind, raw_part)
    };
    let (path, alias) = split_php_use_alias(raw_part);
    let full_path = if prefix.is_empty() {
        path
    } else {
        format!("{prefix}\\{path}")
    };
    let fq = php_namespace_to_fq(&full_path);
    if fq.is_empty() {
        return;
    }
    let local = alias.unwrap_or_else(|| fq.rsplit('.').next().unwrap_or(fq.as_str()).to_string());
    match kind {
        PhpUseKind::Type => aliases.type_aliases.insert(local, fq),
        PhpUseKind::Function => aliases.function_aliases.insert(local, fq),
        PhpUseKind::Const => aliases.const_aliases.insert(local, fq),
    };
}

fn split_php_use_alias(raw_part: &str) -> (String, Option<String>) {
    let normalized = raw_part.trim();
    let lower = normalized.to_ascii_lowercase();
    if let Some(index) = lower.rfind(" as ") {
        let path = normalized[..index].trim().to_string();
        let alias = normalized[index + 4..].trim().to_string();
        return (path, (!alias.is_empty()).then_some(alias));
    }
    (normalized.to_string(), None)
}

pub fn php_namespace_to_fq(name: &str) -> String {
    name.trim()
        .trim_start_matches('\\')
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

pub fn resolve_php_type(raw: &str, ctx: &PhpFileContext) -> Option<String> {
    let first = raw.split('|').next().unwrap_or(raw).trim();
    // A nullable type `?Foo` is `Foo | null`; strip the marker so member access on a
    // nullable-typed receiver resolves against `Foo` (mirrors the union split above).
    let first = first.strip_prefix('?').map(str::trim).unwrap_or(first);
    if first.is_empty() || matches!(first, "self" | "static" | "parent") {
        return None;
    }
    if first.starts_with('\\') {
        return Some(php_namespace_to_fq(first));
    }
    let normalized = php_namespace_to_fq(first);
    let local = normalized.split('.').next().unwrap_or(normalized.as_str());
    if let Some(imported) = ctx.aliases.type_aliases.get(local) {
        if normalized == local {
            return Some(imported.clone());
        }
        let suffix = normalized
            .strip_prefix(local)
            .unwrap_or("")
            .trim_start_matches('.');
        return Some(if suffix.is_empty() {
            imported.clone()
        } else {
            format!("{imported}.{suffix}")
        });
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

pub(crate) fn resolve_php_function(raw: &str, ctx: &PhpFileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(php_namespace_to_fq(raw));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.function_aliases.get(&normalized) {
        return Some(imported.clone());
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

pub(crate) fn resolve_php_constant(raw: &str, ctx: &PhpFileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(module_constant_fq(&php_namespace_to_fq(raw)));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.const_aliases.get(&normalized) {
        return Some(module_constant_fq(imported));
    }
    Some(join_namespace(
        &ctx.namespace,
        &format!("_module_.{normalized}"),
    ))
}

fn module_constant_fq(fq_name: &str) -> String {
    if fq_name.contains("._module_.") {
        return fq_name.to_string();
    }
    let public = public_php_fq_name(fq_name);
    if let Some((namespace, name)) = public.rsplit_once('.') {
        format!("{namespace}._module_.{name}")
    } else {
        format!("_module_.{public}")
    }
}

fn public_php_fq_name(fq_name: &str) -> String {
    fq_name.replace("._module_.", ".")
}

fn join_namespace(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        namespace.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}
