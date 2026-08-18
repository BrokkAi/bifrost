use brokk_bifrost_core::hash::HashMap;
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
    pub fn extend(&mut self, other: Self) {
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

/// The ordered names one PHP function or constant reference can bind to.
///
/// PHP resolves an UNQUALIFIED single-segment function or constant name in the
/// current namespace first and, finding nothing declared there, in the global
/// namespace. A declaration in the current namespace therefore SHADOWS the
/// global one, which is why the two candidates are ordered rather than a set
/// (#1866). Every other spelling -- `\name`, a qualified path, `namespace\name`,
/// a `use function` / `use const` alias -- names exactly one target and carries
/// no fallback.
///
/// Types have no such fallback in PHP, so this shape belongs to the function and
/// constant entry points only and never to [`resolve_php_type`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpCallableCandidates {
    primary: String,
    global_fallback: Option<String>,
}

impl PhpCallableCandidates {
    /// A spelling that names exactly one target.
    fn exact(name: String) -> Self {
        Self {
            primary: name,
            global_fallback: None,
        }
    }

    /// An unqualified name in a namespaced file: the namespace-qualified
    /// spelling shadows the global one.
    fn shadowing(primary: String, global_fallback: String) -> Self {
        debug_assert_ne!(
            primary, global_fallback,
            "a shadowing candidate pair must name two different targets"
        );
        Self {
            primary,
            global_fallback: Some(global_fallback),
        }
    }

    /// The candidates in PHP's own lookup order, most specific first.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.primary.as_str()).chain(self.global_fallback.as_deref())
    }

    /// The name PHP's lookup ends on. An unresolved reference is reported
    /// against this one, because it is where the search actually stopped:
    /// naming `Monolog.substr` for a bare `substr(...)` invents a target PHP
    /// never looked for.
    pub fn last(&self) -> &str {
        self.global_fallback.as_deref().unwrap_or(&self.primary)
    }

    /// The candidate the workspace indexes, preferring the shadowing one. When
    /// it indexes neither, the namespaced spelling stands, so an unresolvable
    /// reference keeps naming the namespace it was written in.
    pub fn first_indexed(&self, is_indexed: impl Fn(&str) -> bool) -> &str {
        self.iter()
            .find(|candidate| is_indexed(candidate))
            .unwrap_or(&self.primary)
    }
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
pub fn php_file_context_from_tree_at(
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

/// The declared PHP types that prove a receiver is dynamic: `object` and
/// `mixed`.
///
/// Both are reserved words -- PHP has forbidden them as class names since 7.2
/// and 8.0 respectively -- so an unqualified spelling of either in a type
/// position is always the builtin and never a class in the current namespace.
/// A declaration that names one of them therefore states that its value's
/// member surface is decided at run time, which is a different fact from a
/// declaration this resolver merely cannot follow.
const PHP_DYNAMIC_TYPE_NAMES: &[&str] = &["object", "mixed"];

/// The builtin non-nominal type `raw` names, if any.
///
/// `raw` is stored-signature or declaration text, the one boundary in the PHP
/// resolver where no parser node exists, so it is split on `|` exactly as
/// [`resolve_php_type_arms`] splits it. A union with a dynamic arm is dynamic:
/// `A|object` admits any object, so the declaration bounds nothing.
pub fn php_dynamic_type_keyword(raw: &str) -> Option<&'static str> {
    raw.split('|').find_map(|piece| {
        let piece = piece.trim();
        let piece = piece.strip_prefix('?').map(str::trim).unwrap_or(piece);
        php_dynamic_type_name(piece)
    })
}

/// The builtin non-nominal type the declared-type node `node` names, if any.
///
/// This is [`php_dynamic_type_keyword`]'s node-path twin: it reads the parser's
/// own type structure -- a `union_type`'s children, an `optional_type`'s inner
/// type -- and never splits text.
pub fn php_dynamic_type_keyword_node(
    node: Node<'_>,
    source: &str,
    mut step: impl FnMut() -> bool,
) -> Option<&'static str> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if !step() {
            return None;
        }
        match current.kind() {
            // `mixed` is a `primitive_type` and `object` is a `named_type`
            // wrapping a bare `name`, so both leaf shapes are read here.
            "primitive_type" | "name" => {
                if let Some(keyword) =
                    php_leaf_text(current, source).and_then(php_dynamic_type_name)
                {
                    return Some(keyword);
                }
            }
            "named_type" | "optional_type" | "union_type" => {
                for index in (0..current.named_child_count()).rev() {
                    if let Some(child) = current.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// The builtin non-nominal type one already isolated type spelling names.
///
/// A leading `\` makes the spelling an explicit global class name, which is a
/// nominal reference to a (nonexistent) class rather than the builtin.
fn php_dynamic_type_name(piece: &str) -> Option<&'static str> {
    if piece.starts_with('\\') {
        return None;
    }
    PHP_DYNAMIC_TYPE_NAMES
        .iter()
        .find(|name| piece.eq_ignore_ascii_case(name))
        .copied()
}

/// What a PHP declaration's declared type proves about the values it holds.
///
/// The three cases are distinct answers, not degrees of one: a nominal type
/// names classes to navigate to, `object`/`mixed` proves the member surface is
/// decided at run time, and everything else proves nothing at all. Collapsing
/// the middle case into the last one is what made a proven-dynamic receiver
/// indistinguishable from a shape the resolver does not follow yet (#2030).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpDeclaredType {
    /// Every class the declaration names: one for an ordinary or nullable
    /// type, several for a finite union. Never empty.
    Nominal(Vec<String>),
    /// The declaration is the builtin `object` or `mixed`, named here so the
    /// report can quote it.
    Dynamic(&'static str),
    /// The declaration is absent, or names something this resolver does not
    /// follow.
    Unknown,
}

impl PhpDeclaredType {
    /// The nominal reading of `arms`, which is [`PhpDeclaredType::Unknown`]
    /// when the arms prove no class.
    pub fn nominal(arms: Vec<String>) -> Self {
        if arms.is_empty() {
            Self::Unknown
        } else {
            Self::Nominal(arms)
        }
    }

    /// Every class this declaration names, and none when it names none.
    pub fn arms(self) -> Vec<String> {
        match self {
            Self::Nominal(arms) => arms,
            Self::Dynamic(_) | Self::Unknown => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhpStructuredPath {
    segments: Vec<String>,
    absolute: bool,
    namespace_relative: bool,
}

/// Resolves one precise nominal PHP type directly from its parser nodes.
///
/// A nullable `?T` is resolved as `T`: `null` has no members, so a member
/// navigation that could succeed at run time can only bind through the non-null
/// arm, and naming `T` manufactures no precision.
///
/// Union, intersection, DNF, primitive, and bottom types stay rejected. A union
/// names two or more classes and picking one arm would invent precision the
/// declaration does not have; see [`resolve_php_type_node_arms`] for the
/// caller that wants the whole arm set instead of one name.
pub fn resolve_php_type_node(
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
            "named_type" | "optional_type" => {
                let child = php_only_named_child(node, &mut step)?;
                if !matches!(child.kind(), "name" | "qualified_name" | "named_type") {
                    return None;
                }
                node = child;
            }
            "name" | "qualified_name" | "namespace_name" | "fully_qualified_name" => break,
            "union_type"
            | "intersection_type"
            | "disjunctive_normal_form_type"
            | "primitive_type"
            | "bottom_type" => return None,
            _ => return None,
        }
    }

    let path = php_structured_path(node, source, &mut step)?;
    // `object` parses as a `named_type` over a bare `name`, so without this
    // guard the namespace join below would answer it as a class named `object`
    // in the current namespace -- a nominal owner no PHP file can declare.
    if !path.absolute
        && !path.namespace_relative
        && let [only] = path.segments.as_slice()
        && php_dynamic_type_name(only).is_some()
    {
        return None;
    }
    resolve_php_structured_path(path, ctx, &ctx.aliases.type_aliases, &mut step)
}

/// Resolves every nominal arm a declared PHP type node names, in declaration
/// order and deduplicated.
///
/// A single nominal (or nullable) type yields one arm. A `union_type` yields
/// one arm per non-`null` member: `null` is dropped because it has no members,
/// exactly as `?T` is unwrapped above. Anything else -- an intersection, a DNF
/// type, a primitive arm, or an arm this resolver cannot name -- yields no arms
/// at all, so the caller makes no claim rather than a partial one.
///
/// The arm count is capped at [`PHP_MAX_TYPE_ARMS`]. A wider union yields no
/// arms: truncating it would report a smaller ambiguity than the declaration
/// actually has.
pub fn resolve_php_type_node_arms(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    mut step: impl FnMut() -> bool,
) -> Vec<String> {
    if !step() {
        return Vec::new();
    }
    if node.kind() != "union_type" {
        return resolve_php_type_node(node, source, ctx, step)
            .into_iter()
            .collect();
    }
    let mut arms: Vec<String> = Vec::new();
    for index in 0..node.named_child_count() {
        if !step() {
            return Vec::new();
        }
        let Some(child) = node.named_child(index) else {
            return Vec::new();
        };
        if php_is_null_type_node(child, source) {
            continue;
        }
        let Some(arm) = resolve_php_type_node(child, source, ctx, &mut step) else {
            return Vec::new();
        };
        if !arms.contains(&arm) {
            arms.push(arm);
        }
    }
    php_capped_type_arms(arms)
}

/// The `null` arm of a union, which the grammar spells as a `primitive_type`.
fn php_is_null_type_node(node: Node<'_>, source: &str) -> bool {
    node.kind() == "primitive_type"
        && php_leaf_text(node, source).is_some_and(|text| text.eq_ignore_ascii_case("null"))
}

/// Resolves one literal PHP function name from parser structure. Dynamic
/// callable expressions deliberately remain unsupported.
pub fn resolve_php_function_node(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    mut step: impl FnMut() -> bool,
) -> Option<PhpCallableCandidates> {
    if !matches!(
        node.kind(),
        "name" | "qualified_name" | "namespace_name" | "fully_qualified_name"
    ) {
        return None;
    }
    let path = php_structured_path(node, source, &mut step)?;
    resolve_php_structured_callable(path, ctx, &ctx.aliases.function_aliases, &mut step)
}

/// Resolves one literal PHP constant name from parser structure and maps the
/// public namespace path to Bifrost's module-constant declaration identity.
pub fn resolve_php_constant_node(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    mut step: impl FnMut() -> bool,
) -> Option<PhpCallableCandidates> {
    if !matches!(
        node.kind(),
        "name" | "qualified_name" | "namespace_name" | "fully_qualified_name"
    ) {
        return None;
    }
    let path = php_structured_path(node, source, &mut step)?;
    let public = resolve_php_structured_callable(path, ctx, &ctx.aliases.const_aliases, &mut step)?;
    if !step() {
        return None;
    }
    Some(match public.global_fallback {
        Some(global) => PhpCallableCandidates::shadowing(
            module_constant_fq(&public.primary),
            module_constant_fq(&global),
        ),
        None => PhpCallableCandidates::exact(module_constant_fq(&public.primary)),
    })
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

/// [`resolve_php_structured_path`] plus PHP's global-namespace fallback.
///
/// The base helper is shared with TYPE resolution, where PHP has no such
/// fallback, so the extra candidate is added here -- on the function and
/// constant entry points -- rather than in the shared walk (#1866).
fn resolve_php_structured_callable(
    path: PhpStructuredPath,
    ctx: &PhpFileContext,
    aliases: &HashMap<String, String>,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpCallableCandidates> {
    let unqualified = !path.absolute
        && !path.namespace_relative
        && path.segments.len() == 1
        && !aliases.contains_key(&path.segments[0]);
    let global = unqualified.then(|| path.segments[0].clone());
    let primary = resolve_php_structured_path(path, ctx, aliases, step)?;
    Some(match global {
        Some(global) if !ctx.namespace.is_empty() => {
            PhpCallableCandidates::shadowing(primary, global)
        }
        _ => PhpCallableCandidates::exact(primary),
    })
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

/// The most nominal arms a declared PHP type may name and still be answered.
///
/// This mirrors `DEFAULT_RECEIVER_MAX_TARGETS`, the shared receiver candidate
/// limit: a wider declaration is not a bounded ambiguity anyone can act on.
pub const PHP_MAX_TYPE_ARMS: usize = 4;

/// Resolves the one class a declared PHP type names, or `None` when it names
/// none or more than one.
///
/// `?T` and `T|null` resolve to `T` because `null` has no members. A true union
/// `A|B` resolves to nothing: every caller of this function needs a single
/// owner fq name, and choosing an arm would manufacture precision. A caller
/// that can carry the whole set asks [`resolve_php_type_arms`] instead; this
/// function is that computation's exactly-one-arm case.
pub fn resolve_php_type(raw: &str, ctx: &PhpFileContext) -> Option<String> {
    let mut arms = resolve_php_type_arms(raw, ctx);
    (arms.len() == 1).then(|| arms.remove(0))
}

/// Resolves every nominal arm a declared PHP type string names, in declaration
/// order and deduplicated.
///
/// `raw` is stored-signature or declaration text. It is the one boundary in the
/// PHP resolver where no parser node exists for the declared type, so it is the
/// one place a `|` split is legitimate; the node path uses
/// [`resolve_php_type_node_arms`] and must not gain string parsing.
///
/// `null` arms are dropped, and a leading `?` on a piece marks that piece's own
/// null arm. An empty or relative (`self`/`static`/`parent`) arm yields no arms
/// at all, and so does a union wider than [`PHP_MAX_TYPE_ARMS`]: truncating it
/// would claim a narrower ambiguity than the declaration has.
pub fn resolve_php_type_arms(raw: &str, ctx: &PhpFileContext) -> Vec<String> {
    let mut arms: Vec<String> = Vec::new();
    for piece in raw.split('|') {
        let piece = piece.trim();
        let piece = piece.strip_prefix('?').map(str::trim).unwrap_or(piece);
        if piece.eq_ignore_ascii_case("null") {
            continue;
        }
        if piece.is_empty() || matches!(piece, "self" | "static" | "parent") {
            return Vec::new();
        }
        let Some(arm) = resolve_php_nominal_type(piece, ctx) else {
            return Vec::new();
        };
        if !arms.contains(&arm) {
            arms.push(arm);
        }
    }
    php_capped_type_arms(arms)
}

fn php_capped_type_arms(arms: Vec<String>) -> Vec<String> {
    if arms.len() > PHP_MAX_TYPE_ARMS {
        return Vec::new();
    }
    arms
}

/// Resolves one already isolated nominal type name against the file's imports
/// and namespace.
fn resolve_php_nominal_type(first: &str, ctx: &PhpFileContext) -> Option<String> {
    if first.starts_with('\\') {
        return Some(php_namespace_to_fq(first));
    }
    // The builtins `object` and `mixed` name no class, and joining them onto
    // the file's namespace would manufacture one (#2030).
    if php_dynamic_type_name(first).is_some() {
        return None;
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

pub fn resolve_php_function(raw: &str, ctx: &PhpFileContext) -> Option<PhpCallableCandidates> {
    if raw.starts_with('\\') {
        return Some(PhpCallableCandidates::exact(php_namespace_to_fq(raw)));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.function_aliases.get(&normalized) {
        return Some(PhpCallableCandidates::exact(imported.clone()));
    }
    let namespaced = join_namespace(&ctx.namespace, &normalized);
    Some(match php_global_fallback_applies(&normalized, ctx) {
        true => PhpCallableCandidates::shadowing(namespaced, normalized),
        false => PhpCallableCandidates::exact(namespaced),
    })
}

pub fn resolve_php_constant(raw: &str, ctx: &PhpFileContext) -> Option<PhpCallableCandidates> {
    if raw.starts_with('\\') {
        return Some(PhpCallableCandidates::exact(module_constant_fq(
            &php_namespace_to_fq(raw),
        )));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.const_aliases.get(&normalized) {
        return Some(PhpCallableCandidates::exact(module_constant_fq(imported)));
    }
    let namespaced = join_namespace(&ctx.namespace, &format!("_module_.{normalized}"));
    Some(match php_global_fallback_applies(&normalized, ctx) {
        true => PhpCallableCandidates::shadowing(namespaced, module_constant_fq(&normalized)),
        false => PhpCallableCandidates::exact(namespaced),
    })
}

/// Whether PHP's global-namespace fallback applies to an already normalized,
/// non-absolute, non-aliased function or constant name.
///
/// The rule is the one `diagnostics.rs` states: an unqualified -- that is,
/// single-segment -- function or constant name reaches the global namespace
/// after the current one. A qualified name (`Sub\name`), the `namespace\name`
/// relative form and a file with no namespace at all each have exactly one
/// candidate: the first two are not unqualified, and in the global namespace the
/// two candidates coincide.
fn php_global_fallback_applies(normalized: &str, ctx: &PhpFileContext) -> bool {
    !ctx.namespace.is_empty() && !normalized.contains('.')
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
