use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhpUseAliases {
    pub type_aliases: HashMap<String, String>,
    pub function_aliases: HashMap<String, String>,
    pub const_aliases: HashMap<String, String>,
    ambiguous_type_targets: HashSet<String>,
    ambiguous_function_targets: HashSet<String>,
    ambiguous_const_targets: HashSet<String>,
}

impl PhpUseAliases {
    pub fn extend(&mut self, other: Self) {
        self.type_aliases.extend(other.type_aliases);
        self.function_aliases.extend(other.function_aliases);
        self.const_aliases.extend(other.const_aliases);
        self.ambiguous_type_targets
            .extend(other.ambiguous_type_targets);
        self.ambiguous_function_targets
            .extend(other.ambiguous_function_targets);
        self.ambiguous_const_targets
            .extend(other.ambiguous_const_targets);
    }

    /// Type targets represented by this alias summary. The iterator may repeat
    /// a target when it appears in both a public map and the retained target set.
    ///
    /// Unlike `type_aliases`, this retains both targets when different
    /// namespace scopes reuse one local alias for different declarations.
    pub fn type_targets(&self) -> impl Iterator<Item = &String> {
        self.type_aliases
            .values()
            .chain(self.ambiguous_type_targets.iter())
    }

    /// Function targets represented by this alias summary. The iterator may
    /// repeat a target when it appears in both a public map and the retained
    /// target set.
    pub fn function_targets(&self) -> impl Iterator<Item = &String> {
        self.function_aliases
            .values()
            .chain(self.ambiguous_function_targets.iter())
    }

    /// Constant targets represented by this alias summary. The iterator may
    /// repeat a target when it appears in both a public map and the retained
    /// target set.
    pub fn const_targets(&self) -> impl Iterator<Item = &String> {
        self.const_aliases
            .values()
            .chain(self.ambiguous_const_targets.iter())
    }

    fn insert(&mut self, kind: PhpUseKind, local: String, imported: String) {
        match kind {
            PhpUseKind::Type => {
                self.type_aliases.insert(local, imported);
            }
            PhpUseKind::Function => {
                self.function_aliases.insert(local, imported);
            }
            PhpUseKind::Const => {
                self.const_aliases.insert(local, imported);
            }
        }
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

#[derive(Debug, Clone)]
struct PhpAliasEvent {
    end: usize,
    aliases: PhpUseAliases,
}

#[derive(Debug, Clone)]
struct PhpNamespaceScope {
    start: usize,
    end: usize,
    namespace: String,
    events: Vec<PhpAliasEvent>,
}

#[derive(Debug, Clone)]
struct PhpContextSegment {
    start: usize,
    end: usize,
    context: PhpFileContext,
}

/// The lexical namespace and import context of a complete PHP source tree.
///
/// PHP has three scope shapes here: statements in the global namespace,
/// braced namespace bodies, and unbraced namespaces that continue to the next
/// namespace declaration (or end of file). The index stores those regions and
/// structured alias events without retaining the parser tree or source bytes,
/// so one parsed file can answer many context queries cheaply.
#[derive(Debug, Clone)]
pub struct PhpFileContextIndex {
    source_len: usize,
    segments: Vec<PhpContextSegment>,
    merged_aliases: PhpUseAliases,
}

impl PhpFileContextIndex {
    /// Build an index while invoking `step` for every syntax node inspected.
    /// Cancellation returns `None`; no partial index escapes the build.
    pub fn from_tree(root: Node<'_>, source: &str, mut step: impl FnMut() -> bool) -> Option<Self> {
        let mut scopes = Vec::new();
        let mut global_start = 0usize;
        let mut global_events = Vec::new();
        let mut unbraced: Option<PhpNamespaceScope> = None;
        let mut cursor = root.walk();
        for child in root.named_children(&mut cursor) {
            if !step() {
                return None;
            }
            if let Some(scope) = &mut unbraced {
                if child.kind() != "namespace_definition" {
                    if child.kind() == "namespace_use_declaration" {
                        let aliases = php_use_aliases_from_node(child, source, &mut step)?;
                        scope.events.push(PhpAliasEvent {
                            end: child.end_byte(),
                            aliases,
                        });
                    }
                    continue;
                }
                let mut finished = unbraced.take().expect("active namespace scope");
                finished.end = child.start_byte();
                scopes.push(finished);
                global_start = child.start_byte();
                global_events.clear();
            }
            if child.kind() != "namespace_definition" {
                if child.kind() == "namespace_use_declaration" {
                    let aliases = php_use_aliases_from_node(child, source, &mut step)?;
                    global_events.push(PhpAliasEvent {
                        end: child.end_byte(),
                        aliases,
                    });
                }
                continue;
            }

            let namespace = match child.child_by_field_name("name") {
                Some(name) => php_path_from_node(name, source, &mut step)?,
                None => String::new(),
            };
            if let Some(body) = child.child_by_field_name("body") {
                scopes.push(PhpNamespaceScope {
                    start: global_start,
                    end: child.start_byte(),
                    namespace: String::new(),
                    events: std::mem::take(&mut global_events),
                });
                scopes.push(PhpNamespaceScope {
                    start: child.start_byte(),
                    end: child.end_byte(),
                    namespace,
                    events: php_alias_events_from_children(
                        body,
                        body.start_byte(),
                        body.end_byte(),
                        source,
                        &mut step,
                    )?,
                });
                global_start = child.end_byte();
            } else {
                scopes.push(PhpNamespaceScope {
                    start: global_start,
                    end: child.start_byte(),
                    namespace: String::new(),
                    events: std::mem::take(&mut global_events),
                });
                unbraced = Some(PhpNamespaceScope {
                    start: child.start_byte(),
                    end: source.len(),
                    namespace,
                    events: Vec::new(),
                });
            }
        }
        if let Some(scope) = unbraced {
            scopes.push(scope);
        } else {
            scopes.push(PhpNamespaceScope {
                start: global_start,
                end: source.len(),
                namespace: String::new(),
                events: global_events,
            });
        }

        let mut merged_aliases = PhpUseAliases::default();
        let mut ambiguous_type_locals = HashSet::default();
        let mut ambiguous_function_locals = HashSet::default();
        let mut ambiguous_const_locals = HashSet::default();
        for scope in &scopes {
            for event in &scope.events {
                merged_aliases.merge_conservative(
                    &event.aliases,
                    &mut ambiguous_type_locals,
                    &mut ambiguous_function_locals,
                    &mut ambiguous_const_locals,
                );
            }
        }

        let mut segments = Vec::new();
        for scope in scopes {
            let mut aliases = PhpUseAliases::default();
            let mut cursor = scope.start;
            for event in scope.events {
                let context = PhpFileContext {
                    namespace: scope.namespace.clone(),
                    aliases: aliases.clone(),
                };
                segments.push(PhpContextSegment {
                    start: cursor,
                    end: event.end,
                    context,
                });
                aliases.extend(event.aliases);
                cursor = event.end;
            }
            segments.push(PhpContextSegment {
                start: cursor,
                end: scope.end,
                context: PhpFileContext {
                    namespace: scope.namespace,
                    aliases,
                },
            });
        }
        Some(Self {
            source_len: source.len(),
            segments,
            merged_aliases,
        })
    }

    /// Return the exact namespace/import context visible at `byte`.
    ///
    /// An import becomes visible only after its complete declaration. A byte at
    /// the import itself therefore does not see that import; import-hit callers
    /// should interpret the declaration node with [`php_use_aliases_from_node`]
    /// directly.
    pub fn context_at(&self, byte: usize) -> &PhpFileContext {
        let byte = byte.min(self.source_len);
        let segment_index = self
            .segments
            .partition_point(|segment| segment.start <= byte)
            .saturating_sub(1);
        let segment = self
            .segments
            .get(segment_index)
            .filter(|segment| byte < segment.end)
            .or_else(|| self.segments.last())
            .expect("a PHP context index always has at least one segment");
        &segment.context
    }

    /// Return aliases that can be used as a conservative whole-file summary.
    ///
    /// A local name whose structured bindings disagree between namespace
    /// scopes is omitted from the exact alias maps. Such a name cannot safely
    /// be interpreted without a byte position. The typed target iterators on
    /// the returned value retain all distinct target identities for conservative
    /// candidate admission without leaking an ambiguous binding into exact
    /// resolution (and may repeat a target that is also present in a map).
    pub fn merged_aliases(&self) -> PhpUseAliases {
        self.merged_aliases.clone()
    }
}

impl PhpUseAliases {
    fn merge_conservative(
        &mut self,
        other: &Self,
        ambiguous_type_locals: &mut HashSet<String>,
        ambiguous_function_locals: &mut HashSet<String>,
        ambiguous_const_locals: &mut HashSet<String>,
    ) {
        self.ambiguous_type_targets
            .extend(other.ambiguous_type_targets.iter().cloned());
        self.ambiguous_function_targets
            .extend(other.ambiguous_function_targets.iter().cloned());
        self.ambiguous_const_targets
            .extend(other.ambiguous_const_targets.iter().cloned());
        merge_alias_map_conservative(
            &mut self.type_aliases,
            &other.type_aliases,
            &mut self.ambiguous_type_targets,
            ambiguous_type_locals,
        );
        merge_alias_map_conservative(
            &mut self.function_aliases,
            &other.function_aliases,
            &mut self.ambiguous_function_targets,
            ambiguous_function_locals,
        );
        merge_alias_map_conservative(
            &mut self.const_aliases,
            &other.const_aliases,
            &mut self.ambiguous_const_targets,
            ambiguous_const_locals,
        );
    }
}

fn merge_alias_map_conservative(
    target: &mut HashMap<String, String>,
    incoming: &HashMap<String, String>,
    ambiguous_targets: &mut HashSet<String>,
    ambiguous_locals: &mut HashSet<String>,
) {
    for (local, imported) in incoming {
        if ambiguous_locals.contains(local) {
            ambiguous_targets.insert(imported.clone());
            continue;
        }
        match target.get(local) {
            Some(existing) if existing != imported => {
                ambiguous_targets.insert(existing.clone());
                ambiguous_targets.insert(imported.clone());
                target.remove(local);
                ambiguous_locals.insert(local.clone());
            }
            Some(_) => {}
            None => {
                target.insert(local.clone(), imported.clone());
            }
        }
    }
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

fn php_alias_events_from_children(
    parent: Node<'_>,
    start: usize,
    end: usize,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<Vec<PhpAliasEvent>> {
    let mut events = Vec::new();
    let mut cursor = parent.walk();
    for child in parent.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if child.start_byte() < start || child.end_byte() > end {
            continue;
        }
        if child.kind() != "namespace_use_declaration" {
            continue;
        }
        let aliases = php_use_aliases_from_node(child, source, step)?;
        events.push(PhpAliasEvent {
            end: child.end_byte(),
            aliases,
        });
    }
    Some(events)
}

/// Builds the PHP namespace/import context visible at `byte` from a complete
/// structured index. `step` is honored during the whole index build; a
/// cancellation never returns a partially collected alias map.
pub fn php_file_context_from_tree_at(
    root: Node<'_>,
    source: &str,
    byte: usize,
    mut step: impl FnMut() -> bool,
) -> Option<PhpFileContext> {
    php_file_context_at_byte(root, source, byte, &mut step)
}

fn php_file_context_at_byte(
    root: Node<'_>,
    source: &str,
    byte: usize,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpFileContext> {
    let byte = byte.min(source.len());
    let mut namespace = String::new();
    let mut aliases = PhpUseAliases::default();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if child.start_byte() > byte {
            break;
        }
        if child.kind() == "namespace_definition" {
            let child_end = child.end_byte();
            let child_namespace = match child.child_by_field_name("name") {
                Some(name) => php_path_from_node(name, source, step)?,
                None => String::new(),
            };
            if let Some(body) = child.child_by_field_name("body") {
                if byte < body.start_byte() {
                    break;
                }
                if byte < body.end_byte() {
                    return Some(PhpFileContext {
                        namespace: child_namespace,
                        aliases: php_aliases_in_body_at(body, source, byte, step)?,
                    });
                }
                namespace.clear();
                aliases = PhpUseAliases::default();
            } else if byte < child_end {
                break;
            } else {
                namespace = child_namespace;
                aliases = PhpUseAliases::default();
            }
            continue;
        }
        if child.kind() == "namespace_use_declaration" {
            if child.start_byte() >= byte || child.end_byte() > byte {
                break;
            }
            let parsed = php_use_aliases_from_node(child, source, step)?;
            aliases.extend(parsed);
        }
    }
    Some(PhpFileContext { namespace, aliases })
}

fn php_aliases_in_body_at(
    body: Node<'_>,
    source: &str,
    byte: usize,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpUseAliases> {
    let mut aliases = PhpUseAliases::default();
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if child.start_byte() >= byte || child.end_byte() > byte {
            break;
        }
        if child.kind() == "namespace_use_declaration" {
            aliases.extend(php_use_aliases_from_node(child, source, step)?);
        }
    }
    Some(aliases)
}

/// Interpret one tree-sitter `namespace_use_declaration` node.
///
/// This is the canonical PHP import interpreter. Callers must provide the
/// declaration node from a complete PHP parse tree; raw snippets are routed
/// through [`parse_php_use_aliases_by_kind`] instead.
pub fn php_use_aliases_from_node(
    declaration: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpUseAliases> {
    if !step() {
        return None;
    }
    if declaration.child_by_field_name("type").is_some() && !step() {
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
    if clause.child_by_field_name("type").is_some() && !step() {
        return None;
    }
    let kind = match php_use_kind(clause.child_by_field_name("type"), source) {
        PhpUseKind::Type if default_kind != PhpUseKind::Type => default_kind,
        kind => kind,
    };
    aliases.insert(kind, local, imported);
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

pub fn parse_php_use_aliases_from_source(source: &str) -> PhpUseAliases {
    let Some(tree) = parse_php_tree(source) else {
        return PhpUseAliases::default();
    };
    let Some(index) = PhpFileContextIndex::from_tree(tree.root_node(), source, || true) else {
        return PhpUseAliases::default();
    };
    index.merged_aliases()
}

pub fn parse_php_use_aliases_by_kind(raw: &str) -> PhpUseAliases {
    let complete_source = format!("<?php\n{raw}\n");
    parse_php_use_aliases_from_source(&complete_source)
}

pub fn parse_php_use_aliases(raw: &str) -> HashMap<String, String> {
    parse_php_use_aliases_by_kind(raw).merged()
}

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
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

pub(crate) fn module_constant_fq(fq_name: &str) -> String {
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

#[cfg(test)]
mod source_alias_tests {
    use super::{
        PhpFileContextIndex, PhpUseAliases, parse_php_tree, parse_php_use_aliases,
        parse_php_use_aliases_by_kind, parse_php_use_aliases_from_source,
        php_file_context_from_tree_at,
    };
    use brokk_bifrost_core::hash::HashSet;

    /// Found while building the PHP builtin declaration pack (issue #2374).
    ///
    #[test]
    fn php_use_alias_inside_a_braced_namespace_is_structured() {
        let source = concat!(
            "<?php\n",
            "\n",
            "namespace {\n",
            "    use Vendor\\Widget\\Renderable as Renderer;\n",
            "\n",
            "    class Widget implements Renderer {}\n",
            "}\n",
        );

        let aliases = parse_php_use_aliases_from_source(source).merged();

        assert_eq!(
            aliases.get("Renderer").map(String::as_str),
            Some("Vendor.Widget.Renderable"),
            "an indented use binding must resolve like a top-level one: {aliases:#?}"
        );
    }

    #[test]
    fn grouped_mixed_imports_keep_type_function_and_const_maps_separate() {
        let aliases = parse_php_use_aliases_by_kind(
            "use Vendor\\Package\\{Target, Helper as Tool, function run, const LIMIT};",
        );
        assert_eq!(aliases.type_aliases["Target"], "Vendor.Package.Target");
        assert_eq!(aliases.type_aliases["Tool"], "Vendor.Package.Helper");
        assert_eq!(aliases.function_aliases["run"], "Vendor.Package.run");
        assert_eq!(aliases.const_aliases["LIMIT"], "Vendor.Package.LIMIT");
        assert!(!aliases.function_aliases.contains_key("Target"));
        assert!(!aliases.const_aliases.contains_key("Tool"));
    }

    #[test]
    fn comments_strings_and_trait_use_are_not_imports() {
        let aliases = parse_php_use_aliases_from_source(
            r#"<?php
            // use Fake\Comment as Commented;
            $text = 'use Fake\\String as Stringed;';
            trait T { use TraitFeature; }
            use Real\Thing as Thing;
            "#,
        );
        assert_eq!(aliases.type_aliases["Thing"], "Real.Thing");
        assert!(!aliases.merged().contains_key("Commented"));
        assert!(!aliases.merged().contains_key("Stringed"));
        assert!(!aliases.merged().contains_key("TraitFeature"));
    }

    #[test]
    fn contexts_partition_braced_namespaces_and_all_alias_kinds() {
        let source = concat!(
            "<?php\n",
            "namespace First {\n",
            "    use Vendor\\First\\Thing as Shared;\n",
            "    use function Vendor\\First\\run as shared_run;\n",
            "    use const Vendor\\First\\FLAG as SHARED_FLAG;\n",
            "    class A {}\n",
            "}\n",
            "namespace Second {\n",
            "    use Vendor\\Second\\Thing as Shared;\n",
            "    use function Vendor\\Second\\run as shared_run;\n",
            "    use const Vendor\\Second\\FLAG as SHARED_FLAG;\n",
            "    class B {}\n",
            "}\n",
            "namespace Third {\n",
            "    class C {}\n",
            "}\n",
        );
        let tree = parse_php_tree(source).expect("PHP source parses");
        let index = PhpFileContextIndex::from_tree(tree.root_node(), source, || true)
            .expect("index builds");
        let first = index.context_at(source.find("class A").expect("A"));
        assert_eq!(first.namespace, "First");
        assert_eq!(first.aliases.type_aliases["Shared"], "Vendor.First.Thing");
        assert_eq!(
            first.aliases.function_aliases["shared_run"],
            "Vendor.First.run"
        );
        assert_eq!(
            first.aliases.const_aliases["SHARED_FLAG"],
            "Vendor.First.FLAG"
        );
        let second = index.context_at(source.find("class B").expect("B"));
        assert_eq!(second.namespace, "Second");
        assert_eq!(second.aliases.type_aliases["Shared"], "Vendor.Second.Thing");
        assert_eq!(
            second.aliases.function_aliases["shared_run"],
            "Vendor.Second.run"
        );
        assert_eq!(
            second.aliases.const_aliases["SHARED_FLAG"],
            "Vendor.Second.FLAG"
        );
        let third = index.context_at(source.find("class C").expect("C"));
        assert_eq!(third.namespace, "Third");
        assert!(!third.aliases.type_aliases.contains_key("Shared"));
        assert!(!third.aliases.function_aliases.contains_key("shared_run"));
        assert!(!third.aliases.const_aliases.contains_key("SHARED_FLAG"));

        let merged = index.merged_aliases();
        let merged_targets = merged.type_targets().cloned().collect::<HashSet<_>>();
        assert!(merged_targets.contains("Vendor.First.Thing"));
        assert!(merged_targets.contains("Vendor.Second.Thing"));
        assert!(!merged.type_aliases.contains_key("Shared"));
        let merged_function_targets = merged.function_targets().cloned().collect::<HashSet<_>>();
        assert!(merged_function_targets.contains("Vendor.First.run"));
        assert!(merged_function_targets.contains("Vendor.Second.run"));
        assert!(!merged.function_aliases.contains_key("shared_run"));
        let merged_const_targets = merged.const_targets().cloned().collect::<HashSet<_>>();
        assert!(merged_const_targets.contains("Vendor.First.FLAG"));
        assert!(merged_const_targets.contains("Vendor.Second.FLAG"));
        assert!(!merged.const_aliases.contains_key("SHARED_FLAG"));
    }

    #[test]
    fn contexts_partition_unbraced_namespaces() {
        let source = concat!(
            "<?php\n",
            "namespace First;\n",
            "use Vendor\\First\\Thing as Shared;\n",
            "class A {}\n",
            "namespace Second;\n",
            "use Vendor\\Second\\Thing as Shared;\n",
            "class B {}\n",
            "namespace Third;\n",
            "class C {}\n",
        );
        let tree = parse_php_tree(source).expect("PHP source parses");
        let index = PhpFileContextIndex::from_tree(tree.root_node(), source, || true)
            .expect("index builds");

        let first = index.context_at(source.find("class A").expect("A"));
        assert_eq!(first.namespace, "First");
        assert_eq!(first.aliases.type_aliases["Shared"], "Vendor.First.Thing");
        let second = index.context_at(source.find("class B").expect("B"));
        assert_eq!(second.namespace, "Second");
        assert_eq!(second.aliases.type_aliases["Shared"], "Vendor.Second.Thing");
        let third = index.context_at(source.find("class C").expect("C"));
        assert_eq!(third.namespace, "Third");
        assert!(!third.aliases.type_aliases.contains_key("Shared"));
    }

    #[test]
    fn aliases_are_invisible_before_their_declaration() {
        let source = "<?php\nnamespace N;\nclass Before extends Alias {}\nuse Vendor\\Base as Alias;\nclass After extends Alias {}\n";
        let tree = parse_php_tree(source).expect("PHP source parses");
        let index = PhpFileContextIndex::from_tree(tree.root_node(), source, || true)
            .expect("index builds");
        let before = index.context_at(source.find("class Before").expect("Before"));
        assert!(!before.aliases.type_aliases.contains_key("Alias"));
        let after = index.context_at(source.find("class After").expect("After"));
        assert_eq!(after.aliases.type_aliases["Alias"], "Vendor.Base");
    }

    #[test]
    fn raw_statement_apis_route_through_complete_php_parse() {
        let aliases = parse_php_use_aliases("use Vendor\\Widget\\Renderable as Renderer;");
        assert_eq!(aliases["Renderer"], "Vendor.Widget.Renderable");
    }

    #[test]
    fn public_alias_map_mutations_are_visible_to_conservative_targets() {
        let mut aliases = PhpUseAliases::default();
        aliases
            .type_aliases
            .insert("Manual".to_string(), "Vendor.Manual".to_string());
        assert!(
            aliases
                .type_targets()
                .any(|target| target == "Vendor.Manual")
        );
    }

    #[test]
    fn context_at_uses_exact_import_boundaries() {
        let source = concat!(
            "<?php\n",
            "namespace First {\n",
            "    use Vendor\\One as One;\n",
            "    class A {}\n",
            "}\n",
            "namespace Second {\n",
            "    use Vendor\\Two as Two;\n",
            "    class B {}\n",
            "}\n",
        );
        let tree = parse_php_tree(source).expect("PHP source parses");
        let index = PhpFileContextIndex::from_tree(tree.root_node(), source, || true)
            .expect("index builds");
        let first_use = source.find("use Vendor").expect("first import");
        let first_end = source[first_use..]
            .find(';')
            .map(|offset| first_use + offset + 1)
            .expect("first import terminator");
        assert!(
            !index
                .context_at(first_use)
                .aliases
                .type_aliases
                .contains_key("One")
        );
        assert!(
            !index
                .context_at(first_end - 1)
                .aliases
                .type_aliases
                .contains_key("One")
        );
        assert_eq!(
            index.context_at(first_end).aliases.type_aliases["One"],
            "Vendor.One"
        );

        let second_namespace = source.find("namespace Second").expect("second namespace");
        let second = index.context_at(second_namespace);
        assert_eq!(second.namespace, "Second");
        assert!(!second.aliases.type_aliases.contains_key("One"));
        let second_use = source[second_namespace..]
            .find("use Vendor")
            .map(|offset| second_namespace + offset)
            .expect("second import");
        let second_end = source[second_use..]
            .find(';')
            .map(|offset| second_use + offset + 1)
            .expect("second import terminator");
        assert!(
            !index
                .context_at(second_end - 1)
                .aliases
                .type_aliases
                .contains_key("Two")
        );
        assert_eq!(
            index.context_at(second_end).aliases.type_aliases["Two"],
            "Vendor.Two"
        );
    }

    #[test]
    fn single_byte_context_does_not_scan_irrelevant_suffix_nodes() {
        let mut source = String::from("<?php\nuse Vendor\\Thing as Thing;\nclass Target {}\n");
        for index in 0..128 {
            source.push_str(&format!("class Tail{index} {{}}\n"));
        }
        let tree = parse_php_tree(&source).expect("PHP source parses");
        let target = source.find("class Target").expect("target declaration");
        let mut short_calls = 0usize;
        let context = php_file_context_from_tree_at(tree.root_node(), &source, target, || {
            short_calls += 1;
            short_calls <= 20
        })
        .expect("near-start lookup must fit its cancellation budget");
        assert_eq!(context.aliases.type_aliases["Thing"], "Vendor.Thing");
        assert!(short_calls <= 20);

        let mut full_calls = 0usize;
        assert!(
            PhpFileContextIndex::from_tree(tree.root_node(), &source, || {
                full_calls += 1;
                full_calls <= 20
            })
            .is_none(),
            "the full-file index should exceed the near-start budget"
        );
    }
}
