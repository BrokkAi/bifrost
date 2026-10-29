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
        alias_targets(&self.type_aliases, &self.ambiguous_type_targets)
    }

    /// Function targets represented by this alias summary. The iterator may
    /// repeat a target when it appears in both a public map and the retained
    /// target set.
    pub fn function_targets(&self) -> impl Iterator<Item = &String> {
        alias_targets(&self.function_aliases, &self.ambiguous_function_targets)
    }

    /// Constant targets represented by this alias summary. The iterator may
    /// repeat a target when it appears in both a public map and the retained
    /// target set.
    pub fn const_targets(&self) -> impl Iterator<Item = &String> {
        alias_targets(&self.const_aliases, &self.ambiguous_const_targets)
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

fn alias_targets<'a>(
    aliases: &'a HashMap<String, String>,
    ambiguous_targets: &'a HashSet<String>,
) -> impl Iterator<Item = &'a String> {
    aliases.values().chain(ambiguous_targets.iter())
}

#[derive(Debug, Clone)]
pub struct PhpFileContext {
    pub namespace: String,
    pub aliases: PhpUseAliases,
}

/// The namespace kind attached to one PHP `use` clause.
pub type PhpImportKind = PhpUseKind;

/// One parser-derived PHP import clause.
///
/// `target` and `alias` retain the exact AST nodes that spell the imported
/// binding and local name. `path_segments` carries the complete path,
/// including a grouped declaration's prefix.
#[derive(Debug, Clone)]
pub struct PhpImport<'tree> {
    pub target: Option<Node<'tree>>,
    pub alias: Option<Node<'tree>>,
    pub path_segments: Vec<String>,
    pub kind: PhpImportKind,
    pub is_global: bool,
}

/// The single structured interpretation of one PHP `namespace_use_declaration`.
#[derive(Debug, Clone)]
pub struct PhpImportSyntax<'tree> {
    pub aliases: PhpUseAliases,
    pub imports: Vec<PhpImport<'tree>>,
}

#[derive(Debug, Clone)]
struct PhpAliasEvent {
    end: usize,
    aliases: PhpUseAliases,
}

/// Read one `use` declaration into its activation boundary and alias maps.
fn php_alias_event(
    declaration: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpAliasEvent> {
    let bindings = php_use_bindings_from_node(declaration, source, step)?;
    let aliases = php_use_aliases_from_bindings(&bindings);
    Some(PhpAliasEvent {
        end: declaration.end_byte(),
        aliases,
    })
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
                        scope
                            .events
                            .push(php_alias_event(child, source, &mut step)?);
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
                    global_events.push(php_alias_event(child, source, &mut step)?);
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

/// Which declaration space a `use` clause binds in. PHP keeps types,
/// functions and constants apart, and `use function` / `use const` say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpUseKind {
    Type,
    Function,
    Const,
}

/// One local name a `use` clause binds, with the exact token that spells it.
///
/// The alias maps above answer "what does this local name mean"; this answers
/// "which token introduced it, and where". The lexical-environment layer joins
/// an import binding to its occurrence row by that token's byte span, so the
/// span is read from the tree here rather than recovered from the snippet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpUseBinding {
    pub kind: PhpUseKind,
    /// The name introduced into the enclosing namespace scope.
    pub local: String,
    /// The absolute target path, group prefix already applied.
    pub segments: Vec<String>,
    /// Byte span of the token that spells `local`: the `as` alias when the
    /// clause renames, the tail segment of the imported path otherwise.
    pub binder_start: usize,
    pub binder_end: usize,
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
        events.push(php_alias_event(child, source, step)?);
    }
    Some(events)
}

/// Interpret one PHP `namespace_use_declaration` directly from its syntax tree.
///
/// The returned leaves include malformed clauses with no recoverable target.
/// Those leaves carry no path or alias-map entry, but preserve the declaration
/// identity for bounded producers. Every successful path and alias is read from
/// parser nodes; this function never scans source text.
pub fn parse_php_import_syntax<'tree>(
    declaration: Node<'tree>,
    source: &str,
) -> PhpImportSyntax<'tree> {
    assert_eq!(
        declaration.kind(),
        "namespace_use_declaration",
        "PHP import syntax must start at a namespace_use_declaration"
    );
    parse_php_import_syntax_bounded(declaration, source, &mut || true)
        .expect("unbounded PHP import syntax interpretation cannot stop")
}

fn parse_php_import_syntax_bounded<'tree>(
    declaration: Node<'tree>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpImportSyntax<'tree>> {
    if !step() {
        return None;
    }
    if declaration.child_by_field_name("type").is_some() && !step() {
        return None;
    }
    let default_kind = php_use_kind(declaration.child_by_field_name("type"), source);
    let body = declaration.child_by_field_name("body");
    let (prefix, prefix_is_global) = if let Some(body) = body {
        let mut cursor = declaration.walk();
        let mut prefix = Vec::new();
        let mut is_global = false;
        for child in declaration.named_children(&mut cursor) {
            if !step() {
                return None;
            }
            if child.id() == body.id() {
                continue;
            }
            if child.kind() == "namespace_name" {
                prefix = php_path_segments(child, source, step)?;
                is_global = php_path_has_leading_separator(child, step)?;
                break;
            }
        }
        (prefix, is_global)
    } else {
        (Vec::new(), false)
    };

    let clause_parent = body.unwrap_or(declaration);
    let mut aliases = PhpUseAliases::default();
    let mut imports = Vec::new();
    let mut cursor = clause_parent.walk();
    for clause in clause_parent.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if clause.kind() != "namespace_use_clause" {
            continue;
        }
        let alias = clause.child_by_field_name("alias");
        let path_node = php_use_clause_target(clause, alias, step)?;
        let target = path_node.and_then(php_path_tail_node);
        let mut path_segments = if let Some(path_node) = path_node {
            php_path_segments(path_node, source, step)?
        } else {
            Vec::new()
        };
        if !prefix.is_empty() {
            let mut full = Vec::with_capacity(prefix.len() + path_segments.len());
            full.extend(prefix.iter().cloned());
            full.append(&mut path_segments);
            path_segments = full;
        }
        let kind = match clause.child_by_field_name("type") {
            Some(node) => php_use_kind(Some(node), source),
            None => default_kind,
        };
        let target_is_global = if let Some(path_node) = path_node {
            php_path_has_leading_separator(path_node, step)?
        } else {
            false
        };
        let import = PhpImport {
            target,
            alias,
            path_segments,
            kind,
            is_global: prefix_is_global || target_is_global,
        };
        add_php_import_alias(&import, source, &mut aliases, step)?;
        imports.push(import);
    }

    if imports.is_empty() {
        imports.push(PhpImport {
            target: None,
            alias: None,
            path_segments: Vec::new(),
            kind: default_kind,
            is_global: prefix_is_global,
        });
    }
    Some(PhpImportSyntax { aliases, imports })
}

fn php_use_clause_target<'tree>(
    clause: Node<'tree>,
    alias: Option<Node<'tree>>,
    step: &mut impl FnMut() -> bool,
) -> Option<Option<Node<'tree>>> {
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if alias.is_some_and(|alias| alias.id() == child.id()) {
            continue;
        }
        if matches!(child.kind(), "name" | "qualified_name" | "namespace_name") {
            return Some(Some(child));
        }
    }
    Some(None)
}

fn add_php_import_alias(
    import: &PhpImport<'_>,
    source: &str,
    aliases: &mut PhpUseAliases,
    step: &mut impl FnMut() -> bool,
) -> Option<()> {
    let Some(last) = import.path_segments.last() else {
        return Some(());
    };
    let local = if let Some(alias) = import.alias {
        if !step() {
            return None;
        }
        php_leaf_text(alias, source)?.to_string()
    } else {
        last.clone()
    };
    aliases.insert(import.kind, local, import.path_segments.join("."));
    Some(())
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

/// Interpret one tree-sitter `namespace_use_declaration` node, one clause at a
/// time.
///
/// This is the canonical PHP import interpreter. Callers must provide the
/// declaration node from a complete PHP parse tree; raw snippets are routed
/// through [`parse_php_use_aliases_by_kind`] instead.
pub fn php_use_bindings_from_node(
    declaration: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<Vec<PhpUseBinding>> {
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
    let mut bindings = Vec::new();
    let mut cursor = clause_parent.walk();
    for clause in clause_parent.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if clause.kind() != "namespace_use_clause" {
            continue;
        }
        if let Some(binding) = php_use_clause_binding(clause, source, &prefix, default_kind, step)?
        {
            bindings.push(binding);
        }
    }
    Some(bindings)
}

/// The alias maps one `namespace_use_declaration` contributes.
///
/// This is [`php_use_bindings_from_node`] collapsed onto the three
/// local-name-to-target maps; both readers interpret the same clauses through
/// [`php_use_clause_binding`], so an alias and its binder token can never
/// disagree about what a clause binds.
pub fn php_use_aliases_from_node(
    declaration: Node<'_>,
    source: &str,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpUseAliases> {
    let bindings = php_use_bindings_from_node(declaration, source, step)?;
    Some(php_use_aliases_from_bindings(&bindings))
}

fn php_use_aliases_from_bindings(bindings: &[PhpUseBinding]) -> PhpUseAliases {
    let mut aliases = PhpUseAliases::default();
    for binding in bindings {
        aliases.insert(
            binding.kind,
            binding.local.clone(),
            binding.segments.join("."),
        );
    }
    aliases
}

/// The token that spells the last segment of a written path.
fn php_path_tail_node<'tree>(path: Node<'tree>) -> Option<Node<'tree>> {
    let mut tail = None;
    let mut stack = vec![path];
    while let Some(current) = stack.pop() {
        if current.kind() == "name" {
            tail = Some(current);
            continue;
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    tail
}

/// Interpret one `namespace_use_clause`.
///
/// The outer `None` aborts the whole declaration, which is what cancellation
/// and an unreadable path did before; the inner `None` is a clause that binds
/// nothing and leaves its siblings alone.
fn php_use_clause_binding(
    clause: Node<'_>,
    source: &str,
    prefix: &[String],
    default_kind: PhpUseKind,
    step: &mut impl FnMut() -> bool,
) -> Option<Option<PhpUseBinding>> {
    let alias_node = clause.child_by_field_name("alias");
    let mut imported_node = None;
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if !step() {
            return None;
        }
        if alias_node.is_some_and(|alias| alias.id() == child.id()) {
            continue;
        }
        if matches!(child.kind(), "name" | "qualified_name" | "namespace_name") {
            imported_node = Some(child);
            break;
        }
    }
    let Some(imported_node) = imported_node else {
        return Some(None);
    };
    let mut imported = php_path_segments(imported_node, source, step)?;
    if imported.is_empty() {
        return Some(None);
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
    let binder = match alias_node {
        Some(alias) => alias,
        None => php_path_tail_node(imported_node)?,
    };
    if clause.child_by_field_name("type").is_some() && !step() {
        return None;
    }
    let kind = match php_use_kind(clause.child_by_field_name("type"), source) {
        PhpUseKind::Type if default_kind != PhpUseKind::Type => default_kind,
        kind => kind,
    };
    Some(Some(PhpUseBinding {
        kind,
        local,
        segments: imported,
        binder_start: binder.start_byte(),
        binder_end: binder.end_byte(),
    }))
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
/// resolver where no parser node exists. Each stored union arm is classified
/// independently. A union with a dynamic arm is dynamic:
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
            // Lowercase builtins are primitive_type; uppercase spellings can
            // be named_type wrappers over name in the pinned grammar.
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
                if !matches!(
                    child.kind(),
                    "name" | "qualified_name" | "relative_name" | "named_type"
                ) {
                    return None;
                }
                node = child;
            }
            "name"
            | "qualified_name"
            | "relative_name"
            | "namespace_name"
            | "fully_qualified_name" => break,
            "union_type"
            | "intersection_type"
            | "disjunctive_normal_form_type"
            | "primitive_type"
            | "bottom_type" => return None,
            _ => return None,
        }
    }

    let path = php_structured_path(node, source, &mut step)?;
    // Uppercase builtin spellings can parse as named_type over name.
    // They still name builtins, never nominal owners in this namespace.
    if !path.absolute
        && !path.namespace_relative
        && let [only] = path.segments.as_slice()
        && php_non_nominal_type_name(only)
    {
        return None;
    }
    resolve_php_structured_path(path, ctx, &mut step)
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
        push_unique_php_type_arm(&mut arms, arm);
    }
    php_capped_type_arms(arms)
}

/// The `null` arm is a primitive or, for mixed/uppercase spellings, a named type.
fn php_is_null_type_node(mut node: Node<'_>, source: &str) -> bool {
    while node.kind() == "named_type" {
        let Some(child) = php_only_named_child(node, &mut || true) else {
            return false;
        };
        node = child;
    }
    matches!(node.kind(), "primitive_type" | "name")
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
        "name" | "qualified_name" | "relative_name" | "namespace_name" | "fully_qualified_name"
    ) {
        return None;
    }
    let path = php_structured_path(node, source, &mut step)?;
    resolve_php_structured_callable(
        path,
        ctx,
        |name| php_case_insensitive_alias(&ctx.aliases.function_aliases, name),
        &mut step,
    )
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
        "name" | "qualified_name" | "relative_name" | "namespace_name" | "fully_qualified_name"
    ) {
        return None;
    }
    let path = php_structured_path(node, source, &mut step)?;
    let public = resolve_php_structured_callable(
        path,
        ctx,
        |name| ctx.aliases.const_aliases.get(name),
        &mut step,
    )?;
    if !step() {
        return None;
    }
    Some(php_constant_candidates(
        public.primary,
        public.global_fallback,
    ))
}

fn php_constant_candidates(
    primary: String,
    global_fallback: Option<String>,
) -> PhpCallableCandidates {
    let primary = module_constant_fq(&primary);
    match global_fallback {
        Some(global) => PhpCallableCandidates::shadowing(primary, module_constant_fq(&global)),
        None => PhpCallableCandidates::exact(primary),
    }
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
    let mut segments = php_path_segments(node, source, step)?;
    if segments.is_empty() {
        return None;
    }
    let namespace_relative = !absolute
        && (node.kind() == "relative_name"
            || (segments[0].eq_ignore_ascii_case("namespace") && segments.len() > 1));
    if node.kind() != "relative_name" && namespace_relative {
        segments.remove(0);
    }
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
    step: &mut impl FnMut() -> bool,
) -> Option<String> {
    let segments = path.segments.as_slice();
    let first = segments.first()?;
    if !path.absolute
        && !path.namespace_relative
        && segments.len() == 1
        && matches!(
            first.to_ascii_lowercase().as_str(),
            "self" | "static" | "parent"
        )
    {
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
    if let Some(imported) = php_case_insensitive_alias(&ctx.aliases.type_aliases, first) {
        return php_join_structured_segments(imported, &segments[1..], step);
    }
    php_join_structured_segments(&ctx.namespace, segments, step)
}

/// [`resolve_php_structured_path`] plus PHP's global-namespace fallback.
///
/// The base helper is shared with TYPE resolution, where PHP has no such
/// fallback, so the extra candidate is added here -- on the function and
/// constant entry points -- rather than in the shared walk (#1866).
fn resolve_php_structured_callable<'a>(
    path: PhpStructuredPath,
    ctx: &'a PhpFileContext,
    lookup: impl Fn(&str) -> Option<&'a String>,
    step: &mut impl FnMut() -> bool,
) -> Option<PhpCallableCandidates> {
    if !step() {
        return None;
    }
    if path.absolute || path.namespace_relative || path.segments.len() > 1 {
        return resolve_php_structured_path(path, ctx, step).map(PhpCallableCandidates::exact);
    }
    let name = path.segments.first()?;
    if let Some(imported) = lookup(name) {
        return Some(PhpCallableCandidates::exact(imported.clone()));
    }
    let primary = php_join_structured_segments(&ctx.namespace, &path.segments, step)?;
    Some(if ctx.namespace.is_empty() {
        PhpCallableCandidates::exact(primary)
    } else {
        PhpCallableCandidates::shadowing(primary, name.clone())
    })
}

// Preserve source spellings in public/import facts. PHP compares class and
// function aliases without ASCII case; constants use their own exact map.
fn php_case_insensitive_alias<'a>(
    aliases: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a String> {
    aliases
        .iter()
        .find_map(|(local, target)| local.eq_ignore_ascii_case(name).then_some(target))
}

fn php_non_nominal_type_name(name: &str) -> bool {
    [
        "int", "float", "string", "bool", "array", "callable", "iterable", "void", "never", "true",
        "false", "null", "object", "mixed",
    ]
    .iter()
    .any(|builtin| name.eq_ignore_ascii_case(builtin))
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
    brokk_bifrost_core::analyzer::common::try_node_source_text(node, source).map(str::trim)
}

/// Collect a conservative whole-file alias summary from an already parsed tree.
/// Scoped aliases are merged through the lexical context index, retaining all
/// distinct targets when one local name is reused in different namespaces.
pub fn php_use_aliases_from_tree(root: Node<'_>, source: &str) -> PhpUseAliases {
    PhpFileContextIndex::from_tree(root, source, || true)
        .map(|index| index.merged_aliases())
        .unwrap_or_default()
}

pub fn parse_php_use_aliases_from_source(source: &str) -> PhpUseAliases {
    let Some(tree) = parse_php_tree(source) else {
        return PhpUseAliases::default();
    };
    php_use_aliases_from_tree(tree.root_node(), source)
}

pub fn parse_php_use_aliases_by_kind(raw: &str) -> PhpUseAliases {
    let complete_source = format!("<?php\n{raw}\n");
    parse_php_use_aliases_from_source(&complete_source)
}

pub fn parse_php_use_aliases(raw: &str) -> HashMap<String, String> {
    parse_php_use_aliases_by_kind(raw).merged()
}

/// Parse PHP source with the bundled Tree-sitter grammar.
pub fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .expect("failed to load php parser");
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
/// Stored signatures are parsed with the same grammar as source declarations;
/// the node resolver owns unions, nullable types, and non-nominal rejection.
pub fn resolve_php_type_arms(raw: &str, ctx: &PhpFileContext) -> Vec<String> {
    let source = format!("<?php function __bifrost_type({raw} $value) {{}}");
    let Some(tree) = parse_php_tree(&source) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }
    let Some(function) = tree.root_node().named_child(1) else {
        return Vec::new();
    };
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let Some(parameter) = parameters.named_child(0) else {
        return Vec::new();
    };
    let Some(ty) = parameter.child_by_field_name("type") else {
        return Vec::new();
    };
    resolve_php_type_node_arms(ty, &source, ctx, || true)
}

fn php_capped_type_arms(arms: Vec<String>) -> Vec<String> {
    if arms.len() > PHP_MAX_TYPE_ARMS {
        return Vec::new();
    }
    arms
}

fn push_unique_php_type_arm(arms: &mut Vec<String>, arm: String) {
    if !arms.contains(&arm) {
        arms.push(arm);
    }
}

pub fn resolve_php_function(raw: &str, ctx: &PhpFileContext) -> Option<PhpCallableCandidates> {
    let source = format!("<?php {raw}();");
    let tree = parse_php_tree(&source)?;
    if tree.root_node().has_error() {
        return None;
    }
    let statement = tree.root_node().named_child(1)?;
    let call = statement.named_child(0)?;
    let name = call.child_by_field_name("function")?;
    resolve_php_function_node(name, &source, ctx, || true)
}

pub fn resolve_php_constant(raw: &str, ctx: &PhpFileContext) -> Option<PhpCallableCandidates> {
    let source = format!("<?php {raw};");
    let tree = parse_php_tree(&source)?;
    if tree.root_node().has_error() {
        return None;
    }
    let statement = tree.root_node().named_child(1)?;
    resolve_php_constant_node(statement.named_child(0)?, &source, ctx, || true)
}

/// Convert a public PHP constant name to its declaration identity. Every
/// caller supplies a public name; a real namespace may itself be _module_.
pub(crate) fn module_constant_fq(fq_name: &str) -> String {
    if let Some((namespace, name)) = fq_name.rsplit_once('.') {
        format!("{namespace}._module_.{name}")
    } else {
        format!("_module_.{fq_name}")
    }
}

#[cfg(test)]
mod source_alias_tests {
    use super::{
        PhpFileContextIndex, PhpUseAliases, parse_php_tree, parse_php_use_aliases,
        parse_php_use_aliases_by_kind, parse_php_use_aliases_from_source,
        php_file_context_from_tree_at, resolve_php_type_node,
    };
    use brokk_bifrost_core::hash::HashSet;
    use brokk_bifrost_test_macros::hardwon;

    /// Found while building the PHP builtin declaration pack (issue #2374).
    ///
    #[test]
    #[hardwon("#3026: imports inside a braced namespace were lost by the column-zero scan")]
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
    #[hardwon("#3026: grouped type, function, and constant imports were conflated")]
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
    #[hardwon("#3026: comments, strings, and trait use were mistaken for imports")]
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
    #[hardwon("#3026: aliases leaked across braced namespace and import-kind boundaries")]
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
    #[hardwon("#3026: aliases leaked across unbraced namespace boundaries")]
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
    #[hardwon("#3503: namespace-relative types were truncated or routed through aliases")]
    fn namespace_relative_type_keeps_ast_provenance_and_ignores_aliases() {
        let source = concat!(
            "<?php\n",
            "namespace App;\n",
            "use Vendor\\Model as Model;\n",
            "function make(): namespace\\Model\\Product {}\n",
        );
        let tree = parse_php_tree(source).expect("PHP source parses");
        let mut stack = vec![tree.root_node()];
        let relative = loop {
            let node = stack.pop().expect("namespace-relative type node");
            if node.kind() == "relative_name" {
                break node;
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        };
        let context =
            php_file_context_from_tree_at(tree.root_node(), source, relative.start_byte(), || true)
                .expect("file context");

        assert_eq!(
            resolve_php_type_node(relative, source, &context, || true).as_deref(),
            Some("App.Model.Product")
        );
    }

    #[test]
    #[hardwon("#3026: an import was visible before its source declaration boundary")]
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
    #[hardwon("#3026: an import became visible before its terminating semicolon")]
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
    #[hardwon("#3026: a near-start alias query scanned irrelevant suffix declarations")]
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

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3026: Issue #3026/#3037 fixed alias-map mutations not reaching conservative PHP targets."
    )]
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
}

#[cfg(test)]
mod alias_resolution_regression_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive as find;
    use brokk_bifrost_test_macros::hardwon;

    fn context() -> PhpFileContext {
        PhpFileContext {
            namespace: "N".into(),
            aliases: parse_php_use_aliases_by_kind(
                "use Vendor\\Package as P; use Vendor\\Thing as Alias; use function Vendor\\run as Go; use const Vendor\\FLAG as Flag;",
            ),
        }
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: callable qualifiers and case-insensitive imports resolved incorrectly"
    )]
    fn callable_namespace_and_alias_rules() {
        let ctx = context();
        assert_eq!(resolve_php_type("alias", &ctx), Some("Vendor.Thing".into()));
        for (raw, expected) in [
            ("go", vec!["Vendor.run"]),
            ("P\\run", vec!["Vendor.Package.run"]),
            ("namespace\\run", vec!["N.run"]),
            ("other", vec!["N.other", "other"]),
        ] {
            let source = format!("<?php {raw}();");
            let tree = parse_php_tree(&source).unwrap();
            let call = find(tree.root_node(), "function_call_expression").unwrap();
            let node = call.child_by_field_name("function").unwrap();
            for actual in [
                resolve_php_function(raw, &ctx),
                resolve_php_function_node(node, &source, &ctx, || true),
            ] {
                assert_eq!(
                    actual.unwrap().iter().collect::<Vec<_>>(),
                    expected,
                    "{raw}"
                );
            }
        }
        for (raw, expected) in [
            ("Flag", vec!["Vendor._module_.FLAG"]),
            ("flag", vec!["N._module_.flag", "_module_.flag"]),
            ("P\\FLAG", vec!["Vendor.Package._module_.FLAG"]),
            ("namespace\\FLAG", vec!["N._module_.FLAG"]),
            ("Sub\\FLAG", vec!["N.Sub._module_.FLAG"]),
        ] {
            let source = format!("<?php {raw};");
            let tree = parse_php_tree(&source).unwrap();
            let expression = find(tree.root_node(), "expression_statement")
                .unwrap()
                .named_child(0)
                .unwrap();
            for actual in [
                resolve_php_constant(raw, &ctx),
                resolve_php_constant_node(expression, &source, &ctx, || true),
            ] {
                assert_eq!(
                    actual.unwrap().iter().collect::<Vec<_>>(),
                    expected,
                    "{raw}"
                );
            }
        }
        let global = PhpFileContext {
            namespace: String::new(),
            aliases: PhpUseAliases::default(),
        };
        assert_eq!(
            resolve_php_constant("FLAG", &global)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            ["_module_.FLAG"]
        );
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: global constants acquired duplicate module markers"
    )]
    fn global_constant_identity_has_one_module_scope() {
        let ctx = PhpFileContext {
            namespace: String::new(),
            aliases: PhpUseAliases::default(),
        };
        assert_eq!(
            resolve_php_constant("FLAG", &ctx)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            ["_module_.FLAG"]
        );
        // _module_ is also a legal user namespace. Conversion always adds
        // the synthetic leaf scope; it must not infer syntax from this value.
        for (name, expected) in [
            ("\\_module_\\FLAG", "_module_._module_.FLAG"),
            ("\\N\\_module_\\FLAG", "N._module_._module_.FLAG"),
        ] {
            assert_eq!(
                resolve_php_constant(name, &ctx)
                    .unwrap()
                    .iter()
                    .collect::<Vec<_>>(),
                [expected]
            );
        }
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: raw relative and scalar type arms fabricated nominal owners"
    )]
    fn declared_types_match_grammar_boundary() {
        let ctx = context();
        for (raw, expected) in [
            ("PARENT", vec![]),
            ("SELF", vec![]),
            ("STATIC", vec![]),
            ("A|int", vec![]),
            ("A|INT", vec![]),
            ("A|null", vec!["N.A"]),
            ("A|B|C|D", vec!["N.A", "N.B", "N.C", "N.D"]),
            ("A|B|C|D|E", vec![]),
            ("OBJECT", vec![]),
            ("MIXED", vec![]),
        ] {
            let source = format!("<?php function f({raw} $value) {{}}");
            let tree = parse_php_tree(&source).unwrap();
            let parameter = find(tree.root_node(), "simple_parameter").unwrap();
            let ty = parameter.child_by_field_name("type").unwrap();
            assert_eq!(resolve_php_type_arms(raw, &ctx), expected, "raw {raw}");
            assert_eq!(
                resolve_php_type_node_arms(ty, &source, &ctx, || true),
                expected,
                "node {raw}"
            );
        }
        for (raw, keyword) in [
            ("? object", "object"),
            ("OBJECT", "object"),
            ("MIXED", "mixed"),
        ] {
            assert_eq!(php_dynamic_type_keyword(raw), Some(keyword));
            let source = format!("<?php function f({raw} $value) {{}}");
            let tree = parse_php_tree(&source).unwrap();
            let ty = find(tree.root_node(), "simple_parameter")
                .unwrap()
                .child_by_field_name("type")
                .unwrap();
            assert_eq!(
                php_dynamic_type_keyword_node(ty, &source, || true),
                Some(keyword)
            );
        }
    }

    #[test]
    #[hardwon("#7228: review: uppercase NULL erased nominal union arms")]
    fn nullable_builtin_spellings() {
        let ctx = context();
        for spelling in ["null", "NULL", "NuLl"] {
            let raw = format!("A|{spelling}");
            assert_eq!(resolve_php_type_arms(&raw, &ctx), ["N.A"], "{raw}");
        }
        for builtin in [
            "int", "float", "string", "bool", "array", "callable", "iterable", "void", "never",
            "true", "false", "object", "mixed",
        ] {
            for spelling in [builtin.to_string(), builtin.to_ascii_uppercase()] {
                assert_eq!(resolve_php_type(&spelling, &ctx), None, "{spelling}");
                assert!(
                    resolve_php_type_arms(&format!("A|{spelling}"), &ctx).is_empty(),
                    "{spelling}"
                );
            }
        }
    }

    #[test]
    #[hardwon("#7228: review: relative-scope keywords rejected namespace segments")]
    fn keyword_namespace_segments() {
        let ctx = context();
        for (raw, expected) in [
            (r"\Self\Thing", "Self.Thing"),
            (r"Parent\Thing", "N.Parent.Thing"),
            (r"\Static\Thing", "Static.Thing"),
            (r"namespace\Self\Thing", "N.Self.Thing"),
            (r"\Self", "Self"),
        ] {
            assert_eq!(
                resolve_php_type(raw, &ctx).as_deref(),
                Some(expected),
                "{raw}"
            );
        }
        for raw in ["self", "STATIC", "Parent"] {
            assert_eq!(resolve_php_type(raw, &ctx), None);
        }
    }

    #[test]
    fn import_grammar_and_activation_boundaries() {
        let source = "<?php namespace N { use Vendor\\Thing; use function Vendor\\Pkg\\{run, stop as halt}; use const Vendor\\Pkg\\{FLAG, LIMIT as Cap}; class C {} }";
        let tree = parse_php_tree(source).unwrap();
        let root = tree.root_node();
        let body = find(root, "namespace_definition")
            .unwrap()
            .child_by_field_name("body")
            .unwrap();
        let mut cursor = body.walk();
        let declarations: Vec<_> = body
            .named_children(&mut cursor)
            .filter(|n| n.kind() == "namespace_use_declaration")
            .collect();
        assert_eq!(declarations.len(), 3);
        for declaration in &declarations {
            let syntax =
                parse_php_import_syntax_bounded(*declaration, source, &mut || true).unwrap();
            let bindings = php_use_bindings_from_node(*declaration, source, &mut || true).unwrap();
            assert_eq!(syntax.imports.len(), bindings.len());
            for (import, binding) in syntax.imports.iter().zip(bindings) {
                assert_eq!(import.kind, binding.kind);
                assert_eq!(
                    &source[binding.binder_start..binding.binder_end],
                    binding.local
                );
                assert_eq!(import.path_segments, binding.segments);
                let map = match binding.kind {
                    PhpUseKind::Type => &syntax.aliases.type_aliases,
                    PhpUseKind::Function => &syntax.aliases.function_aliases,
                    PhpUseKind::Const => &syntax.aliases.const_aliases,
                };
                assert_eq!(map.get(&binding.local), Some(&binding.segments.join(".")));
            }
            for byte in [
                declaration.start_byte(),
                declaration.start_byte() + 1,
                declaration.end_byte() - 1,
                declaration.end_byte(),
            ] {
                let ctx = php_file_context_from_tree_at(root, source, byte, || true).unwrap();
                let completed = declarations.iter().filter(|n| n.end_byte() <= byte).count();
                let actual = ctx.aliases.type_aliases.len()
                    + ctx.aliases.function_aliases.len()
                    + ctx.aliases.const_aliases.len();
                assert_eq!(actual, [0, 1, 3, 5][completed], "byte {byte}");
            }
        }
        let aliases = php_use_aliases_from_tree(root, source);
        assert_eq!(aliases.type_aliases["Thing"], "Vendor.Thing");
        assert_eq!(aliases.function_aliases["run"], "Vendor.Pkg.run");
        assert_eq!(aliases.const_aliases["FLAG"], "Vendor.Pkg.FLAG");
        assert_eq!(aliases.merged().len(), 5);
        assert_eq!(aliases.merged()["Cap"], "Vendor.Pkg.LIMIT");
        let ctx = PhpFileContext {
            namespace: "N".into(),
            aliases,
        };
        let candidates = resolve_php_function("missing", &ctx).unwrap();
        for (indexed, expected) in [
            (vec![], "N.missing"),
            (vec!["missing"], "missing"),
            (vec!["N.missing", "missing"], "N.missing"),
        ] {
            assert_eq!(
                candidates.first_indexed(|name| indexed.contains(&name)),
                expected
            );
        }
    }
}
