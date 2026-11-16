//! Byte-keyed lexical projections. No syntax node or tree identity is retained.
use super::*;
use std::ops::ControlFlow;

type ByteKey = (usize, usize);

#[derive(Debug, Clone, Copy)]
struct SyntaxRange {
    bytes: ByteKey,
    kind: &'static str,
}
impl SyntaxRange {
    fn of(node: Node<'_>) -> Self {
        Self {
            bytes: (node.start_byte(), node.end_byte()),
            kind: node.kind(),
        }
    }
}

#[derive(Debug)]
enum IndexedEvent {
    Parameter(SyntaxRange),
    Item(SyntaxRange),
    Import(SyntaxRange, crate::imports::RustUseBinding),
    Unknown,
    Macro(SyntaxRange),
    End,
}

#[derive(Debug)]
struct ScopeEvents {
    syntax: SyntaxRange,
    parent: Option<usize>,
    ancestor_known: bool,
    inner_known: bool,
    prelude_known: Result<(), RustTypeAuthorityUnknown>,
    module_boundary: bool,
    tables: Option<Box<ScopeTables>>,
}

#[derive(Debug, Default)]
struct ScopeTables {
    events: Vec<IndexedEvent>,
    child_indices: Vec<usize>,
    // All positions are needed by the type selector's ambiguity check.
    named: HashMap<String, Vec<usize>>,
    every: Vec<usize>,
    later_opaque: HashMap<ByteKey, bool>,
    foreign: HashMap<ByteKey, HashSet<String>>,
    macros: HashMap<String, Vec<usize>>,
    macro_imports: HashSet<String>,
}

/// The binders a local scope introduces, by name, each list sorted by where
/// the binding becomes visible.
type LocalBindings = HashMap<String, Vec<LocalBinding>>;

#[derive(Debug)]
struct LocalBinding {
    owner: SyntaxRange,
    start: usize,
    end: usize,
}

// Match the walk's pattern classification, including its attribute behavior.
fn local_names<E>(
    pattern: Node<'_>,
    source: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<HashSet<String>, E> {
    let charge: &mut dyn FnMut(usize) -> Result<(), E> = charge;
    let mut names = HashSet::default();
    // One traversal per owner pattern answers every identifier's climb.
    let mut reachable: HashMap<usize, HashSet<usize>> = HashMap::default();
    let mut pending = vec![pattern];
    while let Some(node) = pending.pop() {
        charge(1)?;
        if matches!(node.kind(), "identifier" | "shorthand_field_identifier")
            && pattern_binding_identifier_with(node, charge, &mut |owner, target, charge| {
                let ids = match reachable.entry(owner.id()) {
                    std::collections::hash_map::Entry::Occupied(ids) => ids.into_mut(),
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(pattern_binding_identifier_ids(owner, charge)?)
                    }
                };
                Ok(ids.contains(&target.id()))
            })?
        {
            names.insert(crate::declarations::rust_node_text(node, source).to_owned());
        }
        pending.extend(node.named_children(&mut node.walk()));
    }
    Ok(names)
}

fn prepare_locals<E>(
    scope: Node<'_>,
    source: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<HashMap<String, Vec<LocalBinding>>, E> {
    let mut candidates = Vec::new();
    match scope.kind() {
        "block" => {
            for raw in scope.named_children(&mut scope.walk()) {
                charge(1)?;
                let binding = unwrap_attributes(raw);
                if binding.kind() == "let_declaration"
                    && let Some(pattern) = binding.child_by_field_name("pattern")
                {
                    candidates.push((binding, pattern, binding.end_byte(), usize::MAX));
                }
            }
        }
        "function_item" | "closure_expression" => {
            if let Some(parameters) = scope.child_by_field_name("parameters") {
                for raw in parameters.named_children(&mut parameters.walk()) {
                    charge(1)?;
                    let parameter = unwrap_attributes(raw);
                    candidates.push((
                        parameter,
                        parameter
                            .child_by_field_name("pattern")
                            .unwrap_or(parameter),
                        0,
                        usize::MAX,
                    ));
                }
            }
        }
        "match_arm" | "for_expression" => {
            if let Some(pattern) = scope.child_by_field_name("pattern") {
                let interval = if scope.kind() == "for_expression" {
                    scope
                        .child_by_field_name("body")
                        .map(|body| (body.start_byte(), body.end_byte()))
                } else {
                    Some((pattern.end_byte(), usize::MAX))
                };
                if let Some((start, end)) = interval {
                    candidates.push((scope, pattern, start, end));
                }
            }
        }
        "if_expression" | "while_expression" => {
            if let Some(body) = scope
                .child_by_field_name("consequence")
                .or_else(|| scope.child_by_field_name("body"))
                && let Some(condition) = scope.child_by_field_name("condition")
            {
                let mut pending = vec![condition];
                while let Some(node) = pending.pop() {
                    charge(1)?;
                    if node.kind() == "let_condition" {
                        if let Some(pattern) = node.child_by_field_name("pattern") {
                            candidates.push((node, pattern, body.start_byte(), body.end_byte()));
                        }
                    } else if matches!(node.kind(), "let_chain" | "parenthesized_expression") {
                        pending.extend(node.named_children(&mut node.walk()));
                    }
                }
            }
        }
        _ => {}
    }
    let mut result: HashMap<String, Vec<LocalBinding>> = HashMap::default();
    for (owner, pattern, start, end) in candidates {
        let mut names = local_names(pattern, source, charge)?;
        if owner.kind() == "self_parameter" {
            names.insert("self".into());
        }
        for name in names {
            let entries = result.entry(name).or_default();
            if scope.kind() == "block" || entries.is_empty() {
                entries.push(LocalBinding {
                    owner: SyntaxRange::of(owner),
                    start,
                    end,
                });
            }
        }
    }
    Ok(result)
}

impl std::ops::Deref for ScopeEvents {
    type Target = ScopeTables;
    fn deref(&self) -> &Self::Target {
        static EMPTY: std::sync::OnceLock<ScopeTables> = std::sync::OnceLock::new();
        self.tables
            .as_deref()
            .unwrap_or_else(|| EMPTY.get_or_init(ScopeTables::default))
    }
}

#[derive(Debug, Default)]
pub(super) struct ScopeArena {
    scopes: Vec<ScopeEvents>,
    /// Local scopes that introduce at least one binder, keyed by the scope
    /// node's range and kind. A query climbs the use site's own ancestors, as
    /// the walk does, so its cost follows the site's depth.
    locals: HashMap<(ByteKey, &'static str), LocalBindings>,
}

fn normalized(name: &str) -> &str {
    brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(name)
}

impl ScopeArena {
    // This table is separate from the selection scopes. Local-only scopes must
    // not change the compact selection chains or their bounded proof costs.
    pub(super) fn add_locals<E>(
        &mut self,
        node: Node<'_>,
        source: &str,
        charge: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<(), E> {
        if !matches!(
            node.kind(),
            "source_file"
                | "block"
                | "function_item"
                | "closure_expression"
                | "match_arm"
                | "for_expression"
                | "if_expression"
                | "while_expression"
        ) {
            return Ok(());
        }
        charge(1)?;
        let bindings = prepare_locals(node, source, charge)?;
        if !bindings.is_empty() {
            let syntax = SyntaxRange::of(node);
            self.locals.insert((syntax.bytes, syntax.kind), bindings);
        }
        Ok(())
    }

    pub(super) fn add<F, E, A>(
        &mut self,
        node: Node<'_>,
        parent: Option<usize>,
        source: &str,
        charge: &mut F,
        attributes_known: &mut A,
    ) -> Result<usize, E>
    where
        F: FnMut(usize) -> Result<(), E>,
        A: FnMut(Node<'_>, &mut F) -> Result<bool, E>,
    {
        let syntax = SyntaxRange::of(node);
        let mut scope = ScopeEvents {
            syntax,
            parent,
            ancestor_known: !node.is_error()
                && !node.is_missing()
                && !matches!(node.kind(), "macro_invocation" | "macro_definition")
                && type_site_attributes_unconditional_bounded(node, source, charge)?,
            inner_known: rust_scope_inner_attributes_known_bounded(node, source, charge)?,
            prelude_known: rust_scope_prelude_attributes_bounded(node, source, charge)?,
            module_boundary: rust_lexical_scope_is_module_boundary(node),
            tables: None,
        };
        let mut tables = ScopeTables::default();
        let child_positions: HashMap<_, _> = node
            .named_children(&mut node.walk())
            .enumerate()
            .map(|(index, child)| {
                let child = unwrap_attributes(child);
                ((child.start_byte(), child.end_byte()), index)
            })
            .collect();
        let no_items: HashSet<_> = node
            .named_children(&mut node.walk())
            .map(unwrap_attributes)
            .filter(|item| rust_item_macro_invocation(*item))
            .map(|item| item.id())
            .collect();
        let mut last_child = 0;
        let result = visit_rust_lexical_scope_with_attributes(
            node,
            charge,
            &mut |event, poll| {
                let child_index = match &event {
                    RustLexicalSelectionEvent::Item(item)
                    | RustLexicalSelectionEvent::Import(item, _) => {
                        let index = child_positions[&(item.start_byte(), item.end_byte())];
                        last_child = index + 1;
                        index
                    }
                    RustLexicalSelectionEvent::ScopeEnd => node.named_child_count(),
                    _ => 0,
                };
                let (name, event) = match event {
                    RustLexicalSelectionEvent::Ancestor(_) => unreachable!(),
                    RustLexicalSelectionEvent::Parameter(parameter) => (
                        parameter.child_by_field_name("name").map(|name| {
                            normalized(crate::declarations::rust_node_text(name, source)).to_owned()
                        }),
                        IndexedEvent::Parameter(SyntaxRange::of(parameter)),
                    ),
                    RustLexicalSelectionEvent::Item(item) if rust_item_macro_invocation(item) => {
                        (None, IndexedEvent::Macro(SyntaxRange::of(item)))
                    }
                    RustLexicalSelectionEvent::Item(item) => {
                        if item.kind() == "foreign_mod_item" {
                            let mut names = HashSet::new();
                            if let Some(body) = item.child_by_field_name("body") {
                                for member in body.named_children(&mut body.walk()) {
                                    poll(0)?;
                                    let member = unwrap_attributes(member);
                                    if matches!(
                                        member.kind(),
                                        "function_signature_item" | "static_item"
                                    ) && let Some(name) = member.child_by_field_name("name")
                                    {
                                        names.insert(
                                            crate::declarations::rust_node_text(name, source)
                                                .to_owned(),
                                        );
                                    }
                                }
                            }
                            tables
                                .foreign
                                .insert((item.start_byte(), item.end_byte()), names);
                        }

                        let name = item.child_by_field_name("name").map(|name| {
                            normalized(crate::declarations::rust_node_text(name, source)).to_owned()
                        });
                        // Macro definitions block the flat binding proof for every name.
                        let name = if matches!(item.kind(), "macro_definition" | "foreign_mod_item")
                        {
                            None
                        } else {
                            name
                        };
                        if name.is_none()
                            && !matches!(item.kind(), "macro_definition" | "foreign_mod_item")
                        {
                            return Ok(ControlFlow::<()>::Continue(()));
                        }
                        (name, IndexedEvent::Item(SyntaxRange::of(item)))
                    }
                    RustLexicalSelectionEvent::Import(item, leaf) => {
                        let name = match leaf.binding_name() {
                            RustImportBindingName::Named(name) => {
                                Some(normalized(&name).to_owned())
                            }
                            _ => None,
                        };
                        (
                            name,
                            IndexedEvent::Import(SyntaxRange::of(item), leaf.clone()),
                        )
                    }
                    RustLexicalSelectionEvent::ScopeEnd => (None, IndexedEvent::End),
                };
                let position = tables.events.len();
                if let Some(name) = name {
                    tables.named.entry(name).or_default().push(position);
                } else {
                    tables.every.push(position);
                }
                tables.child_indices.push(child_index);
                tables.events.push(event);
                Ok(ControlFlow::<()>::Continue(()))
            },
            &no_items,
            attributes_known,
            &mut |parameter, charge| {
                type_site_attributes_unconditional_bounded(parameter, source, charge)
            },
            &mut |item, charge| {
                crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
                    item, source, charge,
                )
                .map(|leaves| {
                    leaves
                        .into_iter()
                        .map(|leaf| crate::imports::RustUseBinding::from_import(leaf.import))
                        .collect()
                })
            },
        )?;
        if matches!(result, ControlFlow::Break(RustLexicalSelection::Unknown)) {
            tables.every.push(tables.events.len());
            tables.child_indices.push(last_child);
            tables.events.push(IndexedEvent::Unknown);
        }
        // Only true suffix flags on named items can affect selection. Absence
        // means false; other children still contribute to the suffix verdict.
        if node.kind() == "block" {
            let children: Vec<_> = node.named_children(&mut node.walk()).collect();
            let mut opaque = false;
            for child in children.iter().rev() {
                if child.child_by_field_name("name").is_some() && opaque {
                    tables
                        .later_opaque
                        .insert((child.start_byte(), child.end_byte()), true);
                }
                opaque |= child.has_error()
                    || child.kind() == "macro_invocation"
                    || (child.kind() == "expression_statement"
                        && child
                            .named_child(0)
                            .is_some_and(|n| n.kind() == "macro_invocation"));
            }
        }
        // Macro lookup inspects direct children of every ancestor, not only item scopes.
        for item in node.named_children(&mut node.walk()) {
            if item.kind() == "macro_definition" {
                if let Some(name) = item.child_by_field_name("name") {
                    tables
                        .macros
                        .entry(
                            normalized(crate::declarations::rust_node_text(name, source))
                                .to_owned(),
                        )
                        .or_default()
                        .push(item.end_byte());
                }
            } else if item.kind() == "use_declaration" {
                for import in
                    crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
                        item,
                        source,
                        &mut *charge,
                    )?
                {
                    if !import.import.module_self
                        && let RustImportBindingName::Named(name) = import.import.binding_name()
                    {
                        tables.macro_imports.insert(normalized(&name).to_owned());
                    }
                }
            }
        }
        // A foreign block contributes only to names it actually declares.
        // This avoids replaying unrelated foreign blocks for each value use.
        for position in 0..tables.events.len() {
            if let IndexedEvent::Item(range) = &tables.events[position]
                && range.kind == "foreign_mod_item"
            {
                for name in &tables.foreign[&range.bytes] {
                    tables
                        .named
                        .entry(normalized(name).to_owned())
                        .or_default()
                        .push(position);
                }
            }
        }
        tables.every.retain(|position| !matches!(&tables.events[*position], IndexedEvent::Item(range) if range.kind == "foreign_mod_item"));
        for positions in tables.named.values_mut() {
            positions.sort_unstable();
        }
        if matches!(tables.events.as_slice(), [IndexedEvent::End]) {
            tables.events = Vec::new();
            tables.child_indices = Vec::new();
            tables.every = Vec::new();
        }
        if !tables.events.is_empty()
            || !tables.later_opaque.is_empty()
            || !tables.macros.is_empty()
            || !tables.macro_imports.is_empty()
            || !tables.foreign.is_empty()
        {
            scope.tables = Some(Box::new(tables));
        }
        if scope.tables.is_none()
            && scope.ancestor_known
            && scope.inner_known
            && scope.prelude_known.is_ok()
            && !scope.module_boundary
            && !matches!(node.kind(), "impl_item" | "trait_item")
            && let Some(parent) = parent
        {
            return Ok(parent);
        }
        let id = self.scopes.len();
        self.scopes.push(scope);
        Ok(id)
    }

    fn positions<'a>(&'a self, id: usize, name: &str) -> impl Iterator<Item = usize> + 'a {
        let scope = &self.scopes[id];
        let mut named = scope
            .named
            .get(normalized(name))
            .into_iter()
            .flatten()
            .copied()
            .peekable();
        let mut every = scope.every.iter().copied().peekable();
        std::iter::from_fn(move || {
            if every.peek().is_none() || (named.peek().is_some() && named.peek() < every.peek()) {
                named.next()
            } else {
                every.next()
            }
        })
    }

    // Named AST ranges are nested or disjoint, and construction is preorder.
    // The last scope starting before the site either contains it or has a
    // containing ancestor. Ordinary syntax nodes need no retained entry.
    fn containing(&self, bytes: ByteKey) -> usize {
        let mut id = self
            .scopes
            .partition_point(|scope| scope.syntax.bytes.0 <= bytes.0)
            .checked_sub(1)
            .expect("site starts inside the indexed root");
        while self.scopes[id].syntax.bytes.1 < bytes.1 {
            id = self.scopes[id]
                .parent
                .expect("site ends inside the indexed root");
        }
        id
    }

    fn node_id(&self, node: Node<'_>) -> usize {
        let key = (node.start_byte(), node.end_byte());
        let mut id = self.containing(key);
        while self.scopes[id].syntax.kind != node.kind() {
            id = self.scopes[id]
                .parent
                .expect("retained wrapper is an ancestor");
            debug_assert_eq!(self.scopes[id].syntax.bytes, key);
        }
        id
    }

    pub(super) fn retained_bytes(&self) -> usize {
        use brokk_bifrost_core::allocation_size::allocation_size;
        use brokk_bifrost_core::hash::{allocated_table_slot_bytes, allocated_vec_slot_bytes};
        let string = |value: &String| allocation_size(value.capacity());
        allocated_table_slot_bytes::<(String, Vec<LocalBinding>)>(self.locals.capacity())
            + self
                .locals
                .values()
                .map(|bindings| {
                    allocated_table_slot_bytes::<(String, Vec<LocalBinding>)>(bindings.capacity())
                        + bindings
                            .values()
                            .map(allocated_vec_slot_bytes)
                            .sum::<usize>()
                        + bindings.keys().map(string).sum::<usize>()
                })
                .sum::<usize>()
            + allocated_vec_slot_bytes(&self.scopes)
            + self
                .scopes
                .iter()
                .map(|scope| {
                    scope
                        .tables
                        .as_ref()
                        .map_or(0, |_| allocation_size(std::mem::size_of::<ScopeTables>()))
                        + allocated_vec_slot_bytes(&scope.events)
                        + allocated_vec_slot_bytes(&scope.child_indices)
                        + allocated_table_slot_bytes::<(String, Vec<usize>)>(scope.named.capacity())
                        + scope
                            .named
                            .values()
                            .map(allocated_vec_slot_bytes)
                            .sum::<usize>()
                        + scope.named.keys().map(string).sum::<usize>()
                        + allocated_vec_slot_bytes(&scope.every)
                        + allocated_table_slot_bytes::<(ByteKey, bool)>(
                            scope.later_opaque.capacity(),
                        )
                        + allocated_table_slot_bytes::<(ByteKey, HashSet<String>)>(
                            scope.foreign.capacity(),
                        )
                        + scope
                            .foreign
                            .values()
                            .map(|names| {
                                allocated_table_slot_bytes::<String>(names.capacity())
                                    + names.iter().map(string).sum::<usize>()
                            })
                            .sum::<usize>()
                        + allocated_table_slot_bytes::<(String, Vec<usize>)>(
                            scope.macros.capacity(),
                        )
                        + scope
                            .macros
                            .values()
                            .map(allocated_vec_slot_bytes)
                            .sum::<usize>()
                        + scope.macros.keys().map(string).sum::<usize>()
                        + allocated_table_slot_bytes::<String>(scope.macro_imports.capacity())
                        + scope.macro_imports.iter().map(string).sum::<usize>()
                        + scope
                            .events
                            .iter()
                            .map(|event| match event {
                                IndexedEvent::Import(_, leaf) => leaf.retained_bytes(),
                                _ => 0,
                            })
                            .sum::<usize>()
                })
                .sum::<usize>()
    }
    #[cfg(test)]
    fn breakdown(&self) -> Vec<(&'static str, usize)> {
        use brokk_bifrost_core::allocation_size::allocation_size;
        use brokk_bifrost_core::hash::{allocated_table_slot_bytes, allocated_vec_slot_bytes};
        let string = |value: &String| allocation_size(value.capacity());
        let mut result = vec![
            ("arena", allocated_vec_slot_bytes(&self.scopes)),
            ("links (implicit in sorted arena)", 0),
            ("table headers", 0),
            ("event rows", 0),
            ("child indices", 0),
            ("per-name map slots", 0),
            ("per-name strings", 0),
            ("per-name position lists", 0),
            ("all-name positions", 0),
            ("suffix slots", 0),
            ("foreign map/set slots", 0),
            ("foreign strings", 0),
            ("macro map/set slots", 0),
            ("macro strings", 0),
            ("macro ends", 0),
            ("import projections", 0),
            ("local binding tables", 0),
        ];
        result[16].1 =
            allocated_table_slot_bytes::<(String, Vec<LocalBinding>)>(self.locals.capacity())
                + self
                    .locals
                    .values()
                    .map(|bindings| {
                        allocated_table_slot_bytes::<(String, Vec<LocalBinding>)>(
                            bindings.capacity(),
                        ) + bindings
                            .values()
                            .map(allocated_vec_slot_bytes)
                            .sum::<usize>()
                            + bindings.keys().map(string).sum::<usize>()
                    })
                    .sum::<usize>();
        for scope in &self.scopes {
            result[2].1 += scope
                .tables
                .as_ref()
                .map_or(0, |_| allocation_size(std::mem::size_of::<ScopeTables>()));
            result[3].1 += allocated_vec_slot_bytes(&scope.events);
            result[4].1 += allocated_vec_slot_bytes(&scope.child_indices);
            result[5].1 +=
                allocated_table_slot_bytes::<(String, Vec<usize>)>(scope.named.capacity());
            result[6].1 += scope.named.keys().map(string).sum::<usize>();
            result[7].1 += scope
                .named
                .values()
                .map(allocated_vec_slot_bytes)
                .sum::<usize>();
            result[8].1 += allocated_vec_slot_bytes(&scope.every);
            result[9].1 +=
                allocated_table_slot_bytes::<(ByteKey, bool)>(scope.later_opaque.capacity());
            result[10].1 +=
                allocated_table_slot_bytes::<(ByteKey, HashSet<String>)>(scope.foreign.capacity())
                    + scope
                        .foreign
                        .values()
                        .map(|names| allocated_table_slot_bytes::<String>(names.capacity()))
                        .sum::<usize>();
            result[11].1 += scope.foreign.values().flatten().map(string).sum::<usize>();
            result[12].1 +=
                allocated_table_slot_bytes::<(String, Vec<usize>)>(scope.macros.capacity())
                    + allocated_table_slot_bytes::<String>(scope.macro_imports.capacity());
            result[13].1 += scope
                .macros
                .keys()
                .chain(scope.macro_imports.iter())
                .map(string)
                .sum::<usize>();
            result[14].1 += scope
                .macros
                .values()
                .map(allocated_vec_slot_bytes)
                .sum::<usize>();
            result[15].1 += scope
                .events
                .iter()
                .map(|event| match event {
                    IndexedEvent::Import(_, leaf) => leaf.retained_bytes(),
                    _ => 0,
                })
                .sum::<usize>();
        }
        assert_eq!(
            result.iter().map(|(_, bytes)| *bytes).sum::<usize>(),
            self.retained_bytes()
        );
        result
    }
}

/// A borrowed plain parse and its matching projection. Production preparation
/// will construct this pairing rather than looking up the source per query.
pub struct RustPlainScope<'tree> {
    root: Node<'tree>,
    source: &'tree str,
    index: PlainIndex<'tree>,
}

enum PlainIndex<'tree> {
    Cached(Arc<Accounted<SourceCached<RustLexicalScopeIndex>>>),
    #[cfg_attr(not(test), allow(dead_code))]
    Oracle(&'tree RustLexicalScopeIndex),
}

impl std::ops::Deref for PlainIndex<'_> {
    type Target = RustLexicalScopeIndex;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Cached(index) => index,
            Self::Oracle(index) => index,
        }
    }
}

impl std::fmt::Debug for RustPlainScope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustPlainScope")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl<'tree> RustPlainScope<'tree> {
    /// Seal a source-keyed projection to an admitted whole-file parse.
    /// Ranges are resolved in this prepared tree's node identity space.
    pub fn new(
        prepared: &'tree brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        caches: &RustLexicalCaches,
    ) -> Self {
        Self::new_bounded(prepared, caches, &mut |_| {
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap()
    }

    pub fn new_bounded<F, E>(
        prepared: &'tree brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        caches: &RustLexicalCaches,
        charge: &mut F,
    ) -> Result<Self, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        Ok(Self {
            root: prepared.tree().root_node(),
            source: prepared.source(),
            index: PlainIndex::Cached(rust_lexical_scope_index_for_prepared(
                caches, prepared, charge,
            )?),
        })
    }

    #[cfg(test)]
    fn for_test(
        root: Node<'tree>,
        source: &'tree str,
        index: &'tree RustLexicalScopeIndex,
    ) -> Self {
        Self {
            root,
            source,
            index: PlainIndex::Oracle(index),
        }
    }

    pub(crate) fn root(&self) -> Node<'tree> {
        self.root
    }

    pub(crate) fn source(&self) -> &'tree str {
        self.source
    }

    /// Fragment queries retain the walk until their owners carry indexes.
    /// The constructor already establishes the whole-file parse identity.
    pub fn contains(&self, node: Node<'_>) -> bool {
        brokk_bifrost_core::analyzer::tree_walk::root_node(node).id() == self.root.id()
    }

    /// Select the nearest local with one charged scope and binary search per level.
    pub fn local_binding_at<E>(
        &self,
        site: Node<'tree>,
        charge: &mut dyn FnMut(usize) -> Result<(), E>,
    ) -> Result<Option<Node<'tree>>, E> {
        if !self.contains(site) {
            return rust_value_binding_at_bounded(site, self.source, charge);
        }
        let arena = &self.index.arena;
        let name = crate::declarations::rust_node_text(site, self.source);
        let byte = site.start_byte();
        let mut current = site.parent();
        while let Some(scope) = current {
            charge(1)?;
            if let Some(bindings) = arena
                .locals
                .get(&((scope.start_byte(), scope.end_byte()), scope.kind()))
                .and_then(|bindings| bindings.get(name))
            {
                charge(1)?;
                let end = bindings.partition_point(|binding| binding.start <= byte);
                if end > 0 && byte < bindings[end - 1].end {
                    return Ok(Some(self.resolve(bindings[end - 1].owner)));
                }
            }
            // Nested function items cannot capture an enclosing value scope.
            if scope.kind() == "function_item" {
                return Ok(None);
            }
            current = scope.parent();
        }
        Ok(None)
    }

    pub fn pattern_name<F, E>(
        &self,
        node: Node<'tree>,
        charge: &mut F,
    ) -> Result<RustPatternName, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if !self.contains(node) {
            return rust_pattern_name_bounded(self.root, self.source, node, charge);
        }
        rust_pattern_name_bounded_with_feed(self.root, self.source, node, charge, self)
    }

    pub fn value_at<F, E>(
        &self,
        node: Node<'tree>,
        charge: &mut F,
    ) -> Result<RustValueName<'tree>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if self.contains(node) {
            self.value(node.byte_range(), charge)
        } else {
            rust_value_name_bounded(self.root, self.source, node, charge)
        }
    }

    pub fn flat_binding_at<F, E>(&self, node: Node<'tree>, charge: &mut F) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if self.contains(node) {
            self.flat_binding(node.byte_range(), charge)
        } else {
            rust_pattern_identifier_binding_bounded(self.root, self.source, node, charge)
        }
    }

    pub fn primitive_at<F, E>(&self, node: Node<'tree>, charge: &mut F) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if self.contains(node) {
            self.primitive(node.byte_range(), charge)
        } else {
            rust_primitive_type_is_unbound_bounded(self.root, self.source, node, charge)
        }
    }

    pub fn owner_item_at<F, E>(
        &self,
        node: Node<'tree>,
        name: &str,
        charge: &mut F,
    ) -> Result<Option<Node<'tree>>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if !self.contains(node) {
            return rust_value_owner_item_bounded(self.root, self.source, node, name, charge);
        }
        Ok(match self.type_head(node, name, charge)? {
            RustTypeHead::Item(item) => Some(item),
            _ => None,
        })
    }

    pub(crate) fn type_head<F, E>(
        &self,
        site: Node<'tree>,
        name: &str,
        charge: &mut F,
    ) -> Result<RustTypeHead<'tree>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        self.type_head_with_memo(site, name, &RustTypeHeadMemo::default(), charge)
    }

    pub(crate) fn type_head_with_memo<F, E>(
        &self,
        site: Node<'tree>,
        name: &str,
        memo: &RustTypeHeadMemo,
        charge: &mut F,
    ) -> Result<RustTypeHead<'tree>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        self.type_head_with_attributes(
            site,
            name,
            charge,
            &memo.no_items_macros.borrow(),
            |scope| {
                scope
                    .inner_known
                    .then_some(())
                    .ok_or(RustTypeAuthorityUnknown::OpaqueScope)
            },
        )
        .map(|selection| selection.head)
    }

    pub(crate) fn prelude_type_head<F, E>(
        &self,
        site: Node<'tree>,
        name: &str,
        charge: &mut F,
    ) -> Result<RustTypeHeadSelection<'tree>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        self.type_head_with_attributes(site, name, charge, &HashSet::new(), |scope| {
            scope.prelude_known
        })
    }

    fn type_head_with_attributes<F, E>(
        &self,
        site: Node<'tree>,
        name: &str,
        charge: &mut F,
        no_items: &HashSet<usize>,
        attributes: impl Fn(&ScopeEvents) -> Result<(), RustTypeAuthorityUnknown>,
    ) -> Result<RustTypeHeadSelection<'tree>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        charge(0)?;
        let arena = &self.index.arena;
        if site.has_error() || site.is_missing() {
            return Ok(type_head_unknown(RustTypeAuthorityUnknown::OpaqueScope));
        }
        let mut current = Some(arena.containing((site.start_byte(), site.end_byte())));
        let mut chain = Vec::new();
        while let Some(id) = current {
            charge(1)?;
            let scope = &arena.scopes[id];
            if !scope.ancestor_known {
                return Ok(type_head_unknown(RustTypeAuthorityUnknown::OpaqueScope));
            }
            chain.push(id);
            current = scope.parent;
        }
        for &id in &chain {
            if let Err(reason) = attributes(&arena.scopes[id]) {
                return Ok(type_head_unknown(reason));
            }
        }
        for id in chain {
            let scope = &arena.scopes[id];
            if let Some(head) = rust_scope_type_head_with_feed(
                self.resolve(scope.syntax),
                self.source,
                name,
                no_items,
                charge,
                self,
            )? {
                return Ok(head);
            }
            if scope.module_boundary {
                break;
            }
        }
        Ok(unbound_type_head(name))
    }

    fn resolve(&self, syntax: SyntaxRange) -> Node<'tree> {
        let mut node = self
            .root
            .descendant_for_byte_range(syntax.bytes.0, syntax.bytes.1)
            .expect("indexed range belongs to paired tree");
        // Single-child grammar wrappers can have the same byte range.
        while node.kind() != syntax.kind
            && let Some(parent) = node
                .parent()
                .filter(|parent| (parent.start_byte(), parent.end_byte()) == syntax.bytes)
        {
            node = parent;
        }
        debug_assert_eq!(
            (node.start_byte(), node.end_byte(), node.kind()),
            (syntax.bytes.0, syntax.bytes.1, syntax.kind)
        );
        node
    }

    fn site(&self, bytes: std::ops::Range<usize>) -> Node<'tree> {
        let node = self
            .root
            .descendant_for_byte_range(bytes.start, bytes.end)
            .expect("site belongs to paired parse");
        debug_assert_eq!(node.byte_range(), bytes);
        node
    }

    pub fn value<F, E>(
        &self,
        bytes: std::ops::Range<usize>,
        charge: &mut F,
    ) -> Result<RustValueName<'tree>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        rust_value_name_bounded_with_feed(self.root, self.source, self.site(bytes), charge, self)
    }
    pub fn flat_binding<F, E>(
        &self,
        bytes: std::ops::Range<usize>,
        charge: &mut F,
    ) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        rust_pattern_identifier_binding_bounded_with_feed(
            self.root,
            self.source,
            self.site(bytes),
            charge,
            self,
        )
    }
    pub fn pattern<F, E>(
        &self,
        bytes: std::ops::Range<usize>,
        charge: &mut F,
    ) -> Result<(RustLexicalSelection<RustPatternName>, bool, bool), E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        rust_pattern_name_selection_bounded_with_feed(
            self.root,
            self.source,
            self.site(bytes),
            charge,
            self,
        )
    }
    pub fn primitive<F, E>(&self, bytes: std::ops::Range<usize>, charge: &mut F) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        self.primitive_unbound(self.root, self.source, self.site(bytes), charge)
    }

    /// All-ancestor macro chain, unlike item lookup which stops at a module.
    pub fn macro_bound(&self, bytes: std::ops::Range<usize>, name: &str) -> bool {
        let arena = &self.index.arena;
        let mut current = arena.scopes[arena.containing((bytes.start, bytes.end))].parent;
        while let Some(id) = current {
            let scope = &arena.scopes[id];
            if scope
                .macros
                .get(normalized(name))
                .is_some_and(|ends| ends.partition_point(|end| *end <= bytes.start) > 0)
                || (crate::format_args::rust_logging_macro("log", name).is_none()
                    && scope.macro_imports.contains(normalized(name)))
            {
                return true;
            }
            current = scope.parent;
        }
        false
    }
}

// Generic methods keep the callback bodies identical across the walk and index.
#[allow(clippy::too_many_arguments)]
pub(super) trait RustScopeFeed<'tree> {
    fn visit<F, E, T>(
        &self,
        root: Node<'tree>,
        source: &str,
        site: Node<'tree>,
        name: &str,
        charge: &mut F,
        select: impl for<'p> FnMut(
            RustLexicalSelectionEvent<'tree, 'p>,
            &mut F,
        ) -> Result<ControlFlow<T>, E>,
    ) -> Result<RustLexicalSelection<T>, E>
    where
        F: FnMut(usize) -> Result<(), E>;
    fn scope<F, E, T>(
        &self,
        scope: Node<'tree>,
        source: &str,
        name: &str,
        charge: &mut F,
        select: &mut impl for<'p> FnMut(
            RustLexicalSelectionEvent<'tree, 'p>,
            &mut F,
        ) -> Result<ControlFlow<T>, E>,
        no_items: &HashSet<usize>,
    ) -> Result<ControlFlow<RustLexicalSelection<T>>, E>
    where
        F: FnMut(usize) -> Result<(), E>;
    fn foreign_occupied<F, E>(
        &self,
        item: Node<'tree>,
        source: &str,
        name: &str,
        charge: &mut F,
    ) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>;
    fn later_opaque<F, E>(&self, item: Node<'tree>, charge: &mut F) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>;
    fn primitive_unbound<F, E>(
        &self,
        root: Node<'tree>,
        source: &str,
        ty: Node<'tree>,
        charge: &mut F,
    ) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>;
}

pub(super) struct RustWalkScope;
impl<'tree> RustScopeFeed<'tree> for RustWalkScope {
    fn visit<F, E, T>(
        &self,
        root: Node<'tree>,
        source: &str,
        site: Node<'tree>,
        _name: &str,
        charge: &mut F,
        select: impl for<'p> FnMut(
            RustLexicalSelectionEvent<'tree, 'p>,
            &mut F,
        ) -> Result<ControlFlow<T>, E>,
    ) -> Result<RustLexicalSelection<T>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        visit_rust_lexical_selection_bounded(root, source, site, charge, select)
    }
    fn scope<F, E, T>(
        &self,
        scope: Node<'tree>,
        source: &str,
        _name: &str,
        charge: &mut F,
        select: &mut impl for<'p> FnMut(
            RustLexicalSelectionEvent<'tree, 'p>,
            &mut F,
        ) -> Result<ControlFlow<T>, E>,
        no_items: &HashSet<usize>,
    ) -> Result<ControlFlow<RustLexicalSelection<T>>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        visit_rust_lexical_scope_with_no_items(scope, source, charge, select, no_items)
    }
    fn foreign_occupied<F, E>(
        &self,
        item: Node<'tree>,
        source: &str,
        name: &str,
        charge: &mut F,
    ) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if let Some(body) = item.child_by_field_name("body") {
            for member in body.named_children(&mut body.walk()) {
                charge(1)?;
                let member = unwrap_attributes(member);
                if matches!(member.kind(), "function_signature_item" | "static_item")
                    && member
                        .child_by_field_name("name")
                        .is_some_and(|n| crate::declarations::rust_node_text(n, source) == name)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn later_opaque<F, E>(&self, item: Node<'tree>, charge: &mut F) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if item.parent().is_some_and(|scope| scope.kind() == "block") {
            let mut later = item.next_named_sibling();
            while let Some(statement) = later {
                charge(1)?;
                if statement.has_error()
                    || statement.kind() == "macro_invocation"
                    || (statement.kind() == "expression_statement"
                        && statement
                            .named_child(0)
                            .is_some_and(|child| child.kind() == "macro_invocation"))
                {
                    return Ok(true);
                }
                later = statement.next_named_sibling();
            }
        }
        Ok(false)
    }
    fn primitive_unbound<F, E>(
        &self,
        root: Node<'tree>,
        source: &str,
        ty: Node<'tree>,
        charge: &mut F,
    ) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        rust_primitive_type_is_unbound_bounded(root, source, ty, charge)
    }
}

impl<'tree> RustScopeFeed<'tree> for RustPlainScope<'tree> {
    fn visit<F, E, T>(
        &self,
        _root: Node<'tree>,
        _source: &str,
        site: Node<'tree>,
        name: &str,
        charge: &mut F,
        mut select: impl for<'p> FnMut(
            RustLexicalSelectionEvent<'tree, 'p>,
            &mut F,
        ) -> Result<ControlFlow<T>, E>,
    ) -> Result<RustLexicalSelection<T>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        charge(0)?;
        let arena = &self.index.arena;
        if site.has_error() || site.is_missing() {
            return Ok(RustLexicalSelection::Unknown);
        }
        let start = arena.containing((site.start_byte(), site.end_byte()));
        let mut current = Some(start);
        let mut chain = Vec::new();
        while let Some(id) = current {
            charge(1)?;
            let scope = &arena.scopes[id];
            if !scope.ancestor_known {
                return Ok(RustLexicalSelection::Unknown);
            }
            if let ControlFlow::Break(value) = select(
                RustLexicalSelectionEvent::Ancestor(self.resolve(scope.syntax)),
                charge,
            )? {
                return Ok(RustLexicalSelection::Selected(value));
            }
            chain.push(id);
            current = scope.parent;
        }
        if chain.iter().any(|id| !arena.scopes[*id].inner_known) {
            return Ok(RustLexicalSelection::Unknown);
        }
        for id in chain {
            let scope = &arena.scopes[id];
            if let ControlFlow::Break(selection) = self.scope(
                self.resolve(scope.syntax),
                self.source,
                name,
                charge,
                &mut select,
                &HashSet::new(),
            )? {
                return Ok(selection);
            }
            if scope.module_boundary {
                break;
            }
        }
        charge(0)?;
        Ok(RustLexicalSelection::Complete)
    }
    fn scope<F, E, T>(
        &self,
        scope: Node<'tree>,
        _source: &str,
        name: &str,
        charge: &mut F,
        select: &mut impl for<'p> FnMut(
            RustLexicalSelectionEvent<'tree, 'p>,
            &mut F,
        ) -> Result<ControlFlow<T>, E>,
        no_items: &HashSet<usize>,
    ) -> Result<ControlFlow<RustLexicalSelection<T>>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        let scope_node = scope;
        let arena = &self.index.arena;
        let scope = &arena.scopes[arena.node_id(scope)];
        for position in arena.positions(arena.node_id(scope_node), name) {
            charge(1)?;
            let event = match &scope.events[position] {
                IndexedEvent::Unknown => {
                    return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
                }
                IndexedEvent::Macro(range) => {
                    let item = self.resolve(*range);
                    if !no_items.contains(&item.id())
                        && !item
                            .named_child(0)
                            .is_some_and(|child| no_items.contains(&child.id()))
                    {
                        return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
                    }
                    RustLexicalSelectionEvent::Item(item)
                }
                IndexedEvent::Parameter(range) => {
                    RustLexicalSelectionEvent::Parameter(self.resolve(*range))
                }
                IndexedEvent::Item(range) => RustLexicalSelectionEvent::Item(self.resolve(*range)),
                IndexedEvent::Import(range, leaf) => {
                    RustLexicalSelectionEvent::Import(self.resolve(*range), leaf)
                }
                IndexedEvent::End => RustLexicalSelectionEvent::ScopeEnd,
            };
            if let ControlFlow::Break(value) = select(event, charge)? {
                return Ok(ControlFlow::Break(RustLexicalSelection::Selected(value)));
            }
        }
        Ok(ControlFlow::Continue(()))
    }
    fn foreign_occupied<F, E>(
        &self,
        item: Node<'tree>,
        _source: &str,
        name: &str,
        charge: &mut F,
    ) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        charge(1)?;
        let arena = &self.index.arena;
        let id = arena.containing((item.start_byte(), item.end_byte()));
        let mut parent = Some(id);
        while let Some(id) = parent {
            if let Some(names) = arena.scopes[id]
                .foreign
                .get(&(item.start_byte(), item.end_byte()))
            {
                return Ok(names.contains(name));
            }
            parent = arena.scopes[id].parent;
        }
        unreachable!("foreign event retains its declared member names")
    }

    fn later_opaque<F, E>(&self, item: Node<'tree>, charge: &mut F) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        charge(1)?;
        let arena = &self.index.arena;
        if !item.parent().is_some_and(|parent| parent.kind() == "block") {
            return Ok(false);
        }
        let key = (item.start_byte(), item.end_byte());
        let mut current = Some(arena.containing(key));
        while let Some(id) = current {
            if let Some(opaque) = arena.scopes[id].later_opaque.get(&key) {
                return Ok(*opaque);
            }
            current = arena.scopes[id].parent;
        }
        Ok(false)
    }

    fn primitive_unbound<F, E>(
        &self,
        _root: Node<'tree>,
        _source: &str,
        ty: Node<'tree>,
        charge: &mut F,
    ) -> Result<bool, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        let name = crate::declarations::rust_node_text(ty, self.source);
        Ok(matches!(
            self.type_head(ty, name, charge)?,
            RustTypeHead::Unbound
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Building the index must not re-prove test-attribute unshadowing for each
    // #[test] item: that walk scans the whole module, so per-item calls make
    // the build quadratic in the number of tests.
    #[test]
    fn lexical_scope_test_attribute_build_is_linear() {
        let measure = |n| {
            let source = (0..n)
                .map(|i| format!("#[test] fn t{i}() {{}}"))
                .collect::<String>();
            let tree = parse_rust_tree_uncached(&source).unwrap();
            let mut work = 0;
            RustLexicalScopeIndex::new_bounded(tree.root_node(), &source, &mut |amount| {
                work += amount;
                Ok::<_, ()>(())
            })
            .unwrap();
            work
        };
        let small = measure(100);
        let large = measure(200);
        assert!(
            large > small * 19 / 10 && large < small * 21 / 10,
            "{small} -> {large}"
        );
    }

    #[test]
    fn lexical_scope_index_resolves_independent_prepared_tree() {
        use brokk_bifrost_core::analyzer::model::{Language, LanguageDialect};
        use brokk_bifrost_core::analyzer::prepared_syntax::{
            PreparedSourceOrigin, PreparedSyntaxSource, PreparedSyntaxTree,
        };
        let source = "const C:i32=1; fn f(){ f(); C; let x=0; x; }";
        let tree = parse_rust_tree_uncached(source).unwrap();
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            tree,
            brokk_bifrost_core::text_utils::compute_line_starts(source),
            LanguageDialect::Standard(Language::Rust),
            PreparedSourceOrigin::Disk,
            None,
        );
        let caches = RustLexicalCaches::new(&RetentionBudget::for_tests());
        // Warm the cache from its own parse of the same source, so the handle
        // must resolve another parse's index into this prepared tree.
        rust_lexical_scope_index_with(&caches, source);
        let scope = RustPlainScope::new(&prepared, &caches);
        let root = prepared.tree().root_node();
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            pending.extend(node.named_children(&mut node.walk()));
            if node.kind() != "identifier" {
                continue;
            }
            let mut free = |_| Ok::<_, ()>(());
            assert_eq!(
                scope
                    .local_binding_at(node, &mut free)
                    .unwrap()
                    .map(|n| n.id()),
                rust_value_binding_at_bounded(node, source, &mut free)
                    .unwrap()
                    .map(|n| n.id()),
                "local binding at {node:?}"
            );
            let name = crate::declarations::rust_node_text(node, source);
            assert_eq!(
                rust_value_owner_item_bounded(root, source, node, name, &mut free)
                    .unwrap()
                    .map(|n| n.id()),
                scope
                    .owner_item_at(node, name, &mut free)
                    .unwrap()
                    .map(|n| n.id()),
            );
            let before = rust_value_name_bounded(root, source, node, &mut free).unwrap();
            let after = scope.value(node.byte_range(), &mut free).unwrap();
            assert_eq!(format!("{before:?}"), format!("{after:?}"));
            if let RustValueName::Callable(item) = after {
                assert_eq!(
                    brokk_bifrost_core::analyzer::tree_walk::root_node(item).id(),
                    root.id()
                );
            }
            assert_eq!(
                rust_pattern_name_selection_bounded(root, source, node, &mut free).unwrap(),
                scope.pattern(node.byte_range(), &mut free).unwrap(),
            );
            assert_eq!(
                rust_pattern_identifier_binding_bounded(root, source, node, &mut free).unwrap(),
                scope.flat_binding(node.byte_range(), &mut free).unwrap(),
            );
        }
    }

    // Build only the unchanged M2 selection projection, omitting M3a's
    // independent local table. This checks the integration's parent links.
    fn m2_arena_without_locals(root: Node<'_>, source: &str) -> ScopeArena {
        let mut free = |_| Ok::<_, ()>(());
        let mut nodes = Vec::new();
        let mut parents = Vec::new();
        let mut ids = HashMap::default();
        let mut pending = vec![(root, None)];
        while let Some((node, parent)) = pending.pop() {
            let id = nodes.len();
            nodes.push(node);
            parents.push(parent);
            ids.insert(node.id(), id);
            pending.extend(
                node.named_children(&mut node.walk())
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .map(|child| (child, Some(id))),
            );
        }
        let attributes = crate::syntax::RustAttributeGroups::prepare(&nodes, &mut free).unwrap();
        let test_scopes = canonical_test_scopes(&nodes, &parents, &ids, source, &mut free).unwrap();
        let ancestry = RustCanonicalParents {
            nodes: &nodes,
            parents: &parents,
            ids: &ids,
        };
        let mut arena = ScopeArena::default();
        let mut pending = vec![(root, None)];
        while let Some((node, parent)) = pending.pop() {
            let id = arena
                .add(node, parent, source, &mut free, &mut |item, charge| {
                    canonical_scope_attributes_known(
                        item,
                        source,
                        &test_scopes,
                        &ancestry,
                        &attributes,
                        charge,
                    )
                })
                .unwrap();
            pending.extend(
                node.named_children(&mut node.walk())
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .map(|child| (child, Some(id))),
            );
        }
        arena
    }

    #[test]
    fn lexical_scope_index_matches_walk_oracle() {
        let corpus = [
            "const C:i32=1; fn f(){let x=C; {const C:i32=2; let C=0; C;} C;}",
            "fn f(){before(); fn before(){} after(); fn after(){} let x=0;}",
            "use dep::*; const C:i32=1; fn f(){let C=1; C; let x=0;}",
            "const C:i32=1; use dep::*; fn f(){let C=1; C; let x=0;}",
            "extern crate dep; fn f(){let x=0; x;}",
            "use dep::{C, f as call, self as d}; fn f(){let C=0; call(); let x=0;}",
            "use dep::C as r#type; fn f(){let r#type=0; r#type;}",
            "#[cfg(feature=\"x\")] const C:i32=1; fn f(){C;let x=0;}",
            "#[inline] fn call(){} #[doc=\"a\"] const C:i32=1; fn f(){call(); C;let x=0;}",
            "#[unknown] fn call(){} fn f(){call(); let x=0;}",
            "mod m{#![cfg(feature=\"x\")] fn f(){let x=0;x;}}",
            "#![allow(dead_code)] fn f(){let x=0;x;}",
            "fn f(){const C:i32=1; m!(); C; let x=0;}",
            "fn f(){const C:i32=1; let broken = ; C; let x=0;}",
            "m!{} const C:i32=1;fn f(){C;let x=0;}",
            "const C:i32=1;m!{} fn f(){C;let x=0;}",
            "const C:i32=1; mod m{fn f(){C;let x=0;} mod n{fn g(){let x=0; C;}}}",
            "struct S; impl S{const C:i32=1; fn f(){let C=0;C;let x=0;}}",
            "trait T{const C:i32; fn f(){let C=0;C;let x=0;}}",
            "fn f<T,const C:usize>(){C;let C=0;let x=0;}",
            "fn f<i32>(){const C:i32=1; C; let x=0;}",
            "type i32=u32; const C:i32=1;fn f(){C;let x=0;}",
            "type i32=u32; type i32=u64; const C:i32=1;fn f(){C;let x=0;}",
            "extern \"C\" {fn foreign(); static S:i32;} fn f(){foreign();S;let x=0;}",
            "#[cfg(feature=\"x\")] extern \"C\" {fn foreign(); static S:i32;} fn f(){foreign();S;let x=0;}",
            "fn f(){before!(); macro_rules! before{()=>{}} before!(); after!(); macro_rules! after{()=>{}} after!();}",
            "use dep::named; fn f(){named!(); missing!();} mod m{fn g(){named!();}}",
            "fn f(){macro_rules! local{()=>{}} mod m{fn g(){local!();}}}",
            "fn f(){let (mut x,y)=(0,1); match y{None=>(),C=>(),z=>()} x;}",
            "fn f(){struct C{} C;let C=0;} const C:i32=1;",
            "fn f(){macro_rules! m{()=>{}} let unrelated=0;}",
            "fn f(mut x:i32){let x=x; #[cfg(any())] let x=x; m!(); {let Some(x)=Some(x) else {x;return;}; x;} if let Some(x)=Some(x) && let Some(y)=Some(x){x;y;}else{x;} while let Some(x)=Some(x) && let Some(y)=Some(x){x;y;} for (x,y) in xs{x;y;} match x{Some(x)|Some(x) if x>0=>{x;}, _=>x}; let c=|x|{let y=x; move |z|{x;y;z;}}; fn inner(){x;} }",
            "const C:(i32,bool)=(1,true); fn f(){C;let x=0;}",
            "struct S; m!(); struct T; fn f(){S;T;}",
        ];
        let mut sites = 0usize;
        let mut macros = 0usize;
        let mut fragments = 0usize;
        let tests = (0..32)
            .map(|i| format!("#[test] fn t{i}() {{ C; let x=0; }}"))
            .collect::<String>();
        let extra = [
            format!("const C:i32=1; {tests} mod nested {{ {tests} }}"),
            format!(
                "macro_rules! test {{()=>{{}}}} const C:i32=1; {tests} mod nested {{ {tests} }}"
            ),
            format!("use dep::*; const C:i32=1; {tests} mod nested {{ {tests} }}"),
        ];
        for source in corpus.into_iter().chain(extra.iter().map(String::as_str)) {
            let tree = parse_rust_tree_uncached(source).unwrap();
            let fragment = tree
                .root_node()
                .named_children(&mut tree.root_node().walk())
                .find(|node| node.kind() == "function_item")
                .map(|node| parse_rust_range_tree(source, node.range()).unwrap());
            fragments += usize::from(fragment.is_some());
            for tree in std::iter::once(&tree).chain(fragment.as_ref()) {
                let root = tree.root_node();
                let index = RustLexicalScopeIndex::new(root, source);
                let m2 = m2_arena_without_locals(root, source);
                let shape = |arena: &ScopeArena| {
                    arena
                        .scopes
                        .iter()
                        .map(|scope| (scope.syntax.bytes, scope.syntax.kind, scope.parent))
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    shape(&index.arena),
                    shape(&m2),
                    "M2 scope count/ranges/parents changed: {source}"
                );
                let paired = RustPlainScope::for_test(root, source, &index);
                let exports = crate::macro_matcher::ExportedMacroDefinitions::from_candidates(
                    Vec::new(),
                    source,
                );
                let mut pending = vec![root];
                while let Some(node) = pending.pop() {
                    if matches!(
                        node.kind(),
                        "identifier"
                            | "shorthand_field_identifier"
                            | "primitive_type"
                            | "mut_pattern"
                    ) {
                        sites += 1;
                        assert_eq!(paired.local_binding_at(node, &mut |_| Err(())), Err(()));
                        let mut free = |_| Ok::<_, ()>(());
                        assert_eq!(
                            paired
                                .local_binding_at(node, &mut free)
                                .unwrap()
                                .map(|n| n.id()),
                            rust_value_binding_at_bounded(node, source, &mut free)
                                .unwrap()
                                .map(|n| n.id()),
                            "local binding {source} at {node:?}"
                        );
                        let name = crate::declarations::rust_node_text(node, source);
                        let exemptions = root
                            .named_children(&mut root.walk())
                            .filter(|item| rust_item_macro_invocation(*item))
                            .map(|item| item.id())
                            .collect();
                        let memo = RustTypeHeadMemo::default();
                        memo.with_no_items_macros(exemptions, || {
                            let walk = rust_type_head_at_bounded(
                                root, source, node, name, &memo, &mut free,
                            )
                            .unwrap();
                            let indexed = paired
                                .type_head_with_memo(node, name, &memo, &mut free)
                                .unwrap();
                            assert_eq!(
                                format!("{walk:?}"),
                                format!("{indexed:?}"),
                                "guarded {source}"
                            );
                        });

                        let walk = rust_type_head_at_bounded(
                            root,
                            source,
                            node,
                            name,
                            &RustTypeHeadMemo::default(),
                            &mut free,
                        )
                        .unwrap();
                        let indexed = paired.type_head(node, name, &mut free).unwrap();
                        assert_eq!(
                            format!("{walk:?}"),
                            format!("{indexed:?}"),
                            "type head {source}"
                        );
                        let walk = rust_type_prelude_authority_at_bounded(
                            root,
                            source,
                            node,
                            name,
                            &RustTypeHeadMemo::default(),
                            &mut free,
                        )
                        .unwrap();
                        let indexed = paired.prelude_type_head(node, name, &mut free).unwrap();
                        assert_eq!(
                            format!("{walk:?}"),
                            format!("{indexed:?}"),
                            "prelude {source}"
                        );

                        assert_eq!(
                            rust_value_name_bounded(root, source, node, &mut free).unwrap(),
                            paired.value(node.byte_range(), &mut free).unwrap(),
                            "value {source}: {node:?}"
                        );
                        assert_eq!(
                            rust_pattern_identifier_binding_bounded(root, source, node, &mut free)
                                .unwrap(),
                            paired.flat_binding(node.byte_range(), &mut free).unwrap(),
                            "flat {source}: {node:?}"
                        );
                        assert_eq!(
                            rust_pattern_name_selection_bounded(root, source, node, &mut free)
                                .unwrap(),
                            paired.pattern(node.byte_range(), &mut free).unwrap(),
                            "pattern {source}: {node:?}"
                        );
                        assert_eq!(
                            rust_primitive_type_is_unbound_bounded(root, source, node, &mut free)
                                .unwrap(),
                            paired.primitive(node.byte_range(), &mut free).unwrap(),
                            "primitive {source}: {node:?}"
                        );
                    }
                    if node.kind() == "macro_invocation"
                        && let Some(name) =
                            crate::declarations::rust_unqualified_macro_invocation_name(
                                node, source,
                            )
                    {
                        macros += 1;
                        assert_eq!(
                            crate::macro_matcher::macro_invocation_is_locally_bound(
                                node, source, &exports, node
                            ),
                            paired.macro_bound(node.byte_range(), name),
                            "macro {source}: {node:?}"
                        );
                    }
                    pending.extend(node.named_children(&mut node.walk()));
                }
            }
        }
        // Measure retained capacities on a real large file without querying all
        // of its sites through the deliberately quadratic reference walk.
        let large = include_str!("../lexical_scope.rs");
        let tree = parse_rust_tree_uncached(large).unwrap();
        let mut build_charges = Vec::new();
        let index = RustLexicalScopeIndex::new_bounded(tree.root_node(), large, &mut |amount| {
            build_charges.push(amount);
            Ok::<_, ()>(())
        })
        .unwrap();
        // The build charges as it runs, so a budget below its total stops it
        // partway instead of after the whole index exists.
        let total: usize = build_charges.iter().sum();
        let largest = build_charges.iter().copied().max().unwrap();
        assert!(largest < total / 2, "{largest} of {total}");
        let mut charged = 0;
        assert!(
            RustLexicalScopeIndex::new_bounded(tree.root_node(), large, &mut |amount| {
                charged += amount;
                if charged > total / 2 { Err(()) } else { Ok(()) }
            })
            .is_err()
        );
        assert!(charged <= total / 2 + largest, "{charged} of {total}");
        let mut polls = 0;
        assert!(
            RustLexicalScopeIndex::new_bounded(tree.root_node(), large, &mut |_| {
                polls += 1;
                if polls == 2 { Err(()) } else { Ok(()) }
            })
            .is_err()
        );
        eprintln!("lexical_scope.rs breakdown: {:?}", index.arena.breakdown());
        let other = include_str!("../macro_matcher.rs");
        let other_tree = parse_rust_tree_uncached(other).unwrap();
        let other_index = RustLexicalScopeIndex::new(other_tree.root_node(), other);
        eprintln!(
            "macro_matcher.rs {} source bytes, {} table bytes; breakdown: {:?}",
            other.len(),
            other_index.arena.retained_bytes(),
            other_index.arena.breakdown()
        );
        eprintln!(
            "oracle: {} snippets plus {fragments} region fragments, {sites} selector sites, {macros} macro sites; lexical_scope.rs {} source bytes, {} new table bytes",
            corpus.len(),
            large.len(),
            index.arena.retained_bytes()
        );
    }
}
