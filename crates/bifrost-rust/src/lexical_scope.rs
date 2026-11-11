use crate::usage_walks::WalkCache;
use brokk_bifrost_core::analyzer::common::{
    parse_source_range_with_cancellation, parse_source_region,
};
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredImportPathKind};
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportBinding, ImportKind};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::retention_budget::{Accounted, RetainedBytes, RetentionBudget};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tree_sitter::{Node, Parser, Tree};

use crate::imports::{
    RustImportBindingName, rust_import_binding_name, rust_imports_from_use_declaration,
};
use crate::syntax::{
    const_type_is_identity_free, outer_attributes, outer_attributes_with_parent, unwrap_attributes,
};

/// Re-exported from core, where the persisted `rust_import_targets` row shape
/// that carries it lives. Kept spelled here because every reader of a cfg
/// predicate reaches it through the lexical-scope surface that computes one.
pub use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;

pub fn rust_cfg_condition(node: Node<'_>, source: &str) -> RustCfgCondition {
    rust_cfg_condition_from_attributes(
        outer_attributes(node).take_while(|attribute| attribute.kind() == "attribute_item"),
        source,
    )
}

pub(crate) fn rust_cfg_condition_with_parent(
    node: Node<'_>,
    parent: Option<Node<'_>>,
    source: &str,
) -> RustCfgCondition {
    rust_cfg_condition_from_attributes(
        outer_attributes_with_parent(node, parent)
            .take_while(|attribute| attribute.kind() == "attribute_item"),
        source,
    )
}

pub fn rust_crate_cfg_condition(root: Node<'_>, source: &str) -> RustCfgCondition {
    let mut cursor = root.walk();
    rust_cfg_condition_from_attributes(
        root.named_children(&mut cursor)
            .filter(|child| child.kind() == "inner_attribute_item"),
        source,
    )
}

fn rust_cfg_condition_from_attributes<'tree>(
    attributes: impl Iterator<Item = Node<'tree>>,
    source: &str,
) -> RustCfgCondition {
    let mut condition = RustCfgCondition::Always;
    for attribute_item in attributes {
        match cfg_attribute_condition(attribute_item, source) {
            Err(()) => return RustCfgCondition::Unknown,
            Ok(None) => {}
            Ok(Some(candidate)) => {
                condition = RustCfgCondition::conjunction([condition, candidate]);
            }
        }
    }
    condition
}

fn cfg_attribute_condition(
    attribute_item: Node<'_>,
    source: &str,
) -> Result<Option<RustCfgCondition>, ()> {
    let attribute = attribute_item.named_child(0).ok_or(())?;
    let path = attribute.named_child(0).ok_or(())?;
    if crate::declarations::rust_node_text(path, source).trim() != "cfg" {
        return Ok(None);
    }
    Ok(Some(
        attribute
            .child_by_field_name("arguments")
            .and_then(|arguments| rust_cfg_argument_condition(arguments, source))
            .unwrap_or(RustCfgCondition::Unknown),
    ))
}

pub(crate) fn rust_cfg_argument_condition(
    arguments: Node<'_>,
    source: &str,
) -> Option<RustCfgCondition> {
    let mut cursor = arguments.walk();
    let children = arguments
        .children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect::<Vec<_>>();
    let [open, inner @ .., close] = children.as_slice() else {
        return None;
    };
    if arguments.kind() != "token_tree" || open.kind() != "(" || close.kind() != ")" {
        return None;
    }
    // A trailing comma is legal in cfg(predicate,).
    let inner = if inner.last().is_some_and(|node| node.kind() == ",") {
        &inner[..inner.len() - 1]
    } else {
        inner
    };
    rust_cfg_predicate_condition(inner, source)
}

/// Read one configuration predicate from structurally selected token nodes.
pub(crate) fn rust_cfg_predicate_condition(
    predicate: &[Node<'_>],
    source: &str,
) -> Option<RustCfgCondition> {
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgInstruction;
    enum Work<'tree> {
        Predicate(Vec<Node<'tree>>),
        Emit(RustCfgInstruction),
    }
    fn arguments_of(node: Node<'_>) -> Option<Vec<Vec<Node<'_>>>> {
        if node.kind() != "token_tree" {
            return None;
        }
        let mut cursor = node.walk();
        let children = node
            .children(&mut cursor)
            .filter(|child| !child.is_extra())
            .collect::<Vec<_>>();
        let [open, inner @ .., close] = children.as_slice() else {
            return None;
        };
        if open.kind() != "(" || close.kind() != ")" {
            return None;
        }
        let mut groups = Vec::new();
        let mut group = Vec::new();
        for &child in inner {
            if child.is_extra() {
                continue;
            }
            match child.kind() {
                "," => {
                    if group.is_empty() {
                        return None;
                    }
                    groups.push(std::mem::take(&mut group));
                }
                _ => group.push(child),
            }
        }
        if !group.is_empty() {
            groups.push(group);
        }
        Some(groups)
    }
    let mut work = vec![Work::Predicate(predicate.to_vec())];
    let mut output = Vec::new();
    while let Some(task) = work.pop() {
        let nodes = match task {
            Work::Emit(instruction) => {
                output.push(instruction);
                continue;
            }
            Work::Predicate(nodes) => nodes,
        };
        let first = *nodes.first()?;
        if nodes.len() == 1 && first.kind() == "boolean_literal" {
            output.push(match crate::declarations::rust_node_text(first, source) {
                "true" => RustCfgInstruction::All(0),
                "false" => RustCfgInstruction::Any(0),
                _ => unreachable!("boolean literal has a boolean value"),
            });
            continue;
        }
        if first.kind() != "identifier" {
            return None;
        }
        let name = crate::declarations::rust_node_text(first, source);
        match nodes.as_slice() {
            [_] => output.push(RustCfgInstruction::Atom(name.to_string())),
            [_, equals, literal] if equals.kind() == "=" => {
                let value = crate::cargo_routes::rust_static_string_literal(*literal, source)?;
                if name == "feature" {
                    output.push(RustCfgInstruction::Atom(format!("feature = {value:?}")));
                } else {
                    output.push(RustCfgInstruction::KeyValue {
                        key: name.to_string(),
                        value,
                    });
                }
            }
            [_, nested] if nested.kind() == "token_tree" => {
                let nested = arguments_of(*nested)?;
                let instruction = match name {
                    "all" => RustCfgInstruction::All(nested.len()),
                    "any" => RustCfgInstruction::Any(nested.len()),
                    "not" if nested.len() == 1 => RustCfgInstruction::Not,
                    _ => return None,
                };
                work.push(Work::Emit(instruction));
                work.extend(nested.into_iter().rev().map(Work::Predicate));
            }
            _ => return None,
        }
    }
    Some(match output.as_slice() {
        [RustCfgInstruction::Atom(atom)] => RustCfgCondition::Atom(atom.clone()),
        [RustCfgInstruction::Atom(atom), RustCfgInstruction::Not] => {
            RustCfgCondition::NotAtom(atom.clone())
        }
        _ => RustCfgCondition::Expression(output.into_boxed_slice()),
    })
}

/// Effective activation is source-owned and includes every enclosing item and
/// the crate's inner attributes. No selected host or manifest is consulted.
pub fn rust_effective_cfg_condition(node: Node<'_>, source: &str) -> RustCfgCondition {
    rust_effective_cfg_condition_with_cache(node, source, &mut HashMap::default())
}

/// The cache belongs to one live tree. In particular, do not reuse primary
/// node ids for temporary embedded replay trees.
pub(crate) fn rust_effective_cfg_condition_with_cache(
    mut node: Node<'_>,
    source: &str,
    cache: &mut HashMap<usize, RustCfgCondition>,
) -> RustCfgCondition {
    node = unwrap_attributes(node);
    let mut pending = Vec::new();
    let mut condition = loop {
        if let Some(condition) = cache.get(&node.id()) {
            break condition.clone();
        }
        let own = if node.kind() == "source_file" {
            rust_crate_cfg_condition(node, source)
        } else {
            rust_cfg_condition(node, source)
        };
        pending.push((node.id(), own));
        let Some(parent) = crate::syntax::parent_outside_attributes(node) else {
            break RustCfgCondition::Always;
        };
        node = parent;
    };
    for (id, own) in pending.into_iter().rev() {
        condition = RustCfgCondition::conjunction([condition, own]);
        cache.insert(id, condition.clone());
    }
    condition
}

/// Source bytes retained by the shared Rust parse memo. Entries are weighed by
/// their source length; the parsed trees they hold are several times larger, so
/// keep this comfortably below the process's memory budget. 32 MiB covers every
/// Rust file of a large workspace (Bifrost's own `src/` is ~20 MiB) in one pass.
static RUST_TREE_PARSES: AtomicUsize = AtomicUsize::new(0);
static RUST_TREE_PARSE_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static RUST_TREE_PARSED_BYTES: AtomicUsize = AtomicUsize::new(0);
static RUST_SCOPE_INDEX_BUILDS: AtomicUsize = AtomicUsize::new(0);

/// Parse and lexical indexes retained by one Rust analyzer's budget.
pub struct RustLexicalCaches {
    trees: WalkCache<SourceKey, SourceCached<Option<Tree>>>,
    scope_indexes: WalkCache<SourceKey, SourceCached<RustLexicalScopeIndex>>,
    use_statements: WalkCache<SourceKey, SourceCached<Vec<RustUseStatement>>>,
    /// Whole-file `use` scans this cache performed (a cache miss), for tests and
    /// telemetry that check several lookups share one scan.
    use_scans: AtomicUsize,
}

impl RustLexicalCaches {
    /// How many whole-file `use` scans this cache has performed.
    pub fn use_statement_scans(&self) -> usize {
        self.use_scans.load(Ordering::Relaxed)
    }

    pub fn new(budget: &RetentionBudget) -> Self {
        Self {
            trees: WalkCache::new(budget, "rust.lexical.trees", weigh_tree),
            scope_indexes: WalkCache::new(budget, "rust.lexical.scope_indexes", weigh_scope_index),
            use_statements: WalkCache::new(
                budget,
                "rust.lexical.use_statements",
                weigh_use_statements,
            ),
            use_scans: AtomicUsize::new(0),
        }
    }
}

/// A lexical cache key: the source's length and fast hash. A lookup computes
/// it without copying the source, and a hit counts only when the cached entry's
/// own source equals the asked source, so a hash collision is a miss.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SourceKey {
    len: usize,
    hash: u64,
}

impl SourceKey {
    fn of(source: &str) -> Self {
        Self {
            len: source.len(),
            hash: brokk_bifrost_core::hash::hash_one(source),
        }
    }
}

impl RetainedBytes for SourceKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// A cached lexical value together with the source it was computed from.
pub struct SourceCached<T> {
    source: Arc<str>,
    value: T,
}

impl<T> std::ops::Deref for SourceCached<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

fn cached_for<T: Send + Sync + 'static>(
    cache: &WalkCache<SourceKey, SourceCached<T>>,
    source: &str,
) -> Option<Arc<Accounted<SourceCached<T>>>> {
    cache
        .get(&SourceKey::of(source))
        .filter(|cached| &*cached.source == source)
}

fn keep_for<T: Send + Sync + 'static>(
    cache: &WalkCache<SourceKey, SourceCached<T>>,
    source: &str,
    value: T,
) -> Arc<Accounted<SourceCached<T>>> {
    cache.keep(
        SourceKey::of(source),
        SourceCached {
            source: Arc::from(source),
            value,
        },
    )
}

/// An estimate of one tree-sitter node's heap allocation. The library allocates
/// a tree's internal nodes separately, so a tree retains several times its
/// source; the cache charges the source plus this per node.
const TREE_SITTER_NODE_BYTES: usize = 80;

fn to_weight(bytes: usize) -> u32 {
    bytes.min(u32::MAX as usize) as u32
}

fn weigh_tree(_: &SourceKey, cached: &SourceCached<Option<Tree>>) -> u32 {
    let nodes = cached
        .value
        .as_ref()
        .map_or(0, |tree| tree.root_node().descendant_count());
    to_weight(
        cached
            .source
            .len()
            .saturating_add(nodes.saturating_mul(TREE_SITTER_NODE_BYTES)),
    )
}

fn weigh_scope_index(_: &SourceKey, cached: &SourceCached<RustLexicalScopeIndex>) -> u32 {
    let index = &cached.value;
    let names = index.items.keys().map(String::capacity).sum::<usize>();
    to_weight(
        cached
            .source
            .len()
            .saturating_add(brokk_bifrost_core::hash::map_of_vec_slot_bytes(
                &index.items,
            ))
            .saturating_add(names)
            .saturating_add(brokk_bifrost_core::hash::vec_slot_bytes(&index.modules)),
    )
}

fn weigh_use_statements(_: &SourceKey, cached: &SourceCached<Vec<RustUseStatement>>) -> u32 {
    // An import's identifier, alias and structured path are spelled inside its
    // snippet, so three times the snippet bounds its strings.
    let imports = cached
        .value
        .iter()
        .map(|statement| {
            brokk_bifrost_core::hash::vec_slot_bytes(&statement.imports).saturating_add(
                statement
                    .imports
                    .iter()
                    .map(|import| import.raw_snippet.capacity().saturating_mul(3))
                    .sum::<usize>(),
            )
        })
        .sum::<usize>();
    to_weight(
        cached
            .source
            .len()
            .saturating_add(brokk_bifrost_core::hash::vec_slot_bytes(&cached.value))
            .saturating_add(imports),
    )
}

pub fn parse_rust_tree_with(caches: &RustLexicalCaches, source: &str) -> Option<Tree> {
    RUST_TREE_PARSE_REQUESTS.fetch_add(1, Ordering::Relaxed);
    if let Some(cached) = cached_for(&caches.trees, source) {
        return cached.value.clone();
    }
    let parsed = parse_rust_tree_uncached(source);
    keep_for(&caches.trees, source, parsed.clone());
    parsed
}

pub fn rust_lexical_scope_index_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
) -> Arc<Accounted<SourceCached<RustLexicalScopeIndex>>> {
    debug_assert!(root.parent().is_none() && root.end_byte() <= source.len());
    if let Some(cached) = cached_for(&caches.scope_indexes, source) {
        return cached;
    }
    RUST_SCOPE_INDEX_BUILDS.fetch_add(1, Ordering::Relaxed);
    keep_for(
        &caches.scope_indexes,
        source,
        RustLexicalScopeIndex::new(root, source),
    )
}

/// Number of lexical scope indexes actually built since the last reset — the
/// complexity signal for the once-per-occurrence rebuild regression (public
/// issue #11), analogous to the parse counters above.
#[cfg(any(test, feature = "test-support"))]
pub fn rust_scope_index_build_count_for_test() -> usize {
    RUST_SCOPE_INDEX_BUILDS.load(Ordering::Relaxed)
}

pub(crate) fn parse_rust_tree_uncached(source: &str) -> Option<Tree> {
    RUST_TREE_PARSES.fetch_add(1, Ordering::Relaxed);
    RUST_TREE_PARSED_BYTES.fetch_add(source.len(), Ordering::Relaxed);
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

/// Parse only `[start, end)` of `source` as Rust via included ranges: node
/// byte/line positions match the original file exactly, and the lexer never
/// touches the prefix. This is issue #1015's item-macro reparse without the
/// padded whole-file copy, whose O(file) whitespace prefix made each reparse
/// cost seconds on large files (issue #1309's cold-start profile).
/// Deliberately unmemoized: the whole-source cache above keys on source text,
/// while a region parse is additionally keyed by position, and macro-interior
/// reparses happen once per invocation site during a file's analysis pass.
pub fn parse_rust_region_tree(source: &str, start: usize, end: usize) -> Option<Tree> {
    parse_rust_fragment_tree(end.saturating_sub(start), || {
        parse_source_region(&tree_sitter_rust::LANGUAGE.into(), source, start, end)
    })
}

/// Parse an AST-provided range without scanning the source prefix to recover
/// line/column positions for each embedded invocation.
pub(crate) fn parse_rust_range_tree(source: &str, range: tree_sitter::Range) -> Option<Tree> {
    parse_rust_fragment_tree(range.end_byte.saturating_sub(range.start_byte), || {
        parse_source_range_with_cancellation(
            &tree_sitter_rust::LANGUAGE.into(),
            source,
            range,
            None,
        )
    })
}

/// Parse several AST-delimited interiors without scanning their source prefixes.
pub(crate) fn parse_rust_included_ranges_tree(
    source: &str,
    ranges: &[tree_sitter::Range],
) -> Option<Tree> {
    assert!(
        !ranges.is_empty(),
        "an embedded item parse has at least one range"
    );
    let bytes = ranges
        .iter()
        .map(|range| range.end_byte - range.start_byte)
        .sum();
    parse_rust_fragment_tree(bytes, || {
        brokk_bifrost_core::analyzer::common::parse_source_with_cancellation(
            &tree_sitter_rust::LANGUAGE.into(),
            source,
            Some(ranges),
            None,
        )
    })
}

fn parse_rust_fragment_tree(
    parse_bytes: usize,
    parse: impl FnOnce() -> Option<Tree>,
) -> Option<Tree> {
    RUST_TREE_PARSE_REQUESTS.fetch_add(1, Ordering::Relaxed);
    RUST_TREE_PARSES.fetch_add(1, Ordering::Relaxed);
    RUST_TREE_PARSED_BYTES.fetch_add(parse_bytes, Ordering::Relaxed);
    parse()
}

/// Number of Rust source texts actually handed to tree-sitter since the last
/// reset — the complexity signal pinned by the issue #1219 regression tests.
#[cfg(any(test, feature = "test-support"))]
pub fn rust_tree_parse_count_for_test() -> usize {
    RUST_TREE_PARSES.load(Ordering::Relaxed)
}

/// Number of `parse_rust_tree` calls since the last reset, cache hits included.
#[cfg(any(test, feature = "test-support"))]
pub fn rust_tree_parse_request_count_for_test() -> usize {
    RUST_TREE_PARSE_REQUESTS.load(Ordering::Relaxed)
}

/// Source bytes actually handed to tree-sitter since the last reset. This is
/// the load-bearing complexity signal: re-parsing a whole file per reference
/// site and parsing one small token-tree fragment per reference site both grow
/// the *call* count, but only the former grows the byte count with file size.
#[cfg(any(test, feature = "test-support"))]
pub fn rust_tree_parsed_bytes_for_test() -> usize {
    RUST_TREE_PARSED_BYTES.load(Ordering::Relaxed)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_rust_tree_parse_counters_for_test() {
    RUST_TREE_PARSES.store(0, Ordering::Relaxed);
    RUST_TREE_PARSE_REQUESTS.store(0, Ordering::Relaxed);
    RUST_TREE_PARSED_BYTES.store(0, Ordering::Relaxed);
    RUST_SCOPE_INDEX_BUILDS.store(0, Ordering::Relaxed);
}

pub fn insert_rust_import_binding(binder: &mut ImportBinder, import: &ImportInfo) {
    if matches!(
        rust_import_binding_name(import),
        RustImportBindingName::Unnamed
    ) {
        return;
    }
    let path = import
        .path
        .as_ref()
        .expect("Rust import binding requires a structured path");
    insert_rust_import_binding_fields(
        binder,
        path.kind,
        &path.segments,
        import.is_wildcard,
        import.is_global,
        import.alias.as_deref(),
        import.identifier.as_deref(),
    );
}

pub(crate) fn insert_rust_source_import_binding(
    binder: &mut ImportBinder,
    import: &SourceImportFact,
) {
    if import.alias.as_deref() == Some("_") {
        return;
    }
    let path = import
        .path
        .as_ref()
        .expect("Rust source imports have structured paths");
    insert_rust_import_binding_fields(
        binder,
        path.kind,
        &path.segments,
        import.is_wildcard,
        import.is_global,
        import.alias.as_deref(),
        import.identifier.as_deref(),
    );
}

fn insert_rust_import_binding_fields(
    binder: &mut ImportBinder,
    path_kind: Option<StructuredImportPathKind>,
    segments: &[String],
    is_wildcard: bool,
    is_global: bool,
    alias: Option<&str>,
    identifier: Option<&str>,
) {
    if path_kind == Some(StructuredImportPathKind::ExternCrate) {
        return;
    }
    assert!(!segments.is_empty(), "Rust import path must have a segment");
    let render_module = |segments: &[String]| {
        let module = segments.join("::");
        if is_global && !module.is_empty() {
            format!("::{module}")
        } else {
            module
        }
    };
    if is_wildcard {
        let module_specifier = render_module(segments);
        if module_specifier.is_empty() {
            return;
        }
        binder.bindings.insert(
            format!("*:{module_specifier}"),
            ImportBinding {
                module_specifier,
                namespace_imported_module: None,
                kind: ImportKind::Glob,
                imported_name: None,
            },
        );
        return;
    }
    let (module_segments, imported_name) = if segments.len() > 1 || is_global {
        let (imported_name, module_segments) = segments
            .split_last()
            .expect("non-empty structured Rust import path");
        (module_segments, imported_name.clone())
    } else {
        // A single unanchored segment aliases a whole namespace, including
        // normalized `use forc_pkg::{self as pkg}` (issue #1089).
        if let Some(alias) = alias {
            let module = &segments[0];
            if !alias.is_empty() && !module.is_empty() {
                binder.bindings.insert(
                    alias.to_string(),
                    ImportBinding {
                        module_specifier: module.clone(),
                        namespace_imported_module: None,
                        kind: ImportKind::Namespace,
                        imported_name: None,
                    },
                );
            }
        }
        return;
    };
    let module_specifier = render_module(module_segments);
    let local_name = alias
        .map(str::to_string)
        .or_else(|| identifier.map(str::to_string))
        .unwrap_or_else(|| imported_name.clone());
    let (local_name, kind, imported_name, module_specifier) = if imported_name == "self" {
        let namespace_name = module_segments.last().cloned().unwrap_or_default();
        (
            namespace_name,
            ImportKind::Namespace,
            None,
            module_specifier,
        )
    } else if alias.is_none()
        && imported_name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch == '_')
    {
        (
            local_name,
            ImportKind::Namespace,
            None,
            format!("{module_specifier}::{imported_name}"),
        )
    } else {
        (
            local_name,
            ImportKind::Named,
            Some(imported_name),
            module_specifier,
        )
    };

    binder.bindings.insert(
        local_name,
        ImportBinding {
            module_specifier,
            namespace_imported_module: None,
            kind,
            imported_name,
        },
    );
}

/// One `use` declaration with the ranges that gate its visibility and its
/// parsed imports, in source-traversal order.
struct RustUseStatement {
    imports: Vec<ImportInfo>,
    mod_range: Option<(usize, usize)>,
    scope_range: Option<(usize, usize)>,
}

/// The file package plus the inline `mod` path enclosing `byte` — the
/// lexical package a nested import's `self`/`super` specifiers resolve
/// against (`super` from `mod tests` is the file's own module, not the
/// file's parent).
pub fn lexical_package_at(file_package: &str, source: &str, byte: usize) -> String {
    // Standalone source has no lexical cache owner.
    let Some(tree) = parse_rust_tree_uncached(source) else {
        return file_package.to_string();
    };
    lexical_package_in_tree(file_package, tree.root_node(), source, byte)
}

/// Derive the lexical module identity from a tree already held by a query.
pub fn lexical_package_in_tree(
    file_package: &str,
    root: Node<'_>,
    source: &str,
    byte: usize,
) -> String {
    let mut modules = Vec::new();
    let mut current = root;
    loop {
        let mut cursor = current.walk();
        let next = current
            .named_children(&mut cursor)
            .find(|child| child.start_byte() <= byte && byte < child.end_byte());
        let Some(child) = next else {
            break;
        };
        if child.kind() == "mod_item"
            && let Some(name_node) = child.child_by_field_name("name")
        {
            let name = crate::declarations::rust_node_text(name_node, source).trim();
            if !name.is_empty() {
                modules.push(name.to_string());
            }
        }
        current = child;
    }
    if file_package.is_empty() {
        modules.join(".")
    } else if modules.is_empty() {
        file_package.to_string()
    } else {
        format!("{}.{}", file_package, modules.join("."))
    }
}

pub(crate) fn use_statement_visible_at(
    reference_byte: usize,
    reference_mod_range: Option<(usize, usize)>,
    mod_range: Option<(usize, usize)>,
    scope_range: Option<(usize, usize)>,
) -> bool {
    if mod_range != reference_mod_range {
        return false;
    }
    let Some((start, end)) = scope_range else {
        return true;
    };
    start <= reference_byte && reference_byte < end
}

pub fn enclosing_mod_item_range_at(node: Node<'_>, byte: usize) -> Option<(usize, usize)> {
    let mut candidate = None;
    let mut current = node;
    loop {
        let mut cursor = current.walk();
        let mut next = None;
        for child in current.named_children(&mut cursor) {
            if child.start_byte() <= byte && byte < child.end_byte() {
                if child.kind() == "mod_item" {
                    candidate = Some((child.start_byte(), child.end_byte()));
                }
                next = Some(child);
                break;
            }
        }
        let Some(child) = next else {
            return candidate;
        };
        current = child;
    }
}

pub(crate) fn lexical_scope_kind(kind: &str) -> bool {
    matches!(
        kind,
        "block" | "function_item" | "impl_item" | "trait_item" | "mod_item"
    )
}

#[derive(Clone, Copy)]
struct ItemVisibility {
    declaration_start: usize,
    start: usize,
    end: usize,
    module: Option<(usize, usize)>,
}

/// Position-aware Rust item visibility for one parsed file.
pub struct RustLexicalScopeIndex {
    items: HashMap<String, Vec<ItemVisibility>>,
    modules: Vec<(usize, usize)>,
}

impl RustLexicalScopeIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut index = Self {
            items: HashMap::default(),
            modules: Vec::new(),
        };
        let mut stack = vec![(root, None, false, root.start_byte(), root.end_byte())];
        while let Some((raw_node, module, associated_type, scope_start, scope_end)) = stack.pop() {
            let mut child_module = module;
            let node = unwrap_attributes(raw_node);
            let child_associated_type = match node.kind() {
                "impl_item" | "trait_item" => true,
                "function_item" | "mod_item" | "source_file" => false,
                _ => associated_type,
            };
            let mut child_scope_start = scope_start;
            let mut child_scope_end = scope_end;
            match node.kind() {
                "function_item" => {
                    index.add_item_binding(node, scope_start, scope_end, source, module);
                    if let Some(body) = node.child_by_field_name("body") {
                        child_scope_end = body.end_byte();
                    }
                }
                "function_signature_item" | "static_item" | "const_item" => {
                    index.add_item_binding(node, scope_start, scope_end, source, module);
                }
                "block" | "declaration_list" => {
                    child_scope_start = node.start_byte();
                    child_scope_end = node.end_byte();
                }
                "type_item" if !associated_type => {
                    index.add_item_binding(node, scope_start, scope_end, source, module);
                }
                "struct_item" | "enum_item" | "union_item" | "trait_item" | "mod_item" => {
                    index.add_item_binding(node, scope_start, scope_end, source, module);
                    if node.kind() == "mod_item" {
                        let module_range = (node.start_byte(), node.end_byte());
                        index.modules.push(module_range);
                        child_module = Some(module_range);
                    }
                }
                _ => {}
            }

            let mut cursor = node.walk();
            let children: Vec<_> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev().map(|child| {
                (
                    child,
                    child_module,
                    child_associated_type,
                    child_scope_start,
                    child_scope_end,
                )
            }));
        }
        index
    }

    pub fn item_bound_at(&self, name: &str, byte: usize) -> bool {
        self.item_visible_at(name, byte, |_| true)
    }

    /// A conservative shadow check including items in every enclosing scope.
    pub fn item_bound_in_enclosing_scope(&self, name: &str, byte: usize) -> bool {
        self.items.get(name).is_some_and(|items| {
            items
                .iter()
                .any(|item| item.start <= byte && byte < item.end)
        })
    }

    /// Whether this exact declaration is visible, rather than another item
    /// of the same spelling in a sibling module or lexical scope.
    pub fn item_declaration_visible_at(
        &self,
        name: &str,
        declaration_start: usize,
        byte: usize,
    ) -> bool {
        self.item_visible_at(name, byte, |item| {
            item.declaration_start == declaration_start
        })
    }

    fn item_visible_at(
        &self,
        name: &str,
        byte: usize,
        predicate: impl Fn(&ItemVisibility) -> bool,
    ) -> bool {
        let module = self
            .modules
            .iter()
            .copied()
            .filter(|(start, end)| *start <= byte && byte < *end)
            .min_by_key(|(start, end)| end - start);
        self.items.get(name).is_some_and(|items| {
            items.iter().any(|item| {
                predicate(item) && item.module == module && item.start <= byte && byte < item.end
            })
        })
    }

    fn add_item_binding(
        &mut self,
        item: Node<'_>,
        start: usize,
        end: usize,
        source: &str,
        module: Option<(usize, usize)>,
    ) {
        let Some(name) = item.child_by_field_name("name") else {
            return;
        };
        let name = crate::declarations::rust_node_text(name, source).trim();
        if name.is_empty() {
            return;
        }
        self.items
            .entry(name.to_string())
            .or_default()
            .push(ItemVisibility {
                declaration_start: item.start_byte(),
                start,
                end,
                module,
            });
    }
}

/// End of the successful body and later condition-chain clauses.
#[doc(hidden)]
pub fn let_condition_visibility_end(mut node: Node<'_>) -> Option<usize> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "if_expression" | "while_expression") {
            return parent
                .child_by_field_name("consequence")
                .or_else(|| parent.child_by_field_name("body"))
                .map(|body| body.end_byte());
        }
        if !matches!(parent.kind(), "let_chain" | "parenthesized_expression") {
            return None;
        }
        node = parent;
    }
    None
}

// #5911: aliases and conditional std ownership must select the same type
// binding at the actual RHS site, rather than share only a spelling.
#[derive(Debug)]
pub(crate) enum RustTypeHead<'tree> {
    Item(Node<'tree>),
    Import {
        path: Vec<String>,
        declaration: Node<'tree>,
    },
    Unbound,
    Unknown,
}

fn is_type_namespace_item(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "struct_item" | "enum_item" | "union_item" | "trait_item" | "type_item" | "mod_item"
    )
}

// Unknown attribute macros may introduce other names in their owning scope.
fn type_scope_attributes_known_bounded<F, E>(
    node: Node<'_>,
    source: &str,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    for attribute in outer_attributes(node) {
        charge(1)?;
        let path = attribute
            .named_child(0)
            .and_then(|attribute| attribute.named_child(0));
        let Some(path) = path.filter(|path| path.kind() == "identifier") else {
            return Ok(false);
        };
        match crate::declarations::rust_node_text(path, source) {
            "cfg" | "inline" | "doc" | "allow" | "warn" | "deny" | "forbid" | "expect"
            | "must_use" | "cold" | "track_caller" | "deprecated" | "repr" | "non_exhaustive" => {}
            "test" => {
                if !rust_test_attribute_unshadowed_bounded(
                    node.parent().unwrap_or(node),
                    source,
                    charge,
                )? {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// Built-in `test` is inert only when no local macro, named import, or glob
/// import can claim its attribute name. This source-only scope proof is shared
/// with the structural binding-access producer.
pub(crate) fn rust_test_attribute_unshadowed_bounded<F, E>(
    node: Node<'_>,
    source: &str,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let mut parent = Some(node);
    while let Some(scope) = parent {
        if !rust_test_scope_unshadowed_bounded(scope, source, charge)? {
            return Ok(false);
        }
        parent = scope.parent();
    }
    Ok(true)
}

pub(crate) fn rust_test_scope_unshadowed_bounded<F, E>(
    scope: Node<'_>,
    source: &str,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    charge(1)?;
    let mut cursor = scope.walk();
    for raw in scope.named_children(&mut cursor) {
        charge(1)?;
        let item = unwrap_attributes(raw);
        // An item invocation can add a named import or definition in this scope.
        if rust_item_macro_invocation(item) {
            return Ok(false);
        }
        if item.kind() == "macro_definition"
            && item.child_by_field_name("name").is_some_and(|name| {
                brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(name, source),
                ) == "test"
            })
        {
            return Ok(false);
        }
        if item.kind() == "use_declaration" {
            for import in crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
                item,
                source,
                &mut *charge,
            )? {
                charge(1)?;
                if !import.import.module_self
                    && match import.import.binding_name() {
                        RustImportBindingName::Glob => rust_glob_may_shadow_test(
                            scope,
                            import.import.path(),
                            source,
                            charge,
                            &mut std::collections::HashSet::new(),
                        )?,
                        RustImportBindingName::Named(name) => {
                            crate::imports::rust_binding_name_matches(&name, "test")
                        }
                        RustImportBindingName::Unnamed => false,
                    }
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

pub(crate) fn rust_item_macro_invocation(item: Node<'_>) -> bool {
    item.kind() == "macro_invocation"
        || (item.kind() == "expression_statement"
            && item
                .named_child(0)
                .is_some_and(|child| child.kind() == "macro_invocation"))
}

/// A local glob contributes `test` only if its file-local target does. An
/// external or unresolved target is opaque because it may export an attribute
/// macro. Cycles through local globs add no new names on a repeated scope.
fn rust_glob_may_shadow_test<F, E>(
    site_scope: Node<'_>,
    path: &[String],
    source: &str,
    charge: &mut F,
    visited: &mut std::collections::HashSet<usize>,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let mut pending = vec![(site_scope, path.to_vec())];
    while let Some((scope, path)) = pending.pop() {
        let Some(target) = rust_local_glob_scope(scope, &path, source, charge)? else {
            return Ok(true);
        };
        if !visited.insert(target.id()) {
            continue;
        }
        let mut cursor = target.walk();
        for raw in target.named_children(&mut cursor) {
            charge(1)?;
            let item = unwrap_attributes(raw);
            // The expansion may export `test`, even when no written item does.
            if rust_item_macro_invocation(item) {
                return Ok(true);
            }
            if item.child_by_field_name("name").is_some_and(|name| {
                brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(name, source),
                ) == "test"
            }) {
                return Ok(true);
            }
            if item.kind() != "use_declaration" {
                continue;
            }
            for import in crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
                item,
                source,
                &mut *charge,
            )? {
                charge(1)?;
                match import.import.binding_name() {
                    RustImportBindingName::Named(name)
                        if crate::imports::rust_binding_name_matches(&name, "test") =>
                    {
                        return Ok(true);
                    }
                    RustImportBindingName::Glob => {
                        pending.push((target, import.import.path().to_vec()));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(false)
}

fn rust_local_glob_scope<'tree, F, E>(
    site_scope: Node<'tree>,
    path: &[String],
    source: &str,
    charge: &mut F,
) -> Result<Option<Node<'tree>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let mut current = Some(site_scope);
    let module = loop {
        let Some(node) = current else { return Ok(None) };
        charge(1)?;
        if rust_lexical_scope_is_module_boundary(node) {
            break node;
        }
        current = node.parent();
    };
    let mut scope = module;
    let mut segments = path.iter().map(String::as_str).peekable();
    match segments.peek().copied() {
        Some("crate") => {
            // This source-only proof has no crate identity. A source_file root
            // can be an out-of-line module, not the crate root.
            return Ok(None);
        }
        Some("self") => {
            segments.next();
        }
        Some("super") => {
            while segments.peek().copied() == Some("super") {
                segments.next();
                let Some(parent) = scope.parent().and_then(|node| node.parent()) else {
                    return Ok(None);
                };
                scope = parent;
            }
        }
        _ => {}
    }
    for segment in segments {
        let mut found = None;
        let mut seen = false;
        let mut cursor = scope.walk();
        for raw in scope.named_children(&mut cursor) {
            charge(1)?;
            let item = unwrap_attributes(raw);
            if item.kind() == "mod_item"
                && item.child_by_field_name("name").is_some_and(|name| {
                    brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                        crate::declarations::rust_node_text(name, source),
                    ) == segment
                })
            {
                if seen {
                    return Ok(None);
                }
                seen = true;
                found = item.child_by_field_name("body");
            }
        }
        let Some(next) = found else { return Ok(None) };
        scope = next;
    }
    Ok(Some(scope))
}

// At a selected site's ancestors, activation attributes need a selected
// configuration; inspecting only their head avoids an unmetered cfg parse.
fn type_site_attributes_unconditional_bounded<F, E>(
    node: Node<'_>,
    source: &str,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    for attribute in outer_attributes(node) {
        charge(1)?;
        let path = attribute
            .named_child(0)
            .and_then(|attribute| attribute.named_child(0));
        if !path.is_some_and(|path| {
            matches!(
                crate::declarations::rust_node_text(path, source),
                "inline" | "doc"
            )
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

// Both selectors consume the same structured scope walk. Selection rules
// remain separate: a type may be selected at one tier, while a pattern binder
// needs complete absence of a competing value throughout the relevant scopes.
enum RustLexicalSelectionEvent<'tree, 'projection> {
    Ancestor(Node<'tree>),
    Parameter(Node<'tree>),
    Item(Node<'tree>),
    Import(
        Node<'tree>,
        &'projection crate::imports::RustImportProjectionLeaf<'tree>,
    ),
    ScopeEnd,
}

enum RustLexicalSelection<T> {
    Complete,
    Selected(T),
    Unknown,
}

fn visit_rust_lexical_selection_bounded<'tree, F, E, T>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    charge: &mut F,
    mut select: impl for<'projection> FnMut(
        RustLexicalSelectionEvent<'tree, 'projection>,
        &mut F,
    ) -> Result<std::ops::ControlFlow<T>, E>,
) -> Result<RustLexicalSelection<T>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    let scopes = match rust_lexical_scope_chain_bounded(root, source, site, charge, &mut select)? {
        ControlFlow::Continue(scopes) => scopes,
        ControlFlow::Break(selection) => return Ok(selection),
    };
    for node in &scopes {
        if !rust_scope_inner_attributes_known_bounded(*node, source, charge)? {
            return Ok(RustLexicalSelection::Unknown);
        }
    }
    for scope in scopes {
        if let ControlFlow::Break(selection) =
            visit_rust_lexical_scope_bounded(scope, source, charge, &mut select)?
        {
            return Ok(selection);
        }
        if rust_lexical_scope_is_module_boundary(scope) {
            break;
        }
    }
    charge(0)?;
    Ok(RustLexicalSelection::Complete)
}

/// The site and its ancestors up to `root`, innermost first, after checking
/// that none of them makes the selection opaque.
fn rust_lexical_scope_chain_bounded<'tree, F, E, T>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    charge: &mut F,
    select: &mut impl for<'projection> FnMut(
        RustLexicalSelectionEvent<'tree, 'projection>,
        &mut F,
    ) -> Result<std::ops::ControlFlow<T>, E>,
) -> Result<std::ops::ControlFlow<RustLexicalSelection<T>, Vec<Node<'tree>>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    charge(0)?;
    let mut current = Some(site);
    let mut scopes = Vec::new();
    while let Some(node) = current {
        charge(1)?;
        if node.is_error() || node.is_missing() || (node.has_error() && node.id() == site.id()) {
            return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
        }
        if matches!(node.kind(), "macro_invocation" | "macro_definition") {
            return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
        }
        if !type_site_attributes_unconditional_bounded(node, source, charge)? {
            return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
        }
        if let ControlFlow::Break(value) =
            select(RustLexicalSelectionEvent::Ancestor(node), charge)?
        {
            return Ok(ControlFlow::Break(RustLexicalSelection::Selected(value)));
        }
        scopes.push(node);
        if node.id() == root.id() {
            break;
        }
        current = node.parent();
    }
    if scopes.last().is_none_or(|node| node.id() != root.id()) {
        return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
    }
    Ok(ControlFlow::Continue(scopes))
}

/// Whether the inner attributes of one node on the scope chain leave its
/// body's selection known. The answer does not depend on the use site.
fn rust_scope_inner_attributes_known_bounded<F, E>(
    node: Node<'_>,
    source: &str,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    charge(1)?;
    // Inner attributes belong to the actual owner body, including
    // module declaration lists, not just the source-file root.
    if matches!(node.kind(), "source_file" | "declaration_list") {
        let mut cursor = node.walk();
        for attribute in node.named_children(&mut cursor) {
            charge(1)?;
            if attribute.kind() != "inner_attribute_item" {
                continue;
            }
            let path = attribute
                .named_child(0)
                .and_then(|attribute| attribute.named_child(0));
            if !path.is_some_and(|path| {
                matches!(
                    crate::declarations::rust_node_text(path, source),
                    "allow" | "warn" | "deny" | "forbid" | "doc"
                )
            }) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Visit one scope's generic parameters, items and imports, then its end.
/// The events depend only on the scope, not on the use site inside it.
fn visit_rust_lexical_scope_bounded<'tree, F, E, T>(
    scope: Node<'tree>,
    source: &str,
    charge: &mut F,
    select: &mut impl for<'projection> FnMut(
        RustLexicalSelectionEvent<'tree, 'projection>,
        &mut F,
    ) -> Result<std::ops::ControlFlow<T>, E>,
) -> Result<std::ops::ControlFlow<RustLexicalSelection<T>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    charge(1)?;
    if let Some(parameters) = scope.child_by_field_name("type_parameters") {
        let mut cursor = parameters.walk();
        for raw in parameters.named_children(&mut cursor) {
            charge(1)?;
            let parameter = unwrap_attributes(raw);
            if raw.has_error()
                || raw.is_missing()
                || !type_site_attributes_unconditional_bounded(parameter, source, charge)?
            {
                return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
            }
            if let ControlFlow::Break(value) =
                select(RustLexicalSelectionEvent::Parameter(parameter), charge)?
            {
                return Ok(ControlFlow::Break(RustLexicalSelection::Selected(value)));
            }
        }
    }
    if !matches!(scope.kind(), "block" | "declaration_list" | "source_file") {
        return Ok(ControlFlow::Continue(()));
    }
    let mut cursor = scope.walk();
    for raw in scope.named_children(&mut cursor) {
        charge(1)?;
        let item = unwrap_attributes(raw);
        if raw.has_error()
            || raw.is_missing()
            || item.kind() == "macro_invocation"
            || (item.kind() == "expression_statement"
                && item
                    .named_child(0)
                    .is_some_and(|child| child.kind() == "macro_invocation"))
            || !type_scope_attributes_known_bounded(item, source, charge)?
        {
            return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
        }
        if let ControlFlow::Break(value) = select(RustLexicalSelectionEvent::Item(item), charge)? {
            return Ok(ControlFlow::Break(RustLexicalSelection::Selected(value)));
        }
        if item.kind() == "extern_crate_declaration" {
            // Tree-local selection does not know Cargo crate identities.
            return Ok(ControlFlow::Break(RustLexicalSelection::Unknown));
        }
        if item.kind() == "use_declaration" {
            for leaf in crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
                item,
                source,
                &mut *charge,
            )? {
                charge(1)?;
                charge(leaf.import.path().len())?;
                if let ControlFlow::Break(value) =
                    select(RustLexicalSelectionEvent::Import(item, &leaf), charge)?
                {
                    return Ok(ControlFlow::Break(RustLexicalSelection::Selected(value)));
                }
            }
        }
    }
    charge(0)?;
    if let ControlFlow::Break(value) = select(RustLexicalSelectionEvent::ScopeEnd, charge)? {
        return Ok(ControlFlow::Break(RustLexicalSelection::Selected(value)));
    }
    Ok(ControlFlow::Continue(()))
}

/// Parent module imports and items are not inherited implicitly.
fn rust_lexical_scope_is_module_boundary(scope: Node<'_>) -> bool {
    scope.kind() == "source_file"
        || (scope.kind() == "declaration_list"
            && scope
                .parent()
                .is_some_and(|parent| parent.kind() == "mod_item"))
}

/// Memo of the site-independent parts of [`rust_type_head_at_bounded`] for
/// one syntax tree: each scope-chain node's inner-attribute check, and which
/// scopes leave a name unbound or make it unknown. A caller asking about many
/// sites in one module would otherwise rescan the module's items and reparse
/// its imports at every site. A scope that selects a declaration is not
/// memoized, so the memo holds no nodes. Each entry keeps the work its scan
/// charged, and a hit charges that work again, so a capped caller runs out of
/// budget exactly where it would without the memo. Keys are node ids of one
/// tree, so the memo must not outlive or be shared beyond that tree.
#[derive(Debug, Default)]
pub(crate) struct RustTypeHeadMemo {
    inner_attributes_known: std::cell::RefCell<HashMap<usize, (bool, usize)>>,
    unselected_scopes: std::cell::RefCell<HashMap<(usize, String), (UnselectedScope, usize)>>,
}

/// A scope's outcome for a name when it selects no declaration.
#[derive(Clone, Copy, Debug)]
enum UnselectedScope {
    /// The scope does not bind the name; the search continues outward.
    Unbound,
    Unknown,
}

/// Charges recorded by a memoized scan. The scan runs to completion and its
/// total is charged to the caller afterwards.
fn record_charges(
    work: &mut usize,
) -> impl FnMut(usize) -> Result<(), std::convert::Infallible> + '_ {
    move |charged| {
        *work += charged;
        Ok(())
    }
}

/// Select a type head in the existing lexical scope chain. Items have the
/// whole containing scope (including before their declaration). Generic type
/// parameters and unknown imports are barriers, never prelude evidence.
/// Every inspected node is charged to the caller, including nodes whose scan
/// `memo` answers.
pub(crate) fn rust_type_head_at_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    name: &str,
    memo: &RustTypeHeadMemo,
    charge: &mut F,
) -> Result<RustTypeHead<'tree>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    let scopes = match rust_lexical_scope_chain_bounded(root, source, site, charge, &mut |_, _| {
        Ok(ControlFlow::<RustTypeHead<'tree>>::Continue(()))
    })? {
        ControlFlow::Continue(scopes) => scopes,
        ControlFlow::Break(_) => return Ok(RustTypeHead::Unknown),
    };
    for node in &scopes {
        let cached = memo
            .inner_attributes_known
            .borrow()
            .get(&node.id())
            .copied();
        let (known, work) = cached.unwrap_or_else(|| {
            let mut work = 0;
            let Ok(known) = rust_scope_inner_attributes_known_bounded(
                *node,
                source,
                &mut record_charges(&mut work),
            );
            memo.inner_attributes_known
                .borrow_mut()
                .insert(node.id(), (known, work));
            (known, work)
        });
        charge(work)?;
        if !known {
            return Ok(RustTypeHead::Unknown);
        }
    }
    for scope in scopes {
        let key = (scope.id(), name.to_string());
        let cached = memo.unselected_scopes.borrow().get(&key).copied();
        let head = match cached {
            Some((unselected, work)) => {
                charge(work)?;
                match unselected {
                    UnselectedScope::Unbound => None,
                    UnselectedScope::Unknown => Some(RustTypeHead::Unknown),
                }
            }
            None => {
                let mut work = 0;
                let Ok(head) = rust_scope_type_head_bounded(
                    scope,
                    source,
                    name,
                    &mut record_charges(&mut work),
                );
                let unselected = match head {
                    None => Some(UnselectedScope::Unbound),
                    Some(RustTypeHead::Unknown) => Some(UnselectedScope::Unknown),
                    Some(_) => None,
                };
                if let Some(unselected) = unselected {
                    memo.unselected_scopes
                        .borrow_mut()
                        .insert(key, (unselected, work));
                }
                charge(work)?;
                head
            }
        };
        if let Some(head) = head {
            return Ok(head);
        }
        if rust_lexical_scope_is_module_boundary(scope) {
            break;
        }
    }
    charge(0)?;
    Ok(RustTypeHead::Unbound)
}

/// The type head that one scope selects for `name`, or `None` when the scope
/// does not bind it and the search continues outward.
fn rust_scope_type_head_bounded<'tree, F, E>(
    scope: Node<'tree>,
    source: &str,
    name: &str,
    charge: &mut F,
) -> Result<Option<RustTypeHead<'tree>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    let mut candidates = Vec::new();
    let selection =
        visit_rust_lexical_scope_bounded(scope, source, charge, &mut |event, charge| {
            match event {
                RustLexicalSelectionEvent::Ancestor(_) => {}
                RustLexicalSelectionEvent::Parameter(parameter) => {
                    if parameter.kind() == "type_parameter"
                        && parameter.child_by_field_name("name").is_some_and(|node| {
                            crate::declarations::rust_node_text(node, source) == name
                        })
                    {
                        return Ok(ControlFlow::Break(RustTypeHead::Unknown));
                    }
                }
                RustLexicalSelectionEvent::Item(item) => {
                    if is_type_namespace_item(item)
                        && item.child_by_field_name("name").is_some_and(|node| {
                            crate::declarations::rust_node_text(node, source) == name
                        })
                    {
                        if item.has_error() || outer_attributes(item).next().is_some() {
                            return Ok(ControlFlow::Break(RustTypeHead::Unknown));
                        }
                        charge(1)?;
                        candidates.push(RustTypeHead::Item(item));
                    }
                }
                RustLexicalSelectionEvent::Import(item, leaf) => match leaf.import.binding_name() {
                    RustImportBindingName::Glob => {
                        return Ok(ControlFlow::Break(RustTypeHead::Unknown));
                    }
                    RustImportBindingName::Named(binding)
                        if crate::imports::rust_binding_name_matches(&binding, name) =>
                    {
                        if item.has_error() || outer_attributes(item).next().is_some() {
                            return Ok(ControlFlow::Break(RustTypeHead::Unknown));
                        }
                        for segment in leaf.import.path() {
                            charge(1)?;
                            charge(segment.len())?;
                        }
                        charge(1)?;
                        candidates.push(RustTypeHead::Import {
                            path: leaf.import.path().to_vec(),
                            declaration: item,
                        });
                    }
                    _ => {}
                },
                RustLexicalSelectionEvent::ScopeEnd => match candidates.len() {
                    0 => {}
                    1 => {
                        return Ok(ControlFlow::Break(candidates.pop().expect("one candidate")));
                    }
                    _ => return Ok(ControlFlow::Break(RustTypeHead::Unknown)),
                },
            }
            Ok(ControlFlow::Continue(()))
        })?;
    Ok(match selection {
        ControlFlow::Continue(()) => None,
        ControlFlow::Break(RustLexicalSelection::Selected(head)) => Some(head),
        ControlFlow::Break(RustLexicalSelection::Unknown) => Some(RustTypeHead::Unknown),
        ControlFlow::Break(RustLexicalSelection::Complete) => {
            unreachable!("a single scope visit never completes the chain")
        }
    })
}

/// Prove that a flat let-pattern identifier introduces a binding, independently
/// of tentative local inventories. Bare constants and unit constructors have
/// the same syntax, so #5911 tuple initialization needs complete value-scope
/// absence before it may publish any component establishment. False withholds
/// proof; it does not establish that a particular constant or import resolved.
/// Ordinary local/parameter names do not conflict with legal rebinding.
pub fn rust_pattern_identifier_binding_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    pattern: Node<'tree>,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    charge(0)?;
    charge(1)?;
    if root.kind() != "source_file" || pattern.is_missing() || pattern.has_error() {
        return Ok(false);
    }
    let name = match pattern.kind() {
        "identifier" => pattern,
        "mut_pattern" => {
            let mut name = None;
            let mut mutable = false;
            let mut cursor = pattern.walk();
            for child in pattern.named_children(&mut cursor) {
                charge(1)?;
                match child.kind() {
                    "line_comment" | "block_comment" => {}
                    "mutable_specifier" if !mutable => mutable = true,
                    "identifier" if name.is_none() => name = Some(child),
                    _ => return Ok(false),
                }
            }
            let Some(name) = name.filter(|_| mutable) else {
                return Ok(false);
            };
            name
        }
        _ => return Ok(false),
    };
    // Validate the actual pattern field, not merely an identifier's spelling.
    // Only the supported flat let/tuple envelope is admitted here.
    let mut owner = pattern;
    if pattern.kind() == "identifier"
        && let Some(parent) = owner
            .parent()
            .filter(|parent| parent.kind() == "mut_pattern")
    {
        charge(1)?;
        owner = parent;
    }
    if let Some(parent) = owner
        .parent()
        .filter(|parent| parent.kind() == "tuple_pattern")
    {
        charge(1)?;
        owner = parent;
    }
    charge(1)?;
    if !owner.parent().is_some_and(|parent| {
        parent.kind() == "let_declaration"
            && parent
                .child_by_field_name("pattern")
                .is_some_and(|node| node.id() == owner.id())
    }) {
        return Ok(false);
    }
    let name = crate::declarations::rust_node_text(name, source);
    if crate::prelude::rust_prelude_candidate(name, crate::prelude::RustPreludeNamespace::Value) {
        return Ok(false);
    }
    let selection =
        visit_rust_lexical_selection_bounded(root, source, pattern, charge, |event, _charge| {
            let conflict = match event {
                RustLexicalSelectionEvent::Ancestor(node) => {
                    // Associated lookup and its inherited trait names require
                    // evidence beyond this same-source lexical proof.
                    matches!(node.kind(), "impl_item" | "trait_item")
                }
                RustLexicalSelectionEvent::Parameter(parameter) => {
                    parameter.kind() == "const_parameter"
                        && parameter.child_by_field_name("name").is_some_and(|node| {
                            crate::declarations::rust_node_text(node, source) == name
                        })
                }
                RustLexicalSelectionEvent::Item(item) => {
                    item.kind() == "macro_definition"
                        || (matches!(item.kind(), "const_item" | "static_item" | "struct_item")
                            && item.child_by_field_name("name").is_some_and(|node| {
                                crate::declarations::rust_node_text(node, source) == name
                            }))
                }
                RustLexicalSelectionEvent::Import(_, leaf) => match leaf.import.binding_name() {
                    RustImportBindingName::Glob => true,
                    RustImportBindingName::Named(binding) => {
                        crate::imports::rust_binding_name_matches(&binding, name)
                    }
                    RustImportBindingName::Unnamed => false,
                },
                RustLexicalSelectionEvent::ScopeEnd => false,
            };
            if conflict {
                Ok(ControlFlow::Break(()))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })?;
    charge(0)?;
    Ok(matches!(selection, RustLexicalSelection::Complete))
}

/// Classify a bare pattern name. Named imports are unresolved here because
/// their targets may be constants, constructors, or ordinary names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustPatternName {
    ValueItem,
    Binding,
    Unknown,
}

/// The item selected by a value-position bare name in this source file.
/// Imports remain unknown because this file does not know their target kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustValueName<'tree> {
    Constant,
    Callable(Node<'tree>),
    PreludeCallable,
    Static,
    Unknown,
}

fn rust_is_associated_member(item: Node<'_>) -> bool {
    crate::syntax::parent_outside_attributes(item).is_some_and(|scope| {
        scope.kind() == "declaration_list"
            && scope
                .parent()
                .is_some_and(|owner| matches!(owner.kind(), "impl_item" | "trait_item"))
    })
}

/// Select a same-file type item at a value path's owner site. Imports,
/// shadowing parameters, ambiguity, and opaque syntax do not prove an item.
pub fn rust_value_owner_item_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    name: &str,
    charge: &mut F,
) -> Result<Option<Node<'tree>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    Ok(
        match rust_type_head_at_bounded(
            root,
            source,
            site,
            name,
            &RustTypeHeadMemo::default(),
            charge,
        )? {
            RustTypeHead::Item(item) => Some(item),
            _ => None,
        },
    )
}

/// Whether the primitive type name written at `ty` names the built-in type
/// there: no item or import in scope shadows it.
pub fn rust_primitive_type_is_unbound_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    ty: Node<'tree>,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let name = crate::declarations::rust_node_text(ty, source);
    Ok(matches!(
        rust_type_head_at_bounded(root, source, ty, name, &RustTypeHeadMemo::default(), charge)?,
        RustTypeHead::Unbound
    ))
}

pub fn rust_value_name_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    charge: &mut F,
) -> Result<RustValueName<'tree>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    let text = crate::declarations::rust_node_text(site, source);
    let selected = visit_rust_lexical_selection_bounded(
        root,
        source,
        site,
        charge,
        |event, charge| {
            let classification = match event {
                RustLexicalSelectionEvent::Parameter(parameter)
                    if parameter.kind() == "const_parameter"
                        && parameter.child_by_field_name("name").is_some_and(|name| {
                            crate::declarations::rust_node_text(name, source) == text
                        }) =>
                {
                    Some(RustValueName::Unknown)
                }
                // `extern { fn f(); static S: T; }` declares its members in
                // the enclosing scope's value namespace. Their targets are not
                // modeled here, so such a member occupies the name as Unknown.
                RustLexicalSelectionEvent::Item(item) if item.kind() == "foreign_mod_item" => {
                    let mut occupied = false;
                    if let Some(body) = item.child_by_field_name("body") {
                        let mut cursor = body.walk();
                        for member in body.named_children(&mut cursor) {
                            charge(1)?;
                            let member = unwrap_attributes(member);
                            if matches!(member.kind(), "function_signature_item" | "static_item")
                                && member.child_by_field_name("name").is_some_and(|name| {
                                    crate::declarations::rust_node_text(name, source) == text
                                })
                            {
                                occupied = true;
                                break;
                            }
                        }
                    }
                    occupied.then_some(RustValueName::Unknown)
                }
                RustLexicalSelectionEvent::Item(item)
                    if item.child_by_field_name("name").is_some_and(|name| {
                        crate::declarations::rust_node_text(name, source) == text
                    }) && !rust_is_associated_member(item) =>
                {
                    if outer_attributes(item).next().is_some() {
                        return Ok(ControlFlow::Break(RustValueName::Unknown));
                    }
                    // In a block, a statement macro after the item can expand
                    // to a `let` of this name that shadows it from there on.
                    // The scope visit stops at the item, before reaching the
                    // macro. Module scopes hold no `let`, and a macro-made
                    // duplicate item there is a compile error.
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
                                return Ok(ControlFlow::Break(RustValueName::Unknown));
                            }
                            later = statement.next_named_sibling();
                        }
                    }
                    match item.kind() {
                        "const_item" => {
                            let identity_free = match item.child_by_field_name("type") {
                                Some(ty) => const_type_is_identity_free(ty, source, |leaf| {
                                    rust_primitive_type_is_unbound_bounded(
                                        root, source, leaf, charge,
                                    )
                                })?,
                                None => false,
                            };
                            Some(if identity_free {
                                RustValueName::Constant
                            } else {
                                RustValueName::Unknown
                            })
                        }
                        "function_item" => Some(RustValueName::Callable(item)),
                        "struct_item" if item.child_by_field_name("body").is_none() => {
                            Some(RustValueName::Constant)
                        }
                        // A tuple struct's name is also its constructor function in
                        // the value namespace, so it occupies the name; its target is
                        // not modeled here.
                        "struct_item" => Some(RustValueName::Unknown),
                        "static_item" => Some(RustValueName::Static),
                        _ => None,
                    }
                }
                RustLexicalSelectionEvent::Import(_, leaf)
                    if matches!(leaf.import.binding_name(), RustImportBindingName::Named(binding) if binding == text)
                        || matches!(leaf.import.binding_name(), RustImportBindingName::Glob) =>
                {
                    Some(RustValueName::Unknown)
                }
                _ => None,
            };
            Ok(classification.map_or(ControlFlow::Continue(()), ControlFlow::Break))
        },
    )?;
    Ok(match selected {
        RustLexicalSelection::Selected(kind) => kind,
        RustLexicalSelection::Complete
            if crate::prelude::rust_prelude_candidate(
                text,
                crate::prelude::RustPreludeNamespace::Value,
            ) =>
        {
            if text == "None" {
                RustValueName::Constant
            } else {
                RustValueName::PreludeCallable
            }
        }
        _ => RustValueName::Unknown,
    })
}

#[doc(hidden)]
pub fn rust_pattern_name_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    name: Node<'tree>,
    charge: &mut F,
) -> Result<RustPatternName, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let (selection, prelude_constructor, saw_glob) =
        rust_pattern_name_selection_bounded(root, source, name, charge)?;
    // A glob import can bring a constant, unit struct or unit variant of this
    // name into scope, which makes the pattern a comparison rather than a
    // binding, as a named import can (#10269). A braced struct defines no
    // value item, so the walk continues past it to an outer item.
    Ok(match selection {
        _ if saw_glob => RustPatternName::Unknown,
        RustLexicalSelection::Selected(classification) => classification,
        RustLexicalSelection::Complete | RustLexicalSelection::Unknown => {
            if prelude_constructor {
                RustPatternName::ValueItem
            } else {
                RustPatternName::Binding
            }
        }
    })
}

/// Strict pattern classification for consumers that must preserve unknown
/// imports and incomplete lexical walks as open binding identities.
#[doc(hidden)]
pub fn rust_pattern_name_strict_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    name: Node<'tree>,
    charge: &mut F,
) -> Result<RustPatternName, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let (selection, prelude_constructor, saw_glob) =
        rust_pattern_name_selection_bounded(root, source, name, charge)?;
    Ok(match selection {
        RustLexicalSelection::Selected(_) if saw_glob => RustPatternName::Unknown,
        RustLexicalSelection::Selected(classification) => classification,
        RustLexicalSelection::Unknown => RustPatternName::Unknown,
        RustLexicalSelection::Complete if saw_glob => RustPatternName::Unknown,
        RustLexicalSelection::Complete if prelude_constructor => RustPatternName::ValueItem,
        RustLexicalSelection::Complete => RustPatternName::Binding,
    })
}

/// Request-local index for repeated strict pattern classifications. The
/// grammar's scope contents are independent of the candidate name, so each
/// scope is scanned once and indexed by its written item/import names. The
/// prefix work at each selection is retained: the same per-candidate bound
/// still yields Open at exactly the old cutoff.
#[derive(Default)]
pub(crate) struct RustStrictPatternIndex {
    scopes: HashMap<usize, RustPatternScopeSummary>,
    inner_attributes: HashMap<usize, (bool, usize)>,
    #[cfg(test)]
    pub(crate) scope_scans: usize,
    #[cfg(test)]
    pub(crate) source_file_scans: usize,
}

#[derive(Default)]
struct RustPatternScopeSummary {
    selected: HashMap<String, (RustPatternName, bool, usize)>,
    saw_glob: bool,
    unknown: bool,
    work: usize,
}

enum IndexedPatternStop<E> {
    PerCandidate,
    External(E),
}

impl RustStrictPatternIndex {
    pub(crate) fn classify(
        &mut self,
        root: Node<'_>,
        source: &str,
        name: Node<'_>,
    ) -> RustPatternName {
        self.classify_bounded(root, source, name, &mut |_| Ok::<(), ()>(()))
            .unwrap_or(RustPatternName::Unknown)
    }

    /// Bounded request preparation: a scope summary is charged as it is
    /// indexed, so cancellation and work exhaustion stop the scan itself.
    pub(crate) fn classify_with_budget<E>(
        &mut self,
        root: Node<'_>,
        source: &str,
        name: Node<'_>,
        charge_work: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<RustPatternName, E> {
        match self.classify_bounded(root, source, name, charge_work) {
            Ok(result) => Ok(result),
            Err(IndexedPatternStop::PerCandidate) => Ok(RustPatternName::Unknown),
            Err(IndexedPatternStop::External(stop)) => Err(stop),
        }
    }

    fn classify_bounded<E>(
        &mut self,
        root: Node<'_>,
        source: &str,
        name: Node<'_>,
        charge_work: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<RustPatternName, IndexedPatternStop<E>> {
        use std::ops::ControlFlow;
        let work = std::cell::Cell::new(0usize);
        let mut charge = |amount: usize| -> Result<(), IndexedPatternStop<E>> {
            work.set(work.get().saturating_add(amount));
            if work.get() > 100_000 {
                return Err(IndexedPatternStop::PerCandidate);
            }
            charge_work(amount).map_err(IndexedPatternStop::External)
        };
        // Replaying a cached summary still applies the per-candidate bound,
        // but its syntax was already charged to this file's preparation.
        let replay = |amount: usize| -> Result<(), IndexedPatternStop<E>> {
            work.set(work.get().saturating_add(amount));
            (work.get() <= 100_000)
                .then_some(())
                .ok_or(IndexedPatternStop::PerCandidate)
        };
        charge(1)?;
        if !matches!(name.kind(), "identifier" | "shorthand_field_identifier")
            || name.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "mut_pattern" | "ref_pattern" | "captured_pattern"
                )
            })
        {
            return Ok(RustPatternName::Binding);
        }
        let text = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
            crate::declarations::rust_node_text(name, source),
        );
        let prelude_constructor =
            text == "None" || crate::prelude::rust_std_constructor_fact(text).is_some();
        let scopes =
            match rust_lexical_scope_chain_bounded(root, source, name, &mut charge, &mut |_, _| {
                Ok(ControlFlow::<RustPatternName>::Continue(()))
            })? {
                ControlFlow::Continue(scopes) => scopes,
                ControlFlow::Break(_) => return Ok(RustPatternName::Unknown),
            };
        for scope in &scopes {
            let (known, cost) = if let Some(cached) = self.inner_attributes.get(&scope.id()) {
                *cached
            } else {
                let mut cost = 0;
                let known =
                    rust_scope_inner_attributes_known_bounded(*scope, source, &mut |amount| {
                        cost += amount;
                        charge(amount)
                    })?;
                self.inner_attributes.insert(scope.id(), (known, cost));
                (known, 0)
            };
            replay(cost)?;
            if !known {
                return Ok(RustPatternName::Unknown);
            }
        }
        let mut saw_glob = false;
        for scope in scopes {
            let cached = self.scopes.contains_key(&scope.id());
            if !cached {
                // A scope's summary and Open outcome must not depend on the
                // prefix work of whichever candidate first reached it.
                let candidate_work = work.replace(0);
                let summary = match RustPatternScopeSummary::new(scope, source, &mut charge) {
                    Ok(summary) => summary,
                    Err(IndexedPatternStop::PerCandidate) => RustPatternScopeSummary {
                        unknown: true,
                        work: work.get(),
                        ..RustPatternScopeSummary::default()
                    },
                    Err(stop) => return Err(stop),
                };
                work.set(candidate_work);
                self.scopes.insert(scope.id(), summary);
                #[cfg(test)]
                {
                    self.scope_scans += 1;
                    if scope.kind() == "source_file" {
                        self.source_file_scans += 1;
                    }
                }
            }
            let summary = &self.scopes[&scope.id()];
            if let Some(&(selection, glob_before, cost)) = summary.selected.get(text) {
                replay(cost)?;
                return Ok(if saw_glob || glob_before {
                    RustPatternName::Unknown
                } else {
                    selection
                });
            }
            replay(summary.work)?;
            if summary.unknown {
                return Ok(RustPatternName::Unknown);
            }
            saw_glob |= summary.saw_glob;
            if rust_lexical_scope_is_module_boundary(scope) {
                break;
            }
        }
        charge(0)?;
        Ok(if saw_glob {
            RustPatternName::Unknown
        } else if prelude_constructor {
            RustPatternName::ValueItem
        } else {
            RustPatternName::Binding
        })
    }
}

impl RustPatternScopeSummary {
    fn new<E>(
        scope: Node<'_>,
        source: &str,
        charge_work: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<Self, E> {
        use std::cell::Cell;
        use std::ops::ControlFlow;
        let work = Cell::new(0usize);
        let mut summary = Self::default();
        let mut charge = |amount: usize| -> Result<(), E> {
            work.set(work.get().saturating_add(amount));
            charge_work(amount)
        };
        let result = visit_rust_lexical_scope_bounded(
            scope,
            source,
            &mut charge,
            &mut |event, _| {
                match event {
                    RustLexicalSelectionEvent::Parameter(parameter)
                        if parameter.kind() == "const_parameter" =>
                    {
                        if let Some(name) = parameter.child_by_field_name("name") {
                            summary
                                .selected
                                .entry(brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(crate::declarations::rust_node_text(name, source)).to_owned())
                                .or_insert((
                                    RustPatternName::ValueItem,
                                    summary.saw_glob,
                                    work.get(),
                                ));
                        }
                    }
                    RustLexicalSelectionEvent::Item(item) => {
                        let associated = crate::syntax::parent_outside_attributes(item)
                            .is_some_and(|owner| {
                                owner.kind() == "declaration_list"
                                    && owner.parent().is_some_and(|parent| {
                                        matches!(parent.kind(), "impl_item" | "trait_item")
                                    })
                            });
                        if !associated {
                            let selection = match item.kind() {
                                "function_item" => Some(RustPatternName::Binding),
                                "const_item" | "static_item" => Some(RustPatternName::ValueItem),
                                "struct_item"
                                    if !(0..item.named_child_count()).any(|index| {
                                        item.named_child(index).is_some_and(|child| {
                                            child.kind() == "field_declaration_list"
                                        })
                                    }) =>
                                {
                                    Some(RustPatternName::ValueItem)
                                }
                                _ => None,
                            };
                            if let Some(selection) = selection
                                && let Some(name) = item.child_by_field_name("name")
                            {
                                summary
                                    .selected
                                    .entry(
                                        brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(crate::declarations::rust_node_text(name, source))
                                            .to_owned(),
                                    )
                                    .or_insert((selection, summary.saw_glob, work.get()));
                            }
                        }
                    }
                    RustLexicalSelectionEvent::Import(_, leaf) => {
                        match leaf.import.binding_name() {
                            RustImportBindingName::Glob => summary.saw_glob = true,
                            RustImportBindingName::Named(binding) => {
                                summary.selected.entry(binding.to_string()).or_insert((
                                    RustPatternName::Unknown,
                                    summary.saw_glob,
                                    work.get(),
                                ));
                            }
                            RustImportBindingName::Unnamed => {}
                        }
                    }
                    _ => {}
                }
                Ok(ControlFlow::<()>::Continue(()))
            },
        );
        summary.unknown = matches!(result?, ControlFlow::Break(RustLexicalSelection::Unknown));
        summary.work = work.get();
        Ok(summary)
    }
}

fn rust_pattern_name_selection_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    name: Node<'tree>,
    charge: &mut F,
) -> Result<(RustLexicalSelection<RustPatternName>, bool, bool), E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    charge(1)?;
    if !matches!(name.kind(), "identifier" | "shorthand_field_identifier")
        || name.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "mut_pattern" | "ref_pattern" | "captured_pattern"
            )
        })
    {
        return Ok((
            RustLexicalSelection::Selected(RustPatternName::Binding),
            false,
            false,
        ));
    }
    let text = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
        crate::declarations::rust_node_text(name, source),
    );
    // Constructors occupy pattern position, while prelude functions such as
    // `drop` can be shadowed by a binding. Select lexical items before falling
    // through to the prelude, so a written function can shadow `None` too.
    let prelude_constructor =
        text == "None" || crate::prelude::rust_std_constructor_fact(text).is_some();
    let mut saw_glob = false;
    let selection =
        visit_rust_lexical_selection_bounded(root, source, name, charge, |event, _| {
            let occupied = match event {
                RustLexicalSelectionEvent::Parameter(parameter) => {
                    parameter.kind() == "const_parameter"
                        && parameter.child_by_field_name("name").is_some_and(|name| {
                            brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                                crate::declarations::rust_node_text(name, source),
                            ) == text
                        })
                }
                RustLexicalSelectionEvent::Item(item) => {
                    // Associated members require `Self::`; they are not
                    // unqualified value bindings in an implementation body.
                    if rust_is_associated_member(item) {
                        return Ok(ControlFlow::Continue(()));
                    }
                    if item.kind() == "function_item"
                        && item.child_by_field_name("name").is_some_and(|name| {
                            brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                                crate::declarations::rust_node_text(name, source),
                            ) == text
                        })
                    {
                        return Ok(ControlFlow::Break(RustPatternName::Binding));
                    }
                    if item.kind() == "struct_item"
                        && item.child_by_field_name("name").is_some_and(|name| {
                            brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                                crate::declarations::rust_node_text(name, source),
                            ) == text
                        })
                        && (0..item.named_child_count()).any(|index| {
                            item.named_child(index)
                                .is_some_and(|child| child.kind() == "field_declaration_list")
                        })
                    {
                        // A braced struct has no value constructor. Keep
                        // searching for an outer const or function item.
                        return Ok(ControlFlow::Continue(()));
                    }
                    matches!(item.kind(), "const_item" | "static_item" | "struct_item")
                        && item.child_by_field_name("name").is_some_and(|name| {
                            brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                                crate::declarations::rust_node_text(name, source),
                            ) == text
                        })
                }
                RustLexicalSelectionEvent::Import(_, leaf) => match leaf.import.binding_name() {
                    RustImportBindingName::Glob => {
                        saw_glob = true;
                        false
                    }
                    RustImportBindingName::Named(binding)
                        if crate::imports::rust_binding_name_matches(&binding, text) =>
                    {
                        return Ok(ControlFlow::Break(RustPatternName::Unknown));
                    }
                    _ => false,
                },
                _ => false,
            };
            Ok(if occupied {
                ControlFlow::Break(RustPatternName::ValueItem)
            } else {
                ControlFlow::Continue(())
            })
        })?;
    Ok((selection, prelude_constructor, saw_glob))
}

/// Select the nearest value binding visible at a use. Like the scope index,
/// lets activate after their declaration, parameters over the callable body,
/// and pattern binders only over their arm/loop/condition body. The returned
/// syntax owner preserves the declared type and initializer for consumers.
pub(crate) fn rust_value_binding_at_bounded<'tree, E>(
    site: Node<'tree>,
    source: &str,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<Option<Node<'tree>>, E> {
    let name = crate::declarations::rust_node_text(site, source);
    let byte = site.start_byte();
    let mut current = site.parent();
    while let Some(scope) = current {
        charge(1)?;
        match scope.kind() {
            "block" => {
                // Source order, nearest let first. A declaration's own
                // initializer still sees the previous binding.
                for index in (0..scope.named_child_count()).rev() {
                    charge(1)?;
                    let raw = scope.named_child(index).expect("indexed block child");
                    let binding = unwrap_attributes(raw);
                    if binding.kind() == "let_declaration"
                        && binding.end_byte() <= byte
                        && let Some(pattern) = binding.child_by_field_name("pattern")
                        && rust_pattern_binds_name_bounded(pattern, name, source, charge)?
                    {
                        return Ok(Some(binding));
                    }
                }
            }
            "function_item" | "closure_expression" => {
                if let Some(parameters) = scope.child_by_field_name("parameters") {
                    let mut cursor = parameters.walk();
                    for raw in parameters.named_children(&mut cursor) {
                        charge(1)?;
                        let parameter = unwrap_attributes(raw);
                        let pattern = parameter
                            .child_by_field_name("pattern")
                            .unwrap_or(parameter);
                        if (parameter.kind() == "self_parameter" && name == "self")
                            || rust_pattern_binds_name_bounded(pattern, name, source, charge)?
                        {
                            return Ok(Some(parameter));
                        }
                    }
                }
                // Closures can capture an outer parameter or local; nested
                // function items cannot capture their enclosing value scope.
                if scope.kind() == "function_item" {
                    return Ok(None);
                }
            }
            "match_arm" | "for_expression" => {
                if let Some(pattern) = scope.child_by_field_name("pattern") {
                    let visible = if scope.kind() == "for_expression" {
                        scope
                            .child_by_field_name("body")
                            .is_some_and(|body| contains_byte(body, byte))
                    } else {
                        pattern.end_byte() <= byte
                    };
                    if visible && rust_pattern_binds_name_bounded(pattern, name, source, charge)? {
                        return Ok(Some(scope));
                    }
                }
            }
            "if_expression" | "while_expression" => {
                if let Some(body) = scope
                    .child_by_field_name("consequence")
                    .or_else(|| scope.child_by_field_name("body"))
                    && contains_byte(body, byte)
                    && let Some(condition) = scope.child_by_field_name("condition")
                {
                    let mut stack = vec![condition];
                    while let Some(node) = stack.pop() {
                        charge(1)?;
                        if node.kind() == "let_condition" {
                            if let Some(pattern) = node.child_by_field_name("pattern")
                                && rust_pattern_binds_name_bounded(pattern, name, source, charge)?
                            {
                                return Ok(Some(node));
                            }
                        } else if matches!(node.kind(), "let_chain" | "parenthesized_expression") {
                            let mut cursor = node.walk();
                            stack.extend(node.named_children(&mut cursor));
                        }
                    }
                }
            }
            _ => {}
        }
        current = scope.parent();
    }
    Ok(None)
}

fn rust_pattern_binds_name_bounded<E>(
    pattern: Node<'_>,
    name: &str,
    source: &str,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<bool, E> {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        charge(1)?;
        if matches!(node.kind(), "identifier" | "shorthand_field_identifier")
            && crate::declarations::rust_node_text(node, source) == name
            && is_pattern_binding_identifier(node)
        {
            return Ok(true);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Ok(false)
}

/// Whether `node` is the identifier being introduced by a Rust binding pattern.
/// Type/variant owners in structured patterns are deliberately excluded.
pub fn is_pattern_binding_identifier(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "shorthand_field_identifier") {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "let_declaration" | "let_condition" | "parameter" | "match_arm" | "for_expression"
        ) && let Some(pattern) = parent.child_by_field_name("pattern")
            && pattern_contains_binding_identifier(pattern, node)
        {
            return true;
        }
        if parent.kind() == "closure_parameters"
            && pattern_contains_binding_identifier(parent, node)
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "block" | "function_item" | "closure_expression"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn pattern_contains_binding_identifier(pattern: Node<'_>, target: Node<'_>) -> bool {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {}
            "identifier" | "shorthand_field_identifier" => {
                if node.id() == target.id() {
                    return true;
                }
            }
            "field_pattern" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    stack.push(pattern);
                } else if let Some(name) = node.child_by_field_name("name") {
                    stack.push(name);
                }
            }
            "struct_pattern" => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    matches!(
                        child.kind(),
                        "field_pattern"
                            | "remaining_field_pattern"
                            | "tuple_pattern"
                            | "struct_pattern"
                            | "ref_pattern"
                            | "reference_pattern"
                            | "mut_pattern"
                    )
                }));
            }
            "tuple_struct_pattern" => {
                let type_id = node.child_by_field_name("type").map(|ty| ty.id());
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    Some(child.id()) != type_id
                        && matches!(
                            child.kind(),
                            "identifier"
                                | "tuple_pattern"
                                | "tuple_struct_pattern"
                                | "struct_pattern"
                                | "slice_pattern"
                                | "or_pattern"
                                | "captured_pattern"
                                | "ref_pattern"
                                | "reference_pattern"
                                | "mut_pattern"
                        )
                }));
            }
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
    }
    false
}

fn contains_byte(node: Node<'_>, byte: usize) -> bool {
    brokk_bifrost_core::analyzer::model::byte_range_contains(
        node.start_byte(),
        node.end_byte(),
        byte,
    )
}

/// Pattern binding candidates in source order. Constant and unit-constructor
/// identifiers require value-namespace selection by the caller.
#[doc(hidden)]
pub fn rust_pattern_binding_identifiers(node: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "scoped_identifier"
            | "scoped_type_identifier"
            | "range_pattern"
            | "macro_invocation" => {}
            "match_pattern" => {
                let guard = node.child_by_field_name("condition").map(|node| node.id());
                let mut cursor = node.walk();
                stack.extend(
                    node.named_children(&mut cursor)
                        .filter(|child| Some(child.id()) != guard),
                );
            }
            "identifier" => {
                out.push(node);
            }
            "field_pattern" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    stack.push(pattern);
                } else if let Some(name) = node.child_by_field_name("name") {
                    out.push(name);
                }
            }
            "struct_pattern" => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    matches!(
                        child.kind(),
                        "field_pattern"
                            | "remaining_field_pattern"
                            | "tuple_pattern"
                            | "struct_pattern"
                            | "ref_pattern"
                            | "reference_pattern"
                            | "mut_pattern"
                    )
                }));
            }
            "tuple_struct_pattern" => {
                let type_id = node.child_by_field_name("type").map(|ty| ty.id());
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    Some(child.id()) != type_id
                        && matches!(
                            child.kind(),
                            "identifier"
                                | "tuple_pattern"
                                | "tuple_struct_pattern"
                                | "struct_pattern"
                                | "slice_pattern"
                                | "or_pattern"
                                | "captured_pattern"
                                | "ref_pattern"
                                | "reference_pattern"
                                | "mut_pattern"
                        )
                }));
            }
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
    }
    out.sort_by_key(Node::start_byte);
    out
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn test_scope_proof(source: &str) -> bool {
        let tree = parse_rust_tree_uncached(source).unwrap();
        rust_test_scope_unshadowed_bounded(tree.root_node(), source, &mut |_| Ok::<_, ()>(()))
            .unwrap()
    }

    #[test]
    #[hardwon("#10389: a raw alias of an imported constant blocks the flat binding proof")]
    fn raw_imported_constant_blocks_flat_binding_proof() {
        let source = "use m::C as r#type; fn f() { let r#type = 1; }";
        let tree = parse_rust_tree_uncached(source).unwrap();
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut candidate = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier"
                && node.parent().is_some_and(|p| p.kind() == "let_declaration")
            {
                candidate = Some(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert!(
            !rust_pattern_identifier_binding_bounded(
                root,
                source,
                candidate.unwrap(),
                &mut |_| Ok::<_, ()>(())
            )
            .unwrap()
        );
    }

    #[test]
    #[hardwon(
        "#10389: crate globs in an out-of-line module cannot resolve against that file's root"
    )]
    fn test_attribute_crate_glob_needs_crate_root_evidence() {
        assert!(!test_scope_proof(
            "mod m {} use crate::m::*; #[test] fn t() {}"
        ));
    }

    #[test]
    #[hardwon("#10389: a glob target's item macro may expand to an attribute import")]
    fn test_attribute_glob_target_item_macro_is_open() {
        assert!(!test_scope_proof(
            "mod m { foo!(); } use m::*; #[test] fn t() {}"
        ));
        assert!(test_scope_proof(
            "mod m { macro_rules! foo { () => {} } } use m::*; #[test] fn t() {}"
        ));
    }

    #[test]
    #[hardwon("#10389: cfg-alternative modules can export different attribute macros")]
    fn test_attribute_duplicate_module_declarations_are_open() {
        assert!(!test_scope_proof(
            "#[cfg(a)] mod m {} #[cfg(b)] mod m { macro_rules! test { () => {} } } use m::*; #[test] fn t() {}"
        ));
    }

    #[test]
    #[hardwon("#10389: an enclosing item macro may expand to a test attribute import")]
    fn test_attribute_enclosing_item_macro_is_open() {
        assert!(!test_scope_proof("my_macro!(); #[test] fn t() {}"));
        assert!(test_scope_proof(
            "macro_rules! other { () => {} } #[test] fn t() {}"
        ));
    }

    #[test]
    #[hardwon("#10389: glob-linked modules use bounded stack space for test attributes")]
    fn test_attribute_glob_chain_is_stack_safe() {
        let source = format!(
            "mod m0 {{ macro_rules! test {{ () => {{}} }} }} {}",
            (1..128)
                .map(|i| format!("mod m{i} {{ use super::m{}::*; }}", i - 1))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let tree = parse_rust_tree_uncached(&source).unwrap();
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let mut work = 0usize;
                let mut charge = |amount| -> Result<(), ()> {
                    work += amount;
                    (work < 100_000).then_some(()).ok_or(())
                };
                assert_eq!(
                    rust_glob_may_shadow_test(
                        tree.root_node(),
                        &["m127".to_owned()],
                        &source,
                        &mut charge,
                        &mut std::collections::HashSet::new(),
                    ),
                    Ok(true)
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    #[hardwon("#10389: cached Rust scope scans consume file preparation once")]
    fn indexed_pattern_scope_reuse_charges_only_new_scans() {
        let source = format!(
            "{}fn f(v: i32) {{ match v {{ {} }} }}",
            (0..600)
                .map(|i| format!("const ITEM_{i}: i32 = {i};"))
                .collect::<Vec<_>>()
                .join("\n"),
            (0..128)
                .map(|i| format!("candidate_{i} => (),"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let tree = parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut candidates = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier"
                && source
                    .get(node.byte_range())
                    .is_some_and(|text| text.starts_with("candidate_"))
            {
                candidates.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(candidates.len(), 128);
        let mut index = RustStrictPatternIndex::default();
        let mut charged = 0usize;
        for candidate in candidates {
            let result = index.classify_with_budget(root, &source, candidate, &mut |amount| {
                charged += amount;
                (charged <= 100_000).then_some(()).ok_or(())
            });
            assert_eq!(result.unwrap(), RustPatternName::Binding);
        }
        assert_eq!(index.source_file_scans, 1);
        assert!(charged < 100_000, "duplicate scope charges: {charged}");
    }

    #[test]
    #[hardwon("#10389: an over-budget Rust scope scan is cached as Open")]
    fn indexed_pattern_over_budget_scope_is_not_rescanned() {
        let source = format!(
            "{}fn f(v: i32) {{ match v {{ first => (), second => () }} }}",
            (0..60_000)
                .map(|i| format!("const ITEM_{i}: i32 = {i};"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let tree = parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut candidates = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier"
                && source
                    .get(node.byte_range())
                    .is_some_and(|text| text == "first" || text == "second")
            {
                candidates.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(candidates.len(), 2);
        let mut index = RustStrictPatternIndex::default();
        for candidate in candidates {
            assert_eq!(
                index.classify(root, &source, candidate),
                RustPatternName::Unknown
            );
        }
        assert_eq!(index.source_file_scans, 1);
    }

    #[test]
    #[hardwon("#10389: indexed Rust scope verdicts do not depend on first candidate work")]
    fn indexed_pattern_scope_verdicts_match_independent_queries() {
        let source = format!(
            "{}fn f(v: i32) {{ match v {{ first => (), second => () }} }}",
            (0..45_000)
                .map(|i| format!("const ITEM_{i}: i32 = {i};"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let tree = parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut candidates = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier"
                && source
                    .get(node.byte_range())
                    .is_some_and(|text| text == "first" || text == "second")
            {
                candidates.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(candidates.len(), 2);
        let mut shared = RustStrictPatternIndex::default();
        for candidate in candidates {
            let independent = RustStrictPatternIndex::default().classify(root, &source, candidate);
            assert_eq!(shared.classify(root, &source, candidate), independent);
        }
        assert_eq!(shared.source_file_scans, 1);
    }

    #[test]
    #[hardwon("#10389: indexed Rust scope summaries stop during large scans")]
    fn indexed_pattern_scope_scan_honors_work_limit_and_cancellation() {
        let source = format!(
            "{}fn f(v: i32) {{ match v {{ candidate => () }} }}",
            (0..4_000)
                .map(|i| format!("const ITEM_{i}: i32 = {i};"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let tree = parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut candidate = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" && source.get(node.byte_range()) == Some("candidate") {
                candidate = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let candidate = candidate.unwrap();
        let mut index = RustStrictPatternIndex::default();
        let mut charged = 0usize;
        let limited = index.classify_with_budget(root, &source, candidate, &mut |amount| {
            charged += amount;
            (charged <= 300).then_some(()).ok_or(())
        });
        assert!(limited.is_err());
        assert!(charged <= 301, "scope scan overran the work cap: {charged}");
        assert_eq!(index.source_file_scans, 0);

        let token = brokk_bifrost_core::CancellationToken::new();
        let mut index = RustStrictPatternIndex::default();
        let mut charged = 0usize;
        let cancelled = index.classify_with_budget(root, &source, candidate, &mut |amount| {
            charged += amount;
            if charged >= 300 {
                token.cancel();
            }
            (!token.is_cancelled()).then_some(()).ok_or(())
        });
        assert!(cancelled.is_err());
        assert!(token.is_cancelled());
        assert_eq!(index.source_file_scans, 0);
    }

    #[test]
    #[hardwon(
        "46e7bf58c956: The cfg adapter distinguishes a direct feature predicate from its negation on separate declarations."
    )]
    fn cfg_condition_reads_direct_feature_and_not_feature_attributes() {
        let source = r#"
#[cfg(feature = "query_apply")]
use crate::apply::apply_from_stdin;

#[cfg(not(feature = "query_apply"))]
fn apply_from_stdin() -> u8 { 1 }
"#;
        let tree = parse_rust_tree_uncached(source).expect("parse Rust fixture");
        let root = tree.root_node();
        let mut cursor = root.walk();
        let declarations = root.named_children(&mut cursor).collect::<Vec<_>>();
        let use_declaration = declarations
            .iter()
            .copied()
            .find(|node| unwrap_attributes(*node).kind() == "use_declaration")
            .expect("use declaration");
        let function = declarations
            .iter()
            .copied()
            .find(|node| unwrap_attributes(*node).kind() == "function_item")
            .expect("function declaration");

        assert_eq!(
            rust_cfg_condition(use_declaration, source),
            RustCfgCondition::Atom("feature = \"query_apply\"".to_string())
        );
        assert_eq!(
            rust_cfg_condition(function, source),
            RustCfgCondition::NotAtom("feature = \"query_apply\"".to_string())
        );
    }

    #[test]
    fn extern_crate_is_structured_and_does_not_enter_use_binder() {
        let source = "extern crate dependency as dep;\n";
        let tree = parse_rust_tree_uncached(source).expect("parse Rust fixture");
        let imports = crate::imports::rust_import_projection(tree.root_node(), source, "");
        assert_eq!(imports.len(), 1);
        let import = &imports[0].import;
        assert!(import.is_extern_crate());
        assert_eq!(import.path(), ["dependency"]);

        let mut binder = ImportBinder::empty();
        insert_rust_import_binding(&mut binder, &import.info);
        assert!(binder.bindings.is_empty());
    }

    #[test]
    fn visible_use_collection_only_descends_into_the_reference_scope_chain() {
        let mut source = String::from(
            r#"
mod selected {
    use crate::ModuleWide;

    fn target() {
        use crate::Local;
        let marker = ModuleWide::new();
    }

    fn sibling() {
        use crate::SiblingOnly;
        let _ = SiblingOnly::new();
    }

    use crate::TrailingModuleWide;
}
"#,
        );
        for index in 0..128 {
            writeln!(
                source,
                "fn unrelated_{index}() {{ use crate::Hidden{index}; let _ = Hidden{index}::new(); }}"
            )
            .expect("write fixture");
        }

        let reference_byte = source.find("marker").expect("reference marker");
        let tree = parse_rust_tree_uncached(&source).expect("parse Rust fixture");
        let root = tree.root_node();
        let caches = RustLexicalCaches::new(&RetentionBudget::for_tests());
        let binder = visible_import_binder_in_tree_with(&caches, root, &source, reference_byte);
        let visible: Vec<&str> = ["ModuleWide", "Local", "TrailingModuleWide"]
            .into_iter()
            .filter(|name| binder.bindings.contains_key(*name))
            .collect();
        assert_eq!(visible, ["ModuleWide", "Local", "TrailingModuleWide"]);
        assert!(
            !binder.bindings.contains_key("SiblingOnly")
                && !binder.bindings.contains_key("Hidden0"),
            "imports in sibling scopes must not be visible: {:?}",
            binder.bindings.keys().collect::<Vec<_>>()
        );

        // The statement index behind the binder is memoized on the source
        // bytes: a second question about the same source must reuse it rather
        // than re-walking the file (public issue #11).
        let caches = RustLexicalCaches::new(
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        );
        let first = rust_use_statements_with(&caches, root, &source);
        let second = rust_use_statements_with(&caches, root, &source);
        assert!(
            Arc::ptr_eq(&first, &second),
            "expected the use-statement index to be shared across asks"
        );
    }

    #[test]
    fn import_binding_uses_structured_path_instead_of_display_text() {
        let source = "use crate::models::{Thing as Local, lower};\n";
        let tree = parse_rust_tree_uncached(source).expect("parse Rust fixture");
        let use_node = tree.root_node().named_child(0).expect("use declaration");
        let mut imports = rust_imports_from_use_declaration(use_node, source);
        assert_eq!(imports.len(), 2);
        for import in &mut imports {
            import.raw_snippet = "use misleading::DisplayOnly;".to_string();
        }

        let mut binder = ImportBinder::empty();
        for import in &imports {
            insert_rust_import_binding(&mut binder, import);
        }

        let local = binder.bindings.get("Local").expect("aliased import");
        assert_eq!(local.kind, ImportKind::Named);
        assert_eq!(local.module_specifier, "crate::models");
        assert_eq!(local.imported_name.as_deref(), Some("Thing"));

        let lower = binder.bindings.get("lower").expect("lowercase import");
        assert_eq!(lower.kind, ImportKind::Namespace);
        assert_eq!(lower.module_specifier, "crate::models::lower");
        assert_eq!(lower.imported_name, None);
    }

    #[test]
    fn absolute_single_segment_import_keeps_legacy_split_behavior() {
        let source = "use ::crate;\nuse crate as alias;\nuse ::crate as absolute_alias;\n";
        let tree = parse_rust_tree_uncached(source).expect("parse Rust fixture");
        let mut binder = ImportBinder::empty();
        let mut cursor = tree.root_node().walk();
        for node in tree
            .root_node()
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "use_declaration")
        {
            for import in rust_imports_from_use_declaration(node, source) {
                insert_rust_import_binding(&mut binder, &import);
            }
        }

        let crate_binding = binder.bindings.get("crate").expect("absolute crate");
        assert_eq!(crate_binding.kind, ImportKind::Namespace);
        assert_eq!(crate_binding.module_specifier, "::crate");

        let alias = binder.bindings.get("alias").expect("single alias");
        assert_eq!(alias.kind, ImportKind::Namespace);
        assert_eq!(alias.module_specifier, "crate");

        let absolute_alias = binder
            .bindings
            .get("absolute_alias")
            .expect("absolute alias");
        assert_eq!(absolute_alias.kind, ImportKind::Named);
        assert_eq!(absolute_alias.module_specifier, "");
        assert_eq!(absolute_alias.imported_name.as_deref(), Some("crate"));
    }
}

#[cfg(test)]
mod ownership_lexical_boundary {
    use super::*;

    #[test]
    fn ownership_lexical_selection_respects_activation_and_recovery() {
        // Each selected Local token is a type field of a parameter or let.
        // An inner alias is independent of a recovered outer sibling, whereas
        // an unknown attribute macro or cfg on the selected scope stays open.
        for (source, selected) in [
            (
                "type Local = (); #[repr(C)] struct S; fn f(x: Local) {}",
                true,
            ),
            (
                "type Local = (); macro_rules! test { () => {} } #[test] fn helper() {} fn f(x: Local) {}",
                false,
            ),
            (
                "type Local = (); fn test() {} #[test] fn helper() {} fn f(x: Local) {}",
                true,
            ),
            (
                "type Local = (); #[cfg(feature = \"conditional\")] fn f(x: Local) {}",
                false,
            ),
            (
                "fn f() { type Local = (); let x: Local = (); } fn broken( {}",
                true,
            ),
        ] {
            let tree = parse_rust_tree_uncached(source).unwrap();
            let root = tree.root_node();
            let mut pending = vec![root];
            let mut site = None;
            while let Some(node) = pending.pop() {
                if matches!(node.kind(), "parameter" | "let_declaration") {
                    site = node.child_by_field_name("type");
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            let site = site.unwrap();
            assert_eq!(site.kind(), "type_identifier");
            assert_eq!(crate::declarations::rust_node_text(site, source), "Local");
            let head = rust_type_head_at_bounded(
                root,
                source,
                site,
                "Local",
                &RustTypeHeadMemo::default(),
                &mut |_| Ok::<_, ()>(()),
            )
            .unwrap();
            assert_eq!(
                matches!(head, RustTypeHead::Item(_)),
                selected,
                "{source}: {head:?}"
            );
            if let RustTypeHead::Item(item) = head {
                assert_eq!(item.kind(), "type_item");
                assert_eq!(
                    item.child_by_field_name("type").unwrap().kind(),
                    "unit_type"
                );
            }
        }
    }
}

#[cfg(test)]
mod qs3_pattern_contract {
    use super::*;

    #[test]
    fn qs3_pattern_grammar_boundary() {
        let source = concat!(
            "fn f() { let Some(x) = input;\n",
            "let closure = |Some(z): Option<u8>| z;\n",
            "for Some(w) in items {}\n",
            "match input { Some(y) if predicate(y) => (), Some(v) => () } }",
        );
        let tree = parse_rust_tree_uncached(source).unwrap();
        assert!(!tree.root_node().has_error());
        let mut stack = vec![tree.root_node()];
        let mut patterns = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "tuple_struct_pattern" {
                let head = node.child_by_field_name("type").unwrap();
                assert_eq!(head.kind(), "identifier");
                assert_eq!(&source[head.byte_range()], "Some");
                assert!(!pattern_contains_binding_identifier(node, head));
                let candidates = rust_pattern_binding_identifiers(node);
                assert_eq!(candidates.len(), 1);
                let candidate = candidates[0];
                assert_eq!(candidate.kind(), "identifier");
                assert!(pattern_contains_binding_identifier(node, candidate));
                patterns.push((
                    &source[candidate.byte_range()],
                    candidate.start_byte(),
                    candidate.end_byte(),
                ));
            }
            if node.kind() == "match_pattern" {
                let binders = rust_pattern_binding_identifiers(node);
                let guard = node.child_by_field_name("condition");
                assert_eq!(binders.len(), 1);
                assert_eq!(
                    &source[binders[0].byte_range()],
                    if guard.is_some() { "y" } else { "v" }
                );
                if let Some(guard) = guard {
                    assert_eq!(guard.kind(), "call_expression");
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        patterns.sort_by_key(|(_, start, _)| *start);
        assert_eq!(
            patterns,
            [
                ("x", 18, 19),
                ("z", 50, 51),
                ("w", 78, 79),
                ("y", 112, 113),
                ("v", 143, 144)
            ]
        );
    }

    #[test]
    fn qs3_inline_module_grammar_boundary() {
        let source = "mod a { trait Visible { fn default_a() {} } fn here() {} } mod b { trait Visible { fn default_b() {} } fn there() {} } fn outside() {}";
        let tree = parse_rust_tree_uncached(source).unwrap();
        assert!(!tree.root_node().has_error());
        let index = RustLexicalScopeIndex::new(tree.root_node(), source);
        let mut stack = vec![tree.root_node()];
        let mut traits = Vec::new();
        let mut functions = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "trait_item" {
                traits.push(node);
            }
            if node.kind() == "function_item" {
                functions.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        traits.sort_by_key(Node::start_byte);
        functions.sort_by_key(Node::start_byte);
        assert_eq!(traits.len(), 2);
        assert_eq!(functions.len(), 5);
        for (i, declaration) in traits.iter().enumerate() {
            assert_eq!(
                declaration.parent().unwrap().parent().unwrap().kind(),
                "mod_item"
            );
            for (j, function) in functions.iter().enumerate() {
                assert_eq!(
                    index.item_declaration_visible_at(
                        "Visible",
                        declaration.start_byte(),
                        function.start_byte()
                    ),
                    j < 4 && i == j / 2
                );
            }
        }
    }
}

fn rust_use_statements_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
) -> Arc<Accounted<SourceCached<Vec<RustUseStatement>>>> {
    debug_assert!(
        root.parent().is_none() && root.end_byte() <= source.len(),
        "rust_use_statements needs the whole-source parse root",
    );
    if let Some(cached) = cached_for(&caches.use_statements, source) {
        return cached;
    }
    caches.use_scans.fetch_add(1, Ordering::Relaxed);
    let mut statements = Vec::new();
    // The same source-order traversal as `collect_visible_use_statements`,
    // minus its byte-position pruning: a pruned-away subtree can only hold
    // statements the visibility filter rejects, so filtering this complete
    // index reproduces the pruned walk's output exactly.
    let mut stack = vec![(root, None, None)];
    while let Some((raw_node, mod_range, scope_range)) = stack.pop() {
        let node = unwrap_attributes(raw_node);
        if matches!(node.kind(), "use_declaration" | "extern_crate_declaration") {
            let imports = if node.kind() == "use_declaration" {
                rust_imports_from_use_declaration(node, source)
            } else {
                crate::imports::rust_import_projection(node, source, "")
                    .into_iter()
                    .map(|projected| projected.import.info)
                    .collect()
            };
            statements.push(RustUseStatement {
                imports,
                mod_range,
                scope_range,
            });
            continue;
        }
        let child_mod_range = if node.kind() == "mod_item" {
            Some((node.start_byte(), node.end_byte()))
        } else {
            mod_range
        };
        let child_scope_range = if lexical_scope_kind(node.kind()) {
            Some((node.start_byte(), node.end_byte()))
        } else {
            scope_range
        };
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|child| (child, child_mod_range, child_scope_range)),
        );
    }
    keep_for(&caches.use_statements, source, statements)
}

pub fn visible_import_binders_with_scopes_in_tree_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
) -> Vec<(usize, ImportBinder)> {
    let reference_mod_range = enclosing_mod_item_range_at(root, reference_byte);
    let mut by_scope: HashMap<(usize, usize), ImportBinder> = HashMap::default();
    for statement in rust_use_statements_with(caches, root, source).iter() {
        // Extern-crate declarations are indexed for type identity, but do not
        // introduce entries (including empty scopes) in the legacy use binder.
        if statement.imports.iter().all(|import| {
            import.path.as_ref().is_some_and(|path| {
                path.kind
                    == Some(
                        brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ExternCrate,
                    )
            })
        }) {
            continue;
        }
        if !use_statement_visible_at(
            reference_byte,
            reference_mod_range,
            statement.mod_range,
            statement.scope_range,
        ) {
            continue;
        }
        let scope = statement
            .scope_range
            .unwrap_or((root.start_byte(), root.end_byte()));
        let binder = by_scope.entry(scope).or_default();
        for import in &statement.imports {
            insert_rust_import_binding(binder, import);
        }
    }
    let mut binders: Vec<_> = by_scope.into_iter().collect();
    binders.sort_by_key(|((start, end), _)| (end.saturating_sub(*start), *start));
    binders
        .into_iter()
        .map(|((start, _), binder)| (start, binder))
        .collect()
}

/// What the `use` declarations visible at a reference bind a name to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustVisibleUse {
    /// No visible `use` binds the name and no visible glob could supply it.
    Unbound,
    /// A visible glob in a scope that binds nothing else of that name could
    /// supply it.
    GlobMayBind,
    /// The innermost scope that binds the name binds it to this item path.
    Named {
        segments: Vec<String>,
        is_global: bool,
    },
    /// Bound, but not to an item path: a namespace alias or a `self` import.
    Namespace,
}

/// The binding of `name` visible at `reference_byte`, innermost scope first,
/// with the item path carried as structured segments. A binding in a scope
/// that does not contain the reference is never consulted.
pub fn visible_use_for_name_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    name: &str,
) -> RustVisibleUse {
    use crate::imports::{RustImportBindingName, rust_import_binding_name};
    let reference_mod_range = enclosing_mod_item_range_at(root, reference_byte);
    #[derive(Default)]
    struct Scope {
        named: Option<RustVisibleUse>,
        glob: bool,
    }
    let mut by_scope: HashMap<(usize, usize), Scope> = HashMap::default();
    for statement in rust_use_statements_with(caches, root, source).iter() {
        if !use_statement_visible_at(
            reference_byte,
            reference_mod_range,
            statement.mod_range,
            statement.scope_range,
        ) {
            continue;
        }
        let scope = by_scope
            .entry(
                statement
                    .scope_range
                    .unwrap_or((root.start_byte(), root.end_byte())),
            )
            .or_default();
        for import in &statement.imports {
            match rust_import_binding_name(import) {
                RustImportBindingName::Glob => scope.glob = true,
                RustImportBindingName::Unnamed => {}
                RustImportBindingName::Named(bound) if bound == name => {
                    let Some(path) = import.path.as_ref() else {
                        scope.named = Some(RustVisibleUse::Namespace);
                        continue;
                    };
                    let last = path.segments.last().map(String::as_str).unwrap_or_default();
                    // The binder files a lowercase unaliased name, a `self`
                    // import and a single unanchored segment as a namespace.
                    let item = (path.segments.len() > 1 || import.is_global)
                        && last != "self"
                        && (import.alias.is_some()
                            || last
                                .chars()
                                .any(|ch| !(ch.is_ascii_lowercase() || ch == '_')));
                    scope.named = Some(if item {
                        RustVisibleUse::Named {
                            segments: path.segments.clone(),
                            is_global: import.is_global,
                        }
                    } else {
                        RustVisibleUse::Namespace
                    });
                }
                RustImportBindingName::Named(_) => {}
            }
        }
    }
    let mut scopes = by_scope.into_iter().collect::<Vec<_>>();
    scopes.sort_by_key(|((start, end), _)| (end.saturating_sub(*start), *start));
    for (_, scope) in scopes {
        if let Some(bound) = scope.named {
            return bound;
        }
        if scope.glob {
            return RustVisibleUse::GlobMayBind;
        }
    }
    RustVisibleUse::Unbound
}

pub fn lexical_package_at_with(
    caches: &RustLexicalCaches,
    file_package: &str,
    source: &str,
    byte: usize,
) -> String {
    let Some(tree) = parse_rust_tree_with(caches, source) else {
        return file_package.to_string();
    };
    lexical_package_in_tree(file_package, tree.root_node(), source, byte)
}

/// Parser-owned declarations for visible imports binding `name`.
pub fn visible_import_declarations_in_tree_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    name: &str,
) -> Vec<brokk_bifrost_core::analyzer::model::ImportInfo> {
    let reference_mod_range = enclosing_mod_item_range_at(root, reference_byte);
    rust_use_statements_with(caches, root, source)
        .iter()
        .filter(|statement| {
            use_statement_visible_at(
                reference_byte,
                reference_mod_range,
                statement.mod_range,
                statement.scope_range,
            )
        })
        .flat_map(|statement| &statement.imports)
        .filter(|import| import.local_name() == Some(name))
        .cloned()
        .collect()
}

/// Parser-owned paths of visible imports binding `name`, including aliases.
pub fn visible_import_paths_in_tree_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    name: &str,
) -> Vec<Vec<String>> {
    visible_import_declarations_in_tree_with(caches, root, source, reference_byte, name)
        .into_iter()
        .map(|import| {
            import
                .path
                .expect("Rust import has a structured path")
                .segments
        })
        .collect()
}

pub fn visible_import_binder_in_tree_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
) -> ImportBinder {
    let reference_mod_range = enclosing_mod_item_range_at(root, reference_byte);
    let mut binder = ImportBinder::empty();
    for statement in rust_use_statements_with(caches, root, source).iter() {
        if !use_statement_visible_at(
            reference_byte,
            reference_mod_range,
            statement.mod_range,
            statement.scope_range,
        ) {
            continue;
        }
        for import in &statement.imports {
            insert_rust_import_binding(&mut binder, import);
        }
    }
    binder
}
