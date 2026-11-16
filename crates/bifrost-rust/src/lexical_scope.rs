mod index;
use crate::usage_walks::WalkCache;
use brokk_bifrost_core::allocation_size::allocation_size;
use brokk_bifrost_core::analyzer::common::{
    parse_source_range_with_cancellation, parse_source_region,
};
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredImportPathKind};
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::structural::spec::BindingWorkLimit;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportBinding, ImportKind};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::retention_budget::{Accounted, RetainedBytes, RetentionBudget};
pub use index::RustPlainScope;
use index::{RustScopeFeed, RustWalkScope, ScopeArena};
use std::collections::HashSet;
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
    use_statements: WalkCache<(SourceKey, usize), SourceCached<Vec<RustUseStatement>>>,
    /// Whole-file `use` scans this cache performed (a cache miss), for tests and
    /// telemetry that check several lookups share one scan.
    use_scans: AtomicUsize,
    scope_builds: AtomicUsize,
}

impl RustLexicalCaches {
    /// Successful scope-index builds owned by this cache.
    pub fn scope_index_builds(&self) -> usize {
        self.scope_builds.load(Ordering::Relaxed)
    }

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
            scope_builds: AtomicUsize::new(0),
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
    // The Arc source buffer includes its two reference counters.
    to_weight(
        std::mem::size_of_val(cached)
            + allocation_size(2 * std::mem::size_of::<usize>() + cached.source.len())
                .saturating_add(nodes.saturating_mul(TREE_SITTER_NODE_BYTES)),
    )
}

fn weigh_scope_index(_: &SourceKey, cached: &SourceCached<RustLexicalScopeIndex>) -> u32 {
    let index = &cached.value;
    // The table is one allocation; each list value owns another.
    let table = brokk_bifrost_core::hash::allocated_table_slot_bytes::<(String, Vec<ItemVisibility>)>(
        index.items.capacity(),
    );
    let lists = index
        .items
        .values()
        .map(crate::cache::vec_buffer_bytes)
        .sum::<usize>();
    let names = index
        .items
        .keys()
        .map(crate::cache::string_bytes)
        .sum::<usize>();
    // The Arc source buffer includes its two reference counters.
    to_weight(
        std::mem::size_of_val(cached)
            + allocation_size(2 * std::mem::size_of::<usize>() + cached.source.len())
                .saturating_add(table)
                .saturating_add(lists)
                .saturating_add(names)
                .saturating_add(crate::cache::vec_buffer_bytes(&index.modules))
                .saturating_add(index.arena.retained_bytes()),
    )
}

fn weigh_use_statements(
    _: &(SourceKey, usize),
    cached: &SourceCached<Vec<RustUseStatement>>,
) -> u32 {
    let imports = cached
        .value
        .iter()
        .map(|statement| {
            crate::cache::vec_buffer_bytes(&statement.imports)
                + statement
                    .imports
                    .iter()
                    .map(|import| {
                        crate::cache::string_bytes(&import.raw_snippet)
                            + import
                                .identifier
                                .as_ref()
                                .map_or(0, crate::cache::string_bytes)
                            + import.alias.as_ref().map_or(0, crate::cache::string_bytes)
                            + import.path.as_ref().map_or(0, |path| {
                                crate::cache::vec_buffer_bytes(&path.segments)
                                    + path
                                        .segments
                                        .iter()
                                        .map(crate::cache::string_bytes)
                                        .sum::<usize>()
                                    + crate::cache::vec_buffer_bytes(&path.lexical_prefixes)
                                    + path
                                        .lexical_prefixes
                                        .iter()
                                        .map(crate::cache::string_bytes)
                                        .sum::<usize>()
                                    + crate::cache::vec_buffer_bytes(&path.lexical_scopes)
                            })
                    })
                    .sum::<usize>()
        })
        .sum::<usize>();
    // The Arc source buffer includes its two reference counters.
    to_weight(
        std::mem::size_of_val(cached)
            + allocation_size(2 * std::mem::size_of::<usize>() + cached.source.len())
                .saturating_add(crate::cache::vec_buffer_bytes(&cached.value))
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
    source: &str,
) -> Arc<Accounted<SourceCached<RustLexicalScopeIndex>>> {
    rust_lexical_scope_index_bounded_with(caches, source, &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap()
}

fn rust_lexical_scope_index_bounded_with<F, E>(
    caches: &RustLexicalCaches,
    source: &str,
    charge: &mut F,
) -> Result<Arc<Accounted<SourceCached<RustLexicalScopeIndex>>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    charge(0)?;
    if let Some(cached) = cached_for(&caches.scope_indexes, source) {
        return Ok(cached);
    }
    let tree = parse_rust_tree_with(caches, source).expect("Rust source has a plain parse");
    build_scope_index(caches, tree.root_node(), source, charge)
}

/// The index for an admitted whole-file parse. A miss builds from that parse,
/// so the file is not parsed a second time outside its admission. The index
/// holds only byte ranges and scalars, so it is the same for any plain parse
/// of this source, which keeps the source-only cache key sound.
pub(crate) fn rust_lexical_scope_index_for_prepared<F, E>(
    caches: &RustLexicalCaches,
    prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
    charge: &mut F,
) -> Result<Arc<Accounted<SourceCached<RustLexicalScopeIndex>>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let source = prepared.source();
    let tree = prepared.tree();
    // A preprocessed or range-restricted parse is not the plain parse the
    // source-keyed cache stands for.
    assert!(
        prepared.preprocessor().is_none()
            && matches!(
                tree.included_ranges().as_slice(),
                [range] if range.start_byte == 0 && range.end_byte >= source.len()
            ),
        "the Rust scope index needs a plain whole-file parse"
    );
    charge(0)?;
    if let Some(cached) = cached_for(&caches.scope_indexes, source) {
        return Ok(cached);
    }
    build_scope_index(caches, tree.root_node(), source, charge)
}

fn build_scope_index<F, E>(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    charge: &mut F,
) -> Result<Arc<Accounted<SourceCached<RustLexicalScopeIndex>>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let index = RustLexicalScopeIndex::new_bounded(root, source, charge)?;
    RUST_SCOPE_INDEX_BUILDS.fetch_add(1, Ordering::Relaxed);
    caches.scope_builds.fetch_add(1, Ordering::Relaxed);
    Ok(keep_for(&caches.scope_indexes, source, index))
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
    attributed: bool,
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
    arena: ScopeArena,
}

impl RustLexicalScopeIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        Self::new_bounded(root, source, &mut |_| Ok::<_, std::convert::Infallible>(())).unwrap()
    }

    /// Charge each visit as the build runs, so a budget can stop it partway.
    /// A refused or cancelled projection is never published.
    pub fn new_bounded<F, E>(root: Node<'_>, source: &str, charge: &mut F) -> Result<Self, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        let mut nodes = Vec::new();
        let mut parents = Vec::new();
        let mut ids = HashMap::default();
        let mut pending = vec![(root, None)];
        while let Some((node, parent)) = pending.pop() {
            charge(1)?;
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
        let attributes = crate::syntax::RustAttributeGroups::prepare(&nodes, &mut *charge)?;
        let test_scopes = canonical_test_scopes(&nodes, &parents, &ids, source, &mut *charge)?;
        let ancestry = RustCanonicalParents {
            nodes: &nodes,
            parents: &parents,
            ids: &ids,
        };
        let mut index = Self {
            items: HashMap::default(),
            modules: Vec::new(),
            arena: ScopeArena::default(),
        };
        let mut stack = vec![(root, None, false, root.start_byte(), root.end_byte(), None)];
        while let Some((raw_node, module, associated_type, scope_start, scope_end, parent)) =
            stack.pop()
        {
            charge(1)?;
            index.arena.add_locals(raw_node, source, charge)?;
            let scope_id = index.arena.add(
                raw_node,
                parent,
                source,
                &mut *charge,
                &mut |item, charge| {
                    canonical_scope_attributes_known(
                        item,
                        source,
                        &test_scopes,
                        &ancestry,
                        &attributes,
                        charge,
                    )
                },
            )?;
            let mut child_module = module;
            let node = raw_node;
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
                    Some(scope_id),
                )
            }));
        }
        Ok(index)
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

/// Why a bounded scope cannot prove a type's standard-prelude authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RustTypeAuthorityUnknown {
    OpaqueScope,
    OpenGlobInventory,
    GenericParameter,
    AmbiguousBinding,
    PreludeDisabled,
    PreludeConfiguration,
    NotPreludeName,
    LocalBinding,
    ExplicitImport,
}

/// Standard-prelude authority is separate from an unbound lexical head.
#[derive(Debug)]
pub(crate) enum RustTypeAuthority {
    ProvenPrelude,
    Bound,
    Unknown(RustTypeAuthorityUnknown),
}

#[derive(Debug)]
pub(crate) struct RustTypeHeadSelection<'tree> {
    pub head: RustTypeHead<'tree>,
    pub authority: RustTypeAuthority,
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
    type_site_attribute_items_unconditional_bounded(outer_attributes(node), source, charge)
}

fn type_site_attribute_items_unconditional_bounded<'tree, F, E>(
    attributes: impl Iterator<Item = Node<'tree>>,
    source: &str,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    for attribute in attributes {
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
    Import(Node<'tree>, &'projection crate::imports::RustUseBinding),
    ScopeEnd,
}

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustLexicalSelection<T> {
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
    visit_rust_lexical_scope_with_no_items(scope, source, charge, select, &HashSet::new())
}

fn visit_rust_lexical_scope_with_no_items<'tree, F, E, T>(
    scope: Node<'tree>,
    source: &str,
    charge: &mut F,
    select: &mut impl for<'projection> FnMut(
        RustLexicalSelectionEvent<'tree, 'projection>,
        &mut F,
    ) -> Result<std::ops::ControlFlow<T>, E>,
    no_items: &HashSet<usize>,
) -> Result<std::ops::ControlFlow<RustLexicalSelection<T>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    visit_rust_lexical_scope_with_attributes(
        scope,
        charge,
        select,
        no_items,
        &mut |item, charge| type_scope_attributes_known_bounded(item, source, charge),
        &mut |parameter, charge| {
            type_site_attributes_unconditional_bounded(parameter, source, charge)
        },
        &mut |item, charge| {
            crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
                item,
                source,
                &mut *charge,
            )
            .map(|leaves| {
                leaves
                    .into_iter()
                    .map(|leaf| crate::imports::RustUseBinding::from_import(leaf.import))
                    .collect()
            })
        },
    )
}

fn visit_rust_lexical_scope_with_attributes<'tree, F, E, T>(
    scope: Node<'tree>,
    charge: &mut F,
    select: &mut impl for<'projection> FnMut(
        RustLexicalSelectionEvent<'tree, 'projection>,
        &mut F,
    ) -> Result<std::ops::ControlFlow<T>, E>,
    no_items: &HashSet<usize>,
    attributes_known: &mut impl FnMut(Node<'tree>, &mut F) -> Result<bool, E>,
    site_attributes_known: &mut impl FnMut(Node<'tree>, &mut F) -> Result<bool, E>,
    imports: &mut impl FnMut(Node<'tree>, &mut F) -> Result<Vec<crate::imports::RustUseBinding>, E>,
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
            if raw.has_error() || raw.is_missing() || !site_attributes_known(parameter, charge)? {
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
            || (rust_item_macro_invocation(item)
                && !no_items.contains(&item.id())
                && !item
                    .named_child(0)
                    .is_some_and(|child| no_items.contains(&child.id())))
            || !attributes_known(item, charge)?
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
            for leaf in imports(item, charge)? {
                charge(1)?;
                charge(leaf.path().len())?;
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

type RustInnerAttributeProof = (Result<(), RustTypeAuthorityUnknown>, usize);

/// Memo of the site-independent parts of [`rust_type_head_at_bounded`] for
/// one syntax tree: each scope-chain node's inner-attribute check, and which
/// scopes leave a name unbound or make it unknown. A caller asking about many
/// sites in one module would otherwise rescan the module's items and reparse
/// its imports at every site. A scope that selects a declaration is not
/// memoized, so the memo holds no nodes. Each entry keeps the work its scan
/// charged, and a hit charges that work again, so a capped caller runs out of
/// budget exactly where it would without the memo. Keys are node ids of one
/// tree, so the memo must not outlive or be shared beyond that tree.
/// Prelude authority and legacy selection must use separate instances because
/// their effective-inner-attribute proofs have different acceptance rules.
#[derive(Debug, Default)]
pub(crate) struct RustTypeHeadMemo {
    pub(crate) no_items_macros: std::cell::RefCell<HashSet<usize>>,
    inner_attributes_known: std::cell::RefCell<HashMap<usize, RustInnerAttributeProof>>,
    unselected_scopes: std::cell::RefCell<HashMap<(usize, String), (UnselectedScope, usize)>>,
}

impl RustTypeHeadMemo {
    /// Isolate the legacy head proofs while lowering one audited alternate.
    /// Prelude authority uses a different memo and is not changed here.
    pub(crate) fn with_no_items_macros<T>(
        &self,
        no_items: HashSet<usize>,
        lower: impl FnOnce() -> T,
    ) -> T {
        struct Restore<'a> {
            memo: &'a RustTypeHeadMemo,
            saved: RustTypeHeadMemo,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.memo
                    .no_items_macros
                    .replace(self.saved.no_items_macros.take());
                self.memo
                    .inner_attributes_known
                    .replace(self.saved.inner_attributes_known.take());
                self.memo
                    .unselected_scopes
                    .replace(self.saved.unselected_scopes.take());
            }
        }
        let _restore = Restore {
            memo: self,
            saved: RustTypeHeadMemo {
                no_items_macros: std::cell::RefCell::new(self.no_items_macros.replace(no_items)),
                inner_attributes_known: std::cell::RefCell::new(self.inner_attributes_known.take()),
                unselected_scopes: std::cell::RefCell::new(self.unselected_scopes.take()),
            },
        };
        lower()
    }
}

/// A scope's outcome for a name when it selects no declaration.
#[derive(Clone, Copy, Debug)]
enum UnselectedScope {
    /// The scope does not bind the name; the search continues outward.
    Unbound,
    Unknown(RustTypeAuthorityUnknown),
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
    rust_type_head_with_attributes_bounded(
        root,
        source,
        site,
        name,
        memo,
        charge,
        &mut |node, source, work| {
            let Ok(known) =
                rust_scope_inner_attributes_known_bounded(node, source, &mut record_charges(work));
            known
                .then_some(())
                .ok_or(RustTypeAuthorityUnknown::OpaqueScope)
        },
    )
    .map(|selection| selection.head)
}

/// The same bounded scope algorithm, with effective prelude configuration.
/// A separate memo keeps these attribute proofs out of legacy head selection.
pub(crate) fn rust_type_prelude_authority_at_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    name: &str,
    memo: &RustTypeHeadMemo,
    charge: &mut F,
) -> Result<RustTypeHeadSelection<'tree>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    rust_type_head_with_attributes_bounded(
        root,
        source,
        site,
        name,
        memo,
        charge,
        &mut |node, source, work| {
            let Ok(known) =
                rust_scope_prelude_attributes_bounded(node, source, &mut record_charges(work));
            known
        },
    )
}

fn rust_scope_prelude_attributes_bounded<F, E>(
    node: Node<'_>,
    source: &str,
    charge: &mut F,
) -> Result<Result<(), RustTypeAuthorityUnknown>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    charge(1)?;
    if matches!(node.kind(), "source_file" | "declaration_list") {
        let mut cursor = node.walk();
        for attribute in node.named_children(&mut cursor) {
            charge(1)?;
            if attribute.kind() != "inner_attribute_item" {
                continue;
            }
            let Some(attributes) =
                crate::resolution::rust_effective_attributes(std::iter::once(attribute), source)
            else {
                return Ok(Err(RustTypeAuthorityUnknown::PreludeConfiguration));
            };
            for attribute in attributes {
                charge(1)?;
                if attribute.path.len() != 1 {
                    return Ok(Err(RustTypeAuthorityUnknown::PreludeConfiguration));
                }
                match crate::declarations::rust_node_text(attribute.path[0], source) {
                    "no_implicit_prelude" | "no_core" => {
                        return Ok(Err(RustTypeAuthorityUnknown::PreludeDisabled));
                    }
                    "no_std" | "allow" | "warn" | "deny" | "forbid" | "doc" => {}
                    _ => return Ok(Err(RustTypeAuthorityUnknown::PreludeConfiguration)),
                }
            }
        }
    }
    Ok(Ok(()))
}

fn rust_type_head_with_attributes_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    name: &str,
    memo: &RustTypeHeadMemo,
    charge: &mut F,
    attributes: &mut impl FnMut(Node<'tree>, &str, &mut usize) -> Result<(), RustTypeAuthorityUnknown>,
) -> Result<RustTypeHeadSelection<'tree>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    let scopes = match rust_lexical_scope_chain_bounded(root, source, site, charge, &mut |_, _| {
        Ok(ControlFlow::<RustTypeHead<'tree>>::Continue(()))
    })? {
        ControlFlow::Continue(scopes) => scopes,
        ControlFlow::Break(_) => {
            return Ok(type_head_unknown(RustTypeAuthorityUnknown::OpaqueScope));
        }
    };
    for node in &scopes {
        let cached = memo
            .inner_attributes_known
            .borrow()
            .get(&node.id())
            .copied();
        let (known, work) = cached.unwrap_or_else(|| {
            let mut work = 0;
            let known = attributes(*node, source, &mut work);
            memo.inner_attributes_known
                .borrow_mut()
                .insert(node.id(), (known, work));
            (known, work)
        });
        charge(work)?;
        if let Err(reason) = known {
            return Ok(type_head_unknown(reason));
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
                    UnselectedScope::Unknown(reason) => Some(type_head_unknown(reason)),
                }
            }
            None => {
                let mut work = 0;
                let Ok(head) = rust_scope_type_head_bounded(
                    scope,
                    source,
                    name,
                    &memo.no_items_macros.borrow(),
                    &mut record_charges(&mut work),
                );
                let unselected = match head {
                    None => Some(UnselectedScope::Unbound),
                    Some(RustTypeHeadSelection {
                        head: RustTypeHead::Unknown,
                        authority: RustTypeAuthority::Unknown(reason),
                    }) => Some(UnselectedScope::Unknown(reason)),
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
    Ok(unbound_type_head(name))
}

fn unbound_type_head<'tree>(name: &str) -> RustTypeHeadSelection<'tree> {
    RustTypeHeadSelection {
        head: RustTypeHead::Unbound,
        // These entries exist in every edition's core prelude. Later-edition
        // or allocator-only names need selected crate configuration instead.
        //
        // The proof sees only this file. In an out-of-line module, the crate
        // root's attributes are elsewhere, which is sound for every stable
        // configuration: `#![no_implicit_prelude]` (on the crate root or an
        // enclosing `#[no_implicit_prelude] mod foo;`) leaves this file to
        // import the name itself, and that import is seen here as Bound or
        // as an open glob; `#![no_std]` keeps the same core trait. The one
        // uncovered case is `#[prelude_import]` at the crate root, which
        // needs the rustc-internal `#![feature(prelude_import)]`. Carrying
        // crate-root facts (edition, no_implicit_prelude, prelude_import)
        // into Rust lowering is #12287.
        authority: if crate::prelude::rust_prelude_name(
            name,
            crate::prelude::RustPreludeNamespace::Type,
            crate::prelude::RustEdition::E2015,
            crate::prelude::RustPreludeCrate::Core,
        )
        .is_some()
        {
            RustTypeAuthority::ProvenPrelude
        } else {
            RustTypeAuthority::Unknown(RustTypeAuthorityUnknown::NotPreludeName)
        },
    }
}

fn type_head_unknown<'tree>(reason: RustTypeAuthorityUnknown) -> RustTypeHeadSelection<'tree> {
    RustTypeHeadSelection {
        head: RustTypeHead::Unknown,
        authority: RustTypeAuthority::Unknown(reason),
    }
}

/// The type head that one scope selects for `name`, or `None` when the scope
/// does not bind it and the search continues outward.
fn rust_scope_type_head_bounded<'tree, F, E>(
    scope: Node<'tree>,
    source: &str,
    name: &str,
    no_items: &HashSet<usize>,
    charge: &mut F,
) -> Result<Option<RustTypeHeadSelection<'tree>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    rust_scope_type_head_with_feed(scope, source, name, no_items, charge, &RustWalkScope)
}

fn rust_scope_type_head_with_feed<'tree, F, E>(
    scope: Node<'tree>,
    source: &str,
    name: &str,
    no_items: &HashSet<usize>,
    charge: &mut F,
    feed: &impl RustScopeFeed<'tree>,
) -> Result<Option<RustTypeHeadSelection<'tree>>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    let mut candidates = Vec::new();
    let selection = feed.scope(
        scope,
        source,
        name,
        charge,
        &mut |event, charge| {
            match event {
                RustLexicalSelectionEvent::Ancestor(_) => {}
                RustLexicalSelectionEvent::Parameter(parameter) => {
                    if parameter.kind() == "type_parameter"
                        && parameter.child_by_field_name("name").is_some_and(|node| {
                            crate::declarations::rust_node_text(node, source) == name
                        })
                    {
                        return Ok(ControlFlow::Break(type_head_unknown(
                            RustTypeAuthorityUnknown::GenericParameter,
                        )));
                    }
                }
                RustLexicalSelectionEvent::Item(item) => {
                    if is_type_namespace_item(item)
                        && item.child_by_field_name("name").is_some_and(|node| {
                            crate::declarations::rust_node_text(node, source) == name
                        })
                    {
                        if item.has_error() || outer_attributes(item).next().is_some() {
                            return Ok(ControlFlow::Break(type_head_unknown(
                                RustTypeAuthorityUnknown::OpaqueScope,
                            )));
                        }
                        charge(1)?;
                        candidates.push(RustTypeHeadSelection {
                            head: RustTypeHead::Item(item),
                            authority: RustTypeAuthority::Bound,
                        });
                    }
                }
                RustLexicalSelectionEvent::Import(item, leaf) => match leaf.binding_name() {
                    RustImportBindingName::Glob => {
                        return Ok(ControlFlow::Break(type_head_unknown(
                            RustTypeAuthorityUnknown::OpenGlobInventory,
                        )));
                    }
                    RustImportBindingName::Named(binding)
                        if crate::imports::rust_binding_name_matches(&binding, name) =>
                    {
                        if item.has_error() || outer_attributes(item).next().is_some() {
                            return Ok(ControlFlow::Break(type_head_unknown(
                                RustTypeAuthorityUnknown::OpaqueScope,
                            )));
                        }
                        for segment in leaf.path() {
                            charge(1)?;
                            charge(segment.len())?;
                        }
                        charge(1)?;
                        candidates.push(RustTypeHeadSelection {
                            authority: RustTypeAuthority::Bound,
                            head: RustTypeHead::Import {
                                path: leaf.path().to_vec(),
                                declaration: item,
                            },
                        });
                    }
                    _ => {}
                },
                RustLexicalSelectionEvent::ScopeEnd => match candidates.len() {
                    0 => {}
                    1 => {
                        return Ok(ControlFlow::Break(candidates.pop().expect("one candidate")));
                    }
                    _ => {
                        return Ok(ControlFlow::Break(type_head_unknown(
                            RustTypeAuthorityUnknown::AmbiguousBinding,
                        )));
                    }
                },
            }
            Ok(ControlFlow::Continue(()))
        },
        no_items,
    )?;
    Ok(match selection {
        ControlFlow::Continue(()) => None,
        ControlFlow::Break(RustLexicalSelection::Selected(head)) => Some(head),
        ControlFlow::Break(RustLexicalSelection::Unknown) => {
            Some(type_head_unknown(RustTypeAuthorityUnknown::OpaqueScope))
        }
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
    rust_pattern_identifier_binding_bounded_with_feed(root, source, pattern, charge, &RustWalkScope)
}

fn rust_pattern_identifier_binding_bounded_with_feed<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    pattern: Node<'tree>,
    charge: &mut F,
    feed: &impl RustScopeFeed<'tree>,
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
    let selection = feed.visit(root, source, pattern, name, charge, |event, _charge| {
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
            RustLexicalSelectionEvent::Import(_, leaf) => match leaf.binding_name() {
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
    rust_value_name_bounded_with_feed(root, source, site, charge, &RustWalkScope)
}

fn rust_value_name_bounded_with_feed<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    site: Node<'tree>,
    charge: &mut F,
    feed: &impl RustScopeFeed<'tree>,
) -> Result<RustValueName<'tree>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    let text = crate::declarations::rust_node_text(site, source);
    let selected = feed.visit(
        root,
        source,
        site,
        text,
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
                    let occupied = feed.foreign_occupied(item, source, text, charge)?;
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
                    if feed.later_opaque(item, charge)? {
                        return Ok(ControlFlow::Break(RustValueName::Unknown));
                    }
                    match item.kind() {
                        "const_item" => {
                            let identity_free = match item.child_by_field_name("type") {
                                Some(ty) => const_type_is_identity_free(ty, source, |leaf| {
                                    feed.primitive_unbound(root, source, leaf, charge)
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
                    if matches!(leaf.binding_name(), RustImportBindingName::Named(binding) if binding == text)
                        || matches!(leaf.binding_name(), RustImportBindingName::Glob) =>
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

// Rust spells `let mut x` with a mutable_specifier beside the pattern,
// while nested `mut` and `ref` patterns wrap their identifier.
fn rust_pattern_has_binding_modifier(name: Node<'_>, parent: Option<Node<'_>>) -> bool {
    let Some(parent) = parent else { return false };
    if matches!(
        parent.kind(),
        "mut_pattern" | "ref_pattern" | "captured_pattern"
    ) {
        return true;
    }
    if parent.child_by_field_name("pattern") != Some(name) {
        return false;
    }
    let mut cursor = parent.walk();
    parent
        .named_children(&mut cursor)
        .any(|child| child.kind() == "mutable_specifier")
}

/// Shared identifier-pattern classification for lets, parameters, loop patterns,
/// and match arms. Keep binding-versus-value decisions here (including #13019):
/// explicit binding modifiers need no lookup; bare names require value-name
/// evidence, and unproven glob absence remains Unknown.
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
    rust_pattern_name_bounded_with_feed(root, source, name, charge, &RustWalkScope)
}

fn rust_pattern_name_bounded_with_feed<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    name: Node<'tree>,
    charge: &mut F,
    feed: &impl RustScopeFeed<'tree>,
) -> Result<RustPatternName, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let (selection, prelude_constructor, saw_glob) =
        rust_pattern_name_selection_bounded_with_feed(root, source, name, charge, feed)?;
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

/// The only stop canonical preparation can produce. Work allowances are not
/// representable in this API, so a producer cannot publish a limit as Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RustPreparationCancelled;

pub(crate) struct RustPreparationWork<'a> {
    cancellation: Option<&'a brokk_bifrost_core::CancellationToken>,
    pub(crate) work: usize,
    #[cfg(test)]
    checks: usize,
    #[cfg(test)]
    phases: [usize; 3],
}

impl<'a> RustPreparationWork<'a> {
    pub(crate) fn new(cancellation: Option<&'a brokk_bifrost_core::CancellationToken>) -> Self {
        Self {
            cancellation,
            work: 0,
            #[cfg(test)]
            checks: 0,
            #[cfg(test)]
            phases: [0; 3],
        }
    }

    pub(crate) fn charge(&mut self, amount: usize) -> Result<(), RustPreparationCancelled> {
        self.work += amount;
        #[cfg(test)]
        {
            self.checks += 1;
        }
        if self.cancellation.is_some_and(|token| token.is_cancelled()) {
            Err(RustPreparationCancelled)
        } else {
            Ok(())
        }
    }
}

/// Compatibility facade for query identity callers. The first lookup prepares
/// the complete file; subsequent lookups never simulate historical prefix work.
#[derive(Default)]
pub(crate) struct RustStrictPatternIndex {
    prepared: Option<RustCanonicalPatternIndex>,
    #[cfg(test)]
    pub(crate) scope_scans: usize,
    #[cfg(test)]
    pub(crate) source_file_scans: usize,
}

#[derive(Default)]
struct RustPatternScopeSummary {
    selected: HashMap<String, (RustPatternName, bool)>,
    saw_glob: bool,
    unknown: bool,
}

/// Completed, request-local canonical answers. There is no bounded constructor.
/// Temporary tree nodes, scope maps and active name stacks die in `prepare`.
pub(crate) struct RustCanonicalPatternIndex {
    answers: HashMap<usize, RustPatternName>,
    pub(crate) test_scopes: HashMap<usize, bool>,
    #[cfg(test)]
    scans: usize,
}

impl RustStrictPatternIndex {
    pub(crate) fn classify(
        &mut self,
        root: Node<'_>,
        source: &str,
        name: Node<'_>,
    ) -> RustPatternName {
        if self.prepared.is_none() {
            let prepared = RustCanonicalPatternIndex::prepare(
                root,
                source,
                &mut RustPreparationWork::new(None),
            )
            .expect("canonical preparation without cancellation");
            #[cfg(test)]
            {
                self.scope_scans = prepared.scans;
                self.source_file_scans = 1;
            }
            self.prepared = Some(prepared);
        }
        self.prepared.as_ref().unwrap().classify(name)
    }

    pub(crate) fn classify_identity_checked(
        &mut self,
        root: Node<'_>,
        source: &str,
        name: Node<'_>,
    ) -> Result<RustPatternName, BindingWorkLimit> {
        // Canonical classification has no query-work stop.
        Ok(self.classify(root, source, name))
    }
}

struct RustCanonicalParents<'a, 'tree> {
    nodes: &'a [Node<'tree>],
    parents: &'a [Option<usize>],
    ids: &'a HashMap<usize, usize>,
}

impl<'tree> RustCanonicalParents<'_, 'tree> {
    fn parent(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        self.parents[self.ids[&node.id()]].map(|id| self.nodes[id])
    }

    fn module_boundary(&self, node: Node<'tree>) -> bool {
        node.kind() == "source_file"
            || (node.kind() == "declaration_list"
                && self
                    .parent(node)
                    .is_some_and(|parent| parent.kind() == "mod_item"))
    }
}

impl RustCanonicalPatternIndex {
    pub(crate) fn classify(&self, name: Node<'_>) -> RustPatternName {
        self.answers
            .get(&name.id())
            .copied()
            .unwrap_or(RustPatternName::Binding)
    }

    pub(crate) fn prepare(
        root: Node<'_>,
        source: &str,
        work: &mut RustPreparationWork<'_>,
    ) -> Result<Self, RustPreparationCancelled> {
        // Preorder node arena: parents precede children, so ancestry metadata
        // is computed once rather than reconstructed for each candidate.
        let mut nodes = Vec::new();
        let mut parents = Vec::new();
        let mut ids = HashMap::default();
        let mut pending = vec![(root, None)];
        let mut needs_test_scopes = false;
        while let Some((node, parent)) = pending.pop() {
            work.charge(1)?;
            if node.kind() == "attribute_item" {
                work.charge(node.end_byte() - node.start_byte())?;
                needs_test_scopes |=
                    crate::resolution::rust_effective_attributes(std::iter::once(node), source)
                        .is_some_and(|attributes| {
                            attributes.into_iter().any(|attribute| {
                                attribute.path.len() == 1
                                    && crate::declarations::rust_node_text(
                                        attribute.path[0],
                                        source,
                                    ) == "test"
                            })
                        });
            }
            let id = nodes.len();
            ids.insert(node.id(), id);
            nodes.push(node);
            parents.push(parent);
            let mut cursor = node.walk();
            let mut children = Vec::new();
            for child in node.named_children(&mut cursor) {
                work.charge(1)?;
                children.push(child);
            }
            for child in children.into_iter().rev() {
                pending.push((child, Some(id)));
            }
        }
        let attributes =
            crate::syntax::RustAttributeGroups::prepare(&nodes, &mut |amount| work.charge(amount))?;
        #[cfg(test)]
        {
            work.phases[0] = work.checks;
        }
        let ancestry = RustCanonicalParents {
            nodes: &nodes,
            parents: &parents,
            ids: &ids,
        };
        let test_scopes = if needs_test_scopes {
            canonical_test_scopes(&nodes, &parents, &ids, source, &mut |amount| {
                work.charge(amount)
            })?
        } else {
            HashMap::default()
        };
        #[cfg(test)]
        {
            work.phases[1] = work.checks;
        }
        let mut result = Self {
            answers: HashMap::default(),
            test_scopes,
            #[cfg(test)]
            scans: 0,
        };
        let mut active: HashMap<String, Vec<(usize, RustPatternName, bool)>> = HashMap::default();
        let mut stack = vec![(0usize, false)];
        let mut summaries = HashMap::default();
        let mut state = Vec::new();
        let mut bad_ancestors = 0usize;
        let mut frontier = None;
        let mut glob = None;
        let mut domain_floor = 0usize;
        let mut lookup_scope = 0usize;
        let mut lookups = HashMap::default();
        while let Some((id, exit)) = stack.pop() {
            work.charge(1)?;
            let node = nodes[id];
            if exit {
                let summary: RustPatternScopeSummary = summaries.remove(&id).unwrap();
                for name in summary.selected.keys() {
                    work.charge(1)?;
                    let values = active.get_mut(name).unwrap();
                    values.pop();
                    if values.is_empty() {
                        active.remove(name);
                    }
                }
                (bad_ancestors, frontier, glob, domain_floor, lookup_scope) = state.pop().unwrap();
                continue;
            }
            state.push((bad_ancestors, frontier, glob, domain_floor, lookup_scope));
            if ancestry.module_boundary(node) {
                domain_floor = id;
                lookup_scope = id;
                frontier = None;
                glob = None;
            }
            let mut charge = |amount| work.charge(amount);
            let bad = node.is_error()
                || node.is_missing()
                || matches!(node.kind(), "macro_invocation" | "macro_definition")
                || !type_site_attribute_items_unconditional_bounded(
                    attributes.attributes(node),
                    source,
                    &mut charge,
                )?
                || !rust_scope_inner_attributes_known_bounded(node, source, &mut charge)?;
            bad_ancestors += usize::from(bad);
            let summary = RustPatternScopeSummary::new_canonical(
                node,
                source,
                &result.test_scopes,
                &ancestry,
                &attributes,
                &mut charge,
            )?;
            #[cfg(test)]
            {
                result.scans += 1;
            }
            // Entries only contain selections before a scope's unknown frontier.
            // A selection at this scope wins that frontier; a deeper one masks
            // both it and the earlier glob. Module boundaries hide outer entries.
            for (name, &(answer, glob_before)) in &summary.selected {
                work.charge(1)?;
                active
                    .entry(name.clone())
                    .or_default()
                    .push((id, answer, glob_before));
            }
            if !summary.selected.is_empty() || summary.unknown || summary.saw_glob {
                lookup_scope = id;
            }
            if summary.unknown {
                frontier = Some(id);
            }
            if summary.saw_glob {
                glob = Some(id);
            }
            if matches!(node.kind(), "identifier" | "shorthand_field_identifier") {
                work.charge(1)?;
                let explicit = rust_pattern_has_binding_modifier(node, ancestry.parent(node));
                let text = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(node, source),
                );
                let answer = if explicit {
                    RustPatternName::Binding
                } else if bad_ancestors > 0 || node.has_error() {
                    RustPatternName::Unknown
                } else {
                    // Empty scopes share their parent's lookup state. Only
                    // queried (scope, name) pairs are memoized, never a cross product.
                    *lookups.entry((lookup_scope, text)).or_insert_with(|| {
                        let selected = active
                            .get(text)
                            .and_then(|entries| entries.last())
                            .filter(|entry| entry.0 >= domain_floor);
                        if let Some(&(scope, answer, glob_before)) = selected {
                            if glob_before
                                || frontier.is_some_and(|f| f > scope)
                                || glob.is_some_and(|g| g > scope)
                            {
                                RustPatternName::Unknown
                            } else {
                                answer
                            }
                        } else if frontier.is_some() || glob.is_some() {
                            RustPatternName::Unknown
                        } else if text == "None"
                            || crate::prelude::rust_std_constructor_fact(text).is_some()
                        {
                            RustPatternName::ValueItem
                        } else {
                            RustPatternName::Binding
                        }
                    })
                };
                result.answers.insert(node.id(), answer);
            }
            summaries.insert(id, summary);
            stack.push((id, true));
            let mut cursor = node.walk();
            let mut children = Vec::new();
            for child in node.named_children(&mut cursor) {
                work.charge(1)?;
                children.push(child);
            }
            for child in children.into_iter().rev() {
                stack.push((ids[&child.id()], false));
            }
        }
        // Publish only the shared ancestry needed by written test attributes.
        // The complete map above was temporary preparation state.
        let mut needed = std::collections::HashSet::new();
        for (id, node) in nodes.iter().enumerate() {
            work.charge(1)?;
            if node.kind() == "attribute_item"
                && crate::resolution::rust_effective_attributes(std::iter::once(*node), source)
                    .is_some_and(|attributes| {
                        attributes.into_iter().any(|attribute| {
                            attribute.path.len() == 1
                                && crate::declarations::rust_node_text(attribute.path[0], source)
                                    == "test"
                        })
                    })
            {
                let mut current = parents[id]
                    .and_then(|p| parents[p])
                    .and_then(|p| parents[p]);
                while let Some(scope) = current {
                    work.charge(1)?;
                    if !needed.insert(nodes[scope].id()) {
                        break;
                    }
                    current = parents[scope];
                }
            }
        }
        let mut published_test_scopes = HashMap::default();
        for id in needed {
            work.charge(1)?;
            published_test_scopes.insert(id, result.test_scopes[&id]);
        }
        result.test_scopes = published_test_scopes;
        #[cfg(test)]
        {
            work.phases[2] = work.checks;
        }
        work.charge(0)?;
        Ok(result)
    }
}

// Summarize local module names and glob edges once. Reverse propagation marks
// every node that can reach a written/opaque `test` export, including cycles.
fn canonical_test_scopes<F, E>(
    nodes: &[Node<'_>],
    parents: &[Option<usize>],
    ids: &HashMap<usize, usize>,
    source: &str,
    charge: &mut F,
) -> Result<HashMap<usize, bool>, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let ancestry = RustCanonicalParents {
        nodes,
        parents,
        ids,
    };
    let n = nodes.len();
    let mut modules = vec![0; n];
    let mut module_parents = vec![None; n];
    let mut names: HashMap<(usize, String), Option<usize>> = HashMap::default();
    let mut direct = vec![false; n];
    let mut exported = vec![false; n];
    let mut edges = vec![Vec::new(); n];
    let mut reverse = vec![Vec::new(); n];
    for (i, &node) in nodes.iter().enumerate() {
        charge(1)?;
        modules[i] = parents[i].map_or(i, |p| modules[p]);
        if ancestry.module_boundary(node) {
            module_parents[i] = parents[i].map(|p| modules[p]);
            modules[i] = i;
        }
        let mut cursor = node.walk();
        for raw in node.named_children(&mut cursor) {
            charge(1)?;
            let item = unwrap_attributes(raw);
            if item.kind() == "mod_item"
                && let Some(name) = item.child_by_field_name("name")
            {
                let text = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(name, source),
                );
                let target = item.child_by_field_name("body").map(|body| ids[&body.id()]);
                names
                    .entry((i, text.to_owned()))
                    .and_modify(|value| *value = None)
                    .or_insert(target);
            }
        }
    }
    for (i, &node) in nodes.iter().enumerate() {
        let mut cursor = node.walk();
        for raw in node.named_children(&mut cursor) {
            charge(1)?;
            let item = unwrap_attributes(raw);
            let named_test = item.child_by_field_name("name").is_some_and(|name| {
                brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(name, source),
                ) == "test"
            });
            exported[i] |= rust_item_macro_invocation(item) || named_test;
            direct[i] |= rust_item_macro_invocation(item)
                || (item.kind() == "macro_definition" && named_test);
            if item.kind() != "use_declaration" {
                continue;
            }
            for leaf in crate::imports::rust_use_bindings_bounded(item, source, &mut |amount| {
                charge(amount)
            })? {
                charge(1)?;
                match leaf.binding_name() {
                    RustImportBindingName::Named(name)
                        if crate::imports::rust_binding_name_matches(&name, "test") =>
                    {
                        exported[i] = true;
                        if !leaf.module_self {
                            direct[i] = true;
                        }
                    }
                    RustImportBindingName::Glob => {
                        let path = leaf.path();
                        let mut at = Some(modules[i]);
                        let mut position = 0;
                        match path.first().map(String::as_str) {
                            Some("crate") => at = None,
                            Some("self") => position = 1,
                            Some("super") => {
                                while path.get(position).is_some_and(|p| p == "super") {
                                    charge(1)?;
                                    at = at.and_then(|m| module_parents[m]);
                                    position += 1;
                                }
                            }
                            _ => {}
                        }
                        for segment in &path[position..] {
                            charge(1)?;
                            at = at
                                .and_then(|m| names.get(&(m, segment.clone())).copied().flatten());
                        }
                        if let Some(target) = at {
                            edges[i].push(target);
                            reverse[target].push(i);
                        } else {
                            exported[i] = true;
                            if !leaf.module_self {
                                direct[i] = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let mut pending = Vec::new();
    for (id, &shadowed) in exported.iter().enumerate() {
        charge(1)?;
        if shadowed {
            pending.push(id);
        }
    }
    while let Some(target) = pending.pop() {
        charge(1)?;
        for &dependent in &reverse[target] {
            charge(1)?;
            if !exported[dependent] {
                exported[dependent] = true;
                pending.push(dependent);
            }
        }
    }
    let mut unshadowed = vec![false; n];
    let mut scopes = HashMap::default();
    for (i, &node) in nodes.iter().enumerate() {
        charge(1)?;
        let mut local = !direct[i];
        for &target in &edges[i] {
            charge(1)?;
            local &= !exported[target];
        }
        unshadowed[i] = local && parents[i].is_none_or(|p| unshadowed[p]);
        scopes.insert(node.id(), unshadowed[i]);
    }
    Ok(scopes)
}

fn canonical_scope_attributes_known<'tree, F, E>(
    node: Node<'tree>,
    source: &str,
    test_scopes: &HashMap<usize, bool>,
    ancestry: &RustCanonicalParents<'_, 'tree>,
    attributes: &crate::syntax::RustAttributeGroups<'tree>,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    for attribute in attributes.attributes(node) {
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
                // Parent metadata is prepared once; no ancestry scan per test.
                if !ancestry
                    .parent(node)
                    .is_some_and(|p| test_scopes.get(&p.id()) == Some(&true))
                {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

impl RustPatternScopeSummary {
    fn new_canonical<'tree, E>(
        scope: Node<'tree>,
        source: &str,
        test_scopes: &HashMap<usize, bool>,
        ancestry: &RustCanonicalParents<'_, 'tree>,
        attributes: &crate::syntax::RustAttributeGroups<'tree>,
        charge_work: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<Self, E> {
        use std::ops::ControlFlow;
        let mut summary = Self::default();
        let result = visit_rust_lexical_scope_with_attributes(
            scope,
            charge_work,
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
                                ));
                        }
                    }
                    RustLexicalSelectionEvent::Item(item) => {
                        let associated = scope.kind() == "declaration_list"
                            && ancestry.parent(scope).is_some_and(|parent| {
                                matches!(parent.kind(), "impl_item" | "trait_item")
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
                                    .or_insert((selection, summary.saw_glob));
                            }
                        }
                    }
                    RustLexicalSelectionEvent::Import(_, leaf) => match leaf.binding_name() {
                        RustImportBindingName::Glob => summary.saw_glob = true,
                        RustImportBindingName::Named(binding) => {
                            summary
                                .selected
                                .entry(binding.to_string())
                                .or_insert((RustPatternName::Unknown, summary.saw_glob));
                        }
                        RustImportBindingName::Unnamed => {}
                    },
                    _ => {}
                }
                Ok(ControlFlow::<()>::Continue(()))
            },
            &HashSet::new(),
            &mut |item, charge| {
                canonical_scope_attributes_known(
                    item,
                    source,
                    test_scopes,
                    ancestry,
                    attributes,
                    charge,
                )
            },
            &mut |parameter, charge| {
                type_site_attribute_items_unconditional_bounded(
                    attributes.attributes(parameter),
                    source,
                    charge,
                )
            },
            &mut |item, charge| {
                crate::imports::rust_use_bindings_bounded(item, source, &mut *charge)
            },
        );
        summary.unknown = matches!(result?, ControlFlow::Break(RustLexicalSelection::Unknown));
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
    rust_pattern_name_selection_bounded_with_feed(root, source, name, charge, &RustWalkScope)
}

fn rust_pattern_name_selection_bounded_with_feed<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    name: Node<'tree>,
    charge: &mut F,
    feed: &impl RustScopeFeed<'tree>,
) -> Result<(RustLexicalSelection<RustPatternName>, bool, bool), E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    charge(1)?;
    if !matches!(name.kind(), "identifier" | "shorthand_field_identifier")
        || rust_pattern_has_binding_modifier(name, name.parent())
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
    let selection = feed.visit(root, source, name, text, charge, |event, _| {
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
            RustLexicalSelectionEvent::Import(_, leaf) => match leaf.binding_name() {
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
    pattern_binding_identifier_with(
        node,
        &mut |_| Ok::<_, std::convert::Infallible>(()),
        &mut |pattern, target, _| Ok(pattern_contains_binding_identifier(pattern, target)),
    )
    .unwrap()
}

/// The ancestor climb behind `is_pattern_binding_identifier`. The caller
/// supplies the test "is `target` a binder reachable from `pattern`", so a
/// scan over every identifier of one pattern can answer it from one
/// traversal of that pattern instead of one traversal per identifier.
pub(crate) type PatternReaches<'a, 'tree, E> = dyn FnMut(Node<'tree>, Node<'tree>, &mut dyn FnMut(usize) -> Result<(), E>) -> Result<bool, E>
    + 'a;

pub(crate) fn pattern_binding_identifier_with<'tree, E>(
    node: Node<'tree>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
    reaches: &mut PatternReaches<'_, 'tree, E>,
) -> Result<bool, E> {
    if !matches!(node.kind(), "identifier" | "shorthand_field_identifier") {
        return Ok(false);
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        charge(1)?;
        if matches!(
            parent.kind(),
            "let_declaration" | "let_condition" | "parameter" | "match_arm" | "for_expression"
        ) && let Some(pattern) = parent.child_by_field_name("pattern")
            && reaches(pattern, node, charge)?
        {
            return Ok(true);
        }
        if parent.kind() == "closure_parameters" && reaches(parent, node, charge)? {
            return Ok(true);
        }
        if matches!(
            parent.kind(),
            "block" | "function_item" | "closure_expression"
        ) {
            return Ok(false);
        }
        current = parent.parent();
    }
    Ok(false)
}

/// Ids of every identifier `pattern_contains_binding_identifier` can reach
/// from `pattern`, from one charged traversal.
pub(crate) fn pattern_binding_identifier_ids<E>(
    pattern: Node<'_>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<HashSet<usize>, E> {
    let mut ids = HashSet::default();
    visit_pattern_binding_identifiers(pattern, charge, &mut |node| {
        ids.insert(node.id());
        std::ops::ControlFlow::Continue(())
    })?;
    Ok(ids)
}

/// Visit each binder identifier reachable from `pattern`. Returns whether the
/// visitor stopped the traversal.
fn visit_pattern_binding_identifiers<'tree, E>(
    pattern: Node<'tree>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
    visit: &mut dyn FnMut(Node<'tree>) -> std::ops::ControlFlow<()>,
) -> Result<bool, E> {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        charge(1)?;
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {}
            "identifier" | "shorthand_field_identifier" => {
                if visit(node).is_break() {
                    return Ok(true);
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
    Ok(false)
}

fn pattern_contains_binding_identifier(pattern: Node<'_>, target: Node<'_>) -> bool {
    visit_pattern_binding_identifiers(
        pattern,
        &mut |_| Ok::<_, std::convert::Infallible>(()),
        &mut |node| {
            if node.id() == target.id() {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        },
    )
    .unwrap()
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
    #[hardwon("#11906: cancellation during canonical preparation must never become Open")]
    fn canonical_preparation_cancellation_in_each_phase() {
        let source = format!(
            "mod a{{macro_rules! test{{()=>{{}}}}}} mod b{{use super::a::*;#[test] fn t(){{}}}} fn f(v:i32){{{} match v{{x=>()}}}}",
            "let _=0;".repeat(512)
        );
        let tree = parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut completed = RustPreparationWork::new(None);
        RustCanonicalPatternIndex::prepare(root, &source, &mut completed).unwrap();
        for (phase, stop) in [5, completed.phases[0] + 5, completed.phases[1] + 5]
            .into_iter()
            .enumerate()
        {
            let token = brokk_bifrost_core::CancellationToken::cancel_after_checks_for_test(stop);
            let mut work = RustPreparationWork::new(Some(&token));
            assert!(matches!(
                RustCanonicalPatternIndex::prepare(root, &source, &mut work),
                Err(RustPreparationCancelled)
            ));
            assert!(token.cancel_after_checks_tripped_for_test());
            assert_eq!(
                work.phases[phase], 0,
                "phase {phase} never returned a complete index"
            );
        }
    }

    #[test]
    #[hardwon("#11906: scope/name lookups and replayed prefixes multiplied canonical work")]
    fn canonical_pattern_preparation_linear_growth() {
        use std::fmt::Write;
        for family in [
            "named-nodes",
            "scope-prefix",
            "candidates",
            "deep-scopes",
            "test-globs",
            "attributes",
            "deep-imports",
            "tuple-elements",
        ] {
            let mut previous = None;
            for size in match family {
                "deep-scopes" | "deep-imports" => [256usize, 512, 1024],
                "test-globs" => [1024, 2048, 4096],
                _ => [16_384, 32_768, 65_536],
            } {
                let mut source = String::new();
                match family {
                    "named-nodes" => {
                        source.push_str("fn f(v:i32) {");
                        for _ in 0..size {
                            source.push_str("let _ = 0;");
                        }
                        source.push_str("match v { late => () }}");
                    }
                    "scope-prefix" => {
                        for i in 0..size {
                            write!(source, "const C{i}:i32={i};").unwrap();
                        }
                        source.push_str("const LATE:i32=1;fn f(v:i32){match v {");
                        for _ in 0..size {
                            source.push_str("LATE=>(),");
                        }
                        source.push_str("late=>()}}");
                    }
                    "candidates" => {
                        source.push_str("fn f(v:i32){match v{");
                        for i in 0..size {
                            write!(source, "same=>(),n{i}=>(),").unwrap();
                        }
                        source.push_str("late=>()}}");
                    }
                    "deep-scopes" => {
                        source.push_str("fn f(v:i32){");
                        for i in 0..size {
                            write!(source, "{{match v{{n{i}=>()}};").unwrap();
                        }
                        source.push_str("match v{late=>()}");
                        for _ in 0..size {
                            source.push('}');
                        }
                        source.push('}');
                    }
                    "deep-imports" => {
                        source.push_str("fn f(v:i32){");
                        for i in 0..size {
                            write!(source, "{{use dep::I{i:05};").unwrap();
                        }
                        source.push_str("match v{late=>()}");
                        for _ in 0..size {
                            source.push('}');
                        }
                        source.push('}');
                    }
                    "tuple-elements" => {
                        source.push_str("fn f(v:i32){let _=(");
                        source.push_str(&"0,".repeat(size));
                        source.push_str(");match v{late=>()}}");
                    }
                    "attributes" => {
                        source.push_str(&"#[inline]\n".repeat(size));
                        source.push_str("fn f(v:i32){match v{late=>()}}");
                    }
                    "test-globs" => {
                        source.push_str("mod m00000{}");
                        for i in 1..size {
                            write!(
                                source,
                                "mod m{i:05}{{use super::m{:05}::*; #[test] fn t(){{}}}}",
                                i - 1
                            )
                            .unwrap();
                        }
                        source.push_str("fn f(v:i32){match v{late=>()}}");
                    }
                    _ => unreachable!(),
                }
                let tree = parse_rust_tree_uncached(&source).unwrap();
                let root = tree.root_node();
                assert!(!root.has_error(), "{family}/{size}");
                let mut work = RustPreparationWork::new(None);
                let prepared =
                    RustCanonicalPatternIndex::prepare(root, &source, &mut work).unwrap();
                let mut pending = vec![root];
                let mut found = false;
                let mut named = 0;
                while let Some(node) = pending.pop() {
                    named += 1;
                    if node.kind() == "identifier"
                        && crate::declarations::rust_node_text(node, &source) == "late"
                    {
                        assert_eq!(
                            prepared.classify(node),
                            RustPatternName::Binding,
                            "{family}/{size}"
                        );
                        found = true;
                    }
                    if node.kind() == "identifier"
                        && crate::declarations::rust_node_text(node, &source) == "LATE"
                        && node.parent().is_some_and(|p| p.kind() == "match_pattern")
                    {
                        assert_eq!(prepared.classify(node), RustPatternName::ValueItem);
                    }
                    pending.extend(node.named_children(&mut node.walk()));
                }
                assert!(found);
                if size == 65_536 && family != "tuple-elements" {
                    assert!(named > 100_000);
                }
                let ratio = previous.map_or(0.0, |p| work.work as f64 / p as f64);
                println!(
                    "{family} | {size} | nodes={named},work={} | {ratio:.4}",
                    work.work
                );
                if let Some(previous) = previous {
                    assert!(
                        work.work <= 2 * previous + 4096,
                        "{family}: {previous} -> {}",
                        work.work
                    );
                }
                assert!(
                    work.work <= 128 * named,
                    "{family}: {} work for {named} nodes",
                    work.work
                );
                previous = Some(work.work);
            }
        }
    }

    #[test]
    #[hardwon(
        "#13018: a mut or ref let pattern under a glob import was treated as a possible imported value"
    )]
    fn glob_modified_pattern_bindings() {
        let source = "use dep::*;fn f(){let mut x=0;let ref y=1;let ref mut z=2;let bare=3;}";
        let tree = parse_rust_tree_uncached(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error());
        let prepared =
            RustCanonicalPatternIndex::prepare(root, source, &mut RustPreparationWork::new(None))
                .unwrap();
        let mut pending = vec![root];
        let mut checked = 0;
        while let Some(node) = pending.pop() {
            if node.kind() == "identifier" {
                let expected = match crate::declarations::rust_node_text(node, source) {
                    "x" | "y" | "z" => Some(RustPatternName::Binding),
                    "bare" => Some(RustPatternName::Unknown),
                    _ => None,
                };
                if let Some(expected) = expected {
                    checked += 1;
                    assert_eq!(
                        rust_pattern_name_bounded(root, source, node, &mut |_| Ok::<_, ()>(()))
                            .unwrap(),
                        expected
                    );
                    assert_eq!(prepared.classify(node), expected);
                }
            }
            pending.extend(node.named_children(&mut node.walk()));
        }
        assert_eq!(checked, 4);
    }

    #[test]
    #[hardwon("#11906: complete indexed selection must preserve semantic uncertainty")]
    fn canonical_pattern_matches_uncapped_semantic_oracle() {
        for source in [
            "use dep::*;fn f(mut p:i32){let mut x=0;let ref y=1;let ref mut z=2;for mut a in [1]{}match p{mut b=>()}let c=|mut d:i32|d;}",
            "const C:i32=1;fn f(v:i32){match v{C=>(),x=>(),None=>()}}",
            "use dep::*; const C:i32=1; fn f(v:i32){match v{C=>(),x=>()}}",
            "const C:i32=1; use dep::*;fn f(v:i32){match v{C=>(),x=>()}}",
            "#[cfg(feature=\"x\")] const C:i32=1;fn f(v:i32){match v{C=>(),x=>()}}",
            "const C:i32=1;mod m{fn f(v:i32){match v{C=>(),x=>()}}}",
            "mod m{#![cfg(feature=\"x\")] fn f(v:i32){match v{x=>()}}}",
            "m!{} const C:i32=1;fn f(v:i32){match v{C=>(),x=>()}}",
            "const C:i32=1;m!{} fn f(v:i32){match v{C=>(),x=>()}}",
            "mod a{}mod b{use super::a::*;#[test] fn t(){match 1{x=>()}}}",
        ] {
            let tree = parse_rust_tree_uncached(source).unwrap();
            let root = tree.root_node();
            let prepared = RustCanonicalPatternIndex::prepare(
                root,
                source,
                &mut RustPreparationWork::new(None),
            )
            .unwrap();
            let mut pending = vec![root];
            while let Some(node) = pending.pop() {
                if matches!(node.kind(), "identifier" | "shorthand_field_identifier") {
                    let expected =
                        rust_pattern_name_strict_bounded(root, source, node, &mut |_| {
                            Ok::<_, ()>(())
                        })
                        .unwrap();
                    assert_eq!(
                        prepared.classify(node),
                        expected,
                        "{source}: {}",
                        crate::declarations::rust_node_text(node, source)
                    );
                }
                pending.extend(node.named_children(&mut node.walk()));
            }
        }
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
        for candidate in candidates {
            assert_eq!(
                index.classify(root, &source, candidate),
                RustPatternName::Binding
            );
        }
        assert_eq!(index.source_file_scans, 1);
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
                RustPatternName::Binding
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
        let token = brokk_bifrost_core::CancellationToken::cancel_after_checks_for_test(300);
        let mut work = RustPreparationWork::new(Some(&token));
        assert!(matches!(
            RustCanonicalPatternIndex::prepare(root, &source, &mut work),
            Err(RustPreparationCancelled)
        ));
        assert!(token.is_cancelled());
        let prepared =
            RustCanonicalPatternIndex::prepare(root, &source, &mut RustPreparationWork::new(None))
                .unwrap();
        assert_eq!(prepared.classify(candidate), RustPatternName::Binding);
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
    #[hardwon("#12159: macro import checks rescanned the whole file for every invocation")]
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
        for _ in 0..32 {
            assert!(macro_import_may_shadow(
                &caches,
                root,
                &source,
                reference_byte,
                "Local"
            ));
            assert!(!macro_import_may_shadow(
                &caches,
                root,
                &source,
                reference_byte,
                "SiblingOnly"
            ));
        }
        assert_eq!(
            caches.use_statement_scans(),
            1,
            "macro checks reuse the file import scan"
        );
        assert!(
            Arc::ptr_eq(&first, &second),
            "expected the use-statement index to be shared across asks"
        );
    }

    #[test]
    #[hardwon(
        "#12159: review found selective and cfg_attr macro_use extern crates escaped both macro shadow proofs"
    )]
    fn selective_macro_use_extern_crate_keeps_macro_imports_open() {
        let source = "#[macro_use(vec)]\nextern crate dependency;\n#[macro_use]\nextern crate enumerated;\n#[cfg_attr(feature = \"custom\", macro_use)]\nextern crate conditional;\nfn run() { let marker = 1; }\n";
        let reference_byte = source.find("marker").expect("reference marker");
        let tree = parse_rust_tree_uncached(source).expect("parse Rust fixture");
        let root = tree.root_node();
        let caches = RustLexicalCaches::new(&RetentionBudget::for_tests());
        let statements = rust_use_statements_with(&caches, root, source);
        let attributed: Vec<bool> = statements
            .iter()
            .map(|statement| statement.attributed)
            .collect();
        // The selected route authority enumerates only the direct blanket form.
        assert_eq!(attributed, [true, false, true]);
        assert!(macro_import_may_shadow(
            &caches,
            root,
            source,
            reference_byte,
            "vec"
        ));
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
    // Operand fragments can share source bytes with the original file while
    // exposing a different syntax tree. Reuse only this tree's inventory.
    let key = (SourceKey::of(source), root.id());
    if let Some(cached) = caches
        .use_statements
        .get(&key)
        .filter(|cached| &*cached.source == source)
    {
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
                // A blanket `#[macro_use] extern crate` is enumerated by the
                // selected route authority, which can prove absence for a
                // given name. The import projection marks only that direct
                // form, so a selective `#[macro_use(name)]` and any
                // `#[cfg_attr(..)]`, which may expand to either form, keep
                // this lexical proof open, as do attributes on use
                // declarations.
                attributed: if node.kind() == "use_declaration" {
                    crate::syntax::outer_attributes(raw_node).next().is_some()
                        || crate::syntax::outer_attributes(node).next().is_some()
                } else {
                    [raw_node, node].into_iter().any(|declaration| {
                        crate::syntax::item_has_path_attribute(declaration, source, "cfg_attr")
                            || crate::imports::rust_item_attribute(declaration, source, "macro_use")
                                .is_some_and(|attribute| {
                                    attribute.child_by_field_name("arguments").is_some()
                                })
                    })
                },
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
    caches.use_statements.keep(
        key,
        SourceCached {
            source: Arc::from(source),
            value: statements,
        },
    )
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

/// Whether a bare prelude name has no visible item or import binding.
/// A glob is harmless only when the caller proves its export closure absent.
/// Reuses the lexical indexes rather than walking imports for each proof.
pub fn prelude_name_is_unbound_with(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    name: &str,
    mut glob_is_absent: impl FnMut(&ImportInfo) -> bool,
) -> bool {
    use crate::imports::{RustImportBindingName, rust_import_binding_name};
    // Item and import binders are indexed without the raw prefix, so compare
    // the written name the same way (`r#String` names `String`).
    let name = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(name);
    if rust_lexical_scope_index_with(caches, source).item_bound_at(name, reference_byte) {
        return false;
    }
    let reference_mod_range = enclosing_mod_item_range_at(root, reference_byte);
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
            match rust_import_binding_name(import) {
                RustImportBindingName::Named(bound) if bound == name => return false,
                RustImportBindingName::Glob if !glob_is_absent(import) => return false,
                _ => {}
            }
        }
    }
    true
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

/// Conservative macro-namespace import proof using the shared iterative scope index.
/// Imports may bind macros regardless of identifier case. Unclosed globs and
/// attributed imports cannot prove absence, including inside function blocks.
pub fn macro_import_may_shadow(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    name: &str,
) -> bool {
    RustMacroImportInventory(rust_use_statements_with(caches, root, source)).may_shadow(
        root,
        reference_byte,
        name,
    )
}

/// Conservative macro-namespace proof for named imports and attributed
/// declarations. Glob imports are classified separately when the caller can
/// prove their macro namespace absent.
pub fn macro_named_import_may_shadow(
    caches: &RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    name: &str,
) -> bool {
    RustMacroImportInventory(rust_use_statements_with(caches, root, source)).named_may_shadow(
        root,
        reference_byte,
        name,
    )
}

/// File-preparation-owned inventory, retained only for this lowering pass.
/// Keeps import syntax available even when the analyzer retention budget is zero.
pub(crate) struct RustMacroImportInventory(Arc<Accounted<SourceCached<Vec<RustUseStatement>>>>);

impl RustMacroImportInventory {
    pub(crate) fn new(root: Node<'_>, source: &str) -> Self {
        let caches = RustLexicalCaches::new(
            &brokk_bifrost_core::retention_budget::RetentionBudget::retain_nothing(),
        );
        Self(rust_use_statements_with(&caches, root, source))
    }

    pub(crate) fn may_shadow(&self, root: Node<'_>, reference_byte: usize, name: &str) -> bool {
        use crate::imports::{RustImportBindingName, rust_import_binding_name};
        let module = enclosing_mod_item_range_at(root, reference_byte);
        self.0.iter().any(|statement| {
            use_statement_visible_at(
                reference_byte,
                module,
                statement.mod_range,
                statement.scope_range,
            ) && (statement.attributed
                || statement
                    .imports
                    .iter()
                    .any(|import| match rust_import_binding_name(import) {
                        RustImportBindingName::Glob => true,
                        RustImportBindingName::Named(bound) => bound == name,
                        RustImportBindingName::Unnamed => false,
                    }))
        })
    }

    pub(crate) fn named_may_shadow(
        &self,
        root: Node<'_>,
        reference_byte: usize,
        name: &str,
    ) -> bool {
        use crate::imports::{RustImportBindingName, rust_import_binding_name};
        let module = enclosing_mod_item_range_at(root, reference_byte);
        self.0.iter().any(|statement| {
            use_statement_visible_at(
                reference_byte,
                module,
                statement.mod_range,
                statement.scope_range,
            ) && (statement.attributed
                || statement.imports.iter().any(|import| {
                    matches!(
                        rust_import_binding_name(import),
                        RustImportBindingName::Named(bound) if bound == name
                    )
                }))
        })
    }
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

#[cfg(all(feature = "test-support", target_os = "linux"))]
#[doc(hidden)]
pub fn check_allocated_lexical_regions() {
    use brokk_bifrost_core::allocation_size::counting::check_region;
    struct Sample<T> {
        _cached: SourceCached<T>,
        bytes: usize,
    }
    impl<T> RetainedBytes for Sample<T> {
        fn retained_bytes(&self) -> usize {
            self.bytes + std::mem::size_of::<Self>()
        }
    }
    let source = "use crate::module::item; pub mod module { pub struct Item; }";
    let tree = parse_rust_tree_uncached(source).expect("valid fixture");
    check_region("rust.lexical.trees", || {
        let cached = SourceCached {
            source: Arc::from(source),
            value: Some(tree.clone()),
        };
        let bytes = weigh_tree(&SourceKey::of(source), &cached) as usize;
        Sample {
            _cached: cached,
            bytes,
        }
    });
    check_region("rust.lexical.scope_indexes", || {
        let cached = SourceCached {
            source: Arc::from(source),
            value: RustLexicalScopeIndex::new(tree.root_node(), source),
        };
        let bytes = weigh_scope_index(&SourceKey::of(source), &cached) as usize;
        Sample {
            _cached: cached,
            bytes,
        }
    });
    check_region("rust.lexical.use_statements", || {
        let cached = SourceCached {
            source: Arc::from(source),
            value: Vec::<RustUseStatement>::with_capacity(8),
        };
        let bytes = weigh_use_statements(&(SourceKey::of(source), 0), &cached) as usize;
        Sample {
            _cached: cached,
            bytes,
        }
    });
}
