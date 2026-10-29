use brokk_bifrost_core::analyzer::common::{
    parse_source_range_with_cancellation, parse_source_region,
};
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredImportPathKind};
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportBinding, ImportKind};
use brokk_bifrost_core::analyzer::weighted_cache::{build_weighted_cache, weight_source_text};
use brokk_bifrost_core::hash::HashMap;
use moka::sync::Cache;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tree_sitter::{Node, Parser, Tree};

use crate::imports::{
    RustImportBindingName, rust_import_binding_name, rust_imports_from_use_declaration,
};
use crate::syntax::{outer_attributes, outer_attributes_with_parent, unwrap_attributes};

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
const RUST_TREE_CACHE_SOURCE_BUDGET_BYTES: u64 = 32 * 1024 * 1024;

static RUST_TREES: OnceLock<Cache<Arc<str>, Option<Tree>>> = OnceLock::new();
static RUST_TREE_PARSES: AtomicUsize = AtomicUsize::new(0);
static RUST_TREE_PARSE_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static RUST_TREE_PARSED_BYTES: AtomicUsize = AtomicUsize::new(0);
static RUST_SCOPE_INDEXES: OnceLock<Cache<Arc<str>, Arc<RustLexicalScopeIndex>>> = OnceLock::new();
static RUST_SCOPE_INDEX_BUILDS: AtomicUsize = AtomicUsize::new(0);

fn rust_scope_index_cache() -> &'static Cache<Arc<str>, Arc<RustLexicalScopeIndex>> {
    RUST_SCOPE_INDEXES.get_or_init(|| {
        build_weighted_cache(RUST_TREE_CACHE_SOURCE_BUDGET_BYTES, weight_source_text)
    })
}

/// The [`RustLexicalScopeIndex`] for `source`, memoized on the exact source
/// bytes like [`parse_rust_tree`].
///
/// Building the index walks the whole file tree. The definition resolvers ask
/// a shadowing question once per reference site, and each ask rebuilt the
/// index from scratch, so resolving every occurrence of a file — the unified
/// reference engine's `usage_graph` shape — walked the file once per
/// occurrence. On `analyze_diff` endpoint graphs over Rust workspaces that
/// quadratic blowup did not finish inside a five-minute budget (public
/// issue #11). The index is a pure function of the source bytes, so the memo
/// is observationally identical, and the weighted cache ages stale entries
/// out exactly like the parse memo above.
///
/// `root` must be the root node of a parse of exactly `source` — the same
/// contract every existing caller already satisfied, asserted here because a
/// mismatched pair would poison the memo for that source text.
pub fn rust_lexical_scope_index(root: Node<'_>, source: &str) -> Arc<RustLexicalScopeIndex> {
    // The root node of a parse spans first token to last token, so only
    // parentlessness and the source bound are checkable here.
    debug_assert!(
        root.parent().is_none() && root.end_byte() <= source.len(),
        "rust_lexical_scope_index needs the whole-source parse root: root spans {}..{} over {} source bytes",
        root.start_byte(),
        root.end_byte(),
        source.len(),
    );
    let cache = rust_scope_index_cache();
    if let Some(cached) = cache.get(source) {
        return cached;
    }
    RUST_SCOPE_INDEX_BUILDS.fetch_add(1, Ordering::Relaxed);
    let index = Arc::new(RustLexicalScopeIndex::new(root, source));
    cache.insert(Arc::from(source), Arc::clone(&index));
    index
}

/// Number of lexical scope indexes actually built since the last reset — the
/// complexity signal for the once-per-occurrence rebuild regression (public
/// issue #11), analogous to the parse counters above.
#[cfg(any(test, feature = "test-support"))]
pub fn rust_scope_index_build_count_for_test() -> usize {
    RUST_SCOPE_INDEX_BUILDS.load(Ordering::Relaxed)
}

fn rust_tree_cache() -> &'static Cache<Arc<str>, Option<Tree>> {
    RUST_TREES.get_or_init(|| {
        build_weighted_cache(RUST_TREE_CACHE_SOURCE_BUDGET_BYTES, weight_source_text)
    })
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

/// Parse `source` as Rust, memoized on the exact source bytes.
///
/// This is a pure function of its argument, but the Rust usage and definition
/// resolvers reach it once per *reference site* and once per *candidate
/// declaration* — `rust_visible_import_resolution`, `lexical_package_at`, and
/// every `is_rust_*_declaration` shape predicate re-parse the whole enclosing
/// file each time they are asked a question about it. On a workspace-wide
/// `scan_usages` that turned into hundreds of thousands of whole-file parses
/// (issue #1219: ~20 minutes at 1200-1600% CPU on Bifrost's own tree, with
/// tree-sitter parsing dominating every stack sample).
///
/// Memoizing here is observationally identical — the same source bytes always
/// produce the same tree — and collapses that to one parse per distinct source.
/// The key is the source text itself, so there is no hash-collision risk and no
/// invalidation to get wrong: edited content is simply a different key, and the
/// weighted cache ages stale entries out. `Tree::clone` is a refcount bump
/// (`ts_tree_copy`), which is also tree-sitter's documented way to hand one
/// parse to several threads.
pub fn parse_rust_tree(source: &str) -> Option<Tree> {
    RUST_TREE_PARSE_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let cache = rust_tree_cache();
    if let Some(cached) = cache.get(source) {
        return cached;
    }
    let parsed = parse_rust_tree_uncached(source);
    cache.insert(Arc::from(source), parsed.clone());
    parsed
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
    // Concurrent tests share the process-wide memo, so a build-count pin must
    // start from a cold cache for its own distinct sources.
    rust_scope_index_cache().invalidate_all();
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

static RUST_USE_STATEMENTS: OnceLock<Cache<Arc<str>, Arc<Vec<RustUseStatement>>>> = OnceLock::new();

fn rust_use_statement_cache() -> &'static Cache<Arc<str>, Arc<Vec<RustUseStatement>>> {
    RUST_USE_STATEMENTS.get_or_init(|| {
        build_weighted_cache(RUST_TREE_CACHE_SOURCE_BUDGET_BYTES, weight_source_text)
    })
}

/// Every `use` declaration in `source` with its visibility-gating ranges,
/// memoized on the exact source bytes like [`parse_rust_tree`] and
/// [`rust_lexical_scope_index`].
///
/// A binder's visibility filter is a pure function of the reference's
/// enclosing `mod` range and scope containment, so per-reference binder
/// questions filter this index instead of re-walking the file and re-parsing
/// each visible `use` per ask — the second whole-file-per-occurrence cost in
/// the public issue #11 `analyze_diff` profile. `root` must be the root node
/// of a parse of exactly `source`, as for [`rust_lexical_scope_index`].
fn rust_use_statements(root: Node<'_>, source: &str) -> Arc<Vec<RustUseStatement>> {
    debug_assert!(
        root.parent().is_none() && root.end_byte() <= source.len(),
        "rust_use_statements needs the whole-source parse root",
    );
    let cache = rust_use_statement_cache();
    if let Some(cached) = cache.get(source) {
        return cached;
    }
    let mut statements = Vec::new();
    // The same source-order traversal as `collect_visible_use_statements`,
    // minus its byte-position pruning: a pruned-away subtree can only hold
    // statements the visibility filter rejects, so filtering this complete
    // index reproduces the pruned walk's output exactly.
    let mut stack = vec![(root, None, None)];
    while let Some((raw_node, mod_range, scope_range)) = stack.pop() {
        let node = unwrap_attributes(raw_node);
        if node.kind() == "use_declaration" {
            statements.push(RustUseStatement {
                imports: rust_imports_from_use_declaration(node, source),
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
    let statements = Arc::new(statements);
    cache.insert(Arc::from(source), Arc::clone(&statements));
    statements
}

/// The scope-start byte of each binder's enclosing visibility scope, so
/// `self`/`super` module specifiers can be resolved against the lexical
/// module the import actually lives in (not just the file package).
pub fn visible_import_binders_with_scopes_in_tree(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
) -> Vec<(usize, ImportBinder)> {
    let reference_mod_range = enclosing_mod_item_range_at(root, reference_byte);
    let mut by_scope: HashMap<(usize, usize), ImportBinder> = HashMap::default();
    for statement in rust_use_statements(root, source).iter() {
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

/// The file package plus the inline `mod` path enclosing `byte` — the
/// lexical package a nested import's `self`/`super` specifiers resolve
/// against (`super` from `mod tests` is the file's own module, not the
/// file's parent).
pub fn lexical_package_at(file_package: &str, source: &str, byte: usize) -> String {
    let Some(tree) = parse_rust_tree(source) else {
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

pub fn visible_import_binder_in_tree(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
) -> ImportBinder {
    let reference_mod_range = enclosing_mod_item_range_at(root, reference_byte);
    let mut binder = ImportBinder::empty();
    for statement in rust_use_statements(root, source).iter() {
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
                "function_signature_item" => {
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
                // Unlike inert attributes, the built-in test macro can be
                // shadowed. Reuse the macro producer's structured import
                // binding projection, including aliases and grouped imports.
                let mut parent = node.parent();
                while let Some(scope) = parent {
                    charge(1)?;
                    let mut cursor = scope.walk();
                    for raw in scope.named_children(&mut cursor) {
                        charge(1)?;
                        let item = unwrap_attributes(raw);
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
                                item, source, &mut *charge,
                            )? {
                                charge(1)?;
                                if !import.import.module_self
                                    && import.import.binding_name().named().is_some_and(|name| {
                                        brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(name) == "test"
                                    })
                                {
                                    return Ok(false);
                                }
                            }
                        }
                    }
                    parent = scope.parent();
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
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
                    RustImportBindingName::Named(binding) if binding == name => {
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
                    RustImportBindingName::Named(binding) => binding == name,
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

/// Recognize a bare pattern name occupied by a value item rather than a
/// binding. Shorthand struct fields force binding syntax and bypass lookup.
/// Unknown selections retain the caller's tentative binding and its gaps.
#[doc(hidden)]
pub fn rust_pattern_identifier_is_value_item_bounded<'tree, F, E>(
    root: Node<'tree>,
    source: &str,
    name: Node<'tree>,
    charge: &mut F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    use std::ops::ControlFlow;
    charge(1)?;
    if name.kind() != "identifier"
        || name.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "mut_pattern" | "ref_pattern" | "captured_pattern"
            )
        })
    {
        return Ok(false);
    }
    let text = crate::declarations::rust_node_text(name, source);
    // Constructors occupy pattern position, while prelude functions such as
    // `drop` can be shadowed by a binding. Select lexical items before falling
    // through to the prelude, so a written function can shadow `None` too.
    let prelude_constructor =
        text == "None" || crate::prelude::rust_std_constructor_fact(text).is_some();
    let selection = visit_rust_lexical_selection_bounded(
        root,
        source,
        name,
        charge,
        |event, _| {
            let occupied = match event {
                RustLexicalSelectionEvent::Parameter(parameter) => {
                    parameter.kind() == "const_parameter"
                        && parameter.child_by_field_name("name").is_some_and(|name| {
                            crate::declarations::rust_node_text(name, source) == text
                        })
                }
                RustLexicalSelectionEvent::Item(item) => {
                    // Associated members require `Self::`; they are not
                    // unqualified value bindings in an implementation body.
                    if crate::syntax::parent_outside_attributes(item).is_some_and(|scope| {
                        scope.kind() == "declaration_list"
                            && scope.parent().is_some_and(|owner| {
                                matches!(owner.kind(), "impl_item" | "trait_item")
                            })
                    }) {
                        return Ok(ControlFlow::Continue(()));
                    }
                    if item.kind() == "function_item"
                        && item.child_by_field_name("name").is_some_and(|name| {
                            crate::declarations::rust_node_text(name, source) == text
                        })
                    {
                        return Ok(ControlFlow::Break(false));
                    }
                    matches!(item.kind(), "const_item" | "static_item" | "struct_item")
                        && item.child_by_field_name("name").is_some_and(|name| {
                            crate::declarations::rust_node_text(name, source) == text
                        })
                }
                RustLexicalSelectionEvent::Import(_, leaf) => {
                    matches!(leaf.import.binding_name(), RustImportBindingName::Named(binding) if binding == text)
                }
                _ => false,
            };
            Ok(if occupied {
                ControlFlow::Break(true)
            } else {
                ControlFlow::Continue(())
            })
        },
    )?;
    Ok(match selection {
        RustLexicalSelection::Selected(occupied) => occupied,
        RustLexicalSelection::Complete | RustLexicalSelection::Unknown => prelude_constructor,
    })
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
        let binder = visible_import_binder_in_tree(root, &source, reference_byte);
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
        let first = rust_use_statements(root, &source);
        let second = rust_use_statements(root, &source);
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
