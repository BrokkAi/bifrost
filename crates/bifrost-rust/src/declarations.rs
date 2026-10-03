use crate::syntax::{item_has_path_attribute, unwrap_attributes};
use brokk_bifrost_core::analyzer::common::{IdentifierSigil, node_ident_text};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::StructuredTypeIdentityBuilder;
use brokk_bifrost_core::analyzer::model::{
    CodeUnitType, DeclarationKind, DispatchExtensibility, PackageAnchor, ParameterMetadata,
    SignatureMetadata, StructuredTypeIdentity, StructuredTypeName,
};
use brokk_bifrost_core::analyzer::parsed_file::{ParsedFile, ParsedSourceFacts, SourceImportFact};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionDefinitionUnitFact;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustCfgCondition, RustImportContextFact, RustImportSourceOccurrences,
    RustItemMacroSourcePosition, RustMacroParseFailure, RustTypeSourceFact,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceImportId, SourceOccurrenceId,
    SourceOccurrenceProvenance, SourceOccurrenceSink,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::TreeWalkAction;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportBinding, ImportKind};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser, Tree, TreeCursor};

use crate::declaration_properties::{
    RustDeclarationPropertyCollector, is_rust_named_declaration_kind,
};
use crate::item_sources::{RustItemSourceCollector, RustItemSourceSink};
use crate::type_syntax::RustTypeSourceCollector;

/// The synthetic module-scope segment Rust uses in `short_name` for
/// package-level `const`/`static`/`type` items (`_module_.NAME`), mirroring
/// Go's `_module_` scope. Emitted as a [`SegmentKind::Package`] segment so the
/// structured name round-trips to the legacy string.
const RUST_MODULE_SCOPE_SEGMENT: &str = "_module_";

/// Intern one qualified-name segment in the process-global interner.
fn rust_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

pub fn rust_file_package_fq(file: &ProjectFile) -> FqName {
    with_rust_package_components(file, |components| {
        let mut fq = FqName::new();
        for component in components {
            fq.push(rust_segment(component, SegmentKind::Package));
        }
        fq
    })
}

pub fn rust_semantic_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in package_name
        .split('.')
        .filter(|component| !component.is_empty())
    {
        fq.push(rust_segment(component, SegmentKind::Package));
    }
    fq
}

/// The [`FqName`] a child declaration extends: its lexical parent's structured
/// name when nested, otherwise the file's package prefix.
fn rust_child_fq_base(parent: Option<&CodeUnit>, file: &ProjectFile) -> FqName {
    match parent {
        Some(parent) => parent.fq().clone(),
        None => rust_file_package_fq(file),
    }
}

use crate::imports::{
    RustImportSourceNodes, RustModuleAnchor, RustProjectedImport,
    rust_import_projection_with_source_nodes,
};

/// Record source identity at declaration creation, before embedded trees are
/// dropped. Consumer identities may repeat; source declaration identities do not.
trait RustDeclarationSourceBridge {
    fn record(&mut self, node: Node<'_>, unit: &CodeUnit) -> SourceDeclarationId;
    fn record_type(&mut self, node: Node<'_>, source: &str) -> &RustTypeSourceFact;
}

struct RustPrimaryDeclarationSourceBridge<'collector, 'source, 'links> {
    collector: &'collector mut PrimarySourceFactCollector<'source>,
    properties: &'collector mut RustDeclarationPropertyCollector<'source>,
    links: &'links mut Vec<(SourceDeclarationId, CodeUnit)>,
    types: &'links mut RustTypeSourceCollector,
}

struct RustEmbeddedDeclarationSourceBridge<'a, 'source> {
    collector: &'a mut PrimarySourceFactCollector<'source>,
    properties: &'a mut RustDeclarationPropertyCollector<'source>,
    module_sources: &'a mut crate::facts::RustModuleSourceCollector<'source>,
    links: &'a mut Vec<(SourceDeclarationId, CodeUnit)>,
    source_maps: &'a mut [RustEmbeddedSourceMap],
    types: &'a mut RustTypeSourceCollector,
    tree_id: usize,
}

struct RustEmbeddedSourceOccurrenceSink<'a, 'source> {
    collector: &'a mut PrimarySourceFactCollector<'source>,
    source_maps: &'a mut [RustEmbeddedSourceMap],
    tree_id: usize,
}

struct RustPrimaryItemSourceSink<'a, 'source> {
    collector: &'a mut PrimarySourceFactCollector<'source>,
    properties: &'a mut RustDeclarationPropertyCollector<'source>,
}

impl SourceOccurrenceSink for RustPrimaryItemSourceSink<'_, '_> {
    fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
        self.collector.intern_node(node)
    }

    fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        self.collector
            .intern_subspan_bytes(start_byte, end_byte, provenance)
    }
}

impl RustItemSourceSink for RustPrimaryItemSourceSink<'_, '_> {
    fn declare_node(&mut self, node: Node<'_>) -> SourceDeclarationId {
        if let Some(declaration) = self.properties.ensure_primary(node, self.collector) {
            return declaration;
        }
        let occurrence = self.collector.intern_node(node);
        let name = node
            .child_by_field_name("name")
            .map(|name| self.collector.intern_node(name));
        self.collector.declare(occurrence, name)
    }
}

impl RustDeclarationSourceBridge for RustPrimaryDeclarationSourceBridge<'_, '_, '_> {
    fn record_type(&mut self, node: Node<'_>, source: &str) -> &RustTypeSourceFact {
        self.types.record_type(node, source, self.collector)
    }

    fn record(&mut self, node: Node<'_>, unit: &CodeUnit) -> SourceDeclarationId {
        let occurrence = self.collector.intern_node(node);
        let name = node
            .child_by_field_name("name")
            .map(|name| self.collector.intern_node(name));
        let declaration = self.collector.declare(occurrence, name);
        self.properties.record_primary(declaration, node);
        self.links.push((declaration, unit.clone()));
        declaration
    }
}

impl RustEmbeddedDeclarationSourceBridge<'_, '_> {
    fn set_tree_id(&mut self, tree_id: usize) {
        self.tree_id = tree_id;
    }

    fn source_import_ids(&self, tree_id: usize, node: Node<'_>) -> &[SourceImportId] {
        self.source_maps[tree_id].source_import_ids(node)
    }

    fn ensure_source_declaration(&mut self, node: Node<'_>) -> SourceDeclarationId {
        let declaration = ensure_embedded_source_declaration(
            self.tree_id,
            node,
            self.collector,
            self.properties,
            self.source_maps,
        );
        if node.kind() == "mod_item" {
            self.module_sources.record_embedded_declaration(
                self.tree_id,
                declaration,
                node,
                self.collector,
                self.source_maps,
            );
        }
        declaration
    }
}

impl SourceOccurrenceSink for RustEmbeddedSourceOccurrenceSink<'_, '_> {
    fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
        self.source_maps[self.tree_id].intern_node(node, self.collector)
    }

    fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        assert_eq!(provenance, SourceOccurrenceProvenance::Embedded);
        self.collector
            .intern_subspan_bytes(start_byte, end_byte, provenance)
    }
}

pub(crate) struct RustEmbeddedSourceMap {
    occurrences: HashMap<usize, SourceOccurrenceId>,
    declarations: HashMap<usize, SourceDeclarationId>,
    imports: HashMap<usize, Vec<SourceImportId>>,
    /// Per-tree property contexts. Embedded items share most of their AST
    /// ancestry, so retaining these only for the live replay tree avoids
    /// repeating depth-proportional parent walks for every item.
    cfg_conditions: HashMap<usize, RustCfgCondition>,
    declaration_ancestries: HashMap<usize, crate::declaration_properties::RustDeclarationAncestry>,
    /// The ancestry of the invocation this tree was parsed for, where the
    /// tree's own root ends; see
    /// [`crate::declaration_properties::RustDeclarationAncestry::of`].
    host: crate::declaration_properties::RustDeclarationAncestry,
    /// The invocation's own effective `cfg`. An item the expansion declares
    /// exists only where the invocation does, so its activation is the
    /// conjunction of this and the item's own attributes.
    host_cfg: RustCfgCondition,
}

/// An empty map for a tree whose invocation is at the top of a file with no
/// `cfg`: what `std::mem::take` leaves behind while a lowering holds the map.
impl Default for RustEmbeddedSourceMap {
    fn default() -> Self {
        Self {
            occurrences: HashMap::default(),
            declarations: HashMap::default(),
            imports: HashMap::default(),
            cfg_conditions: HashMap::default(),
            declaration_ancestries: HashMap::default(),
            host: crate::declaration_properties::RustDeclarationAncestry::default(),
            host_cfg: RustCfgCondition::Always,
        }
    }
}

impl RustEmbeddedSourceMap {
    pub(crate) fn intern_node(
        &mut self,
        node: Node<'_>,
        collector: &mut PrimarySourceFactCollector<'_>,
    ) -> SourceOccurrenceId {
        if let Some(occurrence) = self.occurrences.get(&node.id()).copied() {
            return occurrence;
        }
        let occurrence = collector.intern_subspan_bytes(
            node.start_byte(),
            node.end_byte(),
            SourceOccurrenceProvenance::Embedded,
        );
        assert!(
            self.occurrences.insert(node.id(), occurrence).is_none(),
            "one embedded AST node cannot own two source occurrences"
        );
        occurrence
    }

    pub(crate) const fn host(&self) -> crate::declaration_properties::RustDeclarationAncestry {
        self.host
    }

    pub(crate) const fn host_cfg(&self) -> &RustCfgCondition {
        &self.host_cfg
    }

    pub(crate) fn declare_node(
        &mut self,
        node: Node<'_>,
        collector: &mut PrimarySourceFactCollector<'_>,
    ) -> SourceDeclarationId {
        if let Some(declaration) = self.declarations.get(&node.id()).copied() {
            return declaration;
        }
        let occurrence = self.intern_node(node, collector);
        let name = node
            .child_by_field_name("name")
            .map(|name| self.intern_node(name, collector));
        let declaration = collector.declare(occurrence, name);
        assert!(
            self.declarations.insert(node.id(), declaration).is_none(),
            "one embedded AST node cannot own two source declarations"
        );
        declaration
    }

    fn ensure_source_imports(
        &mut self,
        node: Node<'_>,
        source: &str,
        collector: &mut PrimarySourceFactCollector<'_>,
        source_imports: &mut Vec<SourceImportFact>,
    ) {
        if self.imports.contains_key(&node.id()) {
            return;
        }
        assert!(
            matches!(node.kind(), "use_declaration" | "extern_crate_declaration"),
            "embedded source import cache requires an import declaration"
        );
        let mut ids = Vec::new();
        for (projected, nodes) in rust_import_projection_with_source_nodes(node, source, "") {
            let declaration = self.intern_node(nodes.declaration, collector);
            let target = nodes.target.map(|node| self.intern_node(node, collector));
            let alias = nodes.alias.map(|node| self.intern_node(node, collector));
            let lexical_scopes = nodes
                .lexical_scopes
                .iter()
                .map(|scope| self.intern_node(*scope, collector))
                .collect();
            let source_import_id = SourceImportId::try_from_index(source_imports.len())
                .expect("source import ids must fit in a u32");
            let mut source_import = SourceImportFact::from_import(
                projected.import.info,
                declaration,
                target,
                alias,
                lexical_scopes,
            );
            source_import.is_macro_use = projected.import.is_macro_use;
            source_imports.push(source_import);
            ids.push(source_import_id);
        }
        assert!(
            self.imports.insert(node.id(), ids).is_none(),
            "one embedded import declaration cannot be interpreted twice"
        );
    }

    fn source_import_ids(&self, node: Node<'_>) -> &[SourceImportId] {
        self.imports
            .get(&node.id())
            .expect("embedded import declaration was captured before replay")
            .as_slice()
    }
}

pub(crate) fn ensure_embedded_source_declaration(
    tree_id: usize,
    node: Node<'_>,
    collector: &mut PrimarySourceFactCollector<'_>,
    properties: &mut RustDeclarationPropertyCollector<'_>,
    source_maps: &mut [RustEmbeddedSourceMap],
) -> SourceDeclarationId {
    let declaration = source_maps[tree_id].declare_node(node, collector);
    if is_rust_named_declaration_kind(node.kind()) && node.child_by_field_name("name").is_some() {
        let source_map = &mut source_maps[tree_id];
        properties.record_embedded_with_cache(
            declaration,
            node,
            source_map.host,
            &source_map.host_cfg,
            &mut source_map.cfg_conditions,
            &mut source_map.declaration_ancestries,
        );
    }
    declaration
}

impl RustItemSourceSink for RustEmbeddedSourceOccurrenceSink<'_, '_> {
    fn declare_node(&mut self, node: Node<'_>) -> SourceDeclarationId {
        self.source_maps[self.tree_id].declare_node(node, self.collector)
    }
}

impl RustDeclarationSourceBridge for RustEmbeddedDeclarationSourceBridge<'_, '_> {
    fn record_type(&mut self, node: Node<'_>, source: &str) -> &RustTypeSourceFact {
        let mut sink = RustEmbeddedSourceOccurrenceSink {
            collector: self.collector,
            source_maps: self.source_maps,
            tree_id: self.tree_id,
        };
        self.types.record_type(node, source, &mut sink)
    }

    fn record(&mut self, node: Node<'_>, unit: &CodeUnit) -> SourceDeclarationId {
        let declaration = self.ensure_source_declaration(node);
        self.links.push((declaration, unit.clone()));
        declaration
    }
}

impl SourceOccurrenceSink for RustEmbeddedDeclarationSourceBridge<'_, '_> {
    fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
        self.source_maps[self.tree_id].intern_node(node, self.collector)
    }

    fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        assert_eq!(provenance, SourceOccurrenceProvenance::Embedded);
        self.collector
            .intern_subspan_bytes(start_byte, end_byte, provenance)
    }
}

/// Raw source trees shared by item capture, declaration replay, and routes.
/// Presence in this graph does not grant any consumer's projection admission.
/// `Tree` values are retained only for the duration of one primary macro event;
/// consumers retain facts and source ids, never parser handles.
pub(crate) struct RustEmbeddedReplayGraph {
    trees: Vec<RustEmbeddedReplayTree>,
    source_maps: Vec<RustEmbeddedSourceMap>,
}

pub(crate) struct RustEmbeddedReplayTree {
    tree: Tree,
    child_macros: HashMap<usize, Result<Option<usize>, RustMacroParseFailure>>,
}

impl RustEmbeddedReplayTree {
    pub(crate) fn root(&self) -> Node<'_> {
        self.tree.root_node()
    }

    pub(crate) fn child_tree(&self, node: Node<'_>) -> Option<usize> {
        // Legacy projections visit only returned, nonempty interiors. Source
        // capture consumes the full outcome map and retains failure evidence.
        self.child_macros
            .get(&node.id())
            .copied()
            .and_then(Result::ok)
            .flatten()
    }
}

impl RustEmbeddedReplayGraph {
    fn new(
        tree: Tree,
        host: crate::declaration_properties::RustDeclarationAncestry,
        host_cfg: RustCfgCondition,
    ) -> Self {
        Self {
            trees: vec![RustEmbeddedReplayTree {
                tree,
                child_macros: HashMap::default(),
            }],
            source_maps: vec![RustEmbeddedSourceMap {
                host,
                host_cfg,
                ..RustEmbeddedSourceMap::default()
            }],
        }
    }

    pub(crate) fn root_id(&self) -> usize {
        0
    }

    fn add_tree(
        &mut self,
        tree: Tree,
        host: crate::declaration_properties::RustDeclarationAncestry,
        host_cfg: RustCfgCondition,
    ) -> usize {
        let id = self.trees.len();
        self.trees.push(RustEmbeddedReplayTree {
            tree,
            child_macros: HashMap::default(),
        });
        self.source_maps.push(RustEmbeddedSourceMap {
            host,
            host_cfg,
            ..RustEmbeddedSourceMap::default()
        });
        id
    }

    pub(crate) fn tree(&self, id: usize) -> &Tree {
        &self.trees[id].tree
    }

    pub(crate) fn split_mut(
        &mut self,
    ) -> (&[RustEmbeddedReplayTree], &mut [RustEmbeddedSourceMap]) {
        (&self.trees, &mut self.source_maps)
    }
}

/// Parse the token-tree interior at its exact AST delimiter bounds. The
/// included-range tree keeps byte offsets in the original source, which is
/// required by both route facts and embedded source identities.
pub(crate) fn build_rust_embedded_replay_graph(
    node: Node<'_>,
    source: &str,
) -> Result<Option<RustEmbeddedReplayGraph>, RustMacroParseFailure> {
    let Some(tree) = parse_rust_macro_source_tree(node, source)? else {
        return Ok(None);
    };
    let mut graph = RustEmbeddedReplayGraph::new(
        tree,
        crate::declaration_properties::RustDeclarationAncestry::of(node, None),
        crate::lexical_scope::rust_effective_cfg_condition(node, source),
    );
    let mut pending = vec![graph.root_id()];
    while let Some(tree_id) = pending.pop() {
        let root = graph.trees[tree_id].tree.root_node();
        let source_map = &mut graph.source_maps[tree_id];
        let host = source_map.host;
        let host_cfg = source_map.host_cfg.clone();
        let cfg_conditions = &mut source_map.cfg_conditions;
        let declaration_ancestries = &mut source_map.declaration_ancestries;
        let mut nodes = vec![root];
        let mut child_trees = Vec::new();
        while let Some(current) = nodes.pop() {
            if current.kind() == "macro_invocation" {
                child_trees.push((
                    current.id(),
                    crate::declaration_properties::RustDeclarationAncestry::of_with_cache(
                        current,
                        Some(host),
                        declaration_ancestries,
                    ),
                    RustCfgCondition::conjunction([
                        host_cfg.clone(),
                        crate::lexical_scope::rust_effective_cfg_condition_with_cache(
                            current,
                            source,
                            cfg_conditions,
                        ),
                    ]),
                    parse_rust_macro_source_tree(current, source),
                ));
                continue;
            }
            let mut cursor = current.walk();
            let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
            children.reverse();
            nodes.extend(children);
        }
        for (node_id, child_host, child_cfg, child) in child_trees {
            let outcome = child.map(|child| {
                child.map(|child| {
                    let child_id = graph.add_tree(child, child_host, child_cfg);
                    pending.push(child_id);
                    child_id
                })
            });
            assert!(
                graph.trees[tree_id]
                    .child_macros
                    .insert(node_id, outcome)
                    .is_none()
            );
        }
    }
    Ok(Some(graph))
}

fn parse_rust_macro_source_tree(
    node: Node<'_>,
    source: &str,
) -> Result<Option<Tree>, RustMacroParseFailure> {
    let arguments =
        rust_macro_invocation_arguments(node).ok_or(RustMacroParseFailure::MissingInterior)?;
    let interior =
        rust_macro_token_tree_interior(arguments).ok_or(RustMacroParseFailure::MissingInterior)?;
    if interior.start_byte == interior.end_byte {
        return Ok(None);
    }
    crate::lexical_scope::parse_rust_range_tree(source, interior)
        .map(Some)
        .ok_or(RustMacroParseFailure::ParseUnavailable)
}

#[allow(clippy::too_many_arguments)]
fn collect_rust_embedded_item_sources<'source>(
    invocation: SourceOccurrenceId,
    graph: &mut RustEmbeddedReplayGraph,
    source: &'source str,
    collector: &mut PrimarySourceFactCollector<'source>,
    properties: &mut RustDeclarationPropertyCollector<'source>,
    module_sources: &mut crate::facts::RustModuleSourceCollector<'source>,
    items: &mut RustItemSourceCollector,
    types: &mut RustTypeSourceCollector,
    source_imports: &mut Vec<SourceImportFact>,
) {
    let root_tree = graph.root_id();
    let (trees, maps) = graph.split_mut();
    let root = trees[root_tree].root();
    let root_occurrence = maps[root_tree].intern_node(root, collector);
    items.record_macro(invocation, Ok(Some(root_occurrence)));
    enum Event<'tree> {
        Enter { tree_id: usize, node: Node<'tree> },
        Exit,
    }
    let mut pending = vec![Event::Enter {
        tree_id: root_tree,
        node: root,
    }];
    while let Some(event) = pending.pop() {
        let Event::Enter { tree_id, node } = event else {
            items.exit();
            continue;
        };
        if matches!(node.kind(), "use_declaration" | "extern_crate_declaration") {
            maps[tree_id].ensure_source_imports(node, source, collector, source_imports);
        }
        if is_rust_named_declaration_kind(node.kind()) && node.child_by_field_name("name").is_some()
        {
            let declaration =
                ensure_embedded_source_declaration(tree_id, node, collector, properties, maps);
            if node.kind() == "mod_item" {
                module_sources.record_embedded_declaration(
                    tree_id,
                    declaration,
                    node,
                    collector,
                    maps,
                );
            }
        }
        items.enter(
            node,
            source,
            &mut RustEmbeddedSourceOccurrenceSink {
                collector,
                source_maps: maps,
                tree_id,
            },
            types,
        );
        pending.push(Event::Exit);
        if node.kind() == "macro_invocation" {
            let invocation = maps[tree_id].intern_node(node, collector);
            let outcome = *trees[tree_id]
                .child_macros
                .get(&node.id())
                .expect("the raw graph records every nested macro parse outcome");
            let expansion = outcome.map(|tree| {
                tree.map(|child_tree| {
                    let root = trees[child_tree].root();
                    let occurrence = maps[child_tree].intern_node(root, collector);
                    pending.push(Event::Enter {
                        tree_id: child_tree,
                        node: root,
                    });
                    occurrence
                })
            });
            items.record_macro(invocation, expansion);
            // The child graph owns interpretation of the token-tree interior.
            // Never treat token-tree children as a second source-item parse.
            continue;
        }
        let children = node.named_children(&mut node.walk()).collect::<Vec<_>>();
        pending.extend(
            children
                .into_iter()
                .rev()
                .map(|node| Event::Enter { tree_id, node }),
        );
    }
}

/// Cache projections for the live primary tree by its exact tree-sitter node
/// identity. Forward impl-owner binding and the coordinated event stream then
/// share one projection without a second primary-tree interpretation. Macro
/// fragment reparses never receive this cache: their nodes have independent
/// provenance and continue through their existing explicit path.
struct RustCachedImportProjection<'tree> {
    imports: Vec<RustProjectedImport>,
    source_nodes: Vec<RustImportSourceNodes<'tree>>,
}

struct RustPrimaryImportProjectionCache<'source, 'tree> {
    source: &'source str,
    by_node: HashMap<usize, RustCachedImportProjection<'tree>>,
}

impl<'source, 'tree> RustPrimaryImportProjectionCache<'source, 'tree> {
    fn new(source: &'source str) -> Self {
        Self {
            source,
            by_node: HashMap::default(),
        }
    }

    fn ensure(&mut self, node: Node<'tree>) -> Option<&[RustProjectedImport]> {
        if !matches!(node.kind(), "use_declaration" | "extern_crate_declaration") {
            return None;
        }
        let source = self.source;
        let node_id = node.id();
        let projection = self.by_node.entry(node_id).or_insert_with(|| {
            let projected = rust_import_projection_with_source_nodes(node, source, "");
            let (imports, source_nodes) = projected.into_iter().unzip();
            RustCachedImportProjection {
                imports,
                source_nodes,
            }
        });
        Some(projection.imports.as_slice())
    }

    fn take(
        &mut self,
        node: Node<'tree>,
    ) -> Option<(Vec<RustProjectedImport>, Vec<RustImportSourceNodes<'tree>>)> {
        self.ensure(node)?;
        let projection = self.by_node.remove(&node.id())?;
        Some((projection.imports, projection.source_nodes))
    }
}

fn attach_import_source_occurrences<'source, 'tree>(
    imports: &mut [RustProjectedImport],
    source_nodes: &[RustImportSourceNodes<'tree>],
    collector: &mut PrimarySourceFactCollector<'source>,
    source_imports: &mut Vec<SourceImportFact>,
    rust_import_contexts: &mut Vec<RustImportContextFact>,
) {
    assert_eq!(
        imports.len(),
        source_nodes.len(),
        "every import projection has one exact source-node tuple"
    );
    let Some(first_import) = imports.first() else {
        return;
    };
    let first_nodes = &source_nodes[0];
    assert!(
        imports.iter().all(|import| {
            import.import.visibility == first_import.import.visibility
                && import.cfg_condition == first_import.cfg_condition
        }),
        "grouped Rust import leaves share declaration visibility and cfg"
    );
    assert!(
        source_nodes.iter().all(|nodes| {
            nodes.declaration.id() == first_nodes.declaration.id()
                && nodes.owner_scope.map(|scope| scope.id())
                    == first_nodes.owner_scope.map(|scope| scope.id())
                && nodes.local_scope.map(|scope| scope.id())
                    == first_nodes.local_scope.map(|scope| scope.id())
        }),
        "grouped Rust import leaves share declaration and owner scopes"
    );
    let declaration = collector.intern_node(first_nodes.declaration);
    let owner_scope = first_nodes
        .owner_scope
        .map(|scope| collector.intern_node(scope));
    let local_scope = first_nodes
        .local_scope
        .map(|scope| collector.intern_node(scope));
    let owner_module = match &first_import.owner {
        crate::imports::RustImportOwner::Module { module, .. }
        | crate::imports::RustImportOwner::LocalOnly { module, .. } => module.clone(),
    };
    rust_import_contexts.push(RustImportContextFact {
        declaration,
        native_scope: None,
        owner_module,
        owner_scope,
        local_scope,
        visibility: first_import.import.visibility.clone(),
        cfg_condition: first_import.cfg_condition.clone(),
    });
    for (import, nodes) in imports.iter_mut().zip(source_nodes) {
        assert_eq!(nodes.target.is_none(), import.import.info.is_wildcard);
        assert_eq!(nodes.alias.is_some(), import.import.info.alias.is_some());
        let declaration = collector.intern_node(nodes.declaration);
        let target = nodes.target.map(|node| collector.intern_node(node));
        let alias = nodes.alias.map(|node| collector.intern_node(node));
        let lexical_scopes = nodes
            .lexical_scopes
            .iter()
            .map(|scope| collector.intern_node(*scope))
            .collect();
        let source_import_id = SourceImportId::try_from_index(source_imports.len())
            .expect("source import ids must fit in a u32");
        let mut source_import = SourceImportFact::from_import(
            import.import.info.clone(),
            declaration,
            target,
            alias,
            lexical_scopes,
        );
        source_import.is_macro_use = import.import.is_macro_use;
        source_imports.push(source_import);
        import.source_import_id = Some(source_import_id);
        import.source_occurrences = Some(RustImportSourceOccurrences {
            declaration,
            target,
            alias,
        });
    }
}

/// The `(short_name, fq)` identity every Rust type-namespace declaration
/// carries: the owner's name extended by this declaration's own
/// [`SegmentKind::Type`] segment.
///
/// `struct`, `enum`, `union`, `trait`, `type` alias, and `associated_type` all
/// declare a type, so they all name themselves this way. Keeping the rule in
/// one place is what stops an alias from drifting back onto the `Member`
/// segment a `const` of the same name in the same owner uses (#2911).
fn rust_type_declaration_identity(
    file: &ProjectFile,
    parent: Option<&CodeUnit>,
    name: &str,
) -> (String, FqName) {
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let fq = rust_child_fq_base(parent, file).with_pushed(rust_segment(name, SegmentKind::Type));
    (short_name, fq)
}

/// A member's structured name is built on its parent's, so it is anchored
/// wherever the parent is. This matters for the synthesized owner of an
/// `impl crate::Type` / `impl super::Type` block: without inheritance its
/// members would persist the extracting mount's path-derived package text.
fn rust_inherit_package_anchor(code_unit: CodeUnit, parent: Option<&CodeUnit>) -> CodeUnit {
    match parent.and_then(CodeUnit::package_anchor) {
        Some(anchor) => code_unit.with_package_anchor(anchor),
        None => code_unit,
    }
}

/// Whether `kind` is one of tree-sitter-rust's identifier leaf node kinds.
/// `identifier`, `field_identifier`, `type_identifier`, and
/// `shorthand_field_identifier` are all grammar aliases of the exact same
/// lexical rule (`/(r#)?[_\p{XID_Start}][_\p{XID_Continue}]*/`), so any of
/// them can carry the `r#` raw-identifier escape prefix verbatim in their
/// token text. Compound path nodes (`scoped_identifier`,
/// `scoped_type_identifier`) are deliberately excluded: callers read those by
/// walking to their constituent identifier-kind children (the `path`/`name`
/// fields), never by string-splitting the whole node text, so each segment's
/// text is normalized individually when it is itself read as one of the leaf
/// kinds above.
pub fn rust_identifier_like_node_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "field_identifier" | "type_identifier" | "shorthand_field_identifier"
    )
}

/// tree-sitter-rust raw-identifier normalization (`r#type` -> `type`), gated to
/// the identifier leaf kinds (see [`rust_identifier_like_node_kind`]).
pub const RUST_IDENTIFIER_SIGIL: IdentifierSigil = IdentifierSigil {
    is_identifier_kind: rust_identifier_like_node_kind,
    prefix: "r#",
};

/// Text of `node` verbatim from source, EXCEPT that when `node` is one of
/// tree-sitter-rust's identifier leaf kinds (see
/// [`rust_identifier_like_node_kind`]) a leading
/// `r#` raw-identifier escape is stripped so identity text (short_name,
/// fq_name) and reference/member-name text agree on the canonical spelling
/// (issue #1128). Compound nodes (whole signatures, headers, macro token
/// spans, scoped paths) are returned unmodified — those are only ever
/// normalized by first walking down to their own identifier-kind children.
pub fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_ident_text(node, source, false, &RUST_IDENTIFIER_SIGIL)
}

enum RustPrimaryFrame<'tree> {
    Enter {
        node: Node<'tree>,
        declaration_active: bool,
        native_active: bool,
    },
    Exit {
        native_exit: bool,
    },
}

/// Walk one primary Rust tree while keeping declaration and native descent
/// independent. A native unsupported subtree must not hide declarations (or a
/// future structural collector) in that same syntax. The callback receives
/// both eligibility states and returns the declaration descent decision plus
/// the native enter action. It is called for every primary tree node.
pub(crate) fn walk_rust_primary_tree<'tree, State>(
    root: Node<'tree>,
    state: &mut State,
    mut enter: impl FnMut(Node<'tree>, bool, bool, &mut State) -> (bool, TreeWalkAction),
    mut exit: impl FnMut(bool, &mut State),
) {
    let mut stack = vec![RustPrimaryFrame::Enter {
        node: root,
        declaration_active: true,
        native_active: true,
    }];
    while let Some(frame) = stack.pop() {
        match frame {
            RustPrimaryFrame::Enter {
                node,
                declaration_active,
                native_active,
            } => {
                let (declaration_descend, native_action) =
                    enter(node, declaration_active, native_active, state);
                let native_action = if native_active {
                    native_action
                } else {
                    TreeWalkAction::Skip
                };
                let native_descend = native_active
                    && matches!(
                        &native_action,
                        TreeWalkAction::Descend | TreeWalkAction::DescendWithExit
                    );
                let native_exit =
                    native_active && matches!(&native_action, TreeWalkAction::DescendWithExit);
                stack.push(RustPrimaryFrame::Exit { native_exit });
                // Keep walking even after both language-specific consumers
                // decline a node. Structural collection is grammar-blind and
                // must still see every primary node in that subtree.
                let mut cursor = node.walk();
                let mut children = node.children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children.into_iter().map(|child| RustPrimaryFrame::Enter {
                    node: child,
                    declaration_active: declaration_active && declaration_descend,
                    native_active: native_descend,
                }));
            }
            RustPrimaryFrame::Exit { native_exit } => exit(native_exit, state),
        }
    }
}

/// The largest declaration label this frontend renders.
///
/// A label is a rendering for a reader, not a second copy of the declaration's
/// value. Functions and type headers already stop at the body, but a `const`,
/// a `static`, a field, and a type alias have no body to stop at, so their
/// label was the declaration node's whole source text. Generated dictionary
/// sources declare statics whose initializer alone runs to megabytes
/// (`crate-ci/typos` ships a 12 MB `codegen.rs`), and one of those exceeded the
/// analyzer store's 8 MiB label column cap: the row failed its CHECK, the
/// file's whole parsed blob rolled back, and the recorded store error aborted
/// the entire repository audit (issue #2351).
///
/// 8 KiB is far above any label a reader can use and far below the store cap,
/// so the elision below only ever fires on a declaration that was already
/// unreadable.
const MAX_RUST_DECLARATION_LABEL_BYTES: usize = 8 * 1024;

/// `node`'s declaration text rendered as a label, eliding an oversized
/// initializer.
///
/// The elision is structural: the `value` field says exactly where the
/// declaration stops describing itself and starts spelling its value, so an
/// oversized label keeps the whole header and drops only the value. The byte
/// truncation below it is the last resort for a declaration with no `value`
/// child whose header is itself oversized.
fn rust_bounded_declaration_label(node: Node<'_>, source: &str) -> String {
    let text = rust_node_text(node, source);
    let full = text.trim().trim_end_matches(',');
    if full.len() <= MAX_RUST_DECLARATION_LABEL_BYTES {
        return full.to_string();
    }

    if let Some(value) = node.child_by_field_name("value") {
        let header_len = value.start_byte().saturating_sub(node.start_byte());
        if let Some(header) = text.get(..header_len) {
            let header = header.trim_end();
            if header.len() <= MAX_RUST_DECLARATION_LABEL_BYTES {
                return format!("{header} /* ... */;");
            }
        }
    }

    let mut end = MAX_RUST_DECLARATION_LABEL_BYTES;
    while end > 0 && !full.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} /* ... */", &full[..end])
}

/// Whether `item` carries an attached test-evidence attribute
/// (`#[test]`, `#[cfg(test)]`, `#[tokio::test]`, `#[sqlx::test]`, ...).
///
/// Tree-sitter-rust 0.24 associates outer attributes through an explicit
/// wrapper, so read only that grammar-owned group. This is the
/// per-item half of the test-region taint: combined with the taint inherited
/// from enclosing items, it decides whether a declaration lies in a test
/// region. It operates on whatever tree/source the caller passes, so it also
/// covers the region reparse of item-position macros (#1015).
fn rust_item_carries_test_attribute(item: Node<'_>, source: &str) -> bool {
    crate::syntax::outer_attributes(item).any(|attribute_item| {
        crate::test_detection::rust_attribute_is_test_evidence(attribute_item, source)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustPrimaryDeclarationMode {
    Root,
    Module,
    Class,
    Foreign,
    Impl,
    EnumVariant,
    Disabled,
}

#[derive(Clone)]
struct RustPrimaryDeclarationContext {
    mode: RustPrimaryDeclarationMode,
    parent: Option<CodeUnit>,
    package_name: String,
    impl_import_binder: usize,
    in_test_region: bool,
}

struct RustEmbeddedReplayRequest {
    parent: Option<CodeUnit>,
    package_name: String,
    in_test_region: bool,
    /// The body the invocation is written in, which decides what its items
    /// are: module items, or members of the `impl` or trait that holds it.
    scope: RustEmbeddedReplayScope,
}

#[derive(Default)]
struct RustPrimaryMacroState {
    definitions: Vec<RustRulesItemMacroDefinition>,
}

impl RustPrimaryMacroState {
    fn candidate(
        &self,
        node: Node<'_>,
        scope_start: usize,
        scope_end: usize,
        source: &str,
        declaration: SourceDeclarationId,
        exported: bool,
    ) -> Option<RustRulesItemMacroDefinition> {
        let name = rust_macro_definition_name(node, source)?;
        let (passthrough, decoration) =
            if rust_macro_definition_all_rules_replay_item_parameters(node, source) {
                (true, rust_macro_definition_decoration(node, source))
            } else {
                match rust_macro_definition_item_delegate(node, source)
                    .as_deref()
                    .and_then(|delegate| {
                        rust_latest_visible_rules_item_macro_definition(
                            &self.definitions,
                            delegate,
                            node.end_byte(),
                        )
                    })
                    .filter(|delegate| delegate.passthrough)
                {
                    Some(delegate) => (
                        true,
                        rust_macro_definition_delegate_prefix(node, source)
                            .zip(delegate.decoration.clone())
                            .map(|(prefix, inner)| RustCfgCondition::conjunction([prefix, inner])),
                    ),
                    None => (false, None),
                }
            };
        Some(RustRulesItemMacroDefinition {
            declaration,
            name: name.to_string(),
            visible_after: node.end_byte(),
            scope_start,
            scope_end,
            passthrough,
            arguments_only: rust_macro_definition_expands_to_its_arguments_only(node, source),
            decoration,
            declares_no_item: rust_macro_definition_declares_no_item(node, source),
            writes_only_impls: rust_macro_definition_writes_only_impls(node, source),
            exported,
        })
    }

    fn commit(&mut self, definition: RustRulesItemMacroDefinition) {
        if let Some(previous) = self.definitions.last() {
            assert!(
                previous.visible_after < definition.visible_after,
                "Rust primary item macro definitions are source ordered"
            );
        }
        self.definitions.push(definition);
    }

    /// Whether the latest definition of `name` visible at `invocation_start`
    /// expands to its replayed arguments and nothing else.
    fn latest_visible_expands_to_arguments_only(
        &self,
        name: &str,
        invocation_start: usize,
    ) -> bool {
        self.definitions
            .iter()
            .rfind(|definition| {
                definition.name == name && definition.visible_after <= invocation_start
            })
            .is_some_and(|definition| definition.arguments_only)
    }

    fn as_slice(&self) -> &[RustRulesItemMacroDefinition] {
        &self.definitions
    }

    fn into_definitions(self) -> Vec<RustRulesItemMacroDefinition> {
        self.definitions
    }
}

struct RustPrimaryDeclarations<'source, 'parsed, 'tree> {
    file: &'source ProjectFile,
    source: &'source str,
    parsed: &'parsed mut ParsedFile,
    root_id: usize,
    contexts: Vec<RustPrimaryDeclarationContext>,
    import_binders: Vec<ImportBinder>,
    import_projections: RustPrimaryImportProjectionCache<'source, 'tree>,
    source_imports: Vec<SourceImportFact>,
    rust_import_contexts: Vec<RustImportContextFact>,
    type_sources: RustTypeSourceCollector,
    embedded_import_ids: Vec<SourceImportId>,
    source_declaration_units: Vec<(SourceDeclarationId, CodeUnit)>,
    context_stack: Vec<usize>,
    disabled_context: usize,
}

impl<'source, 'parsed, 'tree> RustPrimaryDeclarations<'source, 'parsed, 'tree> {
    fn new(
        file: &'source ProjectFile,
        source: &'source str,
        impl_import_binder: ImportBinder,
        import_projections: RustPrimaryImportProjectionCache<'source, 'tree>,
        parsed: &'parsed mut ParsedFile,
        root: Node<'tree>,
    ) -> Self {
        let package_name = parsed.package_name.clone();
        let import_binders = vec![impl_import_binder];
        let root_context = RustPrimaryDeclarationContext {
            mode: RustPrimaryDeclarationMode::Root,
            parent: None,
            package_name,
            impl_import_binder: 0,
            in_test_region: false,
        };
        let disabled_context = RustPrimaryDeclarationContext {
            mode: RustPrimaryDeclarationMode::Disabled,
            parent: None,
            package_name: String::new(),
            impl_import_binder: 0,
            in_test_region: false,
        };
        Self {
            file,
            source,
            parsed,
            root_id: root.id(),
            contexts: vec![root_context, disabled_context],
            import_binders,
            import_projections,
            source_imports: Vec::new(),
            rust_import_contexts: Vec::new(),
            type_sources: RustTypeSourceCollector::new(),
            embedded_import_ids: Vec::new(),
            source_declaration_units: Vec::new(),
            context_stack: vec![0],
            disabled_context: 1,
        }
    }

    fn macro_definition_scope(&self, node: Node<'tree>) -> Option<(usize, usize)> {
        if node.kind() != "macro_definition" || node.is_error() || node.is_missing() {
            return None;
        }
        let parent = crate::syntax::parent_outside_attributes(node)?;
        let mut scope = parent;
        while scope.id() != self.root_id {
            let module = scope.parent()?;
            if module.kind() != "mod_item"
                || !module
                    .child_by_field_name("body")
                    .is_some_and(|body| body.id() == scope.id())
            {
                return None;
            }
            // An attributed module (`#[macro_use] mod child { .. }`) sits
            // inside the grammar's attribute wrapper, which is not a scope.
            scope = crate::syntax::parent_outside_attributes(module)?;
        }
        Some((parent.start_byte(), parent.end_byte()))
    }

    fn enter(
        &mut self,
        node: Node<'tree>,
        active: bool,
        collector: &mut PrimarySourceFactCollector<'source>,
        properties: &mut RustDeclarationPropertyCollector<'source>,
    ) -> (bool, Option<CodeUnit>, Option<RustEmbeddedReplayRequest>) {
        if !active || node.is_error() || node.is_missing() {
            self.context_stack.push(self.disabled_context);
            return (false, None, None);
        }

        let current_index = *self
            .context_stack
            .last()
            .expect("Rust declaration context has a root frame");
        let current_mode = self.contexts[current_index].mode;
        let allowed = rust_primary_declaration_kind_allowed(current_mode, node.kind());
        if !allowed && rust_primary_declaration_boundary(node.kind()) {
            self.context_stack.push(self.disabled_context);
            return (false, None, None);
        }
        if !allowed {
            self.context_stack.push(current_index);
            return (true, None, None);
        }

        let current = self.contexts[current_index].clone();
        let mut source_bridge = RustPrimaryDeclarationSourceBridge {
            collector,
            properties,
            links: &mut self.source_declaration_units,
            types: &mut self.type_sources,
        };
        let parent = current.parent.as_ref();
        let package_name = current.package_name.as_str();
        let in_test_region =
            current.in_test_region || rust_item_carries_test_attribute(node, self.source);
        let mut child_context = current.clone();
        child_context.in_test_region = in_test_region;
        let mut declaration_descend = true;
        let mut code_unit = None;

        match node.kind() {
            "struct_item" | "enum_item" | "union_item" | "trait_item" => {
                code_unit = register_rust_class_like(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    current.in_test_region,
                    self.parsed,
                    &mut source_bridge,
                );
                let Some(code_unit) = code_unit.clone() else {
                    declaration_descend = false;
                    child_context.mode = RustPrimaryDeclarationMode::Disabled;
                    self.context_stack.push(self.disabled_context);
                    return (declaration_descend, None, None);
                };
                child_context.mode = RustPrimaryDeclarationMode::Class;
                child_context.parent = Some(code_unit);
            }
            "mod_item" => {
                code_unit = register_rust_module(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    current.in_test_region,
                    self.parsed,
                    &mut source_bridge,
                );
                let Some(code_unit) = code_unit.clone() else {
                    declaration_descend = false;
                    child_context.mode = RustPrimaryDeclarationMode::Disabled;
                    self.context_stack.push(self.disabled_context);
                    return (declaration_descend, None, None);
                };
                child_context.mode = RustPrimaryDeclarationMode::Module;
                child_context.parent = Some(code_unit);
                child_context.impl_import_binder = self.import_binders.len();
                let import_projections = &mut self.import_projections;
                self.import_binders
                    .push(rust_direct_impl_import_binder(node, import_projections));
            }
            "function_item"
                if current.mode == RustPrimaryDeclarationMode::Root
                    || current.mode == RustPrimaryDeclarationMode::Module
                    || current.mode == RustPrimaryDeclarationMode::Class
                    || current.mode == RustPrimaryDeclarationMode::Impl =>
            {
                code_unit = visit_rust_function(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    current.in_test_region,
                    self.parsed,
                    &mut source_bridge,
                );
                declaration_descend = false;
                child_context.mode = RustPrimaryDeclarationMode::Disabled;
            }
            "function_signature_item"
                if current.mode == RustPrimaryDeclarationMode::Class
                    || current.mode == RustPrimaryDeclarationMode::Foreign =>
            {
                code_unit = visit_rust_function(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    current.in_test_region,
                    self.parsed,
                    &mut source_bridge,
                );
                declaration_descend = false;
                child_context.mode = RustPrimaryDeclarationMode::Disabled;
            }
            "foreign_mod_item" => {
                if node.child_by_field_name("body").is_none() {
                    declaration_descend = false;
                    child_context.mode = RustPrimaryDeclarationMode::Disabled;
                } else {
                    child_context.mode = RustPrimaryDeclarationMode::Foreign;
                    child_context.parent = current.parent.clone();
                }
            }
            "field_declaration" | "enum_variant" | "const_item" | "static_item" => {
                code_unit = register_rust_field(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    current.in_test_region,
                    self.parsed,
                    &mut source_bridge,
                );
                declaration_descend = node.kind() == "enum_variant" && code_unit.is_some();
                child_context.mode = if declaration_descend {
                    RustPrimaryDeclarationMode::EnumVariant
                } else {
                    RustPrimaryDeclarationMode::Disabled
                };
                if let Some(code_unit) = code_unit.clone()
                    && declaration_descend
                {
                    child_context.parent = Some(code_unit);
                }
            }
            "macro_definition" => {
                code_unit = visit_rust_macro(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    current.in_test_region,
                    self.parsed,
                    &mut source_bridge,
                );
                declaration_descend = false;
                child_context.mode = RustPrimaryDeclarationMode::Disabled;
            }
            "macro_invocation" => {
                declaration_descend = false;
                child_context.mode = RustPrimaryDeclarationMode::Disabled;
            }
            "type_item" | "associated_type"
                if current.mode == RustPrimaryDeclarationMode::Root
                    || current.mode == RustPrimaryDeclarationMode::Module
                    || current.mode == RustPrimaryDeclarationMode::Class
                    || current.mode == RustPrimaryDeclarationMode::Impl =>
            {
                code_unit = visit_rust_alias(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    current.in_test_region,
                    self.parsed,
                    &mut source_bridge,
                );
                declaration_descend = false;
                child_context.mode = RustPrimaryDeclarationMode::Disabled;
            }
            "impl_item" => {
                if let Some(trait_node) = node.child_by_field_name("trait") {
                    source_bridge.record_type(trait_node, self.source);
                }
                let owner = node.child_by_field_name("type").and_then(|type_node| {
                    let target = source_bridge.record_type(type_node, self.source);
                    rust_impl_owner(
                        self.file,
                        target,
                        parent,
                        package_name,
                        &self.import_binders[current.impl_import_binder],
                        self.parsed,
                    )
                });
                if let (Some(owner), Some(_body)) = (owner, node.child_by_field_name("body")) {
                    child_context.mode = RustPrimaryDeclarationMode::Impl;
                    child_context.parent = Some(owner.clone());
                    child_context.package_name = owner.package_name().to_string();
                    child_context.in_test_region = current.in_test_region
                        || rust_item_carries_test_attribute(node, self.source);
                } else {
                    declaration_descend = false;
                    child_context.mode = RustPrimaryDeclarationMode::Disabled;
                }
            }
            _ => {}
        }

        if declaration_descend {
            self.contexts.push(child_context);
            self.context_stack.push(self.contexts.len() - 1);
        } else {
            self.context_stack.push(self.disabled_context);
        }
        let replay_request =
            (node.kind() == "macro_invocation").then(|| RustEmbeddedReplayRequest {
                parent: parent.cloned(),
                package_name: package_name.to_string(),
                in_test_region: current.in_test_region,
                scope: match current.mode {
                    RustPrimaryDeclarationMode::Impl => RustEmbeddedReplayScope::Impl,
                    RustPrimaryDeclarationMode::Class => RustEmbeddedReplayScope::Class,
                    RustPrimaryDeclarationMode::Root | RustPrimaryDeclarationMode::Module => {
                        RustEmbeddedReplayScope::Root
                    }
                    mode => unreachable!(
                        "an item macro is admitted only in a module, impl or trait body: {mode:?}"
                    ),
                },
            });
        (declaration_descend, code_unit, replay_request)
    }

    fn exit(&mut self) {
        assert!(
            self.context_stack.pop().is_some(),
            "Rust declaration context exit has a frame"
        );
    }
}

fn rust_primary_declaration_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "struct_item"
            | "enum_item"
            | "union_item"
            | "trait_item"
            | "mod_item"
            | "function_item"
            | "function_signature_item"
            | "foreign_mod_item"
            | "field_declaration"
            | "enum_variant"
            | "const_item"
            | "static_item"
            | "macro_definition"
            | "macro_invocation"
            | "type_item"
            | "associated_type"
            | "impl_item"
    )
}

fn rust_primary_declaration_kind_allowed(mode: RustPrimaryDeclarationMode, kind: &str) -> bool {
    match mode {
        RustPrimaryDeclarationMode::Root | RustPrimaryDeclarationMode::Module => {
            matches!(
                kind,
                "struct_item"
                    | "enum_item"
                    | "union_item"
                    | "trait_item"
                    | "mod_item"
                    | "function_item"
                    | "foreign_mod_item"
                    | "const_item"
                    | "static_item"
                    | "macro_definition"
                    | "macro_invocation"
                    | "type_item"
                    | "impl_item"
            )
        }
        RustPrimaryDeclarationMode::Class => matches!(
            kind,
            "field_declaration"
                | "enum_variant"
                | "const_item"
                | "function_item"
                | "function_signature_item"
                | "associated_type"
                | "type_item"
                | "macro_invocation"
        ),
        RustPrimaryDeclarationMode::Foreign => {
            matches!(kind, "function_signature_item" | "static_item")
        }
        RustPrimaryDeclarationMode::Impl => {
            matches!(
                kind,
                "function_item" | "const_item" | "type_item" | "macro_invocation"
            )
        }
        RustPrimaryDeclarationMode::EnumVariant => kind == "field_declaration",
        RustPrimaryDeclarationMode::Disabled => false,
    }
}

struct RustPrimaryParseState<'source, 'parsed, 'tree> {
    declarations: RustPrimaryDeclarations<'source, 'parsed, 'tree>,
    native: crate::resolution::RustResolutionBuilder<'source>,
    usage: crate::facts::RustUsageFactCollector<'source>,
    module_sources: crate::facts::RustModuleSourceCollector<'source>,
    item_sources: RustItemSourceCollector,
    primary_macros: RustPrimaryMacroState,
    native_enabled: bool,
    claimed_units: HashSet<CodeUnit>,
    structural: StructuralFactCollector<'source, 'tree>,
    structural_parents: Vec<Option<u32>>,
    structural_kinds: &'source CompiledKinds,
    call_site_context: &'source CallSiteContext,
}

impl<'source, 'parsed, 'tree> RustPrimaryParseState<'source, 'parsed, 'tree> {
    #[expect(
        clippy::too_many_arguments,
        reason = "the parse state is initialized from the coordinated parser products"
    )]
    fn new(
        file: &'source ProjectFile,
        source: &'source str,
        impl_import_binder: ImportBinder,
        import_projections: RustPrimaryImportProjectionCache<'source, 'tree>,
        parsed: &'parsed mut ParsedFile,
        root: Node<'tree>,
        structural_kinds: &'source CompiledKinds,
        call_site_context: &'source CallSiteContext,
    ) -> Self {
        let mut native = crate::resolution::RustResolutionBuilder::new(root, source);
        let root_occurrence = native.source_collector_mut().intern_node(root);
        let native_enabled = true;
        let mut module_sources =
            crate::facts::RustModuleSourceCollector::new(source, root_occurrence);
        module_sources.record_inner_attributes(root);
        Self {
            declarations: RustPrimaryDeclarations::new(
                file,
                source,
                impl_import_binder,
                import_projections,
                parsed,
                root,
            ),
            native,
            usage: crate::facts::RustUsageFactCollector::new(root, source),
            module_sources,
            item_sources: RustItemSourceCollector::new(),
            primary_macros: RustPrimaryMacroState::default(),
            native_enabled,
            claimed_units: HashSet::default(),
            structural: StructuralFactCollector::new(
                &crate::structural::RUST_STRUCTURAL_SPEC,
                source,
                call_site_context,
                brokk_bifrost_core::analyzer::tree_walk::ParentIndex::new(root),
                usize::MAX,
                None,
            ),
            structural_parents: vec![None],
            structural_kinds,
            call_site_context,
        }
    }

    fn enter(
        &mut self,
        node: Node<'tree>,
        declaration_active: bool,
        native_active: bool,
    ) -> (bool, TreeWalkAction) {
        let (collector, properties) = self.native.source_collectors_mut();
        let source_macro_position = self.item_sources.enter(
            node,
            self.declarations.source,
            &mut RustPrimaryItemSourceSink {
                collector,
                properties,
            },
            &mut self.declarations.type_sources,
        );
        collect_rust_type_identifier(
            node,
            self.declarations.source,
            &mut self.declarations.parsed.type_identifiers,
        );
        let spec = &crate::structural::RUST_STRUCTURAL_SPEC;
        let enclosing = *self
            .structural_parents
            .last()
            .expect("primary structural traversal has a root frame");
        let mut structural_parent = enclosing;
        if node.is_named()
            && let Some(kind) = self.structural_kinds.kind_of(&node)
            && spec.should_extract(node, kind)
        {
            let kind = spec.refine_kind(
                node,
                kind,
                enclosing.map(|id| self.structural.normalized_kind(id)),
                self.declarations.source,
                self.call_site_context,
            );
            let id = self
                .structural
                .enter(node, kind, enclosing, self.native.source_collector_mut())
                .expect(
                    "complete Rust preparation has no structural admission limit or cancellation",
                );
            let mut sink = self
                .structural
                .role_sink(self.native.source_collector_mut());
            spec.extract(node, kind, &mut sink);
            self.structural.accept_roles(id, sink.into_parts()).expect(
                "complete Rust preparation has no structural admission limit or cancellation",
            );
            structural_parent = Some(id);
        }
        self.structural_parents.push(structural_parent);
        let route_macro_needed = self.usage.primary_macro_route_needed(node);
        if node.kind() == "macro_invocation" {
            self.module_sources
                .ensure_primary_invocation(node, self.native.source_collector_mut());
        }
        let (declaration_descend, code_unit, replay_request) = {
            let (source_collector, declaration_properties) = self.native.source_collectors_mut();
            self.declarations.enter(
                node,
                declaration_active,
                source_collector,
                declaration_properties,
            )
        };
        let source_macro_needed =
            source_macro_position == Some(RustItemMacroSourcePosition::DirectItem);
        let mut replay_graph =
            if replay_request.is_some() || route_macro_needed || source_macro_needed {
                let invocation = self.native.source_collector_mut().intern_node(node);
                match build_rust_embedded_replay_graph(node, self.declarations.source) {
                    Ok(Some(mut graph)) => {
                        let (collector, properties) = self.native.source_collectors_mut();
                        collect_rust_embedded_item_sources(
                            invocation,
                            &mut graph,
                            self.declarations.source,
                            collector,
                            properties,
                            &mut self.module_sources,
                            &mut self.item_sources,
                            &mut self.declarations.type_sources,
                            &mut self.declarations.source_imports,
                        );
                        Some(graph)
                    }
                    Ok(None) => {
                        self.item_sources.record_macro(invocation, Ok(None));
                        None
                    }
                    Err(error) => {
                        self.item_sources.record_macro(invocation, Err(error));
                        None
                    }
                }
            } else {
                None
            };
        // The classifier's answer, read and not re-decided, and then the
        // stricter question this lowering has to ask on top of it. Passthrough
        // proves each item argument is replayed; it deliberately admits a rule
        // that decorates the replay, so it is enough to decide a module route
        // and not enough to declare the items with the activation their
        // argument tokens carry. `expands_to_arguments_only` is the difference.
        let declares_its_items =
            rust_unqualified_macro_invocation_name(node, self.declarations.source).is_some_and(
                |name| {
                    rust_latest_visible_rules_item_macro(
                        self.primary_macros.as_slice(),
                        name,
                        node.start_byte(),
                    ) == Some(true)
                        && self
                            .primary_macros
                            .latest_visible_expands_to_arguments_only(name, node.start_byte())
                },
            );
        if let Some(request) = replay_request
            && let Some(graph) = replay_graph.as_mut()
        {
            let (source_collector, declaration_properties) = self.native.source_collectors_mut();
            let root_tree_id = graph.root_id();
            let (trees, source_maps) = graph.split_mut();
            let mut embedded_source_bridge = RustEmbeddedDeclarationSourceBridge {
                collector: source_collector,
                properties: declaration_properties,
                module_sources: &mut self.module_sources,
                links: &mut self.declarations.source_declaration_units,
                source_maps,
                types: &mut self.declarations.type_sources,
                tree_id: root_tree_id,
            };
            visit_rust_macro_invocation_definitions(
                self.declarations.file,
                self.declarations.source,
                node,
                request.parent.as_ref(),
                &request.package_name,
                self.primary_macros.as_slice(),
                request.in_test_region,
                request.scope,
                self.declarations.parsed,
                &mut embedded_source_bridge,
                self.declarations.source_imports.as_slice(),
                &mut self.declarations.embedded_import_ids,
                trees,
                root_tree_id,
            );
        }
        // Replay has now declared this invocation's items, so the native
        // lowering can publish their sites against the identity replay gave
        // them. It walks replay's tree with replay's occurrence map, which is
        // why this runs here, while the graph is held, rather than through the
        // pending-fragment queue: a queued fragment owns its tree and replay's
        // trees are owned by the graph. Item capture declared the items when it
        // built the graph, so this does not depend on the CodeUnit replay above,
        // which an invocation in an `impl` or trait body does not request.
        if declares_its_items && let Some(graph) = replay_graph.as_mut() {
            let root_tree_id = graph.root_id();
            let map = std::mem::take(&mut graph.source_maps[root_tree_id]);
            let tree = graph.trees[root_tree_id].tree.clone();
            let returned = self.native.lower_passthrough_item_macro(node, tree, map);
            graph.source_maps[root_tree_id] = returned;
        }
        let macro_candidate =
            self.declarations
                .macro_definition_scope(node)
                .and_then(|(scope_start, scope_end)| {
                    rust_macro_definition_name(node, self.declarations.source)?;
                    let property = self
                        .native
                        .declaration_property_for_node(node)
                        .expect("eligible named macro has a canonical source property");
                    self.primary_macros.candidate(
                        node,
                        scope_start,
                        scope_end,
                        self.declarations.source,
                        property.declaration,
                        property.macro_exported,
                    )
                });
        let projected_imports =
            self.declarations
                .import_projections
                .take(node)
                .map(|(mut imports, source_nodes)| {
                    attach_import_source_occurrences(
                        &mut imports,
                        &source_nodes,
                        self.native.source_collector_mut(),
                        &mut self.declarations.source_imports,
                        &mut self.declarations.rust_import_contexts,
                    );
                    imports
                });
        let native_action = if self.native_enabled && native_active {
            if node.is_named() {
                self.native.enter(
                    node,
                    projected_imports.as_deref(),
                    macro_candidate.as_ref(),
                    source_macro_position,
                )
            } else {
                // Native lowering historically visited named children only;
                // preserve that behavior while allowing the shared driver to
                // expose anonymous tokens to structural collection.
                TreeWalkAction::Descend
            }
        } else {
            TreeWalkAction::Skip
        };
        let module_scope = (node.kind() == "mod_item")
            .then(|| self.native.module_body_scope(node))
            .flatten();
        let primary_module_declaration = if node.kind() == "mod_item" {
            let declaration = {
                let (source_collector, declaration_properties) =
                    self.native.source_collectors_mut();
                declaration_properties.ensure_primary(node, source_collector)
            };
            if let Some(declaration) = declaration {
                self.module_sources.record_primary_declaration(
                    declaration,
                    node,
                    self.native.source_collector_mut(),
                );
            }
            declaration
        } else {
            None
        };
        let primary_module_property = primary_module_declaration.map(|_| {
            self.native
                .declaration_property_for_node(node)
                .expect("ensured primary module owns a source property")
        });
        self.usage.enter(
            node,
            module_scope,
            projected_imports,
            primary_module_property,
            primary_module_declaration,
            &mut self.module_sources,
        );
        if route_macro_needed && let Some(graph) = replay_graph.as_mut() {
            let (source_collector, declaration_properties) = self.native.source_collectors_mut();
            self.usage.collect_primary_macro_route(
                node,
                graph,
                source_collector,
                declaration_properties,
                &mut self.module_sources,
            );
        }
        if let Some(declaration) = self.native.declaration_site_for_node(node.id()) {
            if let Some(unit) = code_unit {
                if self.claimed_units.insert(unit.clone()) {
                    self.native
                        .add_definition_unit(ResolutionDefinitionUnitFact { declaration, unit });
                }
            } else if node.kind() == "field_declaration" {
                // Fields of block-local types retain native member and type
                // facts, but their owner has no parser CodeUnit. Publish the
                // existing source declaration's lexical interpretation so a
                // resolved member never becomes an unprojectable definition.
                let source_declaration = self
                    .native
                    .declaration_property_for_node(node)
                    .expect("a native field owns its source declaration")
                    .declaration;
                self.native
                    .source_collector_mut()
                    .mark_lexical(source_declaration, DeclarationKind::Field);
            }
        }
        if let Some(definition) = macro_candidate {
            self.primary_macros.commit(definition);
        }
        (declaration_descend, native_action)
    }

    fn exit(&mut self, native_exit: bool) {
        self.item_sources.exit();
        self.structural_parents
            .pop()
            .expect("primary structural node has an exit");
        self.declarations.exit();
        self.usage.exit();
        if native_exit {
            self.native.exit();
        }
    }

    fn finish(mut self) {
        assert_eq!(self.structural_parents, [None]);
        assert!(self.declarations.parsed.source_declaration_units.is_empty());
        self.declarations.parsed.source_declaration_units =
            std::mem::take(&mut self.declarations.source_declaration_units);
        let structural = self
            .structural
            .finish()
            .expect("complete Rust preparation has no structural admission limit or cancellation");
        let mut native = self.native.finish();
        // Native lowering already records inherited access (trait members,
        // enum variants, exported macros and lexical aliases). Preserve those
        // structured decisions when publishing the canonical source family.
        let native_visibilities = native
            .facts
            .declaration_visibilities
            .iter()
            .map(|fact| (fact.declaration, fact.visibility))
            .collect::<HashMap<_, _>>();
        let mut inherited_visibilities = HashMap::default();
        for &(site, declaration) in &native.declaration_sources {
            if let Some(&visibility) = native_visibilities.get(&site)
                && let Some(previous) = inherited_visibilities.insert(declaration, visibility)
            {
                assert_eq!(
                    previous, visibility,
                    "native projections agree on source access"
                );
            }
        }
        let declaration_visibilities = native
            .declaration_properties
            .iter()
            .map(|property| {
                brokk_bifrost_core::analyzer::source_facts::SourceDeclarationVisibilityFact {
                    declaration: property.declaration,
                    visibility: inherited_visibilities
                        .get(&property.declaration)
                        .copied()
                        .unwrap_or_else(|| {
                            // A lexical macro's binder already supplies its
                            // complete scope and textual activation boundary.
                            // Module export access remains in Rust properties.
                            if property.kind == brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind::Macro {
                                DeclaredVisibility::Public
                            } else {
                                crate::declaration_properties::declared_visibility(&property.visibility)
                            }
                        }),
                }
            })
            .collect::<Vec<_>>();
        let source_visibilities = declaration_visibilities
            .iter()
            .map(|fact| (fact.declaration, fact.visibility))
            .collect::<HashMap<_, _>>();
        let mut visibility_gaps = native.facts.gaps.iter()
            .filter(|gap| gap.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedVisibility)
            .map(|gap| gap.site).collect::<HashSet<_>>();
        let mut visibility_eligible = native
            .facts
            .visibility_eligibilities
            .iter()
            .map(|fact| fact.declaration)
            .collect::<HashSet<_>>();
        for &(site, declaration) in &native.declaration_sources {
            if let Some(&visibility) = source_visibilities.get(&declaration) {
                if !native_visibilities.contains_key(&site) {
                    native.facts.declaration_visibilities.push(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionDeclarationVisibilityFact {
                            declaration: site, visibility,
                        });
                }
                if visibility_eligible.insert(site) {
                    native.facts.visibility_eligibilities.push(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionVisibilityEligibilityFact {
                            declaration: site,
                        });
                }
            }
            if source_visibilities
                .get(&declaration)
                .is_some_and(|visibility| *visibility != DeclaredVisibility::Public)
                && visibility_gaps.insert(site)
            {
                native.facts.gaps.push(brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact {
                    site,
                    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedVisibility,
                });
            }
        }
        // Macro item reparses append their imports while the primary tree is
        // live. Keep those after the primary event stream, matching the old
        // root projection's ordering without walking the primary tree again.
        let source_imports = std::mem::take(&mut self.declarations.source_imports);
        let mut rust_import_contexts = std::mem::take(&mut self.declarations.rust_import_contexts);
        let mut native_import_scopes = HashMap::default();
        for site in &native.facts.sites {
            if site.kind != brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ImportDeclaration {
                continue;
            }
            let occurrence = native.site_occurrences[site.id.index()];
            if let Some(previous) = native_import_scopes.insert(occurrence, site.scope) {
                assert_eq!(
                    previous, site.scope,
                    "grouped imports share one lexical scope"
                );
            }
        }
        for context in &mut rust_import_contexts {
            context.native_scope = native_import_scopes.get(&context.declaration).copied();
        }
        let embedded_import_ids = std::mem::take(&mut self.declarations.embedded_import_ids);
        let (mut usage, module_import_ids, rust_modules) = self.usage.finish(
            self.primary_macros.into_definitions(),
            self.module_sources,
            &native.source_facts,
            &native.declaration_properties,
        );
        // A visible user macro named include has a normal Macro reference.
        // Only the builtin (which the native producer marks as a splice
        // frontier) may interpret its literal argument as a file route.
        let declared_macro_heads = native
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.namespace
                    == brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Macro
            })
            .map(|identifier| native.facts.sites[identifier.site.index()].start_byte)
            .collect::<HashSet<_>>();
        usage
            .include_edges
            .retain(|edge| !declared_macro_heads.contains(&edge.include_start));
        for import in &mut usage.import_targets {
            import.native_scope = import.source_occurrences.and_then(|occurrences| {
                native_import_scopes.get(&occurrences.declaration).copied()
            });
        }
        let generic_imports = module_import_ids
            .into_iter()
            .chain(embedded_import_ids)
            .collect::<Vec<_>>();
        self.declarations.parsed.imports = generic_imports
            .iter()
            .map(|source_import_id| {
                source_imports
                    .get(source_import_id.index())
                    .expect("generic import projection references a source import")
                    .import_info(&native.source_facts)
            })
            .collect();
        let mut rust_items = self.item_sources.into_facts();
        let native_frontiers = native.facts.gaps.iter().filter(|gap| {
            matches!(gap.kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder
                | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedExpression
                | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedItemMacro
                | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro
            )
        }).map(|gap| {
            let site = native.facts.sites[gap.site.index()];
            (native.site_occurrences[gap.site.index()], (gap.site, site.scope))
        }).collect::<HashMap<_, _>>();
        for input in &mut rust_items.macro_inputs {
            input.native_frontier = native_frontiers.get(&input.invocation).copied();
        }
        self.declarations.parsed.rust_usage_facts = usage;
        self.declarations.parsed.resolution_facts = native.facts;
        self.declarations.parsed.source_facts = Some(ParsedSourceFacts {
            js_ts: None,
            scala: None,
            php: None,
            cpp: None,
            go: None,
            java: None,
            ruby: None,
            python: None,
            declaration_visibilities: Some(declaration_visibilities),
            source_bytes: self.declarations.source.len(),
            occurrences: native.source_facts,
            structural,
            native_site_occurrences: native.site_occurrences,
            native_declaration_sources: native.declaration_sources,
            rust_declaration_properties: native.declaration_properties,
            rust_modules: Some(rust_modules),
            rust_types: std::mem::take(&mut self.declarations.type_sources).into_facts(),
            rust_items,
            imports: source_imports,
            generic_imports,
            rust_import_contexts,
        });
        assert_eq!(
            self.declarations.parsed.imports.len(),
            self.declarations
                .parsed
                .source_facts
                .as_ref()
                .expect("Rust source facts were just published")
                .generic_imports
                .len(),
            "generic imports and canonical import occurrences share one order"
        );
    }
}

pub fn parse_rust_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let mut parsed = ParsedFile::new(rust_package_name(file));
    let root = tree.root_node();

    // This binder stays top-level-only for its own reason: it resolves the
    // owners of top-level `impl` blocks, and a name bound inside a nested
    // module is not in scope for them. ParsedFile.imports itself is populated
    // from the coordinated usage events in RustPrimaryParseState::finish.
    let mut import_projections = RustPrimaryImportProjectionCache::new(source);
    let mut impl_import_binder = ImportBinder::empty();
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        let child = unwrap_attributes(child);
        if child.kind() == "use_declaration" {
            for projected in import_projections
                .ensure(child)
                .expect("use declarations have a primary import projection")
            {
                assert!(!projected.import.is_extern_crate());
                crate::lexical_scope::insert_rust_import_binding(
                    &mut impl_import_binder,
                    &projected.import.info,
                );
            }
        }
    }

    let spec = &crate::structural::RUST_STRUCTURAL_SPEC;
    let grammar = tree_sitter_rust::LANGUAGE.into();
    let structural_kinds = CompiledKinds::compile(&grammar, spec.kind_table());
    let call_site_context = spec.call_site_context(root, source);
    let mut traversal = RustPrimaryParseState::new(
        file,
        source,
        impl_import_binder,
        import_projections,
        &mut parsed,
        root,
        &structural_kinds,
        &call_site_context,
    );
    walk_rust_primary_tree(
        root,
        &mut traversal,
        |node, declaration_active, native_active, state| {
            state.enter(node, declaration_active, native_active)
        },
        |native_exit, state| state.exit(native_exit),
    );
    traversal.finish();

    parsed
}

pub fn rust_package_name(file: &ProjectFile) -> String {
    with_rust_package_components(file, |components| components.join("."))
}

/// Hands `read` the crate-anchored package components when a `Cargo.toml`
/// governs `file`, otherwise the legacy path-derived scheme.
///
/// Borrowed rather than returned: the crate-anchored components are memoized
/// behind an `Arc` (see `crate_naming`), and this is one of the hottest
/// questions a scan asks, so handing out an owned `Vec` would reinstate the
/// per-call allocation the memo removes.
fn with_rust_package_components<T>(file: &ProjectFile, read: impl FnOnce(&[String]) -> T) -> T {
    match crate::crate_naming::rust_crate_paths(file) {
        Some(paths) => read(&paths.package),
        None => read(&crate::crate_naming::path_derived_package_components(
            file.rel_path(),
        )),
    }
}

fn add_rust_signature_metadata(
    parsed: &mut ParsedFile,
    declaration: SourceDeclarationId,
    unit: CodeUnit,
    metadata: SignatureMetadata,
) {
    let metadata_ordinal = parsed.add_signature_with_metadata(unit.clone(), metadata);
    parsed.source_declaration_metadata.push(
        brokk_bifrost_core::analyzer::parsed_file::SourceDeclarationMetadataLink {
            declaration,
            unit,
            metadata_ordinal,
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn register_rust_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parent_in_test_region: bool,
    parsed: &mut ParsedFile,
    source_bridge: &mut dyn RustDeclarationSourceBridge,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let in_test_region = parent_in_test_region || rust_item_carries_test_attribute(node, source);
    let (short_name, fq) = rust_type_declaration_identity(file, parent, name);
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Class,
        package_name.to_string(),
        short_name,
        fq,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    let declaration = source_bridge.record(node, &code_unit);
    if in_test_region {
        parsed.mark_test_region(&code_unit);
    }
    add_rust_signature_metadata(
        parsed,
        declaration,
        code_unit.clone(),
        SignatureMetadata::new(rust_type_signature(node, source), Vec::new())
            .with_recorded_type_parameters(rust_declared_type_parameters(node, source)),
    );

    Some(code_unit)
}

#[allow(clippy::too_many_arguments)]
fn register_rust_module(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parent_in_test_region: bool,
    parsed: &mut ParsedFile,
    source_bridge: &mut dyn RustDeclarationSourceBridge,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let in_test_region = parent_in_test_region || rust_item_carries_test_attribute(node, source);
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let fq = rust_child_fq_base(parent, file).with_pushed(rust_segment(name, SegmentKind::Package));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Module,
        package_name.to_string(),
        short_name,
        fq,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    source_bridge.record(node, &code_unit);
    if in_test_region {
        parsed.mark_test_region(&code_unit);
    }
    let signature = if node.child_by_field_name("body").is_some() {
        format!("mod {name} {{")
    } else {
        rust_bounded_declaration_label(node, source)
    };
    parsed.add_signature(code_unit.clone(), signature);

    Some(code_unit)
}

fn rust_direct_impl_import_binder<'tree>(
    node: Node<'tree>,
    import_projections: &mut RustPrimaryImportProjectionCache<'_, 'tree>,
) -> ImportBinder {
    let mut binder = ImportBinder::empty();
    let Some(body) = node.child_by_field_name("body") else {
        return binder;
    };
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if child.kind() == "use_declaration" {
            for projected in import_projections
                .ensure(child)
                .expect("use declarations have a primary import projection")
            {
                assert!(!projected.import.is_extern_crate());
                crate::lexical_scope::insert_rust_import_binding(
                    &mut binder,
                    &projected.import.info,
                );
            }
        }
    }
    binder
}

#[allow(clippy::too_many_arguments)]
fn visit_rust_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parent_in_test_region: bool,
    parsed: &mut ParsedFile,
    source_bridge: &mut dyn RustDeclarationSourceBridge,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let in_test_region = parent_in_test_region || rust_item_carries_test_attribute(node, source);
    // `proc_macro_derive(Name)` exports its argument, not the function's name.
    // Keep it a function: declaration-node lookup requires the exported name
    // and the declaration identifier to agree.
    if item_has_path_attribute(node, source, "proc_macro")
        || item_has_path_attribute(node, source, "proc_macro_attribute")
    {
        return register_rust_macro(
            file,
            name,
            package_name,
            parent,
            node,
            rust_function_signature(node, source),
            in_test_region,
            parsed,
            source_bridge,
        );
    }
    let signature = rust_impl_member_identity_signature(node, source).or_else(|| {
        node.child_by_field_name("parameters")
            .map(|parameters| rust_node_text(parameters, source).trim().to_string())
    });
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let fq = rust_child_fq_base(parent, file).with_pushed(rust_segment(name, SegmentKind::Member));
    let code_unit = rust_inherit_package_anchor(
        CodeUnit::with_signature_and_fq(
            file.clone(),
            CodeUnitType::Function,
            package_name.to_string(),
            short_name,
            signature,
            false,
            fq,
        ),
        parent,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    let declaration = source_bridge.record(node, &code_unit);
    if in_test_region {
        parsed.mark_test_region(&code_unit);
    }
    let signature = rust_function_signature(node, source);
    add_rust_signature_metadata(
        parsed,
        declaration,
        code_unit.clone(),
        rust_signature_metadata(signature, node, source),
    );
    Some(code_unit)
}

#[allow(clippy::too_many_arguments)]
fn visit_rust_macro(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parent_in_test_region: bool,
    parsed: &mut ParsedFile,
    source_bridge: &mut dyn RustDeclarationSourceBridge,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let in_test_region = parent_in_test_region || rust_item_carries_test_attribute(node, source);
    register_rust_macro(
        file,
        name,
        package_name,
        parent,
        node,
        rust_macro_signature(node, source),
        in_test_region,
        parsed,
        source_bridge,
    )
}

#[allow(clippy::too_many_arguments)]
fn register_rust_macro(
    file: &ProjectFile,
    name: &str,
    package_name: &str,
    parent: Option<&CodeUnit>,
    node: Node<'_>,
    signature: String,
    in_test_region: bool,
    parsed: &mut ParsedFile,
    source_bridge: &mut dyn RustDeclarationSourceBridge,
) -> Option<CodeUnit> {
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let fq = rust_child_fq_base(parent, file).with_pushed(rust_segment(name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Macro,
        package_name.to_string(),
        short_name,
        fq,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    let range = rust_range_from_node(node);
    parsed.add_code_unit_with_range(code_unit.clone(), range, parent.cloned(), Some(top_level));
    source_bridge.record(node, &code_unit);
    if in_test_region {
        parsed.mark_test_region(&code_unit);
    }
    parsed.add_signature(code_unit.clone(), signature);
    Some(code_unit)
}

/// Index the items written inside an item-position macro invocation
/// (`cfg_rt! { pub mod coop; }`, `cfg_coop! { pub struct RestoreOnPending(...); ... }`)
/// exactly as if the macro braces were absent.
///
/// tokio and similar crates wrap whole modules and free items in
/// conditional-compilation macros defined in *another* file, so the invoked
/// macro's `macro_rules!` definition is not visible here. Rather than relying
/// on a name allowlist, we reparse the token-tree interior as Rust items and,
/// when it genuinely parses as well-formed items (the robustness gate in
/// `rust_reparsed_items_are_indexable`), run the ordinary declaration
/// visitation over the result. Expression-position macros (`println!(...)`,
/// `matches!(...)`) never reach here because they live inside function bodies,
/// not at item position, and their token soup fails the parse gate anyway.
///
/// Range fidelity: the interior is reparsed in place, confined to its region via
/// tree-sitter included ranges, so every node's byte offset and line number
/// matches the original file exactly. This lets the existing visitors (which
/// derive ranges from node positions via `node_range`) run unchanged and still
/// slice the correct source text.
#[allow(clippy::too_many_arguments)]
fn visit_rust_macro_invocation_definitions<'source>(
    file: &ProjectFile,
    source: &'source str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    item_macro_definitions: &[RustRulesItemMacroDefinition],
    parent_in_test_region: bool,
    scope: RustEmbeddedReplayScope,
    parsed: &mut ParsedFile,
    source_bridge: &mut RustEmbeddedDeclarationSourceBridge<'_, 'source>,
    source_imports: &[SourceImportFact],
    embedded_import_ids: &mut Vec<SourceImportId>,
    trees: &[RustEmbeddedReplayTree],
    root_tree_id: usize,
) {
    let Some(admission) = rust_embedded_macro_invocation_admission(
        node,
        source,
        item_macro_definitions,
        parent_in_test_region,
        trees,
        root_tree_id,
    ) else {
        return;
    };
    let mut replay = RustEmbeddedReplayDriver::new(
        trees,
        file,
        source,
        item_macro_definitions,
        parsed,
        source_bridge,
        source_imports,
        embedded_import_ids,
    );
    replay.push_macro_invocation(parent.cloned(), package_name.to_string(), admission, scope);
    replay.run();
}

fn rust_embedded_macro_invocation_admission(
    node: Node<'_>,
    source: &str,
    item_macro_definitions: &[RustRulesItemMacroDefinition],
    parent_in_test_region: bool,
    trees: &[RustEmbeddedReplayTree],
    tree_id: usize,
) -> Option<RustEmbeddedAdmittedMacro> {
    let invoked_macro = rust_unqualified_macro_invocation_name(node, source)?;
    if rust_builtin_macro_does_not_replay_item_arguments(invoked_macro) {
        return None;
    }
    // Unknown external macros may replay ordinary items. Replaying a macro
    // definition itself requires positive local passthrough evidence.
    let locally_proven_passthrough = match rust_latest_visible_rules_item_macro(
        item_macro_definitions,
        invoked_macro,
        node.start_byte(),
    ) {
        Some(false) => return None,
        Some(true) => true,
        None => false,
    };
    let invocation_in_test_region =
        parent_in_test_region || rust_item_carries_test_attribute(node, source);
    if !rust_reparsed_items_are_indexable(trees[tree_id].tree.root_node()) {
        return None;
    }
    Some(RustEmbeddedAdmittedMacro {
        tree_id,
        replay_macro_definitions: locally_proven_passthrough,
        in_test_region: invocation_in_test_region,
    })
}

struct RustEmbeddedAdmittedMacro {
    tree_id: usize,
    replay_macro_definitions: bool,
    in_test_region: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RustEmbeddedReplayScope {
    Root,
    Module,
    Class,
    Foreign,
    Impl,
    EnumVariant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RustEmbeddedReplayPhase {
    BindModule,
    Visit,
}

struct RustEmbeddedReplayContext {
    parent: Option<CodeUnit>,
    package_name: String,
    import_binder: ImportBinder,
    in_test_region: bool,
    replay_macro_definitions: bool,
}

struct RustEmbeddedReplayFrame<'graph> {
    scope: Node<'graph>,
    cursor: TreeCursor<'graph>,
    tree_id: usize,
    context: usize,
    kind: RustEmbeddedReplayScope,
    phase: RustEmbeddedReplayPhase,
    started: bool,
}

impl<'graph> RustEmbeddedReplayFrame<'graph> {
    fn new(
        scope: Node<'graph>,
        tree_id: usize,
        context: usize,
        kind: RustEmbeddedReplayScope,
        phase: RustEmbeddedReplayPhase,
    ) -> Self {
        Self {
            cursor: scope.walk(),
            scope,
            tree_id,
            context,
            kind,
            phase,
            started: false,
        }
    }

    fn reset(&mut self, phase: RustEmbeddedReplayPhase) {
        self.cursor = self.scope.walk();
        self.phase = phase;
        self.started = false;
    }

    fn next_named_child(&mut self) -> Option<Node<'graph>> {
        let moved = if self.started {
            self.cursor.goto_next_sibling()
        } else {
            self.started = true;
            self.cursor.goto_first_child()
        };
        if !moved {
            return None;
        }
        loop {
            if self.cursor.node().is_named() {
                return Some(self.cursor.node());
            }
            if !self.cursor.goto_next_sibling() {
                return None;
            }
        }
    }
}

struct RustEmbeddedReplayDriver<'graph, 'source, 'external, 'collector> {
    trees: &'graph [RustEmbeddedReplayTree],
    file: &'external ProjectFile,
    source: &'source str,
    item_macro_definitions: &'external [RustRulesItemMacroDefinition],
    parsed: &'external mut ParsedFile,
    source_bridge: &'external mut RustEmbeddedDeclarationSourceBridge<'collector, 'source>,
    source_imports: &'external [SourceImportFact],
    embedded_import_ids: &'external mut Vec<SourceImportId>,
    contexts: Vec<RustEmbeddedReplayContext>,
    frames: Vec<RustEmbeddedReplayFrame<'graph>>,
}

#[allow(clippy::too_many_arguments)]
impl<'graph, 'source, 'external, 'collector>
    RustEmbeddedReplayDriver<'graph, 'source, 'external, 'collector>
{
    fn new(
        trees: &'graph [RustEmbeddedReplayTree],
        file: &'external ProjectFile,
        source: &'source str,
        item_macro_definitions: &'external [RustRulesItemMacroDefinition],
        parsed: &'external mut ParsedFile,
        source_bridge: &'external mut RustEmbeddedDeclarationSourceBridge<'collector, 'source>,
        source_imports: &'external [SourceImportFact],
        embedded_import_ids: &'external mut Vec<SourceImportId>,
    ) -> Self {
        Self {
            trees,
            file,
            source,
            item_macro_definitions,
            parsed,
            source_bridge,
            source_imports,
            embedded_import_ids,
            contexts: Vec::new(),
            frames: Vec::new(),
        }
    }

    /// Replay one admitted invocation's items as `scope` declares them: module
    /// items at the root of a file or module, members of `parent` in an `impl`
    /// or trait body.
    fn push_macro_invocation(
        &mut self,
        parent: Option<CodeUnit>,
        package_name: String,
        admission: RustEmbeddedAdmittedMacro,
        scope: RustEmbeddedReplayScope,
    ) {
        let RustEmbeddedAdmittedMacro {
            tree_id,
            replay_macro_definitions,
            in_test_region,
        } = admission;
        let root = self.trees[tree_id].tree.root_node();
        let import_binder = self.bind_root_imports(tree_id, root);
        let context = self.contexts.len();
        self.contexts.push(RustEmbeddedReplayContext {
            parent,
            package_name,
            import_binder,
            in_test_region,
            replay_macro_definitions,
        });
        self.frames.push(RustEmbeddedReplayFrame::new(
            root,
            tree_id,
            context,
            scope,
            RustEmbeddedReplayPhase::Visit,
        ));
    }

    fn bind_root_imports(&mut self, tree_id: usize, root: Node<'graph>) -> ImportBinder {
        let mut binder = ImportBinder::empty();
        let mut cursor = root.walk();
        for child in root.named_children(&mut cursor) {
            let child = unwrap_attributes(child);
            if child.kind() != "use_declaration" {
                continue;
            }
            let source_import_ids = self.source_bridge.source_import_ids(tree_id, child);
            for source_import_id in source_import_ids {
                let source_import = self
                    .source_imports
                    .get(source_import_id.index())
                    .expect("embedded import cache references a source import");
                crate::lexical_scope::insert_rust_source_import_binding(&mut binder, source_import);
                self.embedded_import_ids.push(*source_import_id);
            }
        }
        binder
    }

    fn bind_module_import(&mut self, context: usize, tree_id: usize, child: Node<'graph>) {
        let child = unwrap_attributes(child);
        if child.kind() != "use_declaration" {
            return;
        }
        let source_import_ids = self.source_bridge.source_import_ids(tree_id, child);
        for source_import_id in source_import_ids {
            let source_import = self
                .source_imports
                .get(source_import_id.index())
                .expect("embedded import cache references a source import");
            crate::lexical_scope::insert_rust_source_import_binding(
                &mut self.contexts[context].import_binder,
                source_import,
            );
        }
    }

    fn push_scope(
        &mut self,
        node: Node<'graph>,
        tree_id: usize,
        parent: Option<CodeUnit>,
        package_name: String,
        import_binder: ImportBinder,
        in_test_region: bool,
        replay_macro_definitions: bool,
        kind: RustEmbeddedReplayScope,
    ) {
        let Some(scope) = node.child_by_field_name("body") else {
            return;
        };
        let context = self.contexts.len();
        self.contexts.push(RustEmbeddedReplayContext {
            parent,
            package_name,
            import_binder,
            in_test_region,
            replay_macro_definitions,
        });
        let phase = if kind == RustEmbeddedReplayScope::Module {
            RustEmbeddedReplayPhase::BindModule
        } else {
            RustEmbeddedReplayPhase::Visit
        };
        self.frames.push(RustEmbeddedReplayFrame::new(
            scope, tree_id, context, kind, phase,
        ));
    }

    fn run(&mut self) {
        while !self.frames.is_empty() {
            let index = self.frames.len() - 1;
            if self.frames[index].phase == RustEmbeddedReplayPhase::BindModule {
                if let Some(child) = self.frames[index].next_named_child() {
                    let context = self.frames[index].context;
                    let tree_id = self.frames[index].tree_id;
                    self.bind_module_import(context, tree_id, child);
                } else {
                    self.frames[index].reset(RustEmbeddedReplayPhase::Visit);
                }
                continue;
            }
            let Some(child) = self.frames[index].next_named_child() else {
                debug_assert_eq!(self.frames[index].context, self.contexts.len() - 1);
                self.frames.pop();
                self.contexts
                    .pop()
                    .expect("each replay frame owns the last active context");
                continue;
            };
            let context = self.frames[index].context;
            let kind = self.frames[index].kind;
            let tree_id = self.frames[index].tree_id;
            self.dispatch(child, context, kind, tree_id);
        }
    }

    fn dispatch(
        &mut self,
        node: Node<'graph>,
        context: usize,
        scope_kind: RustEmbeddedReplayScope,
        tree_id: usize,
    ) {
        let node = unwrap_attributes(node);
        self.source_bridge.set_tree_id(tree_id);
        match scope_kind {
            RustEmbeddedReplayScope::Root | RustEmbeddedReplayScope::Module => {
                self.dispatch_module_item(node, context, tree_id);
            }
            RustEmbeddedReplayScope::Class => {
                self.dispatch_class_item(node, context, tree_id);
            }
            RustEmbeddedReplayScope::Foreign => {
                if matches!(node.kind(), "function_signature_item" | "static_item") {
                    let parent = self.contexts[context].parent.as_ref();
                    let package_name = self.contexts[context].package_name.as_str();
                    let parent_in_test_region = self.contexts[context].in_test_region;
                    if node.kind() == "function_signature_item" {
                        visit_rust_function(
                            self.file,
                            self.source,
                            node,
                            parent,
                            package_name,
                            parent_in_test_region,
                            self.parsed,
                            self.source_bridge,
                        );
                    } else {
                        register_rust_field(
                            self.file,
                            self.source,
                            node,
                            parent,
                            package_name,
                            parent_in_test_region,
                            self.parsed,
                            self.source_bridge,
                        );
                    }
                }
            }
            RustEmbeddedReplayScope::Impl => {
                if matches!(node.kind(), "function_item" | "const_item" | "type_item") {
                    let parent = self.contexts[context].parent.as_ref();
                    let package_name = self.contexts[context].package_name.as_str();
                    let parent_in_test_region = self.contexts[context].in_test_region;
                    if node.kind() == "function_item" {
                        visit_rust_function(
                            self.file,
                            self.source,
                            node,
                            parent,
                            package_name,
                            parent_in_test_region,
                            self.parsed,
                            self.source_bridge,
                        );
                    } else if node.kind() == "const_item" {
                        register_rust_field(
                            self.file,
                            self.source,
                            node,
                            parent,
                            package_name,
                            parent_in_test_region,
                            self.parsed,
                            self.source_bridge,
                        );
                    } else {
                        visit_rust_alias(
                            self.file,
                            self.source,
                            node,
                            parent,
                            package_name,
                            parent_in_test_region,
                            self.parsed,
                            self.source_bridge,
                        );
                    }
                }
            }
            RustEmbeddedReplayScope::EnumVariant => {
                if node.kind() == "field_declaration" {
                    let parent = self.contexts[context].parent.as_ref();
                    let package_name = self.contexts[context].package_name.as_str();
                    let parent_in_test_region = self.contexts[context].in_test_region;
                    register_rust_field(
                        self.file,
                        self.source,
                        node,
                        parent,
                        package_name,
                        parent_in_test_region,
                        self.parsed,
                        self.source_bridge,
                    );
                }
            }
        }
    }

    fn dispatch_module_item(&mut self, node: Node<'graph>, context: usize, tree_id: usize) {
        let parent = self.contexts[context].parent.as_ref();
        let package_name = self.contexts[context].package_name.as_str();
        let parent_in_test_region = self.contexts[context].in_test_region;
        let replay_macro_definitions = self.contexts[context].replay_macro_definitions;
        match node.kind() {
            "struct_item" | "enum_item" | "union_item" | "trait_item" => {
                let Some(code_unit) = register_rust_class_like(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                ) else {
                    return;
                };
                let in_test_region =
                    parent_in_test_region || rust_item_carries_test_attribute(node, self.source);
                self.push_scope(
                    node,
                    tree_id,
                    Some(code_unit),
                    package_name.to_string(),
                    ImportBinder::empty(),
                    in_test_region,
                    false,
                    RustEmbeddedReplayScope::Class,
                );
            }
            "mod_item" => {
                let Some(code_unit) = register_rust_module(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                ) else {
                    return;
                };
                let in_test_region =
                    parent_in_test_region || rust_item_carries_test_attribute(node, self.source);
                self.push_scope(
                    node,
                    tree_id,
                    Some(code_unit),
                    package_name.to_string(),
                    ImportBinder::empty(),
                    in_test_region,
                    true,
                    RustEmbeddedReplayScope::Module,
                );
            }
            "function_item" => {
                visit_rust_function(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                );
            }
            "foreign_mod_item" => {
                let in_test_region =
                    parent_in_test_region || rust_item_carries_test_attribute(node, self.source);
                self.push_scope(
                    node,
                    tree_id,
                    parent.cloned(),
                    package_name.to_string(),
                    ImportBinder::empty(),
                    in_test_region,
                    false,
                    RustEmbeddedReplayScope::Foreign,
                );
            }
            "const_item" | "static_item" => {
                register_rust_field(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                );
            }
            "type_item" => {
                visit_rust_alias(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                );
            }
            "macro_definition" if replay_macro_definitions => {
                visit_rust_macro(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                );
            }
            "impl_item" => {
                if let Some(trait_node) = node.child_by_field_name("trait") {
                    self.source_bridge.record_type(trait_node, self.source);
                }
                let Some(type_node) = node.child_by_field_name("type") else {
                    return;
                };
                let target = self.source_bridge.record_type(type_node, self.source);
                let Some(owner) = rust_impl_owner(
                    self.file,
                    target,
                    parent,
                    package_name,
                    &self.contexts[context].import_binder,
                    self.parsed,
                ) else {
                    return;
                };
                let in_test_region =
                    parent_in_test_region || rust_item_carries_test_attribute(node, self.source);
                self.push_scope(
                    node,
                    tree_id,
                    Some(owner.clone()),
                    owner.package_name().to_string(),
                    ImportBinder::empty(),
                    in_test_region,
                    false,
                    RustEmbeddedReplayScope::Impl,
                );
            }
            "macro_invocation" => {
                let Some(child_tree_id) = self.trees[tree_id].child_tree(node) else {
                    return;
                };
                let Some(admission) = rust_embedded_macro_invocation_admission(
                    node,
                    self.source,
                    self.item_macro_definitions,
                    parent_in_test_region,
                    self.trees,
                    child_tree_id,
                ) else {
                    return;
                };
                let parent = parent.cloned();
                let package_name = package_name.to_string();
                self.push_macro_invocation(
                    parent,
                    package_name,
                    admission,
                    RustEmbeddedReplayScope::Root,
                );
            }
            _ => {}
        }
    }

    fn dispatch_class_item(&mut self, node: Node<'graph>, context: usize, tree_id: usize) {
        let parent = self.contexts[context].parent.as_ref();
        let package_name = self.contexts[context].package_name.as_str();
        let parent_in_test_region = self.contexts[context].in_test_region;
        match node.kind() {
            "field_declaration" | "enum_variant" | "const_item" => {
                let Some(code_unit) = register_rust_field(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                ) else {
                    return;
                };
                if node.kind() == "enum_variant"
                    && node
                        .child_by_field_name("body")
                        .is_some_and(|body| body.kind() == "field_declaration_list")
                {
                    let in_test_region = parent_in_test_region
                        || rust_item_carries_test_attribute(node, self.source);
                    self.push_scope(
                        node,
                        tree_id,
                        Some(code_unit),
                        package_name.to_string(),
                        ImportBinder::empty(),
                        in_test_region,
                        false,
                        RustEmbeddedReplayScope::EnumVariant,
                    );
                }
            }
            "function_item" | "function_signature_item" => {
                visit_rust_function(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                );
            }
            "associated_type" | "type_item" => {
                visit_rust_alias(
                    self.file,
                    self.source,
                    node,
                    parent,
                    package_name,
                    parent_in_test_region,
                    self.parsed,
                    self.source_bridge,
                );
            }
            _ => {}
        }
    }
}

/// Exact byte and point range of a `token_tree`'s interior, excluding its
/// delimiters. Returns `None` if the node is not a delimited token tree.
pub fn rust_macro_token_tree_interior(token_tree: Node<'_>) -> Option<tree_sitter::Range> {
    let open = token_tree.child(0)?;
    let close = token_tree.child(token_tree.child_count().checked_sub(1)?)?;
    if !matches!(open.kind(), "(" | "[" | "{") || !matches!(close.kind(), ")" | "]" | "}") {
        return None;
    }
    let start = open.end_byte();
    let end = close.start_byte();
    (start <= end).then_some(tree_sitter::Range {
        start_byte: start,
        end_byte: end,
        start_point: open.end_position(),
        end_point: close.start_position(),
    })
}

/// Robustness gate: the reparsed interior is only indexed when it consists
/// entirely of well-formed Rust items (plus benign comments/attributes) with no
/// ERROR or MISSING nodes anywhere. This rejects expression-macro arguments
/// (`vec![1, 2, 3]`, `matches!(x, Some(_))`, `println!("struct Foo")`) whose
/// interiors are not item streams, while admitting real item blocks -- including
/// `thread_local! { static FOO: ...; }`, which correctly yields a static.
fn rust_reparsed_items_are_indexable(root: Node<'_>) -> bool {
    if root.has_error() {
        return false;
    }
    let mut cursor = root.walk();
    let mut saw_item = false;
    for child in root.named_children(&mut cursor) {
        match unwrap_attributes(child).kind() {
            "line_comment" | "block_comment" | "attribute_item" | "inner_attribute_item" => {}
            kind if rust_is_indexable_item_kind(kind) => saw_item = true,
            _ => return false,
        }
    }
    saw_item
}

fn rust_is_indexable_item_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_item"
            | "struct_item"
            | "enum_item"
            | "union_item"
            | "trait_item"
            | "mod_item"
            | "use_declaration"
            | "const_item"
            | "static_item"
            | "type_item"
            | "impl_item"
            | "macro_definition"
            | "macro_invocation"
            | "extern_crate_declaration"
            | "foreign_mod_item"
    )
}

pub fn rust_unqualified_macro_invocation_name<'a>(
    node: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    let macro_node = node.child_by_field_name("macro")?;
    if !rust_is_identifier_like(macro_node) {
        return None;
    }
    let name = rust_node_text(macro_node, source).trim();
    (!name.is_empty()).then_some(name)
}

/// Whether a tree-sitter Rust node is an item rather than an expression or a
/// statement.
///
/// Two callers ask this, and both ask it about authority rather than about
/// syntax alone. A macro argument group that parses as one of these is an
/// item-position interior, over which declaration replay is the sole
/// declaration authority, so the definition-less argument enumeration must not
/// lower it; and the fragment walk refuses the subset whose authority belongs
/// to another producer even when it appears nested.
///
/// The list is the `_declaration_statement` and item alternatives of the
/// tree-sitter Rust grammar. `impl_item` and the attribute items declare no
/// name of their own and are still items: a group that parses as one is not an
/// expression, which is the question here.
pub(crate) fn rust_node_is_item(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "associated_type"
            | "attribute_item"
            | "const_item"
            | "enum_item"
            | "extern_crate_declaration"
            | "foreign_mod_item"
            | "function_item"
            | "function_signature_item"
            | "impl_item"
            | "inner_attribute_item"
            | "macro_definition"
            | "mod_item"
            | "static_item"
            | "struct_item"
            | "trait_item"
            | "type_item"
            | "union_item"
            | "use_declaration"
    )
}

pub fn rust_macro_invocation_arguments(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("arguments").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "token_tree")
    })
}

/// Classify a macro invocation from its live tree-sitter parents. This shared
/// fact feeds both source replay admission and native resolution gaps.
pub(crate) fn rust_macro_invocation_source_position(node: Node<'_>) -> RustItemMacroSourcePosition {
    debug_assert_eq!(node.kind(), "macro_invocation");
    let Some(parent) = node.parent() else {
        return RustItemMacroSourcePosition::Other;
    };
    if matches!(parent.kind(), "source_file" | "declaration_list") {
        return RustItemMacroSourcePosition::DirectItem;
    }
    if parent.kind() == "expression_statement"
        && parent
            .parent()
            .is_some_and(|owner| matches!(owner.kind(), "source_file" | "declaration_list"))
    {
        return RustItemMacroSourcePosition::ItemStatement;
    }
    RustItemMacroSourcePosition::Other
}

fn rust_is_identifier_like(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "reserved_identifier" | "_reserved_identifier"
    )
}

/// Re-exported from core, where the persisted Rust module-route facts that
/// carry it live.
pub use brokk_bifrost_core::analyzer::rust_facts::RustRulesItemMacroDefinition;

/// The standalone macro scan is retained only for focused tests that exercise
/// route parsing without running the coordinated declaration producer. It
/// deliberately returns a syntax-only projection: it cannot invent a
/// production SourceDeclarationId.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustRawRulesItemMacroDefinition {
    pub(crate) name: String,
    pub(crate) visible_after: usize,
    pub(crate) scope_start: usize,
    pub(crate) scope_end: usize,
    pub(crate) passthrough: bool,
    pub(crate) arguments_only: bool,
    pub(crate) decoration: Option<RustCfgCondition>,
    pub(crate) exported: bool,
}

#[cfg(test)]
pub(crate) fn rust_rules_item_macro_definitions(
    root: Node<'_>,
    source: &str,
) -> Vec<RustRawRulesItemMacroDefinition> {
    let mut definitions = Vec::new();
    let mut pending_scopes = vec![root];
    while let Some(scope) = pending_scopes.pop() {
        let mut cursor = scope.walk();
        let mut children = scope.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        for child in children {
            let child = unwrap_attributes(child);
            if child.kind() == "macro_definition" {
                if let Some(name) = rust_macro_definition_name(child, source) {
                    definitions.push((
                        RustRawRulesItemMacroDefinition {
                            name: name.to_string(),
                            visible_after: child.end_byte(),
                            scope_start: scope.start_byte(),
                            scope_end: scope.end_byte(),
                            passthrough: rust_macro_definition_all_rules_replay_item_parameters(
                                child, source,
                            ),
                            arguments_only: rust_macro_definition_expands_to_its_arguments_only(
                                child, source,
                            ),
                            decoration: rust_macro_definition_all_rules_replay_item_parameters(
                                child, source,
                            )
                            .then(|| rust_macro_definition_decoration(child, source))
                            .flatten(),
                            exported: rust_item_has_simple_attribute(child, source, "macro_export"),
                        },
                        rust_macro_definition_item_delegate(child, source),
                        rust_macro_definition_delegate_prefix(child, source),
                    ));
                }
                continue;
            }
            if child.kind() == "mod_item"
                && let Some(body) = child.child_by_field_name("body")
            {
                pending_scopes.push(body);
            }
        }
    }
    definitions.sort_by_key(|(definition, _, _)| definition.visible_after);
    loop {
        let mut changed = false;
        for index in 0..definitions.len() {
            if definitions[index].0.passthrough {
                continue;
            }
            let Some(delegate) = definitions[index].1.as_deref() else {
                continue;
            };
            let wrapper = &definitions[index].0;
            let delegated = definitions[..index]
                .iter()
                .filter(|(definition, _, _)| {
                    definition.name == delegate
                        && definition.visible_after <= wrapper.visible_after
                        && definition.scope_start <= wrapper.visible_after
                        && wrapper.visible_after < definition.scope_end
                })
                .max_by_key(|(definition, _, _)| (definition.scope_start, definition.visible_after))
                .filter(|(definition, _, _)| definition.passthrough)
                .map(|(definition, _, _)| definition.decoration.clone());
            if let Some(inner) = delegated {
                definitions[index].0.passthrough = true;
                definitions[index].0.decoration = inner.and_then(|inner| {
                    definitions[index]
                        .2
                        .clone()
                        .map(|prefix| RustCfgCondition::conjunction([prefix, inner]))
                });
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    definitions
        .into_iter()
        .map(|(definition, _, _)| definition)
        .collect()
}

pub(crate) fn rust_item_has_simple_attribute(node: Node<'_>, source: &str, expected: &str) -> bool {
    item_has_path_attribute(node, source, expected)
}

fn rust_macro_definition_item_delegate(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let rules: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect();
    let mut delegate = None;
    for rule in rules {
        let candidate = rust_macro_rule_item_delegate(rule, source)?;
        if delegate.as_ref().is_some_and(|known| known != &candidate) {
            return None;
        }
        delegate = Some(candidate);
    }
    delegate
}

fn rust_macro_rule_item_delegate(rule: Node<'_>, source: &str) -> Option<String> {
    let pattern = rule.child_by_field_name("left")?;
    let expansion = rule.child_by_field_name("right")?;
    let item_parameters = rust_macro_rule_item_parameters(pattern, source);
    if item_parameters.is_empty()
        || !rust_macro_rule_matcher_is_item_stream(pattern, source, &item_parameters)
    {
        return None;
    }

    let mut cursor = expansion.walk();
    let children = expansion.children(&mut cursor).collect::<Vec<_>>();
    let mut index = 1;
    let end = children.len().checked_sub(1)?;
    while index + 1 < end
        && children[index].kind() == "#"
        && rust_is_conditional_attribute_token_tree(children[index + 1], source)
    {
        index += 2;
    }
    let name = *children.get(index)?;
    let bang = *children.get(index + 1)?;
    let arguments = *children.get(index + 2)?;
    if index + 3 != end
        || !rust_is_identifier_like(name)
        || bang.kind() != "!"
        || arguments.kind() != "token_tree"
        || !rust_macro_delegate_arguments_replay_items(arguments, source, &item_parameters)
    {
        return None;
    }
    Some(rust_node_text(name, source).trim().to_string())
}

fn rust_is_conditional_attribute_token_tree(node: Node<'_>, source: &str) -> bool {
    node.kind() == "token_tree"
        && node.child(0).is_some_and(|child| child.kind() == "[")
        && node
            .child(node.child_count().saturating_sub(1))
            .is_some_and(|child| child.kind() == "]")
        && node
            .named_child(0)
            .filter(|child| rust_is_identifier_like(*child))
            .map(|child| rust_node_text(child, source).trim())
            .is_some_and(|name| matches!(name, "cfg" | "cfg_attr"))
}

fn rust_macro_delegate_arguments_replay_items(
    arguments: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut cursor = arguments.walk();
    let children = arguments.children(&mut cursor).collect::<Vec<_>>();
    let Some(inner) = children.get(1..children.len().saturating_sub(1)) else {
        return false;
    };
    if inner.is_empty()
        || inner.iter().any(|child| {
            child.kind() != "token_repetition"
                || !rust_item_repetition_replays_parameters(*child, source, item_parameters)
        })
    {
        return false;
    }
    let mut seen = HashMap::default();
    for child in inner {
        let mut pending = vec![*child];
        while let Some(node) = pending.pop() {
            if node.kind() == "metavariable" {
                *seen
                    .entry(rust_node_text(node, source).trim().to_string())
                    .or_insert(0usize) += 1;
                continue;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
    }
    item_parameters
        .keys()
        .all(|parameter| seen.get(parameter) == Some(&1))
        && seen.len() == item_parameters.len()
}

fn rust_item_repetition_replays_parameters(
    repetition: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut cursor = repetition.walk();
    repetition
        .children(&mut cursor)
        .all(|child| match child.kind() {
            "$" | "(" | ")" | "*" | "+" | "?" => true,
            "metavariable" => item_parameters.contains_key(rust_node_text(child, source).trim()),
            _ => false,
        })
}

fn rust_builtin_macro_does_not_replay_item_arguments(name: &str) -> bool {
    matches!(
        name,
        "cfg"
            | "column"
            | "compile_error"
            | "concat"
            | "env"
            | "file"
            | "include"
            | "include_bytes"
            | "include_str"
            | "line"
            | "module_path"
            | "option_env"
            | "stringify"
    )
}

/// Whether every rule of this `macro_rules!` expands to exactly its replayed
/// item arguments and nothing else.
///
/// This is strictly stronger than the item-passthrough proof, and the
/// difference is the whole reason it exists. The passthrough classifier proves
/// each item argument is replayed once at its bound repetition depth and
/// deliberately admits a rule that decorates the replayed items, so
/// `$( #[cfg(any())] $item )*` and `#[cfg(unix)] inner! { $($item)* }` are
/// passthroughs. That is enough to decide a module route, because the item is
/// still there. It is not enough to declare the items with the activation they
/// carry in source: the expansion may add a `cfg` the argument does not have,
/// and a declaration minted from the argument tokens would claim an activation
/// the expansion does not give it.
///
/// So the persisted lowering declares a macro's items only when the expansion
/// adds nothing at all. Every named node of every transcriber must be the
/// repetition scaffolding or a metavariable; one added token anywhere rejects
/// the definition.
pub(crate) fn rust_macro_definition_expands_to_its_arguments_only(
    node: Node<'_>,
    source: &str,
) -> bool {
    let mut cursor = node.walk();
    let rules = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return false;
    }
    rules.into_iter().all(|rule| {
        let Some(expansion) = rule.child_by_field_name("right") else {
            return false;
        };
        if !rust_macro_rule_replays_item_parameters(rule, source) {
            return false;
        }
        let mut pending = vec![expansion];
        while let Some(current) = pending.pop() {
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                if !matches!(child.kind(), "token_repetition" | "metavariable") {
                    return false;
                }
                pending.push(child);
            }
        }
        true
    })
}

/// Whether no rule of this `macro_rules!` can write an item, so an
/// item-position invocation of it declares nothing whatever its input.
///
/// A rule is proven when its transcriber holds no token an item can start
/// with or name as its kind (`fn`, `struct`, `impl`, `mod`, `use`, `extern`,
/// ...), no `!` (a nested invocation could write items), and no metavariable
/// whose fragment could supply such a token (`tt`, `item`, `stmt`, and
/// `ident`, which matches keywords). An empty transcriber is the common case:
/// `($e:expr) => {}`. The proof is conservative: a rule that writes an
/// expression mentioning `crate::` is not proven.
pub(crate) fn rust_macro_definition_declares_no_item(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    let rules = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect::<Vec<_>>();
    !rules.is_empty()
        && rules
            .into_iter()
            .all(|rule| rust_macro_rule_declares_no_item(rule, source))
}

/// Whether one selected macro arm is proven to declare no item.
pub(crate) fn rust_macro_definition_no_item_arms(node: Node<'_>, source: &str) -> Vec<bool> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .map(|rule| rust_macro_rule_declares_no_item(rule, source))
        .collect()
}

fn rust_macro_rule_declares_no_item(rule: Node<'_>, source: &str) -> bool {
    let (Some(pattern), Some(expansion)) = (
        rule.child_by_field_name("left"),
        rule.child_by_field_name("right"),
    ) else {
        return false;
    };
    let mut open_fragments = HashSet::default();
    let mut pending = vec![pattern];
    while let Some(current) = pending.pop() {
        if current.kind() == "token_binding_pattern"
            && matches!(
                rust_macro_binding_fragment(current, source),
                Some("tt" | "item" | "stmt" | "ident")
            )
            && let Some(name) = current.child_by_field_name("name")
        {
            open_fragments.insert(rust_node_text(name, source).trim());
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
    let mut pending = vec![expansion];
    while let Some(current) = pending.pop() {
        let item_token = match current.kind() {
            "fn" | "struct" | "enum" | "union" | "impl" | "trait" | "mod" | "use" | "const"
            | "static" | "type" | "crate" | "!" => true,
            "identifier" => matches!(rust_node_text(current, source), "extern" | "macro_rules"),
            "metavariable" => open_fragments.contains(rust_node_text(current, source).trim()),
            _ => false,
        };
        if item_token {
            return false;
        }
        let mut cursor = current.walk();
        pending.extend(current.children(&mut cursor));
    }
    true
}

/// Whether every rule of this `macro_rules!` writes nothing but `impl`
/// blocks, so an item-position invocation of it binds no name in its module:
/// it can add members to types, and nothing else.
///
/// A rule is proven when its transcriber's top-level tokens are a sequence of
/// `impl` items (optional outer attributes and `unsafe`, the `impl` keyword,
/// a header, and a `{ .. }` body), possibly inside `$( .. )` repetitions of
/// the same shape, and every metavariable it splices is bound as `ty`, `expr`,
/// `path` or `lifetime`, none of which can bring an item or a keyword of its
/// own. tract's `impl_datum_type!` (`($ty:ty, $c:expr) => { impl Datum for
/// $ty { .. } }`) is the shape; a `tt` or `ident` fragment is not proven.
pub(crate) fn rust_macro_definition_writes_only_impls(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    let rules = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect::<Vec<_>>();
    !rules.is_empty()
        && rules.into_iter().all(|rule| {
            let (Some(pattern), Some(expansion)) = (
                rule.child_by_field_name("left"),
                rule.child_by_field_name("right"),
            ) else {
                return false;
            };
            let mut splicing_fragments = HashMap::default();
            let mut pending = vec![pattern];
            while let Some(current) = pending.pop() {
                if current.kind() == "token_binding_pattern"
                    && let (Some(name), Some(fragment)) = (
                        current.child_by_field_name("name"),
                        rust_macro_binding_fragment(current, source),
                    )
                {
                    splicing_fragments.insert(rust_node_text(name, source).trim(), fragment);
                }
                let mut cursor = current.walk();
                pending.extend(current.named_children(&mut cursor));
            }
            let mut pending = vec![expansion];
            while let Some(current) = pending.pop() {
                if current.kind() == "metavariable" {
                    let name = rust_node_text(current, source).trim();
                    let spliced = name == "$crate"
                        || splicing_fragments.get(name).is_some_and(|fragment| {
                            matches!(*fragment, "ty" | "expr" | "path" | "lifetime")
                        });
                    if !spliced {
                        return false;
                    }
                }
                let mut cursor = current.walk();
                pending.extend(current.named_children(&mut cursor));
            }
            let mut cursor = expansion.walk();
            let children = expansion.children(&mut cursor).collect::<Vec<_>>();
            let [_open, interior @ .., _close] = children.as_slice() else {
                return false;
            };
            rust_tokens_are_impl_items(interior)
        })
}

/// Whether `tokens`, one level of a transcriber, are a nonempty sequence of
/// `impl` items or `$( .. )` repetitions of them. See
/// [`rust_macro_definition_writes_only_impls`].
fn rust_tokens_are_impl_items(tokens: &[Node<'_>]) -> bool {
    let mut pending = vec![tokens.to_vec()];
    let mut items = 0usize;
    while let Some(sequence) = pending.pop() {
        let mut in_header = false;
        let mut index = 0;
        while index < sequence.len() {
            let token = sequence[index];
            let opens_body = token.kind() == "token_tree"
                && token.child(0).is_some_and(|open| open.kind() == "{");
            if in_header {
                if opens_body {
                    in_header = false;
                    items += 1;
                } else if token.kind() == ";" {
                    return false;
                }
                index += 1;
                continue;
            }
            match token.kind() {
                "#" => {
                    let attribute = sequence.get(index + 1).is_some_and(|next| {
                        next.kind() == "token_tree"
                            && next.child(0).is_some_and(|open| open.kind() == "[")
                    });
                    if !attribute {
                        return false;
                    }
                    index += 2;
                }
                "unsafe" => index += 1,
                "impl" => {
                    in_header = true;
                    index += 1;
                }
                "token_repetition" => {
                    let mut cursor = token.walk();
                    let parts = token.children(&mut cursor).collect::<Vec<_>>();
                    let Some(open) = parts.iter().position(|part| part.kind() == "(") else {
                        return false;
                    };
                    let Some(close) = parts.iter().rposition(|part| part.kind() == ")") else {
                        return false;
                    };
                    if close <= open + 1 {
                        return false;
                    }
                    pending.push(parts[open + 1..close].to_vec());
                    index += 1;
                }
                _ => return false,
            }
        }
        if in_header {
            return false;
        }
    }
    items > 0
}

fn rust_latest_visible_rules_item_macro(
    definitions: &[RustRulesItemMacroDefinition],
    name: &str,
    invocation_start: usize,
) -> Option<bool> {
    rust_latest_visible_rules_item_macro_definition(definitions, name, invocation_start)
        .map(|definition| definition.passthrough)
}

fn rust_latest_visible_rules_item_macro_definition<'a>(
    definitions: &'a [RustRulesItemMacroDefinition],
    name: &str,
    invocation_start: usize,
) -> Option<&'a RustRulesItemMacroDefinition> {
    definitions
        .iter()
        .filter(|definition| {
            definition.name == name
                && definition.visible_after <= invocation_start
                && definition.scope_start <= invocation_start
                && invocation_start < definition.scope_end
        })
        .max_by_key(|definition| (definition.scope_start, definition.visible_after))
}

/// What one attribute a transcriber adds to the item it replays does to it.
enum RustAddedAttribute {
    Cfg(RustCfgCondition),
    /// `doc`, or a `cfg_attr` whose attributes are all `doc`: it documents the
    /// item and neither removes it nor changes what it declares.
    Documentation,
    Other,
}

/// Classify one attribute token tree, `[..]`, written after a `#` in a
/// transcriber. The tree is a token tree, not an `attribute_item`, because a
/// transcriber is not parsed as items; its predicate is the same token tree an
/// item's `cfg` carries and is read by the same reader.
fn rust_added_attribute(tree: Node<'_>, source: &str) -> RustAddedAttribute {
    let mut cursor = tree.walk();
    let children = tree
        .children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect::<Vec<_>>();
    let [open, name, rest @ .., close] = children.as_slice() else {
        return RustAddedAttribute::Other;
    };
    if open.kind() != "[" || close.kind() != "]" || name.kind() != "identifier" {
        return RustAddedAttribute::Other;
    }
    match (rust_node_text(*name, source).trim(), rest) {
        ("cfg", [arguments]) if arguments.kind() == "token_tree" => RustAddedAttribute::Cfg(
            crate::lexical_scope::rust_cfg_argument_condition(*arguments, source)
                .unwrap_or(RustCfgCondition::Unknown),
        ),
        ("doc", _) => RustAddedAttribute::Documentation,
        ("cfg_attr", [arguments])
            if arguments.kind() == "token_tree"
                && rust_cfg_attr_adds_only_documentation(*arguments, source) =>
        {
            RustAddedAttribute::Documentation
        }
        _ => RustAddedAttribute::Other,
    }
}

/// Whether `cfg_attr(predicate, attributes..)` adds `doc` attributes and
/// nothing else, whatever its predicate decides.
fn rust_cfg_attr_adds_only_documentation(arguments: Node<'_>, source: &str) -> bool {
    let mut cursor = arguments.walk();
    let children = arguments
        .children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect::<Vec<_>>();
    let Some(inner) = children.get(1..children.len().saturating_sub(1)) else {
        return false;
    };
    let groups = inner
        .split(|child| child.kind() == ",")
        .filter(|group| !group.is_empty())
        .collect::<Vec<_>>();
    groups.len() >= 2
        && groups[1..].iter().all(|group| {
            group[0].kind() == "identifier" && rust_node_text(group[0], source).trim() == "doc"
        })
}

/// The activation every rule of a passthrough `macro_rules!` adds to each item
/// it replays, read at the replay depth the classifier proves.
///
/// Each replayed item metavariable may be preceded, in the token list that
/// holds it, by attributes: `$( #[cfg(unix)] #[cfg_attr(docsrs, doc(cfg(unix)))]
/// $item )*` is tokio's `cfg_unix!`. Their `cfg` predicates are conjoined and
/// documentation attributes are skipped. Anything else the transcriber adds --
/// another attribute, an item of its own, an attribute before a repetition --
/// makes the answer `None`, as does a rule or a metavariable whose addition
/// differs from another's, because the crate cannot tell which rule or which
/// parameter an expanded item came from. The caller has already proved that
/// every rule replays its item parameters.
fn rust_macro_definition_decoration(node: Node<'_>, source: &str) -> Option<RustCfgCondition> {
    let mut cursor = node.walk();
    let rules = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect::<Vec<_>>();
    let mut decoration: Option<RustCfgCondition> = None;
    for rule in rules {
        let pattern = rule.child_by_field_name("left")?;
        let expansion = rule.child_by_field_name("right")?;
        let item_parameters = rust_macro_rule_item_parameters(pattern, source);
        let mut pending = vec![expansion];
        while let Some(parent) = pending.pop() {
            let mut cursor = parent.walk();
            let children = parent
                .children(&mut cursor)
                .filter(|child| !child.is_extra())
                .collect::<Vec<_>>();
            // The transcriber's own delimiters, and a repetition's `$( .. )*`.
            let contents = if parent == expansion {
                children.get(1..children.len().saturating_sub(1))?
            } else {
                children.as_slice()
            };
            let mut added = Vec::new();
            let mut attributed = false;
            let mut attribute_opened = false;
            for child in contents {
                match child.kind() {
                    "$" | "(" | ")" | "*" | "+" | "?" if parent != expansion => {}
                    "#" if !attribute_opened => attribute_opened = true,
                    "token_tree" if attribute_opened => {
                        attribute_opened = false;
                        attributed = true;
                        match rust_added_attribute(*child, source) {
                            RustAddedAttribute::Cfg(condition) => added.push(condition),
                            RustAddedAttribute::Documentation => {}
                            RustAddedAttribute::Other => return None,
                        }
                    }
                    "metavariable"
                        if !attribute_opened
                            && item_parameters
                                .contains_key(rust_node_text(*child, source).trim()) =>
                    {
                        let item = RustCfgCondition::conjunction(added.drain(..));
                        attributed = false;
                        match &decoration {
                            None => decoration = Some(item),
                            Some(known) if *known == item => {}
                            Some(_) => return None,
                        }
                    }
                    "token_repetition" if !attribute_opened && !attributed => {
                        pending.push(*child);
                    }
                    _ => return None,
                }
            }
            if attribute_opened || attributed {
                return None;
            }
        }
    }
    decoration
}

/// The activation the `cfg` attributes a delegating passthrough writes before
/// its delegate invocation add (`#[cfg(unix)] direct_items! { $($item)* }`),
/// the same in every rule, or `None`. The delegate's own decoration is the
/// caller's to conjoin.
fn rust_macro_definition_delegate_prefix(node: Node<'_>, source: &str) -> Option<RustCfgCondition> {
    let mut cursor = node.walk();
    let rules = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect::<Vec<_>>();
    let mut prefix: Option<RustCfgCondition> = None;
    for rule in rules {
        let expansion = rule.child_by_field_name("right")?;
        let mut cursor = expansion.walk();
        let children = expansion.children(&mut cursor).collect::<Vec<_>>();
        let mut added = Vec::new();
        let mut index = 1;
        while index + 1 < children.len() && children[index].kind() == "#" {
            match rust_added_attribute(children[index + 1], source) {
                RustAddedAttribute::Cfg(condition) => added.push(condition),
                RustAddedAttribute::Documentation => {}
                RustAddedAttribute::Other => return None,
            }
            index += 2;
        }
        let rule_prefix = RustCfgCondition::conjunction(added);
        match &prefix {
            None => prefix = Some(rule_prefix),
            Some(known) if *known == rule_prefix => {}
            Some(_) => return None,
        }
    }
    prefix
}

fn rust_macro_definition_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    (!name.is_empty()).then_some(name)
}

fn rust_macro_definition_all_rules_replay_item_parameters(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    let rules: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect();
    !rules.is_empty()
        && rules
            .into_iter()
            .all(|rule| rust_macro_rule_replays_item_parameters(rule, source))
}

fn rust_macro_rule_replays_item_parameters(rule: Node<'_>, source: &str) -> bool {
    let Some(pattern) = rule.child_by_field_name("left") else {
        return false;
    };
    let Some(expansion) = rule.child_by_field_name("right") else {
        return false;
    };

    let item_parameters = rust_macro_rule_item_parameters(pattern, source);
    if item_parameters.is_empty()
        || !rust_macro_rule_matcher_is_item_stream(pattern, source, &item_parameters)
    {
        return false;
    }

    let mut occurrences: HashMap<String, usize> = HashMap::default();
    let mut stack = vec![expansion];
    while let Some(node) = stack.pop() {
        if node.kind() == "metavariable" {
            let name = rust_node_text(node, source).trim();
            let Some(pattern_depth) = item_parameters.get(name) else {
                continue;
            };
            let mut repetition_depth = 0;
            let mut ancestor = node;
            loop {
                let Some(parent) = ancestor.parent() else {
                    return false;
                };
                if parent == expansion {
                    break;
                }
                if parent.kind() != "token_repetition" {
                    return false;
                }
                repetition_depth += 1;
                ancestor = parent;
            }
            if repetition_depth != *pattern_depth {
                return false;
            }
            *occurrences.entry(name.to_string()).or_default() += 1;
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    item_parameters
        .keys()
        .all(|parameter| occurrences.get(parameter) == Some(&1))
}

fn rust_macro_rule_item_parameters(pattern: Node<'_>, source: &str) -> HashMap<String, usize> {
    let mut parameters = HashMap::default();
    let mut stack = vec![(pattern, 0)];
    while let Some((node, repetition_depth)) = stack.pop() {
        if node.kind() == "token_binding_pattern"
            && rust_macro_binding_fragment(node, source) == Some("item")
            && let Some(metavariable) = node.child_by_field_name("name")
        {
            let name = rust_node_text(metavariable, source).trim();
            if !name.is_empty() {
                parameters.insert(name.to_string(), repetition_depth);
            }
        }

        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor).map(|child| {
            (
                child,
                repetition_depth + usize::from(child.kind() == "token_repetition_pattern"),
            )
        }));
    }
    parameters
}

fn rust_macro_binding_fragment<'a>(binding: Node<'_>, source: &'a str) -> Option<&'a str> {
    binding
        .child_by_field_name("type")
        .map(|fragment| rust_node_text(fragment, source).trim())
}

fn rust_macro_rule_matcher_is_item_stream(
    pattern: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut cursor = pattern.walk();
    let children = pattern.children(&mut cursor).collect::<Vec<_>>();
    let mut index = 1;
    let end = children.len().saturating_sub(1);
    while index < end {
        let child = children[index];
        match child.kind() {
            "token_binding_pattern" => {
                if rust_macro_binding_fragment(child, source) != Some("item") {
                    return false;
                }
                index += 1;
            }
            "token_repetition_pattern" => {
                if !rust_item_repetition_pattern_is_safe(child, source, item_parameters) {
                    return false;
                }
                index += 1;
            }
            "#" => {
                index += 1;
                if index < end && children[index].kind() == "!" {
                    index += 1;
                }
                if index >= end
                    || children[index].kind() != "token_tree_pattern"
                    || !rust_attribute_meta_pattern_is_safe(children[index], source)
                {
                    return false;
                }
                index += 1;
            }
            _ => return false,
        }
    }
    true
}

fn rust_item_repetition_pattern_is_safe(
    repetition: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut saw_item = false;
    let mut cursor = repetition.walk();
    for child in repetition.children(&mut cursor) {
        match child.kind() {
            "$" | "(" | ")" | "*" | "+" | "?" => {}
            "token_binding_pattern" => {
                let Some(name) = child.child_by_field_name("name") else {
                    return false;
                };
                let name = rust_node_text(name, source).trim();
                if rust_macro_binding_fragment(child, source) != Some("item")
                    || !item_parameters.contains_key(name)
                {
                    return false;
                }
                saw_item = true;
            }
            _ => return false,
        }
    }
    saw_item
}

fn rust_attribute_meta_pattern_is_safe(attribute: Node<'_>, source: &str) -> bool {
    let mut saw_meta = false;
    let mut pending = vec![attribute];
    while let Some(node) = pending.pop() {
        if node.kind() == "token_binding_pattern" {
            if rust_macro_binding_fragment(node, source) != Some("meta") {
                return false;
            }
            saw_meta = true;
            continue;
        }
        if node != attribute && node.kind() == "token_tree_pattern" {
            return false;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    saw_meta
}

fn rust_range_from_node(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

#[allow(clippy::too_many_arguments)]
fn register_rust_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parent_in_test_region: bool,
    parsed: &mut ParsedFile,
    source_bridge: &mut dyn RustDeclarationSourceBridge,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = rust_node_text(name_node, source)
        .trim()
        .trim_end_matches(',')
        .to_string();
    if name.is_empty() {
        return None;
    }

    let in_test_region = parent_in_test_region || rust_item_carries_test_attribute(node, source);
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| format!("{RUST_MODULE_SCOPE_SEGMENT}.{name}"));
    // A package-level `const`/`static` sits under the synthetic `_module_`
    // scope; a member sits directly under its owner.
    let fq = match parent {
        Some(parent) => parent.fq().clone(),
        None => rust_file_package_fq(file).with_pushed(rust_segment(
            RUST_MODULE_SCOPE_SEGMENT,
            SegmentKind::Package,
        )),
    }
    .with_pushed(rust_segment(&name, SegmentKind::Member));
    let code_unit = rust_inherit_package_anchor(
        CodeUnit::with_signature_and_fq(
            file.clone(),
            CodeUnitType::Field,
            package_name.to_string(),
            short_name,
            rust_impl_member_identity_signature(node, source),
            false,
            fq,
        ),
        parent,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    let declaration = source_bridge.record(node, &code_unit);
    if in_test_region {
        parsed.mark_test_region(&code_unit);
    }
    add_rust_signature_metadata(
        parsed,
        declaration,
        code_unit.clone(),
        SignatureMetadata::new(rust_bounded_declaration_label(node, source), Vec::new())
            .with_return_type_text(
                node.child_by_field_name("type")
                    .map(|r#type| rust_node_text(r#type, source).trim().to_owned()),
            )
            .with_return_type_identity(rust_enum_variant_owner_identity(node, source))
            .with_dispatch_extensibility(DispatchExtensibility::Closed),
    );

    Some(code_unit)
}

fn rust_enum_variant_owner_identity(
    variant: Node<'_>,
    source: &str,
) -> Option<StructuredTypeIdentity> {
    if variant.kind() != "enum_variant" {
        return None;
    }
    let mut current = variant.parent()?;
    while current.kind() != "enum_item" {
        current = current.parent()?;
    }
    let enum_name = current.child_by_field_name("name")?;
    let enum_name = rust_node_text(enum_name, source).trim();
    if enum_name.is_empty() {
        return None;
    }

    let mut lexical_scope = Vec::new();
    let mut ancestor = current.parent();
    while let Some(node) = ancestor {
        if node.kind() == "mod_item" {
            let name = node.child_by_field_name("name")?;
            let name = rust_node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            lexical_scope.push(name.to_string());
        }
        ancestor = node.parent();
    }
    lexical_scope.reverse();

    let mut builder = StructuredTypeIdentityBuilder::default();
    let root = builder.named(StructuredTypeName::new(
        vec![enum_name.to_string()],
        lexical_scope,
        false,
    )?)?;
    builder.finish(root)
}

#[allow(clippy::too_many_arguments)]
/// Index a `type` alias or a trait/impl `associated_type` as the type
/// declaration it is: a [`CodeUnitType::Class`] carrying a
/// [`SegmentKind::Type`] segment, exactly what [`visit_rust_class_like`] mints
/// for a `struct`, `enum`, `union`, or `trait`.
///
/// It used to mint a `Field`/`Member` unit, which is byte-for-byte what
/// [`visit_rust_field`] mints for a `const` of the same name in the same owner.
/// `declaration_id` hashes segment kinds, so `mod m { type Max = u32; const Max:
/// u32 = 1; }` produced one CodeUnit instead of two and the `const` was
/// unreachable (#2911).
fn visit_rust_alias(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parent_in_test_region: bool,
    parsed: &mut ParsedFile,
    source_bridge: &mut dyn RustDeclarationSourceBridge,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let in_test_region = parent_in_test_region || rust_item_carries_test_attribute(node, source);
    let (short_name, fq) = rust_type_declaration_identity(file, parent, name);
    let code_unit = rust_inherit_package_anchor(
        CodeUnit::with_signature_and_fq(
            file.clone(),
            CodeUnitType::Class,
            package_name.to_string(),
            short_name,
            rust_impl_member_identity_signature(node, source),
            false,
            fq,
        ),
        parent,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    let declaration = source_bridge.record(node, &code_unit);
    if in_test_region {
        parsed.mark_test_region(&code_unit);
    }
    add_rust_signature_metadata(
        parsed,
        declaration,
        code_unit.clone(),
        SignatureMetadata::new(rust_bounded_declaration_label(node, source), Vec::new())
            .with_recorded_type_parameters(rust_declared_type_parameters(node, source)),
    );
    parsed.mark_type_alias(code_unit.clone());
    Some(code_unit)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustImplOwnerIdentity {
    package_name: String,
    short_name: String,
    /// How `package_name` was resolved, so a persisted member of this owner can
    /// be re-anchored against a live path instead of storing the path-derived
    /// package text of the mount it was extracted from.
    anchor: RustModuleAnchor,
}

fn rust_package_anchor(anchor: RustModuleAnchor) -> Option<PackageAnchor> {
    match anchor {
        RustModuleAnchor::Crate => Some(PackageAnchor::CrateRoot),
        RustModuleAnchor::OwnModule { pop } => Some(PackageAnchor::OwnModule { pop }),
        // A package rooted in another crate cannot be placed from this file's
        // path; encoding falls back to persisting the complete name.
        RustModuleAnchor::External => None,
    }
}

fn rust_impl_owner(
    file: &ProjectFile,
    target: &RustTypeSourceFact,
    lexical_parent: Option<&CodeUnit>,
    package_name: &str,
    import_binder: &ImportBinder,
    parsed: &ParsedFile,
) -> Option<CodeUnit> {
    let target_path: Vec<_> = crate::type_syntax::declaration_owner_path(target)?
        .iter()
        .map(|segment| segment.name.clone())
        .collect();
    let lexical_package = match lexical_parent {
        Some(parent) if package_name.is_empty() => parent.short_name().to_string(),
        Some(parent) => format!("{package_name}.{}", parent.short_name()),
        None => package_name.to_string(),
    };
    let local_identity = RustImplOwnerIdentity {
        package_name: lexical_package.clone(),
        short_name: target_path.join("."),
        anchor: crate::imports::rust_anchor_for_resolved_package(
            &lexical_package,
            package_name,
            false,
        ),
    };
    if let Some(owner) = rust_declared_impl_owner(parsed, &local_identity) {
        return Some(owner);
    }

    let identity = if target_path.len() == 1 {
        let target_name = &target_path[0];
        if let Some(binding) = import_binder.bindings.get(target_name)
            && binding.kind == ImportKind::Named
        {
            let imported_name = binding.imported_name.as_ref()?;
            let resolved_package = crate::imports::resolve_rust_module_path_with_crate(
                &lexical_package,
                &crate::imports::rust_crate_root_package(file),
                &binding.module_specifier,
            )?;
            let anchor = crate::imports::rust_anchor_for_resolved_package(
                &resolved_package,
                package_name,
                crate::imports::rust_module_specifier_is_crate_rooted(&binding.module_specifier),
            );
            RustImplOwnerIdentity {
                package_name: resolved_package,
                short_name: imported_name.clone(),
                anchor,
            }
        } else {
            // Generic parameters and `Self` deliberately remain member namespaces only.
            // Ordinary unresolved bare names do too: only a source declaration can publish
            // a nominal workspace type.
            local_identity
        }
    } else {
        rust_impl_owner_identity_from_path(
            file,
            &lexical_package,
            package_name,
            &target_path,
            import_binder,
        )?
    };

    rust_declared_impl_owner(parsed, &identity).or_else(|| {
        let expected_fqn = if identity.package_name.is_empty() {
            identity.short_name.clone()
        } else {
            format!("{}.{}", identity.package_name, identity.short_name)
        };
        let local_short_name = if package_name.is_empty() {
            Some(expected_fqn)
        } else if identity.package_name == package_name {
            Some(identity.short_name.clone())
        } else {
            identity
                .package_name
                .strip_prefix(package_name)
                .and_then(|suffix| suffix.strip_prefix('.'))
                .map(|suffix| format!("{suffix}.{}", identity.short_name))
        };
        // Re-expressing the owner relative to this file's package also moves its
        // anchor: the structured name is then built on the file's own package,
        // whatever route the specifier took to name it.
        let identity_anchor = identity.anchor;
        let (owner_package, owner_short_name, owner_anchor) = local_short_name
            .map(|short_name| {
                (
                    package_name.to_string(),
                    short_name,
                    RustModuleAnchor::OwnModule { pop: 0 },
                )
            })
            .unwrap_or((identity.package_name, identity.short_name, identity_anchor));
        // This synthesized owner is not itself indexed, but its `fq` seeds the
        // structured names of the impl members that extend it. A resolved
        // owner path names modules before its terminal nominal type. Treating
        // every component as a type creates an equal-rendering orphan when an
        // `impl` precedes the corresponding module-scoped declaration.
        let mut fq = if owner_package == package_name {
            rust_file_package_fq(file)
        } else {
            rust_semantic_package_fq(&owner_package)
        };
        let owner_components = owner_short_name
            .split('.')
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>();
        for (index, component) in owner_components.iter().enumerate() {
            let kind = if index + 1 == owner_components.len() {
                SegmentKind::Type
            } else {
                SegmentKind::Package
            };
            fq.push(rust_segment(component, kind));
        }
        let owner = CodeUnit::new_fq(
            file.clone(),
            CodeUnitType::Class,
            owner_package,
            owner_short_name,
            fq,
        );
        Some(match rust_package_anchor(owner_anchor) {
            Some(anchor) => owner.with_package_anchor(anchor),
            None => owner,
        })
    })
}

fn rust_declared_impl_owner(
    parsed: &ParsedFile,
    identity: &RustImplOwnerIdentity,
) -> Option<CodeUnit> {
    let expected_fqn = if identity.package_name.is_empty() {
        identity.short_name.clone()
    } else {
        format!("{}.{}", identity.package_name, identity.short_name)
    };
    parsed
        .declarations()
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && ((unit.package_name() == identity.package_name
                    && unit.short_name() == identity.short_name)
                    || unit.fq_name() == expected_fqn)
        })
        .cloned()
}

/// The module path that a `use` binding's local name stands for when that name
/// roots a qualified `impl` owner path such as `impl Trait for m::Writer`.
///
/// A namespace binding already names its module. A renamed import keeps the
/// imported terminal name apart from the module it came from, so `m` in
/// `use crate::model as m;` stands for `crate::model` - the two joined. A glob
/// binding names no path root at all.
fn rust_import_binding_module_route(binding: &ImportBinding) -> Option<String> {
    match binding.kind {
        ImportKind::Namespace => Some(binding.module_specifier.clone()),
        ImportKind::Named => {
            let imported_name = binding.imported_name.as_deref()?;
            Some(if binding.module_specifier.is_empty() {
                imported_name.to_string()
            } else {
                format!("{}::{imported_name}", binding.module_specifier)
            })
        }
        _ => None,
    }
}

fn rust_impl_owner_identity_from_path(
    file: &ProjectFile,
    lexical_package: &str,
    file_package: &str,
    path: &[String],
    import_binder: &ImportBinder,
) -> Option<RustImplOwnerIdentity> {
    let (name, module_path) = path.split_last()?;
    let crate_package = crate::imports::rust_crate_root_package(file);
    let (package_name, module_specifier) = if let Some((root, remainder)) =
        module_path.split_first()
        && let Some(binding) = import_binder.bindings.get(root)
        && let Some(root_specifier) = rust_import_binding_module_route(binding)
    {
        let mut resolved = crate::imports::resolve_rust_module_path_with_crate(
            lexical_package,
            &crate_package,
            &root_specifier,
        )?;
        for component in remainder {
            if !resolved.is_empty() {
                resolved.push('.');
            }
            resolved.push_str(component);
        }
        (resolved, root_specifier)
    } else {
        let module_specifier = module_path.join("::");
        let resolved = crate::imports::resolve_rust_module_path_with_crate(
            lexical_package,
            &crate_package,
            &module_specifier,
        )?;
        (resolved, module_specifier)
    };
    let anchor = crate::imports::rust_anchor_for_resolved_package(
        &package_name,
        file_package,
        crate::imports::rust_module_specifier_is_crate_rooted(&module_specifier),
    );

    Some(RustImplOwnerIdentity {
        package_name,
        short_name: name.clone(),
        anchor,
    })
}

/// Return the source-written nominal path contained in a Rust type node.
///
/// This helper intentionally unwraps generic arguments and type wrappers for
/// the ordinary declaration model's synthesized impl owner. Callers that must
/// distinguish `Foo` from a non-nominal target such as `&Foo` must validate
/// the outer Tree-sitter shape before calling it.
pub fn rust_nominal_type_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut pending = vec![node];
    while let Some(candidate) = pending.pop() {
        match candidate.kind() {
            // Primitive spellings can name user declarations (for example
            // half::f16). The parser classifies the token, not its binding.
            "type_identifier" | "identifier" | "primitive_type" => {
                let name = rust_node_text(candidate, source).trim();
                if !name.is_empty() {
                    return Some(vec![name.to_string()]);
                }
            }
            "scoped_type_identifier" => {
                let path = rust_path_components(candidate, source);
                if !path.is_empty() {
                    return Some(path);
                }
            }
            "generic_type" | "reference_type" | "pointer_type" | "array_type" | "slice_type" => {
                if let Some(inner) = candidate.child_by_field_name("type") {
                    pending.push(inner);
                } else {
                    for index in (0..candidate.named_child_count()).rev() {
                        if let Some(child) = candidate.named_child(index)
                            && child.kind() != "type_arguments"
                        {
                            pending.push(child);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn rust_path_components(node: Node<'_>, source: &str) -> Vec<String> {
    let mut components = Vec::new();
    let mut pending = vec![node];
    while let Some(candidate) = pending.pop() {
        match candidate.kind() {
            "crate" | "self" | "super" | "identifier" | "type_identifier" | "primitive_type" => {
                let text = rust_node_text(candidate, source).trim();
                if !text.is_empty() {
                    components.push(text.to_string());
                }
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(name) = candidate.child_by_field_name("name") {
                    pending.push(name);
                }
                if let Some(path) = candidate.child_by_field_name("path") {
                    pending.push(path);
                }
            }
            _ => {}
        }
    }
    components
}

fn rust_declaration_header<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    // A tuple struct's `body` is the parenthesized field list, not the
    // declaration body delimiter. Its signature still runs through the
    // terminating semicolon, while named structs, enums, traits, and unions
    // stop at their brace-delimited body. Use grammar boundaries so braces or
    // semicolons inside const expressions and types remain part of the header.
    let body_start = node
        .child_by_field_name("body")
        .filter(|body| body.kind() != "ordered_field_declaration_list")
        .map(|body| body.start_byte());
    let semicolon_start = || {
        let mut cursor = node.walk();
        node.children(&mut cursor)
            .find(|child| child.kind() == ";")
            .map(|semicolon| semicolon.start_byte())
    };
    let header_end = body_start
        .or_else(semicolon_start)
        .unwrap_or(node.end_byte());
    source
        .get(node.start_byte()..header_end)
        .expect("AST signature boundary must lie within the declaration source")
        .trim()
}

fn rust_type_signature(node: Node<'_>, source: &str) -> String {
    let header = rust_declaration_header(node, source);
    format!("{header} {{")
}

fn rust_function_signature(node: Node<'_>, source: &str) -> String {
    let header = rust_declaration_header(node, source).to_string();
    if node.kind() == "function_signature_item" {
        header
    } else {
        format!("{header} {{ ... }}")
    }
}

fn rust_impl_member_identity_signature(node: Node<'_>, source: &str) -> Option<String> {
    let impl_item = enclosing_rust_impl_item(node)?;
    let type_text = impl_item
        .child_by_field_name("type")
        .map(|node| rust_node_text(node, source).trim())?;
    let item_signature = match node.kind() {
        "function_item" | "function_signature_item" => rust_function_signature(node, source),
        "const_item" | "type_item" | "associated_type" => {
            rust_bounded_declaration_label(node, source)
        }
        _ => return None,
    };
    if let Some(trait_node) = impl_item.child_by_field_name("trait") {
        let trait_text = rust_node_text(trait_node, source).trim();
        Some(format!(
            "impl {trait_text} for {type_text}::{item_signature}"
        ))
    } else {
        Some(format!("impl {type_text}::{item_signature}"))
    }
}

fn enclosing_rust_impl_item(node: Node<'_>) -> Option<Node<'_>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if candidate.kind() == "impl_item" {
            return Some(candidate);
        }
        parent = candidate.parent();
    }
    None
}

/// The names of the type parameters `node` writes, in declaration order.
///
/// Read from the declaration's own `type_parameters` field, which every Rust
/// type declaration carries (`struct_item`, `enum_item`, `union_item`,
/// `trait_item`, `type_item`). An absent field is a declaration that writes no
/// parameter list, which is a recorded arity of zero, not an unknown one.
///
/// Lifetimes and const generics are counted with the types. Generic arity here
/// is the length of the written parameter list, which is what separates
/// `Slice<'a, T>` from `Slice`; it is not a count of the parameters that
/// happen to name types.
fn rust_declared_type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| {
            matches!(
                parameter.kind(),
                "const_parameter" | "lifetime_parameter" | "metavariable" | "type_parameter"
            )
        })
        .map(|parameter| parameter.child_by_field_name("name").unwrap_or(parameter))
        .map(|name| rust_node_text(name, source).trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

fn rust_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let dispatch = rust_callable_dispatch_extensibility(node);
    let parameters_node = node.child_by_field_name("parameters");
    let callable_is_static = !parameters_node.is_some_and(rust_parameters_have_self);
    let with_modifiers = |metadata: SignatureMetadata| {
        metadata
            .with_dispatch_extensibility(dispatch)
            .with_callable_modifiers(callable_is_static, false, DeclaredVisibility::Unknown)
    };
    let Some(parameters_node) = parameters_node else {
        return with_modifiers(SignatureMetadata::new(signature, Vec::new()));
    };
    // The rendered header is an exact, trimmed source prefix. Parameter
    // locations therefore come from their AST nodes, not an earlier matching
    // string literal or type spelling elsewhere in that header.
    let declaration_text = rust_node_text(node, source);
    let header_start =
        node.start_byte() + declaration_text.len() - declaration_text.trim_start().len();
    let parameters = rust_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = rust_node_text(label_node, source).trim();
            if label.is_empty() {
                return None;
            }
            let raw = source
                .get(label_node.byte_range())
                .expect("parameter label has an exact source range");
            let source_end = label_node.start_byte() + raw.trim_end().len();
            // Normalization only removes a leading identifier sigil and
            // surrounding whitespace, so the label is this node's suffix.
            let source_start = source_end - label.len();
            assert!(
                parameters_node.start_byte() <= source_start
                    && source_end <= parameters_node.end_byte()
            );
            let start_byte = source_start - header_start;
            let end_byte = source_end - header_start;
            assert_eq!(
                signature.get(start_byte..end_byte),
                Some(label),
                "parameter metadata must point into its rendered AST header"
            );
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    let metadata = with_modifiers(SignatureMetadata::new(signature, parameters));
    match rust_callable_parameter_type_spellings(parameters_node, source) {
        Some(parameter_types) => metadata.with_callable_parameter_types(parameter_types),
        None => metadata,
    }
}

pub(crate) fn rust_parameters_have_self(parameters: Node<'_>) -> bool {
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        parameter.kind() == "self_parameter"
            || parameter.kind() == "parameter"
                && parameter
                    .child_by_field_name("pattern")
                    .is_some_and(|pattern| pattern.kind() == "self")
    })
}

fn rust_callable_parameter_type_spellings(
    parameters: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| {
            !matches!(
                parameter.kind(),
                "attribute_item" | "attributes" | "line_comment" | "block_comment"
            )
        })
        .map(|parameter| {
            if parameter.kind() != "parameter" {
                return None;
            }
            let type_node = parameter.child_by_field_name("type")?;
            let spelling = rust_node_text(type_node, source).trim();
            (!spelling.is_empty()).then(|| spelling.to_string())
        })
        .collect()
}

fn rust_callable_dispatch_extensibility(node: Node<'_>) -> DispatchExtensibility {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        match candidate.kind() {
            "trait_item" => return DispatchExtensibility::Open,
            "impl_item" => {
                return if candidate.child_by_field_name("trait").is_some() {
                    DispatchExtensibility::Open
                } else {
                    DispatchExtensibility::Closed
                };
            }
            "function_item" | "closure_expression" | "source_file" => break,
            _ => parent = candidate.parent(),
        }
    }
    DispatchExtensibility::Closed
}

#[cfg(test)]
mod structured_package_tests {
    use super::*;

    #[test]
    fn attributed_impl_members_retain_identity_and_test_scope() {
        let source = r#"
pub struct Number { value: String }
impl Number {
    #[cfg(feature = "precision")]
    #[cfg_attr(docsrs, doc(cfg(feature = "precision")))]
    pub fn as_str(&self) -> &str { &self.value }
    pub fn ordinary(&self) -> &str { &self.value }
    #[cfg(test)]
    fn test_helper(&self) {}
    #[allow(dead_code)]
    const LIMIT: usize = 8;
}
trait View { type Item; fn view(&self) -> &str; }
impl View for Number {
    #[allow(dead_code)]
    type Item = String;
    #[inline]
    fn view(&self) -> &str { &self.value }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().canonicalize().unwrap(), "lib.rs");
        let parsed = parse_rust_file(&file, source, &tree);
        let owner = parsed
            .declarations()
            .iter()
            .find(|unit| unit.short_name() == "Number")
            .unwrap();
        for (name, kind, test_region) in [
            ("as_str", CodeUnitType::Function, false),
            ("ordinary", CodeUnitType::Function, false),
            ("test_helper", CodeUnitType::Function, true),
            ("LIMIT", CodeUnitType::Field, false),
            ("Item", CodeUnitType::Class, false),
            ("view", CodeUnitType::Function, false),
        ] {
            let member = parsed.children[owner]
                .iter()
                .find(|unit| unit.identifier() == name)
                .unwrap_or_else(|| panic!("missing {name}: {:?}", parsed.children[owner]));
            assert_eq!(member.kind(), kind, "{member:?}");
            assert_eq!(
                parsed.test_region_units.contains(member),
                test_region,
                "{member:?}"
            );
            assert!(!parsed.ranges[member].is_empty(), "{member:?}");
        }
        assert!(!parsed.test_region_units.contains(owner));
    }

    #[test]
    fn procedural_macro_kinds_preserve_declaration_identifiers() {
        let source = r#"
#[proc_macro]
// A comment does not detach the outer attribute from its item.
pub fn bang(input: TokenStream) -> TokenStream { input }
#[proc_macro_attribute]
// Attribute macros also export the function identifier.
pub fn decorate(args: TokenStream, input: TokenStream) -> TokenStream { input }
#[proc_macro_derive(Derived)]
pub fn derive_impl(input: TokenStream) -> TokenStream { input }
pub fn plain() {}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().canonicalize().unwrap(), "lib.rs");
        let parsed = parse_rust_file(&file, source, &tree);
        for (name, kind) in [
            ("bang", CodeUnitType::Macro),
            ("decorate", CodeUnitType::Macro),
            ("derive_impl", CodeUnitType::Function),
            ("plain", CodeUnitType::Function),
        ] {
            let unit = parsed
                .top_level_declarations
                .iter()
                .find(|unit| unit.identifier() == name)
                .expect("declaration");
            assert_eq!(unit.kind(), kind, "{unit:?}");
        }
    }

    #[test]
    fn hidden_directory_is_one_structured_rust_package_segment() {
        let source = "pub struct Pattern;\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            ".github/workflows/generate-release-yml.rs",
        );

        let parsed = parse_rust_file(&file, source, &tree);
        let pattern = parsed
            .top_level_declarations
            .iter()
            .find(|unit| unit.identifier() == "Pattern")
            .expect("Pattern declaration");

        assert_eq!(pattern.package_name(), ".github.workflows");
        assert_eq!(pattern.fq_name(), ".github.workflows.Pattern");
        assert_eq!(pattern.package_segment_count(), 2);
        assert_eq!(
            pattern.fq_segments_debug(),
            vec![
                ("Package", ".github".to_string()),
                ("Package", "workflows".to_string()),
                ("Type", "Pattern".to_string()),
            ]
        );
    }

    #[test]
    fn coordinated_import_events_preserve_module_order_and_local_usage_scope() {
        let source = "\
use crate::root::Top;
mod nested {
    use crate::nested::Nested;
    fn local() {
        use crate::local::Local;
    }
}
use crate::root::After;
";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );

        let parsed = parse_rust_file(&file, source, &tree);
        let imports = parsed
            .imports
            .iter()
            .map(|import| import.raw_snippet.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            imports,
            vec![
                "use crate::root::Top;",
                "use crate::nested::Nested;",
                "use crate::root::After;",
            ]
        );

        let usage = &parsed.rust_usage_facts;
        let targets = usage
            .import_targets
            .iter()
            .map(|target| {
                (
                    target.module_path.join("::"),
                    target.imported_name.clone(),
                    target.owner_module.clone(),
                    target.local_extent.is_some(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            targets,
            vec![
                (
                    "crate::root".to_string(),
                    Some("Top".to_string()),
                    "".to_string(),
                    false,
                ),
                (
                    "crate::nested".to_string(),
                    Some("Nested".to_string()),
                    "nested".to_string(),
                    false,
                ),
                (
                    "crate::local".to_string(),
                    Some("Local".to_string()),
                    "nested".to_string(),
                    true,
                ),
                (
                    "crate::root".to_string(),
                    Some("After".to_string()),
                    "".to_string(),
                    false,
                ),
            ]
        );
        let source_facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical source facts");
        assert_eq!(source_facts.rust_import_contexts.len(), 4);
        assert!(source_facts.rust_import_contexts[0].owner_scope.is_none());
        assert_eq!(source_facts.rust_import_contexts[1].owner_module, "nested");
        assert!(source_facts.rust_import_contexts[1].owner_scope.is_some());
        assert_eq!(
            source_facts.rust_import_contexts[1].owner_scope,
            source_facts.rust_import_contexts[2].owner_scope,
            "the nested module body is shared by its module and local imports"
        );
        assert!(source_facts.rust_import_contexts[2].local_scope.is_some());
        assert!(source_facts.rust_import_contexts[3].owner_scope.is_none());
    }

    #[test]
    fn empty_use_projection_does_not_create_rust_import_context() {
        let source = "use crate::empty::{};\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );

        let parsed = parse_rust_file(&file, source, &tree);
        let source_facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical source facts");
        assert!(source_facts.imports.is_empty());
        assert!(source_facts.rust_import_contexts.is_empty());
    }

    #[test]
    fn single_name_imports_retain_native_binder_scopes() {
        let source = "pub use First as Second; fn f() { use Second as Third; }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().canonicalize().unwrap(), "src/lib.rs");
        let parsed = parse_rust_file(&file, source, &tree);
        let imports = &parsed.rust_usage_facts.import_targets;
        assert_eq!(imports.len(), 2);
        assert!(
            imports.iter().all(|import| import.native_scope.is_some()),
            "{imports:?}"
        );
        assert_ne!(imports[0].native_scope, imports[1].native_scope);
        assert!(imports.iter().all(|import| import.module_path.is_empty()));
    }

    #[test]
    fn rust_import_context_preserves_module_and_enclosing_local_scopes() {
        let source = "fn wrapper() { mod nested { use crate::Thing; } }\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );

        let parsed = parse_rust_file(&file, source, &tree);
        let source_facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical source facts");
        let context = source_facts
            .rust_import_contexts
            .first()
            .expect("nested local import context");
        assert_eq!(context.owner_module, "nested");
        assert!(context.owner_scope.is_some());
        assert!(context.local_scope.is_some());
        assert_ne!(context.owner_scope, context.local_scope);
    }

    #[test]
    fn coordinated_imports_publish_exact_shared_source_occurrences() {
        let source = "use crate::model::{Thing as Local, lower, *};\nextern crate ext as external;\nfn local() {\n    use crate::local::Item as LocalItem;\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let second_tree = parser.parse(source, None).expect("parse identical fixture");
        let first_root = tempfile::tempdir().expect("first tempdir");
        let second_root = tempfile::tempdir().expect("second tempdir");
        let first_file = ProjectFile::new(
            first_root.path().canonicalize().expect("first root"),
            "src/lib.rs",
        );
        let second_file = ProjectFile::new(
            second_root.path().canonicalize().expect("second root"),
            "src/lib.rs",
        );

        let first = parse_rust_file(&first_file, source, &tree);
        let second = parse_rust_file(&second_file, source, &second_tree);
        assert_eq!(
            first.rust_usage_facts.import_targets, second.rust_usage_facts.import_targets,
            "identical bytes keep source identity indexes mount-independent"
        );
        assert_eq!(
            first
                .source_facts
                .as_ref()
                .expect("first source facts")
                .occurrences,
            second
                .source_facts
                .as_ref()
                .expect("second source facts")
                .occurrences
        );

        let source_facts = &first
            .source_facts
            .as_ref()
            .expect("canonical source facts")
            .occurrences;
        let source_imports = &first
            .source_facts
            .as_ref()
            .expect("canonical source facts")
            .imports;
        let generic_imports = &first
            .source_facts
            .as_ref()
            .expect("canonical source facts")
            .generic_imports;
        let targets = &first.rust_usage_facts.import_targets;
        assert_eq!(targets.len(), 5);
        assert_eq!(first.imports.len(), 4);
        assert_eq!(generic_imports.len(), first.imports.len());
        assert_eq!(source_imports.len(), targets.len());
        assert_eq!(
            targets
                .iter()
                .map(|target| target.source_import_id)
                .collect::<Vec<_>>(),
            (0..targets.len())
                .map(|index| {
                    Some(SourceImportId::try_from_index(index).expect("test import identity fits"))
                })
                .collect::<Vec<_>>(),
            "every primary import leaf receives one shared source identity"
        );
        assert_eq!(
            generic_imports,
            &[
                SourceImportId::new(0),
                SourceImportId::new(1),
                SourceImportId::new(2),
                SourceImportId::new(3),
            ],
            "generic projection excludes only the local-only primary leaf"
        );
        assert_eq!(
            generic_imports
                .iter()
                .map(|source_import_id| source_imports[source_import_id.index()]
                    .import_info(source_facts))
                .collect::<Vec<_>>(),
            first.imports,
            "generic DTOs materialize from canonical source import records"
        );
        let grouped_declaration = targets[0]
            .source_occurrences
            .expect("grouped target source occurrences")
            .declaration;
        let import_contexts = &first
            .source_facts
            .as_ref()
            .expect("canonical source facts")
            .rust_import_contexts;
        assert_eq!(import_contexts.len(), 3);
        assert_eq!(import_contexts[0].declaration, grouped_declaration);
        assert_eq!(import_contexts[0].owner_module, "");
        assert!(import_contexts[0].owner_scope.is_none());
        assert!(import_contexts[0].local_scope.is_none());
        assert_eq!(
            import_contexts[1].declaration,
            targets[3]
                .source_occurrences
                .expect("extern crate source occurrences")
                .declaration
        );
        assert_eq!(
            import_contexts[2].declaration,
            targets[4]
                .source_occurrences
                .expect("local import source occurrences")
                .declaration
        );
        assert!(import_contexts[2].local_scope.is_some());
        assert!(
            import_contexts
                .iter()
                .all(|context| context.owner_module.is_empty())
        );
        assert_eq!(
            targets[1]
                .source_occurrences
                .expect("grouped lower source occurrences")
                .declaration,
            grouped_declaration
        );
        assert_eq!(
            targets[2]
                .source_occurrences
                .expect("grouped glob source occurrences")
                .declaration,
            grouped_declaration
        );
        assert_eq!(
            source_facts.occurrence(grouped_declaration).range,
            Range {
                start_byte: 0,
                end_byte: 45,
                start_line: 1,
                end_line: 1,
            }
        );
        let grouped = targets[0]
            .source_occurrences
            .expect("grouped alias source occurrences");
        assert_eq!(
            source_facts
                .occurrence(grouped.target.expect("Thing target"))
                .range,
            Range {
                start_byte: 19,
                end_byte: 24,
                start_line: 1,
                end_line: 1,
            }
        );
        assert_eq!(
            source_facts
                .occurrence(grouped.alias.expect("Local alias"))
                .range,
            Range {
                start_byte: 28,
                end_byte: 33,
                start_line: 1,
                end_line: 1,
            }
        );
        assert!(
            targets[2]
                .source_occurrences
                .expect("grouped glob source occurrences")
                .target
                .is_none()
        );
        assert_eq!(
            source_imports[generic_imports[0].index()].declaration,
            grouped_declaration,
            "grouped aliases share their producer-linked declaration"
        );
        assert_eq!(
            source_imports[generic_imports[1].index()].declaration,
            grouped_declaration,
            "grouped named leaves retain generic import order"
        );
        assert_eq!(
            source_imports[generic_imports[2].index()].declaration,
            grouped_declaration,
            "grouped globs retain generic import order"
        );
        assert_eq!(
            source_imports[generic_imports[0].index()]
                .alias_occurrence
                .or(source_imports[generic_imports[0].index()].target),
            Some(grouped.alias.expect("grouped alias")),
            "an aliased import binds its alias occurrence"
        );
        assert_eq!(
            source_imports[generic_imports[1].index()]
                .alias_occurrence
                .or(source_imports[generic_imports[1].index()].target),
            Some(
                targets[1]
                    .source_occurrences
                    .expect("grouped lower source occurrences")
                    .target
                    .expect("grouped lower target"),
            ),
            "an unaliased import binds its target occurrence"
        );
        assert_eq!(
            source_imports[generic_imports[2].index()]
                .alias_occurrence
                .or(source_imports[generic_imports[2].index()].target),
            None,
            "a wildcard has no binder occurrence"
        );

        let external = targets[3]
            .source_occurrences
            .expect("extern crate source occurrences");
        assert_eq!(
            source_facts.occurrence(external.declaration).range,
            Range {
                start_byte: 46,
                end_byte: 75,
                start_line: 2,
                end_line: 2,
            }
        );
        assert_eq!(
            source_imports[generic_imports[3].index()].declaration,
            external.declaration
        );
        assert_eq!(
            source_imports[generic_imports[3].index()]
                .alias_occurrence
                .or(source_imports[generic_imports[3].index()].target),
            Some(external.alias.expect("extern alias"))
        );
        assert!(
            generic_imports.iter().all(|source_import_id| source_facts
                .occurrence(source_imports[source_import_id.index()].declaration)
                .range
                .start_byte
                != 93),
            "local-only imports are excluded from generic import occurrences"
        );
        assert_eq!(
            source_facts
                .occurrence(external.target.expect("extern target"))
                .range,
            Range {
                start_byte: 59,
                end_byte: 62,
                start_line: 2,
                end_line: 2,
            }
        );
        assert_eq!(
            source_facts
                .occurrence(external.alias.expect("extern alias"))
                .range,
            Range {
                start_byte: 66,
                end_byte: 74,
                start_line: 2,
                end_line: 2,
            }
        );

        let local = targets[4]
            .source_occurrences
            .expect("local import source occurrences");
        assert_eq!(
            source_facts.occurrence(local.declaration).range,
            Range {
                start_byte: 93,
                end_byte: 129,
                start_line: 4,
                end_line: 4,
            }
        );
        assert_eq!(
            source_facts
                .occurrence(local.target.expect("local target"))
                .range,
            Range {
                start_byte: 111,
                end_byte: 115,
                start_line: 4,
                end_line: 4,
            }
        );
        assert_eq!(
            source_facts
                .occurrence(local.alias.expect("local alias"))
                .range,
            Range {
                start_byte: 119,
                end_byte: 128,
                start_line: 4,
                end_line: 4,
            }
        );
    }

    #[test]
    fn coordinated_import_events_keep_macro_imports_after_primary_imports() {
        let source = r#"
macro_rules! replay { ($($item:item)*) => { $($item)* }; }
use crate::primary::Primary;
replay! {
    use crate::generated::Generated;
    pub fn generated() {}
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );

        let parsed = parse_rust_file(&file, source, &tree);
        let imports = parsed
            .imports
            .iter()
            .map(|import| import.raw_snippet.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            imports,
            vec![
                "use crate::primary::Primary;",
                "use crate::generated::Generated;",
            ]
        );
        let source_facts = parsed.source_facts.as_ref().expect("source facts");
        assert_eq!(source_facts.generic_imports.len(), imports.len());
        assert_eq!(
            source_facts.rust_import_contexts.len(),
            1,
            "embedded macro imports do not acquire primary Rust contexts"
        );
        let primary = source_facts.imports[source_facts.generic_imports[0].index()].declaration;
        let generated = source_facts.imports[source_facts.generic_imports[1].index()].declaration;
        assert_ne!(
            primary, generated,
            "embedded imports get fresh occurrence ids"
        );
        assert_eq!(
            source_facts.occurrences.occurrence(generated).provenance,
            brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
        );
        assert_ne!(
            source_facts.occurrences.occurrence(primary).provenance,
            brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
        );
    }

    #[test]
    fn forward_impl_owner_uses_later_alias_from_shared_projection() {
        let source = concat!(
            "pub struct Owner;\n",
            "impl ImportedOwner { fn method(&self) {} }\n",
            "use crate::Owner as ImportedOwner;\n",
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );

        let parsed = parse_rust_file(&file, source, &tree);
        let method = parsed
            .children
            .values()
            .flatten()
            .find(|unit| unit.identifier() == "method")
            .expect("forward impl method is indexed");
        assert_eq!(method.owner_identifier(), Some("Owner"));
    }

    #[test]
    fn callable_metadata_records_rust_self_parameter_structurally() {
        let source = "pub fn free(value: i32) {}\n\nstruct Thing;\nimpl Thing {\n    fn method(&self, value: i32) {}\n    fn typed(self: Box<Self>) {}\n    fn associated(value: i32) {}\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);

        let metadata_for = |name: &str| {
            parsed
                .signature_metadata
                .iter()
                .find(|(unit, _)| unit.identifier() == name)
                .and_then(|(_, metadata)| metadata.first())
                .unwrap_or_else(|| panic!("missing Rust callable {name}"))
        };
        let free = metadata_for("free");
        assert!(free.callable_modifiers_recorded());
        assert!(free.callable_is_static());
        assert!(!free.callable_is_constructor());

        let method = metadata_for("method");
        assert!(method.callable_modifiers_recorded());
        assert!(!method.callable_is_static());

        let typed = metadata_for("typed");
        assert!(typed.callable_modifiers_recorded());
        assert!(!typed.callable_is_static());

        let associated = metadata_for("associated");
        assert!(associated.callable_modifiers_recorded());
        assert!(associated.callable_is_static());
    }

    #[test]
    fn parameter_metadata_uses_ast_offsets_after_repeated_header_text() {
        let source = r#"
// The parameter text also occurs before the real parameter list.
fn repeated<T: Marker<{ "(r#type: u8, other: u8)".len() }>>(r#type: u8, other: u8) {}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser.parse(source, None).expect("parse signature fixture");
        assert!(
            !tree.root_node().has_error(),
            "signature fixture must parse cleanly"
        );
        let function = tree
            .root_node()
            .named_children(&mut tree.root_node().walk())
            .find(|node| node.kind() == "function_item")
            .expect("function declaration");
        let parameters = function
            .child_by_field_name("parameters")
            .expect("parameter list");
        let first_name = parameters
            .named_child(0)
            .expect("first parameter")
            .child_by_field_name("pattern")
            .expect("parameter pattern");
        let second_name = parameters
            .named_child(1)
            .expect("second parameter")
            .child_by_field_name("pattern")
            .expect("parameter pattern");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let metadata = parsed
            .signature_metadata
            .iter()
            .find(|(unit, _)| unit.identifier() == "repeated")
            .and_then(|(_, signatures)| signatures.first())
            .expect("function metadata");
        assert_eq!(metadata.parameters().len(), 2);
        for (parameter, name, label, sigil_bytes) in [
            (&metadata.parameters()[0], first_name, "type", 2),
            (&metadata.parameters()[1], second_name, "other", 0),
        ] {
            assert_eq!(parameter.label(), label);
            assert_eq!(
                parameter.start_byte(),
                name.start_byte() + sigil_bytes - function.start_byte()
            );
            assert_eq!(
                parameter.end_byte(),
                name.end_byte() - function.start_byte()
            );
            assert_eq!(
                &metadata.label()[parameter.start_byte()..parameter.end_byte()],
                label
            );
        }
    }

    #[test]
    fn signatures_stop_at_ast_bodies_not_header_braces_or_semicolons() {
        let source = r#"
struct Tuple<const N: usize>([u8; { N }]);
struct Named<const N: usize> where [(); { N }]: Sized { value: [u8; { N }] }
struct Unit<const N: usize>;
enum Enum<const N: usize> { Variant([u8; { N }]) }
union Union<const N: usize> { value: [u8; { N }] }
fn compute<const N: usize>(value: [u8; { N }]) -> [u8; { N }] where [(); { N }]: Sized { value }
trait Api<const N: usize> { fn signature(value: [u8; { N }]) -> [u8; { N }] where [(); { N }]: Sized; }
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let root = tree.root_node();
        assert!(
            !root.has_error(),
            "signature fixture must parse without errors: {}",
            root.to_sexp()
        );

        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let signature_for = |name: &str| {
            parsed
                .signatures
                .iter()
                .find(|(unit, _)| unit.identifier() == name)
                .and_then(|(_, signatures)| signatures.first())
                .map(String::as_str)
                .unwrap_or_else(|| panic!("missing signature for {name}"))
        };

        assert_eq!(
            signature_for("Tuple"),
            "struct Tuple<const N: usize>([u8; { N }]) {"
        );
        assert_eq!(
            signature_for("Named"),
            "struct Named<const N: usize> where [(); { N }]: Sized {"
        );
        assert_eq!(signature_for("Unit"), "struct Unit<const N: usize> {");
        assert_eq!(signature_for("Enum"), "enum Enum<const N: usize> {");
        assert_eq!(signature_for("Union"), "union Union<const N: usize> {");
        assert_eq!(
            signature_for("compute"),
            "fn compute<const N: usize>(value: [u8; { N }]) -> [u8; { N }] where [(); { N }]: Sized { ... }"
        );
        assert_eq!(signature_for("Api"), "trait Api<const N: usize> {");
        assert_eq!(
            signature_for("signature"),
            "fn signature(value: [u8; { N }]) -> [u8; { N }] where [(); { N }]: Sized"
        );
    }

    #[test]
    fn native_definition_crosswalk_selects_the_declaration_not_same_named_parameter() {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        let source = "pub fn same(same: i32) -> i32 { same }\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let names = parsed
            .resolution_facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let same_declarations = parsed
            .resolution_facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && names[&identifier.name] == "same"
            })
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        assert_eq!(same_declarations.len(), 2);
        assert_eq!(parsed.resolution_facts.definition_units.len(), 1);
        let crosswalk = &parsed.resolution_facts.definition_units[0];
        assert_eq!(crosswalk.declaration, same_declarations[0]);
        assert_eq!(crosswalk.unit.identifier(), "same");
        assert!(crosswalk.unit.is_function());
    }

    #[test]
    fn native_definition_crosswalk_keeps_multiple_inherent_methods_exact() {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionIdentifierRole, ResolutionSiteKind,
        };

        let source = concat!(
            "pub struct Service;\n",
            "impl Service { fn first(&self) {} }\n",
            "impl Service { fn second(self: Box<Self>) {} }\n",
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let names = parsed
            .resolution_facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let methods = parsed
            .resolution_facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && parsed.resolution_facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::CallableDeclaration
                    && matches!(names[&identifier.name], "first" | "second")
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 2);
        for method in methods {
            let crosswalk = parsed
                .resolution_facts
                .definition_units
                .iter()
                .find(|crosswalk| crosswalk.declaration == method.site)
                .expect("inherent method has an exact parser crosswalk");
            assert_eq!(crosswalk.unit.identifier(), names[&method.name]);
            assert!(crosswalk.unit.is_function());
        }
    }

    #[test]
    fn native_definition_crosswalk_selects_one_repeated_parser_unit_identity() {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        let source = concat!(
            "macro_rules! repeated { () => {} }\n",
            "macro_rules! repeated { ($value:expr) => {} }\n",
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let names = parsed
            .resolution_facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let repeated_declarations = parsed
            .resolution_facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && names[&identifier.name] == "repeated"
            })
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        assert_eq!(repeated_declarations.len(), 2);

        let repeated_crosswalks = parsed
            .resolution_facts
            .definition_units
            .iter()
            .filter(|crosswalk| crosswalk.unit.identifier() == "repeated")
            .collect::<Vec<_>>();
        assert_eq!(repeated_crosswalks.len(), 1);
        assert_eq!(repeated_crosswalks[0].declaration, repeated_declarations[0]);
        assert!(repeated_crosswalks[0].unit.is_macro());
    }

    #[test]
    fn native_definition_crosswalk_includes_top_level_constants_and_statics() {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        let source = "pub const EXPORTED: usize = 1;\nstatic LOCAL: usize = 2;\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let names = parsed
            .resolution_facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();

        for name in ["EXPORTED", "LOCAL"] {
            let declaration = parsed
                .resolution_facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && names[&identifier.name] == name
                })
                .unwrap_or_else(|| panic!("missing {name} declaration"));
            let crosswalk = parsed
                .resolution_facts
                .definition_units
                .iter()
                .find(|crosswalk| crosswalk.declaration == declaration.site)
                .unwrap_or_else(|| panic!("missing {name} definition crosswalk"));
            assert_eq!(crosswalk.unit.identifier(), name);
            assert!(crosswalk.unit.is_field());
        }
    }

    #[test]
    fn union_declarations_are_indexed_and_crosswalked_at_module_depths() {
        let source = concat!(
            "pub union Root { word: u32, bytes: [u8; 4] }\n",
            "mod nested { pub union Inner { word: u32, bytes: [u8; 4] } }\n",
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let mut indexed_unions = parsed
            .top_level_declarations
            .iter()
            .chain(parsed.children.values().flatten())
            .filter(|unit| matches!(unit.identifier(), "Root" | "Inner"))
            .map(CodeUnit::identifier)
            .collect::<Vec<_>>();
        indexed_unions.sort_unstable();
        assert_eq!(indexed_unions, ["Inner", "Root"]);

        let mut crosswalked_unions = parsed
            .resolution_facts
            .definition_units
            .iter()
            .filter(|crosswalk| matches!(crosswalk.unit.identifier(), "Root" | "Inner"))
            .map(|crosswalk| crosswalk.unit.identifier())
            .collect::<Vec<_>>();
        crosswalked_unions.sort_unstable();
        assert_eq!(crosswalked_unions, ["Inner", "Root"]);
    }
}

fn rust_parameter_label_nodes(parameters_node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = parameters_node.walk();
    parameters_node
        .named_children(&mut cursor)
        .filter_map(rust_parameter_label_node)
        .collect()
}

pub(crate) fn rust_parameter_label_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "parameter" => parameter
            .child_by_field_name("pattern")
            .map(|pattern| rust_parameter_pattern_label_node(pattern).unwrap_or(pattern)),
        "self_parameter" => Some(parameter),
        _ => None,
    }
}

fn rust_parameter_pattern_label_node(pattern: Node<'_>) -> Option<Node<'_>> {
    let mut pending = vec![pattern];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "identifier" => return Some(node),
            "mut_pattern" | "ref_pattern" => {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                pending.extend(children.into_iter().rev());
            }
            _ => {}
        }
    }
    None
}

fn rust_macro_signature(node: Node<'_>, source: &str) -> String {
    rust_node_text(node, source)
        .lines()
        .find(|line| line.contains("macro_rules!"))
        .map(str::trim)
        .unwrap_or("macro_rules!")
        .to_string()
}

/// Every type identifier named anywhere in `source`, parsed standalone rather
/// than read off an indexed file: callers pass ad hoc snippets that the
/// analyzer has never seen.
pub fn rust_type_identifiers(source: &str) -> BTreeSet<String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("failed to load rust parser");
    let Some(tree) = parser.parse(source, None) else {
        return BTreeSet::new();
    };
    let mut identifiers = HashSet::default();
    walk_rust_primary_tree(
        tree.root_node(),
        &mut identifiers,
        |node, _, _, identifiers| {
            collect_rust_type_identifier(node, source, identifiers);
            (true, TreeWalkAction::Skip)
        },
        |_, _| {},
    );
    identifiers.into_iter().collect()
}

fn collect_rust_type_identifier(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => {
            let text = rust_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod embedded_replay_tests {
    use super::*;

    fn parse_fixture(source: &str) -> ParsedFile {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        parse_rust_file(&file, source, &tree)
    }

    #[test]
    fn repeated_macro_closure_bindings_keep_their_own_source_occurrences() {
        let source = "macro_rules! apply { ($f:expr) => { $f }; }\nfn test() { apply!(|a| a); apply!(|a| a); }\n";
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().unwrap();
        let parameters = facts
            .occurrences
            .lexical_declarations()
            .iter()
            .filter(|fact| fact.kind == DeclarationKind::Parameter && fact.identifier == "a")
            .map(|fact| {
                let declaration = facts.occurrences.declaration(fact.declaration);
                (
                    facts.occurrences.occurrence(declaration.occurrence).range,
                    facts
                        .occurrences
                        .occurrence(declaration.name.unwrap())
                        .range,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(parameters.len(), 2, "{parameters:?}");
        for (declaration, name) in &parameters {
            assert_eq!(declaration, name);
            assert_eq!(&source[name.start_byte..name.end_byte], "a");
        }
        assert_ne!(parameters[0].1.start_byte, parameters[1].1.start_byte);
    }

    #[test]
    fn impl_owner_construction_retains_exact_type_syntax_and_unsupported_evidence() {
        use brokk_bifrost_core::analyzer::rust_facts::RustTypeSourceShape;

        let source = r#"
struct Item;
trait Trait {}
impl Item { fn plain() {} }
impl Trait for Missing { fn external() {} }
impl (Item, Item) { fn unsupported() {} }
impl Outer<Item>::Assoc { fn fabricated() {} }
wrap! { impl Item { fn embedded_a() {} } }
wrap! { impl Item { fn embedded_b() {} } }
"#;
        let parsed = parse_fixture(source);
        let facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical source facts");
        // Seven impl-head types plus the exact Item argument in Outer<Item>.
        assert_eq!(facts.rust_types.len(), 8);
        let written = |fact: &RustTypeSourceFact| {
            let range = facts.occurrences.occurrence(fact.occurrence).range;
            &source[range.start_byte..range.end_byte]
        };
        let tuple = facts
            .rust_types
            .iter()
            .find(|fact| written(fact) == "(Item, Item)")
            .expect("unsupported tuple impl retains its target");
        assert!(
            matches!(&tuple.shape, RustTypeSourceShape::Unsupported { syntax_kind, .. }
            if syntax_kind == "tuple_type")
        );
        let qualified = facts
            .rust_types
            .iter()
            .find(|fact| written(fact) == "Outer<Item>::Assoc")
            .expect("generic qualifier retains its complete target");
        assert!(crate::type_syntax::declaration_owner_path(qualified).is_none());
        assert!(facts.rust_types.iter().any(|fact| written(fact) == "Trait"));
        assert!(
            facts
                .rust_types
                .iter()
                .any(|fact| written(fact) == "Missing")
        );
        let embedded: Vec<_> = facts
            .rust_types
            .iter()
            .filter(|fact| {
                facts.occurrences.occurrence(fact.occurrence).provenance
                    == SourceOccurrenceProvenance::Embedded
            })
            .collect();
        assert_eq!(embedded.len(), 2);
        assert_ne!(embedded[0].occurrence, embedded[1].occurrence);
        assert!(embedded.iter().all(|fact| written(fact) == "Item"));
        let has_member = |name| {
            parsed
                .signatures
                .keys()
                .any(|unit| unit.identifier() == name)
        };
        for name in ["plain", "external", "embedded_a", "embedded_b"] {
            assert!(has_member(name), "supported owner retains member {name}");
        }
        assert!(!has_member("unsupported"));
        assert!(
            !has_member("fabricated"),
            "a generic qualifier must not invent an Assoc owner"
        );
    }

    #[test]
    fn primary_item_sources_retain_unprojected_owners_and_exact_member_contexts() {
        let source = r#"
struct Item;
trait Trait {
    type Required;
    type Defaulted = Item;
    fn required(&self, r#type: u8);
    trait_members! {}
}
impl Trait for Missing {
    fn member(&self) {
        fn local() { impl Item { fn nested() {} } }
    }
    impl_members! {}
}
impl<T> Trait for T { fn generic(&self) {} }
fn outer() {
    type Local = Item;
    impl (Item, Item) { fn hidden() {} }
}
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let items = &facts.rust_items;
        let text = |occurrence| {
            let range = facts.occurrences.occurrence(occurrence).range;
            &source[range.start_byte..range.end_byte]
        };
        let name = |declaration| facts.occurrences.declaration(declaration).name.map(text);
        assert_eq!(items.impls.len(), 4, "capture precedes display admission");
        for implementation in &items.impls {
            assert_eq!(
                facts
                    .occurrences
                    .declaration(implementation.declaration)
                    .name,
                None
            );
            for target in [implementation.trait_type, implementation.target_type]
                .into_iter()
                .flatten()
            {
                assert_eq!(
                    facts
                        .rust_types
                        .iter()
                        .filter(|fact| fact.occurrence == target)
                        .count(),
                    1
                );
            }
        }
        let missing = items
            .impls
            .iter()
            .find(|item| item.target_type.map(text) == Some("Missing"))
            .expect("unresolved impl retains its exact target");
        assert_eq!(missing.trait_type.map(text), Some("Trait"));
        let direct_names: Vec<_> = missing
            .body_children
            .iter()
            .filter_map(|child| child.declaration.and_then(name))
            .collect();
        assert_eq!(
            direct_names,
            ["member"],
            "nested declarations are not direct members"
        );
        assert!(
            missing
                .body_children
                .iter()
                .any(|child| child.syntax_kind == "macro_invocation")
        );
        let hidden = items
            .callables
            .iter()
            .find(|item| name(item.declaration) == Some("hidden"))
            .expect("unprojectable impl member still has source identity");
        assert!(
            !parsed
                .source_declaration_units
                .iter()
                .any(|(id, _)| *id == hidden.declaration)
        );
        assert!(
            !parsed
                .signatures
                .keys()
                .any(|unit| unit.identifier() == "hidden")
        );
        let nested = items
            .impls
            .iter()
            .find(|item| item.target_type.map(text) == Some("Item"))
            .expect("impl nested inside an unprojected local function");
        let mut context = Some(nested.context);
        let mut owners = Vec::new();
        let mut seen = HashSet::default();
        while let Some(id) = context {
            assert!(seen.insert(id), "source contexts are acyclic");
            let fact = items
                .contexts
                .iter()
                .find(|fact| fact.context == id)
                .expect("linked context exists");
            if let Some(owner) = fact.owner.and_then(name) {
                owners.push(owner);
            }
            context = fact.parent;
        }
        assert!(owners.contains(&"local"));
        assert!(owners.contains(&"member"));
        let required_alias = items
            .aliases
            .iter()
            .find(|item| name(item.declaration) == Some("Required"))
            .expect("associated type declaration");
        assert_eq!(
            required_alias.target_type, None,
            "required associated type has no default"
        );
        for alias_name in ["Defaulted", "Local"] {
            let alias = items
                .aliases
                .iter()
                .find(|item| name(item.declaration) == Some(alias_name))
                .expect("alias source row");
            assert_eq!(alias.target_type.map(text), Some("Item"));
        }
        let required = items
            .callables
            .iter()
            .find(|item| name(item.declaration) == Some("required"))
            .expect("trait signature source row");
        let labels: Vec<_> = required
            .parameter_children
            .iter()
            .filter_map(|parameter| parameter.label.as_ref())
            .collect();
        assert_eq!(
            labels
                .iter()
                .map(|label| label.name.as_str())
                .collect::<Vec<_>>(),
            ["&self", "type"]
        );
        assert_eq!(
            text(labels[1].occurrence),
            "r#type",
            "normalization does not replace token identity"
        );
        let trait_item = items
            .traits
            .iter()
            .find(|item| name(item.declaration) == Some("Trait"))
            .expect("trait inventory");
        assert!(
            trait_item
                .body_children
                .iter()
                .any(|child| child.declaration == Some(required.declaration))
        );
        let blanket = items
            .impls
            .iter()
            .find(|item| item.target_type.map(text) == Some("T"))
            .expect("generic impl");
        let blanket_generics = items
            .generics
            .iter()
            .find(|generic| generic.declaration == blanket.declaration)
            .expect("generic impl parameters");
        assert_eq!(
            blanket_generics
                .parameters
                .iter()
                .filter_map(|parameter| parameter.name.as_ref())
                .map(|name| name.name.as_str())
                .collect::<Vec<_>>(),
            ["T"],
            "the exact generic name, not only its presence, is blanket-impl evidence"
        );
    }

    #[test]
    fn import_source_contexts_cover_raw_trees_without_expanding_projections() {
        let source = r#"
use crate::Top;
fn local() { use crate::Local; }
wrap! {
    impl Alias { fn forward_root() {} }
    use crate::{First as Alias, Other};
    use crate::Second as Alias;
    mod inside {
        impl Nested { fn forward_module() {} }
        use crate::Thing as Nested;
        extern crate dep as renamed;
        inner! { use crate::Deep; }
    }
}
helper::wrap! { use crate::{Hidden, HiddenOther}; extern crate rejected; }
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let contexts: HashMap<_, _> = facts
            .rust_items
            .contexts
            .iter()
            .map(|row| (row.context, row))
            .collect();
        let import_contexts: HashMap<_, _> = facts
            .rust_items
            .import_contexts
            .iter()
            .map(|row| (row.declaration, row.context))
            .collect();
        assert_eq!(import_contexts.len(), 9);
        assert_eq!(
            import_contexts.len(),
            facts.rust_items.import_contexts.len()
        );
        assert_eq!(facts.imports.len(), 11);
        let text = |occurrence| {
            let range = facts.occurrences.occurrence(occurrence).range;
            &source[range.start_byte..range.end_byte]
        };
        for import in &facts.imports {
            let context = import_contexts[&import.declaration];
            assert!(contexts.contains_key(&context));
            let declaration = facts.occurrences.occurrence(import.declaration);
            for occurrence in import.target.iter().chain(import.alias_occurrence.iter()) {
                let token = facts.occurrences.occurrence(*occurrence);
                assert_eq!(token.provenance, declaration.provenance);
                assert!(declaration.range.start_byte <= token.range.start_byte);
                assert!(token.range.end_byte <= declaration.range.end_byte);
            }
        }
        let generic: Vec<_> = facts
            .generic_imports
            .iter()
            .map(|id| facts.imports[id.index()].identifier.as_deref())
            .collect();
        assert_eq!(
            generic,
            [
                Some("Top"),
                Some("First"),
                Some("Other"),
                Some("Second"),
                Some("Deep")
            ]
        );
        assert_eq!(parsed.imports.len(), generic.len());
        assert_eq!(
            parsed.rust_usage_facts.import_targets.len(),
            2,
            "raw import capture cannot grant primary native target membership"
        );
        assert_eq!(
            facts.rust_import_contexts.len(),
            2,
            "primary target ownership remains distinct from source context links"
        );
        let deep = facts
            .imports
            .iter()
            .find(|row| row.identifier.as_deref() == Some("Deep"))
            .expect("nested macro source import");
        let mut current = Some(import_contexts[&deep.declaration]);
        let mut owners = Vec::new();
        while let Some(context) = current {
            let row = contexts[&context];
            if let Some(name) = row
                .owner
                .and_then(|id| facts.occurrences.declaration(id).name)
            {
                owners.push(text(name));
            }
            current = row.parent;
        }
        assert_eq!(
            owners,
            ["inside"],
            "nested macro imports retain their module barrier"
        );
        let first = facts
            .imports
            .iter()
            .find(|row| row.identifier.as_deref() == Some("First"))
            .unwrap();
        let other = facts
            .imports
            .iter()
            .find(|row| row.identifier.as_deref() == Some("Other"))
            .unwrap();
        assert_eq!(
            first.declaration, other.declaration,
            "grouped leaves share one context link"
        );
        for (member, owner) in [("forward_root", "Second"), ("forward_module", "Thing")] {
            assert!(
                parsed
                    .signatures
                    .keys()
                    .any(|unit| unit.identifier() == member
                        && unit.owner_identifier() == Some(owner)),
                "forward and source-order replacement semantics survive shared capture for {member}: {:?}",
                parsed.signatures.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn empty_import_projections_retain_primary_and_embedded_contexts() {
        let source = "use crate::{}; helper::wrap! { use crate::{}; }";
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        assert!(facts.imports.is_empty());
        assert!(facts.generic_imports.is_empty());
        assert_eq!(facts.rust_items.import_contexts.len(), 2);
        let primary = &facts.rust_items.import_contexts[0];
        let embedded = &facts.rust_items.import_contexts[1];
        assert_ne!(primary.declaration, embedded.declaration);
        assert_ne!(primary.context, embedded.context);
        assert_eq!(
            facts.occurrences.occurrence(primary.declaration).provenance,
            SourceOccurrenceProvenance::PrimaryNode
        );
        assert_eq!(
            facts
                .occurrences
                .occurrence(embedded.declaration)
                .provenance,
            SourceOccurrenceProvenance::Embedded
        );
        let embedded_root = facts
            .rust_items
            .contexts
            .iter()
            .find(|row| row.context == embedded.context)
            .expect("raw source root");
        assert_eq!(embedded_root.parent, Some(primary.context));
    }

    #[test]
    fn parsed_error_roots_retain_embedded_context_and_syntax() {
        use brokk_bifrost_core::analyzer::rust_facts::{
            RustItemMacroExpansion, RustSourceContextKind,
        };
        let source = r#"
macro_rules! evaluate { ($expression:expr) => { $expression }; }
const EXACT: usize = 1;
struct Other;
impl Other { const EXACT: usize = 2; }
fn module_reference() -> usize { evaluate!(EXACT) + evaluate!(EXACT | 8) }
fn associated_decoy() -> usize { evaluate!(Other::EXACT) }
fn lexical_decoy() -> usize { let EXACT = 3; evaluate!(EXACT) }
fn local_item_decoy() -> usize { const EXACT: usize = 4; evaluate!(EXACT) }
"#;
        let tree = crate::lexical_scope::parse_rust_tree(source).unwrap();
        let mut pending = vec![tree.root_node()];
        let mut error_roots = 0;
        let mut roots = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "macro_invocation" {
                let graph = build_rust_embedded_replay_graph(node, source)
                    .unwrap()
                    .unwrap();
                error_roots += usize::from(graph.tree(graph.root_id()).root_node().is_error());
                roots.push(graph.tree(graph.root_id()).root_node().to_sexp());
            }
            pending.extend(node.named_children(&mut node.walk()));
        }
        assert!(
            error_roots > 0,
            "fixture must exercise a parsed ERROR root: {roots:?}"
        );
        let parsed = parse_fixture(source);
        let items = &parsed.source_facts.as_ref().unwrap().rust_items;
        for expansion in &items.macros {
            let RustItemMacroExpansion::Parsed(root) = expansion.expansion else {
                panic!("expected parsed fragment: {expansion:?}");
            };
            let context = items
                .contexts
                .iter()
                .find(|context| context.context == root)
                .expect("each parsed root owns a source context");
            assert_eq!(context.kind, RustSourceContextKind::FileRoot);
            assert_eq!(context.parent, Some(expansion.context));
            let syntax = items
                .syntax
                .iter()
                .find(|syntax| syntax.occurrence == root)
                .expect("each parsed root has checked syntax");
            assert!(syntax.has_error);
        }
    }

    #[test]
    fn secondary_item_sources_keep_rejected_syntax_and_invoking_contexts() {
        use brokk_bifrost_core::analyzer::rust_facts::RustItemMacroExpansion;
        let source = r#"
mod outer {
    trait Trait {}
    struct Item;
    wrap! { mod inside { inner! { impl Trait for Item { fn nested() {} } } } }
    helper::wrap! { mod qualified_module; impl Trait for Item { fn qualified() {} } }
    stringify! { impl Trait for Item { fn builtin() {} } }
    macro_rules! discard { ($($t:tt)*) => {} }
    discard! { impl Trait for Item { fn discarded() {} } }
    broken! { mod malformed_module; impl Trait for Item { fn malformed() {} } let = ; }
    empty!{}
    whitespace!{ }
    comment!{ /* only trivia */ }
}
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let items = &facts.rust_items;
        let text = |occurrence| {
            let range = facts.occurrences.occurrence(occurrence).range;
            &source[range.start_byte..range.end_byte]
        };
        let name = |declaration| facts.occurrences.declaration(declaration).name.map(text);
        assert_eq!(
            items.impls.len(),
            5,
            "raw evidence is independent of display rejection"
        );
        for implementation in &items.impls {
            assert_eq!(
                facts
                    .occurrences
                    .occurrence(
                        facts
                            .occurrences
                            .declaration(implementation.declaration)
                            .occurrence
                    )
                    .provenance,
                SourceOccurrenceProvenance::Embedded
            );
        }
        for member_name in ["qualified", "builtin", "discarded", "malformed"] {
            let member = items
                .callables
                .iter()
                .find(|member| name(member.declaration) == Some(member_name))
                .expect("rejected member retains source identity");
            assert!(
                !parsed
                    .source_declaration_units
                    .iter()
                    .any(|(id, _)| *id == member.declaration)
            );
            assert!(
                !parsed
                    .signatures
                    .keys()
                    .any(|unit| unit.identifier() == member_name)
            );
        }
        assert!(
            parsed
                .signatures
                .keys()
                .any(|unit| unit.identifier() == "nested")
        );
        let contexts: HashMap<_, _> = items
            .contexts
            .iter()
            .map(|context| (context.context, context))
            .collect();
        for expansion in &items.macros {
            if let RustItemMacroExpansion::Parsed(root) = expansion.expansion {
                let invocation_range = facts.occurrences.occurrence(expansion.invocation).range;
                let root_range = facts.occurrences.occurrence(root).range;
                assert!(
                    invocation_range.start_byte <= root_range.start_byte
                        && root_range.end_byte <= invocation_range.end_byte,
                    "a parsed macro root stays inside its actual invocation, including trivia-only interiors"
                );
                assert_eq!(
                    contexts[&root].parent,
                    Some(expansion.context),
                    "every raw root inherits the invocation's live source context"
                );
            }
        }
        let nested = items
            .callables
            .iter()
            .find(|member| name(member.declaration) == Some("nested"))
            .expect("nested callable");
        let mut context = Some(nested.context);
        let mut names = Vec::new();
        while let Some(id) = context {
            let row = contexts[&id];
            if let Some(name) = row.owner.and_then(name) {
                names.push(name);
            }
            context = row.parent;
        }
        assert!(
            names.contains(&"inside") && names.contains(&"outer"),
            "embedded roots must not erase lexical module ancestry: {names:?}"
        );
        let empty = items
            .macros
            .iter()
            .find(|item| text(item.invocation) == "empty!{}")
            .expect("empty macro evidence");
        assert_eq!(empty.expansion, RustItemMacroExpansion::EmptyInterior);
        let broken = items
            .macros
            .iter()
            .find(|item| text(item.invocation).starts_with("broken!"))
            .expect("broken macro evidence");
        let RustItemMacroExpansion::Parsed(root) = broken.expansion else {
            panic!("returned error tree must be retained");
        };
        assert!(
            items
                .syntax
                .iter()
                .find(|row| row.occurrence == root)
                .unwrap()
                .has_error
        );
        for module_name in ["qualified_module", "malformed_module"] {
            let module = facts
                .rust_modules
                .as_ref()
                .expect("source modules")
                .declarations
                .iter()
                .find(|module| module.name == module_name)
                .expect("raw source module metadata");
            assert!(
                !facts
                    .rust_modules
                    .as_ref()
                    .unwrap()
                    .routes
                    .iter()
                    .any(|route| route.declaration == module.declaration)
            );
            assert!(
                !parsed
                    .source_declaration_units
                    .iter()
                    .any(|(id, _)| *id == module.declaration)
            );
        }
    }

    #[test]
    fn macro_source_descriptors_retain_unrequested_macro_path_children() {
        use brokk_bifrost_core::analyzer::rust_facts::RustItemMacroExpansion;
        for source in ["<inner!()>::outer!{}", "outer::<inner!()>::invoke!{}"] {
            let parsed = parse_fixture(source);
            let facts = parsed.source_facts.as_ref().unwrap();
            assert!(
                facts
                    .rust_items
                    .macros
                    .iter()
                    .any(|fact| fact.expansion == RustItemMacroExpansion::NotRequested),
                "{source}: {:?}",
                facts.rust_items.macros
            );
        }
    }

    #[test]
    fn macro_source_descriptors_capture_primary_positions_and_outcomes() {
        use brokk_bifrost_core::analyzer::rust_facts::{
            RustItemMacroExpansion, RustItemMacroSourcePosition,
        };

        let source = r#"
outer! { inner!(); }
statement!();
fn containing() { expression!(); qualified::expression!(); }
empty!{}
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let items = &facts.rust_items;
        let macro_text = |invocation| -> String {
            let range = facts.occurrences.occurrence(invocation).range;
            source[range.start_byte..range.end_byte].to_owned()
        };
        let primary_macro = |text: &str| {
            items
                .macros
                .iter()
                .find(|fact| {
                    macro_text(fact.invocation) == text
                        && facts.occurrences.occurrence(fact.invocation).provenance
                            == SourceOccurrenceProvenance::PrimaryNode
                })
                .copied()
                .unwrap_or_else(|| panic!("missing primary macro descriptor {text:?}"))
        };

        let outer = primary_macro("outer! { inner!(); }");
        assert_eq!(outer.position, RustItemMacroSourcePosition::DirectItem);
        assert!(matches!(outer.expansion, RustItemMacroExpansion::Parsed(_)));

        let statement = primary_macro("statement!()");
        assert_eq!(
            statement.position,
            RustItemMacroSourcePosition::ItemStatement
        );
        assert_eq!(statement.expansion, RustItemMacroExpansion::EmptyInterior);

        let expression = primary_macro("expression!()");
        assert_eq!(expression.position, RustItemMacroSourcePosition::Other);
        assert_eq!(expression.expansion, RustItemMacroExpansion::EmptyInterior);

        let empty = primary_macro("empty!{}");
        assert_eq!(empty.position, RustItemMacroSourcePosition::DirectItem);
        assert_eq!(empty.expansion, RustItemMacroExpansion::EmptyInterior);

        let embedded_nested = items
            .macros
            .iter()
            .find(|fact| {
                macro_text(fact.invocation) == "inner!()"
                    && facts.occurrences.occurrence(fact.invocation).provenance
                        == SourceOccurrenceProvenance::Embedded
            })
            .copied()
            .expect("embedded nested macro descriptor");
        assert_eq!(
            embedded_nested.position,
            RustItemMacroSourcePosition::ItemStatement
        );
        assert_eq!(
            embedded_nested.expansion,
            RustItemMacroExpansion::EmptyInterior
        );

        let qualified = primary_macro("qualified::expression!()");
        assert_eq!(qualified.position, RustItemMacroSourcePosition::Other);
        assert_eq!(qualified.expansion, RustItemMacroExpansion::EmptyInterior);
    }

    #[test]
    fn secondary_item_sources_do_not_admit_rejected_child_routes() {
        let source = r#"
envelope! {
    helper::hidden! { mod nested_qualified; }
    broken_inner! { mod nested_bad; let = ; }
    valid! { mod admitted; }
}
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let modules = facts.rust_modules.as_ref().expect("source modules");
        for name in ["nested_qualified", "nested_bad", "admitted"] {
            let module = modules
                .declarations
                .iter()
                .find(|module| module.name == name)
                .expect("all raw source modules are captured");
            let admitted = name == "admitted";
            assert_eq!(
                modules
                    .routes
                    .iter()
                    .any(|route| route.declaration == module.declaration),
                admitted,
                "route admission for {name}"
            );
            assert_eq!(
                parsed
                    .source_declaration_units
                    .iter()
                    .any(|(id, _)| *id == module.declaration),
                admitted,
                "display admission for {name}"
            );
        }
    }

    #[test]
    fn item_syntax_errors_have_one_owner_across_contexts_and_body_members() {
        let source = r#"
trait Broken { fn bad(&self, value: ); type Missing = ; }
impl Broken for Missing { fn ok(&self) {} }
helper::wrap! { trait Raw { fn broken(&self, value: ); } }
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let items = &facts.rust_items;
        let syntax: HashMap<_, _> = items
            .syntax
            .iter()
            .map(|row| (row.occurrence, row.has_error))
            .collect();
        assert_eq!(
            syntax.len(),
            items.syntax.len(),
            "one syntax owner per exact occurrence"
        );
        for context in &items.contexts {
            assert!(
                syntax.contains_key(&context.context),
                "every context was checked"
            );
        }
        for declaration in items
            .impls
            .iter()
            .map(|row| row.declaration)
            .chain(items.traits.iter().map(|row| row.declaration))
            .chain(items.aliases.iter().map(|row| row.declaration))
            .chain(items.callables.iter().map(|row| row.declaration))
        {
            assert!(
                syntax.contains_key(&facts.occurrences.declaration(declaration).occurrence),
                "every item has an explicit syntax check, including clean items"
            );
        }
        for child in items
            .impls
            .iter()
            .flat_map(|row| &row.body_children)
            .chain(items.traits.iter().flat_map(|row| &row.body_children))
        {
            assert!(syntax.contains_key(&child.occurrence));
            if let Some(declaration) = child.declaration {
                assert_eq!(
                    facts.occurrences.declaration(declaration).occurrence,
                    child.occurrence
                );
            }
        }
        let text = |occurrence| {
            let range = facts.occurrences.occurrence(occurrence).range;
            &source[range.start_byte..range.end_byte]
        };
        for (name, error) in [("bad", true), ("ok", false), ("broken", true)] {
            let callable = items
                .callables
                .iter()
                .find(|row| {
                    facts
                        .occurrences
                        .declaration(row.declaration)
                        .name
                        .map(text)
                        == Some(name)
                })
                .expect("primary or raw embedded callable survives projection admission");
            let occurrence = facts
                .occurrences
                .declaration(callable.declaration)
                .occurrence;
            let context = items
                .contexts
                .iter()
                .find(|row| row.owner == Some(callable.declaration))
                .expect("callable context");
            assert_eq!(context.context, occurrence);
            assert_eq!(syntax[&occurrence], error, "syntax result for {name}");
        }
        let alias = items
            .aliases
            .iter()
            .find(|row| {
                facts
                    .occurrences
                    .declaration(row.declaration)
                    .name
                    .map(text)
                    == Some("Missing")
            })
            .expect("malformed alias remains source evidence");
        assert!(syntax[&facts.occurrences.declaration(alias.declaration).occurrence]);
        let property = facts
            .rust_declaration_properties
            .iter()
            .find(|row| row.declaration == alias.declaration)
            .expect("named alias classification");
        assert!(matches!(
            property.kind,
            brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind::TypeAlias
                | brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind::AssociatedType
        ));
    }

    #[test]
    fn primary_item_sources_retain_negative_impl_and_unclassified_parse_errors() {
        let source = "struct Item; trait Trait {} impl !Trait for Item {}";
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let implementation = &facts.rust_items.impls[0];
        let negation = implementation.negation.expect("negative impl token");
        let range = facts.occurrences.occurrence(negation).range;
        assert_eq!(&source[range.start_byte..range.end_byte], "!");
        assert!(implementation.trait_type.is_some());
        let occurrence = facts
            .occurrences
            .declaration(implementation.declaration)
            .occurrence;
        assert!(
            !facts
                .rust_items
                .syntax
                .iter()
                .find(|row| row.occurrence == occurrence)
                .unwrap()
                .has_error
        );

        let malformed = parse_fixture("impl");
        let items = &malformed
            .source_facts
            .as_ref()
            .expect("source facts")
            .rust_items;
        assert!(
            items
                .syntax
                .iter()
                .find(|row| row.occurrence == items.contexts[0].context)
                .unwrap()
                .has_error,
            "unclassified syntax errors cannot look like complete empty input"
        );
    }

    #[test]
    fn primary_item_sources_preserve_generic_names_and_nonlabel_parameters() {
        let source = r#"
struct Item;
impl<'a, T: Bound, U = Item, const N: usize> Trait for Item {}
extern "C" { fn variadic(r#type: u8, /* parameter trivia */ ...); }
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let items = &facts.rust_items;
        let names: Vec<_> = items
            .generics
            .iter()
            .find(|generic| generic.declaration == items.impls[0].declaration)
            .expect("impl generic group")
            .parameters
            .iter()
            .filter_map(|parameter| parameter.name.as_ref())
            .map(|name| name.name.as_str())
            .collect();
        assert_eq!(names, ["'a", "T", "U", "N"]);
        let parameters = &items.callables[0].parameter_children;
        let written = |occurrence| {
            let range = facts.occurrences.occurrence(occurrence).range;
            &source[range.start_byte..range.end_byte]
        };
        assert!(
            parameters.iter().any(
                |parameter| written(parameter.occurrence) == "..." && parameter.label.is_none()
            )
        );
        assert!(
            parameters
                .iter()
                .any(
                    |parameter| written(parameter.occurrence) == "/* parameter trivia */"
                        && parameter.label.is_none()
                )
        );
        assert_eq!(
            parameters
                .iter()
                .filter_map(|parameter| parameter.label.as_ref())
                .map(|label| label.name.as_str())
                .collect::<Vec<_>>(),
            ["type"]
        );
        for parameter in &items
            .generics
            .iter()
            .find(|generic| generic.declaration == items.impls[0].declaration)
            .expect("impl generic group")
            .parameters
        {
            let name = parameter
                .name
                .as_ref()
                .expect("all fixture generic parameters have names");
            assert_eq!(written(name.occurrence), name.name);
        }
    }

    #[test]
    fn item_sources_link_type_fields_and_generic_groups_across_primary_and_embedded_trees() {
        use brokk_bifrost_core::analyzer::rust_facts::RustSourceContextKind;

        use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

        let source = r#"
struct Struct<T> { field: T }
enum Enum<T> { Named { field: T } }
union Union<T> { field: T }
type Alias<T> = Vec<T>;
trait Trait<T> { type Assoc<U>; fn method<V>(value: V) -> V; }
fn callable<T>(value: T) -> T { value }
struct NoGeneric;
fn no_generic() {}
impl<T> Trait<T> for Struct<T> {
    type Assoc<U> = U;
    fn method<V>(&self, value: V) -> V { value }
}
wrap! {
    struct EmbeddedStruct<T> { field: T }
    enum EmbeddedEnum<T> { Named { field: T } }
    union EmbeddedUnion<T> { field: T }
    type EmbeddedAlias<T> = Vec<T>;
    trait EmbeddedTrait<T> { type Assoc<U>; fn method<V>(value: V) -> V; }
    fn embedded_callable<T>(value: T) -> T { value }
    struct EmbeddedNoGeneric;
    fn embedded_no_generic() {}
    impl<T> EmbeddedTrait<T> for EmbeddedStruct<T> {
        type Assoc<U> = U;
        fn method<V>(&self, value: V) -> V { value }
    }
}
"#;
        let parsed = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let items = &facts.rust_items;

        let declaration_name = |declaration| {
            facts.occurrences.declaration(declaration).name.map(|name| {
                let range = facts.occurrences.occurrence(name).range;
                &source[range.start_byte..range.end_byte]
            })
        };
        let declaration_provenance = |declaration| {
            let occurrence = facts.occurrences.declaration(declaration).occurrence;
            facts.occurrences.occurrence(occurrence).provenance
        };
        let generic_names = |declaration| {
            items
                .generics
                .iter()
                .find(|generic| generic.declaration == declaration)
                .expect("generic group for declaration")
                .parameters
                .iter()
                .map(|parameter| {
                    parameter
                        .name
                        .as_ref()
                        .expect("fixture generic parameter name")
                        .name
                        .as_str()
                })
                .collect::<Vec<_>>()
        };

        for (name, expected) in [
            ("Struct", vec!["T"]),
            ("Enum", vec!["T"]),
            ("Union", vec!["T"]),
            ("Alias", vec!["T"]),
            ("Trait", vec!["T"]),
            ("callable", vec!["T"]),
            ("EmbeddedStruct", vec!["T"]),
            ("EmbeddedEnum", vec!["T"]),
            ("EmbeddedUnion", vec!["T"]),
            ("EmbeddedAlias", vec!["T"]),
            ("EmbeddedTrait", vec!["T"]),
            ("embedded_callable", vec!["T"]),
        ] {
            let declarations = items
                .generics
                .iter()
                .filter(|generic| declaration_name(generic.declaration) == Some(name))
                .collect::<Vec<_>>();
            assert!(!declarations.is_empty(), "missing generic group for {name}");
            for generic in declarations {
                assert_eq!(generic_names(generic.declaration), expected);
            }
        }

        for name in ["Assoc", "method"] {
            let declarations = items
                .generics
                .iter()
                .filter(|generic| declaration_name(generic.declaration) == Some(name))
                .collect::<Vec<_>>();
            assert_eq!(declarations.len(), 4, "primary and embedded {name} groups");
            for generic in declarations {
                assert_eq!(
                    generic_names(generic.declaration),
                    if name == "Assoc" {
                        vec!["U"]
                    } else {
                        vec!["V"]
                    }
                );
            }
        }

        for declaration_name_to_skip in [
            "NoGeneric",
            "no_generic",
            "EmbeddedNoGeneric",
            "embedded_no_generic",
        ] {
            assert!(!items.generics.iter().any(|generic| {
                declaration_name(generic.declaration) == Some(declaration_name_to_skip)
            }));
        }

        let unnamed_impl_groups = items
            .impls
            .iter()
            .filter_map(|implementation| {
                items
                    .generics
                    .iter()
                    .find(|generic| generic.declaration == implementation.declaration)
            })
            .collect::<Vec<_>>();
        assert_eq!(unnamed_impl_groups.len(), 2);
        assert!(
            unnamed_impl_groups
                .iter()
                .all(|generic| generic_names(generic.declaration) == ["T"])
        );

        for generic in &items.generics {
            let provenance = declaration_provenance(generic.declaration);
            assert!(!generic.parameters.is_empty());
            for parameter in &generic.parameters {
                assert_eq!(
                    facts
                        .occurrences
                        .occurrence(parameter.occurrence)
                        .provenance,
                    provenance,
                    "generic parameter identity must remain in its declaration tree"
                );
            }
        }

        for (owner_name, provenance) in [
            ("Struct", SourceOccurrenceProvenance::PrimaryNode),
            ("Enum", SourceOccurrenceProvenance::PrimaryNode),
            ("Union", SourceOccurrenceProvenance::PrimaryNode),
            ("EmbeddedStruct", SourceOccurrenceProvenance::Embedded),
            ("EmbeddedEnum", SourceOccurrenceProvenance::Embedded),
            ("EmbeddedUnion", SourceOccurrenceProvenance::Embedded),
        ] {
            let value = items
                .values
                .iter()
                .find(|value| {
                    declaration_name(value.declaration) == Some("field")
                        && declaration_provenance(value.declaration) == provenance
                        && items
                            .contexts
                            .iter()
                            .find(|context| context.context == value.context)
                            .and_then(|context| context.owner)
                            .and_then(declaration_name)
                            == Some(owner_name)
                })
                .expect("named field has a type owner context");
            let context = items
                .contexts
                .iter()
                .find(|context| context.context == value.context)
                .expect("field context");
            assert_eq!(context.kind, RustSourceContextKind::Type);
            assert_eq!(context.owner.and_then(declaration_name), Some(owner_name));
        }
    }

    #[test]
    fn primary_item_contexts_retain_linear_parent_links_at_depth() {
        let depth = 256;
        let mut source = String::new();
        for index in 0..depth {
            source.push_str(&format!("mod m{index} {{ "));
        }
        source.push_str("fn leaf() {} ");
        for _ in 0..depth {
            source.push_str("} ");
        }
        let parsed = parse_fixture(&source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let contexts = &facts.rust_items.contexts;
        assert_eq!(
            contexts.len(),
            2 * depth + 3,
            "one row per actual context, not copied ancestry"
        );
        let by_id: HashMap<_, _> = contexts
            .iter()
            .map(|context| (context.context, context))
            .collect();
        assert_eq!(by_id.len(), contexts.len());
        let mut current = contexts.last().map(|context| context.context);
        let mut count = 0;
        while let Some(id) = current {
            count += 1;
            assert!(count <= contexts.len(), "parent links cannot cycle");
            current = by_id[&id].parent;
        }
        assert_eq!(
            count,
            contexts.len(),
            "the nested chain terminates at its file root"
        );
    }

    #[test]
    fn deeply_nested_embedded_modules_replay_without_rust_stack_growth() {
        let depth = 512;
        let mut source = String::from("wrap! { ");
        for index in 0..depth {
            source.push_str("mod m");
            source.push_str(&index.to_string());
            source.push_str(" { ");
        }
        source.push_str("fn deepest() {} ");
        for _ in 0..depth {
            source.push_str("} ");
        }
        source.push('}');

        assert_deepest_on_small_stack(source);
    }

    #[test]
    fn deeply_nested_embedded_macros_replay_without_rust_stack_growth() {
        let depth = 128;
        let mut source = "wrap! { ".repeat(depth);
        source.push_str("fn deepest() {} ");
        source.push_str(&"} ".repeat(depth));
        assert_deepest_on_small_stack(source);
    }

    fn assert_deepest_on_small_stack(source: String) {
        let handle = std::thread::Builder::new()
            .name("rust-embedded-deep-replay".to_string())
            .stack_size(256 * 1024)
            .spawn(move || {
                let parsed = parse_fixture(&source);
                assert!(
                    parsed
                        .source_declaration_units
                        .iter()
                        .any(|(_, unit)| unit.identifier() == "deepest"),
                    "deep embedded declaration was not replayed"
                );
            })
            .expect("spawn deep replay test thread");
        if let Err(payload) = handle.join() {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn wide_nested_embedded_macros_preserve_declaration_order() {
        let width = 128;
        let mut source = String::from("wrap! { ");
        for index in 0..width {
            source.push_str("nested! { fn generated_");
            source.push_str(&index.to_string());
            source.push_str("() {} } ");
        }
        source.push('}');

        let parsed = parse_fixture(&source);
        let names = parsed
            .source_declaration_units
            .iter()
            .map(|(_, unit)| unit.identifier().to_string())
            .collect::<Vec<_>>();
        let expected = (0..width)
            .map(|index| format!("generated_{index}"))
            .collect::<Vec<_>>();
        assert_eq!(names, expected);
    }

    #[test]
    fn embedded_source_maps_share_live_node_occurrences_across_bridges() {
        let source = "wrap! { mod root { type Item = u8; } nested! { mod child; } }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let primary_tree = parser.parse(source, None).expect("parse Rust fixture");
        let invocation = primary_tree
            .root_node()
            .named_child(0)
            .expect("outer macro invocation");
        let mut graph = build_rust_embedded_replay_graph(invocation, source)
            .expect("build embedded replay graph")
            .expect("nonempty replay interior");

        fn first_kind<'tree>(root: Node<'tree>, kind: &str) -> Node<'tree> {
            let mut pending = vec![root];
            while let Some(node) = pending.pop() {
                if node.kind() == kind {
                    return node;
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            panic!("missing embedded {kind} node");
        }

        let mut collector = PrimarySourceFactCollector::new(source);
        let mut properties = RustDeclarationPropertyCollector::new(source);
        let root = collector.intern_node(primary_tree.root_node());
        let mut module_sources = crate::facts::RustModuleSourceCollector::new(source, root);
        module_sources.record_inner_attributes(primary_tree.root_node());
        let mut links = Vec::new();
        let mut types = RustTypeSourceCollector::new();
        let (root_declaration, root_occurrence, body_occurrence, child_occurrence) = {
            let (trees, source_maps) = graph.split_mut();
            assert_eq!(trees.len(), 2, "nested macro gets a distinct replay tree");
            let root_module = first_kind(trees[0].root(), "mod_item");
            let child_module = first_kind(trees[1].root(), "mod_item");

            let first_occurrence = source_maps[0].intern_node(root_module, &mut collector);
            let repeated_occurrence = source_maps[0].intern_node(root_module, &mut collector);
            assert_eq!(first_occurrence, repeated_occurrence);

            let root_declaration = ensure_embedded_source_declaration(
                0,
                root_module,
                &mut collector,
                &mut properties,
                source_maps,
            );
            assert_eq!(
                collector.declaration(root_declaration).occurrence,
                first_occurrence,
                "declaration and type/module bridge share the live-node occurrence"
            );
            module_sources.record_embedded_declaration(
                0,
                root_declaration,
                root_module,
                &mut collector,
                source_maps,
            );
            let mut bridge = RustEmbeddedDeclarationSourceBridge {
                collector: &mut collector,
                properties: &mut properties,
                module_sources: &mut module_sources,
                links: &mut links,
                source_maps,
                types: &mut types,
                tree_id: 0,
            };
            let name = root_module
                .child_by_field_name("name")
                .expect("module name");
            let type_occurrence = bridge.record_type(name, source).occurrence;
            let repeated_type_occurrence = bridge.record_type(name, source).occurrence;
            assert_eq!(type_occurrence, repeated_type_occurrence);
            let body_occurrence = bridge.intern_node(
                root_module
                    .child_by_field_name("body")
                    .expect("module body"),
            );
            assert_eq!(
                collector.declaration(root_declaration).name,
                Some(type_occurrence),
                "the type sink reuses the declaration's exact name occurrence"
            );

            let child_occurrence = source_maps[1].intern_node(child_module, &mut collector);
            assert_ne!(first_occurrence, child_occurrence);
            (
                root_declaration,
                first_occurrence,
                body_occurrence,
                child_occurrence,
            )
        };
        let modules = module_sources.finish(vec![
            brokk_bifrost_core::analyzer::rust_facts::RustModuleInventorySourceFact {
                declaration: None,
                parent_scope: 0,
            },
        ]);
        assert_eq!(
            modules.declarations[0].body,
            Some(body_occurrence),
            "the generic source sink reuses the module's exact body occurrence"
        );
        drop(graph);
        let mut replayed = build_rust_embedded_replay_graph(invocation, source)
            .expect("repeat the same replay event")
            .expect("nonempty replay interior");
        let (trees, maps) = replayed.split_mut();
        let repeated_module = first_kind(trees[0].root(), "mod_item");
        let repeated_occurrence = maps[0].intern_node(repeated_module, &mut collector);
        let mut sink = RustEmbeddedSourceOccurrenceSink {
            collector: &mut collector,
            source_maps: maps,
            tree_id: 0,
        };
        types.record_type(
            repeated_module
                .child_by_field_name("name")
                .expect("module name"),
            source,
            &mut sink,
        );
        let types = types.into_facts();
        assert_eq!(types.len(), 2, "one type fact per replay, not per request");
        assert_ne!(types[0].occurrence, types[1].occurrence);
        assert_eq!(
            collector.occurrence(types[0].occurrence).range,
            collector.occurrence(types[1].occurrence).range,
            "equal physical type spans from separate replays are distinct facts"
        );
        assert_ne!(root_occurrence, repeated_occurrence);
        assert_eq!(
            collector.occurrence(root_occurrence).range,
            collector.occurrence(repeated_occurrence).range,
            "separate replay events remain distinct even at identical ranges"
        );
        let rows = collector.finish();
        assert_eq!(
            rows.declaration(root_declaration).occurrence,
            root_occurrence
        );
        assert_ne!(root_occurrence, child_occurrence);
        assert_eq!(
            rows.occurrence(root_occurrence).provenance,
            SourceOccurrenceProvenance::Embedded
        );
    }

    #[test]
    fn coordinated_replay_keeps_declaration_dfs_and_route_fifo_order() {
        let source = r#"
wrap! { pub mod first; nested! { pub mod child; } }
wrap! { pub mod second; }
"#;
        let parsed = parse_fixture(source);
        let declaration_names = parsed
            .source_declaration_units
            .iter()
            .map(|(_, unit)| unit.identifier().to_string())
            .collect::<Vec<_>>();
        assert_eq!(declaration_names, ["first", "child", "second"]);

        let route_names = parsed
            .rust_usage_facts
            .module_routes
            .routes
            .iter()
            .map(|route| route.module_name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(route_names, ["first", "second", "child"]);

        let source_facts = parsed.source_facts.as_ref().expect("source facts");
        for name in ["first", "child", "second"] {
            let declarations = parsed
                .source_declaration_units
                .iter()
                .filter(|(_, unit)| unit.identifier() == name)
                .map(|(declaration, _)| *declaration)
                .collect::<Vec<_>>();
            assert_eq!(
                declarations.len(),
                1,
                "duplicate source identity for {name}"
            );
            let occurrence = source_facts
                .occurrences
                .declaration(declarations[0])
                .occurrence;
            assert_eq!(
                source_facts.occurrences.occurrence(occurrence).provenance,
                SourceOccurrenceProvenance::Embedded,
                "embedded declaration provenance for {name}"
            );
            assert_eq!(
                source_facts
                    .rust_declaration_properties
                    .iter()
                    .filter(|property| property.declaration == declarations[0])
                    .count(),
                1,
                "one canonical property row for {name}"
            );
        }
    }

    #[test]
    fn coordinated_replay_parses_each_macro_interior_once() {
        let source = r#"
wrap! { pub mod first; nested! { pub mod child; } }
wrap! { pub mod second; }
stringify! { pub mod route_only; }
"#;
        crate::lexical_scope::reset_rust_tree_parse_counters_for_test();
        let parsed = parse_fixture(source);
        assert_eq!(
            crate::lexical_scope::rust_tree_parse_request_count_for_test(),
            4,
            "one raw-tree parse for each primary or nested macro invocation"
        );
        // Four replay trees plus one enumeration attempt for each of the
        // three item-position invocations the native walk reaches (`wrap!`
        // twice and `stringify!`; `nested!` is inside `wrap!`'s interior and
        // is replayed, not visited). An attempt parses the first group of the
        // token tree, `pub mod first`, `pub mod second` and `pub mod
        // route_only`, none of which is an expression, so each invocation
        // keeps its reference-enumeration gap. Those parses go through
        // `parse_rust_tree_uncached`, which raises this counter and not the
        // request counter above; the request count is replay's alone, and it
        // is what pins that no interior is replayed twice.
        assert_eq!(
            crate::lexical_scope::rust_tree_parse_count_for_test(),
            7,
            "declaration and route projections share the same four replay trees"
        );
        let source_facts = parsed.source_facts.as_ref().expect("source facts");
        let route_only = source_facts
            .rust_declaration_properties
            .iter()
            .find(|property| {
                let Some(name) = source_facts
                    .occurrences
                    .declaration(property.declaration)
                    .name
                else {
                    return false;
                };
                let range = source_facts.occurrences.occurrence(name).range;
                source.get(range.start_byte..range.end_byte) == Some("route_only")
            })
            .expect("builtin route-only property");
        assert!(
            !parsed
                .source_declaration_units
                .iter()
                .any(|(declaration, _)| *declaration == route_only.declaration),
            "route-only builtin item has no display declaration link"
        );
    }

    #[test]
    fn malformed_nested_replay_is_ignored_without_losing_outer_items() {
        let source = r#"
wrap! { pub mod kept; nested! { pub mod malformed = ; } }
"#;
        let parsed = parse_fixture(source);
        assert!(
            parsed
                .rust_usage_facts
                .module_routes
                .routes
                .iter()
                .any(|route| route.module_name == "kept")
        );
        assert!(
            !parsed
                .rust_usage_facts
                .module_routes
                .routes
                .iter()
                .any(|route| route.module_name == "malformed")
        );
        assert!(
            parsed
                .source_declaration_units
                .iter()
                .any(|(_, unit)| unit.identifier() == "kept")
        );
        assert!(
            !parsed
                .source_declaration_units
                .iter()
                .any(|(_, unit)| unit.identifier() == "malformed")
        );
    }
}

#[cfg(test)]
mod declaration_property_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind;
    use brokk_bifrost_core::analyzer::rust_facts::{
        RustCfgCondition, RustDeclarationBoundary, RustDeclarationKind,
    };
    use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

    fn parse_fixture(source: &str) -> (ParsedFile, String) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root, "src/lib.rs");
        let parsed = parse_rust_file(&file, source, &tree);
        (parsed, source.to_owned())
    }

    fn declaration_name<'a>(
        parsed: &'a ParsedFile,
        source: &'a str,
        id: SourceDeclarationId,
    ) -> Option<&'a str> {
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let name = facts.occurrences.declaration(id).name?;
        let range = facts.occurrences.occurrence(name).range;
        source.get(range.start_byte..range.end_byte)
    }

    #[test]
    fn named_properties_capture_cfg_visibility_and_constructor_constraints_once() {
        let source = r#"
#[cfg(feature = "x")]
pub struct Tuple(pub u8, u8);
pub struct Unit;
pub struct Named { pub field: u8 }
#[non_exhaustive]
pub struct NonExhaustive(pub u8);
fn outer(param: u8) { fn inner() {} let local = param; }
"#;
        let (parsed, source) = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");

        let linked = |name: &str| {
            let (declaration, _) = parsed
                .source_declaration_units
                .iter()
                .find(|(_, unit)| unit.identifier() == name)
                .unwrap_or_else(|| panic!("missing linked declaration {name}"));
            facts
                .rust_declaration_properties
                .iter()
                .find(|fact| fact.declaration == *declaration)
                .unwrap_or_else(|| panic!("missing properties for {name}"))
        };

        let tuple = linked("Tuple");
        assert_eq!(tuple.visibility, crate::imports::RustVisibility::Public);
        let tuple_declaration = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.identifier() == "Tuple")
            .map(|(declaration, _)| *declaration)
            .expect("primary declaration link");
        let tuple_occurrence = facts.occurrences.declaration(tuple_declaration).occurrence;
        assert_eq!(
            facts.occurrences.occurrence(tuple_occurrence).provenance,
            SourceOccurrenceProvenance::PrimaryNode
        );
        assert!(matches!(
            &tuple.cfg_condition,
            RustCfgCondition::Atom(atom) if atom == "feature = \"x\""
        ));
        let constructor = tuple
            .value_constructor
            .as_deref()
            .expect("tuple constructor properties");
        assert_eq!(
            constructor.field_visibilities,
            vec![
                crate::imports::RustVisibility::Public,
                crate::imports::RustVisibility::Private,
            ]
        );
        assert!(!constructor.non_exhaustive);

        let unit = linked("Unit");
        assert!(
            unit.value_constructor
                .as_deref()
                .is_some_and(|constructor| {
                    constructor.field_visibilities.is_empty() && !constructor.non_exhaustive
                })
        );
        assert!(linked("Named").value_constructor.is_none());
        let non_exhaustive = linked("NonExhaustive")
            .value_constructor
            .as_deref()
            .expect("non-exhaustive constructor properties");
        assert!(non_exhaustive.non_exhaustive);
        assert_eq!(
            non_exhaustive.field_visibilities,
            vec![crate::imports::RustVisibility::Public]
        );

        let inner = facts
            .rust_declaration_properties
            .iter()
            .find(|fact| declaration_name(&parsed, &source, fact.declaration) == Some("inner"))
            .expect("native-only nested function has properties");
        assert!(
            !parsed
                .source_declaration_units
                .iter()
                .any(|(declaration, _)| *declaration == inner.declaration)
        );

        let local_parameter = facts
            .native_declaration_sources
            .iter()
            .map(|(_, declaration)| *declaration)
            .find(|declaration| declaration_name(&parsed, &source, *declaration) == Some("param"))
            .expect("parameter source declaration");
        assert!(
            !facts
                .rust_declaration_properties
                .iter()
                .any(|fact| fact.declaration == local_parameter)
        );
    }

    #[test]
    fn generic_parameter_binders_bridge_exact_source_owner_and_name_occurrences() {
        let source = r#"
struct First<T, const N: usize> { value: T }
fn second<T, const N: usize>(value: T) -> [u8; N] { [0; N] }
"#;
        let (parsed, _) = parse_fixture(source);
        let source_facts = parsed.source_facts.as_ref().expect("source facts");
        let resolution = &parsed.resolution_facts;
        let mut generic_links = Vec::new();

        for generic in &source_facts.rust_items.generics {
            for parameter in &generic.parameters {
                let name = parameter
                    .name
                    .as_ref()
                    .expect("fixture generic parameter name");
                let links = source_facts
                    .native_declaration_sources
                    .iter()
                    .filter(|(_, declaration)| {
                        let source_declaration = source_facts.occurrences.declaration(*declaration);
                        source_declaration.occurrence == parameter.occurrence
                            && source_declaration.name == Some(name.occurrence)
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    links.len(),
                    1,
                    "generic parameter {:?} must have one native/source bridge: {links:?}",
                    name.name
                );
                let (site, source_declaration) = *links[0];

                let binder = resolution
                    .binders
                    .iter()
                    .find(|binder| binder.declaration == site)
                    .expect("generic source bridge points at a native binder");
                assert_eq!(
                    binder.kind,
                    match parameter.kind.as_str() {
                        "type_parameter" => ResolutionBinderKind::Type,
                        "const_parameter" => ResolutionBinderKind::Parameter,
                        kind => panic!("unexpected retained generic parameter kind {kind:?}"),
                    }
                );

                let owner_range = source_facts
                    .occurrences
                    .occurrence(parameter.occurrence)
                    .range;
                let name_range = source_facts.occurrences.occurrence(name.occurrence).range;
                let site_fact = &resolution.sites[site.index()];
                assert_eq!(
                    (site_fact.start_byte, site_fact.end_byte),
                    (name_range.start_byte, name_range.end_byte),
                    "native binder site must retain the exact generic name span"
                );
                let declaration = source_facts.occurrences.declaration(source_declaration);
                assert_eq!(declaration.occurrence, parameter.occurrence);
                assert_eq!(declaration.name, Some(name.occurrence));
                assert_eq!(
                    (
                        source_facts
                            .occurrences
                            .occurrence(declaration.occurrence)
                            .range
                            .start_byte,
                        source_facts
                            .occurrences
                            .occurrence(declaration.occurrence)
                            .range
                            .end_byte
                    ),
                    (owner_range.start_byte, owner_range.end_byte),
                    "source declaration must retain the exact generic owner span"
                );
                generic_links.push((name.name.as_str(), site, source_declaration, binder.scope));
            }
        }

        assert_eq!(generic_links.len(), 4);
        for name in ["T", "N"] {
            let links = generic_links
                .iter()
                .filter(|(candidate, ..)| *candidate == name)
                .collect::<Vec<_>>();
            assert_eq!(links.len(), 2, "two distinct generic scopes for {name}");
            assert_ne!(links[0].1, links[1].1, "native sites for {name}");
            assert_ne!(links[0].2, links[1].2, "source declarations for {name}");
            assert_ne!(links[0].3, links[1].3, "binder scopes for {name}");
        }
    }

    #[test]
    fn embedded_properties_retain_embedded_identity_and_constructor_shape() {
        let source = r#"
wrap! {
    #[cfg(feature = "embedded")]
    pub struct Generated(pub u8, u8);
}
"#;
        let (parsed, _) = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let (declaration, _) = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.identifier() == "Generated")
            .expect("embedded declaration link");
        let fact = facts
            .rust_declaration_properties
            .iter()
            .find(|fact| fact.declaration == *declaration)
            .expect("embedded declaration properties");
        assert_eq!(
            fact.nearest_declaration_boundary,
            RustDeclarationBoundary::ModuleOrFile
        );
        assert!(!fact.has_impl_or_trait_ancestor);
        assert!(matches!(
            &fact.cfg_condition,
            RustCfgCondition::Atom(atom) if atom == "feature = \"embedded\""
        ));
        assert_eq!(fact.visibility, crate::imports::RustVisibility::Public);
        assert_eq!(
            fact.value_constructor
                .as_deref()
                .expect("embedded constructor")
                .field_visibilities,
            vec![
                crate::imports::RustVisibility::Public,
                crate::imports::RustVisibility::Private,
            ]
        );
        let occurrence = facts.occurrences.declaration(*declaration).occurrence;
        assert_eq!(
            facts.occurrences.occurrence(occurrence).provenance,
            SourceOccurrenceProvenance::Embedded
        );
    }

    #[test]
    fn repeated_primary_declarations_keep_independent_owner_properties() {
        let source = r#"
#[cfg(feature = "one")]
fn repeated() {}
#[cfg(not(feature = "one"))]
fn repeated() {}
"#;
        let (parsed, source) = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let repeated = facts
            .rust_declaration_properties
            .iter()
            .filter(|fact| declaration_name(&parsed, &source, fact.declaration) == Some("repeated"))
            .collect::<Vec<_>>();
        assert_eq!(repeated.len(), 2);
        assert_ne!(repeated[0].declaration, repeated[1].declaration);
        assert!(repeated.iter().all(|fact| {
            !fact.has_impl_or_trait_ancestor
                && fact.nearest_declaration_boundary == RustDeclarationBoundary::ModuleOrFile
        }));
    }

    #[test]
    fn named_properties_capture_each_supported_declaration_kind() {
        let source = r#"
pub struct Struct { pub struct_field: u8 }
enum Enum { Variant }
union Union { union_field: u8 }
trait Trait { type Associated; fn signature(&self); }
mod inline {}
mod external;
fn function() {}
const CONSTANT: u8 = 0;
static STATIC: u8 = 0;
macro_rules! declaration_macro { () => {}; }
type Alias = u8;
"#;
        let (parsed, source) = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let kind_for = |name: &str| {
            facts
                .rust_declaration_properties
                .iter()
                .find(|fact| declaration_name(&parsed, &source, fact.declaration) == Some(name))
                .map(|fact| fact.kind)
        };

        for (name, expected) in [
            ("Struct", RustDeclarationKind::Struct),
            ("Enum", RustDeclarationKind::Enum),
            ("Union", RustDeclarationKind::Union),
            ("Trait", RustDeclarationKind::Trait),
            ("inline", RustDeclarationKind::InlineModule),
            ("external", RustDeclarationKind::ExternalModule),
            ("function", RustDeclarationKind::Function),
            ("signature", RustDeclarationKind::FunctionSignature),
            ("struct_field", RustDeclarationKind::Field),
            ("Variant", RustDeclarationKind::EnumVariant),
            ("CONSTANT", RustDeclarationKind::Const),
            ("STATIC", RustDeclarationKind::Static),
            ("declaration_macro", RustDeclarationKind::Macro),
            ("Alias", RustDeclarationKind::TypeAlias),
            ("Associated", RustDeclarationKind::AssociatedType),
        ] {
            assert_eq!(
                kind_for(name),
                Some(expected),
                "missing or wrong kind for {name}"
            );
        }
    }

    #[test]
    fn trait_and_inherent_impl_members_keep_distinct_properties() {
        let source = r#"
struct Subject;
trait Trait {}
impl Trait for Subject { fn trait_method(&self) {} }
impl Subject { fn inherent_method(&self) {} }
"#;
        let (parsed, source) = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let member = |name: &str| {
            facts
                .rust_declaration_properties
                .iter()
                .find(|fact| declaration_name(&parsed, &source, fact.declaration) == Some(name))
                .expect("impl member property")
        };
        assert!(member("trait_method").trait_impl_member);
        assert!(!member("inherent_method").trait_impl_member);
    }

    #[test]
    fn exported_primary_and_embedded_macros_keep_exact_source_identity() {
        let source = r#"
#[macro_export]
macro_rules! primary_macro { () => {}; }
macro_rules! wrap { ($($item:item)*) => { $($item)* }; }
wrap! {
    #[macro_export]
    macro_rules! embedded_macro { () => {}; }
}
"#;
        let (parsed, source) = parse_fixture(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let linked = |name: &str| {
            parsed
                .source_declaration_units
                .iter()
                .find(|(_, unit)| unit.identifier() == name)
                .map(|(declaration, _)| {
                    facts
                        .rust_declaration_properties
                        .iter()
                        .find(|fact| fact.declaration == *declaration)
                        .expect("macro property")
                })
                .expect("linked macro declaration")
        };
        let primary = linked("primary_macro");
        let embedded = linked("embedded_macro");
        assert_ne!(primary.declaration, embedded.declaration);
        assert_eq!(primary.kind, RustDeclarationKind::Macro);
        assert_eq!(embedded.kind, RustDeclarationKind::Macro);
        assert!(primary.macro_exported);
        assert!(embedded.macro_exported);
        let macros = &parsed.rust_usage_facts.module_routes.item_macros;
        assert_eq!(
            macros
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            ["primary_macro", "wrap"]
        );
        assert_eq!(macros[0].declaration, primary.declaration);
        let primary_occurrence = facts
            .occurrences
            .declaration(primary.declaration)
            .occurrence;
        let embedded_occurrence = facts
            .occurrences
            .declaration(embedded.declaration)
            .occurrence;
        assert_eq!(
            facts.occurrences.occurrence(primary_occurrence).provenance,
            SourceOccurrenceProvenance::PrimaryNode
        );
        assert_eq!(
            facts.occurrences.occurrence(embedded_occurrence).provenance,
            SourceOccurrenceProvenance::Embedded
        );
        assert_eq!(
            declaration_name(&parsed, &source, primary.declaration),
            Some("primary_macro")
        );
        assert_eq!(
            declaration_name(&parsed, &source, embedded.declaration),
            Some("embedded_macro")
        );
    }
}

#[cfg(test)]
mod passthrough_macro_tests {
    use super::*;

    /// One source item inside a macro invocation is one source declaration.
    ///
    /// `lower_macro_bindings` states the invariant this pins
    /// (`crate::resolution`, "declaration replay owns the declarations an item
    /// macro expands to in this blob, and minting a second set beside them
    /// would give one source item two declarations"). It does not hold for an
    /// invocation whose definition is not visible: declaration replay mints an
    /// `Embedded` declaration carrying the `CodeUnit`, and
    /// `lower_definition_less_macro_arguments` parses the same argument group
    /// and lowers it through the ordinary fragment walk, minting a second
    /// `PrimaryNode` declaration that takes the native site and the bridge.
    ///
    /// The two then disagree: the first has the identifier, the unit and
    /// `ModuleOrFile`; the second has the definition site and
    /// `LocalBlockOrFunction`, because the argument group parses inside a
    /// block. `rust_crate_exports` joins declarations to bridges, so the item
    /// gets no export row and a qualified path answers a decided absence for an
    /// item that exists.
    ///
    /// No macro definition is visible in this fixture, which is the point: the
    /// split is not the passthrough path and does not depend on the classifier.
    #[test]
    fn a_macro_wrapped_item_is_one_source_declaration() {
        let source = "my_cfg! {\n    pub fn poll_proceed() -> u32 {\n        42\n    }\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(temp.path().canonicalize().unwrap(), "src/lib.rs");
        let parsed = parse_rust_file(&file, source, &tree);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let properties = &facts.rust_declaration_properties;
        assert_eq!(
            properties.len(),
            1,
            "one source item is one source declaration: {properties:?}"
        );
        let unit_declarations = facts.occurrences.declarations().len();
        assert_eq!(
            unit_declarations,
            1,
            "{:?}",
            facts.occurrences.declarations()
        );
        // No definition is visible, so nothing declares this item a second
        // time and nothing bridges a native site to one. What the invariant
        // forbids is a bridge naming a declaration other than the one the unit
        // is linked to, which is what the split produced.
        let stray = facts
            .native_declaration_sources
            .iter()
            .map(|&(_, declaration)| declaration)
            .filter(|declaration| *declaration != properties[0].declaration)
            .collect::<Vec<_>>();
        assert_eq!(
            stray,
            Vec::new(),
            "no bridge names a declaration the unit is not linked to: {:?}",
            facts.native_declaration_sources
        );
    }

    /// A proven-passthrough invocation's items are declared once and bridged.
    ///
    /// The macro is visible and every rule replays its item arguments, so the
    /// persisted lowering declares the items against the identity declaration
    /// replay gave them: one declaration for the item, carrying the unit, and a
    /// native definition site bridged to that same declaration. Without the
    /// bridge the crate rows have no export row for the item and a qualified
    /// path answers a decided absence for something that exists.
    #[test]
    fn proven_passthrough_items_are_declared_once_and_bridged() {
        let source = "macro_rules! my_cfg {\n    ($($item:item)*) => { $($item)* };\n}\n\nmy_cfg! {\n    pub fn poll_proceed() -> u32 {\n        42\n    }\n    pub mod child;\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(temp.path().canonicalize().unwrap(), "src/lib.rs");
        let parsed = parse_rust_file(&file, source, &tree);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let item = facts
            .rust_declaration_properties
            .iter()
            .filter(|property| format!("{:?}", property.kind) == "Function")
            .collect::<Vec<_>>();
        assert_eq!(item.len(), 1, "{:?}", facts.rust_declaration_properties);
        let bridged = facts
            .native_declaration_sources
            .iter()
            .any(|&(_, declaration)| declaration == item[0].declaration);
        assert!(
            bridged,
            "the item's declaration carries a native definition site: {:?} {:?}",
            facts.native_declaration_sources, item
        );
        // The `mod` in the same expansion is the route's to mount, and its name
        // is still a declaration the module above it exports. Both hold: one
        // declaration for it, and a site bridged to that declaration.
        let module = facts
            .rust_declaration_properties
            .iter()
            .filter(|property| format!("{:?}", property.kind) == "ExternalModule")
            .collect::<Vec<_>>();
        assert_eq!(module.len(), 1, "{:?}", facts.rust_declaration_properties);
        assert!(
            facts
                .native_declaration_sources
                .iter()
                .any(|&(_, declaration)| declaration == module[0].declaration),
            "the module's declaration carries a native definition site: {:?} {:?}",
            facts.native_declaration_sources,
            module
        );
    }

    #[test]
    fn item_passthrough_classifier_requires_a_safe_matcher_and_faithful_replay() {
        let source = r#"
macro_rules! replay { ($($item:item)*) => { $( #[cfg(any())] $item )* }; }
macro_rules! feature { (#![$meta:meta] $($item:item)*) => { $( #[$meta] $item )* }; }
macro_rules! base { ($($item:item)*) => { $( #[cfg(any())] $item )* }; }
macro_rules! delegated { ($($item:item)*) => { #[cfg(unix)] base! { $($item)* } }; }
macro_rules! attributed_nested { ($($item:item)*) => { #[allow(dead_code)] base! { $($item)* } }; }
macro_rules! dropped { ($($left:item)* $($right:item)*) => { $($left)* }; }
macro_rules! stringified { ($($item:item)*) => { stringify!($($item)*) }; }
macro_rules! nested { ($($item:item)*) => { wrapper! { $($item)* } }; }
macro_rules! mixed { ($name:ident, $item:item) => { $item }; }
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(temp.path().canonicalize().unwrap(), "src/lib.rs");
        let definitions = parse_rust_file(&file, source, &tree)
            .rust_usage_facts
            .module_routes
            .item_macros
            .into_iter()
            .map(|definition| (definition.name, definition.passthrough))
            .collect::<HashMap<_, _>>();

        for name in ["replay", "feature", "base", "delegated"] {
            assert_eq!(definitions.get(name), Some(&true), "{name}");
        }
        for name in [
            "attributed_nested",
            "dropped",
            "stringified",
            "nested",
            "mixed",
        ] {
            assert_eq!(definitions.get(name), Some(&false), "{name}");
        }
    }

    /// The activation a passthrough adds to each replayed item is read from
    /// the transcriber's attributes at the replay depth: `cfg` predicates are
    /// conjoined, documentation attributes add nothing, and anything else --
    /// or rules that disagree -- leaves it unknown.
    #[test]
    fn passthrough_decoration_records_added_cfg_and_nothing_else() {
        let source = r#"
macro_rules! plain { ($($item:item)*) => { $($item)* }; }
macro_rules! cfg_unix {
    ($($item:item)*) => {
        $(
            #[cfg(unix)]
            #[cfg_attr(docsrs, doc(cfg(unix)))]
            $item
        )*
    }
}
macro_rules! documented { ($($item:item)*) => { $( #[doc = "generated"] $item )* }; }
macro_rules! feature { (#![$meta:meta] $($item:item)*) => { $( #[$meta] $item )* }; }
macro_rules! allowed { ($($item:item)*) => { $( #[allow(dead_code)] $item )* }; }
macro_rules! conditional_allow {
    ($($item:item)*) => { $( #[cfg_attr(unix, allow(dead_code))] $item )* };
}
macro_rules! added { ($($item:item)*) => { $($item)* pub fn extra() {} }; }
macro_rules! disagree {
    ($item:item) => { #[cfg(windows)] $item };
    ($($item:item)*) => { $( #[cfg(unix)] $item )* };
}
macro_rules! delegated { ($($item:item)*) => { #[cfg(feature = "rt")] cfg_unix! { $($item)* } }; }
macro_rules! opaque { ($($item:item)*) => { unknown! { $($item)* } }; }
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(temp.path().canonicalize().unwrap(), "src/lib.rs");
        let definitions = parse_rust_file(&file, source, &tree)
            .rust_usage_facts
            .module_routes
            .item_macros
            .into_iter()
            .map(|definition| {
                (
                    definition.name,
                    (definition.passthrough, definition.decoration),
                )
            })
            .collect::<HashMap<_, _>>();
        let unix = RustCfgCondition::Atom("unix".into());
        for (name, expected) in [
            ("plain", (true, Some(RustCfgCondition::Always))),
            ("cfg_unix", (true, Some(unix.clone()))),
            ("documented", (true, Some(RustCfgCondition::Always))),
            ("feature", (true, None)),
            ("allowed", (true, None)),
            ("conditional_allow", (true, None)),
            ("added", (true, None)),
            ("disagree", (true, None)),
            (
                "delegated",
                (
                    true,
                    Some(RustCfgCondition::conjunction([
                        RustCfgCondition::Atom("feature = \"rt\"".into()),
                        unix.clone(),
                    ])),
                ),
            ),
            ("opaque", (false, None)),
        ] {
            assert_eq!(definitions.get(name), Some(&expected), "{name}");
        }
    }

    #[test]
    fn built_in_token_macros_are_not_item_passthroughs() {
        for name in [
            "cfg",
            "column",
            "compile_error",
            "concat",
            "env",
            "file",
            "include",
            "include_bytes",
            "include_str",
            "line",
            "module_path",
            "option_env",
            "stringify",
        ] {
            assert!(
                rust_builtin_macro_does_not_replay_item_arguments(name),
                "{name}"
            );
        }
        assert!(!rust_builtin_macro_does_not_replay_item_arguments(
            "external_cfg_items"
        ));
    }

    #[test]
    fn primitive_spelling_does_not_hide_a_user_types_impl_members() {
        let source = "pub struct f16; impl f16 { pub fn to_f32(&self) -> f32 { 0.0 } }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let file = ProjectFile::new(std::env::current_dir().unwrap(), "half.rs");
        let parsed = parse_rust_file(&file, source, &tree);
        assert!(
            parsed.children.iter().any(|(owner, members)| {
                owner.identifier() == "f16"
                    && members.iter().any(|member| member.identifier() == "to_f32")
            }),
            "the source-declared f16 must retain its impl members: {:?}",
            parsed.children
        );
    }

    #[test]
    fn declaration_expansion_uses_the_latest_visible_same_name_macro() {
        let source = r#"
macro_rules! wrapper { ($($item:item)*) => { $($item)* }; }
wrapper! { macro_rules! Before { () => {} } }
macro_rules! wrapper { (drop $name:ident) => {}; }
wrapper! { macro_rules! Phantom { () => {} } }
mod inline_scope {
    macro_rules! wrapper { ($($item:item)*) => { $($item)* }; }
    wrapper! { macro_rules! InlineGenerated { () => {} } }
}
wrapper! { macro_rules! OutsidePhantom { () => {} } }
other::wrapper! { macro_rules! QualifiedPhantom { () => {} } }
fn local_module() {
    mod nested_in_function {
        macro_rules! LocalOnly { ($($item:item)*) => { $($item)* }; }
    }
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        assert_eq!(
            parsed
                .rust_usage_facts
                .module_routes
                .item_macros
                .iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            ["wrapper", "wrapper", "wrapper"]
        );
        assert_eq!(
            parsed
                .rust_usage_facts
                .module_routes
                .item_macros
                .iter()
                .map(|definition| definition.passthrough)
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        let macros = parsed
            .top_level_declarations
            .iter()
            .chain(parsed.children.values().flatten())
            .filter(|unit| unit.is_macro())
            .map(|unit| unit.identifier())
            .collect::<HashSet<_>>();

        for expected in ["Before", "InlineGenerated"] {
            assert!(macros.contains(expected), "missing {expected}: {macros:?}");
        }
        for phantom in ["Phantom", "OutsidePhantom", "QualifiedPhantom"] {
            assert!(
                !macros.contains(phantom),
                "unexpected {phantom}: {macros:?}"
            );
        }
    }
}

#[cfg(test)]
mod test_region_taint_tests {
    use super::*;

    /// Parse `source` as `src/lib.rs` and return the set of short names for the
    /// declarations recorded in the per-declaration test-region taint side-map.
    fn tainted_short_names(source: &str) -> HashSet<String> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        parsed
            .test_region_units
            .iter()
            .map(|unit| unit.short_name().to_string())
            .collect()
    }

    #[test]
    fn inline_cfg_test_module_taints_only_the_test_symbols() {
        // The issue's exact shape: a production fn plus an inline
        // `#[cfg(test)] mod tests`. Production API must stay untainted.
        let tainted = tainted_short_names(
            r#"
pub fn make_widget() {}

#[cfg(test)]
mod tests {
    fn it_works() {}
}

pub fn after_tests() {}
"#,
        );
        assert!(tainted.contains("tests"), "{tainted:?}");
        assert!(tainted.contains("tests.it_works"), "{tainted:?}");
        assert!(!tainted.contains("make_widget"), "{tainted:?}");
        assert!(!tainted.contains("after_tests"), "{tainted:?}");
    }

    #[test]
    fn test_attributed_free_functions_are_tainted() {
        let tainted = tainted_short_names(
            r#"
#[test]
fn top_level_test() {}

#[tokio::test]
async fn tokio_test() {}

#[my_framework::test]
fn custom_last_segment_test() {}

pub fn production() {}
"#,
        );
        assert!(tainted.contains("top_level_test"), "{tainted:?}");
        assert!(tainted.contains("tokio_test"), "{tainted:?}");
        assert!(tainted.contains("custom_last_segment_test"), "{tainted:?}");
        assert!(!tainted.contains("production"), "{tainted:?}");
    }

    #[test]
    fn nested_modules_inside_cfg_test_inherit_the_taint() {
        let tainted = tainted_short_names(
            r#"
#[cfg(test)]
mod outer {
    mod inner {
        fn helper() {}
        struct Fixture {}
    }
}
"#,
        );
        for name in [
            "outer",
            "outer.inner",
            "outer.inner.helper",
            "outer.inner.Fixture",
        ] {
            assert!(tainted.contains(name), "missing {name}: {tainted:?}");
        }
    }

    #[test]
    fn cfg_all_test_feature_is_tainted_but_cfg_not_test_is_not() {
        let positive = tainted_short_names(
            r#"
#[cfg(all(test, feature = "x"))]
mod gated {
    fn used() {}
}
"#,
        );
        assert!(positive.contains("gated"), "{positive:?}");
        assert!(positive.contains("gated.used"), "{positive:?}");

        let negative = tainted_short_names(
            r#"
#[cfg(not(test))]
mod prod_only {
    fn used() {}
}
"#,
        );
        assert!(
            negative.is_empty(),
            "cfg(not(test)) must not taint: {negative:?}"
        );
    }

    #[test]
    fn production_symbol_after_a_test_module_is_untainted() {
        let tainted = tainted_short_names(
            r#"
#[cfg(test)]
mod tests {
    fn t() {}
}

pub struct Widget {}
"#,
        );
        assert!(tainted.contains("tests"), "{tainted:?}");
        assert!(!tainted.contains("Widget"), "{tainted:?}");
    }

    #[test]
    fn cfg_test_gated_macro_region_taints_reparsed_items() {
        // A `#[cfg(test)]`-gated item-position macro invocation taints the items
        // recovered through the #1015 reparse path, both when the attribute sits
        // on the invocation and when it guards an item *inside* the token tree.
        let tainted = tainted_short_names(
            r#"
macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }

#[cfg(test)]
passthrough! {
    fn generated_under_test() {}
    pub struct GeneratedFixture {}
}

passthrough! {
    #[cfg(test)]
    fn inner_gated_test() {}

    pub fn inner_production() {}
}
"#,
        );
        assert!(tainted.contains("generated_under_test"), "{tainted:?}");
        assert!(tainted.contains("GeneratedFixture"), "{tainted:?}");
        assert!(tainted.contains("inner_gated_test"), "{tainted:?}");
        assert!(!tainted.contains("inner_production"), "{tainted:?}");
    }

    #[test]
    fn test_impl_taints_members_not_the_owner_type() {
        let tainted = tainted_short_names(
            r#"
pub struct Widget {}

#[cfg(test)]
impl Widget {
    fn test_only_helper() {}
}
"#,
        );
        assert!(
            !tainted.contains("Widget"),
            "owner type must stay untainted: {tainted:?}"
        );
        assert!(
            tainted
                .iter()
                .any(|name| name.ends_with("test_only_helper")),
            "impl member should be tainted: {tainted:?}"
        );
    }
}

#[cfg(test)]
mod type_parameter_metadata_tests {
    use super::*;

    /// The recorded `(short_name, arity)` pairs of every declaration whose
    /// signature metadata read a type-parameter list.
    fn recorded_arities(source: &str) -> Vec<(String, usize)> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let mut recorded = parsed
            .signature_metadata
            .iter()
            .flat_map(|(unit, metadata)| {
                metadata
                    .iter()
                    .filter(|entry| entry.type_parameters_recorded())
                    .map(|entry| (unit.short_name().to_string(), entry.type_parameters().len()))
            })
            .collect::<Vec<_>>();
        recorded.sort();
        recorded
    }

    /// Every Rust type declaration records its own parameter list, so a
    /// nongeneric type is a proven zero rather than an unread list (#1651).
    /// Lifetimes and const generics are parameters of that list and count.
    #[test]
    fn rust_type_declarations_record_their_type_parameters() {
        let recorded = recorded_arities(
            r#"
pub struct Plain;
pub struct Generic<T> { pub value: T }
pub struct Pair<K, V> { pub key: K, pub value: V }
pub struct Borrowed<'a, T, const N: usize> { pub items: &'a [T; N] }
pub enum Choice<T> { Only(T) }
pub trait Marker {}
pub trait Convert<T> { fn convert(&self) -> T; }
pub type Alias<T> = Option<T>;
pub type Plainest = usize;
pub fn free<T>(value: T) -> T { value }
"#,
        );
        assert_eq!(
            recorded,
            vec![
                ("Alias".to_string(), 1),
                ("Borrowed".to_string(), 3),
                ("Choice".to_string(), 1),
                ("Convert".to_string(), 1),
                ("Generic".to_string(), 1),
                ("Marker".to_string(), 0),
                ("Pair".to_string(), 2),
                ("Plain".to_string(), 0),
                ("Plainest".to_string(), 0),
            ],
            "a callable's type parameters stay unrecorded; every type declaration records"
        );
    }
}
