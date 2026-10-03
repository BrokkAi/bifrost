//! Extracting the per-file Rust usage facts from one parsed tree.
//!
//! The value types and their storage encoding live in
//! [`brokk_bifrost_core::analyzer::rust_facts`]; what is here is the walk that
//! fills them. They are extracted once, in `parse_rust_file`, from the tree
//! that pass already holds, and travel to the store as part of `ParsedFile` /
//! `FileState` like every other language-specific fact (`scala_exports`,
//! `cpp_template_metadata`, ...).
//!
//! Everything here is a function of the file's BYTES alone. Nothing may depend
//! on the file's path, because the store keys these rows by content hash and
//! two byte-identical files at different paths share one row set. Module names
//! are therefore relative to the file's own root module, and import/export
//! paths are the verbatim source spelling.

use std::collections::VecDeque;

use tree_sitter::Node;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
use brokk_bifrost_core::analyzer::rust_facts::{
    RUST_OCCURRENCE_CODE, RUST_OCCURRENCE_COMMENT, RUST_OCCURRENCE_MACRO, RUST_OCCURRENCE_STRING,
    RustDeclarationKind, RustDeclarationPropertyFact, RustExportFact, RustIdentifierOccurrence,
    RustImportTargetFact, RustIncludeBindingKind, RustIncludeEdgeFact, RustIncludeHostBindingFact,
    RustInnerAttributeSourceFact, RustMacroInvocationSourceFact, RustModuleDeclarationSourceFact,
    RustModuleFact, RustModuleInventorySourceFact, RustModuleRouteFact, RustModuleRouteFacts,
    RustModuleRouteSourceFact, RustModuleScopeFact, RustModuleScopeSourceFact,
    RustModuleSourceFacts, RustRulesItemMacroDefinition, RustUsageFacts, RustVisibility,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceImportId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::cargo_routes::rust_static_string_literal;
use crate::declaration_properties::RustDeclarationPropertyCollector;
use crate::declarations::{
    RustEmbeddedReplayGraph, RustEmbeddedReplayTree, RustEmbeddedSourceMap,
    ensure_embedded_source_declaration, rust_identifier_like_node_kind,
    rust_macro_invocation_arguments, rust_unqualified_macro_invocation_name,
};
use crate::imports::{RustImportBindingName, RustImportOwner, RustProjectedImport};
use crate::syntax::outer_attributes;

/// Canonical source metadata for the Rust module route surface. The source
/// declaration collector owns declaration identities; this collector only
/// records the module-specific interpretation at the same live AST creation
/// point and uses the replay graph's exact per-tree occurrence maps.
pub(crate) struct RustModuleSourceCollector<'source> {
    source: &'source str,
    root: SourceOccurrenceId,
    declarations: Vec<RustModuleDeclarationSourceFact>,
    declaration_indexes: HashMap<SourceDeclarationId, usize>,
    invocations: Vec<RustMacroInvocationSourceFact>,
    invocation_occurrences: HashSet<SourceOccurrenceId>,
    primary_invocations: HashMap<usize, SourceOccurrenceId>,
    scopes: Vec<RustModuleScopeSourceFact>,
    routes: Vec<RustModuleRouteSourceFact>,
    inner_attributes: Vec<RustInnerAttributeSourceFact>,
}

impl<'source> RustModuleSourceCollector<'source> {
    pub(crate) fn new(source: &'source str, root: SourceOccurrenceId) -> Self {
        Self {
            source,
            root,
            declarations: Vec::new(),
            declaration_indexes: HashMap::default(),
            invocations: Vec::new(),
            invocation_occurrences: HashSet::default(),
            primary_invocations: HashMap::default(),
            scopes: vec![RustModuleScopeSourceFact {
                parent: None,
                declaration: None,
                resolution_scope: Some(ResolutionScopeId::new(0)),
            }],
            routes: Vec::new(),
            inner_attributes: Vec::new(),
        }
    }

    /// Record the file's top-level inner attributes from the tree-sitter
    /// `inner_attribute_item` nodes that are direct children of the file.
    /// The name is the attribute's path; the arguments are the identifier and
    /// literal tokens directly inside its argument token tree. Nested token
    /// trees are not arguments of the attribute itself.
    pub(crate) fn record_inner_attributes(&mut self, root: Node<'_>) {
        let text = |node: Node<'_>| {
            self.source
                .get(node.start_byte()..node.end_byte())
                .expect("a tree-sitter node lies inside its source")
                .to_owned()
        };
        let mut cursor = root.walk();
        for item in root
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "inner_attribute_item")
        {
            let mut item_cursor = item.walk();
            let Some(attribute) = item
                .named_children(&mut item_cursor)
                .find(|node| node.kind() == "attribute")
            else {
                continue;
            };
            let Some(path) = attribute
                .named_child(0)
                .filter(|path| matches!(path.kind(), "identifier" | "scoped_identifier"))
            else {
                continue;
            };
            let mut arguments = Vec::new();
            if let Some(tokens) = attribute.child_by_field_name("arguments") {
                let mut token_cursor = tokens.walk();
                arguments.extend(
                    tokens
                        .named_children(&mut token_cursor)
                        .filter(|token| {
                            matches!(
                                token.kind(),
                                "identifier"
                                    | "string_literal"
                                    | "integer_literal"
                                    | "boolean_literal"
                            )
                        })
                        .map(text),
                );
            }
            self.inner_attributes.push(RustInnerAttributeSourceFact {
                name: text(path),
                arguments,
            });
        }
    }

    fn module_metadata(&self, node: Node<'_>) -> Option<(String, Option<String>, bool, bool)> {
        let name = node
            .child_by_field_name("name")
            .and_then(|name| self.source.get(name.byte_range()))
            .map(strip_raw_identifier_prefix)
            .filter(|name| !name.is_empty())?
            .to_string();
        Some((
            name,
            rust_path_attribute_value(node, self.source),
            crate::imports::rust_item_has_attribute(node, self.source, "macro_use"),
            rust_declaration_is_bare_cfg_test_gated(node, self.source),
        ))
    }

    fn record_declaration(
        &mut self,
        declaration: SourceDeclarationId,
        node: Node<'_>,
        body: Option<SourceOccurrenceId>,
    ) {
        assert_eq!(
            node.kind(),
            "mod_item",
            "module metadata requires a module AST node"
        );
        if self.declaration_indexes.contains_key(&declaration) {
            return;
        }
        let (name, path_attribute, macro_use, test_gated) = self
            .module_metadata(node)
            .expect("a canonical module declaration has a nonempty name");
        let index = self.declarations.len();
        assert!(
            self.declaration_indexes
                .insert(declaration, index)
                .is_none(),
            "one canonical module declaration row per source declaration"
        );
        self.declarations.push(RustModuleDeclarationSourceFact {
            declaration,
            name,
            body,
            path_attribute,
            macro_use,
            test_gated,
        });
    }

    pub(crate) fn record_primary_declaration(
        &mut self,
        declaration: SourceDeclarationId,
        node: Node<'_>,
        collector: &mut PrimarySourceFactCollector<'source>,
    ) {
        if self.declaration_indexes.contains_key(&declaration) {
            return;
        }
        let body = node
            .child_by_field_name("body")
            .map(|body| collector.intern_node(body));
        self.record_declaration(declaration, node, body);
    }

    pub(crate) fn record_embedded_declaration(
        &mut self,
        tree_id: usize,
        declaration: SourceDeclarationId,
        node: Node<'_>,
        collector: &mut PrimarySourceFactCollector<'source>,
        source_maps: &mut [RustEmbeddedSourceMap],
    ) {
        if self.declaration_indexes.contains_key(&declaration) {
            return;
        }
        let body = node
            .child_by_field_name("body")
            .map(|body| source_maps[tree_id].intern_node(body, collector));
        self.record_declaration(declaration, node, body);
    }

    pub(crate) fn ensure_primary_invocation(
        &mut self,
        node: Node<'_>,
        collector: &mut PrimarySourceFactCollector<'source>,
    ) -> Option<SourceOccurrenceId> {
        let name = rust_unqualified_macro_invocation_name(node, self.source)?;
        if let Some(occurrence) = self.primary_invocations.get(&node.id()).copied() {
            return Some(occurrence);
        }
        let occurrence = collector.intern_node(node);
        self.primary_invocations.insert(node.id(), occurrence);
        assert!(self.invocation_occurrences.insert(occurrence));
        self.invocations.push(RustMacroInvocationSourceFact {
            occurrence,
            name: name.to_string(),
        });
        Some(occurrence)
    }

    pub(crate) fn ensure_embedded_invocation(
        &mut self,
        tree_id: usize,
        node: Node<'_>,
        collector: &mut PrimarySourceFactCollector<'source>,
        source_maps: &mut [RustEmbeddedSourceMap],
    ) -> Option<SourceOccurrenceId> {
        let name = rust_unqualified_macro_invocation_name(node, self.source)?;
        let occurrence = source_maps[tree_id].intern_node(node, collector);
        if !self.invocation_occurrences.insert(occurrence) {
            return Some(occurrence);
        }
        self.invocations.push(RustMacroInvocationSourceFact {
            occurrence,
            name: name.to_string(),
        });
        Some(occurrence)
    }

    pub(crate) fn record_primary_scope(
        &mut self,
        parent: usize,
        declaration: SourceDeclarationId,
        resolution_scope: Option<ResolutionScopeId>,
    ) -> usize {
        assert!(parent < self.scopes.len());
        let scope = self.scopes.len();
        self.scopes.push(RustModuleScopeSourceFact {
            parent: Some(parent),
            declaration: Some(declaration),
            resolution_scope,
        });
        scope
    }

    pub(crate) fn record_primary_route(&mut self, scope: usize, declaration: SourceDeclarationId) {
        assert!(scope < self.scopes.len());
        self.routes.push(RustModuleRouteSourceFact {
            scope,
            declaration,
            gates: Vec::new(),
        });
    }

    pub(crate) fn finish(
        self,
        inventory: Vec<RustModuleInventorySourceFact>,
    ) -> RustModuleSourceFacts {
        assert!(
            !inventory.is_empty(),
            "Rust module inventory includes the root"
        );
        RustModuleSourceFacts {
            root: self.root,
            declarations: self.declarations,
            invocations: self.invocations,
            inventory,
            scopes: self.scopes,
            routes: self.routes,
            inner_attributes: self.inner_attributes,
        }
    }
}

/// Event-driven collection of Rust usage facts from the primary parser tree.
///
/// The production Rust parser driver calls [`Self::enter`] and [`Self::exit`]
/// for every primary node. Secondary item-macro fragments are coordinated with
/// declaration replay at each primary macro event, as they are an explicit
/// provenance surface rather than a second independent primary walk.
pub(crate) struct RustUsageFactCollector<'source> {
    source: &'source str,
    imports: Vec<RustProjectedImport>,
    masks: HashMap<&'source str, u32>,
    module_inventory: Vec<RustModuleInventoryEntry>,
    module_name_arena: Vec<String>,
    module_name_frames: Vec<usize>,
    route_scopes: Vec<usize>,
    route_active: Vec<bool>,
    token_tree_depth: usize,
    token_tree_frames: Vec<bool>,
    module_routes: RustModuleRouteFacts,
    pending_route_roots: VecDeque<usize>,
    route_batches: Vec<RustRouteBatch>,
    include_edges: Vec<RustIncludeEdgeFact>,
}

enum RustRouteBatchParent {
    Primary(usize),
    Batch { batch: usize, scope_local: usize },
}

struct RustRouteBatch {
    parent: RustRouteBatchParent,
    /// Scope ordinals are local to this batch: 0 is the inherited parent and
    /// 1..N index `scopes`. They are remapped when the batch is assembled.
    scopes: Vec<RustModuleScopeFact>,
    routes: Vec<RustModuleRouteFact>,
    source_scopes: Vec<RustModuleScopeSourceFact>,
    source_routes: Vec<RustModuleRouteSourceFact>,
    children: Vec<usize>,
}

struct RustModuleInventoryEntry {
    declaration: Option<SourceDeclarationId>,
    parent_scope: usize,
    module: RustModuleFact,
}

impl<'source> RustUsageFactCollector<'source> {
    pub(crate) fn new(root: Node<'_>, source: &'source str) -> Self {
        let root_scope = RustModuleScopeFact {
            parent: None,
            declaration: None,
            module_name: String::new(),
            path_attribute: None,
            visibility: RustVisibility::Private,
            imports_macros: true,
            resolution_scope: Some(ResolutionScopeId::new(0)),
            body_start: root.start_byte(),
            body_end: root.end_byte(),
        };
        Self {
            source,
            imports: Vec::new(),
            masks: HashMap::default(),
            module_inventory: vec![RustModuleInventoryEntry {
                declaration: None,
                parent_scope: 0,
                module: RustModuleFact {
                    module_name: String::new(),
                    is_inline: true,
                    start_byte: root.start_byte(),
                    end_byte: root.end_byte(),
                    cfg_condition: crate::lexical_scope::RustCfgCondition::Always,
                },
            }],
            module_name_arena: vec![String::new()],
            module_name_frames: vec![0],
            route_scopes: vec![0],
            route_active: vec![true],
            token_tree_depth: 0,
            token_tree_frames: Vec::new(),
            module_routes: RustModuleRouteFacts {
                scopes: vec![root_scope],
                routes: Vec::new(),
                item_macros: Vec::new(),
            },
            pending_route_roots: VecDeque::new(),
            route_batches: Vec::new(),
            include_edges: Vec::new(),
        }
    }

    pub(crate) fn primary_macro_route_needed(&self, node: Node<'_>) -> bool {
        node.kind() == "macro_invocation"
            && *self
                .route_active
                .last()
                .expect("Rust usage collector has a root route activity frame")
    }

    /// Consume one primary-tree event.
    pub(crate) fn enter(
        &mut self,
        node: Node<'_>,
        native_module_scope: Option<ResolutionScopeId>,
        projected_imports: Option<Vec<RustProjectedImport>>,
        primary_module_property: Option<&RustDeclarationPropertyFact>,
        primary_module_declaration: Option<SourceDeclarationId>,
        module_sources: &mut RustModuleSourceCollector<'source>,
    ) {
        let parent_scope = *self
            .route_scopes
            .last()
            .expect("Rust usage collector has a root route scope");
        let parent_module_index = *self
            .module_name_frames
            .last()
            .expect("Rust usage collector has a root module name frame");
        let route_parent_active = *self
            .route_active
            .last()
            .expect("Rust usage collector has a root route activity frame");
        let mut child_scope = parent_scope;
        let mut child_route_active = route_parent_active;

        self.collect_identifier_event(node);
        self.token_tree_frames.push(node.kind() == "token_tree");
        self.collect_import_event(node, projected_imports);
        self.collect_include_event(node);

        if route_parent_active && node.kind() == "macro_invocation" {
            // The primary route walk stops at a macro invocation. Its raw
            // replay graph is scanned by the coordinator after declaration
            // DFS, and only an owned route-batch id is retained here.
            child_route_active = false;
        } else if route_parent_active && node.kind() == "mod_item" {
            let Some(name_node) = node.child_by_field_name("name") else {
                self.push_frames(child_scope, child_route_active, parent_module_index);
                return;
            };
            let Some(name) = self
                .source
                .get(name_node.start_byte()..name_node.end_byte())
                .map(strip_raw_identifier_prefix)
                .filter(|name| !name.is_empty())
            else {
                self.push_frames(child_scope, child_route_active, parent_module_index);
                return;
            };
            let parent_module = &self.module_name_arena[parent_module_index];
            let full_module_name = if parent_module.is_empty() {
                name.to_string()
            } else {
                format!("{parent_module}.{name}")
            };
            let property = primary_module_property
                .expect("route-admitted primary module has canonical source properties");
            let declaration = primary_module_declaration
                .expect("route-admitted primary module has a source declaration");
            assert!(matches!(
                property.kind,
                RustDeclarationKind::InlineModule | RustDeclarationKind::ExternalModule
            ));
            match node.child_by_field_name("body") {
                Some(body) => {
                    self.module_inventory.push(RustModuleInventoryEntry {
                        declaration: Some(declaration),
                        parent_scope,
                        module: RustModuleFact {
                            module_name: full_module_name.clone(),
                            is_inline: true,
                            start_byte: body.start_byte(),
                            end_byte: body.end_byte(),
                            cfg_condition: property.cfg_condition.clone(),
                        },
                    });
                    let imports_macros = self.module_routes.scopes[parent_scope].imports_macros
                        && crate::imports::rust_item_has_attribute(node, self.source, "macro_use");
                    module_sources.record_primary_scope(
                        parent_scope,
                        declaration,
                        native_module_scope,
                    );
                    self.module_routes.scopes.push(RustModuleScopeFact {
                        parent: Some(parent_scope),
                        declaration: Some(declaration),
                        module_name: name.to_string(),
                        path_attribute: rust_path_attribute_value(node, self.source),
                        visibility: property.visibility.clone(),
                        imports_macros,
                        resolution_scope: native_module_scope,
                        body_start: body.start_byte(),
                        body_end: body.end_byte(),
                    });
                    child_scope = self.module_routes.scopes.len() - 1;
                    let child_module_name_index = self.module_name_arena.len();
                    self.module_name_arena.push(full_module_name);
                    self.push_frames(child_scope, child_route_active, child_module_name_index);
                    return;
                }
                None => {
                    self.module_inventory.push(RustModuleInventoryEntry {
                        declaration: Some(declaration),
                        parent_scope,
                        module: RustModuleFact {
                            module_name: full_module_name,
                            is_inline: false,
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            cfg_condition: property.cfg_condition.clone(),
                        },
                    });
                    module_sources.record_primary_route(parent_scope, declaration);
                    self.module_routes.routes.push(RustModuleRouteFact {
                        scope: parent_scope,
                        declaration,
                        module_name: name.to_string(),
                        path_attribute: rust_path_attribute_value(node, self.source),
                        visibility: property.visibility.clone(),
                        imports_macros: self.module_routes.scopes[parent_scope].imports_macros
                            && crate::imports::rust_item_has_attribute(
                                node,
                                self.source,
                                "macro_use",
                            ),
                        test_gated: rust_declaration_is_bare_cfg_test_gated(node, self.source),
                        cfg_condition: property.cfg_condition.clone(),
                        declaration_start: node.start_byte(),
                        declaration_end: node.end_byte(),
                        gates: Vec::new(),
                    });
                }
            }
        }
        self.push_frames(child_scope, child_route_active, parent_module_index);
    }

    pub(crate) fn collect_primary_macro_route(
        &mut self,
        node: Node<'_>,
        graph: &mut RustEmbeddedReplayGraph,
        source_collector: &mut PrimarySourceFactCollector<'source>,
        declaration_properties: &mut RustDeclarationPropertyCollector<'source>,
        module_sources: &mut RustModuleSourceCollector<'source>,
    ) {
        if graph.tree(graph.root_id()).root_node().has_error() {
            return;
        }
        let Some(root_gate) = module_sources.ensure_primary_invocation(node, source_collector)
        else {
            return;
        };
        let parent_scope = *self
            .route_scopes
            .last()
            .expect("Rust usage collector has a root route scope");
        let batch_id = self.route_batches.len();
        self.route_batches.push(RustRouteBatch {
            parent: RustRouteBatchParent::Primary(parent_scope),
            scopes: Vec::new(),
            routes: Vec::new(),
            source_scopes: Vec::new(),
            source_routes: Vec::new(),
            children: Vec::new(),
        });
        self.pending_route_roots.push_back(batch_id);
        let root_tree = graph.root_id();
        let (trees, source_maps) = graph.split_mut();
        self.collect_route_batches(
            trees,
            source_maps,
            batch_id,
            root_tree,
            vec![root_gate],
            source_collector,
            declaration_properties,
            module_sources,
        );
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "route replay coordinates several independent canonical fact sinks"
    )]
    fn collect_route_batches(
        &mut self,
        trees: &[RustEmbeddedReplayTree],
        source_maps: &mut [RustEmbeddedSourceMap],
        root_batch: usize,
        root_tree: usize,
        root_gates: Vec<SourceOccurrenceId>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
        declaration_properties: &mut RustDeclarationPropertyCollector<'source>,
        module_sources: &mut RustModuleSourceCollector<'source>,
    ) {
        let mut work = VecDeque::from([(root_batch, root_tree, root_gates)]);
        while let Some((batch_id, tree_id, gates)) = work.pop_front() {
            let mut pending = vec![(trees[tree_id].root(), 0usize)];
            while let Some((node, scope_local)) = pending.pop() {
                if node.kind() == "macro_invocation" {
                    let Some(child_tree) = trees[tree_id].child_tree(node) else {
                        continue;
                    };
                    if trees[child_tree].root().has_error() {
                        continue;
                    }
                    let Some(_) = rust_unqualified_macro_invocation_name(node, self.source) else {
                        continue;
                    };
                    let child_batch = self.route_batches.len();
                    self.route_batches.push(RustRouteBatch {
                        parent: RustRouteBatchParent::Batch {
                            batch: batch_id,
                            scope_local,
                        },
                        scopes: Vec::new(),
                        routes: Vec::new(),
                        source_scopes: Vec::new(),
                        source_routes: Vec::new(),
                        children: Vec::new(),
                    });
                    self.route_batches[batch_id].children.push(child_batch);
                    let mut child_gates = gates.clone();
                    let child_gate = module_sources
                        .ensure_embedded_invocation(tree_id, node, source_collector, source_maps)
                        .expect("qualified macro routes are not admitted");
                    child_gates.push(child_gate);
                    work.push_back((child_batch, child_tree, child_gates));
                    continue;
                }
                if node.kind() == "mod_item" {
                    let Some(name_node) = node.child_by_field_name("name") else {
                        continue;
                    };
                    let Some(name) = self
                        .source
                        .get(name_node.start_byte()..name_node.end_byte())
                        .map(strip_raw_identifier_prefix)
                        .filter(|name| !name.is_empty())
                    else {
                        continue;
                    };
                    let declaration = ensure_embedded_source_declaration(
                        tree_id,
                        node,
                        source_collector,
                        declaration_properties,
                        source_maps,
                    );
                    let property = declaration_properties
                        .for_declaration(declaration)
                        .expect("route module owns canonical source properties");
                    assert!(matches!(
                        property.kind,
                        RustDeclarationKind::InlineModule | RustDeclarationKind::ExternalModule
                    ));
                    module_sources.record_embedded_declaration(
                        tree_id,
                        declaration,
                        node,
                        source_collector,
                        source_maps,
                    );
                    let imports_macros = self.batch_scope_imports_macros(batch_id, scope_local)
                        && crate::imports::rust_item_has_attribute(node, self.source, "macro_use");
                    if let Some(body) = node.child_by_field_name("body") {
                        let child_scope = self.route_batches[batch_id].scopes.len() + 1;
                        self.route_batches[batch_id]
                            .scopes
                            .push(RustModuleScopeFact {
                                parent: Some(scope_local),
                                declaration: Some(declaration),
                                module_name: name.to_string(),
                                path_attribute: rust_path_attribute_value(node, self.source),
                                visibility: property.visibility.clone(),
                                imports_macros,
                                resolution_scope: None,
                                body_start: body.start_byte(),
                                body_end: body.end_byte(),
                            });
                        self.route_batches[batch_id].source_scopes.push(
                            RustModuleScopeSourceFact {
                                parent: Some(scope_local),
                                declaration: Some(declaration),
                                resolution_scope: None,
                            },
                        );
                        pending.push((body, child_scope));
                    } else {
                        self.route_batches[batch_id]
                            .routes
                            .push(RustModuleRouteFact {
                                scope: scope_local,
                                declaration,
                                module_name: name.to_string(),
                                path_attribute: rust_path_attribute_value(node, self.source),
                                visibility: property.visibility.clone(),
                                imports_macros,
                                test_gated: rust_declaration_is_bare_cfg_test_gated(
                                    node,
                                    self.source,
                                ),
                                cfg_condition: property.cfg_condition.clone(),
                                declaration_start: node.start_byte(),
                                declaration_end: node.end_byte(),
                                gates: Vec::new(),
                            });
                        self.route_batches[batch_id].source_routes.push(
                            RustModuleRouteSourceFact {
                                scope: scope_local,
                                declaration,
                                gates: gates.clone(),
                            },
                        );
                    }
                    continue;
                }
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                pending.extend(children.into_iter().map(|child| (child, scope_local)));
            }
        }
    }

    fn batch_scope_imports_macros(&self, batch_id: usize, scope_local: usize) -> bool {
        let mut batch_id = batch_id;
        let mut scope_local = scope_local;
        loop {
            if scope_local != 0 {
                return self.route_batches[batch_id].scopes[scope_local - 1].imports_macros;
            }
            match self.route_batches[batch_id].parent {
                RustRouteBatchParent::Primary(scope) => {
                    return self.module_routes.scopes[scope].imports_macros;
                }
                RustRouteBatchParent::Batch {
                    batch,
                    scope_local: parent_scope_local,
                } => {
                    batch_id = batch;
                    scope_local = parent_scope_local;
                }
            }
        }
    }

    /// Finish one primary stream and the explicitly queued item-macro streams.
    pub(crate) fn finish(
        mut self,
        item_macro_definitions: Vec<RustRulesItemMacroDefinition>,
        mut module_sources: RustModuleSourceCollector<'source>,
        source_facts: &brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
        declaration_properties: &[RustDeclarationPropertyFact],
    ) -> (RustUsageFacts, Vec<SourceImportId>, RustModuleSourceFacts) {
        self.finish_secondary_route_batches(&mut module_sources);
        self.module_routes.item_macros = item_macro_definitions;
        let import_targets = self.import_targets();
        self.module_inventory.sort_by(|left, right| {
            left.module
                .start_byte
                .cmp(&right.module.start_byte)
                .then_with(|| right.module.end_byte.cmp(&left.module.end_byte))
                .then_with(|| left.module.module_name.cmp(&right.module.module_name))
        });
        let inventory = self
            .module_inventory
            .iter()
            .map(|entry| RustModuleInventorySourceFact {
                declaration: entry.declaration,
                parent_scope: entry.parent_scope,
            })
            .collect::<Vec<_>>();
        let module_sources = module_sources.finish(inventory);
        let (modules, scopes, routes) =
            module_sources.materialize(source_facts, declaration_properties);
        self.module_routes.scopes = scopes;
        self.module_routes.routes = routes;
        let mut include_edges = self.include_edges;
        for edge in &mut include_edges {
            edge.host_bindings = include_host_bindings(&self.imports, edge.include_start);
        }
        include_edges.sort_by(|left, right| {
            left.relative_path
                .cmp(&right.relative_path)
                .then_with(|| left.include_start.cmp(&right.include_start))
        });
        include_edges.dedup_by(|left, right| {
            left.relative_path == right.relative_path
                && left.include_start == right.include_start
                && left.host_bindings == right.host_bindings
        });
        let identifier_occurrences = self
            .masks
            .into_iter()
            .map(|(identifier, context_mask)| RustIdentifierOccurrence {
                identifier: identifier.to_string(),
                context_mask,
            })
            .collect::<Vec<_>>();
        let mut identifier_occurrences = identifier_occurrences;
        identifier_occurrences.sort_by(|left, right| left.identifier.cmp(&right.identifier));
        let facts = RustUsageFacts {
            exports: extract_exports(&import_targets),
            import_targets,
            modules,
            identifier_occurrences,
            module_routes: self.module_routes,
            include_edges,
        };
        let mut module_import_ids = Vec::new();
        for projected in self
            .imports
            .into_iter()
            .filter(|projected| matches!(projected.owner, RustImportOwner::Module { .. }))
        {
            if let Some(source_import_id) = projected.source_import_id {
                module_import_ids.push(source_import_id);
            }
        }
        (facts, module_import_ids, module_sources)
    }

    pub(crate) fn exit(&mut self) {
        if self
            .token_tree_frames
            .pop()
            .expect("Rust usage token-tree frame exists")
        {
            self.token_tree_depth = self
                .token_tree_depth
                .checked_sub(1)
                .expect("Rust usage token-tree depth matches its frames");
        }
        assert!(
            self.route_scopes.pop().is_some(),
            "Rust usage route frame exists"
        );
        assert!(
            self.route_active.pop().is_some(),
            "Rust usage route activity frame exists"
        );
        assert!(
            self.module_name_frames.pop().is_some(),
            "Rust usage module frame exists"
        );
    }

    fn push_frames(&mut self, scope: usize, route_active: bool, module_name: usize) {
        self.route_scopes.push(scope);
        self.route_active.push(route_active);
        self.module_name_frames.push(module_name);
    }

    fn collect_identifier_event(&mut self, node: Node<'_>) {
        let inherited = if self.token_tree_depth > 0 {
            RUST_OCCURRENCE_MACRO
        } else {
            0
        };
        match node.kind() {
            kind if rust_identifier_like_node_kind(kind) => {
                let text = strip_raw_identifier_prefix(&self.source[node.byte_range()]);
                if !text.is_empty() {
                    *self.masks.entry(text).or_default() |= RUST_OCCURRENCE_CODE | inherited;
                }
            }
            "line_comment" | "block_comment" => {
                record_words(
                    &self.source[node.byte_range()],
                    RUST_OCCURRENCE_COMMENT,
                    &mut self.masks,
                );
            }
            "string_literal" | "raw_string_literal" | "char_literal" => {
                record_words(
                    &self.source[node.byte_range()],
                    RUST_OCCURRENCE_STRING,
                    &mut self.masks,
                );
            }
            "token_tree" => self.token_tree_depth += 1,
            _ => {}
        }
    }

    fn collect_import_event(
        &mut self,
        node: Node<'_>,
        projected_imports: Option<Vec<RustProjectedImport>>,
    ) {
        if matches!(node.kind(), "use_declaration" | "extern_crate_declaration") {
            self.imports.extend(
                projected_imports.expect("primary import events carry their shared projection"),
            );
        } else {
            assert!(
                projected_imports.is_none(),
                "non-import primary events do not carry an import projection"
            );
        }
    }

    fn collect_include_event(&mut self, node: Node<'_>) {
        if node.kind() != "macro_invocation"
            || rust_unqualified_macro_invocation_name(node, self.source) != Some("include")
        {
            return;
        }
        let Some(arguments) = rust_macro_invocation_arguments(node) else {
            return;
        };
        let Some(literal) = single_named_child(arguments) else {
            return;
        };
        let Some(relative_path) = rust_static_string_literal(literal, self.source) else {
            return;
        };
        if relative_path.is_empty() || std::path::Path::new(&relative_path).is_absolute() {
            return;
        }
        let Some(file_name) = std::path::Path::new(&relative_path)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            return;
        };
        self.include_edges.push(RustIncludeEdgeFact {
            file_name: file_name.to_string(),
            include_start: node.start_byte(),
            host_bindings: Vec::new(),
            relative_path,
        });
    }

    fn import_targets(&self) -> Vec<RustImportTargetFact> {
        self.imports
            .iter()
            .map(|projected| {
                let (owner_module, owner_start, owner_end, local_extent) = match &projected.owner {
                    RustImportOwner::Module { module, start, end } => {
                        (module.clone(), *start, *end, None)
                    }
                    RustImportOwner::LocalOnly {
                        module,
                        module_start,
                        module_end,
                        start,
                        end,
                    } => (
                        module.clone(),
                        *module_start,
                        *module_end,
                        Some((*start, *end)),
                    ),
                };
                let path = projected.import.path();
                let binding_name = projected.import.binding_name();
                let (module_path, imported_name, bound_name) = if binding_name.is_glob() {
                    (path.to_vec(), None, None)
                } else {
                    let (prefix, name) = path.split_last().map_or_else(
                        || (Vec::new(), None),
                        |(name, prefix)| (prefix.to_vec(), Some(name.clone())),
                    );
                    (prefix, name, binding_name.named().map(str::to_string))
                };
                RustImportTargetFact {
                    native_scope: None,
                    source_import_id: projected.source_import_id,
                    module_path,
                    bound_name,
                    imported_name,
                    is_glob: projected.import.info.is_wildcard,
                    leading_absolute: projected.import.info.is_global,
                    is_extern_crate: projected.import.is_extern_crate(),
                    is_macro_use: projected.import.is_macro_use,
                    visibility: projected.import.visibility.clone(),
                    cfg_condition: projected.cfg_condition.clone(),
                    owner_module,
                    owner_start,
                    owner_end,
                    local_extent,
                    source_occurrences: projected.source_occurrences,
                }
            })
            .collect()
    }

    fn finish_secondary_route_batches(
        &mut self,
        module_sources: &mut RustModuleSourceCollector<'source>,
    ) {
        let mut pending = std::mem::take(&mut self.pending_route_roots);
        let mut scope_maps: Vec<Option<Vec<usize>>> =
            (0..self.route_batches.len()).map(|_| None).collect();
        while let Some(batch_id) = pending.pop_front() {
            let parent_scope = match self.route_batches[batch_id].parent {
                RustRouteBatchParent::Primary(scope) => scope,
                RustRouteBatchParent::Batch { batch, scope_local } => scope_maps[batch]
                    .as_ref()
                    .expect("route batch parent is assembled before its child")[scope_local],
            };
            let (scopes, routes, source_scopes, source_routes, children) = {
                let batch = &mut self.route_batches[batch_id];
                (
                    std::mem::take(&mut batch.scopes),
                    std::mem::take(&mut batch.routes),
                    std::mem::take(&mut batch.source_scopes),
                    std::mem::take(&mut batch.source_routes),
                    std::mem::take(&mut batch.children),
                )
            };
            assert_eq!(
                scopes.len(),
                source_scopes.len(),
                "secondary DTO and canonical scopes share one local order"
            );
            assert_eq!(
                routes.len(),
                source_routes.len(),
                "secondary DTO and canonical routes share one local order"
            );
            let mut local_to_global = vec![parent_scope];
            let mut source_scopes = source_scopes.into_iter();
            for mut scope in scopes {
                let parent = local_to_global[scope
                    .parent
                    .expect("secondary route scopes always have a local parent")];
                scope.parent = Some(parent);
                let global = self.module_routes.scopes.len();
                self.module_routes.scopes.push(scope);
                let mut source_scope = source_scopes
                    .next()
                    .expect("canonical secondary scope follows its DTO scope");
                let source_parent = source_scope
                    .parent
                    .expect("secondary source scope has a local parent");
                source_scope.parent = Some(local_to_global[source_parent]);
                assert_eq!(
                    module_sources.scopes.len(),
                    self.module_routes.scopes.len() - 1,
                    "canonical and DTO scopes share one global order"
                );
                module_sources.scopes.push(source_scope);
                local_to_global.push(global);
            }
            assert!(source_scopes.next().is_none());
            let mut source_routes = source_routes.into_iter();
            for mut route in routes {
                route.scope = local_to_global[route.scope];
                self.module_routes.routes.push(route);
                let mut source_route = source_routes
                    .next()
                    .expect("canonical secondary route follows its DTO route");
                source_route.scope = local_to_global[source_route.scope];
                module_sources.routes.push(source_route);
            }
            assert!(source_routes.next().is_none());
            scope_maps[batch_id] = Some(local_to_global);
            pending.extend(children);
        }
        self.route_batches.clear();
    }
}

/// The file's import bindings whose lexical scope contains `include_start`.
///
/// The stored `module_specifier` is the written prefix; a glob binds no local
/// name and records `*`, matching what the route composition shadows on.
fn include_host_bindings(
    imports: &[RustProjectedImport],
    include_start: usize,
) -> Vec<RustIncludeHostBindingFact> {
    let mut bindings = Vec::new();
    for projected in imports {
        let (scope_start, scope_end) = match &projected.owner {
            RustImportOwner::Module { start, end, .. } => (*start, *end),
            RustImportOwner::LocalOnly {
                module_start,
                module_end,
                ..
            } => (*module_start, *module_end),
        };
        if !(scope_start <= include_start && include_start < scope_end) {
            continue;
        }
        let (local_name, module_specifier, imported_name, kind) =
            match projected.import.binding_name() {
                RustImportBindingName::Glob => (
                    "*".to_string(),
                    projected.import.path().join("::"),
                    None,
                    RustIncludeBindingKind::Glob,
                ),
                RustImportBindingName::Unnamed => continue,
                RustImportBindingName::Named(local_name)
                    if projected.import.is_extern_crate() || projected.import.path().len() <= 1 =>
                {
                    (
                        local_name.to_string(),
                        projected.import.path().join("::"),
                        None,
                        RustIncludeBindingKind::Namespace,
                    )
                }
                RustImportBindingName::Named(local_name) => {
                    let Some((imported_name, module_path)) = projected.import.path().split_last()
                    else {
                        continue;
                    };
                    (
                        local_name.to_string(),
                        module_path.join("::"),
                        Some(imported_name.clone()),
                        RustIncludeBindingKind::Named,
                    )
                }
            };
        if module_specifier.is_empty() {
            continue;
        }
        bindings.push(RustIncludeHostBindingFact {
            local_name,
            module_specifier,
            imported_name,
            scope_start,
            kind,
        });
    }
    bindings.sort_by(|left, right| {
        left.scope_start
            .cmp(&right.scope_start)
            .then_with(|| left.local_name.cmp(&right.local_name))
            .then_with(|| left.module_specifier.cmp(&right.module_specifier))
    });
    bindings.dedup();
    bindings
}

/// The one named child of `node`, or `None` when it has none or several.
fn single_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    let child = children.next()?;
    children.next().is_none().then_some(child)
}

/// The re-export subset of the import bindings: root-module `use` declarations
/// that are visible outside the file.
///
/// This is the same filter `export_index_of_declarations` applies to the same
/// declarations, so the persisted rows and the live projection agree. Local
/// `pub` declarations are the other half of that projection and are NOT
/// recorded here: they are already `code_units` rows, and their export status
/// is a visibility question over those rows rather than a path this file names.
fn extract_exports(import_targets: &[RustImportTargetFact]) -> Vec<RustExportFact> {
    import_targets
        .iter()
        .filter(|target| target.owner_module.is_empty() && target.local_extent.is_none())
        .filter(|target| {
            !matches!(
                target.visibility,
                RustVisibility::Private | RustVisibility::SelfModule
            )
        })
        .filter(|target| !(target.is_glob && target.module_path.is_empty()))
        .filter(|target| target.is_glob || target.imported_name.is_some())
        .map(|target| RustExportFact {
            source_import_id: target.source_import_id,
            exported_name: target.bound_name.clone(),
            source_path: target.module_path.join("::"),
            imported_name: target.imported_name.clone(),
            is_glob: target.is_glob,
        })
        .collect()
}

/// Record every identifier-shaped word in one opaque token's `text` under
/// `context`. A word starts with a letter or underscore and continues with
/// letters, digits, or underscores -- Rust identifier shape.
fn record_words<'source>(text: &'source str, context: u32, masks: &mut HashMap<&'source str, u32>) {
    let bytes = text.as_bytes();
    let mut start = None;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        let continues = byte.is_ascii_alphanumeric() || byte == b'_';
        match (start, continues) {
            (None, true) if byte.is_ascii_alphabetic() || byte == b'_' => start = Some(offset),
            (Some(begin), false) => {
                *masks.entry(&text[begin..offset]).or_default() |= context;
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        *masks.entry(&text[begin..]).or_default() |= context;
    }
}

fn rust_declaration_is_bare_cfg_test_gated(module: Node<'_>, source: &str) -> bool {
    outer_attributes(module)
        .any(|attribute_item| rust_attribute_is_bare_cfg_test(attribute_item, source))
}

fn rust_attribute_is_bare_cfg_test(attribute_item: Node<'_>, source: &str) -> bool {
    let mut item_cursor = attribute_item.walk();
    let Some(attribute) = attribute_item
        .named_children(&mut item_cursor)
        .find(|child| child.kind() == "attribute")
    else {
        return false;
    };
    let Some(path) = attribute.named_child(0) else {
        return false;
    };
    if path.kind() != "identifier" || source.get(path.start_byte()..path.end_byte()) != Some("cfg")
    {
        return false;
    }
    let Some(arguments) = attribute.child_by_field_name("arguments") else {
        return false;
    };
    let mut argument_cursor = arguments.walk();
    let mut tokens = arguments.named_children(&mut argument_cursor);
    let Some(token) = tokens.next() else {
        return false;
    };
    tokens.next().is_none()
        && token.kind() == "identifier"
        && source.get(token.start_byte()..token.end_byte()) == Some("test")
}

fn rust_path_attribute_value(module: Node<'_>, source: &str) -> Option<String> {
    for attribute_item in outer_attributes(module) {
        let Some(attribute) = attribute_item.named_child(0) else {
            continue;
        };
        let Some(path) = attribute.named_child(0) else {
            continue;
        };
        if source.get(path.start_byte()..path.end_byte()) != Some("path") {
            continue;
        }
        let value = attribute.child_by_field_name("value")?;
        return rust_static_string_literal(value, source).filter(|path| !path.is_empty());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
    use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;
    use tree_sitter::Parser;

    fn facts(source: &str) -> RustUsageFacts {
        parsed_file(source).rust_usage_facts
    }

    fn parsed_file(source: &str) -> ParsedFile {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("load rust grammar");
        let tree = parser.parse(source, None).expect("parse rust source");
        let temp = tempfile::tempdir().expect("temporary workspace");
        let file = ProjectFile::new(
            temp.path()
                .canonicalize()
                .expect("canonical temporary root"),
            "src/lib.rs",
        );
        crate::declarations::parse_rust_file(&file, source, &tree)
    }

    #[test]
    fn primary_module_routes_use_canonical_properties_for_every_named_route_module() {
        let source = r#"
#[cfg(feature = "first")]
pub mod repeated;
#[cfg(not(feature = "first"))]
mod repeated;
pub mod inline {}
pub(crate) mod external;
fn local_owner() {
    #[cfg(feature = "local")]
    mod local {}
}
"#;
        let parsed = parsed_file(source);
        let source_facts = parsed.source_facts.as_ref().expect("source facts");
        let properties = &source_facts.rust_declaration_properties;
        let declaration_name = |declaration| {
            let name = source_facts.occurrences.declaration(declaration).name?;
            let range = source_facts.occurrences.occurrence(name).range;
            source.get(range.start_byte..range.end_byte)
        };
        let property_for = |name: &str| {
            properties
                .iter()
                .filter(|property| declaration_name(property.declaration) == Some(name))
                .collect::<Vec<_>>()
        };

        let repeated = property_for("repeated");
        assert_eq!(repeated.len(), 2, "repeated properties: {properties:?}");
        assert_eq!(repeated[0].visibility, RustVisibility::Public);
        assert_eq!(repeated[1].visibility, RustVisibility::Private);
        assert!(matches!(
            &repeated[0].cfg_condition,
            RustCfgCondition::Atom(atom) if atom == "feature = \"first\""
        ));
        assert!(matches!(
            &repeated[1].cfg_condition,
            RustCfgCondition::NotAtom(atom) if atom == "feature = \"first\""
        ));
        assert_ne!(repeated[0].declaration, repeated[1].declaration);

        let routes = &parsed.rust_usage_facts.module_routes;
        let repeated_routes = routes
            .routes
            .iter()
            .filter(|route| route.module_name == "repeated")
            .collect::<Vec<_>>();
        assert_eq!(repeated_routes.len(), 2, "repeated routes: {routes:?}");
        assert_eq!(
            repeated_routes
                .iter()
                .map(|route| route.visibility.clone())
                .collect::<Vec<_>>(),
            vec![RustVisibility::Public, RustVisibility::Private]
        );
        assert_eq!(
            repeated_routes
                .iter()
                .map(|route| route.cfg_condition.clone())
                .collect::<Vec<_>>(),
            repeated
                .iter()
                .map(|property| property.cfg_condition.clone())
                .collect::<Vec<_>>()
        );

        let inline_property = property_for("inline");
        assert_eq!(inline_property.len(), 1);
        let inline_scope = routes
            .scopes
            .iter()
            .find(|scope| scope.module_name == "inline")
            .expect("inline module route scope");
        assert_eq!(&inline_scope.visibility, &inline_property[0].visibility);
        let inline_module = parsed
            .rust_usage_facts
            .modules
            .iter()
            .find(|module| module.module_name == "inline")
            .expect("inline module fact");
        assert_eq!(
            &inline_module.cfg_condition,
            &inline_property[0].cfg_condition
        );

        let external_property = property_for("external");
        assert_eq!(external_property.len(), 1);
        let external_route = routes
            .routes
            .iter()
            .find(|route| route.module_name == "external")
            .expect("external module route");
        assert_eq!(&external_route.visibility, &external_property[0].visibility);
        assert_eq!(
            &external_route.cfg_condition,
            &external_property[0].cfg_condition
        );

        let local_property = property_for("local");
        assert_eq!(local_property.len(), 1);
        let local_declaration = local_property[0].declaration;
        assert!(
            !parsed
                .source_declaration_units
                .iter()
                .any(|(declaration, _)| *declaration == local_declaration),
            "function-local route module must remain source-only"
        );
        assert!(
            source_facts
                .native_declaration_sources
                .iter()
                .any(|(_, declaration)| *declaration == local_declaration),
            "conditional function-local module retains its native declaration for activation"
        );
        assert!(
            parsed
                .rust_usage_facts
                .modules
                .iter()
                .any(|module| module.module_name == "local"),
            "route-only local module remains in the existing route membership"
        );
        assert!(matches!(
            &local_property[0].cfg_condition,
            RustCfgCondition::Atom(atom) if atom == "feature = \"local\""
        ));
    }

    #[test]
    fn route_union_keeps_builtin_and_local_modules_source_only() {
        let source = r#"
stringify! { pub mod generated; }
fn owner() { unknown! { mod local; } }
"#;
        let parsed = parsed_file(source);
        let source_facts = parsed.source_facts.as_ref().expect("source facts");
        let declaration_name = |declaration| {
            let name = source_facts.occurrences.declaration(declaration).name?;
            let range = source_facts.occurrences.occurrence(name).range;
            source.get(range.start_byte..range.end_byte)
        };
        let routes = &parsed.rust_usage_facts.module_routes.routes;
        assert_eq!(
            routes
                .iter()
                .map(|route| route.module_name.as_str())
                .collect::<Vec<_>>(),
            ["generated", "local"]
        );

        for name in ["generated", "local"] {
            let properties = source_facts
                .rust_declaration_properties
                .iter()
                .filter(|property| declaration_name(property.declaration) == Some(name))
                .collect::<Vec<_>>();
            assert_eq!(properties.len(), 1, "source-only property rows for {name}");
            let declaration = properties[0].declaration;
            assert!(
                !parsed
                    .source_declaration_units
                    .iter()
                    .any(|(candidate, _)| *candidate == declaration)
            );
            assert!(
                !source_facts
                    .native_declaration_sources
                    .iter()
                    .any(|(_, candidate)| *candidate == declaration)
            );
            let occurrence = source_facts.occurrences.declaration(declaration).occurrence;
            assert_eq!(
                source_facts.occurrences.occurrence(occurrence).provenance,
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
            );
        }
    }

    #[test]
    fn route_attributes_and_multibyte_names_match_canonical_properties() {
        for prefix in ["", "\u{feff}", "#!/usr/bin/env rust\n"] {
            let source = format!(
                "{prefix}#![allow(dead_code)]\nwrap! {{ #![allow(unused)] #[path = \"caf\u{e9}.rs\"] #[macro_use] #[cfg(feature = \"cafe-\u{e9}\")] pub mod caf\u{e9}; }}"
            );
            let parsed = parsed_file(&source);
            let source_facts = parsed.source_facts.as_ref().expect("source facts");
            let property = source_facts
                .rust_declaration_properties
                .iter()
                .find_map(|property| {
                    let name = source_facts
                        .occurrences
                        .declaration(property.declaration)
                        .name?;
                    let range = source_facts.occurrences.occurrence(name).range;
                    (source.get(range.start_byte..range.end_byte) == Some("caf\u{e9}"))
                        .then_some(property)
                })
                .expect("multibyte route property");
            assert!(matches!(
                &property.cfg_condition,
                RustCfgCondition::Atom(atom) if atom == "feature = \"cafe-\u{e9}\""
            ));
            let route = parsed
                .rust_usage_facts
                .module_routes
                .routes
                .iter()
                .find(|route| route.module_name == "caf\u{e9}")
                .expect("multibyte route");
            assert_eq!(&route.cfg_condition, &property.cfg_condition);
            assert_eq!(
                route.declaration_start,
                source.find("pub mod caf\u{e9}").expect("module byte range")
            );
            assert_eq!(
                route.declaration_end,
                route.declaration_start + "pub mod caf\u{e9};".len()
            );
            assert_eq!(route.path_attribute.as_deref(), Some("caf\u{e9}.rs"));
            assert!(route.imports_macros);
            let occurrence = source_facts
                .occurrences
                .declaration(property.declaration)
                .occurrence;
            let occurrence = source_facts.occurrences.occurrence(occurrence);
            assert_eq!(occurrence.range.start_byte, route.declaration_start);
            assert_eq!(occurrence.range.end_byte, route.declaration_end);
            assert_eq!(
                occurrence.provenance,
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
            );
        }
    }

    #[test]
    fn missing_macro_delimiters_keep_ast_ranges_and_exclude_qualified_invocations() {
        for source in [
            "outer! { mod kept;",
            "outer! { mod kept; ",
            "outer! { mod kept; \n",
        ] {
            let coordinated = parsed_file(source).rust_usage_facts.module_routes;
            let route = coordinated
                .routes
                .iter()
                .find(|route| route.module_name == "kept")
                .expect("missing-close route remains indexable");
            let expected_start = source.find("mod kept").expect("module bytes");
            let expected_end = expected_start + "mod kept;".len();
            assert_eq!(route.declaration_start, expected_start, "{source:?}");
            assert_eq!(route.declaration_end, expected_end, "{source:?}");
        }

        let source = "qualified::outer! { mod ignored; }";
        let coordinated = parsed_file(source).rust_usage_facts.module_routes;
        assert!(
            coordinated.routes.is_empty(),
            "qualified macro invocations are not module declarations: {coordinated:#?}"
        );
    }

    #[test]
    fn modules_record_the_file_root_and_every_declared_module() {
        let source = "mod detached;\nmod inline { mod nested { } }\n";
        let modules = facts(source).modules;
        let named: Vec<_> = modules
            .iter()
            .map(|module| (module.module_name.as_str(), module.is_inline))
            .collect();
        assert_eq!(
            named,
            vec![
                ("", true),
                ("detached", false),
                ("inline", true),
                ("inline.nested", true),
            ],
            "modules were {modules:?}"
        );
        assert_eq!(modules[0].start_byte, 0);
        assert_eq!(modules[0].end_byte, source.len());
    }

    #[test]
    fn import_targets_record_named_glob_aliased_and_local_bindings() {
        let source = "\
use alpha::beta::Gamma;
use alpha::beta::*;
use alpha::Delta as Epsilon;
mod inner {
    use crate::Zeta;
    fn f() {
        use crate::Eta;
        }
	    }
	";

        let targets = facts(source).import_targets;
        let described: Vec<_> = targets
            .iter()
            .map(|target| {
                (
                    target
                        .module_path
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    target.bound_name.as_deref(),
                    target.imported_name.as_deref(),
                    target.is_glob,
                    target.owner_module.as_str(),
                    target.local_extent.is_some(),
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (
                    vec!["alpha", "beta"],
                    Some("Gamma"),
                    Some("Gamma"),
                    false,
                    "",
                    false
                ),
                (vec!["alpha", "beta"], None, None, true, "", false),
                (
                    vec!["alpha"],
                    Some("Epsilon"),
                    Some("Delta"),
                    false,
                    "",
                    false
                ),
                (
                    vec!["crate"],
                    Some("Zeta"),
                    Some("Zeta"),
                    false,
                    "inner",
                    false
                ),
                (
                    vec!["crate"],
                    Some("Eta"),
                    Some("Eta"),
                    false,
                    "inner",
                    true
                ),
            ],
            "targets were {targets:?}"
        );
    }

    #[test]
    fn canonical_module_source_facts_materialize_the_existing_views() {
        let source = r###"#[macro_use]
pub mod inline {
    pub mod nested {}
}
outer! { pub struct Item; pub fn function() {} pub mod generated; inner! { mod nested_route; } }
"###;
        let parsed = parsed_file(source);
        let source_facts = parsed.source_facts.as_ref().expect("source facts");
        let modules = source_facts
            .rust_modules
            .as_ref()
            .expect("Rust parses publish module source facts");

        let root = source_facts.occurrences.occurrence(modules.root);
        assert_eq!(root.provenance, SourceOccurrenceProvenance::PrimaryNode);
        assert_eq!(root.range.start_byte, 0);
        assert_eq!(root.range.end_byte, source.len());
        assert_eq!(
            modules.inventory.first().map(|entry| entry.declaration),
            Some(None)
        );
        assert!(modules.declarations.iter().all(|declaration| {
            source_facts
                .rust_declaration_properties
                .iter()
                .any(|property| {
                    property.declaration == declaration.declaration
                        && matches!(
                            property.kind,
                            RustDeclarationKind::InlineModule | RustDeclarationKind::ExternalModule
                        )
                })
        }));
        assert_eq!(
            modules.declarations.len(),
            4,
            "non-module embedded declarations have no module metadata"
        );
        assert!(modules.declarations.iter().all(|declaration| {
            declaration.body.is_none_or(|body| {
                matches!(
                    source_facts.occurrences.occurrence(body).provenance,
                    SourceOccurrenceProvenance::PrimaryNode | SourceOccurrenceProvenance::Embedded
                )
            })
        }));
        assert!(modules.invocations.iter().all(|invocation| {
            source_facts
                .occurrences
                .occurrence(invocation.occurrence)
                .range
                .start_byte
                < source.len()
        }));
        assert!(modules.routes.iter().any(|route| !route.gates.is_empty()));

        let (materialized_modules, materialized_scopes, materialized_routes) = modules.materialize(
            &source_facts.occurrences,
            &source_facts.rust_declaration_properties,
        );
        assert_eq!(materialized_modules, parsed.rust_usage_facts.modules);
        assert_eq!(
            materialized_scopes,
            parsed.rust_usage_facts.module_routes.scopes
        );
        assert_eq!(
            materialized_routes,
            parsed.rust_usage_facts.module_routes.routes
        );
    }

    #[test]
    fn import_targets_preserve_each_leafs_absolute_anchor() {
        let source = "use {::root::absolute, local::relative};\nuse ::root::group::{one, *};\n";
        let targets = facts(source).import_targets;
        let described = targets
            .iter()
            .map(|target| {
                (
                    target
                        .module_path
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    target.imported_name.as_deref(),
                    target.leading_absolute,
                    target.is_glob,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            described,
            vec![
                (vec!["root"], Some("absolute"), true, false),
                (vec!["local"], Some("relative"), false, false),
                (vec!["root", "group"], Some("one"), true, false),
                (vec!["root", "group"], None, true, true),
            ]
        );
    }

    #[test]
    fn unnamed_imports_keep_the_target_without_a_local_binding() {
        let source = "pub use alpha::Trait as _;\nuse beta::Other as _;\n";
        let facts = facts(source);

        let described: Vec<_> = facts
            .import_targets
            .iter()
            .map(|target| {
                (
                    target
                        .module_path
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    target.bound_name.as_deref(),
                    target.imported_name.as_deref(),
                    target.is_glob,
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (vec!["alpha"], None, Some("Trait"), false),
                (vec!["beta"], None, Some("Other"), false),
            ],
            "targets were {:?}",
            facts.import_targets
        );
        assert_eq!(facts.exports.len(), 1);
        assert_eq!(facts.exports[0].exported_name, None);
        assert_eq!(facts.exports[0].source_path, "alpha");
        assert_eq!(facts.exports[0].imported_name.as_deref(), Some("Trait"));
        assert!(!facts.exports[0].is_glob);
    }

    #[test]
    fn exports_take_the_non_private_root_use_declarations_only() {
        let source = "\
use private::Hidden;
pub use alpha::Shown;
pub use alpha::Renamed as Visible;
pub(crate) use beta::*;
pub(self) use gamma::AlsoHidden;
mod inner {
    pub use delta::NotAFileExport;
}
";
        let exports = facts(source).exports;
        let described: Vec<_> = exports
            .iter()
            .map(|export| {
                (
                    export.exported_name.as_deref(),
                    export.source_path.as_str(),
                    export.imported_name.as_deref(),
                    export.is_glob,
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (Some("Shown"), "alpha", Some("Shown"), false),
                (Some("Visible"), "alpha", Some("Renamed"), false),
                (None, "beta", None, true),
            ],
            "exports were {exports:?}"
        );
    }

    #[test]
    fn identifier_occurrences_separate_code_comment_string_and_macro_contexts() {
        let source = "\
// mentions_in_comment
fn declared_in_code() {
    let _ = \"mentions_in_string\";
    println!(\"{}\", mentions_in_macro);
}
";
        let occurrences = facts(source).identifier_occurrences;
        let mask = |name: &str| {
            occurrences
                .iter()
                .find(|occurrence| occurrence.identifier == name)
                .unwrap_or_else(|| panic!("{name} missing from {occurrences:?}"))
                .context_mask
        };
        assert_eq!(mask("declared_in_code"), RUST_OCCURRENCE_CODE);
        assert_eq!(mask("mentions_in_comment"), RUST_OCCURRENCE_COMMENT);
        assert_eq!(mask("mentions_in_string"), RUST_OCCURRENCE_STRING);
        assert_eq!(
            mask("mentions_in_macro"),
            RUST_OCCURRENCE_CODE | RUST_OCCURRENCE_MACRO
        );
        assert!(
            occurrences
                .windows(2)
                .all(|pair| pair[0].identifier < pair[1].identifier),
            "occurrences must be deduped and sorted: {occurrences:?}"
        );
    }

    #[test]
    fn raw_identifiers_are_recorded_under_their_canonical_spelling() {
        let occurrences = facts("fn r#match() {}\n").identifier_occurrences;
        assert!(
            occurrences
                .iter()
                .any(|occurrence| occurrence.identifier == "match"),
            "raw identifier should canonicalize: {occurrences:?}"
        );
    }
}
