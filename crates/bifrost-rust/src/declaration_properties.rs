use brokk_bifrost_core::analyzer::rust_facts::{
    RustCfgCondition, RustDeclarationBoundary, RustDeclarationKind, RustDeclarationPropertyFact,
};
use brokk_bifrost_core::analyzer::source_facts::{PrimarySourceFactCollector, SourceDeclarationId};
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

/// Item kinds which own a named declaration property. This deliberately does
/// not include local parameters or pattern bindings: those use the same
/// generic source-declaration id space but have no item visibility, cfg, or
/// value-constructor meaning.
pub(crate) fn is_rust_named_declaration_kind(kind: &str) -> bool {
    matches!(
        kind,
        "struct_item"
            | "enum_item"
            | "union_item"
            | "trait_item"
            | "mod_item"
            | "function_item"
            | "function_signature_item"
            | "field_declaration"
            | "enum_variant"
            | "const_item"
            | "static_item"
            | "macro_definition"
            | "type_item"
            | "associated_type"
    )
}

/// Producer-owned property rows for the live source-declaration arena. The
/// primary-node map lets native lowering request the exact declaration first
/// created by the declaration bridge; embedded nodes are recorded by their
/// already allocated declaration id and never enter this map.
pub(crate) struct RustDeclarationPropertyCollector<'source> {
    source: &'source str,
    rows: Vec<RustDeclarationPropertyFact>,
    by_declaration: HashMap<SourceDeclarationId, usize>,
    primary_by_node: HashMap<usize, SourceDeclarationId>,
    primary_cfg_conditions: HashMap<usize, RustCfgCondition>,
}

impl<'source> RustDeclarationPropertyCollector<'source> {
    pub(crate) fn new(source: &'source str) -> Self {
        Self {
            source,
            rows: Vec::new(),
            by_declaration: HashMap::default(),
            primary_by_node: HashMap::default(),
            primary_cfg_conditions: HashMap::default(),
        }
    }

    /// Ensure a property row for a primary named item and return its existing
    /// source declaration identity. This is called before native cfg gating so
    /// native-only named items receive the same creation-time interpretation as
    /// display-visible items.
    pub(crate) fn ensure_primary(
        &mut self,
        node: Node<'_>,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) -> Option<SourceDeclarationId> {
        if !is_rust_named_declaration_kind(node.kind()) {
            return None;
        }
        let name = node.child_by_field_name("name")?;
        if let Some(declaration) = self.primary_by_node.get(&node.id()).copied() {
            return Some(declaration);
        }

        let occurrence = source_collector.intern_node(node);
        let name = source_collector.intern_node(name);
        let declaration = source_collector.declare(occurrence, Some(name));
        self.record_primary(declaration, node);
        Some(declaration)
    }

    pub(crate) fn ensure_positional_field(
        &mut self,
        node: Node<'_>,
        visibility: crate::imports::RustVisibility,
        source_collector: &mut PrimarySourceFactCollector<'source>,
    ) -> SourceDeclarationId {
        assert_eq!(
            node.parent().unwrap().kind(),
            "ordered_field_declaration_list"
        );
        let occurrence = source_collector.intern_node(node);
        // A positional field has no name token. An empty anchor at the end
        // keeps declaration-name lookup from stealing the field's type token.
        let name = source_collector.intern_subspan_bytes(
            node.end_byte(),
            node.end_byte(),
            brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::ExplicitSubspan,
        );
        let declaration = source_collector.declare(occurrence, Some(name));
        self.record_primary(declaration, node);
        let index = self.by_declaration[&declaration];
        self.rows[index].visibility = visibility;
        declaration
    }

    /// Record a declaration created by the primary bridge. The bridge and the
    /// native producer may both request it; only the first request interprets
    /// the live AST.
    pub(crate) fn record_primary(&mut self, declaration: SourceDeclarationId, node: Node<'_>) {
        if let Some(existing) = self.primary_by_node.get(&node.id()).copied() {
            assert_eq!(
                existing, declaration,
                "one primary AST node cannot own two source declarations"
            );
            return;
        }
        self.primary_by_node.insert(node.id(), declaration);
        let condition = crate::lexical_scope::rust_effective_cfg_condition_with_cache(
            node,
            self.source,
            &mut self.primary_cfg_conditions,
        );
        self.record(declaration, node, condition);
    }

    /// Record a declaration created from an embedded replay tree. Embedded
    /// occurrence ids are already explicit and must remain distinct even when
    /// ranges or node ids happen to coincide.
    ///
    /// `host` is the ancestry of the invocation the tree was parsed for, in
    /// the tree that holds it, and `host_cfg` that invocation's effective
    /// `cfg`. An item replayed for an invocation written in
    /// an `impl` or trait body is that owner's member, and the replay tree's
    /// own root says nothing about it, so the item's ancestry continues into
    /// the host where the tree's root ends.
    pub(crate) fn record_embedded(
        &mut self,
        declaration: SourceDeclarationId,
        node: Node<'_>,
        host: RustDeclarationAncestry,
        host_cfg: &RustCfgCondition,
    ) {
        if self.by_declaration.contains_key(&declaration) {
            return;
        }
        // This path is used outside replay-tree collection. Keep its direct
        // structured walk and its early first-impl stop; replay trees opt into
        // the bounded, per-tree context cache below.
        let condition = RustCfgCondition::conjunction([
            host_cfg.clone(),
            crate::lexical_scope::rust_effective_cfg_condition(node, self.source),
        ]);
        self.record_with_ancestry(
            declaration,
            node,
            condition,
            RustDeclarationAncestry::of(node, Some(host)),
        );
    }

    pub(crate) fn record_embedded_with_cache(
        &mut self,
        declaration: SourceDeclarationId,
        node: Node<'_>,
        host: RustDeclarationAncestry,
        host_cfg: &RustCfgCondition,
        cfg_conditions: &mut HashMap<usize, RustCfgCondition>,
        declaration_ancestries: &mut HashMap<usize, RustDeclarationAncestry>,
    ) {
        if self.by_declaration.contains_key(&declaration) {
            return;
        }
        // The replay tree's own attributes, and the invocation's: an item the
        // expansion declares exists only where the invocation does.
        let condition = RustCfgCondition::conjunction([
            host_cfg.clone(),
            crate::lexical_scope::rust_effective_cfg_condition_with_cache(
                node,
                self.source,
                cfg_conditions,
            ),
        ]);
        self.record_with_ancestry(
            declaration,
            node,
            condition,
            RustDeclarationAncestry::of_with_cache(node, Some(host), declaration_ancestries),
        );
    }

    pub(crate) fn for_primary_node(&self, node: Node<'_>) -> Option<&RustDeclarationPropertyFact> {
        self.primary_by_node
            .get(&node.id())
            .and_then(|declaration| self.for_declaration(*declaration))
    }

    pub(crate) fn for_declaration(
        &self,
        declaration: SourceDeclarationId,
    ) -> Option<&RustDeclarationPropertyFact> {
        self.by_declaration
            .get(&declaration)
            .map(|index| &self.rows[*index])
    }

    pub(crate) fn into_rows(self) -> Vec<RustDeclarationPropertyFact> {
        self.rows
    }

    fn record(
        &mut self,
        declaration: SourceDeclarationId,
        node: Node<'_>,
        cfg_condition: RustCfgCondition,
    ) {
        self.record_with_ancestry(
            declaration,
            node,
            cfg_condition,
            RustDeclarationAncestry::of(node, None),
        );
    }

    fn record_with_ancestry(
        &mut self,
        declaration: SourceDeclarationId,
        node: Node<'_>,
        cfg_condition: RustCfgCondition,
        ancestry: RustDeclarationAncestry,
    ) {
        if self.by_declaration.contains_key(&declaration) {
            return;
        }
        let (has_impl_or_trait_ancestor, nearest_declaration_boundary, trait_impl_member) =
            ancestry.facts();
        let fact = RustDeclarationPropertyFact {
            declaration,
            kind: rust_declaration_kind(node),
            visibility: crate::imports::rust_item_visibility(node, self.source),
            cfg_condition,
            value_constructor: crate::graph_support::rust_value_constructor_properties(
                node,
                self.source,
            )
            .map(Box::new),
            macro_exported: node.kind() == "macro_definition"
                && crate::declarations::rust_item_has_simple_attribute(
                    node,
                    self.source,
                    "macro_export",
                ),
            has_impl_or_trait_ancestor,
            nearest_declaration_boundary,
            trait_impl_member,
            serde_helper_derive: crate::resolution::rust_item_serde_helper_derive(
                node,
                self.source,
            ),
        };
        let index = self.rows.len();
        assert!(
            self.by_declaration.insert(declaration, index).is_none(),
            "one source declaration has one Rust property row"
        );
        self.rows.push(fact);
    }
}

fn rust_declaration_kind(node: Node<'_>) -> RustDeclarationKind {
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "ordered_field_declaration_list")
    {
        return RustDeclarationKind::Field;
    }
    match node.kind() {
        "struct_item" => RustDeclarationKind::Struct,
        "enum_item" => RustDeclarationKind::Enum,
        "union_item" => RustDeclarationKind::Union,
        "trait_item" => RustDeclarationKind::Trait,
        "mod_item" if node.child_by_field_name("body").is_some() => {
            RustDeclarationKind::InlineModule
        }
        "mod_item" => RustDeclarationKind::ExternalModule,
        "function_item" => RustDeclarationKind::Function,
        "function_signature_item" => RustDeclarationKind::FunctionSignature,
        "field_declaration" => RustDeclarationKind::Field,
        "enum_variant" => RustDeclarationKind::EnumVariant,
        "const_item" => RustDeclarationKind::Const,
        "static_item" => RustDeclarationKind::Static,
        "macro_definition" => RustDeclarationKind::Macro,
        "type_item" => RustDeclarationKind::TypeAlias,
        "associated_type" => RustDeclarationKind::AssociatedType,
        kind => panic!("Rust declaration property has unsupported kind {kind:?}"),
    }
}

/// Capture the ownership distinctions used by definition-role resolution in
/// one ancestor walk. The free-function and module-alias predicates inspect
/// every ancestor, while module-value classification uses only the nearest
/// relevant boundary. The existing trait-impl predicate remains tied to the
/// first impl ancestor rather than to either of those answers.
/// The three ancestry facts of a declaration, as the walk outward from it
/// finds them: whether an `impl` or trait encloses it, the nearest declaration
/// boundary, and whether the first enclosing `impl` implements a trait.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RustDeclarationAncestry {
    has_impl_or_trait_ancestor: bool,
    nearest_declaration_boundary: Option<RustDeclarationBoundary>,
    first_impl_trait: Option<bool>,
    /// The first `impl` settles all three facts; farther ancestors cannot
    /// change either the nearest boundary or its trait flag.
    settled: bool,
}

impl RustDeclarationAncestry {
    /// Walk outward from `node`. With a `host`, `node` is in a replay tree:
    /// the tree's root is the invocation's token-tree interior, not a file, so
    /// the walk stops below it and continues with the host's ancestry.
    pub(crate) fn of(node: Node<'_>, host: Option<Self>) -> Self {
        let mut ancestry = Self::default();
        let mut parent = node.parent();
        while let Some(candidate) = parent {
            if host.is_some() && candidate.parent().is_none() {
                break;
            }
            match candidate.kind() {
                "impl_item" => {
                    ancestry.has_impl_or_trait_ancestor = true;
                    ancestry.first_impl_trait =
                        Some(candidate.child_by_field_name("trait").is_some());
                    ancestry
                        .nearest_declaration_boundary
                        .get_or_insert(RustDeclarationBoundary::Impl);
                    ancestry.settled = true;
                    return ancestry;
                }
                "trait_item" => {
                    ancestry.has_impl_or_trait_ancestor = true;
                    ancestry
                        .nearest_declaration_boundary
                        .get_or_insert(RustDeclarationBoundary::Trait);
                }
                "block" | "function_item" => {
                    ancestry
                        .nearest_declaration_boundary
                        .get_or_insert(RustDeclarationBoundary::LocalBlockOrFunction);
                }
                "mod_item" | "source_file" => {
                    ancestry
                        .nearest_declaration_boundary
                        .get_or_insert(RustDeclarationBoundary::ModuleOrFile);
                }
                _ => {}
            }
            parent = candidate.parent();
        }
        match host {
            Some(host) => Self {
                has_impl_or_trait_ancestor: ancestry.has_impl_or_trait_ancestor
                    || host.has_impl_or_trait_ancestor,
                nearest_declaration_boundary: ancestry
                    .nearest_declaration_boundary
                    .or(host.nearest_declaration_boundary),
                first_impl_trait: host.first_impl_trait,
                settled: host.settled,
            },
            None => ancestry,
        }
    }

    /// Compute one declaration's owner facts while memoizing the local parent
    /// context visited in this walk. Cache entries deliberately exclude the
    /// host: the same replay tree has one fixed host, and each entry can then
    /// be reused for every item while the host is merged at the leaf. The
    /// cache belongs to one replay tree and must not be shared across primary
    /// or sibling trees.
    pub(crate) fn of_with_cache(
        node: Node<'_>,
        host: Option<Self>,
        cache: &mut HashMap<usize, Self>,
    ) -> Self {
        if let Some(local) = cache.get(&node.id()).copied() {
            return Self::merge_host(local, host);
        }

        // `path` contains the unprocessed parents, nearest first. A replay
        // root has no parent, and therefore is the host boundary rather than
        // a declaration boundary of its own. With no host, retain the direct
        // walk's source-file boundary instead.
        let mut path = Vec::new();
        let mut candidate = node.parent();
        while let Some(parent) = candidate {
            if host.is_some() && parent.parent().is_none() {
                break;
            }
            path.push(parent);
            if cache.contains_key(&parent.id()) {
                break;
            }
            candidate = parent.parent();
        }

        let mut ancestry = path
            .last()
            .and_then(|parent| cache.get(&parent.id()).copied())
            .unwrap_or_default();
        for index in (0..path.len()).rev() {
            cache.insert(path[index].id(), ancestry);
            ancestry = Self::with_closer_parent(path[index], ancestry);
        }
        cache.insert(node.id(), ancestry);

        Self::merge_host(
            cache
                .get(&node.id())
                .copied()
                .expect("ancestry cache contains the requested node"),
            host,
        )
    }

    fn merge_host(local: Self, host: Option<Self>) -> Self {
        let Some(host) = host else {
            return local;
        };
        if local.first_impl_trait.is_some() {
            // The direct walk returns immediately at the first impl, so host
            // facts farther out cannot affect this result.
            return local;
        }
        Self {
            has_impl_or_trait_ancestor: local.has_impl_or_trait_ancestor
                || host.has_impl_or_trait_ancestor,
            nearest_declaration_boundary: local
                .nearest_declaration_boundary
                .or(host.nearest_declaration_boundary),
            first_impl_trait: host.first_impl_trait,
            settled: host.settled,
        }
    }

    /// Add one node whose facts are closer than `inherited`. This is the
    /// reverse of the direct walk's `get_or_insert`: while replay contexts are
    /// assembled from the outer boundary inward, every closer boundary wins.
    fn with_closer_parent(candidate: Node<'_>, inherited: Self) -> Self {
        let mut ancestry = inherited;
        match candidate.kind() {
            "impl_item" => {
                ancestry.has_impl_or_trait_ancestor = true;
                ancestry.nearest_declaration_boundary = Some(RustDeclarationBoundary::Impl);
                ancestry.first_impl_trait = Some(candidate.child_by_field_name("trait").is_some());
                ancestry.settled = true;
            }
            "trait_item" => {
                ancestry.has_impl_or_trait_ancestor = true;
                ancestry.nearest_declaration_boundary = Some(RustDeclarationBoundary::Trait);
            }
            "block" | "function_item" => {
                ancestry.nearest_declaration_boundary =
                    Some(RustDeclarationBoundary::LocalBlockOrFunction);
            }
            "mod_item" | "source_file" => {
                ancestry.nearest_declaration_boundary = Some(RustDeclarationBoundary::ModuleOrFile);
            }
            _ => {}
        }
        ancestry
    }

    fn facts(self) -> (bool, RustDeclarationBoundary, bool) {
        (
            self.has_impl_or_trait_ancestor,
            self.nearest_declaration_boundary
                .unwrap_or(RustDeclarationBoundary::ModuleOrFile),
            self.first_impl_trait.unwrap_or(false),
        )
    }
}

/// The common visibility projection of Rust's structured access policy.
pub(crate) fn declared_visibility(
    visibility: &brokk_bifrost_core::analyzer::rust_facts::RustVisibility,
) -> brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility {
    use brokk_bifrost_core::analyzer::rust_facts::RustVisibility;
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
    match visibility {
        RustVisibility::Public => DeclaredVisibility::Public,
        RustVisibility::Private => DeclaredVisibility::Private,
        _ => DeclaredVisibility::CrateOrModule,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_nodes<'tree>(root: Node<'tree>) -> Vec<Node<'tree>> {
        let mut nodes = Vec::new();
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
            nodes.push(node);
        }
        nodes
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        parser.parse(source, None).expect("parse Rust fixture")
    }

    fn assert_cached_matches_uncached(
        root: Node<'_>,
        host: Option<RustDeclarationAncestry>,
        cache: &mut HashMap<usize, RustDeclarationAncestry>,
    ) {
        for node in all_nodes(root) {
            let expected = RustDeclarationAncestry::of(node, host);
            let actual = RustDeclarationAncestry::of_with_cache(node, host, cache);
            assert_eq!(actual, expected, "ancestry mismatch for {}", node.kind());
        }
    }

    #[test]
    fn cached_ancestry_matches_nested_boundaries_and_host_boundary() {
        let source = r#"
struct Subject;
trait Trait {
    fn trait_method() {
        fn trait_nested() {}
    }
}
impl Trait for Subject {
    fn impl_method() {
        fn impl_nested() {}
    }
}
mod outer {
    fn module_function() {}
}
fn free() {}
"#;
        let tree = parse(source);
        let mut cache = HashMap::default();
        assert_cached_matches_uncached(tree.root_node(), None, &mut cache);

        let host = RustDeclarationAncestry {
            has_impl_or_trait_ancestor: true,
            nearest_declaration_boundary: Some(RustDeclarationBoundary::Impl),
            first_impl_trait: Some(true),
            settled: true,
        };
        let mut replay_cache = HashMap::default();
        assert_cached_matches_uncached(tree.root_node(), Some(host), &mut replay_cache);
    }

    #[test]
    fn replay_ancestry_caches_are_independent_for_sibling_trees() {
        let source = "wrap! { nested! { fn nested() {} } fn sibling() {} }";
        let tree = parse(source);
        let invocation = tree
            .root_node()
            .named_child(0)
            .expect("outer macro invocation");
        let mut graph = crate::declarations::build_rust_embedded_replay_graph(invocation, source)
            .expect("build embedded replay graph")
            .expect("nonempty replay interior");
        let (trees, source_maps) = graph.split_mut();
        assert_eq!(trees.len(), 2, "nested macro gets a sibling replay tree");
        for (tree, source_map) in trees.iter().zip(source_maps.iter()) {
            let mut cache = HashMap::default();
            assert_cached_matches_uncached(tree.root(), Some(source_map.host()), &mut cache);
        }
    }

    #[test]
    fn nearest_impl_classification_does_not_use_a_farther_trait_impl() {
        // Production deliberately does not admit all nested trait-body items.
        // Test this interpretation without expanding traversal membership.
        let source = "impl Trait for Subject { fn outer() { fn nested() {} impl Subject { fn inherent() {} } } }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut identities = PrimarySourceFactCollector::new(source);
        let mut properties = RustDeclarationPropertyCollector::new(source);
        let mut pending = vec![tree.root_node()];
        let mut names = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "function_item" {
                let name = node
                    .child_by_field_name("name")
                    .unwrap()
                    .utf8_text(source.as_bytes())
                    .unwrap();
                let declaration = properties.ensure_primary(node, &mut identities).unwrap();
                let property = properties.for_primary_node(node).unwrap();
                assert_eq!(property.declaration, declaration);
                assert_eq!(property.trait_impl_member, name != "inherent", "{name}");
                assert!(property.has_impl_or_trait_ancestor, "{name}");
                assert_eq!(
                    property.nearest_declaration_boundary,
                    match name {
                        "nested" => RustDeclarationBoundary::LocalBlockOrFunction,
                        _ => RustDeclarationBoundary::Impl,
                    },
                    "{name}",
                );
                names.push(name);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        names.sort_unstable();
        assert_eq!(names, ["inherent", "nested", "outer"]);
    }

    #[test]
    fn ancestry_properties_keep_any_impl_and_nearest_boundary_distinct() {
        let source = r#"
struct Subject;
trait Trait {
    const ASSOCIATED: u8 = 0;
    fn default_method() {
        const LOCAL: u8 = 0;
        fn nested() {}
    }
}
impl Subject {
    const INHERENT: u8 = 0;
    type Alias = u8;
}
fn free() {}
type ModuleAlias = u8;
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let mut source_collector = PrimarySourceFactCollector::new(source);
        let mut properties = RustDeclarationPropertyCollector::new(source);
        let mut facts = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if is_rust_named_declaration_kind(node.kind())
                && node.child_by_field_name("name").is_some()
            {
                let declaration = properties
                    .ensure_primary(node, &mut source_collector)
                    .expect("named declaration identity");
                let name = node
                    .child_by_field_name("name")
                    .expect("named declaration name")
                    .utf8_text(source.as_bytes())
                    .expect("declaration name text")
                    .to_owned();
                facts.push((
                    name,
                    properties
                        .for_declaration(declaration)
                        .expect("declaration property")
                        .clone(),
                ));
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }

        let fact = |name: &str| {
            facts
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, fact)| fact)
                .unwrap_or_else(|| panic!("missing property for {name}"))
        };
        assert_eq!(
            fact("free").nearest_declaration_boundary,
            RustDeclarationBoundary::ModuleOrFile
        );
        assert!(!fact("free").has_impl_or_trait_ancestor);
        assert_eq!(
            fact("ModuleAlias").nearest_declaration_boundary,
            RustDeclarationBoundary::ModuleOrFile
        );
        assert!(!fact("ModuleAlias").has_impl_or_trait_ancestor);
        assert_eq!(
            fact("default_method").nearest_declaration_boundary,
            RustDeclarationBoundary::Trait
        );
        assert!(fact("default_method").has_impl_or_trait_ancestor);
        assert_eq!(
            fact("ASSOCIATED").nearest_declaration_boundary,
            RustDeclarationBoundary::Trait
        );
        assert!(fact("ASSOCIATED").has_impl_or_trait_ancestor);
        assert_eq!(
            fact("LOCAL").nearest_declaration_boundary,
            RustDeclarationBoundary::LocalBlockOrFunction
        );
        assert!(fact("LOCAL").has_impl_or_trait_ancestor);
        assert_eq!(
            fact("nested").nearest_declaration_boundary,
            RustDeclarationBoundary::LocalBlockOrFunction
        );
        assert!(fact("nested").has_impl_or_trait_ancestor);
        assert_eq!(
            fact("INHERENT").nearest_declaration_boundary,
            RustDeclarationBoundary::Impl
        );
        assert!(fact("INHERENT").has_impl_or_trait_ancestor);
        assert_eq!(
            fact("Alias").nearest_declaration_boundary,
            RustDeclarationBoundary::Impl
        );
        assert!(fact("Alias").has_impl_or_trait_ancestor);
    }
}
