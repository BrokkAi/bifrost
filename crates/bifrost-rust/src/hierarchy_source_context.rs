//! Source-owned lexical context for Rust hierarchy resolution.
//!
//! This module interprets only persisted source facts: it does not parse
//! source text, inspect native import projections, or decide which contexts a
//! caller is allowed to use.

use crate::graph_support::RustCargoRouteError;
use crate::hierarchy::RustHierarchySourceFacts;
use crate::lexical_scope::insert_rust_source_import_binding;
use brokk_bifrost_core::analyzer::rust_facts::{RustSourceContextFact, RustSourceContextKind};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::analyzer::usages::model::ImportBinder;
use brokk_bifrost_core::hash::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContextPlacement {
    tree_root: SourceOccurrenceId,
    nearest_module_or_file_root: SourceOccurrenceId,
}

/// Owned indexes over one canonical hierarchy fact product.
///
/// The index deliberately owns no fact rows and has no lifetime tied to the
/// facts. This lets several consumers retain one canonical
/// `Arc<RustHierarchySourceFacts>` and share this bounded lookup state without
/// building a second snapshot or a self-referential value. A `FileRoot`
/// terminates the default context walk, including an embedded root whose
/// parent is the invoking source context. Thus ordinary source-context
/// lookups do not inherit the invoking inline module path or its imports;
/// callers needing the legacy macro-reader binder use the explicit
/// [`Self::primary_import_binder`] projection.
#[derive(Debug, Clone)]
pub struct RustSourceContextIndex {
    contexts: HashMap<SourceOccurrenceId, usize>,
    import_contexts: HashMap<SourceOccurrenceId, usize>,
    owner_contexts: HashMap<SourceDeclarationId, SourceOccurrenceId>,
    placements: HashMap<SourceOccurrenceId, ContextPlacement>,
    imports_by_anchor: HashMap<SourceOccurrenceId, Vec<usize>>,
    imports_without_context: Vec<usize>,
}

impl RustSourceContextIndex {
    /// Build indexes for one canonical fact product.
    ///
    /// Construction visits every context and import row once. The predicate
    /// is checked before each visited row so a cancelled request does not
    /// finish indexing a large source file.
    pub fn new(
        facts: &RustHierarchySourceFacts,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Self, RustCargoRouteError> {
        let mut contexts =
            HashMap::with_capacity_and_hasher(facts.items.contexts.len(), Default::default());
        let mut owner_contexts = HashMap::default();
        for (position, context) in facts.items.contexts.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            assert!(
                contexts.insert(context.context, position).is_none(),
                "one Rust source occurrence cannot own two contexts"
            );
            if let Some(owner) = context.owner {
                assert!(
                    owner_contexts.insert(owner, context.context).is_none(),
                    "one Rust source declaration cannot own two source contexts"
                );
            }
        }

        let mut import_contexts = HashMap::with_capacity_and_hasher(
            facts.items.import_contexts.len(),
            Default::default(),
        );
        for (position, import_context) in facts.items.import_contexts.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let context_position = contexts
                .get(&import_context.context)
                .copied()
                .expect("Rust source import context must point to a source context");
            assert!(
                import_contexts
                    .insert(import_context.declaration, position)
                    .is_none(),
                "one Rust import declaration cannot own two source contexts"
            );
            assert_eq!(
                facts.items.contexts[context_position].context, import_context.context,
                "Rust source import context position must identify its context"
            );
        }

        let mut index = Self {
            contexts,
            import_contexts,
            owner_contexts,
            placements: HashMap::with_capacity_and_hasher(
                facts.items.contexts.len(),
                Default::default(),
            ),
            imports_by_anchor: HashMap::default(),
            imports_without_context: Vec::new(),
        };
        index.build_placements(facts, keep_going)?;
        index.build_import_index(facts, keep_going)?;
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        Ok(index)
    }

    /// The first `FileRoot` reached from `context`, with embedded roots kept
    /// separate from their invoking primary tree.
    pub fn nearest_tree_root(
        &self,
        context: SourceOccurrenceId,
    ) -> Result<SourceOccurrenceId, RustCargoRouteError> {
        Ok(self.placement(context)?.tree_root)
    }

    /// Return the nearest module or file anchor for `context`.
    pub fn nearest_module_or_file_root(
        &self,
        context: SourceOccurrenceId,
    ) -> Result<SourceOccurrenceId, RustCargoRouteError> {
        Ok(self.placement(context)?.nearest_module_or_file_root)
    }

    /// Return the source context owned by `declaration`, if it owns one.
    pub fn owner_context(&self, declaration: SourceDeclarationId) -> Option<SourceOccurrenceId> {
        self.owner_contexts.get(&declaration).copied()
    }

    /// Look up a persisted context row by source occurrence identity.
    pub fn context<'facts>(
        &self,
        facts: &'facts RustHierarchySourceFacts,
        context: SourceOccurrenceId,
    ) -> Result<&'facts RustSourceContextFact, RustCargoRouteError> {
        let position = self
            .contexts
            .get(&context)
            .copied()
            .ok_or(RustCargoRouteError::Unavailable)?;
        let row = facts
            .items
            .contexts
            .get(position)
            .ok_or(RustCargoRouteError::Unavailable)?;
        assert_eq!(
            row.context, context,
            "Rust source context position must identify its context"
        );
        Ok(row)
    }

    /// Whether the nearest tree root is the primary parse tree. Publication
    /// and caller-specific admission remain outside this helper; this only
    /// exposes the structural root fact.
    pub fn is_primary(
        &self,
        facts: &RustHierarchySourceFacts,
        context: SourceOccurrenceId,
    ) -> Result<bool, RustCargoRouteError> {
        let root = self.nearest_tree_root(context)?;
        let root = self.context(facts, root)?;
        Ok(root.parent.is_none())
    }

    /// The full inline module path containing `context`.
    ///
    /// Module names are canonical local names. The context chain is walked
    /// iteratively and reversed into root-to-item order. A normal file root
    /// has the valid empty path. No rendered source text is parsed.
    pub fn module_path<'facts>(
        &self,
        facts: &'facts RustHierarchySourceFacts,
        context: SourceOccurrenceId,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Vec<&'facts str>, RustCargoRouteError> {
        let chain = self.context_chain(facts, context, keep_going)?;
        let mut path = Vec::new();
        for row in &chain {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            if row.kind != RustSourceContextKind::Module {
                continue;
            }
            let declaration = row.owner.ok_or(RustCargoRouteError::Unavailable)?;
            let name = facts
                .module_names
                .get(&declaration)
                .ok_or(RustCargoRouteError::Unavailable)?;
            if name.is_empty() {
                return Err(RustCargoRouteError::Unavailable);
            }
            path.push(name.as_str());
        }
        path.reverse();
        Ok(path)
    }

    /// Build the source import binder visible from `context`.
    ///
    /// Imports are selected by exact source-context identity and the nearest
    /// module/file anchor. The anchor index retains canonical fact order, so
    /// later bindings overwrite earlier ones exactly as the source binder
    /// does. No declaration-byte ordering is applied: forward imports are
    /// visible.
    pub fn visible_import_binder(
        &self,
        facts: &RustHierarchySourceFacts,
        context: SourceOccurrenceId,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<ImportBinder, RustCargoRouteError> {
        let chain = self.context_chain(facts, context, keep_going)?;
        let ancestors = chain
            .iter()
            .map(|context| context.context)
            .collect::<HashSet<_>>();
        let query_anchor = self.nearest_module_or_file_root(context)?;
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        if !self.imports_without_context.is_empty() {
            return Err(RustCargoRouteError::Unavailable);
        }
        let mut binder = ImportBinder::empty();

        for import_position in self
            .imports_by_anchor
            .get(&query_anchor)
            .into_iter()
            .flatten()
        {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let import = facts
                .imports
                .get(*import_position)
                .ok_or(RustCargoRouteError::Unavailable)?;
            let import_context_position = self
                .import_contexts
                .get(&import.declaration)
                .copied()
                .ok_or(RustCargoRouteError::Unavailable)?;
            let import_context = facts
                .items
                .import_contexts
                .get(import_context_position)
                .ok_or(RustCargoRouteError::Unavailable)?;
            assert_eq!(
                import_context.declaration, import.declaration,
                "Rust source import context position must identify its declaration"
            );
            if !ancestors.contains(&import_context.context) {
                continue;
            }
            insert_rust_source_import_binding(&mut binder, import);
        }
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        Ok(binder)
    }

    /// Build one binder per context in the visible chain, ordered from the
    /// queried context outward to its file root. Each binder contains only
    /// imports declared directly in that context. The anchor index is walked
    /// once and rows are distributed to their direct context binder, so a
    /// deep chain does not rescan its imports once per ancestor.
    pub fn visible_import_binders(
        &self,
        facts: &RustHierarchySourceFacts,
        context: SourceOccurrenceId,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Vec<(SourceOccurrenceId, ImportBinder)>, RustCargoRouteError> {
        let chain = self.context_chain(facts, context, keep_going)?;
        let ancestors = chain
            .iter()
            .map(|context| context.context)
            .collect::<HashSet<_>>();
        let query_anchor = self.nearest_module_or_file_root(context)?;
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        if !self.imports_without_context.is_empty() {
            return Err(RustCargoRouteError::Unavailable);
        }

        let mut binders = chain
            .iter()
            .map(|context| (context.context, ImportBinder::empty()))
            .collect::<HashMap<_, _>>();
        for import_position in self
            .imports_by_anchor
            .get(&query_anchor)
            .into_iter()
            .flatten()
        {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let import = facts
                .imports
                .get(*import_position)
                .ok_or(RustCargoRouteError::Unavailable)?;
            let import_context_position = self
                .import_contexts
                .get(&import.declaration)
                .copied()
                .ok_or(RustCargoRouteError::Unavailable)?;
            let import_context = facts
                .items
                .import_contexts
                .get(import_context_position)
                .ok_or(RustCargoRouteError::Unavailable)?;
            assert_eq!(
                import_context.declaration, import.declaration,
                "Rust source import context position must identify its declaration"
            );
            if !ancestors.contains(&import_context.context) {
                continue;
            }
            let binder = binders
                .get_mut(&import_context.context)
                .expect("visible import context is in the context chain");
            insert_rust_source_import_binding(binder, import);
        }

        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }

        chain
            .into_iter()
            .map(|context| {
                let context_id = context.context;
                let binder = binders
                    .remove(&context_id)
                    .expect("every visible context has one binder");
                Ok((context_id, binder))
            })
            .collect()
    }

    /// Build the binder used by a declaration whose syntax was replayed from
    /// a macro interior. The module path remains relative to the replay tree,
    /// but the old hierarchy reader resolved imports in the original source
    /// tree at the macro invocation. Follow embedded roots back through their
    /// invoking contexts before selecting that binder.
    pub fn primary_import_binder(
        &self,
        facts: &RustHierarchySourceFacts,
        context: SourceOccurrenceId,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<ImportBinder, RustCargoRouteError> {
        let mut current = context;
        loop {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let root = self.nearest_tree_root(current)?;
            let root = self.context(facts, root)?;
            let Some(parent) = root.parent else {
                return self.visible_import_binder(facts, current, keep_going);
            };
            current = parent;
        }
    }

    fn build_placements(
        &mut self,
        facts: &RustHierarchySourceFacts,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<(), RustCargoRouteError> {
        for row in &facts.items.contexts {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            if let Some(parent) = row.parent {
                assert!(
                    self.placements.contains_key(&parent),
                    "Rust source contexts are parent-before-child"
                );
            }
            let (tree_root, nearest_module_or_file_root) =
                if row.kind == RustSourceContextKind::FileRoot {
                    // An embedded root may retain its invoking context as a
                    // parent, but it starts a new lexical tree here.
                    (row.context, row.context)
                } else {
                    let parent = row
                        .parent
                        .expect("non-root Rust context must have a parent");
                    let parent_placement = self
                        .placements
                        .get(&parent)
                        .copied()
                        .expect("Rust source contexts are parent-before-child");
                    let nearest = if row.kind == RustSourceContextKind::Module {
                        row.context
                    } else {
                        parent_placement.nearest_module_or_file_root
                    };
                    (parent_placement.tree_root, nearest)
                };
            assert!(
                self.placements
                    .insert(
                        row.context,
                        ContextPlacement {
                            tree_root,
                            nearest_module_or_file_root,
                        },
                    )
                    .is_none(),
                "one Rust source occurrence cannot own two placements"
            );
        }
        Ok(())
    }

    fn build_import_index(
        &mut self,
        facts: &RustHierarchySourceFacts,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<(), RustCargoRouteError> {
        for (position, import) in facts.imports.iter().enumerate() {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let Some(import_context_position) =
                self.import_contexts.get(&import.declaration).copied()
            else {
                self.imports_without_context.push(position);
                continue;
            };
            let import_context = facts
                .items
                .import_contexts
                .get(import_context_position)
                .expect("Rust source import context position must identify its row");
            assert_eq!(
                import_context.declaration, import.declaration,
                "Rust source import context position must identify its declaration"
            );
            let anchor = self.nearest_module_or_file_root(import_context.context)?;
            self.imports_by_anchor
                .entry(anchor)
                .or_default()
                .push(position);
        }
        Ok(())
    }

    fn placement(
        &self,
        context: SourceOccurrenceId,
    ) -> Result<ContextPlacement, RustCargoRouteError> {
        self.placements
            .get(&context)
            .copied()
            .ok_or(RustCargoRouteError::Unavailable)
    }

    pub fn context_chain<'facts>(
        &self,
        facts: &'facts RustHierarchySourceFacts,
        context: SourceOccurrenceId,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Vec<&'facts RustSourceContextFact>, RustCargoRouteError> {
        let mut chain = Vec::new();
        let mut current = context;
        loop {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            let row = self.context(facts, current)?;
            chain.push(row);
            if row.kind == RustSourceContextKind::FileRoot {
                return Ok(chain);
            }
            current = row.parent.ok_or(RustCargoRouteError::Unavailable)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declarations::parse_rust_file;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;
    use brokk_bifrost_core::analyzer::parsed_file::{SourceImportFact, SourceImportPathFact};
    use brokk_bifrost_core::analyzer::rust_facts::{
        RustItemImportContextFact, RustItemSourceFacts,
    };

    fn occurrence(index: u32) -> SourceOccurrenceId {
        SourceOccurrenceId::new(index)
    }

    fn declaration(index: u32) -> SourceDeclarationId {
        SourceDeclarationId::new(index)
    }

    fn import(declaration: SourceOccurrenceId, module: &str) -> SourceImportFact {
        SourceImportFact {
            declaration,
            target: None,
            alias_occurrence: None,
            statement: format!("use crate::{module}::Thing;"),
            is_wildcard: false,
            is_global: false,
            is_macro_use: false,
            identifier: Some("Thing".to_string()),
            alias: None,
            path: Some(SourceImportPathFact {
                kind: Some(StructuredImportPathKind::ImportFrom),
                segments: vec!["crate".to_string(), module.to_string(), "Thing".to_string()],
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
            }),
        }
    }

    fn facts() -> RustHierarchySourceFacts {
        let root = occurrence(0);
        let module = occurrence(1);
        let body = occurrence(2);
        let function = occurrence(3);
        let embedded_root = occurrence(4);
        let embedded_function = occurrence(5);
        let root_import = occurrence(10);
        let module_import = occurrence(11);
        let module_override = occurrence(12);
        let embedded_import = occurrence(13);
        let module_declaration = declaration(0);
        let items = RustItemSourceFacts {
            contexts: vec![
                RustSourceContextFact {
                    context: root,
                    parent: None,
                    owner: None,
                    kind: RustSourceContextKind::FileRoot,
                },
                RustSourceContextFact {
                    context: module,
                    parent: Some(root),
                    owner: Some(module_declaration),
                    kind: RustSourceContextKind::Module,
                },
                RustSourceContextFact {
                    context: body,
                    parent: Some(module),
                    owner: None,
                    kind: RustSourceContextKind::DeclarationBody,
                },
                RustSourceContextFact {
                    context: function,
                    parent: Some(body),
                    owner: None,
                    kind: RustSourceContextKind::Function,
                },
                RustSourceContextFact {
                    context: embedded_root,
                    parent: Some(module),
                    owner: None,
                    kind: RustSourceContextKind::FileRoot,
                },
                RustSourceContextFact {
                    context: embedded_function,
                    parent: Some(embedded_root),
                    owner: None,
                    kind: RustSourceContextKind::Function,
                },
            ],
            import_contexts: vec![
                RustItemImportContextFact {
                    declaration: root_import,
                    context: root,
                },
                RustItemImportContextFact {
                    declaration: module_import,
                    context: module,
                },
                RustItemImportContextFact {
                    declaration: module_override,
                    context: module,
                },
                RustItemImportContextFact {
                    declaration: embedded_import,
                    context: embedded_root,
                },
            ],
            ..RustItemSourceFacts::default()
        };
        let mut module_names = HashMap::default();
        module_names.insert(module_declaration, "outer".to_string());
        RustHierarchySourceFacts {
            items,
            types: Vec::new(),
            declarations: Vec::new(),
            declaration_units: Vec::new(),
            module_names,
            imports: vec![
                import(root_import, "root"),
                import(module_import, "first"),
                import(module_override, "second"),
                import(embedded_import, "embedded"),
            ],
        }
    }

    #[test]
    fn module_path_root_and_embedded_tree_do_not_inherit_parent_module() {
        let facts = facts();
        let contexts = RustSourceContextIndex::new(&facts, &|| true).unwrap();
        assert_eq!(
            contexts
                .module_path(&facts, occurrence(3), &|| true)
                .unwrap(),
            vec!["outer"]
        );
        assert!(
            contexts
                .module_path(&facts, occurrence(0), &|| true)
                .unwrap()
                .is_empty()
        );
        assert!(
            contexts
                .module_path(&facts, occurrence(5), &|| true)
                .unwrap()
                .is_empty()
        );
        assert!(contexts.is_primary(&facts, occurrence(3)).unwrap());
        assert!(!contexts.is_primary(&facts, occurrence(5)).unwrap());
        assert_eq!(
            contexts.nearest_tree_root(occurrence(5)).unwrap(),
            occurrence(4)
        );
    }

    #[test]
    fn binder_uses_ancestor_contexts_same_module_anchor_and_canonical_order() {
        let facts = facts();
        let contexts = RustSourceContextIndex::new(&facts, &|| true).unwrap();
        let binder = contexts
            .visible_import_binder(&facts, occurrence(3), &|| true)
            .unwrap();
        assert_eq!(
            binder.bindings.get("Thing").unwrap().module_specifier,
            "crate::second"
        );

        let root_binder = contexts
            .visible_import_binder(&facts, occurrence(0), &|| true)
            .unwrap();
        assert_eq!(
            root_binder.bindings.get("Thing").unwrap().module_specifier,
            "crate::root"
        );

        let embedded_binder = contexts
            .visible_import_binder(&facts, occurrence(5), &|| true)
            .unwrap();
        assert_eq!(
            embedded_binder
                .bindings
                .get("Thing")
                .unwrap()
                .module_specifier,
            "crate::embedded"
        );
        let primary_binder = contexts
            .primary_import_binder(&facts, occurrence(5), &|| true)
            .unwrap();
        assert_eq!(
            primary_binder
                .bindings
                .get("Thing")
                .unwrap()
                .module_specifier,
            "crate::second"
        );
    }

    #[test]
    fn index_exposes_owner_rows_anchors_and_direct_binders() {
        let facts = facts();
        let contexts = RustSourceContextIndex::new(&facts, &|| true).unwrap();
        assert_eq!(contexts.owner_context(declaration(0)), Some(occurrence(1)));
        assert_eq!(
            contexts.context(&facts, occurrence(1)).unwrap().owner,
            Some(declaration(0))
        );
        assert_eq!(
            contexts.nearest_module_or_file_root(occurrence(3)).unwrap(),
            occurrence(1)
        );

        let binders = contexts
            .visible_import_binders(&facts, occurrence(3), &|| true)
            .unwrap();
        assert_eq!(
            binders
                .iter()
                .map(|(context, _)| *context)
                .collect::<Vec<_>>(),
            vec![occurrence(3), occurrence(2), occurrence(1), occurrence(0)]
        );
        assert!(binders[0].1.bindings.is_empty());
        assert_eq!(
            binders[2].1.bindings.get("Thing").unwrap().module_specifier,
            "crate::second"
        );
        assert!(
            binders[3].1.bindings.is_empty(),
            "imports outside the query's module anchor are not visible"
        );
    }

    #[test]
    fn construction_and_context_walk_honor_cancellation() {
        let facts = facts();
        assert!(matches!(
            RustSourceContextIndex::new(&facts, &|| false),
            Err(RustCargoRouteError::Cancelled)
        ));

        let contexts = RustSourceContextIndex::new(&facts, &|| true).unwrap();
        assert_eq!(
            contexts.module_path(&facts, occurrence(3), &|| false),
            Err(RustCargoRouteError::Cancelled)
        );
        assert!(matches!(
            contexts.visible_import_binders(&facts, occurrence(3), &|| false),
            Err(RustCargoRouteError::Cancelled)
        ));
    }

    #[test]
    fn missing_module_name_and_import_context_are_unavailable() {
        let mut missing_name = facts();
        missing_name.module_names.clear();
        let contexts = RustSourceContextIndex::new(&missing_name, &|| true).unwrap();
        assert_eq!(
            contexts.module_path(&missing_name, occurrence(3), &|| true),
            Err(RustCargoRouteError::Unavailable)
        );

        let mut facts = facts();
        facts.items.import_contexts.clear();
        let contexts = RustSourceContextIndex::new(&facts, &|| true).unwrap();
        assert!(matches!(
            contexts.visible_import_binder(&facts, occurrence(0), &|| true),
            Err(RustCargoRouteError::Unavailable)
        ));

        let empty = RustHierarchySourceFacts {
            items: RustItemSourceFacts {
                contexts: vec![RustSourceContextFact {
                    context: occurrence(0),
                    parent: None,
                    owner: None,
                    kind: RustSourceContextKind::FileRoot,
                }],
                ..RustItemSourceFacts::default()
            },
            types: Vec::new(),
            declarations: Vec::new(),
            declaration_units: Vec::new(),
            module_names: HashMap::default(),
            imports: Vec::new(),
        };
        let contexts = RustSourceContextIndex::new(&empty, &|| true).unwrap();
        assert!(
            contexts
                .visible_import_binder(&empty, occurrence(0), &|| true)
                .unwrap()
                .bindings
                .is_empty()
        );
    }

    #[test]
    fn real_parse_function_alias_sees_forward_enclosing_import_only() {
        let source = "fn f() {\n    type LocalAlias = Imported;\n    use crate::source::Item as Imported;\n    {\n        use crate::sibling::Item as Imported;\n    }\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("Rust fixture tree");
        let root = tempfile::tempdir().expect("fixture root");
        let file = ProjectFile::new(
            root.path().canonicalize().expect("canonical fixture root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let canonical = parsed.source_facts.as_ref().expect("canonical Rust facts");
        assert_eq!(canonical.rust_items.aliases.len(), 1);
        let alias = &canonical.rust_items.aliases[0];

        let module_names = canonical
            .rust_modules
            .as_ref()
            .expect("canonical module facts")
            .declarations
            .iter()
            .map(|module| (module.declaration, module.name.clone()))
            .collect();
        let hierarchy_facts = RustHierarchySourceFacts {
            items: canonical.rust_items.clone(),
            types: canonical.rust_types.clone(),
            declarations: canonical.occurrences.declarations().to_vec(),
            declaration_units: parsed.source_declaration_units.clone(),
            module_names,
            imports: canonical.imports.clone(),
        };
        let contexts = RustSourceContextIndex::new(&hierarchy_facts, &|| true).unwrap();
        let binder = contexts
            .visible_import_binder(&hierarchy_facts, alias.context, &|| true)
            .expect("function-local alias context binder");
        let binding = binder
            .bindings
            .get("Imported")
            .expect("forward enclosing import binding");
        assert_eq!(binding.module_specifier, "crate::source");
        assert_eq!(binding.imported_name.as_deref(), Some("Item"));
        assert_eq!(binder.bindings.len(), 1);
    }
}
