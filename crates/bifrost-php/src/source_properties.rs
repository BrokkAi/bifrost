//! PHP source properties captured while the primary parser nodes are live.

use brokk_bifrost_core::analyzer::php_facts::*;
use brokk_bifrost_core::analyzer::source_facts::{PrimarySourceFactCollector, SourceDeclarationId};
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

use crate::aliases::{
    PhpFileContext, PhpUseAliases, php_dynamic_type_keyword_node, resolve_php_type,
    resolve_php_type_node_arms,
};
use crate::declarations::php_declared_type_node;
use crate::graph::syntax::{
    declaration_doc_comment, promoted_property_doc_element_type, relative_declared_type_keyword,
};

pub(crate) struct PhpSourcePropertyCollector {
    pub facts: PhpSourceFacts,
    pub imports: Vec<brokk_bifrost_core::analyzer::parsed_file::SourceImportFact>,
    pub context: PhpSourceContextId,
    declarations: HashMap<usize, usize>,
    types: HashMap<usize, PhpDeclaredSourceType>,
    raw_supertypes: HashMap<usize, Vec<String>>,
}

impl PhpSourcePropertyCollector {
    pub fn new() -> Self {
        Self {
            imports: Vec::new(),
            facts: PhpSourceFacts {
                contexts: vec![PhpContextSourceFact {
                    namespace: String::new(),
                    aliases: Vec::new(),
                }],
                ..Default::default()
            },
            context: PhpSourceContextId::new(0),
            declarations: HashMap::default(),
            types: HashMap::default(),
            raw_supertypes: HashMap::default(),
        }
    }

    pub fn enter_namespace(&mut self, namespace: String) {
        self.context = PhpSourceContextId::try_from_index(self.facts.contexts.len())
            .expect("PHP context ids fit in u32");
        self.facts.contexts.push(PhpContextSourceFact {
            namespace,
            aliases: Vec::new(),
        });
    }

    pub fn context(&self) -> PhpFileContext {
        let context = &self.facts.contexts[self.context.index()];
        let mut aliases = PhpUseAliases::default();
        for id in &context.aliases {
            let alias = &self.facts.aliases[*id as usize];
            let map = match alias.kind {
                PhpAliasKind::Type => &mut aliases.type_aliases,
                PhpAliasKind::Function => &mut aliases.function_aliases,
                PhpAliasKind::Constant => &mut aliases.const_aliases,
            };
            let (local, target) = alias.binding(&self.imports);
            map.insert(local.to_owned(), target);
        }
        PhpFileContext {
            namespace: context.namespace.clone(),
            aliases,
        }
    }

    pub fn add_aliases(&mut self, aliases: impl IntoIterator<Item = PhpAliasSourceFact>) {
        let mut context = self.facts.contexts[self.context.index()].clone();
        for alias in aliases {
            context
                .aliases
                .push(u32::try_from(self.facts.aliases.len()).expect("PHP alias ids fit in u32"));
            self.facts.aliases.push(alias);
        }
        self.context = PhpSourceContextId::try_from_index(self.facts.contexts.len())
            .expect("PHP context ids fit in u32");
        self.facts.contexts.push(context);
    }

    pub fn capture(
        &mut self,
        node: Node<'_>,
        source: &str,
        occurrences: &mut PrimarySourceFactCollector<'_>,
    ) -> Option<SourceDeclarationId> {
        if let Some(index) = self.declarations.get(&node.id()) {
            return Some(self.facts.declarations[*index].declaration);
        }
        let kind = match node.kind() {
            "class_declaration" => PhpDeclarationKind::Class,
            "interface_declaration" => PhpDeclarationKind::Interface,
            "trait_declaration" => PhpDeclarationKind::Trait,
            "enum_declaration" => PhpDeclarationKind::Enum,
            "function_definition" => PhpDeclarationKind::Function,
            "method_declaration" => PhpDeclarationKind::Method,
            "property_element" => PhpDeclarationKind::Property,
            "const_element" => PhpDeclarationKind::Constant,
            "enum_case" => PhpDeclarationKind::EnumCase,
            "property_promotion_parameter" => PhpDeclarationKind::PromotedProperty,
            _ => return None,
        };
        let occurrence = occurrences.intern_node(node);
        let name = node
            .child_by_field_name("name")
            .or_else(|| {
                (node.kind() == "const_element")
                    .then(|| {
                        (0..node.named_child_count())
                            .filter_map(|i| node.named_child(i))
                            .find(|child| child.kind() == "name")
                    })
                    .flatten()
            })
            .map(|name| occurrences.intern_node(name));
        let declaration = occurrences.declare(occurrence, name);
        let owner = if matches!(
            kind,
            PhpDeclarationKind::Property | PhpDeclarationKind::Constant
        ) {
            node.parent()
                .expect("PHP member element has a declaration parent")
        } else {
            node
        };
        let type_node = php_declared_type_node(owner);
        let ctx = self.context();
        let declared_type = type_node
            .map(|ty| self.type_properties(ty, source))
            .unwrap_or(PhpDeclaredSourceType::Unknown);
        let doc = declaration_doc_comment(owner, source);
        let (nominal, element) = match kind {
            PhpDeclarationKind::Function | PhpDeclarationKind::Method => (
                doc.and_then(crate::phpdoc::return_nominal_type),
                doc.and_then(crate::phpdoc::return_element_type),
            ),
            PhpDeclarationKind::Property => (
                doc.and_then(crate::phpdoc::var_nominal_type),
                doc.and_then(crate::phpdoc::var_element_type),
            ),
            PhpDeclarationKind::PromotedProperty => (
                None,
                promoted_property_doc_element_type(node, source, || true),
            ),
            _ => (None, None),
        };
        let mut supertypes = Vec::new();
        let mut class_parent = None;
        let mut raw_supertypes = Vec::new();
        if matches!(
            kind,
            PhpDeclarationKind::Class
                | PhpDeclarationKind::Interface
                | PhpDeclarationKind::Trait
                | PhpDeclarationKind::Enum
        ) {
            let mut clauses = Vec::new();
            for index in 0..node.named_child_count() {
                let child = node.named_child(index).expect("named child index is valid");
                if matches!(child.kind(), "base_clause" | "class_interface_clause") {
                    clauses.push(child);
                } else if kind == PhpDeclarationKind::Class && child.kind() == "declaration_list" {
                    for index in 0..child.named_child_count() {
                        let member = child
                            .named_child(index)
                            .expect("named child index is valid");
                        if member.kind() == "use_declaration" {
                            clauses.push(member);
                        }
                    }
                }
            }
            for clause in clauses {
                let mut stack = vec![clause];
                while let Some(ty) = stack.pop() {
                    if matches!(
                        ty.kind(),
                        "name" | "namespace_name" | "qualified_name" | "fully_qualified_name"
                    ) {
                        let raw = ty
                            .utf8_text(source.as_bytes())
                            .expect("PHP type source is UTF-8")
                            .trim();
                        if !raw.is_empty() {
                            raw_supertypes.push(raw.to_owned());
                        }
                        // The display projection historically includes names
                        // inside trait adaptations. Hierarchy proof admits
                        // only direct type children of the written clause.
                        if ty.parent().is_some_and(|parent| parent.id() == clause.id())
                            && let Some(name) =
                                crate::aliases::resolve_php_type_node(ty, source, &ctx, || true)
                        {
                            if kind == PhpDeclarationKind::Class
                                && clause.kind() == "base_clause"
                                && class_parent.is_none()
                            {
                                class_parent = Some(name.clone());
                            }
                            supertypes.push(name);
                        }
                        continue;
                    }
                    for index in (0..ty.named_child_count()).rev() {
                        if let Some(child) = ty.named_child(index) {
                            stack.push(child);
                        }
                    }
                }
            }
        }
        self.raw_supertypes.insert(node.id(), raw_supertypes);
        let fact = PhpDeclarationSourceFact {
            declaration,
            kind,
            context: self.context,
            declared_type_occurrence: type_node.map(|ty| occurrences.intern_node(ty)),
            declared_type,
            supertypes,
            class_parent,
            has_trait_use: false,
            doc_nominal_type: nominal.and_then(|raw| resolve_php_type(&raw, &ctx)),
            doc_element_type: element.and_then(|raw| resolve_php_type(&raw, &ctx)),
        };
        self.declarations
            .insert(node.id(), self.facts.declarations.len());
        self.facts.declarations.push(fact);
        Some(declaration)
    }

    fn type_properties(&mut self, node: Node<'_>, source: &str) -> PhpDeclaredSourceType {
        if let Some(ty) = self.types.get(&node.id()) {
            return ty.clone();
        }
        let ty = if let Some(keyword) = php_dynamic_type_keyword_node(node, source, || true) {
            match keyword {
                "object" => PhpDeclaredSourceType::DynamicObject,
                "mixed" => PhpDeclaredSourceType::DynamicMixed,
                _ => unreachable!(),
            }
        } else if let Some(keyword) = relative_declared_type_keyword(node, source, || true) {
            match keyword {
                "self" => PhpDeclaredSourceType::SelfType,
                "static" => PhpDeclaredSourceType::StaticType,
                "parent" => PhpDeclaredSourceType::ParentType,
                _ => unreachable!(),
            }
        } else {
            let arms = resolve_php_type_node_arms(node, source, &self.context(), || true);
            if arms.is_empty() {
                PhpDeclaredSourceType::Unknown
            } else {
                PhpDeclaredSourceType::Nominal(arms)
            }
        };
        self.types.insert(node.id(), ty.clone());
        ty
    }

    pub fn capture_trait_use(&mut self, node: Node<'_>) {
        if node.kind() != "use_declaration" {
            return;
        }
        let mut ancestor = node.parent();
        while let Some(owner) = ancestor {
            if let Some(index) = self.declarations.get(&owner.id()) {
                self.facts.declarations[*index].has_trait_use = true;
            }
            ancestor = owner.parent();
        }
    }

    pub fn capture_write(
        &mut self,
        node: Node<'_>,
        source: &str,
        occurrences: &mut PrimarySourceFactCollector<'_>,
    ) {
        use crate::graph::syntax::*;
        let Some((left, right)) = assignment_parts(node) else {
            return;
        };
        let (field, kind) = if let Some(field) = this_field_name(left, source) {
            (field, PhpFieldWriteKind::Instance)
        } else if let Some(field) = static_self_field_name(left, source) {
            (field, PhpFieldWriteKind::Static)
        } else if left.kind() == "subscript_expression"
            && let Some(field) = left
                .named_child(0)
                .and_then(|base| this_field_name(base, source))
        {
            (field, PhpFieldWriteKind::Indexed)
        } else {
            return;
        };
        let ctx = self.context();
        let right = unwrap_parenthesized(right);
        let type_node = if right.kind() == "object_creation_expression" {
            object_creation_type(right)
        } else {
            match kind {
                PhpFieldWriteKind::Instance => {
                    constructor_parameter_type_node(right, source, || true)
                }
                PhpFieldWriteKind::Indexed => parameter_type_node(right, source, || true),
                PhpFieldWriteKind::Static => None,
            }
        };
        let value_type = type_node
            .map(|ty| self.type_properties(ty, source))
            .unwrap_or(PhpDeclaredSourceType::Unknown);
        let doc_element_type = parameter_doc_element_type(right, source, || true)
            .and_then(|raw| resolve_php_type(&raw, &ctx));
        let occurrence = occurrences.intern_node(node);
        let mut ancestor = node.parent();
        while let Some(class) = ancestor {
            if class.kind() == "class_declaration" {
                let declaration = self
                    .capture(class, source, occurrences)
                    .expect("class has source properties");
                self.facts.writes.push(PhpFieldWriteSourceFact {
                    occurrence,
                    class: declaration,
                    field: field.to_owned(),
                    kind,
                    directly_in_constructor: assignment_is_directly_in_constructor(
                        node,
                        source,
                        class,
                        &mut || true,
                    ),
                    value_type: value_type.clone(),
                    doc_element_type: doc_element_type.clone(),
                });
                if kind == PhpFieldWriteKind::Indexed {
                    break;
                }
            }
            ancestor = class.parent();
        }
    }

    pub fn raw_supertypes(&self, node: Node<'_>) -> Vec<String> {
        self.raw_supertypes
            .get(&node.id())
            .expect("PHP supertype syntax captured before display projection")
            .clone()
    }

    pub fn declaration(&self, node: Node<'_>) -> &PhpDeclarationSourceFact {
        &self.facts.declarations[*self
            .declarations
            .get(&node.id())
            .expect("PHP declaration properties captured before display projection")]
    }
}
