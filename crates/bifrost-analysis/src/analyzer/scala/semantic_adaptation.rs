//! Same-file Scala implicit-conversion and value-class/opaque adaptation.
//!
//! Selection is structural: tree-sitter fields, declaration ranges, and
//! procedure identities. A uniquely selected conversion is never treated as
//! identity merely because its body is missing. An incomplete catalog walk
//! never certifies that a candidate is unique.

use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::semantic::{ProcedureId, children_by_field_name, node_text};
use crate::analyzer::tree_walk::named_children;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{nearest_ancestor, node_range};
use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_jvm::scala::ambient_use::scala_has_modifier;
use brokk_bifrost_jvm::scala::graph::namespace::{
    scala_nearest_unindexed_type_owner, scala_unindexed_type_binding_shadows,
};
use brokk_bifrost_jvm::scala::imports::{scala_import_infos_from_node, scala_lexical_scope_path};
use brokk_bifrost_jvm::scala::structural::{
    SCALA_KIND_TABLE, SCALA_STRUCTURAL_SPEC, scala_occurrence_role,
};

use super::{
    scala_default_type_name, scala_enclosing_package_segments_at, scala_import_visible_at,
    scala_package_prefixes_at, scala_type_lookup_segments,
};

const ADAPTATION_NODE_BUDGET: usize = 256;
const ADAPTATION_COLLECT_NODE_BUDGET: usize = 32_768;

type NominalType = Arc<[String]>;
type NominalTypePair = (NominalType, NominalType);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScalaConversionCallableKind {
    Function,
    Constructor { value_class: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdaptationFailure {
    Unresolved,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScalaTypeBinding<'tree> {
    Declaration(Node<'tree>),
    TypeParameter,
    Prelude,
}

#[derive(Debug, Clone)]
struct CatalogImport {
    info: ImportInfo,
    given_wildcard: bool,
    owner_shadowed: bool,
}

#[derive(Debug, Clone)]
pub(super) struct SelectedScalaAdaptation {
    pub(super) kind: SelectedAdaptationKind,
    #[allow(dead_code)]
    pub(super) source_type: Arc<[String]>,
    #[allow(dead_code)]
    pub(super) target_type: Arc<[String]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SelectedAdaptationKind {
    ImplicitCall {
        procedure: Option<ProcedureId>,
        callable: ScalaConversionCallableKind,
    },
    OpaqueWrap,
    OpaqueUnwrap,
}

#[derive(Debug, Clone)]
struct ScalaImplicitConversion<'tree> {
    node: Node<'tree>,
    scope: Node<'tree>,
    owner: Option<Node<'tree>>,
    name: Box<str>,
    source_type: Arc<[String]>,
    target_type: Arc<[String]>,
    procedure: Option<ProcedureId>,
    callable_kind: ScalaConversionCallableKind,
}

#[derive(Debug, Clone)]
pub(super) struct ScalaValueClass<'tree> {
    pub(super) class: Node<'tree>,
    #[allow(dead_code)]
    pub(super) name: Box<str>,
    pub(super) payload_name: Box<str>,
    pub(super) payload_type: Arc<[String]>,
    #[allow(dead_code)]
    pub(super) wrapper_type: Arc<[String]>,
    pub(super) constructor: Option<ProcedureId>,
}

#[derive(Debug, Clone)]
struct ScalaOpaqueAlias<'tree> {
    owner: Option<Node<'tree>>,
    node: Node<'tree>,
    alias: Arc<[String]>,
    underlying: Arc<[String]>,
}

#[derive(Debug, Clone)]
struct TypeDeclaration<'tree> {
    node: Node<'tree>,
    enclosing_template: Option<Node<'tree>>,
    package: Arc<[String]>,
    owners: Arc<[String]>,
    name: Box<str>,
}

impl TypeDeclaration<'_> {
    fn full_path(&self) -> Vec<String> {
        let mut path = Vec::with_capacity(self.package.len() + self.owners.len() + 1);
        path.extend(self.package.iter().cloned());
        path.extend(self.owners.iter().cloned());
        path.push(self.name.to_string());
        path
    }
}

struct ScalaTermBinding<'tree> {
    binder: Node<'tree>,
    scope: Node<'tree>,
    activation: Range,
}

impl ScalaTermBinding<'_> {
    fn is_active_at(&self, source: &str, name: &str, site: Node<'_>) -> bool {
        nonempty_text(source, self.binder) == Some(name)
            && self.activation.start_byte <= site.start_byte()
            && site.start_byte() < self.activation.end_byte
            && owner_encloses(Some(self.scope), site)
    }
}

pub(super) struct ScalaAdaptationCatalog<'tree> {
    conversions: Vec<ScalaImplicitConversion<'tree>>,
    value_classes: Vec<ScalaValueClass<'tree>>,
    opaque_aliases: Vec<ScalaOpaqueAlias<'tree>>,
    type_declarations: Vec<TypeDeclaration<'tree>>,
    imports: Vec<CatalogImport>,
    term_bindings: Vec<ScalaTermBinding<'tree>>,
    complete: bool,
}

impl<'tree> ScalaAdaptationCatalog<'tree> {
    pub(super) fn collect(
        source: &str,
        root: Node<'tree>,
        procedure_targets: &HashMap<usize, ProcedureId>,
    ) -> Self {
        let mut conversions = Vec::new();
        let mut class_nodes = Vec::new();
        let mut opaque_aliases = Vec::new();
        let mut type_declarations = Vec::new();
        let mut imports = Vec::new();
        let mut term_bindings = Vec::new();
        let mut stack = vec![root];
        let mut examined = 0_usize;
        let mut complete = true;
        while let Some(node) = stack.pop() {
            examined += 1;
            if examined > ADAPTATION_COLLECT_NODE_BUDGET {
                complete = false;
                break;
            }
            if scala_occurrence_role(node) == Some(OccurrenceRole::Binder) {
                let scope = scala_scope_for(node, root);
                let Some(activation) =
                    SCALA_STRUCTURAL_SPEC.binding_activation(node, node_range(scope))
                else {
                    complete = false;
                    break;
                };
                term_bindings.push(ScalaTermBinding {
                    binder: node,
                    scope,
                    activation: activation.activation,
                });
            }
            match node.kind() {
                "function_definition" if scala_has_modifier(node, "implicit") => {
                    if let Some(conversion) =
                        implicit_def_conversion(node, source, procedure_targets)
                    {
                        conversions.push(conversion);
                    }
                }
                "given_definition" => {
                    if let Some(conversion) = given_conversion(node, source, procedure_targets) {
                        conversions.push(conversion);
                    }
                }
                "class_definition" => {
                    class_nodes.push(node);
                    if let Some(declaration) = type_declaration(node, source, root) {
                        type_declarations.push(declaration);
                    }
                }
                "object_definition" | "trait_definition" | "enum_definition" => {
                    if let Some(declaration) = type_declaration(node, source, root) {
                        type_declarations.push(declaration);
                    }
                }
                "type_definition" => {
                    if let Some(alias) = opaque_alias(node, source, root) {
                        opaque_aliases.push(alias);
                    }
                    if let Some(declaration) = type_declaration(node, source, root) {
                        type_declarations.push(declaration);
                    }
                }
                "import_declaration" => {
                    let given_wildcard = import_is_given_wildcard(node, source);
                    imports.extend(scala_import_infos_from_node(node, source).into_iter().map(
                        |info| CatalogImport {
                            info,
                            given_wildcard,
                            owner_shadowed: false,
                        },
                    ));
                }
                _ => {}
            }
            let mut children = named_children(node);
            children.reverse();
            stack.extend(children);
        }
        // Resolve roots at the import declaration, before a later use can
        // introduce a different lexical binder with the same spelling.
        let shadowed_owners = imports
            .iter()
            .map(|import| {
                let Some(path) = import_owner_path(import) else {
                    return false;
                };
                let Some(root_name) = path.first() else {
                    return false;
                };
                let declaration = import_declaration(import, root);
                let Ok(owner) = resolve_stable_owner(&type_declarations, source, path, declaration)
                else {
                    return false;
                };
                let root_owner = std::iter::successors(Some(owner.node), |node| node.parent())
                    .find(|node| {
                        is_stable_owner(*node)
                            && template_name(*node, source).as_deref() == Some(root_name)
                    });
                let owner_scope = root_owner.map_or(root, |node| scala_scope_for(node, root));
                let shadows_owner = |scope| {
                    owner_encloses(Some(scope), declaration)
                        && owner_encloses(Some(owner_scope), scope)
                };
                term_bindings.iter().any(|binding| {
                    binding.is_active_at(source, root_name, declaration)
                        && shadows_owner(binding.scope)
                }) || imports_visible_at(&imports, source, declaration)
                    .iter()
                    .any(|other| {
                        !other.info.is_wildcard
                            && other.info.local_name() == Some(root_name)
                            && shadows_owner(scala_scope_for(import_declaration(other, root), root))
                    })
            })
            .collect::<Vec<_>>();
        for (import, shadowed) in imports.iter_mut().zip(shadowed_owners) {
            import.owner_shadowed = shadowed;
        }
        let mut catalog = Self {
            conversions,
            value_classes: Vec::new(),
            opaque_aliases,
            type_declarations,
            imports,
            term_bindings,
            complete,
        };
        for class in &class_nodes {
            if scala_has_modifier(*class, "implicit")
                && let Some(conversion) =
                    implicit_class_conversion(*class, source, root, procedure_targets, &catalog)
            {
                catalog.conversions.push(conversion);
            }
        }
        catalog.value_classes = class_nodes
            .into_iter()
            .filter_map(|class| {
                value_class_declaration(class, source, root, procedure_targets, &catalog)
            })
            .collect();
        catalog
    }

    pub(super) fn select(
        &self,
        source: &str,
        use_site: Node<'tree>,
        source_type: &[String],
        target_type: &[String],
    ) -> Result<SelectedScalaAdaptation, AdaptationFailure> {
        if self.types_match(source, source_type, use_site, target_type, use_site) {
            return Err(AdaptationFailure::Unresolved);
        }
        let mut matches = Vec::new();
        for conversion in &self.conversions {
            if self.types_match(
                source,
                &conversion.source_type,
                conversion.node,
                source_type,
                use_site,
            ) && self.types_match(
                source,
                &conversion.target_type,
                conversion.node,
                target_type,
                use_site,
            ) && self.conversion_in_scope(source, conversion, use_site, source_type, target_type)
            {
                matches.push(SelectedScalaAdaptation {
                    kind: SelectedAdaptationKind::ImplicitCall {
                        procedure: conversion.procedure,
                        callable: conversion.callable_kind,
                    },
                    source_type: Arc::clone(&conversion.source_type),
                    target_type: Arc::clone(&conversion.target_type),
                });
            }
        }
        for alias in &self.opaque_aliases {
            if !owner_encloses(alias.owner, use_site) {
                continue;
            }
            if self.types_match(source, &alias.underlying, alias.node, source_type, use_site)
                && self.types_match(source, &alias.alias, alias.node, target_type, use_site)
            {
                matches.push(SelectedScalaAdaptation {
                    kind: SelectedAdaptationKind::OpaqueWrap,
                    source_type: Arc::clone(&alias.underlying),
                    target_type: Arc::clone(&alias.alias),
                });
            }
            if self.types_match(source, &alias.alias, alias.node, source_type, use_site)
                && self.types_match(source, &alias.underlying, alias.node, target_type, use_site)
            {
                matches.push(SelectedScalaAdaptation {
                    kind: SelectedAdaptationKind::OpaqueUnwrap,
                    source_type: Arc::clone(&alias.alias),
                    target_type: Arc::clone(&alias.underlying),
                });
            }
        }
        match matches.len() {
            1 if self.complete => Ok(matches.remove(0)),
            n if n >= 2 => Err(AdaptationFailure::Ambiguous),
            _ => Err(AdaptationFailure::Unresolved),
        }
    }

    pub(super) fn value_class_for_type(
        &self,
        source: &str,
        use_site: Node<'tree>,
        type_path: &[String],
    ) -> Option<&ScalaValueClass<'tree>> {
        let ScalaTypeBinding::Declaration(node) =
            self.bind_nominal_type(source, type_path, use_site).ok()?
        else {
            return None;
        };
        let mut found = self
            .value_classes
            .iter()
            .filter(|class| class.class.id() == node.id())
            .collect::<Vec<_>>();
        match found.len() {
            1 => found.pop(),
            _ => None,
        }
    }

    pub(super) fn value_class_unwrap(
        &self,
        source: &str,
        wrapper_type: &[String],
        field: &str,
        use_site: Node<'tree>,
    ) -> Option<&ScalaValueClass<'tree>> {
        let class = self.value_class_for_type(source, use_site, wrapper_type)?;
        (class.payload_name.as_ref() == field).then_some(class)
    }

    pub(super) fn bind_nominal_type(
        &self,
        source: &str,
        type_path: &[String],
        use_site: Node<'tree>,
    ) -> Result<ScalaTypeBinding<'tree>, AdaptationFailure> {
        let declarations = &self.type_declarations;
        let imports = &self.imports;
        let path = type_path;
        if !self.complete || path.is_empty() {
            return Err(AdaptationFailure::Unresolved);
        }
        if path.len() == 1 {
            let name = path[0].as_str();
            if scala_unindexed_type_binding_shadows(source, use_site, name) {
                return Ok(ScalaTypeBinding::TypeParameter);
            }
            if let Some(declaration) = unique_nested_type(declarations, name, use_site)? {
                return Ok(ScalaTypeBinding::Declaration(declaration.node));
            }
            if let Some(declaration) =
                unique_imported_type(declarations, imports, source, name, use_site)?
            {
                return Ok(ScalaTypeBinding::Declaration(declaration.node));
            }
            if let Some(declaration) = unique_top_level_type(declarations, source, name, use_site)?
            {
                return Ok(ScalaTypeBinding::Declaration(declaration.node));
            }
            if is_prelude_type_path(path) {
                return Ok(ScalaTypeBinding::Prelude);
            }
            return Err(AdaptationFailure::Unresolved);
        }
        if path[0] != "_root_"
            && (scala_unindexed_type_binding_shadows(source, use_site, &path[0])
                || self
                    .term_bindings
                    .iter()
                    .any(|binding| binding.is_active_at(source, &path[0], use_site))
                || imports_visible_at(imports, source, use_site)
                    .iter()
                    .any(|import| {
                        import.info.is_wildcard
                            || import.info.local_name() == Some(path[0].as_str())
                    }))
        {
            return Err(AdaptationFailure::Unresolved);
        }
        if let Some(declaration) = unique_exact_type(declarations, path)? {
            return Ok(ScalaTypeBinding::Declaration(declaration.node));
        }
        if is_prelude_type_path(path) {
            return Ok(ScalaTypeBinding::Prelude);
        }
        Err(AdaptationFailure::Unresolved)
    }

    fn types_match(
        &self,
        source: &str,
        left: &[String],
        left_site: Node<'tree>,
        right: &[String],
        right_site: Node<'tree>,
    ) -> bool {
        match (
            self.bind_nominal_type(source, left, left_site),
            self.bind_nominal_type(source, right, right_site),
        ) {
            (Ok(ScalaTypeBinding::Declaration(left)), Ok(ScalaTypeBinding::Declaration(right))) => {
                left.id() == right.id()
            }
            (Ok(ScalaTypeBinding::Prelude), Ok(ScalaTypeBinding::Prelude)) => {
                scala_nominal_types_match(left, right)
            }
            (Ok(ScalaTypeBinding::TypeParameter), Ok(ScalaTypeBinding::TypeParameter)) => {
                left == right
                    && scala_nearest_unindexed_type_owner(source, left_site, &left[0])
                        == scala_nearest_unindexed_type_owner(source, right_site, &right[0])
            }
            _ => false,
        }
    }

    fn payload_matches(
        &self,
        source: &str,
        class: &ScalaValueClass<'tree>,
        observed: &[String],
        use_site: Node<'tree>,
    ) -> bool {
        self.types_match(source, &class.payload_type, class.class, observed, use_site)
    }

    pub(super) fn value_class_boxes(
        &self,
        source: &str,
        use_site: Node<'tree>,
        payload_type: &[String],
        wrapper_type: &[String],
    ) -> bool {
        self.value_class_for_type(source, use_site, wrapper_type)
            .is_some_and(|class| self.payload_matches(source, class, payload_type, use_site))
    }

    pub(super) fn value_class_unboxes(
        &self,
        source: &str,
        use_site: Node<'tree>,
        wrapper_type: &[String],
        payload_type: &[String],
    ) -> bool {
        self.value_class_for_type(source, use_site, wrapper_type)
            .is_some_and(|class| self.payload_matches(source, class, payload_type, use_site))
    }

    fn conversion_in_scope(
        &self,
        source: &str,
        conversion: &ScalaImplicitConversion<'tree>,
        use_site: Node<'tree>,
        source_type: &[String],
        target_type: &[String],
    ) -> bool {
        if owner_encloses(Some(conversion.scope), use_site) {
            if is_local_scope(conversion.scope)
                && use_site.start_byte() < conversion.node.start_byte()
            {
                return false;
            }
            return true;
        }
        if self.companion_in_implicit_scope(source, conversion, use_site, source_type, target_type)
        {
            return true;
        }
        self.explicit_import_selects(source, conversion, use_site)
    }

    fn companion_in_implicit_scope(
        &self,
        source: &str,
        conversion: &ScalaImplicitConversion<'tree>,
        use_site: Node<'tree>,
        source_type: &[String],
        target_type: &[String],
    ) -> bool {
        let Some(owner) = conversion.owner else {
            return false;
        };
        if owner.kind() != "object_definition" {
            return false;
        }
        let Some(companion) = unique_companion_class(&self.type_declarations, owner, source) else {
            return false;
        };
        let companion_path = companion.full_path();
        self.types_match(
            source,
            &companion_path,
            companion.node,
            source_type,
            use_site,
        ) || self.types_match(
            source,
            &companion_path,
            companion.node,
            target_type,
            use_site,
        )
    }

    fn explicit_import_selects(
        &self,
        source: &str,
        conversion: &ScalaImplicitConversion<'tree>,
        use_site: Node<'tree>,
    ) -> bool {
        let Some(owner) = conversion.owner else {
            return false;
        };
        let mut matched = false;
        for import in imports_visible_at(&self.imports, source, use_site) {
            if import.info.is_wildcard
                || import.given_wildcard
                || import_source_member(import) != Some(conversion.name.as_ref())
            {
                continue;
            }
            match resolve_import_owner(self, source, import, use_site) {
                Ok(declared) if declared.node.id() == owner.id() => matched = true,
                _ => return false,
            }
        }
        matched
    }
}

fn unique_companion_class<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    owner: Node<'tree>,
    source: &str,
) -> Option<&'a TypeDeclaration<'tree>> {
    let owner_name = template_name(owner, source)?;
    let owner_package = compilation_unit(owner)
        .map(|root| scala_enclosing_package_segments_at(root, source, owner.start_byte()))
        .unwrap_or_default();
    let owner_owners = enclosing_template_names(owner, source);
    let companions = declarations
        .iter()
        .filter(|declaration| {
            matches!(
                declaration.node.kind(),
                "class_definition" | "trait_definition" | "enum_definition"
            ) && declaration.name.as_ref() == owner_name.as_ref()
                && declaration.package.as_ref() == owner_package.as_slice()
                && declaration.owners.as_ref() == owner_owners.as_slice()
        })
        .collect::<Vec<_>>();
    match companions.as_slice() {
        [companion] => Some(*companion),
        _ => None,
    }
}

fn implicit_def_conversion<'tree>(
    node: Node<'tree>,
    source: &str,
    procedure_targets: &HashMap<usize, ProcedureId>,
) -> Option<ScalaImplicitConversion<'tree>> {
    let name = node
        .child_by_field_name("name")
        .and_then(|name| nonempty_text(source, name))?;
    let (source_type, _) = single_strict_value_parameter(node, source)?;
    let target_type = declared_result_type(node, source)?;
    Some(scala_conversion(
        node,
        Box::from(name),
        source_type,
        target_type,
        procedure_targets.get(&node.id()).copied(),
        ScalaConversionCallableKind::Function,
    ))
}

fn given_conversion<'tree>(
    node: Node<'tree>,
    source: &str,
    procedure_targets: &HashMap<usize, ProcedureId>,
) -> Option<ScalaImplicitConversion<'tree>> {
    if node.child_by_field_name("type_parameters").is_some() {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .and_then(|name| nonempty_text(source, name))
        .unwrap_or("given");
    if let Some((source_type, _)) = single_strict_value_parameter(node, source) {
        let target_type = declared_result_type(node, source)?;
        return Some(scala_conversion(
            node,
            Box::from(name),
            source_type,
            target_type,
            procedure_targets.get(&node.id()).copied(),
            ScalaConversionCallableKind::Function,
        ));
    }
    let return_type = node.child_by_field_name("return_type")?;
    let (source_type, target_type) = conversion_type_pair(return_type, source)?;
    let body = given_body(node)?;
    let callable = conversion_callable_from_body(body, source)?;
    Some(scala_conversion(
        node,
        Box::from(name),
        source_type,
        target_type,
        procedure_targets.get(&callable.id()).copied(),
        ScalaConversionCallableKind::Function,
    ))
}

fn implicit_class_conversion<'tree>(
    node: Node<'tree>,
    source: &str,
    root: Node<'tree>,
    procedure_targets: &HashMap<usize, ProcedureId>,
    catalog: &ScalaAdaptationCatalog<'tree>,
) -> Option<ScalaImplicitConversion<'tree>> {
    let name = node
        .child_by_field_name("name")
        .and_then(|name| nonempty_text(source, name))?;
    let (_payload_name, payload_type) = unique_class_parameter(node, source)?;
    let wrapper_type = declaration_path(node, source, root)
        .unwrap_or_else(|| Arc::<[String]>::from(vec![name.to_string()]));
    let value_class = extends_language_anyval(node, source, catalog);
    Some(scala_conversion(
        node,
        Box::from(name),
        payload_type,
        wrapper_type,
        procedure_targets.get(&node.id()).copied(),
        ScalaConversionCallableKind::Constructor { value_class },
    ))
}

fn value_class_declaration<'tree>(
    node: Node<'tree>,
    source: &str,
    root: Node<'tree>,
    procedure_targets: &HashMap<usize, ProcedureId>,
    catalog: &ScalaAdaptationCatalog<'tree>,
) -> Option<ScalaValueClass<'tree>> {
    if !extends_language_anyval(node, source, catalog) {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .and_then(|name| nonempty_text(source, name))?;
    let (payload_name, payload_type) = unique_class_parameter(node, source)?;
    let wrapper_type = declaration_path(node, source, root)
        .unwrap_or_else(|| Arc::<[String]>::from(vec![name.to_string()]));
    Some(ScalaValueClass {
        class: node,
        name: Box::from(name),
        payload_name,
        payload_type,
        wrapper_type,
        constructor: procedure_targets.get(&node.id()).copied(),
    })
}

fn opaque_alias<'tree>(
    node: Node<'tree>,
    source: &str,
    root: Node<'tree>,
) -> Option<ScalaOpaqueAlias<'tree>> {
    if !named_children(node)
        .into_iter()
        .any(|child| child.kind() == "opaque_modifier")
    {
        return None;
    }
    if node.child_by_field_name("type_parameters").is_some() {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .and_then(|name| nonempty_text(source, name))?;
    let underlying = node.child_by_field_name("type")?;
    let underlying = type_identity(underlying, source)?;
    let alias = declaration_path(node, source, root)
        .unwrap_or_else(|| Arc::<[String]>::from(vec![name.to_string()]));
    Some(ScalaOpaqueAlias {
        owner: enclosing_template(node),
        node,
        alias,
        underlying,
    })
}

fn type_declaration<'tree>(
    node: Node<'tree>,
    source: &str,
    root: Node<'tree>,
) -> Option<TypeDeclaration<'tree>> {
    let name = template_name(node, source)?;
    Some(TypeDeclaration {
        node,
        enclosing_template: enclosing_template(node),
        package: Arc::from(scala_enclosing_package_segments_at(
            root,
            source,
            node.start_byte(),
        )),
        owners: Arc::from(enclosing_template_names(node, source)),
        name,
    })
}

fn declaration_path(node: Node<'_>, source: &str, root: Node<'_>) -> Option<NominalType> {
    let declaration = type_declaration(node, source, root)?;
    Some(Arc::from(declaration.full_path()))
}

fn scala_conversion<'tree>(
    node: Node<'tree>,
    name: Box<str>,
    source_type: Arc<[String]>,
    target_type: Arc<[String]>,
    procedure: Option<ProcedureId>,
    callable_kind: ScalaConversionCallableKind,
) -> ScalaImplicitConversion<'tree> {
    ScalaImplicitConversion {
        node,
        scope: declaring_scope(node),
        owner: enclosing_template(node),
        name,
        source_type,
        target_type,
        procedure,
        callable_kind,
    }
}

fn given_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        node.child_by_field_name("return_type")
            .and_then(|return_type| return_type.child_by_field_name("body"))
    })
}

fn conversion_callable_from_body<'tree>(body: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    match body.kind() {
        "lambda_expression" => Some(body),
        "block" | "indented_block" => {
            let children = named_children(body);
            match children.as_slice() {
                [inner] if inner.kind() == "lambda_expression" => Some(*inner),
                _ => None,
            }
        }
        "with_template_body" | "template_body" => unique_apply_method(body, source),
        _ => None,
    }
}

fn unique_apply_method<'tree>(body: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut found = Vec::new();
    let mut stack = named_children(body);
    let mut examined = 0_usize;
    while let Some(node) = stack.pop() {
        examined += 1;
        if examined > ADAPTATION_NODE_BUDGET {
            return None;
        }
        if matches!(
            node.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            continue;
        }
        if node.kind() == "function_definition"
            && node
                .child_by_field_name("name")
                .and_then(|name| nonempty_text(source, name))
                == Some("apply")
        {
            found.push(node);
        }
        stack.extend(named_children(node));
    }
    let [apply] = found.as_slice() else {
        return None;
    };
    Some(*apply)
}

fn single_strict_value_parameter<'tree>(
    callable: Node<'tree>,
    source: &str,
) -> Option<(Arc<[String]>, Node<'tree>)> {
    if callable.child_by_field_name("type_parameters").is_some() {
        return None;
    }
    let lists = children_by_field_name(callable, "parameters");
    let [list] = lists.as_slice() else {
        return None;
    };
    if parameter_list_is_contextual(*list) {
        return None;
    }
    let parameters = named_children(*list)
        .into_iter()
        .filter(|child| child.kind() == "parameter")
        .collect::<Vec<_>>();
    let [parameter] = parameters.as_slice() else {
        return None;
    };
    if subtree_has_kind(*parameter, "lazy_parameter_type") {
        return None;
    }
    let declared = parameter.child_by_field_name("type")?;
    Some((type_identity(declared, source)?, *parameter))
}

fn unique_class_parameter(class: Node<'_>, source: &str) -> Option<(Box<str>, Arc<[String]>)> {
    let lists = children_by_field_name(class, "class_parameters");
    let [list] = lists.as_slice() else {
        return None;
    };
    let parameters = named_children(*list)
        .into_iter()
        .filter(|child| child.kind() == "class_parameter")
        .collect::<Vec<_>>();
    let [parameter] = parameters.as_slice() else {
        return None;
    };
    let name = parameter
        .child_by_field_name("name")
        .and_then(|name| nonempty_text(source, name))?;
    let declared = parameter.child_by_field_name("type")?;
    Some((Box::from(name), type_identity(declared, source)?))
}

fn declared_result_type(callable: Node<'_>, source: &str) -> Option<Arc<[String]>> {
    type_identity(callable.child_by_field_name("return_type")?, source)
}

fn conversion_type_pair(node: Node<'_>, source: &str) -> Option<NominalTypePair> {
    let generic = find_conversion_generic(node, source)?;
    let arguments = generic.child_by_field_name("type_arguments")?;
    let types = named_children(arguments);
    let [source_type, target_type] = types.as_slice() else {
        return None;
    };
    Some((
        type_identity(*source_type, source)?,
        type_identity(*target_type, source)?,
    ))
}

fn find_conversion_generic<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    let mut examined = 0_usize;
    while let Some(current) = stack.pop() {
        examined += 1;
        if examined > ADAPTATION_NODE_BUDGET {
            return None;
        }
        if current.kind() == "generic_type" {
            let base = current
                .child_by_field_name("type")
                .map(|base| scala_type_lookup_segments(base, source))
                .unwrap_or_default();
            if base.last().map(String::as_str) == Some("Conversion") {
                return Some(current);
            }
        }
        if matches!(current.kind(), "type_arguments" | "annotation") {
            continue;
        }
        stack.extend(named_children(current));
    }
    None
}

fn extends_language_anyval<'tree>(
    class: Node<'tree>,
    source: &str,
    catalog: &ScalaAdaptationCatalog<'tree>,
) -> bool {
    class.child_by_field_name("extend").is_some_and(|extend| {
        let segments = scala_type_lookup_segments(extend, source);
        matches!(
            catalog.bind_nominal_type(source, &segments, class),
            Ok(ScalaTypeBinding::Prelude)
        ) && segments.last().map(String::as_str) == Some("AnyVal")
    })
}

fn type_identity(node: Node<'_>, source: &str) -> Option<Arc<[String]>> {
    let segments = scala_type_lookup_segments(node, source);
    (!segments.is_empty()).then(|| Arc::from(segments.into_boxed_slice()))
}

pub(super) fn scala_nominal_types_match(left: &[String], right: &[String]) -> bool {
    if left == right {
        return true;
    }
    let (Some(left_name), Some(right_name)) = (left.last(), right.last()) else {
        return false;
    };
    left_name == right_name
        && scala_default_type_name(left_name)
        && is_prelude_type_path(left)
        && is_prelude_type_path(right)
}

pub(super) fn is_prelude_type_path(segments: &[String]) -> bool {
    match segments {
        [name] => scala_default_type_name(name),
        [package, name] if package == "scala" => scala_default_type_name(name),
        [root, package, name] if root == "_root_" && package == "scala" => {
            scala_default_type_name(name)
        }
        _ => false,
    }
}

fn unique_exact_type<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    path: &[String],
) -> Result<Option<&'a TypeDeclaration<'tree>>, AdaptationFailure> {
    let exact = declarations
        .iter()
        .filter(|declaration| {
            is_type_namespace(declaration.node) && declaration.full_path() == path
        })
        .collect::<Vec<_>>();
    match exact.as_slice() {
        [declaration] => Ok(Some(*declaration)),
        [] => Ok(None),
        _ => Err(AdaptationFailure::Ambiguous),
    }
}

fn unique_nested_type<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    name: &str,
    use_site: Node<'tree>,
) -> Result<Option<&'a TypeDeclaration<'tree>>, AdaptationFailure> {
    let mut nested = declarations
        .iter()
        .filter(|declaration| {
            is_type_namespace(declaration.node)
                && declaration.name.as_ref() == name
                && !declaration.owners.is_empty()
                && owner_encloses(declaration.enclosing_template, use_site)
        })
        .collect::<Vec<_>>();
    if nested.len() > 1 {
        nested.sort_by_key(|declaration| {
            declaration
                .enclosing_template
                .map(|owner| owner.end_byte() - owner.start_byte())
                .unwrap_or(usize::MAX)
        });
        let innermost = nested[0]
            .enclosing_template
            .map(|owner| owner.end_byte() - owner.start_byte());
        nested.retain(|declaration| {
            declaration
                .enclosing_template
                .map(|owner| owner.end_byte() - owner.start_byte())
                == innermost
        });
    }
    match nested.as_slice() {
        [declaration] => Ok(Some(*declaration)),
        [] => Ok(None),
        _ => Err(AdaptationFailure::Ambiguous),
    }
}

fn unique_top_level_type<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    source: &str,
    name: &str,
    use_site: Node<'tree>,
) -> Result<Option<&'a TypeDeclaration<'tree>>, AdaptationFailure> {
    let use_package = compilation_unit(use_site)
        .map(|root| scala_enclosing_package_segments_at(root, source, use_site.start_byte()))
        .unwrap_or_default();
    let top_level = declarations
        .iter()
        .filter(|declaration| {
            is_type_namespace(declaration.node)
                && declaration.name.as_ref() == name
                && declaration.owners.is_empty()
                && declaration.package.as_ref() == use_package.as_slice()
        })
        .collect::<Vec<_>>();
    match top_level.as_slice() {
        [declaration] => Ok(Some(*declaration)),
        [] => Ok(None),
        _ => Err(AdaptationFailure::Ambiguous),
    }
}

fn unique_imported_type<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    imports: &[CatalogImport],
    source: &str,
    name: &str,
    use_site: Node<'tree>,
) -> Result<Option<&'a TypeDeclaration<'tree>>, AdaptationFailure> {
    let visible = imports_visible_at(imports, source, use_site);
    let explicit = visible
        .iter()
        .copied()
        .filter(|import| {
            !import.info.is_wildcard
                && !import.given_wildcard
                && import.info.local_name() == Some(name)
        })
        .collect::<Vec<_>>();
    if !explicit.is_empty() {
        let mut resolved = Vec::new();
        for import in explicit {
            match imported_type_declaration(declarations, source, import, use_site) {
                Ok(Some(declaration)) => resolved.push(declaration),
                Ok(None) | Err(AdaptationFailure::Unresolved) => {
                    return Err(AdaptationFailure::Unresolved);
                }
                Err(AdaptationFailure::Ambiguous) => return Err(AdaptationFailure::Ambiguous),
            }
        }
        resolved.sort_by_key(|declaration| declaration.node.id());
        resolved.dedup_by_key(|declaration| declaration.node.id());
        return match resolved.as_slice() {
            [declaration] => Ok(Some(*declaration)),
            [] => Err(AdaptationFailure::Unresolved),
            _ => Err(AdaptationFailure::Ambiguous),
        };
    }
    let mut wildcard_types = Vec::new();
    for import in visible
        .iter()
        .copied()
        .filter(|import| import.info.is_wildcard && !import.given_wildcard)
    {
        match resolve_import_owner_parts(declarations, source, import, use_site) {
            Ok(owner) => {
                let members = declarations
                    .iter()
                    .filter(|declaration| {
                        is_type_namespace(declaration.node)
                            && declaration.name.as_ref() == name
                            && declaration
                                .enclosing_template
                                .is_some_and(|template| template.id() == owner.node.id())
                    })
                    .collect::<Vec<_>>();
                match members.as_slice() {
                    [declaration] => wildcard_types.push(*declaration),
                    [] => {}
                    _ => return Err(AdaptationFailure::Ambiguous),
                }
            }
            Err(AdaptationFailure::Ambiguous) => return Err(AdaptationFailure::Ambiguous),
            Err(AdaptationFailure::Unresolved) => return Err(AdaptationFailure::Unresolved),
        }
    }
    wildcard_types.sort_by_key(|declaration| declaration.node.id());
    wildcard_types.dedup_by_key(|declaration| declaration.node.id());
    match wildcard_types.as_slice() {
        [declaration] => Ok(Some(*declaration)),
        [] => Ok(None),
        _ => Err(AdaptationFailure::Ambiguous),
    }
}

fn imported_type_declaration<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    source: &str,
    import: &CatalogImport,
    use_site: Node<'tree>,
) -> Result<Option<&'a TypeDeclaration<'tree>>, AdaptationFailure> {
    let owner = resolve_import_owner_parts(declarations, source, import, use_site)?;
    let Some(member) = import_source_member(import) else {
        return Ok(None);
    };
    let members = declarations
        .iter()
        .filter(|declaration| {
            is_type_namespace(declaration.node)
                && declaration.name.as_ref() == member
                && declaration
                    .enclosing_template
                    .is_some_and(|template| template.id() == owner.node.id())
        })
        .collect::<Vec<_>>();
    match members.as_slice() {
        [declaration] => Ok(Some(*declaration)),
        [] => Ok(None),
        _ => Err(AdaptationFailure::Ambiguous),
    }
}

fn imports_visible_at<'a>(
    imports: &'a [CatalogImport],
    source: &str,
    use_site: Node<'_>,
) -> Vec<&'a CatalogImport> {
    let Some(root) = compilation_unit(use_site) else {
        return Vec::new();
    };
    let prefixes = scala_package_prefixes_at(root, source, use_site.start_byte());
    let scopes = scala_lexical_scope_path(use_site);
    imports
        .iter()
        .filter(|import| {
            scala_import_visible_at(&import.info, &prefixes, &scopes, use_site.start_byte())
        })
        .collect()
}

fn resolve_import_owner<'a, 'tree>(
    catalog: &'a ScalaAdaptationCatalog<'tree>,
    source: &str,
    import: &CatalogImport,
    use_site: Node<'tree>,
) -> Result<&'a TypeDeclaration<'tree>, AdaptationFailure> {
    resolve_import_owner_parts(&catalog.type_declarations, source, import, use_site)
}

fn resolve_import_owner_parts<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    source: &str,
    import: &CatalogImport,
    use_site: Node<'tree>,
) -> Result<&'a TypeDeclaration<'tree>, AdaptationFailure> {
    if import.owner_shadowed {
        return Err(AdaptationFailure::Unresolved);
    }
    let Some(owner_path) = import_owner_path(import) else {
        return Err(AdaptationFailure::Unresolved);
    };
    let root = compilation_unit(use_site).ok_or(AdaptationFailure::Unresolved)?;
    resolve_stable_owner(
        declarations,
        source,
        owner_path,
        import_declaration(import, root),
    )
}

fn resolve_stable_owner<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    source: &str,
    path: &[String],
    use_site: Node<'tree>,
) -> Result<&'a TypeDeclaration<'tree>, AdaptationFailure> {
    if path.is_empty() {
        return Err(AdaptationFailure::Unresolved);
    }
    if path.len() > 1 {
        let exact = declarations
            .iter()
            .filter(|declaration| {
                is_stable_owner(declaration.node) && declaration.full_path() == path
            })
            .collect::<Vec<_>>();
        return match exact.as_slice() {
            [declaration] => Ok(*declaration),
            [] => Err(AdaptationFailure::Unresolved),
            _ => Err(AdaptationFailure::Ambiguous),
        };
    }
    let name = path[0].as_str();
    if let Some(declaration) = unique_nested_stable(declarations, name, use_site)? {
        return Ok(declaration);
    }
    let use_package = compilation_unit(use_site)
        .map(|root| scala_enclosing_package_segments_at(root, source, use_site.start_byte()))
        .unwrap_or_default();
    let top_level = declarations
        .iter()
        .filter(|declaration| {
            is_stable_owner(declaration.node)
                && declaration.name.as_ref() == name
                && declaration.owners.is_empty()
                && declaration.package.as_ref() == use_package.as_slice()
        })
        .collect::<Vec<_>>();
    match top_level.as_slice() {
        [declaration] => Ok(*declaration),
        [] => Err(AdaptationFailure::Unresolved),
        _ => Err(AdaptationFailure::Ambiguous),
    }
}

fn unique_nested_stable<'a, 'tree>(
    declarations: &'a [TypeDeclaration<'tree>],
    name: &str,
    use_site: Node<'tree>,
) -> Result<Option<&'a TypeDeclaration<'tree>>, AdaptationFailure> {
    let nested = declarations
        .iter()
        .filter(|declaration| {
            is_stable_owner(declaration.node)
                && declaration.name.as_ref() == name
                && !declaration.owners.is_empty()
                && owner_encloses(declaration.enclosing_template, use_site)
        })
        .collect::<Vec<_>>();
    match nested.as_slice() {
        [declaration] => Ok(Some(*declaration)),
        [] => Ok(None),
        _ => Err(AdaptationFailure::Ambiguous),
    }
}

fn scala_scope_for<'tree>(node: Node<'tree>, root: Node<'tree>) -> Node<'tree> {
    nearest_ancestor(node, |kind| {
        SCALA_KIND_TABLE.iter().any(|(syntax, normalized)| {
            *syntax == kind
                && SCALA_STRUCTURAL_SPEC
                    .scope_formation(*normalized)
                    .opens_scope()
        })
    })
    .unwrap_or(root)
}

fn import_declaration<'tree>(import: &CatalogImport, root: Node<'tree>) -> Node<'tree> {
    let start = import
        .info
        .path
        .as_ref()
        .expect("catalog import has a structured path")
        .declaration_start_byte;
    let token = root
        .descendant_for_byte_range(start, start + 1)
        .expect("catalog import belongs to this syntax tree");
    if token.kind() == "import_declaration" {
        token
    } else {
        nearest_ancestor(token, |kind| kind == "import_declaration")
            .expect("structured import start identifies its declaration")
    }
}

fn import_owner_path(import: &CatalogImport) -> Option<&[String]> {
    let segments = import.info.path.as_ref()?.segments.as_slice();
    if import.info.is_wildcard {
        return (!segments.is_empty()).then_some(segments);
    }
    (segments.len() >= 2).then_some(&segments[..segments.len() - 1])
}

fn import_source_member(import: &CatalogImport) -> Option<&str> {
    if import.info.is_wildcard {
        return None;
    }
    import
        .info
        .path
        .as_ref()
        .and_then(|path| path.segments.last())
        .map(String::as_str)
}

fn import_is_given_wildcard(import: Node<'_>, source: &str) -> bool {
    let mut stack = vec![import];
    while let Some(node) = stack.pop() {
        if node.kind() == "namespace_wildcard" {
            if nonempty_text(source, node) == Some("given") {
                return true;
            }
            if (0..node.child_count()).any(|index| {
                node.child(index)
                    .is_some_and(|child| !child.is_named() && child.kind() == "given")
            }) {
                return true;
            }
        }
        stack.extend(named_children(node));
    }
    false
}

fn enclosing_template_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) && let Some(name) = template_name(parent, source)
        {
            names.push(name.to_string());
        }
        current = parent;
    }
    names.reverse();
    names
}

fn enclosing_template(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn declaring_scope(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "function_definition"
                | "lambda_expression"
                | "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "package_clause"
                | "compilation_unit"
        ) {
            return parent;
        }
        node = parent;
    }
    node
}

fn is_type_namespace(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition" | "trait_definition" | "enum_definition" | "type_definition"
    )
}

fn is_stable_owner(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
    )
}

fn is_local_scope(scope: Node<'_>) -> bool {
    matches!(
        scope.kind(),
        "function_definition" | "lambda_expression" | "block" | "indented_block"
    )
}

fn owner_encloses(owner: Option<Node<'_>>, use_site: Node<'_>) -> bool {
    let Some(owner) = owner else {
        return true;
    };
    let mut current = Some(use_site);
    while let Some(node) = current {
        if node.id() == owner.id() {
            return true;
        }
        current = node.parent();
    }
    false
}

fn compilation_unit(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "compilation_unit" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn template_name(node: Node<'_>, source: &str) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_text(source, name))
        .map(Box::from)
}

fn nonempty_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

fn parameter_list_is_contextual(list: Node<'_>) -> bool {
    let mut cursor = list.walk();
    list.children(&mut cursor)
        .any(|child| matches!(child.kind(), "using" | "implicit"))
}

fn subtree_has_kind(node: Node<'_>, kind: &str) -> bool {
    let mut stack = vec![node];
    let mut examined = 0_usize;
    while let Some(current) = stack.pop() {
        examined += 1;
        if examined > ADAPTATION_NODE_BUDGET {
            return false;
        }
        if current.kind() == kind {
            return true;
        }
        stack.extend(named_children(current));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        AdaptationFailure, ScalaAdaptationCatalog, ScalaTypeBinding, SelectedAdaptationKind,
        scala_nominal_types_match,
    };
    use crate::hash::HashMap;

    impl ScalaAdaptationCatalog<'_> {
        fn force_incomplete(&mut self) {
            self.complete = false;
        }
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::analyzer::scala::language::LANGUAGE.into())
            .expect("load Scala grammar");
        let tree = parser.parse(source, None).expect("parse Scala");
        assert!(
            !tree.root_node().has_error(),
            "Scala fixture must parse:\n{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    fn catalog<'tree>(
        source: &'tree str,
        tree: &'tree tree_sitter::Tree,
    ) -> ScalaAdaptationCatalog<'tree> {
        ScalaAdaptationCatalog::collect(source, tree.root_node(), &HashMap::default())
    }

    #[test]
    fn prelude_int_paths_match_and_foreign_int_does_not() {
        assert!(scala_nominal_types_match(
            &["Int".to_owned()],
            &["scala".to_owned(), "Int".to_owned()]
        ));
        assert!(!scala_nominal_types_match(
            &["Int".to_owned()],
            &["foo".to_owned(), "Int".to_owned()]
        ));
    }

    #[test]
    fn uniquely_selected_given_conversion_is_in_scope_of_its_object() {
        const SOURCE: &str = r#"
object Exact {
  given Conversion[Int, String] = (value: Int) => value.toString
  def convert(value: Int): String = value
}
object WrongScope {
  given Conversion[Int, String] = (value: Int) => "wrong"
  def convert(value: Int): String = value
}
object Empty {
  def none(value: Int): String = value
}
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let exact = find_named(&tree, SOURCE, "object_definition", "Exact");
        let convert = find_child_named(exact, SOURCE, "function_definition", "convert");
        let selected = catalog
            .select(SOURCE, convert, &["Int".to_owned()], &["String".to_owned()])
            .expect("unique in-scope Conversion");
        assert!(matches!(
            selected.kind,
            SelectedAdaptationKind::ImplicitCall { .. }
        ));
        let none = find_named(&tree, SOURCE, "function_definition", "none");
        assert!(
            catalog
                .select(SOURCE, none, &["Int".to_owned()], &["String".to_owned()],)
                .is_err(),
            "a use site outside the given's object must not select it"
        );
    }

    #[test]
    fn source_owned_anyval_is_not_language_anyval() {
        const SOURCE: &str = r#"
class AnyVal
class Meter(val value: Int) extends AnyVal
object App { def fake(raw: Int): Meter = new Meter(raw) }
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let fake = find_named(&tree, SOURCE, "function_definition", "fake");
        assert!(
            catalog
                .value_class_for_type(SOURCE, fake, &["Meter".to_owned()])
                .is_none(),
            "a class that extends a source-owned AnyVal is not a value class"
        );
    }

    #[test]
    fn genuine_value_class_is_distinct_from_qualified_ordinary_class() {
        const SOURCE: &str = r#"
class Meter(val value: Int) extends AnyVal
package other {
  class Meter(val value: Int)
}
object App {
  def wrap(raw: Int): Meter = new Meter(raw)
  def fakeNew(raw: Int): other.Meter = new other.Meter(raw)
  def fakeUnwrap(m: other.Meter): Int = m.value
}
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let wrap = find_named(&tree, SOURCE, "function_definition", "wrap");
        assert!(
            catalog
                .value_class_for_type(SOURCE, wrap, &["Meter".to_owned()])
                .is_some(),
            "file-local Meter must remain a value class"
        );
        let fake_new = find_named(&tree, SOURCE, "function_definition", "fakeNew");
        assert!(
            catalog
                .value_class_for_type(SOURCE, fake_new, &["other".to_owned(), "Meter".to_owned()])
                .is_none(),
            "other.Meter must not inherit the local value-class identity"
        );
        let fake_unwrap = find_named(&tree, SOURCE, "function_definition", "fakeUnwrap");
        assert!(
            catalog
                .value_class_unwrap(
                    SOURCE,
                    &["other".to_owned(), "Meter".to_owned()],
                    "value",
                    fake_unwrap
                )
                .is_none(),
            "unwrapping must require the wrapper's exact type identity"
        );
    }

    #[test]
    fn method_local_implicit_does_not_leak_into_sibling() {
        const SOURCE: &str = r#"
object App {
  def inside(x: Int): String = {
    implicit def convert(i: Int): String = i.toString
    x
  }
  def outside(x: Int): String = x
}
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let inside = find_named(&tree, SOURCE, "function_definition", "inside");
        let inside_use = function_result_site(inside);
        catalog
            .select(
                SOURCE,
                inside_use,
                &["Int".to_owned()],
                &["String".to_owned()],
            )
            .expect("method-local implicit is in scope at its own use site");
        let outside = find_named(&tree, SOURCE, "function_definition", "outside");
        let outside_use = function_result_site(outside);
        assert!(
            matches!(
                catalog.select(
                    SOURCE,
                    outside_use,
                    &["Int".to_owned()],
                    &["String".to_owned()],
                ),
                Err(AdaptationFailure::Unresolved)
            ),
            "a sibling must not see a method-local implicit"
        );
    }

    #[test]
    fn method_local_import_does_not_leak_into_sibling() {
        const SOURCE: &str = r#"
object Convert { implicit def convert(x: Int): String = x.toString }
object App {
  def inside(x: Int): String = { import Convert.convert; x }
  def outside(x: Int): String = x
}
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let inside = find_named(&tree, SOURCE, "function_definition", "inside");
        let inside_use = function_result_site(inside);
        catalog
            .select(
                SOURCE,
                inside_use,
                &["Int".to_owned()],
                &["String".to_owned()],
            )
            .expect("explicit import in the same method selects the conversion");
        let outside = find_named(&tree, SOURCE, "function_definition", "outside");
        let outside_use = function_result_site(outside);
        assert!(
            matches!(
                catalog.select(
                    SOURCE,
                    outside_use,
                    &["Int".to_owned()],
                    &["String".to_owned()],
                ),
                Err(AdaptationFailure::Unresolved)
            ),
            "a sibling must not see a method-local import"
        );
    }

    #[test]
    fn object_member_implicit_stays_in_scope_and_wildcard_given_does_not_select() {
        const SOURCE: &str = r#"
object Givens {
  given Conversion[Int, String] = (value: Int) => value.toString
}
object App {
  implicit def convert(i: Int): String = i.toString
  def use(x: Int): String = x
}
object Wildcard {
  def wildcard(x: Int): String = {
    import Givens.given
    x
  }
}
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let use_site =
            function_result_site(find_named(&tree, SOURCE, "function_definition", "use"));
        catalog
            .select(
                SOURCE,
                use_site,
                &["Int".to_owned()],
                &["String".to_owned()],
            )
            .expect("an implicit declared in the same object remains selectable");
        let wildcard =
            function_result_site(find_named(&tree, SOURCE, "function_definition", "wildcard"));
        assert!(
            matches!(
                catalog.select(
                    SOURCE,
                    wildcard,
                    &["Int".to_owned()],
                    &["String".to_owned()],
                ),
                Err(AdaptationFailure::Unresolved)
            ),
            "a Scala 3 given wildcard import must not uniquely select a conversion"
        );
    }

    #[test]
    fn incomplete_catalog_does_not_certify_uniqueness() {
        const SOURCE: &str = r#"
class Meter(val value: Int) extends AnyVal
object Exact {
  given Conversion[Int, String] = (value: Int) => value.toString
  def convert(value: Int): String = value
}
"#;
        let tree = parse(SOURCE);
        let mut catalog = catalog(SOURCE, &tree);
        let convert = find_named(&tree, SOURCE, "function_definition", "convert");
        catalog
            .select(SOURCE, convert, &["Int".to_owned()], &["String".to_owned()])
            .expect("complete catalog may select the unique given");
        catalog.force_incomplete();
        assert!(
            catalog
                .select(SOURCE, convert, &["Int".to_owned()], &["String".to_owned()],)
                .is_err(),
            "an incomplete catalog must not certify a unique conversion"
        );
        assert!(
            catalog
                .value_class_for_type(SOURCE, convert, &["Meter".to_owned()])
                .is_none(),
            "an incomplete catalog must not certify a unique value class"
        );
        let meter = find_named(&tree, SOURCE, "class_definition", "Meter");
        assert!(
            !matches!(
                catalog.bind_nominal_type(SOURCE, &["AnyVal".to_owned()], meter),
                Ok(ScalaTypeBinding::Prelude)
            ),
            "an incomplete catalog must not certify prelude AnyVal"
        );
    }

    #[test]
    fn imported_ordinary_member_does_not_select_unrelated_implicit() {
        const SOURCE: &str = r#"
object Actual { implicit def convert(x: Int): String = x.toString }
object Other { def convert(x: Int): String = x.toString }
object App {
  import Other.convert
  def outside(x: Int): String = x
}
object Aliased {
  import Other.{convert => conv}
  def aliased(x: Int): String = x
}
object Hidden {
  import Other.{convert => _}
  def hidden(x: Int): String = x
}
object Selected {
  import Actual.{convert => conv}
  def selected(x: Int): String = x
}
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        for name in ["outside", "aliased", "hidden"] {
            let use_site =
                function_result_site(find_named(&tree, SOURCE, "function_definition", name));
            assert!(
                matches!(
                    catalog.select(
                        SOURCE,
                        use_site,
                        &["Int".to_owned()],
                        &["String".to_owned()],
                    ),
                    Err(AdaptationFailure::Unresolved)
                ),
                "{name}: imported ordinary convert must not select Actual.convert"
            );
        }
        let selected =
            function_result_site(find_named(&tree, SOURCE, "function_definition", "selected"));
        catalog
            .select(
                SOURCE,
                selected,
                &["Int".to_owned()],
                &["String".to_owned()],
            )
            .expect("import Actual.convert as conv still selects Actual.convert");
    }

    #[test]
    fn imported_anyval_is_not_language_anyval() {
        const SOURCE: &str = r#"
object Foreign { class AnyVal }
import Foreign.AnyVal
class Meter(val value: Int) extends AnyVal
object App { def fake(raw: Int): Meter = new Meter(raw) }
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let fake = find_named(&tree, SOURCE, "function_definition", "fake");
        assert!(
            catalog
                .value_class_for_type(SOURCE, fake, &["Meter".to_owned()])
                .is_none(),
            "Meter that extends an imported AnyVal is not a value class"
        );
        let meter = find_named(&tree, SOURCE, "class_definition", "Meter");
        assert!(
            !matches!(
                catalog.bind_nominal_type(SOURCE, &["AnyVal".to_owned()], meter),
                Ok(ScalaTypeBinding::Prelude)
            ),
            "imported AnyVal must not bind as prelude"
        );
    }

    #[test]
    fn type_parameter_shadows_value_class_unwrap() {
        const SOURCE: &str = r#"
class Ordinary(val value: Int)
class Meter(val value: Int) extends AnyVal
object App {
  def shadow[Meter <: Ordinary](m: Meter): Int = m.value
  def real(m: Meter): Int = m.value
}
class Host[Meter <: Ordinary] {
  def nested(m: Meter): Int = m.value
}
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let shadow = find_named(&tree, SOURCE, "function_definition", "shadow");
        let shadowed = function_result_site(shadow);
        assert!(
            catalog
                .value_class_unwrap(SOURCE, &["Meter".to_owned()], "value", shadowed)
                .is_none(),
            "a type-parameter Meter must not unwrap as the file value class"
        );
        let nested =
            function_result_site(find_named(&tree, SOURCE, "function_definition", "nested"));
        assert!(
            catalog
                .value_class_unwrap(SOURCE, &["Meter".to_owned()], "value", nested)
                .is_none(),
            "an enclosing type-parameter Meter must not unwrap as the file value class"
        );
        let real = function_result_site(find_named(&tree, SOURCE, "function_definition", "real"));
        assert!(
            catalog
                .value_class_unwrap(SOURCE, &["Meter".to_owned()], "value", real)
                .is_some(),
            "an unshadowed Meter parameter still unwraps as the value class"
        );
    }

    #[test]
    fn qualified_scala_anyval_remains_a_value_class() {
        const SOURCE: &str = r#"
class AnyVal
class Meter(val value: Int) extends scala.AnyVal
object App { def wrap(raw: Int): Meter = new Meter(raw) }
"#;
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let wrap = find_named(&tree, SOURCE, "function_definition", "wrap");
        assert!(
            catalog
                .value_class_for_type(SOURCE, wrap, &["Meter".to_owned()])
                .is_some(),
            "qualified scala.AnyVal still identifies a value class"
        );
    }

    fn function_result_site(function: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
        let body = function.child_by_field_name("body").unwrap_or(function);
        let mut current = body;
        loop {
            let children = {
                let mut cursor = current.walk();
                current
                    .named_children(&mut cursor)
                    .filter(|child| {
                        !matches!(
                            child.kind(),
                            "comment" | "line_comment" | "block_comment" | "import_declaration"
                        )
                    })
                    .collect::<Vec<_>>()
            };
            match children.last() {
                Some(last) if last.id() != current.id() => current = *last,
                _ => return current,
            }
        }
    }

    fn find_named<'tree>(
        tree: &'tree tree_sitter::Tree,
        source: &str,
        kind: &str,
        name: &str,
    ) -> tree_sitter::Node<'tree> {
        find_child_named(tree.root_node(), source, kind, name)
    }

    fn find_child_named<'tree>(
        root: tree_sitter::Node<'tree>,
        source: &str,
        kind: &str,
        name: &str,
    ) -> tree_sitter::Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind
                && node
                    .child_by_field_name("name")
                    .and_then(|declared| source.get(declared.byte_range()))
                    == Some(name)
            {
                return node;
            }
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        }
        panic!("missing {kind} named {name}")
    }
    #[test]
    fn unresolved_import_competitor_does_not_prove_a_known_type() {
        const SOURCE: &str = "object Local { class Meter(val value: Int) extends AnyVal }\nimport Local.Meter\nimport external.Meter\nobject App { def fake(raw: Int): Meter = new Meter(raw) }";
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let site = function_result_site(find_named(&tree, SOURCE, "function_definition", "fake"));
        assert!(matches!(
            catalog.bind_nominal_type(SOURCE, &["Meter".to_owned()], site),
            Err(AdaptationFailure::Unresolved)
        ));
    }

    #[test]
    fn import_owner_value_binding_prevents_an_unrelated_implicit_proof() {
        const SOURCE: &str = "object Convert { implicit def convert(x: Int): String = x.toString }\nobject Other { def convert(x: Int): String = x.toString }\nobject App { val Convert = Other; import Convert.convert; def outside(x: Int): String = x }";
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let site =
            function_result_site(find_named(&tree, SOURCE, "function_definition", "outside"));
        assert!(matches!(
            catalog.select(SOURCE, site, &["Int".to_owned()], &["String".to_owned()]),
            Err(AdaptationFailure::Unresolved)
        ));
    }

    #[test]
    fn unresolved_wildcard_does_not_certify_prelude_anyval() {
        const SOURCE: &str = "import external.*\nclass Meter(val value: Int) extends AnyVal\nclass Exact(val value: Int) extends _root_.scala.AnyVal";
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let meter = find_named(&tree, SOURCE, "class_definition", "Meter");
        assert!(matches!(
            catalog.bind_nominal_type(SOURCE, &["AnyVal".to_owned()], meter),
            Err(AdaptationFailure::Unresolved)
        ));
        assert!(
            !catalog
                .value_classes
                .iter()
                .any(|class| class.class == meter)
        );
        let exact = find_named(&tree, SOURCE, "class_definition", "Exact");
        assert!(
            catalog
                .value_classes
                .iter()
                .any(|class| class.class == exact)
        );
    }
    #[test]
    fn qualified_prelude_root_respects_term_shadowing() {
        const SOURCE: &str = "object Foreign { class AnyVal }\nobject App { val scala = Foreign; class Meter(val value: Int) extends scala.AnyVal; class Exact(val value: Int) extends _root_.scala.AnyVal }";
        let tree = parse(SOURCE);
        let catalog = catalog(SOURCE, &tree);
        let meter = find_named(&tree, SOURCE, "class_definition", "Meter");
        assert!(matches!(
            catalog.bind_nominal_type(SOURCE, &["scala".to_owned(), "AnyVal".to_owned()], meter),
            Err(AdaptationFailure::Unresolved)
        ));
        assert!(
            !catalog
                .value_classes
                .iter()
                .any(|class| class.class == meter)
        );
        let exact = find_named(&tree, SOURCE, "class_definition", "Exact");
        assert!(
            catalog
                .value_classes
                .iter()
                .any(|class| class.class == exact)
        );
    }
}
