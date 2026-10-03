//! Canonical declaration properties captured by the C/C++ primary producer.

use super::model::{CppTemplateExpression, StructuredTypeName};
use super::source_facts::{SourceDeclarationId, SourceOccurrenceId};

pub const CPP_SOURCE_FACTS_VERSION: i64 = 1;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CppOccurrenceRole {
    DeclarationOnly,
    Definition,
    Both,
    #[default]
    Unknown,
}

impl CppOccurrenceRole {
    pub fn api_label(self) -> Option<&'static str> {
        match self {
            Self::DeclarationOnly => Some("declaration"),
            Self::Definition => Some("definition"),
            Self::Both | Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppGuardSet {
    pub nodes: Vec<CppGuardNode>,
    pub roots: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CppGuardNode {
    Defined(String),
    Undefined(String),
    Boolean(usize),
    Expression(String),
    NegatedExpression(String),
    Constant(bool),
    Truthy(String),
    Falsy(String),
    Opaque(String),
    NegatedOpaque(String),
    All(Vec<usize>),
    Any(Vec<usize>),
}

impl CppGuardSet {
    pub fn new(nodes: Vec<CppGuardNode>, roots: Vec<usize>) -> Self {
        Self { nodes, roots }
    }

    pub fn valid(&self) -> bool {
        if !self.roots.iter().all(|root| *root < self.nodes.len()) {
            return false;
        }
        let mut references = vec![0usize; self.nodes.len()];
        for (index, node) in self.nodes.iter().enumerate() {
            let mut count_child = |child: usize| {
                if child >= index {
                    return false;
                }
                references[child] = references[child].saturating_add(1);
                true
            };
            let valid = match node {
                CppGuardNode::Boolean(root) => count_child(*root),
                CppGuardNode::All(children) | CppGuardNode::Any(children) => {
                    children.iter().copied().all(count_child)
                }
                _ => true,
            };
            if !valid {
                return false;
            }
        }
        for root in &self.roots {
            references[*root] = references[*root].saturating_add(1);
        }
        references.into_iter().all(|references| references == 1)
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppComparableSlot {
    Shape(CppComparableParameter),
    Ellipsis,
    Unstructured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppComparableParameter {
    nodes: Vec<CppComparableNode>,
    root: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppComparableNode {
    Named {
        name: StructuredTypeName,
        primitive: bool,
        konst: bool,
        volatil: bool,
    },
    Pointer {
        inner: usize,
        konst: bool,
        volatil: bool,
    },
    Reference {
        inner: usize,
    },
    Array {
        inner: usize,
    },
    Generic {
        base: usize,
        arguments: Vec<usize>,
    },
}

impl CppComparableParameter {
    pub fn new(nodes: Vec<CppComparableNode>, root: usize) -> Self {
        Self { nodes, root }
    }

    pub fn root(&self) -> usize {
        self.root
    }

    pub fn node(&self, index: usize) -> &CppComparableNode {
        &self.nodes[index]
    }

    pub fn nodes(&self) -> &[CppComparableNode] {
        &self.nodes
    }

    fn valid(&self) -> bool {
        self.root < self.nodes.len()
            && self.nodes.iter().all(|node| match node {
                CppComparableNode::Named { .. } => true,
                CppComparableNode::Pointer { inner, .. }
                | CppComparableNode::Reference { inner }
                | CppComparableNode::Array { inner } => *inner < self.nodes.len(),
                CppComparableNode::Generic { base, arguments } => {
                    *base < self.nodes.len()
                        && arguments
                            .iter()
                            .all(|argument| *argument < self.nodes.len())
                }
            })
    }

    /// Apply the [dcl.fct]/5 parameter-type adjustments, which hold at the
    /// parameter's top level only.
    pub fn adjust_parameter_top_level(&mut self) {
        let root = self.root;
        match &mut self.nodes[root] {
            CppComparableNode::Named { konst, volatil, .. }
            | CppComparableNode::Pointer { konst, volatil, .. } => {
                *konst = false;
                *volatil = false;
            }
            CppComparableNode::Array { inner } => {
                let inner = *inner;
                self.nodes[root] = CppComparableNode::Pointer {
                    inner,
                    konst: false,
                    volatil: false,
                };
            }
            CppComparableNode::Generic { base, .. } => {
                let base = *base;
                let CppComparableNode::Named { konst, volatil, .. } = &mut self.nodes[base] else {
                    unreachable!("a comparable generic's base is always a named leaf");
                };
                *konst = false;
                *volatil = false;
            }
            CppComparableNode::Reference { .. } => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppClassDeclarationStrength {
    Full,
    Forward,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppEnumOwnerKind {
    Scoped,
    Unscoped,
    NonEnum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppDeclaredFieldTypeFact {
    pub type_text: String,
    pub indirection: i32,
    /// The member binds `type_text` through a pointer or a reference, so it
    /// holds no subobject of that type. An array of the type does hold
    /// subobjects, so it is not indirect.
    pub binds_indirectly: bool,
    pub template_arguments: Option<Vec<CppTemplateExpression>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppStructuredAliasTarget {
    Builtin,
    Named {
        components: Vec<String>,
        global: bool,
        arguments: Option<Vec<CppTemplateExpression>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppMemberUsingFact {
    pub member: String,
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppBaseSpecifierFact {
    pub absolute: bool,
    pub components: Vec<String>,
    pub is_virtual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppFileScopeAliasFact {
    pub name: String,
    pub target: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppDeclarationSourceFact {
    pub declaration: SourceDeclarationId,
    pub occurrence_role: CppOccurrenceRole,
    pub conditional_family: Option<SourceOccurrenceId>,
    pub class_strength: CppClassDeclarationStrength,
    pub enum_kind: CppEnumOwnerKind,
    pub field_type: Option<CppDeclaredFieldTypeFact>,
    pub alias_target: Option<CppStructuredAliasTarget>,
    pub alias_target_text: Option<String>,
    pub adds_indirection: bool,
    pub names_function_type: bool,
    pub written_owner: Vec<String>,
    pub lexical_path: Vec<String>,
    pub dependency_type_names: Vec<String>,
    pub file_scope_alias: Option<CppFileScopeAliasFact>,
    pub trailing_qualifiers: String,
    pub member_usings: Vec<CppMemberUsingFact>,
    pub bases: Vec<CppBaseSpecifierFact>,
    pub callable_comparable_shapes: Option<Vec<CppComparableSlot>>,
    pub callable_identity_suffix: Option<String>,
    pub callable_is_constructor: bool,
    pub callable_is_deduction_guide: bool,
    pub callable_is_template: bool,
    pub guard_requirements: Option<CppGuardSet>,
    pub callable_guards: Option<CppGuardSet>,
    pub callable_activation: Option<usize>,
    /// All enclosing undecided conditional families have terminal else arms.
    /// Some(0) means no such family; a positive byte is the outermost family end.
    /// None means a non-exhaustive or unavailable context prevents relaxation.
    pub callable_guard_completion_byte: Option<usize>,
    pub exhaustive_conditional_family: Option<SourceOccurrenceId>,
    pub flattened_macro_namespace: Option<Vec<String>>,
    pub displaced_namespace_closing_brace: Option<SourceOccurrenceId>,
}

impl CppDeclarationSourceFact {
    pub fn new(declaration: SourceDeclarationId) -> Self {
        Self {
            declaration,
            occurrence_role: CppOccurrenceRole::Unknown,
            conditional_family: None,
            class_strength: CppClassDeclarationStrength::Unknown,
            enum_kind: CppEnumOwnerKind::NonEnum,
            field_type: None,
            alias_target: None,
            alias_target_text: None,
            adds_indirection: false,
            names_function_type: false,
            written_owner: Vec::new(),
            lexical_path: Vec::new(),
            dependency_type_names: Vec::new(),
            file_scope_alias: None,
            trailing_qualifiers: String::new(),
            member_usings: Vec::new(),
            bases: Vec::new(),
            callable_comparable_shapes: None,
            callable_identity_suffix: None,
            callable_is_constructor: false,
            callable_is_deduction_guide: false,
            callable_is_template: false,
            guard_requirements: None,
            callable_guards: None,
            callable_activation: None,
            callable_guard_completion_byte: None,
            exhaustive_conditional_family: None,
            flattened_macro_namespace: None,
            displaced_namespace_closing_brace: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppIncludeFact {
    pub declaration: SourceOccurrenceId,
    pub target: SourceOccurrenceId,
    pub path: String,
    pub quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppSourceFacts {
    pub includes: Vec<CppIncludeFact>,
    pub declarations: Vec<CppDeclarationSourceFact>,
    pub using_namespaces: Vec<(SourceOccurrenceId, String)>,
}

impl CppSourceFacts {
    pub fn valid_links(&self, source: &super::source_facts::SourceFactRows) -> bool {
        let mut seen = crate::hash::HashSet::default();
        self.includes.iter().all(|include| {
            include.declaration.index() < source.occurrence_count()
                && include.target.index() < source.occurrence_count()
        }) && self.declarations.iter().all(|fact| {
            fact.declaration.index() < source.declaration_count()
                && fact
                    .conditional_family
                    .is_none_or(|occurrence| occurrence.index() < source.occurrence_count())
                && fact
                    .guard_requirements
                    .as_ref()
                    .is_none_or(CppGuardSet::valid)
                && fact.callable_guards.as_ref().is_none_or(CppGuardSet::valid)
                && fact
                    .exhaustive_conditional_family
                    .is_none_or(|occurrence| occurrence.index() < source.occurrence_count())
                && fact
                    .displaced_namespace_closing_brace
                    .is_none_or(|occurrence| occurrence.index() < source.occurrence_count())
                && fact
                    .callable_comparable_shapes
                    .as_ref()
                    .is_none_or(|shapes| {
                        shapes.iter().all(|shape| {
                            !matches!(
                                shape,
                                CppComparableSlot::Shape(parameter) if !parameter.valid()
                            )
                        })
                    })
                && seen.insert(fact.declaration)
        }) && self
            .using_namespaces
            .iter()
            .all(|(occurrence, _)| occurrence.index() < source.occurrence_count())
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = self.includes.capacity() * std::mem::size_of::<CppIncludeFact>()
            + self.declarations.capacity() * std::mem::size_of::<CppDeclarationSourceFact>()
            + self.using_namespaces.capacity()
                * std::mem::size_of::<(SourceOccurrenceId, String)>();
        for fact in &self.declarations {
            if let Some(alias) = &fact.file_scope_alias {
                bytes += alias.name.capacity()
                    + alias.target.capacity()
                    + alias.namespace.as_ref().map_or(0, String::capacity);
            }
            bytes += fact.trailing_qualifiers.capacity()
                + fact.alias_target_text.as_ref().map_or(0, String::capacity)
                + fact
                    .callable_identity_suffix
                    .as_ref()
                    .map_or(0, String::capacity);
            for guards in [&fact.guard_requirements, &fact.callable_guards]
                .into_iter()
                .flatten()
            {
                bytes += guards.nodes.capacity() * std::mem::size_of::<CppGuardNode>()
                    + guards.roots.capacity() * std::mem::size_of::<usize>();
                for node in &guards.nodes {
                    match node {
                        CppGuardNode::Defined(value)
                        | CppGuardNode::Undefined(value)
                        | CppGuardNode::Expression(value)
                        | CppGuardNode::NegatedExpression(value)
                        | CppGuardNode::Truthy(value)
                        | CppGuardNode::Falsy(value)
                        | CppGuardNode::Opaque(value)
                        | CppGuardNode::NegatedOpaque(value) => bytes += value.capacity(),
                        CppGuardNode::All(children) | CppGuardNode::Any(children) => {
                            bytes += children.capacity() * std::mem::size_of::<usize>();
                        }
                        CppGuardNode::Boolean(_) | CppGuardNode::Constant(_) => {}
                    }
                }
            }
            bytes += (fact.written_owner.capacity()
                + fact.lexical_path.capacity()
                + fact.dependency_type_names.capacity())
                * std::mem::size_of::<String>();
            bytes += fact.member_usings.capacity() * std::mem::size_of::<CppMemberUsingFact>()
                + fact.bases.capacity() * std::mem::size_of::<CppBaseSpecifierFact>();
            bytes += fact
                .written_owner
                .iter()
                .chain(&fact.lexical_path)
                .chain(&fact.dependency_type_names)
                .map(String::capacity)
                .sum::<usize>();
            for using in &fact.member_usings {
                bytes += using.scope.capacity() * std::mem::size_of::<String>()
                    + using.member.capacity()
                    + using.scope.iter().map(String::capacity).sum::<usize>();
            }
            for base in &fact.bases {
                bytes += base.components.capacity() * std::mem::size_of::<String>()
                    + base.components.iter().map(String::capacity).sum::<usize>();
            }
            if let Some(components) = &fact.flattened_macro_namespace {
                bytes += components.capacity() * std::mem::size_of::<String>()
                    + components.iter().map(String::capacity).sum::<usize>();
            }
            if let Some(shapes) = &fact.callable_comparable_shapes {
                bytes += shapes.capacity() * std::mem::size_of::<CppComparableSlot>();
                for shape in shapes {
                    let CppComparableSlot::Shape(parameter) = shape else {
                        continue;
                    };
                    bytes += parameter.nodes.capacity() * std::mem::size_of::<CppComparableNode>();
                    for node in &parameter.nodes {
                        match node {
                            CppComparableNode::Named { name, .. } => {
                                bytes += (name.path().len() + name.lexical_scope().len())
                                    * std::mem::size_of::<String>();
                                bytes += name.path().iter().map(String::capacity).sum::<usize>();
                                bytes += name
                                    .lexical_scope()
                                    .iter()
                                    .map(String::capacity)
                                    .sum::<usize>();
                            }
                            CppComparableNode::Generic { arguments, .. } => {
                                bytes += arguments.capacity() * std::mem::size_of::<usize>();
                            }
                            _ => {}
                        }
                    }
                }
            }
            if let Some(field) = &fact.field_type {
                bytes += field.type_text.capacity();
            }
            if let Some(CppStructuredAliasTarget::Named { components, .. }) = &fact.alias_target {
                bytes += components.capacity() * std::mem::size_of::<String>()
                    + components.iter().map(String::capacity).sum::<usize>();
            }
            let field_arguments = fact
                .field_type
                .as_ref()
                .and_then(|field| field.template_arguments.as_deref())
                .unwrap_or_default();
            let alias_arguments = match &fact.alias_target {
                Some(CppStructuredAliasTarget::Named {
                    arguments: Some(arguments),
                    ..
                }) => arguments.as_slice(),
                _ => &[],
            };
            for expression in field_arguments.iter().chain(alias_arguments) {
                bytes += expression.text.capacity();
                let mut stack = vec![&expression.term];
                while let Some(term) = stack.pop() {
                    bytes += std::mem::size_of::<super::model::CppTemplateTerm>();
                    match term {
                        super::model::CppTemplateTerm::Parameter(name) => bytes += name.capacity(),
                        super::model::CppTemplateTerm::Atom { kind, text } => {
                            bytes += kind.capacity() + text.capacity()
                        }
                        super::model::CppTemplateTerm::Node { kind, children } => {
                            bytes += kind.capacity();
                            stack.extend(children);
                        }
                    }
                }
            }
        }
        bytes += self
            .includes
            .iter()
            .map(|include| include.path.capacity())
            .sum::<usize>();
        bytes
            + self
                .using_namespaces
                .iter()
                .map(|(_, namespace)| namespace.capacity())
                .sum::<usize>()
    }
}
