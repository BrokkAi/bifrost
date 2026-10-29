//! Structured reconciliation of C++ template heads and class-template owners
//! (#6902 item 7).
//!
//! A declaration and its definition do not have to spell their template
//! heads alike. An in-class `void get(T);` in `template <class T> struct Box`
//! and its out-of-line body `template <typename U> void Box<U>::get(U) {}`
//! declare one member ([temp.mem.func], [temp.over.link]): the heads agree in
//! arity and in the kind of each parameter, the written owner `Box<U>` names
//! the primary template (its arguments are exactly the head's parameters, in
//! order), and the parameter types agree once `U` is read as `T`.
//!
//! This module answers that question from syntax and nothing else. It turns
//! one declaration into a [`CppTemplateContext`] -- the template levels that
//! apply to it, outermost first: each enclosing class with the head that
//! introduces its parameters and the arguments that select it, then the
//! declaration's own head -- and [`CppTemplateContext::reconcile`] decides
//! whether two contexts declare one entity. Equivalence carries a
//! [`CppTemplateBinding`] from the right context's parameter names to the
//! left's, which the caller applies when it compares the parameter types.
//!
//! The comparison is deliberately positional and structural. Parameter names
//! never decide anything; kinds, pack-ness, non-type parameter types,
//! requires-clauses and owner arguments do. A written owner whose arguments are
//! not the head's parameters (`Box<T*>`, `Box<int>`) selects a specialization,
//! which is a different owner from the primary; the arguments are kept as
//! [`CppTemplateTerm`]s so a specialization member can still be matched with
//! its own in-class declaration, and so later owner-selection work (a
//! specialization alias keeping its owner, #6902 item 9) can compare a
//! qualifier's arguments against a specialization's with the same terms.
//!
//! What the module cannot model -- a qualifier spelled through an alias, more
//! heads than the qualifier can consume, a local class, parser recovery --
//! answers [`CppTemplateReconciliation::Unsupported`] rather than either
//! verdict, so callers keep those pairs apart without claiming they differ.

use crate::declarations::{
    cpp_template_parameter_kind, cpp_template_parameter_name, cpp_template_term, node_text,
    normalize_cpp_whitespace,
};
use crate::graph::resolver::{
    cpp_name_component_nodes, cpp_substitute_template_term, cpp_template_terms_equal,
};
use brokk_bifrost_core::analyzer::model::{CppTemplateParameterKind, CppTemplateTerm};
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// What a template parameter is, apart from its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppTemplateParameterShape {
    Type,
    /// A non-type parameter: its declared type and, when the declarator adds
    /// pointer or reference structure, that declarator. Both terms read the
    /// parameters already in scope, the parameter itself included, as
    /// [`CppTemplateTerm::Parameter`].
    Value {
        type_term: CppTemplateTerm,
        declarator: Option<CppTemplateTerm>,
    },
    /// A template template parameter: the kind and pack-ness of each of its
    /// own parameters. Their names are unobservable, and a nested template
    /// template parameter is compared by kind only.
    Template(Vec<(CppTemplateParameterKind, bool)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppTemplateParameter {
    /// The written name, or an impossible identifier for an unnamed one.
    pub name: String,
    pub variadic: bool,
    pub shape: CppTemplateParameterShape,
}

impl CppTemplateParameter {
    /// The argument that names this parameter in its own template: `T`, or
    /// `Ts...` for a pack -- the injected template arguments of a primary
    /// class template ([temp.local]).
    fn injected_argument(&self) -> CppTemplateTerm {
        let parameter = CppTemplateTerm::Parameter(self.name.clone());
        if self.variadic {
            CppTemplateTerm::Node {
                kind: "parameter_pack_expansion".to_owned(),
                children: vec![
                    parameter,
                    CppTemplateTerm::Atom {
                        kind: "...".to_owned(),
                        text: "...".to_owned(),
                    },
                ],
            }
        } else {
            parameter
        }
    }
}

/// One `template <...>` head with a non-empty parameter list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppTemplateHead {
    pub parameters: Vec<CppTemplateParameter>,
    /// The head's requires-clause, over the parameters in scope.
    pub requires: Option<CppTemplateTerm>,
}

/// One level of template ownership: an enclosing class, or the declaration
/// itself (always the last level; its `name` is empty for a callable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppTemplateLevel {
    /// The class name as written at this level; empty for a callable.
    pub name: String,
    /// The head that introduces this level's parameters. `None` for a
    /// non-template level and for an explicit specialization, whose
    /// `template <>` introduces nothing.
    pub head: Option<CppTemplateHead>,
    /// The written template arguments that select this level's class: the
    /// specialization arguments of an in-class declaration's class, or the
    /// qualifier's arguments of an out-of-line one, or a function template
    /// explicit specialization's own arguments. `None` means the primary
    /// template's injected arguments when `head` is present, and a
    /// non-template class otherwise.
    pub arguments: Option<Vec<CppTemplateTerm>>,
}

impl CppTemplateLevel {
    fn is_bare(&self) -> bool {
        self.head.is_none() && self.arguments.is_none()
    }

    /// Whether the written arguments select a specialization rather than the
    /// primary template: they are not the injected arguments of the head that
    /// introduces this level's parameters. `Box<T*>` under `template <class
    /// T>` and `Box<int>` with no head of its own both do; `Box<U>` under
    /// `template <class U>` names the primary.
    pub fn selects_specialization(&self) -> bool {
        let Some(arguments) = &self.arguments else {
            return false;
        };
        let Some(head) = &self.head else {
            return true;
        };
        arguments.len() != head.parameters.len()
            || !arguments
                .iter()
                .zip(&head.parameters)
                .all(|(argument, parameter)| {
                    cpp_template_terms_equal(argument, &parameter.injected_argument())
                })
    }

    fn effective_arguments(&self) -> Option<Vec<CppTemplateTerm>> {
        self.arguments.clone().or_else(|| {
            self.head.as_ref().map(|head| {
                head.parameters
                    .iter()
                    .map(CppTemplateParameter::injected_argument)
                    .collect()
            })
        })
    }
}

/// The template levels that apply to one declaration, outermost first; the
/// last level is the declaration's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppTemplateContext {
    pub levels: Vec<CppTemplateLevel>,
}

/// The right context's template parameters renamed to the left's, position by
/// position. Empty for two non-template contexts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CppTemplateBinding {
    right_to_left: HashMap<String, CppTemplateTerm>,
    left: HashSet<String>,
}

impl CppTemplateBinding {
    pub fn is_empty(&self) -> bool {
        self.left.is_empty()
    }

    pub fn is_left_parameter(&self, name: &str) -> bool {
        self.left.contains(name)
    }

    pub fn is_right_parameter(&self, name: &str) -> bool {
        self.right_to_left.contains_key(name)
    }

    /// Whether `right` is the parameter the binding pairs with `left`.
    pub fn binds(&self, right: &str, left: &str) -> bool {
        matches!(
            self.right_to_left.get(right),
            Some(CppTemplateTerm::Parameter(bound)) if bound == left
        )
    }

    /// `term`, written over the right context's parameters, rewritten over
    /// the left's. `None` when it names a parameter the binding does not know.
    pub fn rename(&self, term: &CppTemplateTerm) -> Option<CppTemplateTerm> {
        cpp_substitute_template_term(term, &self.right_to_left)
    }

    /// Whether a right-context term means what a left-context term means.
    pub fn terms_agree(&self, left: &CppTemplateTerm, right: &CppTemplateTerm) -> bool {
        self.rename(right)
            .is_some_and(|renamed| cpp_template_terms_equal(left, &renamed))
    }

    fn bind(&mut self, right: &str, left: &str) {
        self.left.insert(left.to_owned());
        self.right_to_left.insert(
            right.to_owned(),
            CppTemplateTerm::Parameter(left.to_owned()),
        );
    }
}

/// Whether two template contexts declare one entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppTemplateReconciliation {
    /// The heads and owner arguments agree level by level.
    Equivalent(CppTemplateBinding),
    /// A head, a parameter, a requires-clause or an owner argument list
    /// differs: different arity, kind or pack-ness, a non-type parameter of
    /// another type, a specialization against the primary.
    Distinct,
    /// The levels cannot be aligned structurally, for example because a
    /// qualifier is spelled through an alias.
    Unsupported,
}

impl CppTemplateContext {
    /// Whether any level carries a head or written arguments.
    pub fn is_templated(&self) -> bool {
        self.levels.iter().any(|level| !level.is_bare())
    }

    /// Decide whether `self` and `other` declare one entity.
    ///
    /// Levels are aligned from the declaration outwards. Leading levels only
    /// one side spells -- the namespaces an out-of-line qualifier names, or a
    /// non-template outer class one side omits -- must be bare, because a
    /// level that introduces or selects template arguments has to be matched.
    pub fn reconcile(&self, other: &CppTemplateContext) -> CppTemplateReconciliation {
        let shared = self.levels.len().min(other.levels.len());
        let (left_extra, left) = self.levels.split_at(self.levels.len() - shared);
        let (right_extra, right) = other.levels.split_at(other.levels.len() - shared);
        if !left_extra
            .iter()
            .chain(right_extra)
            .all(CppTemplateLevel::is_bare)
        {
            return CppTemplateReconciliation::Unsupported;
        }
        let mut binding = CppTemplateBinding::default();
        for (left_level, right_level) in left.iter().zip(right) {
            if left_level.name != right_level.name {
                return CppTemplateReconciliation::Unsupported;
            }
            match (&left_level.head, &right_level.head) {
                (None, None) => {}
                (Some(left_head), Some(right_head)) => {
                    if !heads_agree(left_head, right_head, &mut binding) {
                        return CppTemplateReconciliation::Distinct;
                    }
                }
                _ => return CppTemplateReconciliation::Distinct,
            }
            let agree = match (
                left_level.effective_arguments(),
                right_level.effective_arguments(),
            ) {
                (None, None) => true,
                (Some(left_arguments), Some(right_arguments)) => {
                    left_arguments.len() == right_arguments.len()
                        && left_arguments
                            .iter()
                            .zip(&right_arguments)
                            .all(|(left, right)| binding.terms_agree(left, right))
                }
                _ => false,
            };
            if !agree {
                return CppTemplateReconciliation::Distinct;
            }
        }
        CppTemplateReconciliation::Equivalent(binding)
    }
}

/// Compare two heads position by position, extending `binding` with each
/// parameter before its own shape is compared: a later parameter's type may
/// name an earlier one (`template <class T, T value>`), and a non-type
/// parameter's declarator names the parameter itself.
fn heads_agree(
    left: &CppTemplateHead,
    right: &CppTemplateHead,
    binding: &mut CppTemplateBinding,
) -> bool {
    if left.parameters.len() != right.parameters.len() {
        return false;
    }
    for (left_parameter, right_parameter) in left.parameters.iter().zip(&right.parameters) {
        if left_parameter.variadic != right_parameter.variadic {
            return false;
        }
        binding.bind(&right_parameter.name, &left_parameter.name);
        let agree = match (&left_parameter.shape, &right_parameter.shape) {
            (CppTemplateParameterShape::Type, CppTemplateParameterShape::Type) => true,
            (
                CppTemplateParameterShape::Value {
                    type_term: left_type,
                    declarator: left_declarator,
                },
                CppTemplateParameterShape::Value {
                    type_term: right_type,
                    declarator: right_declarator,
                },
            ) => {
                binding.terms_agree(left_type, right_type)
                    && match (left_declarator, right_declarator) {
                        (None, None) => true,
                        (Some(left), Some(right)) => binding.terms_agree(left, right),
                        _ => false,
                    }
            }
            (
                CppTemplateParameterShape::Template(left_kinds),
                CppTemplateParameterShape::Template(right_kinds),
            ) => left_kinds == right_kinds,
            _ => false,
        };
        if !agree {
            return false;
        }
    }
    match (&left.requires, &right.requires) {
        (None, None) => true,
        (Some(left), Some(right)) => binding.terms_agree(left, right),
        _ => false,
    }
}

/// The template context of the declaration `node` -- a function definition,
/// declaration, field declaration or function declarator, or a class
/// specifier -- read from its syntax.
///
/// `None` when the shape is outside what this module models: parser recovery
/// on the path, a local class, a qualified name inside a class body, or more
/// heads than the written owner can consume.
pub fn cpp_declaration_template_context(
    node: Node<'_>,
    source: &str,
) -> Option<CppTemplateContext> {
    let statement = declaration_statement(node)?;
    let (own_heads, top) = direct_template_heads(statement);
    let qualified = declaration_qualifier(statement);
    let mut enclosing = Vec::new();
    let mut current = top;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "field_declaration_list" => {
                let class = parent.parent()?;
                if !is_class_specifier(class) {
                    return None;
                }
                enclosing.push(class);
                current = class;
            }
            "template_declaration"
            | "declaration"
            | "field_declaration"
            | "declaration_list"
            | "namespace_definition"
            | "linkage_specification"
            | "preproc_if"
            | "preproc_ifdef"
            | "preproc_else"
            | "preproc_elif"
            | "preproc_elifdef" => current = parent,
            "translation_unit" => break,
            _ => return None,
        }
    }
    let mut builder = ContextBuilder {
        source,
        ancestry: ParentIndex::unindexed(),
        names: Vec::new(),
        levels: Vec::new(),
    };
    for class in enclosing.into_iter().rev() {
        let (heads, _) = direct_template_heads(class);
        match heads.as_slice() {
            [] => builder.push_class(class, None)?,
            [head] => builder.push_class(class, Some(*head))?,
            _ => return None,
        }
    }
    if is_class_specifier(statement) {
        match own_heads.as_slice() {
            [] => builder.push_class(statement, None)?,
            [head] => builder.push_class(statement, Some(*head))?,
            _ => return None,
        }
        return Some(builder.finish());
    }
    match qualified {
        // An out-of-line definition lives at namespace scope; a qualified
        // name inside a class body is a friend or a recovery artifact.
        Some(_) if !builder.levels.is_empty() => return None,
        Some(qualifier) => builder.push_out_of_line(qualifier, &own_heads)?,
        None => {
            let head = match own_heads.as_slice() {
                [] => None,
                [head] => builder.head(*head)?,
                _ => return None,
            };
            builder.levels.push(CppTemplateLevel {
                name: String::new(),
                head,
                arguments: None,
            });
        }
    }
    // An explicit specialization of a function template, `f<int>`, names its
    // arguments on the declaration itself; they distinguish it from both the
    // primary template and an ordinary function of the same signature.
    if let Some(arguments) = declaration_terminal(statement)
        .filter(|terminal| terminal.kind() == "template_function")
        .and_then(|terminal| terminal.child_by_field_name("arguments"))
    {
        let arguments = builder.arguments(arguments);
        builder.levels.last_mut()?.arguments = Some(arguments);
    }
    Some(builder.finish())
}

/// The owner each qualifier component of the out-of-line declaration `node`
/// names, outermost first, terminal member excluded.
///
/// A component whose written arguments select a specialization
/// ([`CppTemplateLevel::selects_specialization`]) names that specialization by
/// its written template-id, `Box<T*>` or `Box<int>`, which is how the class
/// body publishes the specialization's own members. Every other component,
/// the primary template's `Box<T>` included, names its bare class or
/// namespace. `None` when the template levels cannot be read.
pub fn cpp_out_of_line_owner_names(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let context = cpp_declaration_template_context(node, source)?;
    let mut components =
        cpp_name_component_nodes(declaration_qualifier(declaration_statement(node)?)?)?;
    components.pop()?;
    // One level per qualifier component plus the member's own.
    debug_assert_eq!(context.levels.len(), components.len() + 1);
    let names = components
        .into_iter()
        .zip(&context.levels)
        .map(|(component, level)| {
            debug_assert_eq!(level.name, node_text(component, source));
            match component.parent() {
                Some(template)
                    if level.selects_specialization()
                        && template.kind() == "template_type"
                        && template.child_by_field_name("name") == Some(component) =>
                {
                    normalize_cpp_whitespace(node_text(template, source))
                }
                _ => node_text(component, source).to_owned(),
            }
        })
        .collect();
    Some(names)
}

struct ContextBuilder<'a, 'tree> {
    source: &'a str,
    ancestry: ParentIndex<'tree>,
    /// Every parameter name in scope at the level being built.
    names: Vec<String>,
    levels: Vec<CppTemplateLevel>,
}

impl<'tree> ContextBuilder<'_, 'tree> {
    fn finish(self) -> CppTemplateContext {
        CppTemplateContext {
            levels: self.levels,
        }
    }

    fn push_class(&mut self, class: Node<'tree>, head: Option<Node<'tree>>) -> Option<()> {
        let head = match head {
            Some(head) => self.head(head)?,
            None => None,
        };
        let (name, arguments) = match class.child_by_field_name("name") {
            None => (String::new(), None),
            Some(name) if name.kind() == "template_type" => (
                node_text(name.child_by_field_name("name")?, self.source).to_owned(),
                Some(self.arguments(name.child_by_field_name("arguments")?)),
            ),
            Some(name) if name.kind() == "type_identifier" => {
                (node_text(name, self.source).to_owned(), None)
            }
            // A qualified class name is an out-of-line nested class
            // definition, whose heads this module does not assign.
            Some(_) => return None,
        };
        self.levels.push(CppTemplateLevel {
            name,
            head,
            arguments,
        });
        Some(())
    }

    /// Assign an out-of-line definition's heads to its qualifier.
    ///
    /// Each qualifier component with template arguments consumes the next
    /// head when that head is `template <>` (an explicit specialization) or
    /// when the component's arguments name one of its parameters; otherwise
    /// the component is a member of an explicit specialization, which takes
    /// no head of its own. One head left over is the member's own; more than
    /// one cannot be assigned.
    fn push_out_of_line(&mut self, qualifier: Node<'tree>, heads: &[Node<'tree>]) -> Option<()> {
        let mut components = cpp_name_component_nodes(qualifier)?;
        components.pop()?;
        let mut heads = heads.iter().copied().peekable();
        for component in components {
            let arguments = component
                .parent()
                .filter(|parent| {
                    matches!(parent.kind(), "template_type" | "template_function")
                        && parent.child_by_field_name("name") == Some(component)
                })
                .map(|template| template.child_by_field_name("arguments"));
            let name = node_text(component, self.source).to_owned();
            let Some(arguments) = arguments else {
                self.levels.push(CppTemplateLevel {
                    name,
                    head: None,
                    arguments: None,
                });
                continue;
            };
            let arguments = arguments?;
            let scope = self.names.len();
            let head = match heads.peek().copied() {
                Some(head) => {
                    let parsed = self.head(head)?;
                    let consumed = match &parsed {
                        None => true,
                        Some(parsed) => {
                            let introduced = parsed
                                .parameters
                                .iter()
                                .map(|parameter| parameter.name.as_str())
                                .collect::<HashSet<_>>();
                            self.arguments(arguments)
                                .iter()
                                .any(|term| term_names_any(term, &introduced))
                        }
                    };
                    if consumed {
                        heads.next();
                        parsed
                    } else {
                        self.names.truncate(scope);
                        None
                    }
                }
                None => None,
            };
            let arguments = Some(self.arguments(arguments));
            self.levels.push(CppTemplateLevel {
                name,
                head,
                arguments,
            });
        }
        let own = match heads.next() {
            Some(head) => self.head(head)?,
            None => None,
        };
        if heads.next().is_some() {
            return None;
        }
        self.levels.push(CppTemplateLevel {
            name: String::new(),
            head: own,
            arguments: None,
        });
        Some(())
    }

    /// Parse one head and bring its parameters into scope. `Some(None)` is
    /// `template <>`.
    fn head(&mut self, template: Node<'tree>) -> Option<Option<CppTemplateHead>> {
        let list = template.child_by_field_name("parameters")?;
        let mut parameters = Vec::new();
        let mut cursor = list.walk();
        for (index, parameter) in list
            .named_children(&mut cursor)
            .filter(|child| !child.is_extra())
            .enumerate()
        {
            if !matches!(
                parameter.kind(),
                "type_parameter_declaration"
                    | "optional_type_parameter_declaration"
                    | "variadic_type_parameter_declaration"
                    | "template_template_parameter_declaration"
                    | "parameter_declaration"
                    | "optional_parameter_declaration"
                    | "variadic_parameter_declaration"
            ) {
                return None;
            }
            let name = cpp_template_parameter_name(parameter, self.source)
                .unwrap_or_else(|| format!("<anonymous:{}:{index}>", self.names.len()));
            self.names.push(name.clone());
            let variadic = matches!(
                parameter.kind(),
                "variadic_type_parameter_declaration" | "variadic_parameter_declaration"
            );
            let shape = match cpp_template_parameter_kind(parameter) {
                CppTemplateParameterKind::Type => CppTemplateParameterShape::Type,
                CppTemplateParameterKind::Template => {
                    let nested = parameter.child_by_field_name("parameters")?;
                    let mut cursor = nested.walk();
                    CppTemplateParameterShape::Template(
                        nested
                            .named_children(&mut cursor)
                            .filter(|child| !child.is_extra())
                            .map(|child| {
                                (
                                    cpp_template_parameter_kind(child),
                                    matches!(
                                        child.kind(),
                                        "variadic_type_parameter_declaration"
                                            | "variadic_parameter_declaration"
                                    ),
                                )
                            })
                            .collect(),
                    )
                }
                CppTemplateParameterKind::Value => CppTemplateParameterShape::Value {
                    type_term: self.term(parameter.child_by_field_name("type")?),
                    declarator: parameter
                        .child_by_field_name("declarator")
                        .filter(|declarator| {
                            !matches!(declarator.kind(), "identifier" | "variadic_declarator")
                        })
                        .map(|declarator| self.term(declarator)),
                },
            };
            parameters.push(CppTemplateParameter {
                name,
                variadic,
                shape,
            });
        }
        let mut cursor = template.walk();
        let requires = template
            .named_children(&mut cursor)
            .find(|child| child.kind() == "requires_clause")
            .map(|clause| self.term(clause));
        Some((!parameters.is_empty()).then_some(CppTemplateHead {
            parameters,
            requires,
        }))
    }

    fn arguments(&self, list: Node<'tree>) -> Vec<CppTemplateTerm> {
        let mut cursor = list.walk();
        list.named_children(&mut cursor)
            .filter(|argument| !argument.is_extra() && argument.kind() != "comment")
            .map(|argument| self.term(argument))
            .collect()
    }

    fn term(&self, node: Node<'tree>) -> CppTemplateTerm {
        cpp_template_term(node, self.source, &self.names, &self.ancestry)
    }
}

fn term_names_any(term: &CppTemplateTerm, names: &HashSet<&str>) -> bool {
    let mut work = vec![term];
    while let Some(term) = work.pop() {
        match term {
            CppTemplateTerm::Parameter(name) if names.contains(name.as_str()) => return true,
            CppTemplateTerm::Node { children, .. } => work.extend(children),
            CppTemplateTerm::Parameter(_) | CppTemplateTerm::Atom { .. } => {}
        }
    }
    false
}

fn is_class_specifier(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    )
}

/// The statement a declaration's template heads wrap: the declaration node
/// itself, or for a function declarator the declaration that owns it.
fn declaration_statement(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        match current.kind() {
            "function_definition" | "declaration" | "field_declaration" => return Some(current),
            _ if is_class_specifier(current) => return Some(current),
            "function_declarator"
            | "pointer_declarator"
            | "reference_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator"
            | "init_declarator" => current = current.parent()?,
            _ => return None,
        }
    }
}

/// The statement whose template wrapper belongs to a class specifier: the
/// specifier, or the declaration it is the type of.
fn class_statement(class: Node<'_>) -> Node<'_> {
    class
        .parent()
        .filter(|parent| {
            matches!(parent.kind(), "declaration" | "field_declaration")
                && parent.child_by_field_name("type") == Some(class)
        })
        .unwrap_or(class)
}

/// The `template <...>` heads that directly wrap `statement`, outermost
/// first, and the outermost node of that wrapper chain.
fn direct_template_heads(statement: Node<'_>) -> (Vec<Node<'_>>, Node<'_>) {
    let statement = if is_class_specifier(statement) {
        class_statement(statement)
    } else {
        statement
    };
    let mut heads = Vec::new();
    let mut current = statement;
    while let Some(parent) = current.parent() {
        if parent.kind() != "template_declaration"
            || parent.child_by_field_name("parameters") == Some(current)
        {
            break;
        }
        heads.push(parent);
        current = parent;
    }
    heads.reverse();
    (heads, current)
}

/// The qualified name an out-of-line callable declares, when it has one.
fn declaration_qualifier(statement: Node<'_>) -> Option<Node<'_>> {
    if is_class_specifier(statement) {
        return None;
    }
    let mut current = statement.child_by_field_name("declarator")?;
    loop {
        match current.kind() {
            "qualified_identifier" => return Some(current),
            "identifier" | "field_identifier" | "operator_name" | "destructor_name"
            | "template_function" => return None,
            _ => {
                current = current
                    .child_by_field_name("declarator")
                    .or_else(|| current.named_child(0))?;
            }
        }
    }
}

/// The last name component a callable declarator declares, through any
/// qualifier: `f`, or the `template_function` `f<int>`.
fn declaration_terminal(statement: Node<'_>) -> Option<Node<'_>> {
    if is_class_specifier(statement) {
        return None;
    }
    let mut current = statement.child_by_field_name("declarator")?;
    loop {
        match current.kind() {
            "qualified_identifier" => current = current.child_by_field_name("name")?,
            "identifier" | "field_identifier" | "operator_name" | "destructor_name"
            | "template_function" => return Some(current),
            _ => {
                current = current
                    .child_by_field_name("declarator")
                    .or_else(|| current.named_child(0))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECLARATIONS: &str = r#"namespace n {
template<class T> struct Box {
    void put(T);
    template<class U> void take(U);
};
template<class T> struct Box<T*> {
    void put(T*);
};
template<> struct Box<int> {
    void exact();
};
template<class T, class U> struct Pair {
    void pair();
};
template<int N> struct Fixed {
    void reset();
};
template<class... Ts> struct Pack {
    void pack();
};
template<class T> requires Ready<T> struct Gate {
    void open();
};
void make();
}
"#;

    const DEFINITIONS: &str = r#"namespace n {
template<typename U> void Box<U>::put(U) {}
template<class T> template<class W> void Box<T>::take(W) {}
template<class T> void Box<T*>::put(T*) {}
void Box<int>::exact() {}
template<class T> void Pair<T>::pair() {}
template<long N> void Fixed<N>::reset() {}
template<int M> void Fixed<M>::reset() {}
template<class... Us> void Pack<Us...>::pack() {}
template<class T> void Pack<T>::pack() {}
template<class U> requires Ready<U> void Gate<U>::open() {}
template<class U> void Gate<U>::open() {}
template<> void make<int>() {}
using Exact = Box<int>;
void Exact::exact() {}
}
"#;

    fn context_of(source: &str, needle: &str) -> CppTemplateContext {
        let tree = crate::diagnostics::parse_cpp_tree(source);
        assert!(!tree.root_node().has_error(), "fixture must parse cleanly");
        let start = source.find(needle).expect("needle");
        let mut node = tree
            .root_node()
            .descendant_for_byte_range(start, start + needle.len())
            .expect("needle node");
        while !matches!(
            node.kind(),
            "function_definition" | "field_declaration" | "declaration" | "template_declaration"
        ) {
            node = node.parent().expect("declaration ancestor");
        }
        while node.kind() == "template_declaration" {
            node = node
                .named_child(node.named_child_count() - 1)
                .expect("templated declaration");
        }
        cpp_declaration_template_context(node, source)
            .unwrap_or_else(|| panic!("no template context for {needle}"))
    }

    /// Each in-class declaration against the out-of-line definitions that only
    /// look like it: renamed heads and members of a partial or explicit
    /// specialization agree, while a different arity, parameter kind or
    /// non-type parameter type, a pack against a single parameter, a missing
    /// requires-clause, the primary against a specialization, and a function
    /// template specialization against an ordinary function do not. A
    /// qualifier spelled through an alias cannot be aligned at all.
    #[test]
    fn reconcile_matches_heads_and_owner_arguments_structurally() {
        use CppTemplateReconciliation::{Distinct, Unsupported};
        let cases = [
            ("put(T);", "Box<U>::put(U)", Some(true)),
            ("take(U)", "Box<T>::take(W)", Some(true)),
            ("put(T*)", "Box<T*>::put(T*)", Some(true)),
            ("put(T);", "Box<T*>::put(T*)", Some(false)),
            ("exact();", "Box<int>::exact()", Some(true)),
            ("put(T);", "Box<int>::exact()", Some(false)),
            ("pair();", "Pair<T>::pair()", Some(false)),
            ("reset();", "Fixed<N>::reset()", Some(false)),
            ("reset();", "Fixed<M>::reset()", Some(true)),
            ("pack();", "Pack<Us...>::pack()", Some(true)),
            ("pack();", "Pack<T>::pack()", Some(false)),
            ("open();", "Ready<U> void Gate<U>::open()", Some(true)),
            ("open();", "<class U> void Gate<U>::open()", Some(false)),
            ("make();", "make<int>()", Some(false)),
            ("exact();", "Exact::exact()", None),
        ];
        let mut mismatches = Vec::new();
        for (declaration, definition, expected) in cases {
            let left = context_of(DECLARATIONS, declaration);
            let right = context_of(DEFINITIONS, definition);
            let forward = left.reconcile(&right);
            let inverse = right.reconcile(&left);
            let verdict = |reconciliation: &CppTemplateReconciliation| match reconciliation {
                CppTemplateReconciliation::Equivalent(_) => Some(true),
                Distinct => Some(false),
                Unsupported => None,
            };
            if verdict(&forward) != expected || verdict(&inverse) != expected {
                mismatches.push((declaration, definition, forward, inverse));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }
}
