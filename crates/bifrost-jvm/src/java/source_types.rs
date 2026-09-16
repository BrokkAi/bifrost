//! Source-owned Java type syntax and declaration properties.
//!
//! The primary declaration walk calls this collector while the tree-sitter
//! tree is live. The resulting rows keep only source handles and bounded
//! structured type shapes; no parser node or query-specific resolution is
//! retained.

use brokk_bifrost_core::analyzer::java_facts::{
    JavaAnonymousReturnEntry, JavaAnonymousReturnFact, JavaAnonymousReturnStatus,
    JavaCallableReturnFact, JavaLocalTypeFact, JavaSourceFacts, JavaSourceTypeId,
    JavaTypeParameterFact, JavaTypeSyntaxFact, JavaTypeSyntaxShape,
};
use brokk_bifrost_core::analyzer::model::StructuredTypeName;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId, SourceOccurrenceSink,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use super::graph::return_type::java_type_name_components;
use super::graph_support::{
    java_declared_type_parameters, java_type_parameter_bounds, java_type_parameter_in_scope,
    java_type_parameter_name, java_type_parameter_name_node,
};

#[derive(Default)]
pub(crate) struct JavaSourceTypeCollector {
    facts: JavaSourceFacts,
    by_occurrence: HashMap<SourceOccurrenceId, JavaSourceTypeId>,
    inferred_occurrences: HashSet<SourceOccurrenceId>,
    parameter_declarations: HashMap<usize, SourceDeclarationId>,
    parameter_rows: HashSet<(SourceDeclarationId, u32)>,
    callable_rows: HashSet<SourceDeclarationId>,
    local_rows: HashSet<SourceDeclarationId>,
    anonymous_rows: HashSet<SourceDeclarationId>,
    declaration_owners: HashSet<(SourceDeclarationId, SourceDeclarationId)>,
}

impl JavaSourceTypeCollector {
    pub(crate) fn record_type(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn SourceOccurrenceSink,
    ) -> JavaSourceTypeId {
        let occurrence = sink.intern_node(node);
        if let Some(id) = self.by_occurrence.get(&occurrence).copied() {
            return id;
        }
        let mut frames = vec![JavaTypeFrame::Visit(node)];
        let mut scheduled = HashSet::default();
        while let Some(frame) = frames.pop() {
            match frame {
                JavaTypeFrame::Visit(current) => {
                    let occurrence = sink.intern_node(current);
                    if self.by_occurrence.contains_key(&occurrence) || !scheduled.insert(occurrence)
                    {
                        continue;
                    }
                    match java_type_children(current) {
                        JavaTypeChildren::Generic { base, arguments } => {
                            let visits = arguments
                                .iter()
                                .rev()
                                .copied()
                                .map(JavaTypeFrame::Visit)
                                .collect::<Vec<_>>();
                            frames.push(JavaTypeFrame::FinishGeneric { current, arguments });
                            frames.extend(visits);
                            frames.push(JavaTypeFrame::Visit(base));
                        }
                        JavaTypeChildren::Array {
                            element,
                            dimensions,
                        } => {
                            frames.push(JavaTypeFrame::FinishWrapper {
                                current,
                                kind: JavaTypeWrapperKind::Array { dimensions },
                            });
                            frames.push(JavaTypeFrame::Visit(element));
                        }
                        JavaTypeChildren::Annotated { element } => {
                            frames.push(JavaTypeFrame::FinishWrapper {
                                current,
                                kind: JavaTypeWrapperKind::Annotated,
                            });
                            frames.push(JavaTypeFrame::Visit(element));
                        }
                        JavaTypeChildren::Leaf => {
                            self.finish_java_type_leaf(current, source, sink);
                        }
                    }
                }
                JavaTypeFrame::FinishGeneric { current, arguments } => {
                    let occurrence = sink.intern_node(current);
                    let Some(base_node) = current
                        .child_by_field_name("type")
                        .or_else(|| java_named_type_child(current))
                    else {
                        self.push_unknown_java_type(occurrence);
                        continue;
                    };
                    let base_occurrence = sink.intern_node(base_node);
                    let Some(base) = self.by_occurrence.get(&base_occurrence).copied() else {
                        self.push_unknown_java_type(occurrence);
                        continue;
                    };
                    let mut argument_ids = Vec::with_capacity(arguments.len());
                    let mut all_arguments_captured = true;
                    for argument in &arguments {
                        let argument_occurrence = sink.intern_node(*argument);
                        let Some(argument_id) =
                            self.by_occurrence.get(&argument_occurrence).copied()
                        else {
                            all_arguments_captured = false;
                            break;
                        };
                        argument_ids.push(argument_id);
                    }
                    if !all_arguments_captured {
                        self.push_unknown_java_type(occurrence);
                        continue;
                    }
                    self.push_java_type(
                        occurrence,
                        JavaTypeSyntaxShape::Generic {
                            base,
                            arguments: argument_ids,
                        },
                    );
                }
                JavaTypeFrame::FinishWrapper { current, kind } => {
                    let occurrence = sink.intern_node(current);
                    let Some(element_node) = current.child_by_field_name("element").or_else(|| {
                        let mut cursor = current.walk();
                        current
                            .named_children(&mut cursor)
                            .find(|child| child.kind() != "annotation")
                    }) else {
                        self.push_unknown_java_type(occurrence);
                        continue;
                    };
                    let element_occurrence = sink.intern_node(element_node);
                    let Some(element) = self.by_occurrence.get(&element_occurrence).copied() else {
                        self.push_unknown_java_type(occurrence);
                        continue;
                    };
                    self.push_java_type(
                        occurrence,
                        match kind {
                            JavaTypeWrapperKind::Array { dimensions } => {
                                JavaTypeSyntaxShape::Array {
                                    element,
                                    dimensions,
                                }
                            }
                            JavaTypeWrapperKind::Annotated => {
                                JavaTypeSyntaxShape::Annotated(element)
                            }
                        },
                    );
                }
            }
        }
        self.by_occurrence
            .get(&occurrence)
            .copied()
            .expect("the requested Java source type was captured")
    }

    /// Declare all parameters before interpreting any of their bounds. This
    /// makes a self-bound (`T extends Field<T>`) and nested shadowing use the
    /// same source declaration IDs as later callable returns.
    pub(crate) fn record_type_parameters(
        &mut self,
        owner_node: Node<'_>,
        owner: SourceDeclarationId,
        source: &str,
        sink: &mut PrimarySourceFactCollector<'_>,
    ) {
        let parameters = java_declared_type_parameters(owner_node);
        for parameter in &parameters {
            let Some(name_node) = java_type_parameter_name_node(*parameter) else {
                continue;
            };
            let occurrence = sink.intern_node(*parameter);
            let name_occurrence = sink.intern_node(name_node);
            let declaration = sink.declare(occurrence, Some(name_occurrence));
            if let Some(previous) = self
                .parameter_declarations
                .insert(parameter.id(), declaration)
            {
                assert_eq!(previous, declaration);
            }
        }

        for (ordinal, parameter) in parameters.into_iter().enumerate() {
            let Some(name_node) = java_type_parameter_name_node(parameter) else {
                continue;
            };
            let Some(declaration) = self.parameter_declarations.get(&parameter.id()).copied()
            else {
                continue;
            };
            let name = java_type_parameter_name(parameter, source)
                .expect("a Java type-parameter name node has source text")
                .trim();
            if name.is_empty() {
                continue;
            }
            let ordinal = u32::try_from(ordinal).expect("Java type-parameter ordinal fits u32");
            if !self.parameter_rows.insert((owner, ordinal)) {
                continue;
            }
            let bounds = java_type_parameter_bounds(parameter)
                .into_iter()
                .map(|bound| self.record_type(bound, source, sink))
                .collect();
            self.facts.type_parameters.push(JavaTypeParameterFact {
                owner,
                ordinal,
                declaration,
                name: name.to_string(),
                bounds,
            });
            assert_eq!(
                name_node,
                java_type_parameter_name_node(parameter)
                    .expect("the captured type-parameter name remains present")
            );
        }
    }

    pub(crate) fn record_callable(
        &mut self,
        node: Node<'_>,
        callable: SourceDeclarationId,
        source: &str,
        sink: &mut PrimarySourceFactCollector<'_>,
    ) {
        self.record_type_parameters(node, callable, source, sink);
        let return_type = node
            .child_by_field_name("type")
            .map(|type_node| self.record_type(type_node, source, sink));
        if self.callable_rows.insert(callable) {
            self.facts.callable_returns.push(JavaCallableReturnFact {
                callable,
                ty: return_type,
            });
        }
        self.record_anonymous_returns(node, callable, source, sink);
    }

    pub(crate) fn record_local_type(
        &mut self,
        declaration_node: Node<'_>,
        declaration: SourceDeclarationId,
        sink: &mut dyn SourceOccurrenceSink,
    ) {
        if !self.local_rows.insert(declaration) {
            return;
        }
        let mut current = declaration_node.parent();
        while let Some(node) = current {
            if is_java_class_like_kind(node.kind()) || is_java_synthetic_class_body(node) {
                self.local_rows.remove(&declaration);
                return;
            }
            if is_java_local_type_scope_node(node.kind()) {
                self.facts.local_types.push(JavaLocalTypeFact {
                    declaration,
                    lexical_scope: sink.intern_node(node),
                });
                return;
            }
            current = node.parent();
        }
        // A caller only asks for local classes. If the grammar gives one no
        // lexical scope, retain no fabricated scope fact.
        self.local_rows.remove(&declaration);
    }

    pub(crate) fn record_declaration_owner(
        &mut self,
        declaration: SourceDeclarationId,
        owner: SourceDeclarationId,
    ) {
        if self.declaration_owners.insert((declaration, owner)) {
            self.facts.declaration_owners.push((declaration, owner));
        }
    }

    pub(crate) fn shape(&self, id: JavaSourceTypeId) -> Option<&JavaTypeSyntaxShape> {
        self.facts.types.get(id.index()).map(|fact| &fact.shape)
    }

    pub(crate) fn is_inferred_type(&self, id: JavaSourceTypeId) -> bool {
        self.facts
            .types
            .get(id.index())
            .is_some_and(|fact| self.inferred_occurrences.contains(&fact.occurrence))
    }

    pub(crate) fn finish(self) -> JavaSourceFacts {
        self.facts
    }
}

enum JavaTypeFrame<'tree> {
    Visit(Node<'tree>),
    FinishGeneric {
        current: Node<'tree>,
        arguments: Vec<Node<'tree>>,
    },
    FinishWrapper {
        current: Node<'tree>,
        kind: JavaTypeWrapperKind,
    },
}

#[derive(Clone, Copy)]
enum JavaTypeWrapperKind {
    Array { dimensions: u32 },
    Annotated,
}

enum JavaTypeChildren<'tree> {
    Generic {
        base: Node<'tree>,
        arguments: Vec<Node<'tree>>,
    },
    Array {
        element: Node<'tree>,
        dimensions: u32,
    },
    Annotated {
        element: Node<'tree>,
    },
    Leaf,
}

fn java_named_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "type_arguments" | "annotation"))
}

fn java_type_children(node: Node<'_>) -> JavaTypeChildren<'_> {
    match node.kind() {
        "generic_type" => {
            let base = node
                .child_by_field_name("type")
                .or_else(|| java_named_type_child(node));
            let arguments = node.child_by_field_name("type_arguments").or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "type_arguments")
            });
            let Some((base, arguments)) = base.zip(arguments) else {
                return JavaTypeChildren::Leaf;
            };
            let mut cursor = arguments.walk();
            let arguments = arguments.named_children(&mut cursor).collect::<Vec<_>>();
            if arguments.is_empty() {
                JavaTypeChildren::Leaf
            } else {
                JavaTypeChildren::Generic { base, arguments }
            }
        }
        "array_type" => {
            let Some(element) = node.child_by_field_name("element") else {
                return JavaTypeChildren::Leaf;
            };
            let Some(dimensions) = node.child_by_field_name("dimensions") else {
                return JavaTypeChildren::Leaf;
            };
            let mut cursor = dimensions.walk();
            let count = dimensions
                .children(&mut cursor)
                .filter(|child| child.kind() == "[")
                .count();
            let dimensions = u32::try_from(count).expect("Java array dimensions fit u32");
            assert!(dimensions > 0, "Java array type has at least one dimension");
            JavaTypeChildren::Array {
                element,
                dimensions,
            }
        }
        "annotated_type" => {
            let mut cursor = node.walk();
            let mut types = node
                .named_children(&mut cursor)
                .filter(|child| child.kind() != "annotation");
            match (types.next(), types.next()) {
                (Some(element), None) => JavaTypeChildren::Annotated { element },
                _ => JavaTypeChildren::Leaf,
            }
        }
        _ => JavaTypeChildren::Leaf,
    }
}

impl JavaSourceTypeCollector {
    fn finish_java_type_leaf(
        &mut self,
        node: Node<'_>,
        source: &str,
        sink: &mut dyn SourceOccurrenceSink,
    ) {
        let occurrence = sink.intern_node(node);
        let shape = match node.kind() {
            "integral_type" | "floating_point_type" | "boolean_type" | "void_type" => {
                JavaTypeSyntaxShape::NonNominal
            }
            "type_identifier" | "identifier" | "scoped_type_identifier" | "scoped_identifier" => {
                if node
                    .utf8_text(source.as_bytes())
                    .is_ok_and(|text| text.trim() == "var")
                {
                    assert!(self.inferred_occurrences.insert(occurrence));
                    JavaTypeSyntaxShape::Unknown
                } else {
                    let Some(path) = java_type_name_components(node, source) else {
                        self.push_unknown_java_type(occurrence);
                        return;
                    };
                    let Some(scope) = java_lexical_scope(node, source) else {
                        self.push_unknown_java_type(occurrence);
                        return;
                    };
                    let single_name = (path.len() == 1).then(|| path[0].clone());
                    let Some(name) = StructuredTypeName::new(path, scope, false) else {
                        self.push_unknown_java_type(occurrence);
                        return;
                    };
                    // A qualified name's terminal component is a type name, never
                    // a local type-parameter use. Only a single leaf can bind.
                    let parameter = single_name.as_deref().and_then(|name| {
                        java_type_parameter_in_scope(node, source, name).and_then(|parameter| {
                            self.parameter_declarations.get(&parameter.id()).copied()
                        })
                    });
                    JavaTypeSyntaxShape::Named { name, parameter }
                }
            }
            // `var`, wildcard, and all richer Java type forms are not a
            // nominal receiver identity for this bounded source family.
            _ => JavaTypeSyntaxShape::Unknown,
        };
        self.push_java_type(occurrence, shape);
    }

    fn push_unknown_java_type(&mut self, occurrence: SourceOccurrenceId) -> JavaSourceTypeId {
        self.push_java_type(occurrence, JavaTypeSyntaxShape::Unknown)
    }

    fn push_java_type(
        &mut self,
        occurrence: SourceOccurrenceId,
        shape: JavaTypeSyntaxShape,
    ) -> JavaSourceTypeId {
        if let Some(id) = self.by_occurrence.get(&occurrence).copied() {
            return id;
        }
        let id = JavaSourceTypeId::try_from_index(self.facts.types.len())
            .expect("Java source type ids must fit in a u32");
        self.facts
            .types
            .push(JavaTypeSyntaxFact { occurrence, shape });
        assert!(self.by_occurrence.insert(occurrence, id).is_none());
        id
    }

    /// Check only the requested source type and its reachable children. Type
    /// IDs are child-before-parent, but unrelated earlier rows must not affect
    /// this completeness result.
    fn complete_nominal_type(&self, root: JavaSourceTypeId) -> bool {
        let mut visited = HashSet::default();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let Some(fact) = self.facts.types.get(id.index()) else {
                return false;
            };
            match &fact.shape {
                JavaTypeSyntaxShape::Named { .. } => {}
                JavaTypeSyntaxShape::Generic { base, arguments } => {
                    pending.push(*base);
                    pending.extend(arguments.iter().copied());
                }
                JavaTypeSyntaxShape::Array { element, .. }
                | JavaTypeSyntaxShape::Annotated(element) => pending.push(*element),
                JavaTypeSyntaxShape::NonNominal | JavaTypeSyntaxShape::Unknown => {
                    return false;
                }
            }
        }
        true
    }
}

fn java_lexical_scope(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut scope = Vec::new();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if is_java_class_like_kind(ancestor.kind()) {
            let name = ancestor.child_by_field_name("name")?;
            let text = name.utf8_text(source.as_bytes()).ok()?.trim();
            if text.is_empty() {
                return None;
            }
            scope.push(text.to_string());
        }
        current = ancestor.parent();
    }
    scope.reverse();
    Some(scope)
}

fn is_java_class_like_kind(kind: &str) -> bool {
    matches!(
        kind,
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    )
}

pub(crate) fn is_java_synthetic_class_body(node: Node<'_>) -> bool {
    node.kind() == "class_body"
        && node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "object_creation_expression" | "enum_constant"
            )
        })
}

fn is_java_local_type_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "block"
            | "lambda_expression"
            | "catch_clause"
            | "enhanced_for_statement"
            | "for_statement"
            | "try_with_resources_statement"
    )
}

impl JavaSourceTypeCollector {
    fn record_anonymous_returns(
        &mut self,
        method: Node<'_>,
        callable: SourceDeclarationId,
        source: &str,
        sink: &mut dyn SourceOccurrenceSink,
    ) {
        if !self.anonymous_rows.insert(callable) {
            return;
        }
        let Some(body) = method.child_by_field_name("body") else {
            self.facts.anonymous_returns.push(JavaAnonymousReturnFact {
                callable,
                status: JavaAnonymousReturnStatus::Unknown,
                returns: Vec::new(),
            });
            return;
        };
        let mut stack = vec![body];
        let mut returns = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "return_statement" {
                let Some(value) = node
                    .child_by_field_name("value")
                    .or_else(|| node.named_child(0))
                else {
                    returns.clear();
                    break;
                };
                if value.kind() != "object_creation_expression"
                    || !java_has_anonymous_class_body(value)
                {
                    returns.clear();
                    break;
                }
                let Some(type_node) = value.child_by_field_name("type") else {
                    returns.clear();
                    break;
                };
                let declared_type = self.record_type(type_node, source, sink);
                if !self.complete_nominal_type(declared_type) {
                    returns.clear();
                    break;
                }
                returns.push(JavaAnonymousReturnEntry {
                    return_occurrence: sink.intern_node(node),
                    object_creation_occurrence: sink.intern_node(value),
                    declared_type,
                });
                continue;
            }
            if matches!(
                node.kind(),
                "class_declaration" | "interface_declaration" | "lambda_expression"
            ) {
                continue;
            }
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        }
        let status = if returns.is_empty() {
            JavaAnonymousReturnStatus::Unknown
        } else {
            JavaAnonymousReturnStatus::AllAnonymous
        };
        self.facts.anonymous_returns.push(JavaAnonymousReturnFact {
            callable,
            status,
            returns,
        });
    }
}

fn java_has_anonymous_class_body(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "class_body")
}

#[cfg(test)]
mod producer_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::java_facts::JavaAnonymousReturnStatus;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::source_facts::SourceFactRows;
    use tree_sitter::Parser;

    fn parse(source: &str) -> ParsedFile {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("java grammar");
        let tree = parser.parse(source, None).expect("java tree");
        let file = ProjectFile::new(std::env::temp_dir().join("java-source-types"), "C.java");
        super::super::declarations::parse_java_file(&file, source, &tree)
    }

    fn occurrence_text<'a>(
        source: &'a str,
        rows: &SourceFactRows,
        occurrence: SourceOccurrenceId,
    ) -> &'a str {
        let range = rows.occurrence(occurrence).range;
        &source[range.start_byte..range.end_byte]
    }

    #[test]
    fn qualified_generic_owner_retains_nominal_path_and_native_terminal() {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionGapKind, ResolutionSiteKind,
        };

        let source = "class Box<T> { class Inner {} } class Factory { Box<String>.Inner make() { return null; } }";
        let parsed = parse(source);
        let source_facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        let facts = source_facts.java.as_ref().expect("Java source facts");
        let return_type = facts.callable_returns.first().expect("method return");
        let JavaTypeSyntaxShape::Named { name, .. } =
            &facts.types[return_type.ty.expect("explicit return type").index()].shape
        else {
            panic!("qualified generic owner must retain its nominal path");
        };
        assert_eq!(name.path(), &["Box", "Inner"]);

        let native = &parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts();
        let terminal = native
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::MemberReference
                    && &source[site.start_byte..site.end_byte] == "Inner"
            })
            .expect("native terminal reference survives unsupported generic owner");
        assert!(native.gaps.iter().any(|gap| {
            gap.site == terminal.id && gap.kind == ResolutionGapKind::AmbiguousQualifiedType
        }));
        assert!(
            native
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedTypeSyntax)
        );
    }

    #[test]
    fn producer_retains_incomplete_generic_base_and_array_dimensions() {
        let source = "class C { List<?> wildcard(); List<int> primitive(); String[][] matrix(); }";
        let parsed = parse(source);
        let source_facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        let facts = source_facts.java.as_ref().expect("Java source facts");

        let list_ids = facts
            .types
            .iter()
            .enumerate()
            .filter_map(|(index, fact)| match &fact.shape {
                JavaTypeSyntaxShape::Named { name, .. }
                    if name.path().len() == 1 && name.path()[0] == "List" =>
                {
                    Some(JavaSourceTypeId::new(index as u32))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!list_ids.is_empty(), "List base was captured");
        let wildcard_generic = facts.types.iter().find(|fact| {
            occurrence_text(source, &source_facts.occurrences, fact.occurrence).contains("List<?>")
        });
        let Some(wildcard_generic) = wildcard_generic else {
            panic!("wildcard generic syntax is retained")
        };
        let JavaTypeSyntaxShape::Generic { base, arguments } = &wildcard_generic.shape else {
            panic!(
                "wildcard type has generic shape: {:?}",
                wildcard_generic.shape
            )
        };
        assert!(list_ids.contains(base));
        assert_eq!(arguments.len(), 1);
        assert!(matches!(
            &facts.types[arguments[0].index()].shape,
            JavaTypeSyntaxShape::Unknown
        ));

        let primitive_generic = facts.types.iter().find(|fact| {
            matches!(
                &fact.shape,
                JavaTypeSyntaxShape::Generic { base, .. } if list_ids.contains(base)
            ) && occurrence_text(source, &source_facts.occurrences, fact.occurrence)
                .contains("List<int>")
        });
        let primitive_generic = primitive_generic.expect("primitive generic syntax is retained");
        let JavaTypeSyntaxShape::Generic { arguments, .. } = &primitive_generic.shape else {
            panic!(
                "primitive type has generic shape: {:?}",
                primitive_generic.shape
            )
        };
        assert!(matches!(
            &facts.types[arguments[0].index()].shape,
            JavaTypeSyntaxShape::NonNominal
        ));

        let array = facts.types.iter().find_map(|fact| match &fact.shape {
            JavaTypeSyntaxShape::Array { dimensions, .. }
                if occurrence_text(source, &source_facts.occurrences, fact.occurrence)
                    .contains("String[][]") =>
            {
                Some(*dimensions)
            }
            _ => None,
        });
        assert_eq!(array, Some(2));
        assert!(facts.valid_links(&source_facts.occurrences));
    }

    #[test]
    fn producer_binds_only_unqualified_type_parameter_and_records_local_scope() {
        let source = "class C<T> { pkg.T qualified(); T plain(); void body() { class Local {} Local value; } }";
        let parsed = parse(source);
        let source_facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        let facts = source_facts.java.as_ref().expect("Java source facts");

        let mut qualified_seen = false;
        let mut qualified_parameter = false;
        let mut plain_parameter = false;
        for callable in &facts.callable_returns {
            let Some(ty) = callable.ty else { continue };
            let text = occurrence_text(
                source,
                &source_facts.occurrences,
                facts.types[ty.index()].occurrence,
            );
            match &facts.types[ty.index()].shape {
                JavaTypeSyntaxShape::Named { name, parameter } if text == "pkg.T" => {
                    assert_eq!(name.path().len(), 2);
                    assert_eq!(name.path()[0], "pkg");
                    assert_eq!(name.path()[1], "T");
                    qualified_seen = true;
                    qualified_parameter = parameter.is_some();
                }
                JavaTypeSyntaxShape::Named { name, parameter } if text == "T" => {
                    assert_eq!(name.path().len(), 1);
                    assert_eq!(name.path()[0], "T");
                    plain_parameter = parameter.is_some();
                }
                _ => {}
            }
        }
        assert!(qualified_seen, "qualified return type was captured");
        assert!(!qualified_parameter, "qualified terminal must not bind T");
        assert!(
            plain_parameter,
            "unqualified T must bind the class parameter"
        );

        let local = facts.local_types.first().expect("local class fact");
        let declaration = source_facts.occurrences.occurrence(
            source_facts
                .occurrences
                .declaration(local.declaration)
                .occurrence,
        );
        let scope = source_facts.occurrences.occurrence(local.lexical_scope);
        assert!(scope.range.start_byte <= declaration.range.start_byte);
        assert!(declaration.range.end_byte <= scope.range.end_byte);
    }

    #[test]
    fn producer_does_not_expose_member_class_inside_local_class_as_local() {
        let source = "class Outer { void host() { class Local { class Nested {} } } }";
        let parsed = parse(source);
        let source_facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        let facts = source_facts.java.as_ref().expect("Java source facts");
        let names = facts
            .local_types
            .iter()
            .map(|local| {
                let declaration = source_facts.occurrences.declaration(local.declaration);
                occurrence_text(
                    source,
                    &source_facts.occurrences,
                    declaration.name.expect("local class has a name"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Local"]);
        assert!(facts.valid_links(&source_facts.occurrences));
    }

    #[test]
    fn producer_does_not_attach_anonymous_body_members_to_outer_type() {
        let parsed = parse("class Outer { Runnable value = new Runnable() { void run() {} }; }");
        let source_facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        let facts = source_facts.java.as_ref().expect("Java source facts");
        assert!(facts.declaration_owners.is_empty());
        assert!(facts.valid_links(&source_facts.occurrences));
    }

    #[test]
    fn producer_publishes_all_anonymous_return_only_for_declared_nominal_types() {
        let parsed = parse(
            "class C { Runnable anonymous() { return new Runnable() {}; } Runnable mixed() { return null; } }",
        );
        let source_facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        let facts = source_facts.java.as_ref().expect("Java source facts");
        let anonymous = facts
            .anonymous_returns
            .iter()
            .find(|fact| fact.status == JavaAnonymousReturnStatus::AllAnonymous)
            .expect("all-anonymous callable fact");
        assert_eq!(anonymous.returns.len(), 1);
        let mixed = facts
            .anonymous_returns
            .iter()
            .find(|fact| fact.status == JavaAnonymousReturnStatus::Unknown)
            .expect("mixed callable fact");
        assert!(mixed.returns.is_empty());
        assert!(facts.valid_links(&source_facts.occurrences));
    }

    #[test]
    fn anonymous_return_completeness_ignores_unrelated_prior_type_rows() {
        let parsed = parse(
            "class C { void nothing(); int primitive(); List<?> wildcard(); Runnable anonymous() { return new Runnable() {}; } }",
        );
        let source_facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        let facts = source_facts.java.as_ref().expect("Java source facts");
        let anonymous = facts
            .anonymous_returns
            .iter()
            .find(|fact| {
                facts
                    .callable_returns
                    .iter()
                    .any(|callable| callable.callable == fact.callable)
                    && fact.returns.len() == 1
            })
            .expect("anonymous return fact");
        assert_eq!(anonymous.status, JavaAnonymousReturnStatus::AllAnonymous);
        assert!(facts.valid_links(&source_facts.occurrences));
    }
}
