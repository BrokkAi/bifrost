//! Relational publication of canonical C++ declaration source facts.

use brokk_bifrost_core::analyzer::cpp_facts::*;
use brokk_bifrost_core::analyzer::model::CppTemplateTerm;
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use rusqlite::{Transaction, params};

use crate::CancellationToken;
use crate::analyzer::store::cpp_template::{TemplateTermRow, flatten_template_expression};
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.cpp.as_ref().map(cost),
    insert,
};

pub(crate) fn cost(facts: &CppSourceFacts) -> (usize, usize) {
    let mut rows = 1usize
        .saturating_add(facts.includes.len())
        .saturating_add(facts.declarations.len())
        .saturating_add(facts.using_namespaces.len());
    let mut bytes = 0usize;
    for include in &facts.includes {
        bytes = bytes.saturating_add(include.path.len());
    }
    for fact in &facts.declarations {
        rows = rows
            .saturating_add(fact.written_owner.len())
            .saturating_add(fact.lexical_path.len())
            .saturating_add(fact.dependency_type_names.len())
            .saturating_add(fact.member_usings.len())
            .saturating_add(
                fact.member_usings
                    .iter()
                    .map(|using| using.scope.len())
                    .sum::<usize>(),
            )
            .saturating_add(fact.bases.len())
            .saturating_add(
                fact.bases
                    .iter()
                    .map(|base| base.components.len())
                    .sum::<usize>(),
            );
        bytes = bytes
            .saturating_add(fact.trailing_qualifiers.len())
            .saturating_add(fact.alias_target_text.as_ref().map_or(0, String::len))
            .saturating_add(
                fact.callable_identity_suffix
                    .as_ref()
                    .map_or(0, String::len),
            )
            .saturating_add(fact.written_owner.iter().map(String::len).sum::<usize>())
            .saturating_add(fact.lexical_path.iter().map(String::len).sum::<usize>())
            .saturating_add(
                fact.dependency_type_names
                    .iter()
                    .map(String::len)
                    .sum::<usize>(),
            )
            .saturating_add(
                fact.member_usings
                    .iter()
                    .map(|using| {
                        using.member.len() + using.scope.iter().map(String::len).sum::<usize>()
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                fact.bases
                    .iter()
                    .map(|base| base.components.iter().map(String::len).sum::<usize>())
                    .sum::<usize>(),
            );
        if let Some(field) = &fact.field_type {
            rows = rows.saturating_add(
                field
                    .template_arguments
                    .as_ref()
                    .map_or(0, |args| template_expression_rows(args)),
            );
            bytes = bytes.saturating_add(field.type_text.len());
            bytes = bytes.saturating_add(
                field
                    .template_arguments
                    .as_ref()
                    .map_or(0, |args| template_expression_payload(args)),
            );
        }
        if let Some(shapes) = &fact.callable_comparable_shapes {
            rows = rows.saturating_add(shapes.len());
            for shape in shapes {
                let CppComparableSlot::Shape(parameter) = shape else {
                    continue;
                };
                rows = rows
                    .saturating_add(1)
                    .saturating_add(parameter.nodes().len());
                for node in parameter.nodes() {
                    match node {
                        CppComparableNode::Named { name, .. } => {
                            rows = rows
                                .saturating_add(name.path().len())
                                .saturating_add(name.lexical_scope().len());
                            bytes = bytes
                                .saturating_add(name.path().iter().map(String::len).sum::<usize>())
                                .saturating_add(
                                    name.lexical_scope().iter().map(String::len).sum::<usize>(),
                                );
                        }
                        CppComparableNode::Generic { arguments, .. } => {
                            rows = rows.saturating_add(arguments.len());
                        }
                        _ => {}
                    }
                }
            }
        }
        if let Some(CppStructuredAliasTarget::Named {
            components,
            arguments,
            ..
        }) = &fact.alias_target
        {
            rows = rows.saturating_add(components.len());
            bytes = bytes.saturating_add(components.iter().map(String::len).sum::<usize>());
            rows = rows.saturating_add(
                arguments
                    .as_ref()
                    .map_or(0, |args| template_expression_rows(args)),
            );
            bytes = bytes.saturating_add(
                arguments
                    .as_ref()
                    .map_or(0, |args| template_expression_payload(args)),
            );
        }
    }
    bytes = bytes.saturating_add(
        facts
            .using_namespaces
            .iter()
            .map(|(_, namespace)| namespace.len())
            .sum::<usize>(),
    );
    let (context_rows, context_bytes) = super::source_publication_context::cost(facts);
    (
        rows.saturating_add(context_rows),
        bytes.saturating_add(context_bytes),
    )
}

fn template_expression_rows(
    expressions: &[brokk_bifrost_core::analyzer::model::CppTemplateExpression],
) -> usize {
    expressions
        .iter()
        .map(|expression| {
            let mut count = 1usize;
            let mut stack = vec![&expression.term];
            while let Some(term) = stack.pop() {
                count = count.saturating_add(1);
                if let CppTemplateTerm::Node { children, .. } = term {
                    stack.extend(children.iter());
                }
            }
            count
        })
        .sum()
}

fn template_expression_payload(
    expressions: &[brokk_bifrost_core::analyzer::model::CppTemplateExpression],
) -> usize {
    expressions
        .iter()
        .map(|expression| {
            let mut bytes = expression.text.len();
            let mut stack = vec![&expression.term];
            while let Some(term) = stack.pop() {
                match term {
                    CppTemplateTerm::Parameter(name) => bytes = bytes.saturating_add(name.len()),
                    CppTemplateTerm::Atom { kind, text } => {
                        bytes = bytes.saturating_add(kind.len()).saturating_add(text.len())
                    }
                    CppTemplateTerm::Node { kind, children } => {
                        bytes = bytes.saturating_add(kind.len());
                        stack.extend(children.iter());
                    }
                }
            }
            bytes
        })
        .sum()
}

fn class_strength(value: CppClassDeclarationStrength) -> i64 {
    match value {
        CppClassDeclarationStrength::Unknown => 0,
        CppClassDeclarationStrength::Full => 1,
        CppClassDeclarationStrength::Forward => 2,
    }
}

fn enum_kind(value: CppEnumOwnerKind) -> i64 {
    match value {
        CppEnumOwnerKind::NonEnum => 0,
        CppEnumOwnerKind::Scoped => 1,
        CppEnumOwnerKind::Unscoped => 2,
    }
}

fn occurrence_role(value: CppOccurrenceRole) -> i64 {
    match value {
        CppOccurrenceRole::DeclarationOnly => 0,
        CppOccurrenceRole::Definition => 1,
        CppOccurrenceRole::Both => 2,
        CppOccurrenceRole::Unknown => 3,
    }
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = &source.cpp else {
        return Ok(());
    };
    assert!(
        facts.valid_links(&source.occurrences),
        "invalid C++ source links: {facts:?}"
    );

    let mut includes = tx.prepare_cached(
        "INSERT INTO source_cpp_includes
         (blob_id, ordinal, declaration_occurrence_id, target_occurrence_id, path, quoted)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (ordinal, include) in facts.includes.iter().enumerate() {
        check_cancelled(cancellation)?;
        includes.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            i64::from(include.declaration.get()),
            i64::from(include.target.get()),
            &include.path,
            i64::from(include.quoted),
        ])?;
    }
    drop(includes);

    let mut declarations = tx.prepare_cached(
        "INSERT INTO source_cpp_declarations
         (blob_id, declaration_id, occurrence_role, conditional_family_occurrence_id,
          class_strength, enum_kind, field_type_text,
          field_indirection, field_binds_indirectly, alias_kind, alias_global, alias_target_text,
          adds_indirection, names_function_type, trailing_qualifiers,
          callable_shapes_present, callable_identity_suffix,
          callable_is_constructor, callable_is_deduction_guide, callable_is_template,
          field_arguments_present, alias_arguments_present)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
    )?;
    let mut paths = tx.prepare_cached(
        "INSERT INTO source_cpp_declaration_paths
         (blob_id, declaration_id, path_kind, ordinal, component)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut usings = tx.prepare_cached(
        "INSERT INTO source_cpp_member_usings
         (blob_id, declaration_id, ordinal, member)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut using_scopes = tx.prepare_cached(
        "INSERT INTO source_cpp_member_using_scopes
         (blob_id, declaration_id, using_ordinal, ordinal, component)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut bases = tx.prepare_cached(
        "INSERT INTO source_cpp_bases
         (blob_id, declaration_id, ordinal, is_virtual, absolute)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut base_components = tx.prepare_cached(
        "INSERT INTO source_cpp_base_components
         (blob_id, declaration_id, base_ordinal, ordinal, component)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut expressions = TemplateExpressions::default();
    for fact in &facts.declarations {
        check_cancelled(cancellation)?;
        let (field_text, field_indirection, field_binds_indirectly) = fact
            .field_type
            .as_ref()
            .map_or((None, None, None), |field| {
                (
                    Some(field.type_text.as_str()),
                    Some(field.indirection),
                    Some(i64::from(field.binds_indirectly)),
                )
            });
        let (alias_kind, alias_global, alias_target_text) = match &fact.alias_target {
            None => (None, None, fact.alias_target_text.as_deref()),
            Some(CppStructuredAliasTarget::Builtin) => {
                (Some(0), None, fact.alias_target_text.as_deref())
            }
            Some(CppStructuredAliasTarget::Named { global, .. }) => (
                Some(1),
                Some(i64::from(*global)),
                fact.alias_target_text.as_deref(),
            ),
        };
        declarations.execute(params![
            blob_id,
            i64::from(fact.declaration.get()),
            occurrence_role(fact.occurrence_role),
            fact.conditional_family.map(|id| i64::from(id.get())),
            class_strength(fact.class_strength),
            enum_kind(fact.enum_kind),
            field_text,
            field_indirection,
            field_binds_indirectly,
            alias_kind,
            alias_global,
            alias_target_text,
            i64::from(fact.adds_indirection),
            i64::from(fact.names_function_type),
            &fact.trailing_qualifiers,
            i64::from(fact.callable_comparable_shapes.is_some()),
            fact.callable_identity_suffix.as_deref(),
            i64::from(fact.callable_is_constructor),
            i64::from(fact.callable_is_deduction_guide),
            i64::from(fact.callable_is_template),
            i64::from(
                fact.field_type
                    .as_ref()
                    .is_some_and(|field| field.template_arguments.is_some())
            ),
            i64::from(matches!(
                &fact.alias_target,
                Some(CppStructuredAliasTarget::Named {
                    arguments: Some(_),
                    ..
                })
            )),
        ])?;
        for (path_kind, path) in [
            (0i64, &fact.written_owner),
            (1, &fact.lexical_path),
            (2, &fact.dependency_type_names),
        ] {
            for (ordinal, component) in path.iter().enumerate() {
                paths.execute(params![
                    blob_id,
                    fact.declaration.get(),
                    path_kind,
                    usize_to_i64(ordinal)?,
                    component
                ])?;
            }
        }
        for (ordinal, using) in fact.member_usings.iter().enumerate() {
            usings.execute(params![
                blob_id,
                fact.declaration.get(),
                usize_to_i64(ordinal)?,
                &using.member
            ])?;
            for (scope_ordinal, component) in using.scope.iter().enumerate() {
                using_scopes.execute(params![
                    blob_id,
                    fact.declaration.get(),
                    usize_to_i64(ordinal)?,
                    usize_to_i64(scope_ordinal)?,
                    component
                ])?;
            }
        }
        for (ordinal, base) in fact.bases.iter().enumerate() {
            bases.execute(params![
                blob_id,
                fact.declaration.get(),
                usize_to_i64(ordinal)?,
                i64::from(base.is_virtual),
                i64::from(base.absolute)
            ])?;
            for (component_ordinal, component) in base.components.iter().enumerate() {
                base_components.execute(params![
                    blob_id,
                    fact.declaration.get(),
                    usize_to_i64(ordinal)?,
                    usize_to_i64(component_ordinal)?,
                    component
                ])?;
            }
        }
        if let Some(field) = &fact.field_type
            && let Some(arguments) = &field.template_arguments
        {
            expressions.push(fact.declaration.get(), 0, arguments)?;
        }
        if let Some(CppStructuredAliasTarget::Named {
            arguments: Some(arguments),
            ..
        }) = &fact.alias_target
        {
            expressions.push(fact.declaration.get(), 1, arguments)?;
        }
    }
    drop((
        declarations,
        paths,
        usings,
        using_scopes,
        bases,
        base_components,
    ));
    insert_callable_shapes(tx, blob_id, facts, cancellation)?;

    let mut alias_components = tx.prepare_cached(
        "INSERT INTO source_cpp_alias_components
         (blob_id, declaration_id, ordinal, component)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for fact in &facts.declarations {
        if let Some(CppStructuredAliasTarget::Named { components, .. }) = &fact.alias_target {
            for (ordinal, component) in components.iter().enumerate() {
                alias_components.execute(params![
                    blob_id,
                    fact.declaration.get(),
                    usize_to_i64(ordinal)?,
                    component
                ])?;
            }
        }
    }
    drop(alias_components);

    expressions.insert(tx, blob_id, cancellation)?;
    let mut namespaces = tx.prepare_cached(
        "INSERT INTO source_cpp_using_namespaces
         (blob_id, ordinal, occurrence_id, namespace)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (ordinal, (occurrence, namespace)) in facts.using_namespaces.iter().enumerate() {
        check_cancelled(cancellation)?;
        namespaces.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            occurrence.get(),
            namespace
        ])?;
    }
    drop(namespaces);

    super::source_publication_context::insert(tx, blob_id, facts, cancellation)?;
    let (logical_rows, payload_bytes) = cost(facts);
    tx.execute(
        "INSERT INTO source_cpp_manifests(blob_id, facts_version, logical_rows, payload_bytes)
         VALUES(?1, ?2, ?3, ?4)",
        params![
            blob_id,
            CPP_SOURCE_FACTS_VERSION,
            usize_to_i64(logical_rows)?,
            usize_to_i64(payload_bytes)?
        ],
    )?;
    Ok(())
}

fn insert_callable_shapes(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &CppSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut shapes = tx.prepare_cached(
        "INSERT INTO source_cpp_callable_shapes
         (blob_id, declaration_id, ordinal, kind, parameter_id)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut parameters = tx.prepare_cached(
        "INSERT INTO source_cpp_comparable_parameters
         (blob_id, parameter_id, root_node_id) VALUES(?1, ?2, ?3)",
    )?;
    let mut nodes = tx.prepare_cached(
        "INSERT INTO source_cpp_comparable_nodes
         (blob_id, parameter_id, node_id, kind, inner_node_id, base_node_id,
          primitive, konst, volatil, absolute)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    let mut names = tx.prepare_cached(
        "INSERT INTO source_cpp_comparable_node_names
         (blob_id, parameter_id, node_id, axis, ordinal, name)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut arguments = tx.prepare_cached(
        "INSERT INTO source_cpp_comparable_node_arguments
         (blob_id, parameter_id, node_id, ordinal, child_node_id)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut parameter_id = 0i64;
    for fact in &facts.declarations {
        let Some(callable_shapes) = &fact.callable_comparable_shapes else {
            continue;
        };
        for (shape_ordinal, shape) in callable_shapes.iter().enumerate() {
            check_cancelled(cancellation)?;
            let (kind, shape_parameter_id) = match shape {
                CppComparableSlot::Shape(_) => {
                    let id = parameter_id;
                    parameter_id = parameter_id.checked_add(1).ok_or_else(|| {
                        crate::analyzer::store::StoreError::new("C++ parameter id overflow")
                    })?;
                    (0, Some(id))
                }
                CppComparableSlot::Ellipsis => (1, None),
                CppComparableSlot::Unstructured => (2, None),
            };
            shapes.execute(params![
                blob_id,
                fact.declaration.get(),
                usize_to_i64(shape_ordinal)?,
                kind,
                shape_parameter_id,
            ])?;
            let CppComparableSlot::Shape(parameter) = shape else {
                continue;
            };
            parameters.execute(params![
                blob_id,
                shape_parameter_id,
                usize_to_i64(parameter.root())?,
            ])?;
            for (node_id, node) in parameter.nodes().iter().enumerate() {
                let (kind, inner, base, primitive, konst, volatil, absolute) = match node {
                    CppComparableNode::Named {
                        name,
                        primitive,
                        konst,
                        volatil,
                    } => (
                        0,
                        None,
                        None,
                        Some(i64::from(*primitive)),
                        Some(i64::from(*konst)),
                        Some(i64::from(*volatil)),
                        Some(i64::from(name.is_absolute())),
                    ),
                    CppComparableNode::Pointer {
                        inner,
                        konst,
                        volatil,
                    } => (
                        1,
                        Some(usize_to_i64(*inner)?),
                        None,
                        None,
                        Some(i64::from(*konst)),
                        Some(i64::from(*volatil)),
                        None,
                    ),
                    CppComparableNode::Reference { inner } => {
                        (2, Some(usize_to_i64(*inner)?), None, None, None, None, None)
                    }
                    CppComparableNode::Array { inner } => {
                        (3, Some(usize_to_i64(*inner)?), None, None, None, None, None)
                    }
                    CppComparableNode::Generic { base, .. } => {
                        (4, None, Some(usize_to_i64(*base)?), None, None, None, None)
                    }
                };
                nodes.execute(params![
                    blob_id,
                    shape_parameter_id,
                    usize_to_i64(node_id)?,
                    kind,
                    inner,
                    base,
                    primitive,
                    konst,
                    volatil,
                    absolute,
                ])?;
                if let CppComparableNode::Named { name, .. } = node {
                    for (axis, parts) in [(0i64, name.path()), (1, name.lexical_scope())] {
                        for (ordinal, name) in parts.iter().enumerate() {
                            names.execute(params![
                                blob_id,
                                shape_parameter_id,
                                usize_to_i64(node_id)?,
                                axis,
                                usize_to_i64(ordinal)?,
                                name,
                            ])?;
                        }
                    }
                }
                if let CppComparableNode::Generic {
                    arguments: children,
                    ..
                } = node
                {
                    for (ordinal, child) in children.iter().enumerate() {
                        arguments.execute(params![
                            blob_id,
                            shape_parameter_id,
                            usize_to_i64(node_id)?,
                            usize_to_i64(ordinal)?,
                            usize_to_i64(*child)?,
                        ])?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct TemplateExpressions {
    expressions: Vec<ExpressionRow>,
    terms: Vec<TemplateTermRow>,
}

struct ExpressionRow {
    id: i64,
    declaration: i64,
    owner_kind: i64,
    ordinal: i64,
    text: String,
    root_term: i64,
}

impl TemplateExpressions {
    fn push(
        &mut self,
        declaration: u32,
        owner_kind: i64,
        expressions: &[brokk_bifrost_core::analyzer::model::CppTemplateExpression],
    ) -> Result<()> {
        for (ordinal, expression) in expressions.iter().enumerate() {
            let expression_id = i64::try_from(self.expressions.len()).map_err(|_| {
                crate::analyzer::store::StoreError::new("C++ template expression id overflow")
            })?;
            let root_term = i64::try_from(self.terms.len()).map_err(|_| {
                crate::analyzer::store::StoreError::new("C++ template term id overflow")
            })?;
            let (flattened_root, rows) =
                flatten_template_expression(expression_id, root_term, expression)?;
            debug_assert_eq!(flattened_root, root_term);
            self.terms.extend(rows);
            self.expressions.push(ExpressionRow {
                id: expression_id,
                declaration: i64::from(declaration),
                owner_kind,
                ordinal: i64::try_from(ordinal).map_err(|_| {
                    crate::analyzer::store::StoreError::new(
                        "C++ template argument ordinal overflow",
                    )
                })?,
                text: expression.text.clone(),
                root_term,
            });
        }
        Ok(())
    }

    fn insert(
        &self,
        tx: &Transaction<'_>,
        blob_id: i64,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut expressions = tx.prepare_cached(
            "INSERT INTO source_cpp_template_expressions
             (blob_id, expression_id, declaration_id, owner_kind, argument_ordinal, text, root_term_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for expression in &self.expressions {
            check_cancelled(cancellation)?;
            expressions.execute(params![
                blob_id,
                expression.id,
                expression.declaration,
                expression.owner_kind,
                expression.ordinal,
                &expression.text,
                expression.root_term
            ])?;
        }
        drop(expressions);
        let mut terms = tx.prepare_cached(
            "INSERT INTO source_cpp_template_terms
             (blob_id, term_id, expression_id, parent_term_id, ordinal, kind, text, atom_kind)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for term in &self.terms {
            check_cancelled(cancellation)?;
            terms.execute(params![
                blob_id,
                term.id,
                term.expression,
                term.parent,
                usize_to_i64(term.ordinal)?,
                term.kind,
                term.text.as_deref(),
                term.atom_kind.as_deref()
            ])?;
        }
        Ok(())
    }
}
