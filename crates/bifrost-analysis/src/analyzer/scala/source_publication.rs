//! Relational publication of Scala declaration source properties.

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::scala_facts::*;
use rusqlite::{Transaction, params};
use std::collections::HashMap;

use crate::CancellationToken;
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.scala.as_ref().map(cost),
    insert,
};

/// Return the exact row and string accounting recorded in the Scala manifest.
/// Every relational child row is included, including path segments and
/// expression edges; this keeps the manifest useful as a publication proof.
pub(crate) fn cost(facts: &ScalaSourceFacts) -> (usize, usize) {
    let expressions = ExpressionRows::from_facts(facts);
    let mut rows = 1usize + expressions.rows.len();
    let mut bytes = 0usize;
    for expression in &expressions.rows {
        rows = rows
            .saturating_add(expression.segments.len())
            .saturating_add(expression.arguments.len());
        bytes = bytes.saturating_add(expression.segments.iter().map(String::len).sum::<usize>());
    }
    for fact in &facts.declarations {
        rows = rows
            .saturating_add(1)
            .saturating_add(fact.lexical_prefixes.len())
            .saturating_add(fact.lexical_scopes.len())
            .saturating_add(path_segments(fact.field_type_path.as_deref()))
            .saturating_add(path_segments(fact.type_alias_path.as_deref()));
        bytes = bytes
            .saturating_add(fact.lexical_prefixes.iter().map(String::len).sum::<usize>())
            .saturating_add(path_bytes(fact.field_type_path.as_deref()))
            .saturating_add(path_bytes(fact.type_alias_path.as_deref()));
        if let Some(owner) = &fact.generic_owner {
            rows = rows
                .saturating_add(1)
                .saturating_add(owner.type_parameters.len())
                .saturating_add(owner.supertypes.len());
            bytes =
                bytes.saturating_add(owner.type_parameters.iter().map(String::len).sum::<usize>());
        }
        if let Some(callable) = &fact.callable {
            rows = rows.saturating_add(1);
            rows = rows
                .saturating_add(path_segments(
                    callable.extension_receiver_type_path.as_deref(),
                ))
                .saturating_add(path_segments(callable.return_type_path.as_deref()));
            bytes = bytes
                .saturating_add(path_bytes(callable.extension_receiver_type_path.as_deref()))
                .saturating_add(path_bytes(callable.return_type_path.as_deref()));
            for (list_index, _list) in callable.shape.iter().enumerate() {
                rows = rows.saturating_add(1);
                for parameter_index in 0..callable.parameter_defaults[list_index].len() {
                    rows = rows.saturating_add(1);
                    let path = callable
                        .parameter_type_paths
                        .get(list_index)
                        .and_then(|paths| paths.get(parameter_index))
                        .and_then(Option::as_deref);
                    rows = rows.saturating_add(path_segments(path));
                    bytes = bytes.saturating_add(path_bytes(path));
                    if let Some(function) = callable
                        .parameter_function_type_paths
                        .get(list_index)
                        .and_then(|paths| paths.get(parameter_index))
                        .and_then(Option::as_ref)
                    {
                        rows = rows.saturating_add(1).saturating_add(function.len());
                        for path in function {
                            rows = rows.saturating_add(path_segments(path.as_deref()));
                            bytes = bytes.saturating_add(path_bytes(path.as_deref()));
                        }
                    }
                }
            }
        }
    }
    (rows, bytes)
}

/// Insert one complete Scala source-facts family.  The caller owns the common
/// source manifest and declaration-unit bridge; this function owns only the
/// Scala extension tables and its sealed family manifest.
fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = &source.scala else {
        return Ok(());
    };
    assert!(
        facts.valid_links(&source.occurrences),
        "invalid Scala source links: {facts:?}"
    );
    let expressions = ExpressionRows::from_facts(facts);

    let mut declarations = tx.prepare_cached(
        "INSERT INTO source_scala_declarations(
           blob_id, declaration_id, kind, visibility, callable_present,
           field_type_path_present, type_alias_path_present, stable_owner,
           is_enum, is_term_field, is_case_class, is_full_enum_case,
           is_abstract_callable, is_explicitly_abstract, is_sealed, is_final,
           generic_owner_present
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
    )?;
    let mut lexical_prefixes = tx.prepare_cached(
        "INSERT INTO source_scala_declaration_lexical_prefixes(
           blob_id, declaration_id, ordinal, prefix
         ) VALUES(?1,?2,?3,?4)",
    )?;
    let mut lexical_scopes = tx.prepare_cached(
        "INSERT INTO source_scala_declaration_lexical_scopes(
           blob_id, declaration_id, ordinal, occurrence_id
         ) VALUES(?1,?2,?3,?4)",
    )?;
    let mut declaration_paths = tx.prepare_cached(
        "INSERT INTO source_scala_declaration_path_segments(
           blob_id, declaration_id, path_kind, ordinal, segment
         ) VALUES(?1,?2,?3,?4,?5)",
    )?;
    let mut generic_owners = tx.prepare_cached(
        "INSERT INTO source_scala_generic_owners(blob_id,declaration_id)
         VALUES(?1,?2)",
    )?;
    let mut generic_parameters = tx.prepare_cached(
        "INSERT INTO source_scala_generic_parameters(
           blob_id,declaration_id,ordinal,name
         ) VALUES(?1,?2,?3,?4)",
    )?;
    let mut generic_supertypes = tx.prepare_cached(
        "INSERT INTO source_scala_generic_supertypes(
           blob_id,declaration_id,ordinal,expression_id
         ) VALUES(?1,?2,?3,?4)",
    )?;
    let mut callables = tx.prepare_cached(
        "INSERT INTO source_scala_callables(
           blob_id,declaration_id,role,function_lists,result_open,
           parameter_defaults_present,parameter_function_arities_present,
           parameter_type_paths_present,parameter_type_expressions_present,
           parameter_function_type_paths_present,extension_path_present,
           return_path_present,return_type_is_singleton,return_expression_id
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
    )?;
    let mut parameter_lists = tx.prepare_cached(
        "INSERT INTO source_scala_callable_lists(
           blob_id,declaration_id,ordinal,kind,required_arity,total_arity,repeated
         ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
    )?;
    let mut parameters = tx.prepare_cached(
        "INSERT INTO source_scala_callable_parameters(
           blob_id,declaration_id,list_ordinal,ordinal,defaulted,function_arity,
           type_path_present,type_expression_id,function_path_present
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
    )?;
    let mut callable_paths = tx.prepare_cached(
        "INSERT INTO source_scala_callable_path_segments(
           blob_id,declaration_id,path_kind,ordinal,segment
         ) VALUES(?1,?2,?3,?4,?5)",
    )?;
    let mut function_paths = tx.prepare_cached(
        "INSERT INTO source_scala_callable_function_paths(
           blob_id,declaration_id,list_ordinal,parameter_ordinal,present
         ) VALUES(?1,?2,?3,?4,?5)",
    )?;
    let mut function_cells = tx.prepare_cached(
        "INSERT INTO source_scala_callable_function_path_cells(
           blob_id,declaration_id,list_ordinal,parameter_ordinal,function_ordinal,present
         ) VALUES(?1,?2,?3,?4,?5,?6)",
    )?;
    let mut function_cell_segments = tx.prepare_cached(
        "INSERT INTO source_scala_callable_function_path_segments(
           blob_id,declaration_id,list_ordinal,parameter_ordinal,function_ordinal,ordinal,segment
         ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
    )?;

    for fact in &facts.declarations {
        check_cancelled(cancellation)?;
        let declaration = i64::from(fact.declaration.get());
        declarations.execute(params![
            blob_id,
            declaration,
            fact.kind.encoded(),
            fact.visibility.encoded(),
            i64::from(fact.callable.is_some()),
            i64::from(fact.field_type_path.is_some()),
            i64::from(fact.type_alias_path.is_some()),
            i64::from(fact.stable_owner),
            i64::from(fact.is_enum),
            i64::from(fact.is_term_field),
            i64::from(fact.is_case_class),
            i64::from(fact.is_full_enum_case),
            i64::from(fact.is_abstract_callable),
            i64::from(fact.is_explicitly_abstract),
            i64::from(fact.is_sealed),
            i64::from(fact.is_final),
            i64::from(fact.generic_owner.is_some()),
        ])?;
        for (ordinal, prefix) in fact.lexical_prefixes.iter().enumerate() {
            lexical_prefixes.execute(params![
                blob_id,
                declaration,
                usize_to_i64(ordinal)?,
                prefix
            ])?;
        }
        for (ordinal, scope) in fact.lexical_scopes.iter().enumerate() {
            lexical_scopes.execute(params![
                blob_id,
                declaration,
                usize_to_i64(ordinal)?,
                scope.get()
            ])?;
        }
        for (kind, path) in [
            (0_i64, fact.field_type_path.as_deref()),
            (1_i64, fact.type_alias_path.as_deref()),
        ] {
            if let Some(path) = path {
                for (ordinal, segment) in path.iter().enumerate() {
                    declaration_paths.execute(params![
                        blob_id,
                        declaration,
                        kind,
                        usize_to_i64(ordinal)?,
                        segment
                    ])?;
                }
            }
        }
        if let Some(owner) = &fact.generic_owner {
            generic_owners.execute(params![blob_id, declaration])?;
            for (ordinal, name) in owner.type_parameters.iter().enumerate() {
                generic_parameters.execute(params![
                    blob_id,
                    declaration,
                    usize_to_i64(ordinal)?,
                    name
                ])?;
            }
            for (ordinal, expression) in owner.supertypes.iter().enumerate() {
                generic_supertypes.execute(params![
                    blob_id,
                    declaration,
                    usize_to_i64(ordinal)?,
                    expressions.id(expression)
                ])?;
            }
        }
        let Some(callable) = &fact.callable else {
            continue;
        };
        callables.execute(params![
            blob_id,
            declaration,
            encode_role(callable.role),
            usize_to_i64(callable.result.function_lists)?,
            i64::from(callable.result.open),
            i64::from(!callable.parameter_defaults.is_empty()),
            i64::from(!callable.parameter_function_arities.is_empty()),
            i64::from(!callable.parameter_type_paths.is_empty()),
            i64::from(!callable.parameter_type_expressions.is_empty()),
            i64::from(!callable.parameter_function_type_paths.is_empty()),
            i64::from(callable.extension_receiver_type_path.is_some()),
            i64::from(callable.return_type_path.is_some()),
            i64::from(callable.return_type_is_singleton),
            callable
                .return_type_expression
                .as_ref()
                .map(|expression| expressions.id(expression)),
        ])?;
        for (list_ordinal, list) in callable.shape.iter().enumerate() {
            parameter_lists.execute(params![
                blob_id,
                declaration,
                usize_to_i64(list_ordinal)?,
                encode_parameter_list_kind(list.kind),
                usize_to_i64(list.arity.required())?,
                usize_to_i64(list.arity.total())?,
                i64::from(list.arity.is_repeated()),
            ])?;
            for parameter_ordinal in 0..callable.parameter_defaults[list_ordinal].len() {
                check_cancelled(cancellation)?;
                let type_path = callable
                    .parameter_type_paths
                    .get(list_ordinal)
                    .and_then(|paths| paths.get(parameter_ordinal))
                    .and_then(Option::as_deref);
                let type_expression = callable
                    .parameter_type_expressions
                    .get(list_ordinal)
                    .and_then(|paths| paths.get(parameter_ordinal))
                    .and_then(Option::as_ref);
                let function_path = callable
                    .parameter_function_type_paths
                    .get(list_ordinal)
                    .and_then(|paths| paths.get(parameter_ordinal))
                    .and_then(Option::as_ref);
                parameters.execute(params![
                    blob_id,
                    declaration,
                    usize_to_i64(list_ordinal)?,
                    usize_to_i64(parameter_ordinal)?,
                    i64::from(callable.parameter_defaults[list_ordinal][parameter_ordinal]),
                    callable
                        .parameter_function_arities
                        .get(list_ordinal)
                        .and_then(|paths| paths.get(parameter_ordinal))
                        .copied()
                        .flatten()
                        .map(usize_to_i64)
                        .transpose()?,
                    i64::from(type_path.is_some()),
                    type_expression.map(|expression| expressions.id(expression)),
                    i64::from(function_path.is_some()),
                ])?;
                if let Some(function) = function_path {
                    function_paths.execute(params![
                        blob_id,
                        declaration,
                        usize_to_i64(list_ordinal)?,
                        usize_to_i64(parameter_ordinal)?,
                        1_i64
                    ])?;
                    for (function_ordinal, path) in function.iter().enumerate() {
                        function_cells.execute(params![
                            blob_id,
                            declaration,
                            usize_to_i64(list_ordinal)?,
                            usize_to_i64(parameter_ordinal)?,
                            usize_to_i64(function_ordinal)?,
                            i64::from(path.is_some()),
                        ])?;
                        if let Some(path) = path {
                            for (ordinal, segment) in path.iter().enumerate() {
                                function_cell_segments.execute(params![
                                    blob_id,
                                    declaration,
                                    usize_to_i64(list_ordinal)?,
                                    usize_to_i64(parameter_ordinal)?,
                                    usize_to_i64(function_ordinal)?,
                                    usize_to_i64(ordinal)?,
                                    segment,
                                ])?;
                            }
                        }
                    }
                }
            }
        }
        if let Some(path) = callable.extension_receiver_type_path.as_deref() {
            for (ordinal, segment) in path.iter().enumerate() {
                callable_paths.execute(params![
                    blob_id,
                    declaration,
                    0_i64,
                    usize_to_i64(ordinal)?,
                    segment
                ])?;
            }
        }
        if let Some(path) = callable.return_type_path.as_deref() {
            for (ordinal, segment) in path.iter().enumerate() {
                callable_paths.execute(params![
                    blob_id,
                    declaration,
                    1_i64,
                    usize_to_i64(ordinal)?,
                    segment
                ])?;
            }
        }
    }
    drop((
        declarations,
        lexical_prefixes,
        lexical_scopes,
        declaration_paths,
        generic_owners,
        generic_parameters,
        generic_supertypes,
        callables,
        parameter_lists,
        parameters,
        callable_paths,
        function_paths,
        function_cells,
        function_cell_segments,
    ));

    // Parameter path segments need all three ordinals, so they are kept in a
    // dedicated child table rather than overloading callable path rows.
    let mut parameter_path_segments = tx.prepare_cached(
        "INSERT INTO source_scala_callable_parameter_path_segments(
           blob_id,declaration_id,list_ordinal,parameter_ordinal,ordinal,segment
         ) VALUES(?1,?2,?3,?4,?5,?6)",
    )?;
    for fact in &facts.declarations {
        let Some(callable) = &fact.callable else {
            continue;
        };
        for (list_ordinal, paths) in callable.parameter_type_paths.iter().enumerate() {
            for (parameter_ordinal, path) in paths.iter().enumerate() {
                let Some(path) = path else {
                    continue;
                };
                for (ordinal, segment) in path.iter().enumerate() {
                    check_cancelled(cancellation)?;
                    parameter_path_segments.execute(params![
                        blob_id,
                        fact.declaration.get(),
                        usize_to_i64(list_ordinal)?,
                        usize_to_i64(parameter_ordinal)?,
                        usize_to_i64(ordinal)?,
                        segment,
                    ])?;
                }
            }
        }
    }
    drop(parameter_path_segments);

    let mut expression_rows = tx.prepare_cached(
        "INSERT INTO source_scala_type_expressions(blob_id,expression_id)
         VALUES(?1,?2)",
    )?;
    let mut expression_segments = tx.prepare_cached(
        "INSERT INTO source_scala_type_expression_segments(
           blob_id,expression_id,ordinal,segment
         ) VALUES(?1,?2,?3,?4)",
    )?;
    let mut expression_arguments = tx.prepare_cached(
        "INSERT INTO source_scala_type_expression_arguments(
           blob_id,expression_id,ordinal,child_id
         ) VALUES(?1,?2,?3,?4)",
    )?;
    for (id, expression) in expressions.rows.iter().enumerate() {
        check_cancelled(cancellation)?;
        expression_rows.execute(params![blob_id, usize_to_i64(id)?])?;
        for (ordinal, segment) in expression.segments.iter().enumerate() {
            expression_segments.execute(params![
                blob_id,
                usize_to_i64(id)?,
                usize_to_i64(ordinal)?,
                segment
            ])?;
        }
        for (ordinal, child) in expression.arguments.iter().enumerate() {
            expression_arguments.execute(params![
                blob_id,
                usize_to_i64(id)?,
                usize_to_i64(ordinal)?,
                child.get()
            ])?;
        }
    }
    drop((expression_rows, expression_segments, expression_arguments));

    let (logical_rows, payload_bytes) = cost(facts);
    tx.execute(
        "INSERT INTO source_scala_declaration_manifests(
           blob_id,facts_version,logical_rows,payload_bytes
         ) VALUES(?1,?2,?3,?4)",
        params![
            blob_id,
            SCALA_SOURCE_FACTS_VERSION,
            usize_to_i64(logical_rows)?,
            usize_to_i64(payload_bytes)?
        ],
    )?;
    Ok(())
}

fn encode_role(role: ScalaCallableRole) -> i64 {
    match role {
        ScalaCallableRole::Ordinary => 0,
        ScalaCallableRole::PrimaryConstructor => 1,
        ScalaCallableRole::SecondaryConstructor => 2,
    }
}

fn encode_parameter_list_kind(kind: ScalaParameterListKind) -> i64 {
    match kind {
        ScalaParameterListKind::Explicit => 0,
        ScalaParameterListKind::Contextual => 1,
    }
}

fn path_segments(path: Option<&[String]>) -> usize {
    path.map_or(0, <[String]>::len)
}

fn path_bytes(path: Option<&[String]>) -> usize {
    path.map_or(0, |segments| segments.iter().map(String::len).sum())
}

#[derive(Clone, Debug)]
struct FlatExpression {
    segments: Vec<String>,
    arguments: Vec<ScalaTypeExpressionId>,
}

#[derive(Default)]
struct ExpressionRows {
    rows: Vec<FlatExpression>,
    ids: HashMap<usize, ScalaTypeExpressionId>,
}

enum ExpressionTask<'a> {
    Visit(&'a ScalaTypeExpressionPath),
    Finish(&'a ScalaTypeExpressionPath),
}

impl ExpressionRows {
    fn from_facts(facts: &ScalaSourceFacts) -> Self {
        let mut rows = Self::default();
        for fact in &facts.declarations {
            if let Some(owner) = &fact.generic_owner {
                for expression in &owner.supertypes {
                    rows.intern(expression);
                }
            }
            let Some(callable) = &fact.callable else {
                continue;
            };
            if let Some(expression) = &callable.return_type_expression {
                rows.intern(expression);
            }
            for list in &callable.parameter_type_expressions {
                for expression in list.iter().flatten() {
                    rows.intern(expression);
                }
            }
        }
        rows
    }

    fn intern(&mut self, root: &ScalaTypeExpressionPath) -> ScalaTypeExpressionId {
        let root_key = root as *const ScalaTypeExpressionPath as usize;
        if let Some(id) = self.ids.get(&root_key).copied() {
            return id;
        }
        let mut stack = vec![ExpressionTask::Visit(root)];
        while let Some(task) = stack.pop() {
            match task {
                ExpressionTask::Visit(expression) => {
                    let key = expression as *const ScalaTypeExpressionPath as usize;
                    if self.ids.contains_key(&key) {
                        continue;
                    }
                    stack.push(ExpressionTask::Finish(expression));
                    for argument in expression.arguments.iter().rev() {
                        let argument_key = argument as *const ScalaTypeExpressionPath as usize;
                        if !self.ids.contains_key(&argument_key) {
                            stack.push(ExpressionTask::Visit(argument));
                        }
                    }
                }
                ExpressionTask::Finish(expression) => {
                    let key = expression as *const ScalaTypeExpressionPath as usize;
                    if self.ids.contains_key(&key) {
                        continue;
                    }
                    let arguments = expression
                        .arguments
                        .iter()
                        .map(|argument| {
                            *self
                                .ids
                                .get(&(argument as *const ScalaTypeExpressionPath as usize))
                                .expect("expression children are flattened before parents")
                        })
                        .collect();
                    let id = ScalaTypeExpressionId::new(
                        u32::try_from(self.rows.len()).expect("Scala expression ids fit in u32"),
                    );
                    self.rows.push(FlatExpression {
                        segments: expression.segments.clone(),
                        arguments,
                    });
                    assert!(self.ids.insert(key, id).is_none());
                }
            }
        }
        *self
            .ids
            .get(&root_key)
            .expect("expression root is flattened")
    }

    fn id(&self, expression: &ScalaTypeExpressionPath) -> u32 {
        self.ids
            .get(&(expression as *const ScalaTypeExpressionPath as usize))
            .expect("all Scala expressions are flattened before insertion")
            .get()
    }
}
