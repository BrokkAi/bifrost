//! Generation-checked Scala source facts and exact mounted declaration links.

use crate::analyzer::LanguageAdapter;
use crate::analyzer::store::source_facts::{
    SOURCE_DECLARATION_UNITS_SQL, SOURCE_FACTS_VERSION, read_source_identity_rows, strict_bool,
};
use crate::analyzer::store::{
    AnalyzerStore, GenerationId, Result, StoreError, read_source_unit_map,
};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::scala_facts::*;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_jvm::scala::source_facts::ScalaFileSourceFacts;
use git2::Oid;
use rusqlite::{OptionalExtension, params};

pub(in crate::analyzer) const SCALA_SOURCE_HEADER_SQL: &str =
    "SELECT blob.id, marker.logical_rows, marker.payload_bytes,
            source.occurrence_count, source.declaration_count, source.declaration_unit_count
     FROM blobs AS blob
     JOIN source_scala_declaration_manifests AS marker ON marker.blob_id = blob.id
     JOIN source_fact_manifests AS source ON source.blob_id = blob.id
     JOIN blob_meta AS meta ON meta.blob_id = blob.id
     JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
     WHERE blob.blob_oid = ?1 AND blob.lang = 'scala' AND blob.generation = ?2
       AND marker.facts_version = ?3 AND source.facts_version = ?4
       AND source.publication_state = 'complete' AND meta.is_complete = 1 AND ready.available = 1";

fn required<T>(value: Option<T>, label: &str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(format!("Scala source syntax is missing {label}")))
}

fn decode_kind(value: i64) -> Result<ScalaDeclarationKind> {
    match value {
        0 => Ok(ScalaDeclarationKind::Other),
        1 => Ok(ScalaDeclarationKind::Class),
        2 => Ok(ScalaDeclarationKind::Trait),
        3 => Ok(ScalaDeclarationKind::Object),
        4 => Ok(ScalaDeclarationKind::Enum),
        5 => Ok(ScalaDeclarationKind::EnumCase),
        6 => Ok(ScalaDeclarationKind::TypeAlias),
        value => Err(StoreError::new(format!(
            "invalid Scala declaration kind {value}"
        ))),
    }
}

fn decode_visibility(value: i64) -> Result<ScalaDeclarationVisibility> {
    match value {
        0 => Ok(ScalaDeclarationVisibility::Public),
        1 => Ok(ScalaDeclarationVisibility::Protected),
        2 => Ok(ScalaDeclarationVisibility::NonApi),
        value => Err(StoreError::new(format!(
            "invalid Scala declaration visibility {value}"
        ))),
    }
}

fn take_expression(
    expressions: &mut [Option<ScalaTypeExpressionPath>],
    id: ScalaTypeExpressionId,
    label: &str,
) -> Result<ScalaTypeExpressionPath> {
    expressions
        .get_mut(id.index())
        .and_then(Option::take)
        .ok_or_else(|| StoreError::new(format!("Scala {label} expression is missing or reused")))
}

#[derive(Clone)]
struct CallableRow {
    role: ScalaCallableRole,
    result: ScalaDeclaredResult,
    defaults_present: bool,
    function_arities_present: bool,
    type_paths_present: bool,
    type_expressions_present: bool,
    function_paths_present: bool,
    extension_path_present: bool,
    return_path_present: bool,
    return_type_is_singleton: bool,
    return_expression: Option<ScalaTypeExpressionId>,
}

#[derive(Clone, Copy)]
struct ListRow {
    kind: ScalaParameterListKind,
    arity: brokk_bifrost_core::analyzer::model::CallableArity,
}

#[derive(Clone)]
struct ParameterRow {
    defaulted: bool,
    function_arity: Option<usize>,
    type_path_present: bool,
    type_expression: Option<ScalaTypeExpressionId>,
    function_path_present: bool,
}

impl AnalyzerStore {
    pub(crate) fn scala_source_facts<A: LanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<ScalaFileSourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }
        self.read_source_transaction("scala", generation, |tx| {
            let header = tx
                .query_row(
                    SCALA_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        generation.get(),
                        SCALA_SOURCE_FACTS_VERSION,
                        SOURCE_FACTS_VERSION
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, usize>(1)?,
                            row.get::<_, usize>(2)?,
                            row.get::<_, usize>(3)?,
                            row.get::<_, usize>(4)?,
                            row.get::<_, usize>(5)?,
                        ))
                    },
                )
                .optional()?;
            let (
                blob_id,
                expected_rows,
                expected_bytes,
                expected_occurrences,
                expected_declarations,
                expected_bridges,
            ) = header.ok_or_else(|| {
                StoreError::new(format!(
                    "canonical Scala source facts unavailable for {file:?} ({oid})"
                ))
            })?;

            macro_rules! read_rows {
                ($sql:expr, $row:ident, $body:block) => {{
                    let mut statement = tx.prepare_cached($sql)?;
                    let mut rows = statement.query([blob_id])?;
                    while let Some($row) = rows.next()? {
                        if !keep_going() {
                            return Ok(None);
                        }
                        $body
                    }
                }};
            }
            let Some(source) = read_source_identity_rows(
                tx,
                blob_id,
                expected_occurrences,
                expected_declarations,
                keep_going,
            )?
            else {
                return Ok(None);
            };

            let mut prefixes: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,ordinal,prefix FROM source_scala_declaration_lexical_prefixes
                 WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
                row,
                {
                    let list = prefixes.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Scala lexical prefix"));
                    }
                    list.push(row.get(2)?);
                }
            );
            let mut scopes: HashMap<u32, Vec<SourceOccurrenceId>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,ordinal,occurrence_id FROM source_scala_declaration_lexical_scopes
                 WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
                row,
                {
                    let list = scopes.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Scala lexical scope"));
                    }
                    list.push(SourceOccurrenceId::new(row.get(2)?));
                }
            );

            let mut declaration_paths: HashMap<(u32, i64), Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,path_kind,ordinal,segment
                 FROM source_scala_declaration_path_segments
                 WHERE blob_id=?1 ORDER BY declaration_id,path_kind,ordinal",
                row,
                {
                    let kind: i64 = row.get(1)?;
                    if !matches!(kind, 0 | 1) {
                        return Err(StoreError::new("invalid Scala declaration path kind"));
                    }
                    let list = declaration_paths.entry((row.get(0)?, kind)).or_default();
                    if row.get::<_, usize>(2)? != list.len() {
                        return Err(StoreError::new("non-dense Scala declaration path"));
                    }
                    list.push(row.get(3)?);
                }
            );

            let mut expression_segments: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT expression_id,ordinal,segment
                 FROM source_scala_type_expression_segments
                 WHERE blob_id=?1 ORDER BY expression_id,ordinal",
                row,
                {
                    let list = expression_segments.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Scala expression segment"));
                    }
                    list.push(row.get(2)?);
                }
            );
            let mut expression_arguments: HashMap<u32, Vec<u32>> = HashMap::default();
            read_rows!(
                "SELECT expression_id,ordinal,child_id
                 FROM source_scala_type_expression_arguments
                 WHERE blob_id=?1 ORDER BY expression_id,ordinal",
                row,
                {
                    let list = expression_arguments.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Scala expression argument"));
                    }
                    list.push(row.get(2)?);
                }
            );
            let expression_count: usize = tx.query_row(
                "SELECT COUNT(*) FROM source_scala_type_expressions WHERE blob_id=?1",
                [blob_id],
                |row| row.get(0),
            )?;
            let mut expressions: Vec<Option<ScalaTypeExpressionPath>> =
                Vec::with_capacity(expression_count);
            for id in 0..expression_count {
                let id = u32::try_from(id).expect("Scala expression ids fit in u32");
                let segments = required(expression_segments.remove(&id), "expression segments")?;
                let argument_ids = expression_arguments.remove(&id).unwrap_or_default();
                let mut arguments = Vec::with_capacity(argument_ids.len());
                for child in argument_ids {
                    let child = ScalaTypeExpressionId::new(child);
                    arguments.push(take_expression(&mut expressions, child, "type argument")?);
                }
                expressions.push(Some(ScalaTypeExpressionPath {
                    segments,
                    arguments,
                }));
            }
            if !expression_segments.is_empty() || !expression_arguments.is_empty() {
                return Err(StoreError::new("orphan Scala expression details"));
            }

            let mut generic_parameters: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,ordinal,name FROM source_scala_generic_parameters
                 WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
                row,
                {
                    let list = generic_parameters.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Scala generic parameter"));
                    }
                    list.push(row.get(2)?);
                }
            );
            let mut generic_supertypes: HashMap<u32, Vec<ScalaTypeExpressionId>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,ordinal,expression_id FROM source_scala_generic_supertypes
                 WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
                row,
                {
                    let list = generic_supertypes.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Scala generic supertype"));
                    }
                    list.push(ScalaTypeExpressionId::new(row.get(2)?));
                }
            );
            let mut generic_owners = std::collections::HashSet::new();
            read_rows!(
                "SELECT declaration_id FROM source_scala_generic_owners WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    if !generic_owners.insert(row.get::<_, u32>(0)?) {
                        return Err(StoreError::new("duplicate Scala generic owner"));
                    }
                }
            );

            let mut callable_rows: HashMap<u32, CallableRow> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,role,function_lists,result_open,
                        parameter_defaults_present,parameter_function_arities_present,
                        parameter_type_paths_present,parameter_type_expressions_present,
                        parameter_function_type_paths_present,extension_path_present,
                        return_path_present,return_type_is_singleton,return_expression_id
                 FROM source_scala_callables WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    let role = match row.get::<_, i64>(1)? {
                        0 => ScalaCallableRole::Ordinary,
                        1 => ScalaCallableRole::PrimaryConstructor,
                        2 => ScalaCallableRole::SecondaryConstructor,
                        value => {
                            return Err(StoreError::new(format!(
                                "invalid Scala callable role {value}"
                            )));
                        }
                    };
                    callable_rows.insert(
                        row.get(0)?,
                        CallableRow {
                            role,
                            result: ScalaDeclaredResult::new(
                                row.get::<_, usize>(2)?,
                                strict_bool(row.get(3)?, "Scala result openness")?,
                            ),
                            defaults_present: strict_bool(row.get(4)?, "Scala defaults presence")?,
                            function_arities_present: strict_bool(
                                row.get(5)?,
                                "Scala function arities presence",
                            )?,
                            type_paths_present: strict_bool(
                                row.get(6)?,
                                "Scala parameter paths presence",
                            )?,
                            type_expressions_present: strict_bool(
                                row.get(7)?,
                                "Scala parameter expressions presence",
                            )?,
                            function_paths_present: strict_bool(
                                row.get(8)?,
                                "Scala function paths presence",
                            )?,
                            extension_path_present: strict_bool(
                                row.get(9)?,
                                "Scala extension path presence",
                            )?,
                            return_path_present: strict_bool(
                                row.get(10)?,
                                "Scala return path presence",
                            )?,
                            return_type_is_singleton: strict_bool(
                                row.get(11)?,
                                "Scala singleton return type",
                            )?,
                            return_expression: row
                                .get::<_, Option<u32>>(12)?
                                .map(ScalaTypeExpressionId::new),
                        },
                    );
                }
            );
            let mut callable_lists: HashMap<u32, Vec<ListRow>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,ordinal,kind,required_arity,total_arity,repeated
                 FROM source_scala_callable_lists WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
                row,
                {
                    let list = callable_lists.entry(row.get(0)?).or_default();
                    if row.get::<_, usize>(1)? != list.len() {
                        return Err(StoreError::new("non-dense Scala callable list"));
                    }
                    let kind = match row.get::<_, i64>(2)? {
                        0 => ScalaParameterListKind::Explicit,
                        1 => ScalaParameterListKind::Contextual,
                        value => {
                            return Err(StoreError::new(format!(
                                "invalid Scala parameter list kind {value}"
                            )));
                        }
                    };
                    let required: usize = row.get(3)?;
                    let total: usize = row.get(4)?;
                    if required > total {
                        return Err(StoreError::new(
                            "Scala callable required arity exceeds total",
                        ));
                    }
                    list.push(ListRow {
                        kind,
                        arity: brokk_bifrost_core::analyzer::model::CallableArity::new(
                            required,
                            total,
                            strict_bool(row.get(5)?, "Scala repeated arity")?,
                        ),
                    });
                }
            );
            let mut parameters: HashMap<(u32, u32, u32), ParameterRow> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,list_ordinal,ordinal,defaulted,function_arity,
                        type_path_present,type_expression_id,function_path_present
                 FROM source_scala_callable_parameters
                 WHERE blob_id=?1 ORDER BY declaration_id,list_ordinal,ordinal",
                row,
                {
                    let key = (row.get(0)?, row.get(1)?, row.get(2)?);
                    if parameters
                        .insert(
                            key,
                            ParameterRow {
                                defaulted: strict_bool(row.get(3)?, "Scala parameter default")?,
                                function_arity: row.get(4)?,
                                type_path_present: strict_bool(
                                    row.get(5)?,
                                    "Scala parameter path presence",
                                )?,
                                type_expression: row
                                    .get::<_, Option<u32>>(6)?
                                    .map(ScalaTypeExpressionId::new),
                                function_path_present: strict_bool(
                                    row.get(7)?,
                                    "Scala function path presence",
                                )?,
                            },
                        )
                        .is_some()
                    {
                        return Err(StoreError::new("duplicate Scala callable parameter"));
                    }
                }
            );
            let mut parameter_paths: HashMap<(u32, u32, u32), Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,list_ordinal,parameter_ordinal,ordinal,segment
                 FROM source_scala_callable_parameter_path_segments
                 WHERE blob_id=?1 ORDER BY declaration_id,list_ordinal,parameter_ordinal,ordinal",
                row,
                {
                    let key = (row.get(0)?, row.get(1)?, row.get(2)?);
                    let list = parameter_paths.entry(key).or_default();
                    if row.get::<_, usize>(3)? != list.len() {
                        return Err(StoreError::new("non-dense Scala parameter type path"));
                    }
                    list.push(row.get(4)?);
                }
            );
            let mut callable_paths: HashMap<(u32, i64), Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,path_kind,ordinal,segment
                 FROM source_scala_callable_path_segments
                 WHERE blob_id=?1 ORDER BY declaration_id,path_kind,ordinal",
                row,
                {
                    let kind: i64 = row.get(1)?;
                    if !matches!(kind, 0 | 1) {
                        return Err(StoreError::new("invalid Scala callable path kind"));
                    }
                    let list = callable_paths.entry((row.get(0)?, kind)).or_default();
                    if row.get::<_, usize>(2)? != list.len() {
                        return Err(StoreError::new("non-dense Scala callable path"));
                    }
                    list.push(row.get(3)?);
                }
            );
            let mut function_path_presence = std::collections::HashSet::new();
            read_rows!(
                "SELECT declaration_id,list_ordinal,parameter_ordinal
                 FROM source_scala_callable_function_paths WHERE blob_id=?1",
                row,
                {
                    function_path_presence.insert((row.get(0)?, row.get(1)?, row.get(2)?));
                }
            );
            let mut function_cells: HashMap<(u32, u32, u32), Vec<bool>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id,list_ordinal,parameter_ordinal,function_ordinal,present
                 FROM source_scala_callable_function_path_cells
                 WHERE blob_id=?1 ORDER BY declaration_id,list_ordinal,parameter_ordinal,function_ordinal",
                row,
                {
                    let key = (row.get(0)?, row.get(1)?, row.get(2)?);
                    let list = function_cells.entry(key).or_default();
                    if row.get::<_, usize>(3)? != list.len() {
                        return Err(StoreError::new("non-dense Scala function path cell"));
                    }
                    list.push(strict_bool(row.get(4)?, "Scala function path cell")?);
                }
            );
            let mut function_cell_paths: HashMap<(u32, u32, u32, u32), Vec<String>> =
                HashMap::default();
            read_rows!(
                "SELECT declaration_id,list_ordinal,parameter_ordinal,function_ordinal,ordinal,segment
                 FROM source_scala_callable_function_path_segments
                 WHERE blob_id=?1 ORDER BY declaration_id,list_ordinal,parameter_ordinal,function_ordinal,ordinal",
                row,
                {
                    let key = (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
                    let list = function_cell_paths.entry(key).or_default();
                    if row.get::<_, usize>(4)? != list.len() {
                        return Err(StoreError::new("non-dense Scala function path segment"));
                    }
                    list.push(row.get(5)?);
                }
            );

            let mut facts = ScalaSourceFacts::default();
            read_rows!(
                "SELECT declaration_id,kind,visibility,callable_present,
                        field_type_path_present,type_alias_path_present,stable_owner,
                        is_enum,is_term_field,is_case_class,is_full_enum_case,
                        is_abstract_callable,is_explicitly_abstract,is_sealed,is_final,
                        generic_owner_present
                 FROM source_scala_declarations WHERE blob_id=?1 ORDER BY declaration_id",
                row,
                {
                    let declaration = SourceDeclarationId::new(row.get(0)?);
                    let declaration_key = declaration.get();
                    let kind = decode_kind(row.get(1)?)?;
                    let visibility = decode_visibility(row.get(2)?)?;
                    let generic_owner_present = strict_bool(row.get(15)?, "Scala generic owner")?;
                    let generic_owner = if generic_owner_present {
                        if !generic_owners.remove(&declaration_key) {
                            return Err(StoreError::new("Scala generic owner row is missing"));
                        }
                        Some(ScalaGenericOwnerSourceFacts {
                            type_parameters: generic_parameters
                                .remove(&declaration_key)
                                .unwrap_or_default(),
                            supertypes: generic_supertypes
                                .remove(&declaration_key)
                                .unwrap_or_default()
                                .into_iter()
                                .map(|id| take_expression(&mut expressions, id, "generic supertype"))
                                .collect::<Result<Vec<_>>>()?,
                        })
                    } else {
                        if generic_parameters.contains_key(&declaration_key)
                            || generic_supertypes.contains_key(&declaration_key)
                        {
                            return Err(StoreError::new("orphan Scala generic owner details"));
                        }
                        None
                    };
                    let callable_present = strict_bool(row.get(3)?, "Scala callable presence")?;
                    let callable = if callable_present {
                        let callable_row =
                            required(callable_rows.remove(&declaration_key), "callable")?;
                        let list_rows = callable_lists.remove(&declaration_key).unwrap_or_default();
                        let mut shape = Vec::with_capacity(list_rows.len());
                        let mut defaults = Vec::with_capacity(list_rows.len());
                        let mut function_arities = Vec::with_capacity(list_rows.len());
                        let mut type_paths = Vec::with_capacity(list_rows.len());
                        let mut type_expressions = Vec::with_capacity(list_rows.len());
                        let mut function_paths = Vec::with_capacity(list_rows.len());
                        for (list_ordinal, list) in list_rows.iter().enumerate() {
                            shape.push(ScalaCallableParameterList {
                                arity: list.arity,
                                kind: list.kind,
                            });
                            let mut list_defaults = Vec::with_capacity(list.arity.total());
                            let mut list_arities = Vec::with_capacity(list.arity.total());
                            let mut list_paths = Vec::with_capacity(list.arity.total());
                            let mut list_expressions = Vec::with_capacity(list.arity.total());
                            let mut list_function_paths = Vec::with_capacity(list.arity.total());
                            for parameter_ordinal in 0..list.arity.total() {
                                let key = (
                                    declaration_key,
                                    list_ordinal as u32,
                                    parameter_ordinal as u32,
                                );
                                let parameter =
                                    required(parameters.remove(&key), "callable parameter")?;
                                list_defaults.push(parameter.defaulted);
                                list_arities.push(parameter.function_arity);
                                let path = parameter_paths.remove(&key);
                                if parameter.type_path_present != path.is_some() {
                                    return Err(StoreError::new(
                                        "Scala parameter path presence mismatch",
                                    ));
                                }
                                list_paths.push(path);
                                let expression = parameter
                                    .type_expression
                                    .map(|id| take_expression(&mut expressions, id, "parameter"))
                                    .transpose()?;
                                list_expressions.push(expression);
                                let function_key_present = function_path_presence.remove(&key);
                                if parameter.function_path_present != function_key_present {
                                    return Err(StoreError::new(
                                        "Scala function path presence mismatch",
                                    ));
                                }
                                let function = if function_key_present {
                                    let cells = function_cells.remove(&key).unwrap_or_default();
                                    let mut paths = Vec::with_capacity(cells.len());
                                    for (function_ordinal, present) in cells.into_iter().enumerate() {
                                        let cell_key = (
                                            declaration_key,
                                            list_ordinal as u32,
                                            parameter_ordinal as u32,
                                            function_ordinal as u32,
                                        );
                                        let path = function_cell_paths.remove(&cell_key);
                                        if present != path.is_some() {
                                            return Err(StoreError::new(
                                                "Scala function cell presence mismatch",
                                            ));
                                        }
                                        paths.push(path);
                                    }
                                    Some(paths)
                                } else {
                                    None
                                };
                                list_function_paths.push(function);
                            }
                            defaults.push(list_defaults);
                            function_arities.push(list_arities);
                            type_paths.push(list_paths);
                            type_expressions.push(list_expressions);
                            function_paths.push(list_function_paths);
                        }
                        if callable_row.defaults_present == defaults.is_empty() {
                            return Err(StoreError::new("Scala callable defaults presence mismatch"));
                        }
                        let extension_path = callable_paths.remove(&(declaration_key, 0));
                        let return_path = callable_paths.remove(&(declaration_key, 1));
                        if callable_row.extension_path_present != extension_path.is_some()
                            || callable_row.return_path_present != return_path.is_some()
                        {
                            return Err(StoreError::new("Scala callable path presence mismatch"));
                        }
                        let return_expression = callable_row
                            .return_expression
                            .map(|id| take_expression(&mut expressions, id, "return"))
                            .transpose()?;
                        Some(ScalaCallableSourceAlternative {
                            role: callable_row.role,
                            shape,
                            result: callable_row.result,
                            parameter_defaults: defaults,
                            parameter_function_arities: if callable_row.function_arities_present {
                                function_arities
                            } else {
                                Vec::new()
                            },
                            parameter_type_paths: if callable_row.type_paths_present {
                                type_paths
                            } else {
                                Vec::new()
                            },
                            parameter_type_expressions: if callable_row.type_expressions_present {
                                type_expressions
                            } else {
                                Vec::new()
                            },
                            parameter_function_type_paths: if callable_row.function_paths_present {
                                function_paths
                            } else {
                                Vec::new()
                            },
                            extension_receiver_type_path: extension_path,
                            return_type_path: return_path,
                            return_type_is_singleton: callable_row.return_type_is_singleton,
                            return_type_expression: return_expression,
                        })
                    } else {
                        if callable_rows.contains_key(&declaration_key)
                            || callable_lists.contains_key(&declaration_key)
                        {
                            return Err(StoreError::new("orphan Scala callable rows"));
                        }
                        None
                    };
                    let field_type_path = declaration_paths.remove(&(declaration_key, 0));
                    let type_alias_path = declaration_paths.remove(&(declaration_key, 1));
                    if strict_bool(row.get(4)?, "Scala field path presence")?
                        != field_type_path.is_some()
                        || strict_bool(row.get(5)?, "Scala alias path presence")?
                            != type_alias_path.is_some()
                    {
                        return Err(StoreError::new("Scala declaration path presence mismatch"));
                    }
                    facts.declarations.push(ScalaDeclarationSourceFact {
                        declaration,
                        kind,
                        visibility,
                        callable,
                        field_type_path,
                        type_alias_path,
                        stable_owner: strict_bool(row.get(6)?, "Scala stable owner")?,
                        is_enum: strict_bool(row.get(7)?, "Scala enum")?,
                        is_term_field: strict_bool(row.get(8)?, "Scala term field")?,
                        is_case_class: strict_bool(row.get(9)?, "Scala case class")?,
                        is_full_enum_case: strict_bool(row.get(10)?, "Scala full enum case")?,
                        is_abstract_callable: strict_bool(row.get(11)?, "Scala abstract callable")?,
                        is_explicitly_abstract: strict_bool(
                            row.get(12)?,
                            "Scala explicitly abstract declaration",
                        )?,
                        is_sealed: strict_bool(row.get(13)?, "Scala sealed declaration")?,
                        is_final: strict_bool(row.get(14)?, "Scala final declaration")?,
                        generic_owner,
                        lexical_prefixes: prefixes.remove(&declaration_key).unwrap_or_default(),
                        lexical_scopes: scopes.remove(&declaration_key).unwrap_or_default(),
                    });
                }
            );
            if !prefixes.is_empty()
                || !scopes.is_empty()
                || !declaration_paths.is_empty()
                || !generic_owners.is_empty()
                || !generic_parameters.is_empty()
                || !generic_supertypes.is_empty()
                || !callable_rows.is_empty()
                || !callable_lists.is_empty()
                || !parameters.is_empty()
                || !parameter_paths.is_empty()
                || !callable_paths.is_empty()
                || !function_path_presence.is_empty()
                || !function_cells.is_empty()
                || !function_cell_paths.is_empty()
            {
                return Err(StoreError::new("orphan Scala source details"));
            }
            if expressions.iter().any(Option::is_some) {
                return Err(StoreError::new("orphan or unowned Scala expressions"));
            }
            if !facts.valid_links(&source)
                || super::source_publication::cost(&facts) != (expected_rows, expected_bytes)
            {
                return Err(StoreError::new(format!(
                    "invalid or incomplete Scala source publication: {facts:?}"
                )));
            }
            let Some(units) = read_source_unit_map(
                tx,
                &oid.to_string(),
                "scala",
                adapter,
                file,
                keep_going,
            )?
            else {
                return Ok(None);
            };
            let mut declaration_units: HashMap<_, Vec<_>> = HashMap::default();
            let mut bridge_count = 0;
            read_rows!(SOURCE_DECLARATION_UNITS_SQL, row, {
                let declaration = SourceDeclarationId::new(row.get(0)?);
                let key: i64 = row.get(1)?;
                let unit = required(units.get(&key), "declaration unit")?;
                if declaration.index() >= source.declaration_count() {
                    return Err(StoreError::new("Scala unit bridge has no declaration"));
                }
                declaration_units
                    .entry(declaration)
                    .or_default()
                    .push(unit.clone());
                bridge_count += 1;
            });
            if bridge_count != expected_bridges {
                return Err(StoreError::new(format!(
                    "incomplete Scala declaration bridges: {declaration_units:?}"
                )));
            }
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(ScalaFileSourceFacts {
                source,
                facts,
                declaration_units,
            }))
        })
    }
}
