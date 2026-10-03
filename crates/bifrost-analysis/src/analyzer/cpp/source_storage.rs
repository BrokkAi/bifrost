//! Hydration of one generation-selected C++ source-facts publication.

use crate::analyzer::LanguageAdapter;
use crate::analyzer::store::cpp_template::{TemplateTermRow, build_template_term};
use crate::analyzer::store::source_facts::{
    SOURCE_DECLARATION_UNITS_SQL, SOURCE_FACTS_VERSION, read_source_identity_rows, strict_bool,
};
use crate::analyzer::store::{
    AnalyzerStore, GenerationId, Result, StoreError, read_source_unit_map,
};
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::cpp_facts::*;
use brokk_bifrost_core::analyzer::model::{CppTemplateExpression, StructuredTypeName};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_cpp::source_facts::CppFileSourceFacts;
use git2::Oid;
use rusqlite::{OptionalExtension, params};

pub(in crate::analyzer) const CPP_SOURCE_HEADER_SQL: &str =
    "SELECT blob.id, marker.logical_rows, marker.payload_bytes,
            source.occurrence_count, source.declaration_count, source.declaration_unit_count
     FROM blobs AS blob
     JOIN source_cpp_manifests AS marker ON marker.blob_id = blob.id
     JOIN source_fact_manifests AS source ON source.blob_id = blob.id
     JOIN blob_meta AS meta ON meta.blob_id = blob.id
     JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
     WHERE blob.blob_oid = ?1 AND blob.lang = ?2 AND blob.generation = ?3
       AND marker.facts_version = ?4 AND source.facts_version = ?5
       AND source.publication_state = 'complete' AND meta.is_complete = 1 AND ready.available = 1";

fn required<T>(value: Option<T>, label: &str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(format!("C++ source syntax is missing {label}")))
}

impl AnalyzerStore {
    pub(crate) fn cpp_source_facts<A: LanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        lang: &str,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<CppFileSourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }
        self.read_source_transaction(lang, generation, |tx| {
            let header = tx
                .query_row(
                    CPP_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        lang,
                        generation.get(),
                        CPP_SOURCE_FACTS_VERSION,
                        SOURCE_FACTS_VERSION,
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
            let Some((
                blob_id,
                expected_rows,
                expected_bytes,
                expected_occurrences,
                expected_declarations,
                expected_bridges,
            )) = header
            else {
                return Ok(None);
            };
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

            let mut includes = Vec::new();
            read_rows!(
                "SELECT ordinal, declaration_occurrence_id, target_occurrence_id, path, quoted
             FROM source_cpp_includes WHERE blob_id = ?1 ORDER BY ordinal",
                row,
                {
                    let ordinal: usize = row.get(0)?;
                    if ordinal != includes.len() {
                        return Err(StoreError::new("non-dense C++ include ordinals"));
                    }
                    includes.push(CppIncludeFact {
                        declaration: SourceOccurrenceId::new(row.get(1)?),
                        target: SourceOccurrenceId::new(row.get(2)?),
                        path: row.get(3)?,
                        quoted: strict_bool(row.get(4)?, "C++ include quoting")?,
                    });
                }
            );

            let mut using_namespaces = Vec::new();
            read_rows!(
                "SELECT ordinal, occurrence_id, namespace
             FROM source_cpp_using_namespaces WHERE blob_id = ?1 ORDER BY ordinal",
                row,
                {
                    let ordinal: usize = row.get(0)?;
                    if ordinal != using_namespaces.len() {
                        return Err(StoreError::new("non-dense C++ using namespace ordinals"));
                    }
                    using_namespaces.push((SourceOccurrenceId::new(row.get(1)?), row.get(2)?));
                }
            );

            let mut paths: HashMap<(u32, i64), Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id, path_kind, ordinal, component
             FROM source_cpp_declaration_paths
             WHERE blob_id = ?1 ORDER BY declaration_id, path_kind, ordinal",
                row,
                {
                    let key = (row.get(0)?, row.get(1)?);
                    let list = paths.entry(key).or_default();
                    let ordinal: usize = row.get(2)?;
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense C++ declaration path"));
                    }
                    list.push(row.get(3)?);
                }
            );
            let mut alias_components: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id, ordinal, component
             FROM source_cpp_alias_components
             WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
                row,
                {
                    let declaration: u32 = row.get(0)?;
                    let list = alias_components.entry(declaration).or_default();
                    let ordinal: usize = row.get(1)?;
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense C++ alias components"));
                    }
                    list.push(row.get(2)?);
                }
            );
            let mut member_usings: HashMap<u32, Vec<(String, Vec<String>)>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id, ordinal, member
             FROM source_cpp_member_usings WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
                row,
                {
                    let declaration: u32 = row.get(0)?;
                    let list = member_usings.entry(declaration).or_default();
                    let ordinal: usize = row.get(1)?;
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense C++ member using"));
                    }
                    list.push((row.get(2)?, Vec::new()));
                }
            );
            read_rows!(
                "SELECT declaration_id, using_ordinal, ordinal, component
             FROM source_cpp_member_using_scopes
             WHERE blob_id = ?1 ORDER BY declaration_id, using_ordinal, ordinal",
                row,
                {
                    let declaration: u32 = row.get(0)?;
                    let using_ordinal: usize = row.get(1)?;
                    let list = member_usings
                        .get_mut(&declaration)
                        .ok_or_else(|| StoreError::new("C++ member using scope has no owner"))?;
                    let using = list.get_mut(using_ordinal).ok_or_else(|| {
                        StoreError::new("C++ member using scope ordinal is invalid")
                    })?;
                    let ordinal: usize = row.get(2)?;
                    if ordinal != using.1.len() {
                        return Err(StoreError::new("non-dense C++ member using scope"));
                    }
                    using.1.push(row.get(3)?);
                }
            );
            let mut bases: HashMap<u32, Vec<(bool, bool, Vec<String>)>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id, ordinal, is_virtual, absolute
             FROM source_cpp_bases WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
                row,
                {
                    let declaration: u32 = row.get(0)?;
                    let list = bases.entry(declaration).or_default();
                    let ordinal: usize = row.get(1)?;
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense C++ bases"));
                    }
                    list.push((
                        strict_bool(row.get(2)?, "C++ virtual base")?,
                        strict_bool(row.get(3)?, "C++ absolute base")?,
                        Vec::new(),
                    ));
                }
            );
            read_rows!(
                "SELECT declaration_id, base_ordinal, ordinal, component
             FROM source_cpp_base_components
             WHERE blob_id = ?1 ORDER BY declaration_id, base_ordinal, ordinal",
                row,
                {
                    let declaration: u32 = row.get(0)?;
                    let base_ordinal: usize = row.get(1)?;
                    let list = bases
                        .get_mut(&declaration)
                        .ok_or_else(|| StoreError::new("C++ base component has no owner"))?;
                    let base = list
                        .get_mut(base_ordinal)
                        .ok_or_else(|| StoreError::new("C++ base component ordinal is invalid"))?;
                    let ordinal: usize = row.get(2)?;
                    if ordinal != base.2.len() {
                        return Err(StoreError::new("non-dense C++ base components"));
                    }
                    base.2.push(row.get(3)?);
                }
            );

            let mut callable_shapes: HashMap<u32, Vec<(i64, Option<i64>)>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id, ordinal, kind, parameter_id
             FROM source_cpp_callable_shapes
             WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
                row,
                {
                    let declaration: u32 = row.get(0)?;
                    let list = callable_shapes.entry(declaration).or_default();
                    let ordinal: usize = row.get(1)?;
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense C++ callable shapes"));
                    }
                    list.push((row.get(2)?, row.get(3)?));
                }
            );
            let mut comparable_parameters: HashMap<i64, i64> = HashMap::default();
            read_rows!(
                "SELECT parameter_id, root_node_id
             FROM source_cpp_comparable_parameters
             WHERE blob_id = ?1 ORDER BY parameter_id",
                row,
                {
                    let parameter_id: i64 = row.get(0)?;
                    if parameter_id
                        != i64::try_from(comparable_parameters.len())
                            .expect("C++ parameter count fits i64")
                    {
                        return Err(StoreError::new("non-dense C++ comparable parameters"));
                    }
                    comparable_parameters.insert(parameter_id, row.get(1)?);
                }
            );
            let mut comparable_nodes: HashMap<i64, Vec<ComparableNodeRow>> = HashMap::default();
            read_rows!(
                "SELECT parameter_id, node_id, kind, inner_node_id, base_node_id,
                    primitive, konst, volatil, absolute
             FROM source_cpp_comparable_nodes
             WHERE blob_id = ?1 ORDER BY parameter_id, node_id",
                row,
                {
                    let parameter_id: i64 = row.get(0)?;
                    let list = comparable_nodes.entry(parameter_id).or_default();
                    let node_id: usize = row.get(1)?;
                    if node_id != list.len() {
                        return Err(StoreError::new("non-dense C++ comparable nodes"));
                    }
                    list.push(ComparableNodeRow {
                        kind: row.get(2)?,
                        inner: row.get(3)?,
                        base: row.get(4)?,
                        primitive: row.get(5)?,
                        konst: row.get(6)?,
                        volatil: row.get(7)?,
                        absolute: row.get(8)?,
                    });
                }
            );
            let mut comparable_names: HashMap<(i64, i64, i64), Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT parameter_id, node_id, axis, ordinal, name
             FROM source_cpp_comparable_node_names
             WHERE blob_id = ?1 ORDER BY parameter_id, node_id, axis, ordinal",
                row,
                {
                    let key = (row.get(0)?, row.get(1)?, row.get(2)?);
                    let list = comparable_names.entry(key).or_default();
                    let ordinal: usize = row.get(3)?;
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense C++ comparable names"));
                    }
                    list.push(row.get(4)?);
                }
            );
            let mut comparable_arguments: HashMap<(i64, i64), Vec<u32>> = HashMap::default();
            read_rows!(
                "SELECT parameter_id, node_id, ordinal, child_node_id
             FROM source_cpp_comparable_node_arguments
             WHERE blob_id = ?1 ORDER BY parameter_id, node_id, ordinal",
                row,
                {
                    let key = (row.get(0)?, row.get(1)?);
                    let list = comparable_arguments.entry(key).or_default();
                    let ordinal: usize = row.get(2)?;
                    if ordinal != list.len() {
                        return Err(StoreError::new("non-dense C++ comparable arguments"));
                    }
                    list.push(row.get(3)?);
                }
            );

            let Some(mut template_arguments) = read_template_arguments(tx, blob_id, keep_going)?
            else {
                return Ok(None);
            };
            let mut facts = CppSourceFacts {
                includes,
                declarations: Vec::new(),
                using_namespaces,
            };
            read_rows!(
                "SELECT declaration_id, occurrence_role, conditional_family_occurrence_id,
                    class_strength, enum_kind, field_type_text,
                    field_indirection, field_binds_indirectly,
                    alias_kind, alias_global, alias_target_text,
                    adds_indirection, names_function_type, trailing_qualifiers,
                    callable_shapes_present, callable_identity_suffix,
                    callable_is_constructor, callable_is_deduction_guide, callable_is_template,
                    field_arguments_present, alias_arguments_present
             FROM source_cpp_declarations WHERE blob_id = ?1 ORDER BY declaration_id",
                row,
                {
                    let declaration: u32 = row.get(0)?;
                    let field_text: Option<String> = row.get(5)?;
                    let field_indirection: Option<i32> = row.get(6)?;
                    let field_binds_indirectly: Option<i64> = row.get(7)?;
                    if field_text.is_some() != field_indirection.is_some()
                        || field_text.is_some() != field_binds_indirectly.is_some()
                    {
                        return Err(StoreError::new("inconsistent C++ field type columns"));
                    }
                    let field_binds_indirectly = field_binds_indirectly
                        .map(|value| strict_bool(value, "C++ field indirect binding"))
                        .transpose()?;
                    let alias_kind: Option<i64> = row.get(8)?;
                    let alias_global: Option<i64> = row.get(9)?;
                    let alias_target_text: Option<String> = row.get(10)?;
                    let field_arguments_present =
                        strict_bool(row.get(19)?, "C++ field arguments presence")?;
                    let alias_arguments_present =
                        strict_bool(row.get(20)?, "C++ alias arguments presence")?;
                    let alias_target = match alias_kind {
                        None => {
                            if alias_global.is_some() || alias_components.contains_key(&declaration)
                            {
                                return Err(StoreError::new("orphan C++ alias target columns"));
                            }
                            None
                        }
                        Some(0) => {
                            if alias_global.is_some() || alias_components.contains_key(&declaration)
                            {
                                return Err(StoreError::new(
                                    "builtin C++ alias has named target data",
                                ));
                            }
                            Some(CppStructuredAliasTarget::Builtin)
                        }
                        Some(1) => Some(CppStructuredAliasTarget::Named {
                            components: alias_components.remove(&declaration).unwrap_or_default(),
                            global: strict_bool(
                                required(alias_global, "named alias global flag")?,
                                "C++ alias global",
                            )?,
                            arguments: alias_arguments_present.then(|| {
                                template_arguments
                                    .remove(&(declaration, 1))
                                    .unwrap_or_default()
                            }),
                        }),
                        Some(value) => {
                            return Err(StoreError::new(format!("invalid C++ alias kind {value}")));
                        }
                    };
                    let class_strength = match row.get::<_, i64>(3)? {
                        0 => CppClassDeclarationStrength::Unknown,
                        1 => CppClassDeclarationStrength::Full,
                        2 => CppClassDeclarationStrength::Forward,
                        value => {
                            return Err(StoreError::new(format!(
                                "invalid C++ class strength {value}"
                            )));
                        }
                    };
                    let enum_kind = match row.get::<_, i64>(4)? {
                        0 => CppEnumOwnerKind::NonEnum,
                        1 => CppEnumOwnerKind::Scoped,
                        2 => CppEnumOwnerKind::Unscoped,
                        value => {
                            return Err(StoreError::new(format!("invalid C++ enum kind {value}")));
                        }
                    };
                    let field_type = field_text.map(|type_text| CppDeclaredFieldTypeFact {
                        type_text,
                        indirection: field_indirection
                            .expect("field type indirection checked above"),
                        binds_indirectly: field_binds_indirectly
                            .expect("field type indirect binding checked above"),
                        template_arguments: field_arguments_present.then(|| {
                            template_arguments
                                .remove(&(declaration, 0))
                                .unwrap_or_default()
                        }),
                    });
                    let member_usings_for_declaration =
                        member_usings.remove(&declaration).unwrap_or_default();
                    let bases_for_declaration = bases.remove(&declaration).unwrap_or_default();
                    let callable_shapes_present =
                        strict_bool(row.get(14)?, "C++ callable shapes presence")?;
                    let callable_comparable_shapes = if callable_shapes_present {
                        let shape_rows = callable_shapes.remove(&declaration).unwrap_or_default();
                        let mut shapes = Vec::with_capacity(shape_rows.len());
                        for (kind, parameter_id) in shape_rows {
                            let shape = match kind {
                                0 => {
                                    let parameter_id =
                                        required(parameter_id, "C++ comparable parameter")?;
                                    let root = comparable_parameters
                                        .remove(&parameter_id)
                                        .ok_or_else(|| {
                                            StoreError::new(
                                                "C++ callable shape parameter is missing",
                                            )
                                        })?;
                                    CppComparableSlot::Shape(build_comparable_parameter(
                                        parameter_id,
                                        root,
                                        &mut comparable_nodes,
                                        &mut comparable_names,
                                        &mut comparable_arguments,
                                    )?)
                                }
                                1 => CppComparableSlot::Ellipsis,
                                2 => CppComparableSlot::Unstructured,
                                value => {
                                    return Err(StoreError::new(format!(
                                        "invalid C++ callable shape {value}"
                                    )));
                                }
                            };
                            shapes.push(shape);
                        }
                        Some(shapes)
                    } else {
                        if callable_shapes.remove(&declaration).is_some() {
                            return Err(StoreError::new(
                                "C++ callable shapes are present unexpectedly",
                            ));
                        }
                        None
                    };
                    facts.declarations.push(CppDeclarationSourceFact {
                        declaration: SourceDeclarationId::new(declaration),
                        occurrence_role: match row.get::<_, i64>(1)? {
                            0 => CppOccurrenceRole::DeclarationOnly,
                            1 => CppOccurrenceRole::Definition,
                            2 => CppOccurrenceRole::Both,
                            3 => CppOccurrenceRole::Unknown,
                            value => {
                                return Err(StoreError::new(format!(
                                    "invalid C++ occurrence role {value}"
                                )));
                            }
                        },
                        conditional_family: row
                            .get::<_, Option<u32>>(2)?
                            .map(SourceOccurrenceId::new),
                        class_strength,
                        enum_kind,
                        field_type,
                        alias_target,
                        alias_target_text,
                        adds_indirection: strict_bool(row.get(11)?, "C++ alias indirection")?,
                        names_function_type: strict_bool(row.get(12)?, "C++ function type")?,
                        written_owner: paths.remove(&(declaration, 0)).unwrap_or_default(),
                        lexical_path: paths.remove(&(declaration, 1)).unwrap_or_default(),
                        dependency_type_names: paths.remove(&(declaration, 2)).unwrap_or_default(),
                        trailing_qualifiers: row.get(13)?,
                        member_usings: member_usings_for_declaration
                            .into_iter()
                            .map(|(member, scope)| CppMemberUsingFact { member, scope })
                            .collect(),
                        bases: bases_for_declaration
                            .into_iter()
                            .map(|(is_virtual, absolute, components)| CppBaseSpecifierFact {
                                components,
                                is_virtual,
                                absolute,
                            })
                            .collect(),
                        callable_comparable_shapes,
                        callable_identity_suffix: row.get(15)?,
                        callable_is_constructor: strict_bool(
                            row.get(16)?,
                            "C++ constructor callable",
                        )?,
                        callable_is_deduction_guide: strict_bool(
                            row.get(17)?,
                            "C++ deduction guide callable",
                        )?,
                        callable_is_template: strict_bool(row.get(18)?, "C++ template callable")?,
                        ..CppDeclarationSourceFact::new(SourceDeclarationId::new(declaration))
                    });
                }
            );
            if !paths.is_empty()
                || !alias_components.is_empty()
                || !member_usings.is_empty()
                || !bases.is_empty()
                || !callable_shapes.is_empty()
                || !comparable_parameters.is_empty()
                || !comparable_nodes.is_empty()
                || !comparable_names.is_empty()
                || !comparable_arguments.is_empty()
                || !template_arguments.is_empty()
            {
                return Err(StoreError::new("orphan C++ declaration source rows"));
            }
            if super::source_publication_context::read(tx, blob_id, &mut facts, keep_going)?
                .is_none()
            {
                return Ok(None);
            }
            if !facts.valid_links(&source)
                || super::source_publication::cost(&facts) != (expected_rows, expected_bytes)
            {
                return Err(StoreError::new(format!(
                    "invalid or incomplete C++ source publication: {facts:?}"
                )));
            }
            let Some(units) =
                read_source_unit_map(tx, &oid.to_string(), lang, adapter, file, keep_going)?
            else {
                return Ok(None);
            };
            let mut declaration_units: HashMap<_, Vec<CodeUnit>> = HashMap::default();
            let mut bridge_count = 0usize;
            read_rows!(SOURCE_DECLARATION_UNITS_SQL, row, {
                let declaration = SourceDeclarationId::new(row.get(0)?);
                let key: i64 = row.get(1)?;
                let unit = required(units.get(&key), "declaration unit")?;
                if declaration.index() >= source.declaration_count() {
                    return Err(StoreError::new("C++ unit bridge has no declaration"));
                }
                declaration_units
                    .entry(declaration)
                    .or_default()
                    .push(unit.clone());
                bridge_count += 1;
            });
            if bridge_count != expected_bridges {
                return Err(StoreError::new(format!(
                    "incomplete C++ declaration bridges: {declaration_units:?}"
                )));
            }
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(CppFileSourceFacts::new(
                source,
                facts,
                declaration_units,
            )))
        })
    }
}

type DeclarationTemplateArguments = HashMap<(u32, i64), Vec<CppTemplateExpression>>;

fn read_template_arguments(
    tx: &rusqlite::Transaction<'_>,
    blob_id: i64,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<DeclarationTemplateArguments>> {
    let mut expressions: Vec<(i64, u32, i64, usize, String, i64)> = Vec::new();
    let mut statement = tx.prepare_cached(
        "SELECT expression_id, declaration_id, owner_kind, argument_ordinal, text, root_term_id
         FROM source_cpp_template_expressions
         WHERE blob_id = ?1 ORDER BY expression_id",
    )?;
    let mut query = statement.query([blob_id])?;
    while let Some(row) = query.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let id: i64 = row.get(0)?;
        if id != i64::try_from(expressions.len()).expect("C++ expression count fits i64") {
            return Err(StoreError::new("non-dense C++ template expressions"));
        }
        expressions.push((
            id,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ));
    }
    drop(query);
    drop(statement);
    let mut by_expression: HashMap<i64, Vec<TemplateTermRow>> = HashMap::default();
    let mut statement = tx.prepare_cached(
        "SELECT term_id, expression_id, parent_term_id, ordinal, kind, text, atom_kind
         FROM source_cpp_template_terms WHERE blob_id = ?1 ORDER BY term_id",
    )?;
    let mut query = statement.query([blob_id])?;
    let mut expected_term_id = 0i64;
    while let Some(row) = query.next()? {
        if !keep_going() {
            return Ok(None);
        }
        let id: i64 = row.get(0)?;
        if id != expected_term_id {
            return Err(StoreError::new("non-dense C++ template terms"));
        }
        expected_term_id += 1;
        by_expression
            .entry(row.get(1)?)
            .or_default()
            .push(TemplateTermRow {
                id,
                expression: row.get(1)?,
                parent: row.get(2)?,
                ordinal: row.get(3)?,
                kind: row.get(4)?,
                text: row.get(5)?,
                atom_kind: row.get(6)?,
            });
    }
    drop(query);
    drop(statement);

    let mut result = DeclarationTemplateArguments::default();
    for (expression_id, declaration, owner_kind, argument_ordinal, text, root_term) in expressions {
        let rows = by_expression.remove(&expression_id).unwrap_or_default();
        if rows.is_empty() {
            return Err(StoreError::new("C++ template expression has no root term"));
        }
        let term = build_template_term(rows, root_term)?;
        let arguments = result.entry((declaration, owner_kind)).or_default();
        if argument_ordinal != arguments.len() {
            return Err(StoreError::new("non-dense C++ template argument ordinals"));
        }
        arguments.push(CppTemplateExpression { text, term });
    }
    if !by_expression.is_empty() {
        return Err(StoreError::new("orphan C++ template terms"));
    }
    for values in result.values() {
        // Argument ordinals are checked while reading the rows below; this
        // loop only keeps the map's values owned by the returned facts.
        if values.is_empty() {
            return Err(StoreError::new("empty C++ template argument list"));
        }
    }
    Ok(Some(result))
}

struct ComparableNodeRow {
    kind: i64,
    inner: Option<u32>,
    base: Option<u32>,
    primitive: Option<i64>,
    konst: Option<i64>,
    volatil: Option<i64>,
    absolute: Option<i64>,
}

fn build_comparable_parameter(
    parameter_id: i64,
    root: i64,
    nodes: &mut HashMap<i64, Vec<ComparableNodeRow>>,
    names: &mut HashMap<(i64, i64, i64), Vec<String>>,
    arguments: &mut HashMap<(i64, i64), Vec<u32>>,
) -> Result<CppComparableParameter> {
    let rows = nodes
        .remove(&parameter_id)
        .ok_or_else(|| StoreError::new("C++ comparable parameter has no nodes"))?;
    let root = usize::try_from(root)
        .map_err(|_| StoreError::new("negative C++ comparable parameter root"))?;
    let mut result = Vec::with_capacity(rows.len());
    for (node_id, row) in rows.into_iter().enumerate() {
        let node_id = i64::try_from(node_id).expect("C++ node id fits i64");
        let node = match row.kind {
            0 => {
                if row.inner.is_some()
                    || row.base.is_some()
                    || row.primitive.is_none()
                    || row.konst.is_none()
                    || row.volatil.is_none()
                    || row.absolute.is_none()
                    || arguments.contains_key(&(parameter_id, node_id))
                {
                    return Err(StoreError::new("invalid C++ comparable named node"));
                }
                let path = names
                    .remove(&(parameter_id, node_id, 0))
                    .unwrap_or_default();
                let lexical_scope = names
                    .remove(&(parameter_id, node_id, 1))
                    .unwrap_or_default();
                let name = StructuredTypeName::new(
                    path,
                    lexical_scope,
                    strict_bool(row.absolute.expect("checked above"), "C++ named absolute")?,
                )
                .ok_or_else(|| StoreError::new("invalid C++ comparable structured name"))?;
                CppComparableNode::Named {
                    name,
                    primitive: strict_bool(
                        row.primitive.expect("checked above"),
                        "C++ primitive name",
                    )?,
                    konst: strict_bool(row.konst.expect("checked above"), "C++ named const")?,
                    volatil: strict_bool(
                        row.volatil.expect("checked above"),
                        "C++ named volatile",
                    )?,
                }
            }
            1 => CppComparableNode::Pointer {
                inner: usize::try_from(required(row.inner, "C++ pointer inner")?)
                    .map_err(|_| StoreError::new("negative C++ pointer inner"))?,
                konst: strict_bool(
                    required(row.konst, "C++ pointer const")?,
                    "C++ pointer const",
                )?,
                volatil: strict_bool(
                    required(row.volatil, "C++ pointer volatile")?,
                    "C++ pointer volatile",
                )?,
            },
            2 => CppComparableNode::Reference {
                inner: usize::try_from(required(row.inner, "C++ reference inner")?)
                    .map_err(|_| StoreError::new("negative C++ reference inner"))?,
            },
            3 => CppComparableNode::Array {
                inner: usize::try_from(required(row.inner, "C++ array inner")?)
                    .map_err(|_| StoreError::new("negative C++ array inner"))?,
            },
            4 => {
                if row.inner.is_some() || row.base.is_none() {
                    return Err(StoreError::new("invalid C++ comparable generic node"));
                }
                let children = arguments
                    .remove(&(parameter_id, node_id))
                    .unwrap_or_default();
                CppComparableNode::Generic {
                    base: usize::try_from(row.base.expect("checked above"))
                        .map_err(|_| StoreError::new("negative C++ generic base"))?,
                    arguments: children
                        .into_iter()
                        .map(|child| {
                            usize::try_from(child)
                                .map_err(|_| StoreError::new("negative C++ generic argument"))
                        })
                        .collect::<Result<Vec<_>>>()?,
                }
            }
            value => {
                return Err(StoreError::new(format!(
                    "invalid C++ comparable node kind {value}"
                )));
            }
        };
        result.push(node);
    }
    Ok(CppComparableParameter::new(result, root))
}
