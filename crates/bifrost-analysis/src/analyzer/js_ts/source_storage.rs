//! Generation-selected JavaScript/TypeScript declaration facts and imports.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::js_ts_facts::{
    JS_TS_SOURCE_FACTS_VERSION, JsTsComponentPropsFact, JsTsDeclarationBindingFact,
    JsTsDeclarationFact, JsTsExportFact, JsTsExportKind, JsTsImportBindingFact,
    JsTsPropertyReceiverFact, JsTsReceiverBinding, JsTsSourceFacts, JsTsSourceTypeId, JsTsTypeFact,
    JsTsTypeShape,
};
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclarationId, SourceImportId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_js_ts::source_facts::JsTsFileSourceFacts;
use git2::Oid;
use rusqlite::{OptionalExtension, params};

use crate::analyzer::LanguageAdapter;
use crate::analyzer::store::source_facts::{
    SOURCE_DECLARATION_UNITS_SQL, SOURCE_FACTS_VERSION, read_source_identity_rows,
    read_source_imports, strict_bool,
};
use crate::analyzer::store::{
    AnalyzerStore, GenerationId, Result, StoreError, read_source_unit_map,
};

pub(in crate::analyzer) const JS_TS_SOURCE_HEADER_SQL: &str =
    "SELECT blob.id, marker.logical_rows, marker.payload_bytes,
            marker.binding_count, marker.export_count, marker.declaration_count,
            marker.type_count, marker.type_name_count, marker.type_child_count,
            marker.type_member_count, marker.type_parameter_count,
            marker.declaration_parameter_count, marker.component_member_count,
            marker.declaration_binding_count, marker.property_receiver_count,
            marker.property_receiver_member_count, marker.file_is_external_module,
            marker.file_is_esm,
            source.occurrence_count, source.declaration_count,
            source.declaration_unit_count
       FROM blobs AS blob
       JOIN source_js_ts_manifests AS marker ON marker.blob_id = blob.id
       JOIN source_fact_manifests AS source ON source.blob_id = blob.id
       JOIN blob_meta AS meta ON meta.blob_id = blob.id
       JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
      WHERE blob.blob_oid = ?1 AND blob.lang = ?2 AND blob.generation = ?3
        AND marker.facts_version = ?4 AND source.facts_version = ?5
        AND meta.js_ts_source_version = ?4
        AND source.publication_state = 'complete' AND meta.is_complete = 1
        AND ready.available = 1";

fn required<T>(value: Option<T>, label: &str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(format!("JS/TS source facts are missing {label}")))
}

fn source_import(value: i64, label: &str) -> Result<SourceImportId> {
    let value = u32::try_from(value)
        .map_err(|_| StoreError::new(format!("invalid {label} source import id {value}")))?;
    Ok(SourceImportId::new(value))
}

fn source_type(value: Option<i64>, label: &str) -> Result<Option<JsTsSourceTypeId>> {
    value
        .map(|value| {
            let value = u32::try_from(value)
                .map_err(|_| StoreError::new(format!("invalid {label} source type id {value}")))?;
            Ok(JsTsSourceTypeId::new(value))
        })
        .transpose()
}

fn type_row_id(value: i64, label: &str) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| StoreError::new(format!("invalid {label} JS/TS type id {value}")))
}

fn prior_type(type_id: JsTsSourceTypeId, current: usize, label: &str) -> Result<JsTsSourceTypeId> {
    if type_id.index() >= current {
        return Err(StoreError::new(format!(
            "JS/TS {label} type link is not postorder: {type_id:?} >= {current}"
        )));
    }
    Ok(type_id)
}

fn decode_import_kind(value: i64) -> Result<ImportKind> {
    match value {
        0 => Ok(ImportKind::Default),
        1 => Ok(ImportKind::Named),
        2 => Ok(ImportKind::Namespace),
        3 => Ok(ImportKind::CommonJsRequire),
        4 => Ok(ImportKind::Glob),
        _ => Err(StoreError::new(format!(
            "invalid JS/TS import kind {value}"
        ))),
    }
}

fn decode_receiver_binding(value: i64) -> Result<JsTsReceiverBinding> {
    match value {
        0 => Ok(JsTsReceiverBinding::Unbound),
        1 => Ok(JsTsReceiverBinding::Program),
        2 => Ok(JsTsReceiverBinding::Local),
        _ => Err(StoreError::new(format!(
            "invalid JS/TS receiver binding {value}"
        ))),
    }
}

impl AnalyzerStore {
    pub(crate) fn js_ts_source_facts<A: LanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<JsTsFileSourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }
        let language = adapter.storage_language_key_for_file(file);
        self.read_source_transaction(language, generation, |tx| {
            let header = tx
                .query_row(
                    JS_TS_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        language,
                        generation.get(),
                        JS_TS_SOURCE_FACTS_VERSION,
                        SOURCE_FACTS_VERSION,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, usize>(1)?,
                            row.get::<_, usize>(2)?,
                            row.get::<_, usize>(3)?,
                            row.get::<_, usize>(4)?,
                            row.get::<_, usize>(5)?,
                            row.get::<_, usize>(6)?,
                            row.get::<_, usize>(7)?,
                            row.get::<_, usize>(8)?,
                            row.get::<_, usize>(9)?,
                            row.get::<_, usize>(10)?,
                            row.get::<_, usize>(11)?,
                            row.get::<_, usize>(12)?,
                            row.get::<_, usize>(13)?,
                            row.get::<_, usize>(14)?,
                            row.get::<_, usize>(15)?,
                            row.get::<_, i64>(16)?,
                            row.get::<_, i64>(17)?,
                            row.get::<_, usize>(18)?,
                            row.get::<_, usize>(19)?,
                            row.get::<_, usize>(20)?,
                        ))
                    },
                )
                .optional()?;
            let (
                expected_rows,
                expected_bytes,
                expected_bindings,
                expected_exports,
                expected_declarations,
                expected_types,
                expected_type_names,
                expected_type_children,
                expected_type_members,
                expected_type_parameters,
                expected_declaration_parameters,
                expected_component_members,
                expected_declaration_bindings,
                expected_property_receivers,
                expected_property_receiver_members,
                file_is_external_module,
                file_is_esm,
                expected_occurrences,
                expected_source_declarations,
                expected_bridges,
            ) = header.ok_or_else(|| {
                StoreError::new(format!(
                    "canonical JS/TS source facts unavailable for {file:?} ({oid})"
                ))
            })?;

            let blob_id: i64 = tx.query_row(
                    "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND generation = ?3",
                    params![oid.to_string(), language, generation.get()],
                    |row| row.get(0),
                )?;
            let Some(source) = read_source_identity_rows(
                tx,
                blob_id,
                expected_occurrences,
                expected_source_declarations,
                keep_going,
            )?
            else {
                return Ok(None);
            };
            let Some(imports) = read_source_imports(tx, blob_id, keep_going)? else {
                return Ok(None);
            };

            let mut bindings = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT ordinal, import_id, kind, is_static
                   FROM source_js_ts_bindings
                  WHERE blob_id = ?1 ORDER BY ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let ordinal: usize = row.get(0)?;
                let import = source_import(row.get(1)?, "JS/TS binding")?;
                if ordinal != bindings.len() || import.index() >= imports.len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS binding ordinal/import: {ordinal}/{import:?}"
                    )));
                }
                bindings.push(JsTsImportBindingFact {
                    import,
                    kind: decode_import_kind(row.get(2)?)?,
                    is_static: strict_bool(row.get(3)?, "JS/TS binding static")?,
                });
            }
            drop(rows);
            drop(statement);
            if bindings.len() != expected_bindings {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS bindings for {oid}: {} != {expected_bindings}",
                    bindings.len()
                )));
            }

            let mut exports = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT ordinal, occurrence_id, name, kind, local_name, import_id, is_esm
                   FROM source_js_ts_exports
                  WHERE blob_id = ?1 ORDER BY ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let ordinal: usize = row.get(0)?;
                let occurrence = SourceOccurrenceId::new(row.get(1)?);
                let name: Option<String> = row.get(2)?;
                let kind: i64 = row.get(3)?;
                let local_name: Option<String> = row.get(4)?;
                let import = row
                    .get::<_, Option<i64>>(5)?
                    .map(|value| source_import(value, "JS/TS export"))
                    .transpose()?;
                let is_esm = strict_bool(row.get(6)?, "JS/TS export ESM")?;
                if ordinal != exports.len()
                    || occurrence.index() >= source.occurrence_count()
                    || import.is_some_and(|id| id.index() >= imports.len())
                {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS export row {ordinal}/{occurrence:?}/{import:?}"
                    )));
                }
                let kind = match kind {
                    0 => JsTsExportKind::Local {
                        local_name: required(local_name, "local export name")?,
                    },
                    1 => JsTsExportKind::Default { local_name },
                    2 => JsTsExportKind::ReexportNamed {
                        import: required(import, "named reexport import")?,
                    },
                    3 => JsTsExportKind::ReexportModule {
                        import: required(import, "module reexport import")?,
                    },
                    4 => JsTsExportKind::Star {
                        import: required(import, "star reexport import")?,
                    },
                    _ => return Err(StoreError::new(format!("invalid JS/TS export kind {kind}"))),
                };
                if matches!(kind, JsTsExportKind::Star { .. }) != name.is_none() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS export name for {kind:?}: {name:?}"
                    )));
                }
                exports.push(JsTsExportFact {
                    occurrence,
                    name,
                    kind,
                    is_esm,
                });
            }
            drop(rows);
            drop(statement);
            if exports.len() != expected_exports {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS exports for {oid}: {} != {expected_exports}",
                    exports.len()
                )));
            }

            let mut type_names: Vec<Vec<String>> = (0..expected_types).map(|_| Vec::new()).collect();
            let mut statement = tx.prepare_cached(
                "SELECT type_id, ordinal, name
                   FROM source_js_ts_type_names
                  WHERE blob_id = ?1 ORDER BY type_id, ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            let mut type_name_count = 0;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_id = type_row_id(row.get(0)?, "name")?;
                let ordinal: usize = row
                    .get::<_, i64>(1)?
                    .try_into()
                    .map_err(|_| StoreError::new("invalid JS/TS type name ordinal".to_owned()))?;
                if type_id >= expected_types || ordinal != type_names[type_id].len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS type name row {type_id}/{ordinal}"
                    )));
                }
                type_names[type_id].push(row.get(2)?);
                type_name_count += 1;
            }
            if type_name_count != expected_type_names {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS type names for {oid}: {type_name_count} != {expected_type_names}"
                )));
            }
            drop(rows);
            drop(statement);

            let mut type_children: Vec<Vec<JsTsSourceTypeId>> =
                (0..expected_types).map(|_| Vec::new()).collect();
            let mut statement = tx.prepare_cached(
                "SELECT type_id, ordinal, child_id
                   FROM source_js_ts_type_children
                  WHERE blob_id = ?1 ORDER BY type_id, ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            let mut type_child_count = 0;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_id = type_row_id(row.get(0)?, "child")?;
                let ordinal: usize = row
                    .get::<_, i64>(1)?
                    .try_into()
                    .map_err(|_| StoreError::new("invalid JS/TS type child ordinal".to_owned()))?;
                let child =
                    source_type(Some(row.get(2)?), "JS/TS type child")?.expect("source type id");
                if type_id >= expected_types || ordinal != type_children[type_id].len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS type child row {type_id}/{ordinal}"
                    )));
                }
                type_children[type_id].push(child);
                type_child_count += 1;
            }
            if type_child_count != expected_type_children {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS type children for {oid}: {type_child_count} != {expected_type_children}"
                )));
            }
            drop(rows);
            drop(statement);

            let mut type_members: Vec<Vec<(String, JsTsSourceTypeId)>> =
                (0..expected_types).map(|_| Vec::new()).collect();
            let mut statement = tx.prepare_cached(
                "SELECT type_id, ordinal, name, child_id
                   FROM source_js_ts_type_members
                  WHERE blob_id = ?1 ORDER BY type_id, ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            let mut type_member_count = 0;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_id = type_row_id(row.get(0)?, "member")?;
                let ordinal: usize = row
                    .get::<_, i64>(1)?
                    .try_into()
                    .map_err(|_| StoreError::new("invalid JS/TS type member ordinal".to_owned()))?;
                let child =
                    source_type(Some(row.get(3)?), "JS/TS type member")?.expect("source type id");
                if type_id >= expected_types || ordinal != type_members[type_id].len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS type member row {type_id}/{ordinal}"
                    )));
                }
                type_members[type_id].push((row.get(2)?, child));
                type_member_count += 1;
            }
            if type_member_count != expected_type_members {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS type members for {oid}: {type_member_count} != {expected_type_members}"
                )));
            }
            drop(rows);
            drop(statement);

            let mut type_parameters: Vec<Vec<Option<JsTsSourceTypeId>>> =
                (0..expected_types).map(|_| Vec::new()).collect();
            let mut statement = tx.prepare_cached(
                "SELECT type_id, ordinal, child_id
                   FROM source_js_ts_type_parameters
                  WHERE blob_id = ?1 ORDER BY type_id, ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            let mut type_parameter_count = 0;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_id = type_row_id(row.get(0)?, "parameter")?;
                let ordinal: usize = row
                    .get::<_, i64>(1)?
                    .try_into()
                    .map_err(|_| StoreError::new("invalid JS/TS type parameter ordinal".to_owned()))?;
                let child = source_type(row.get(2)?, "JS/TS type parameter")?;
                if type_id >= expected_types || ordinal != type_parameters[type_id].len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS type parameter row {type_id}/{ordinal}"
                    )));
                }
                type_parameters[type_id].push(child);
                type_parameter_count += 1;
            }
            if type_parameter_count != expected_type_parameters {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS type parameters for {oid}: {type_parameter_count} != {expected_type_parameters}"
                )));
            }
            drop(rows);
            drop(statement);

            let mut types = Vec::with_capacity(expected_types);
            let mut statement = tx.prepare_cached(
                "SELECT type_id, occurrence_id, kind, child_id, result_type_id
                   FROM source_js_ts_types
                  WHERE blob_id = ?1 ORDER BY type_id",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let type_id = type_row_id(row.get(0)?, "type")?;
                let occurrence = SourceOccurrenceId::new(row.get(1)?);
                let kind: i64 = row.get(2)?;
                let child = source_type(row.get(3)?, "JS/TS type child")?;
                let result = source_type(row.get(4)?, "JS/TS type result")?;
                if type_id != types.len()
                    || type_id >= expected_types
                    || occurrence.index() >= source.occurrence_count()
                {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS type row {type_id}/{occurrence:?}"
                    )));
                }
                let child = child
                    .map(|id| prior_type(id, type_id, "base"))
                    .transpose()?;
                let result = result
                    .map(|id| prior_type(id, type_id, "result"))
                    .transpose()?;
                if matches!(kind, 1 | 2 | 5 | 8) != child.is_some() || (kind != 6 && result.is_some()) {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS type scalar links for {type_id}: kind={kind}, child={child:?}, result={result:?}"
                    )));
                }
                let shape =
                    match kind {
                        0 => {
                            if type_names[type_id].is_empty()
                                || !type_children[type_id].is_empty()
                                || !type_members[type_id].is_empty()
                                || !type_parameters[type_id].is_empty()
                                || child.is_some()
                                || result.is_some()
                            {
                                return Err(StoreError::new(format!(
                                    "invalid JS/TS named type rows for {type_id}"
                                )));
                            }
                            JsTsTypeShape::Named(std::mem::take(&mut type_names[type_id]))
                        }
                        1 => JsTsTypeShape::Generic {
                            base: child.ok_or_else(|| {
                                StoreError::new("generic JS/TS type has no base".to_owned())
                            })?,
                            arguments: std::mem::take(&mut type_children[type_id]),
                        },
                        2 => JsTsTypeShape::Wrapped(child.ok_or_else(|| {
                            StoreError::new("wrapped JS/TS type has no child".to_owned())
                        })?),
                        3 => JsTsTypeShape::Union(std::mem::take(&mut type_children[type_id])),
                        4 => JsTsTypeShape::Intersection(std::mem::take(&mut type_children[type_id])),
                        5 => JsTsTypeShape::Query(child.ok_or_else(|| {
                            StoreError::new("query JS/TS type has no child".to_owned())
                        })?),
                        6 => {
                            if !type_names[type_id].is_empty()
                                || !type_children[type_id].is_empty()
                                || !type_members[type_id].is_empty()
                                || child.is_some()
                            {
                                return Err(StoreError::new(format!(
                                    "invalid JS/TS function type rows for {type_id}"
                                )));
                            }
                            JsTsTypeShape::Function {
                                parameters: std::mem::take(&mut type_parameters[type_id]),
                                result,
                            }
                        }
                        7 => {
                            if !type_names[type_id].is_empty()
                                || !type_children[type_id].is_empty()
                                || !type_parameters[type_id].is_empty()
                                || child.is_some()
                                || result.is_some()
                            {
                                return Err(StoreError::new(format!(
                                    "invalid JS/TS object type rows for {type_id}"
                                )));
                            }
                            JsTsTypeShape::Object(std::mem::take(&mut type_members[type_id]))
                        }
                        8 => JsTsTypeShape::Array(child.ok_or_else(|| {
                            StoreError::new("array JS/TS type has no child".to_owned())
                        })?),
                        9 => JsTsTypeShape::Tuple(std::mem::take(&mut type_children[type_id])),
                        10 => JsTsTypeShape::NoReceiver,
                        11 => JsTsTypeShape::Unknown,
                        _ => return Err(StoreError::new(format!("invalid JS/TS type kind {kind}"))),
                    };
                if !type_names[type_id].is_empty()
                    || !type_children[type_id].is_empty()
                    || !type_members[type_id].is_empty()
                    || !type_parameters[type_id].is_empty()
                {
                    return Err(StoreError::new(format!(
                        "orphan JS/TS type rows for {type_id}"
                    )));
                }
                types.push(JsTsTypeFact { occurrence, shape });
            }
            if types.len() != expected_types {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS types for {oid}: {} != {expected_types}",
                    types.len()
                )));
            }
            drop(rows);
            drop(statement);

            let mut component_members: HashMap<u32, Vec<String>> = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, ordinal, name
                   FROM source_js_ts_component_members
                  WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            let mut component_member_count = 0;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration_id: u32 = row.get::<_, i64>(0)?.try_into().map_err(|_| {
                    StoreError::new("invalid JS/TS component declaration id".to_owned())
                })?;
                let ordinal: usize = row.get::<_, i64>(1)?.try_into().map_err(|_| {
                    StoreError::new("invalid JS/TS component member ordinal".to_owned())
                })?;
                let members = component_members.entry(declaration_id).or_default();
                if ordinal != members.len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS component member row {declaration_id}/{ordinal}"
                    )));
                }
                members.push(row.get(2)?);
                component_member_count += 1;
            }
            if component_member_count != expected_component_members {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS component members for {oid}: {component_member_count} != {expected_component_members}"
                )));
            }
            drop(rows);
            drop(statement);

            let mut declarations = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT ordinal, declaration_id, is_interface, is_global, alias_type_id,
                        member_type_id, declared_type_id, return_type_id,
                        component_kind, component_type_id, component_import_id,
                        component_name, is_callable
                   FROM source_js_ts_declarations
                  WHERE blob_id = ?1 ORDER BY ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let ordinal: usize = row.get(0)?;
                let declaration = SourceDeclarationId::new(row.get(1)?);
                if ordinal != declarations.len() || declaration.index() >= source.declaration_count() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS declaration row {ordinal}/{declaration:?}"
                    )));
                }
                let component_kind: Option<i64> = row.get(8)?;
                let component_type = source_type(row.get(9)?, "JS/TS component")?;
                let component_import = row
                    .get::<_, Option<i64>>(10)?
                    .map(|value| source_import(value, "JS/TS component"))
                    .transpose()?;
                let component_name: Option<String> = row.get(11)?;
                let component_props = match component_kind {
                    None => {
                        if component_type.is_some()
                            || component_import.is_some()
                            || component_name.is_some()
                        {
                            return Err(StoreError::new(
                                "invalid empty JS/TS component props".to_owned(),
                            ));
                        }
                        None
                    }
                    Some(0) => Some(JsTsComponentPropsFact::Type(required(
                        component_type,
                        "component type",
                    )?)),
                    Some(1) => Some(JsTsComponentPropsFact::Named(required(
                        component_name,
                        "component name",
                    )?)),
                    Some(2) => Some(JsTsComponentPropsFact::Module(required(
                        component_import,
                        "component module",
                    )?)),
                    Some(3) => Some(JsTsComponentPropsFact::TypeMember {
                        owner_type: required(component_type, "component member owner")?,
                        members: component_members
                            .remove(&declaration.get())
                            .ok_or_else(|| {
                                StoreError::new("missing JS/TS component member path".to_owned())
                            })?,
                    }),
                    Some(kind) => {
                        return Err(StoreError::new(format!(
                            "invalid JS/TS component kind {kind}"
                        )));
                    }
                };
                declarations.push(JsTsDeclarationFact {
                    declaration,
                    is_interface: strict_bool(row.get(2)?, "JS/TS interface")?,
                    is_global: strict_bool(row.get(3)?, "JS/TS global")?,
                    alias_type: source_type(row.get(4)?, "JS/TS alias")?,
                    member_type: source_type(row.get(5)?, "JS/TS member")?,
                    declared_type: source_type(row.get(6)?, "JS/TS declared")?,
                    parameters: strict_bool(row.get(12)?, "JS/TS callable")?.then(Vec::new),
                    return_type: source_type(row.get(7)?, "JS/TS return")?,
                    component_props,
                });
            }
            drop(rows);
            drop(statement);
            if declarations.len() != expected_declarations {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS declarations for {oid}: {} != {expected_declarations}",
                    declarations.len()
                )));
            }
            if !component_members.is_empty() {
                return Err(StoreError::new(
                    "orphan JS/TS component member rows".to_owned(),
                ));
            }

            let declaration_ids: HashMap<u32, bool> = declarations
                .iter()
                .map(|declaration| (declaration.declaration.get(), true))
                .collect();
            let mut declaration_parameters: HashMap<u32, Vec<Option<JsTsSourceTypeId>>> =
                HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT declaration_id, ordinal, type_id
                   FROM source_js_ts_declaration_parameters
                  WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            let mut declaration_parameter_count = 0;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration_id: u32 = row.get::<_, i64>(0)?.try_into().map_err(|_| {
                    StoreError::new("invalid JS/TS parameter declaration id".to_owned())
                })?;
                let ordinal: usize = row.get::<_, i64>(1)?.try_into().map_err(|_| {
                    StoreError::new("invalid JS/TS declaration parameter ordinal".to_owned())
                })?;
                let type_id = source_type(row.get(2)?, "JS/TS declaration parameter")?;
                if !declaration_ids.contains_key(&declaration_id) {
                    return Err(StoreError::new(format!(
                        "JS/TS declaration parameters reference unknown declaration {declaration_id}"
                    )));
                }
                let parameters = declaration_parameters.entry(declaration_id).or_default();
                if ordinal != parameters.len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS declaration parameter row {declaration_id}/{ordinal}"
                    )));
                }
                parameters.push(type_id);
                declaration_parameter_count += 1;
            }
            if declaration_parameter_count != expected_declaration_parameters {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS declaration parameters for {oid}: {declaration_parameter_count} != {expected_declaration_parameters}"
                )));
            }
            for declaration in &mut declarations {
                if let Some(parameters) = declaration_parameters.remove(&declaration.declaration.get())
                {
                    if declaration.parameters.is_none() {
                        return Err(StoreError::new(format!(
                            "noncallable JS/TS declaration has parameters: {:?}",
                            declaration.declaration
                        )));
                    }
                    declaration.parameters = Some(parameters);
                }
                for type_id in declaration
                    .alias_type
                    .into_iter()
                    .chain(declaration.member_type)
                    .chain(declaration.declared_type)
                    .chain(declaration.return_type)
                    .chain(
                        declaration
                            .parameters
                            .iter()
                            .flat_map(|types| types.iter().flatten().copied()),
                    )
                {
                    if type_id.index() >= types.len() {
                        return Err(StoreError::new(format!(
                            "JS/TS declaration type link is outside arena: {type_id:?}"
                        )));
                    }
                }
                if let Some(props) = &declaration.component_props {
                    match props {
                        JsTsComponentPropsFact::Type(type_id)
                        | JsTsComponentPropsFact::TypeMember {
                            owner_type: type_id,
                            ..
                        } => {
                            if type_id.index() >= types.len() {
                                return Err(StoreError::new(format!(
                                    "JS/TS component type link is outside arena: {type_id:?}"
                                )));
                            }
                        }
                        JsTsComponentPropsFact::Module(import) => {
                            if import.index() >= imports.len() {
                                return Err(StoreError::new(format!(
                                    "JS/TS component import link is outside imports: {import:?}"
                                )));
                            }
                        }
                        JsTsComponentPropsFact::Named(_) => {}
                    }
                }
            }
            if !declaration_parameters.is_empty() {
                return Err(StoreError::new(
                    "orphan JS/TS declaration parameter rows".to_owned(),
                ));
            }
            drop(rows);
            drop(statement);

            let mut declaration_bindings = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT ordinal, declaration_id, binder_id, name, is_program
                   FROM source_js_ts_declaration_bindings
                  WHERE blob_id = ?1 ORDER BY ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let ordinal: usize = row.get(0)?;
                let declaration = SourceDeclarationId::new(row.get(1)?);
                let binder = SourceOccurrenceId::new(row.get(2)?);
                if ordinal != declaration_bindings.len()
                    || declaration.index() >= source.declaration_count()
                    || binder.index() >= source.occurrence_count()
                {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS declaration binding row {ordinal}/{declaration:?}"
                    )));
                }
                declaration_bindings.push(JsTsDeclarationBindingFact {
                    declaration,
                    binder,
                    name: row.get(3)?,
                    is_program: strict_bool(row.get(4)?, "JS/TS program binding")?,
                });
            }
            if declaration_bindings.len() != expected_declaration_bindings {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS declaration bindings for {oid}: {} != {expected_declaration_bindings}",
                    declaration_bindings.len()
                )));
            }
            drop(rows);
            drop(statement);

            let mut receiver_members: HashMap<u32, Vec<String>> = HashMap::default();
            let mut statement = tx.prepare_cached(
                "SELECT receiver_ordinal, ordinal, name
                   FROM source_js_ts_property_receiver_members
                  WHERE blob_id = ?1 ORDER BY receiver_ordinal, ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            let mut property_receiver_member_count = 0;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let receiver_ordinal: u32 = row
                    .get::<_, i64>(0)?
                    .try_into()
                    .map_err(|_| StoreError::new("invalid JS/TS receiver ordinal".to_owned()))?;
                let ordinal: usize = row
                    .get::<_, i64>(1)?
                    .try_into()
                    .map_err(|_| StoreError::new("invalid JS/TS receiver member ordinal".to_owned()))?;
                let members = receiver_members.entry(receiver_ordinal).or_default();
                if ordinal != members.len() {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS receiver member row {receiver_ordinal}/{ordinal}"
                    )));
                }
                members.push(row.get(2)?);
                property_receiver_member_count += 1;
            }
            if property_receiver_member_count != expected_property_receiver_members {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS receiver members for {oid}: {property_receiver_member_count} != {expected_property_receiver_members}"
                )));
            }
            drop(rows);
            drop(statement);

            let mut property_receivers = Vec::new();
            let mut statement = tx.prepare_cached(
                "SELECT ordinal, declaration_id, property_id, receiver_root, binding
                   FROM source_js_ts_property_receivers
                  WHERE blob_id = ?1 ORDER BY ordinal",
            )?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let ordinal: u32 = row.get::<_, i64>(0)?.try_into().map_err(|_| {
                    StoreError::new("invalid JS/TS property receiver ordinal".to_owned())
                })?;
                let declaration = SourceDeclarationId::new(row.get(1)?);
                let property = SourceOccurrenceId::new(row.get(2)?);
                if ordinal as usize != property_receivers.len()
                    || declaration.index() >= source.declaration_count()
                    || property.index() >= source.occurrence_count()
                {
                    return Err(StoreError::new(format!(
                        "invalid JS/TS property receiver row {ordinal}/{declaration:?}/{property:?}"
                    )));
                }
                property_receivers.push(JsTsPropertyReceiverFact {
                    declaration,
                    property,
                    receiver_root: row.get(3)?,
                    members: receiver_members.remove(&ordinal).unwrap_or_default(),
                    binding: decode_receiver_binding(row.get(4)?)?,
                });
            }
            if property_receivers.len() != expected_property_receivers {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS property receivers for {oid}: {} != {expected_property_receivers}",
                    property_receivers.len()
                )));
            }
            if !receiver_members.is_empty() {
                return Err(StoreError::new(
                    "orphan JS/TS property receiver members".to_owned(),
                ));
            }
            drop(rows);
            drop(statement);

            let facts = JsTsSourceFacts {
                file_is_external_module: strict_bool(file_is_external_module, "JS/TS external module")?,
                file_is_esm: strict_bool(file_is_esm, "JS/TS ESM")?,
                bindings,
                exports,
                declarations,
                types,
                declaration_bindings,
                property_receivers,
            };
            if super::source_publication::cost(&facts) != (expected_rows, expected_bytes) {
                return Err(StoreError::new(format!(
                    "invalid JS/TS source publication for {oid}: {facts:?}"
                )));
            }

            let Some(units) = read_source_unit_map(
                tx,
                &oid.to_string(),
                language,
                adapter,
                file,
                keep_going,
            )?
            else {
                return Ok(None);
            };
            let mut declaration_units: HashMap<_, Vec<_>> = HashMap::default();
            let mut statement = tx.prepare_cached(SOURCE_DECLARATION_UNITS_SQL)?;
            let mut rows = statement.query([blob_id])?;
            let mut bridge_count = 0usize;
            while let Some(row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                let declaration = SourceDeclarationId::new(row.get(0)?);
                let key: i64 = row.get(1)?;
                let unit = units.get(&key).ok_or_else(|| {
                    StoreError::new(format!("JS/TS declaration bridge has no unit {key}"))
                })?;
                declaration_units
                    .entry(declaration)
                    .or_default()
                    .push(unit.clone());
                bridge_count += 1;
            }
            if bridge_count != expected_bridges {
                return Err(StoreError::new(format!(
                    "incomplete JS/TS declaration bridges for {oid}: {bridge_count} != {expected_bridges}"
                )));
            }
            drop(rows);
            drop(statement);
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(JsTsFileSourceFacts {
                source,
                imports,
                facts,
                declaration_units,
            }))
        })
    }
}
