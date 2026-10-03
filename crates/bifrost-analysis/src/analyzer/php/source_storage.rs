//! One generation-checked snapshot of PHP source facts and mounted units.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::php_facts::*;
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclarationId, SourceImportId, SourceOccurrenceId,
};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_php::source_facts::PhpFileSourceFacts;
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

pub(in crate::analyzer) const PHP_SOURCE_HEADER_SQL: &str =
    "SELECT blob.id, marker.logical_rows, marker.payload_bytes,
            source.occurrence_count, source.declaration_count, source.declaration_unit_count
     FROM blobs AS blob
     JOIN source_php_manifests AS marker ON marker.blob_id = blob.id
     JOIN source_fact_manifests AS source ON source.blob_id = blob.id
     JOIN blob_meta AS meta ON meta.blob_id = blob.id
     JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
     WHERE blob.blob_oid = ?1 AND blob.lang = 'php' AND blob.generation = ?2
       AND marker.facts_version = ?3 AND source.facts_version = ?4
       AND source.publication_state = 'complete' AND meta.is_complete = 1 AND ready.available = 1";

fn required<T>(value: Option<T>, label: &str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(format!("PHP source facts are missing {label}")))
}

fn decode_alias_kind(value: i64) -> Result<PhpAliasKind> {
    Ok(match value {
        0 => PhpAliasKind::Type,
        1 => PhpAliasKind::Function,
        2 => PhpAliasKind::Constant,
        _ => return Err(StoreError::new(format!("invalid PHP alias kind {value}"))),
    })
}

fn decode_declaration_kind(value: i64) -> Result<PhpDeclarationKind> {
    Ok(match value {
        0 => PhpDeclarationKind::Class,
        1 => PhpDeclarationKind::Interface,
        2 => PhpDeclarationKind::Trait,
        3 => PhpDeclarationKind::Enum,
        4 => PhpDeclarationKind::Function,
        5 => PhpDeclarationKind::Method,
        6 => PhpDeclarationKind::Property,
        7 => PhpDeclarationKind::Constant,
        8 => PhpDeclarationKind::EnumCase,
        9 => PhpDeclarationKind::PromotedProperty,
        _ => {
            return Err(StoreError::new(format!(
                "invalid PHP declaration kind {value}"
            )));
        }
    })
}

fn decode_type(kind: i64, arms: Option<Vec<String>>, label: &str) -> Result<PhpDeclaredSourceType> {
    Ok(match kind {
        0 => {
            if arms.is_some() {
                return Err(StoreError::new(format!(
                    "{label} unknown type has nominal arms"
                )));
            }
            PhpDeclaredSourceType::Unknown
        }
        1 => {
            let arms = required(arms, "nominal arms")?;
            if arms.is_empty() {
                return Err(StoreError::new(format!("{label} nominal type has no arms")));
            }
            PhpDeclaredSourceType::Nominal(arms)
        }
        2 => {
            if arms.is_some() {
                return Err(StoreError::new(format!(
                    "{label} object type has nominal arms"
                )));
            }
            PhpDeclaredSourceType::DynamicObject
        }
        3 => {
            if arms.is_some() {
                return Err(StoreError::new(format!(
                    "{label} mixed type has nominal arms"
                )));
            }
            PhpDeclaredSourceType::DynamicMixed
        }
        4 => {
            if arms.is_some() {
                return Err(StoreError::new(format!(
                    "{label} self type has nominal arms"
                )));
            }
            PhpDeclaredSourceType::SelfType
        }
        5 => {
            if arms.is_some() {
                return Err(StoreError::new(format!(
                    "{label} static type has nominal arms"
                )));
            }
            PhpDeclaredSourceType::StaticType
        }
        6 => {
            if arms.is_some() {
                return Err(StoreError::new(format!(
                    "{label} parent type has nominal arms"
                )));
            }
            PhpDeclaredSourceType::ParentType
        }
        _ => {
            return Err(StoreError::new(format!(
                "invalid PHP {label} type kind {kind}"
            )));
        }
    })
}

fn decode_write_kind(value: i64) -> Result<PhpFieldWriteKind> {
    Ok(match value {
        0 => PhpFieldWriteKind::Instance,
        1 => PhpFieldWriteKind::Static,
        2 => PhpFieldWriteKind::Indexed,
        _ => {
            return Err(StoreError::new(format!(
                "invalid PHP field-write kind {value}"
            )));
        }
    })
}

impl AnalyzerStore {
    pub(crate) fn php_source_facts<A: LanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<PhpFileSourceFacts>> {
        if !keep_going() {
            return Ok(None);
        }
        self.read_source_transaction("php", generation, |tx| {
            let header = tx
                .query_row(
                    PHP_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        generation.get(),
                        PHP_SOURCE_FACTS_VERSION,
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
            let (
                blob_id,
                expected_rows,
                expected_bytes,
                expected_occurrences,
                expected_declarations,
                expected_bridges,
            ) = header.ok_or_else(|| {
                StoreError::new(format!(
                    "canonical PHP source facts unavailable for {file:?} ({oid})"
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
            let Some(imports) = read_source_imports(tx, blob_id, keep_going)?
            else {
                return Ok(None);
            };

            let mut alias_lists: HashMap<u32, Vec<u32>> = HashMap::default();
            let mut class_parent_ordinals: HashMap<u32, Option<u32>> = HashMap::default();
            read_rows!(
                "SELECT context_id, ordinal, alias_id FROM source_php_context_aliases
                 WHERE blob_id = ?1 ORDER BY context_id, ordinal",
                row,
                {
                    let context_id: u32 = row.get(0)?;
                    let ordinal: usize = row.get(1)?;
                    let aliases = alias_lists.entry(context_id).or_default();
                    if ordinal != aliases.len() {
                        return Err(StoreError::new("non-dense PHP context aliases"));
                    }
                    if aliases.contains(&row.get::<_, u32>(2)?) {
                        return Err(StoreError::new("duplicate PHP context alias"));
                    }
                    aliases.push(row.get(2)?);
                }
            );

            let mut facts = PhpSourceFacts::default();
            let mut declaration_indices: HashMap<SourceDeclarationId, usize> = HashMap::default();
            read_rows!(
                "SELECT context_id, namespace FROM source_php_contexts
                 WHERE blob_id = ?1 ORDER BY context_id",
                row,
                {
                    let id: u32 = row.get(0)?;
                    if id as usize != facts.contexts.len() {
                        return Err(StoreError::new("non-dense PHP context arena"));
                    }
                    facts.contexts.push(PhpContextSourceFact {
                        namespace: row.get(1)?,
                        aliases: alias_lists.remove(&id).unwrap_or_default(),
                    });
                }
            );
            if !alias_lists.is_empty() {
                return Err(StoreError::new(format!(
                    "orphan PHP context aliases: {alias_lists:?}"
                )));
            }

            read_rows!(
                "SELECT alias_id, source_import_id, kind
                 FROM source_php_aliases WHERE blob_id = ?1 ORDER BY alias_id",
                row,
                {
                    let id: u32 = row.get(0)?;
                    if id as usize != facts.aliases.len() {
                        return Err(StoreError::new("non-dense PHP alias arena"));
                    }
                    facts.aliases.push(PhpAliasSourceFact {
                        import: SourceImportId::new(row.get(1)?),
                        kind: decode_alias_kind(row.get(2)?)?,
                    });
                }
            );

            let mut nominal_arms: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id, ordinal, arm FROM source_php_nominal_arms
                 WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
                row,
                {
                    let declaration_id: u32 = row.get(0)?;
                    let ordinal: usize = row.get(1)?;
                    let arms = nominal_arms.entry(declaration_id).or_default();
                    if ordinal != arms.len() {
                        return Err(StoreError::new("non-dense PHP nominal arms"));
                    }
                    arms.push(row.get(2)?);
                }
            );
            let mut supertypes: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT declaration_id, ordinal, supertype FROM source_php_supertypes
                 WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
                row,
                {
                    let declaration_id: u32 = row.get(0)?;
                    let ordinal: usize = row.get(1)?;
                    let entries = supertypes.entry(declaration_id).or_default();
                    if ordinal != entries.len() {
                        return Err(StoreError::new("non-dense PHP supertypes"));
                    }
                    entries.push(row.get(2)?);
                }
            );

            read_rows!(
                "SELECT declaration_id, kind, context_id, declared_type_occurrence_id,
                        declared_type_kind, class_parent_ordinal, has_trait_use,
                        doc_nominal_type, doc_element_type
                 FROM source_php_declarations WHERE blob_id = ?1 ORDER BY declaration_id",
                row,
                {
                    let id: u32 = row.get(0)?;
                    let declaration = SourceDeclarationId::new(id);
                    if declaration.index() >= source.declaration_count()
                        || declaration_indices
                            .insert(declaration, facts.declarations.len())
                            .is_some()
                    {
                        return Err(StoreError::new("invalid or duplicate PHP declaration id"));
                    }
                    class_parent_ordinals.insert(id, row.get(5)?);
                    let arms = nominal_arms.remove(&id);
                    facts.declarations.push(PhpDeclarationSourceFact {
                        declaration,
                        kind: decode_declaration_kind(row.get(1)?)?,
                        context: PhpSourceContextId::new(row.get(2)?),
                        declared_type_occurrence: row
                            .get::<_, Option<u32>>(3)?
                            .map(SourceOccurrenceId::new),
                        declared_type: decode_type(row.get(4)?, arms, "declaration")?,
                        class_parent: None,
                        has_trait_use: strict_bool(row.get(6)?, "PHP trait use")?,
                        doc_nominal_type: row.get(7)?,
                        doc_element_type: row.get(8)?,
                        supertypes: Vec::new(),
                    });
                }
            );
            if !nominal_arms.is_empty() {
                return Err(StoreError::new(format!(
                    "orphan PHP declaration nominal arms: {nominal_arms:?}"
                )));
            }
            for (declaration_id, entries) in supertypes {
                let index = required(
                    declaration_indices
                        .get(&SourceDeclarationId::new(declaration_id))
                        .copied(),
                    "supertype declaration",
                )?;
                let declaration = &mut facts.declarations[index];
                declaration.class_parent = class_parent_ordinals
                    .remove(&declaration_id)
                    .flatten()
                    .map(|ordinal| {
                        entries.get(ordinal as usize).cloned().ok_or_else(|| {
                            StoreError::new("invalid PHP class parent supertype ordinal")
                        })
                    })
                    .transpose()?;
                declaration.supertypes = entries;
            }
            for (declaration_id, ordinal) in class_parent_ordinals {
                if ordinal.is_some() {
                    return Err(StoreError::new(format!(
                        "PHP class parent references missing supertypes for declaration {declaration_id}"
                    )));
                }
            }

            let mut write_arms: HashMap<u32, Vec<String>> = HashMap::default();
            read_rows!(
                "SELECT write_ordinal, ordinal, arm FROM source_php_write_nominal_arms
                 WHERE blob_id = ?1 ORDER BY write_ordinal, ordinal",
                row,
                {
                    let write_ordinal: u32 = row.get(0)?;
                    let ordinal: usize = row.get(1)?;
                    let arms = write_arms.entry(write_ordinal).or_default();
                    if ordinal != arms.len() {
                        return Err(StoreError::new("non-dense PHP write nominal arms"));
                    }
                    arms.push(row.get(2)?);
                }
            );
            read_rows!(
                "SELECT ordinal, occurrence_id, class_declaration_id, field, kind,
                        directly_in_constructor, value_type_kind, doc_element_type
                 FROM source_php_writes WHERE blob_id = ?1 ORDER BY ordinal",
                row,
                {
                    let ordinal: u32 = row.get(0)?;
                    if ordinal as usize != facts.writes.len() {
                        return Err(StoreError::new("non-dense PHP write arena"));
                    }
                    let class = SourceDeclarationId::new(row.get(2)?);
                    let class_index = required(
                        declaration_indices.get(&class).copied(),
                        "PHP field-write class declaration",
                    )?;
                    if facts.declarations[class_index].kind != PhpDeclarationKind::Class {
                        return Err(StoreError::new("PHP field write does not target a class"));
                    }
                    facts.writes.push(PhpFieldWriteSourceFact {
                        occurrence: SourceOccurrenceId::new(row.get(1)?),
                        class,
                        field: row.get(3)?,
                        kind: decode_write_kind(row.get(4)?)?,
                        directly_in_constructor: strict_bool(row.get(5)?, "PHP constructor write")?,
                        value_type: decode_type(row.get(6)?, write_arms.remove(&ordinal), "write")?,
                        doc_element_type: row.get(7)?,
                    });
                }
            );
            if !write_arms.is_empty() {
                return Err(StoreError::new(format!(
                    "orphan PHP write nominal arms: {write_arms:?}"
                )));
            }

            if !facts.valid_links(&source, &imports)
                || super::source_publication::cost(&facts) != (expected_rows, expected_bytes)
            {
                return Err(StoreError::new(format!(
                    "invalid or incomplete PHP source publication: {facts:?}"
                )));
            }
            let Some(units) = read_source_unit_map(
                tx,
                &oid.to_string(),
                "php",
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
                    return Err(StoreError::new("PHP unit bridge has no declaration"));
                }
                declaration_units
                    .entry(declaration)
                    .or_default()
                    .push(unit.clone());
                bridge_count += 1;
            });
            if bridge_count != expected_bridges {
                return Err(StoreError::new(format!(
                    "incomplete PHP declaration bridges: {declaration_units:?}"
                )));
            }
            if !keep_going() {
                return Ok(None);
            }
            Ok(Some(PhpFileSourceFacts {
                source,
                imports,
                facts,
                declaration_units,
            }))
        })
    }
}
