//! Generation-selected Ruby load publication readback.

use crate::analyzer::store::source_facts::{SOURCE_FACTS_VERSION, strict_bool};
use crate::analyzer::store::{AnalyzerStore, GenerationId, Result, StoreError};
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::ruby_facts::*;
use brokk_bifrost_core::analyzer::structural::facts::Span;
use git2::Oid;
use rusqlite::{OptionalExtension, params};

pub(in crate::analyzer) const RUBY_SOURCE_HEADER_SQL: &str = "SELECT blob.id, marker.logical_rows, marker.payload_bytes, source.import_count, source.source_bytes, marker.has_parse_errors, marker.runtime_boundary_kind
    FROM blobs AS blob
    JOIN source_ruby_manifests AS marker ON marker.blob_id = blob.id
    JOIN source_fact_manifests AS source ON source.blob_id = blob.id
    JOIN blob_meta AS meta ON meta.blob_id = blob.id
    JOIN source_fact_readiness AS ready ON ready.blob_id = blob.id
    WHERE blob.blob_oid = ?1 AND blob.lang = 'ruby' AND blob.generation = ?2
      AND marker.facts_version = ?3 AND source.facts_version = ?4
      AND source.publication_state = 'complete' AND meta.is_complete = 1 AND ready.available = 1";

pub(in crate::analyzer) const RUBY_LOADS_SQL: &str = "SELECT load.import_id,load.kind,load.has_receiver,load.has_constant,
        imports.statement,imports.is_wildcard,imports.is_global,imports.identifier,imports.alias,imports.has_structured_path,
        COALESCE(imports.alias_start_byte,imports.target_start_byte),
        COALESCE(imports.alias_end_byte,imports.target_end_byte),
        EXISTS(SELECT 1 FROM import_statements AS generic WHERE generic.blob_id=load.blob_id AND generic.source_import_id=load.import_id)
    FROM source_ruby_loads AS load
    JOIN source_imports AS imports ON imports.blob_id=load.blob_id AND imports.import_id=load.import_id

    WHERE load.blob_id=?1 ORDER BY load.import_id";

impl AnalyzerStore {
    pub(crate) fn ruby_source_facts(
        &self,
        oid: Oid,
        generation: GenerationId,
    ) -> Result<RubyFileSourceInfo> {
        self.read_source_transaction("ruby", generation, |tx| {
            type RubyPublicationHeader = (i64, usize, usize, usize, usize, i64, Option<u8>);
            let header: Option<RubyPublicationHeader> = tx
                .query_row(
                    RUBY_SOURCE_HEADER_SQL,
                    params![
                        oid.to_string(),
                        generation.get(),
                        RUBY_SOURCE_FACTS_VERSION,
                        SOURCE_FACTS_VERSION
                    ],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()?;
            let (
                blob_id,
                expected_rows,
                expected_bytes,
                expected_imports,
                source_bytes,
                parse_errors,
                boundary,
            ) = header.ok_or_else(|| {
                StoreError::new(format!("canonical Ruby load facts unavailable for {oid}"))
            })?;
            let mut loads = Vec::new();
            let mut statement = tx.prepare_cached(RUBY_LOADS_SQL)?;
            let mut rows = statement.query([blob_id])?;
            while let Some(row) = rows.next()? {
                if row.get::<_, usize>(0)? != loads.len() {
                    return Err(StoreError::new("Ruby load/import identities are not dense"));
                }
                let kind = match row.get::<_, i64>(1)? {
                    0 => RubyLoadKind::Require,
                    1 => RubyLoadKind::RequireRelative,
                    2 => RubyLoadKind::Load,
                    3 => RubyLoadKind::Autoload,
                    other => return Err(StoreError::new(format!("invalid Ruby load kind {other}"))),
                };
                let has_constant = strict_bool(row.get(3)?, "Ruby constant availability")?;
                if (has_constant && kind != RubyLoadKind::Autoload)
                    || strict_bool(row.get(9)?, "Ruby load path")?
                {
                    return Err(StoreError::new("invalid canonical Ruby load shape"));
                }
                let binder_span = match (
                    row.get::<_, Option<usize>>(10)?,
                    row.get::<_, Option<usize>>(11)?,
                ) {
                    (Some(start_byte), Some(end_byte)) if start_byte <= end_byte => Some(Span {
                        start_byte,
                        end_byte,
                    }),
                    (None, None) => None,
                    _ => return Err(StoreError::new("invalid Ruby load source target range")),
                };
                loads.push(RubyLoadInfo {
                    import: ImportInfo {
                        raw_snippet: row.get(4)?,
                        is_wildcard: strict_bool(row.get(5)?, "Ruby load wildcard")?,
                        is_global: strict_bool(row.get(6)?, "Ruby load global")?,
                        identifier: row.get(7)?,
                        alias: row.get(8)?,
                        path: None,
                        binder_span,
                    },
                    kind,
                    has_receiver: strict_bool(row.get(2)?, "Ruby load receiver")?,
                    autoload_constant: has_constant.then(Vec::new),
                    generic: strict_bool(row.get(12)?, "Ruby generic import membership")?,
                });
            }
            drop(rows);
            drop(statement);
            let mut statement = tx.prepare_cached("SELECT import_id,ordinal,segment FROM source_ruby_load_constants WHERE blob_id=?1 ORDER BY import_id,ordinal")?;
            let mut rows = statement.query([blob_id])?;
            let mut logical_rows = 1 + loads.len();
            let mut payload_bytes = 0usize;
            while let Some(row) = rows.next()? {
                let import: usize = row.get(0)?;
                let parts = loads
                    .get_mut(import)
                    .and_then(|load| load.autoload_constant.as_mut())
                    .ok_or_else(|| StoreError::new("Ruby constant refers to unavailable load"))?;
                if row.get::<_, usize>(1)? != parts.len() {
                    return Err(StoreError::new("Ruby constant segments are not dense"));
                }
                let part: String = row.get(2)?;
                if part.is_empty() {
                    return Err(StoreError::new("Ruby constant segment is empty"));
                }
                logical_rows += 1;
                payload_bytes += part.len();
                parts.push(part);
            }
            if loads.len() != expected_imports
                || logical_rows != expected_rows
                || payload_bytes != expected_bytes
                || loads
                    .iter()
                    .any(|load| load.autoload_constant.as_ref().is_some_and(Vec::is_empty))
            {
                return Err(StoreError::new(
                    "canonical Ruby load publication is incomplete",
                ));
            }
            drop(rows);
            drop(statement);
            Ok(RubyFileSourceInfo {
                loads,
                source_bytes,
                has_parse_errors: strict_bool(parse_errors, "Ruby parse error state")?,
                runtime_boundary: boundary
                    .map(|tag| {
                        RubyRuntimeBoundary::from_tag(tag)
                            .ok_or_else(|| StoreError::new("invalid Ruby runtime boundary"))
                    })
                    .transpose()?,
            })
        })
    }
}
