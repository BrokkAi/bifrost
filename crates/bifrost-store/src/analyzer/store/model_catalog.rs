use crate::CancellationToken;
use crate::analyzer::canonical_hash::is_lower_sha256;
use crate::analyzer::semantic_model::ArtifactProducerLimits;
use crate::analyzer::semantic_model::ExactArtifact;
use crate::analyzer::semantic_model::GoPinnedPackage;
use crate::analyzer::semantic_model::csmi::CsmiCallableValuesModality;
use crate::analyzer::semantic_model::csmi::CsmiCallableValuesPayload;
use crate::analyzer::semantic_model::csmi::CsmiCallableValuesShape;
use crate::analyzer::semantic_model::csmi::CsmiCallableValuesTiming;
use crate::analyzer::semantic_model::csmi::CsmiCoverageStatus;
use crate::analyzer::semantic_model::model::CallableValuesCoverage;
use crate::analyzer::semantic_model::model::CallableValuesFact;
use crate::analyzer::semantic_model::model::CallableValuesFamily;
use crate::analyzer::semantic_model::validate::is_canonical_relative_path;
use crate::analyzer::store::SemanticPackActivationSourceKind;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::*;
use brokk_bifrost_semantic::analyzer::semantic_model::dependency::JvmDependencyGap;
use brokk_bifrost_semantic::analyzer::semantic_model::runtime::FamilyOpen;
use rusqlite::Connection;
use rusqlite::params;
use serde::Deserialize;
use serde::Serialize;

use std::fmt;
use std::path::{Path, PathBuf};

use std::sync::Arc;
use std::sync::Mutex;

use tempfile::TempDir;

pub fn query_callable_values_on_connection(
    connection: &Connection,
    query: &CatalogCallableValuesQuery<'_>,
    limits: CatalogCallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
    let mut result = CatalogCallableValuesQueryResult {
        facts: Vec::new(),
        coverage_claims: Vec::new(),
        executable_coverage: CsmiCoverageStatus::Unknown,
        examined_records: 0,
        gap: None,
    };
    if cancellation.is_cancelled() {
        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
        return Ok(result);
    }
    if limits.max_records == 0 {
        result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 0 });
        return Ok(result);
    }

    let limit = callable_values_sql_limit(limits.max_records.saturating_add(1));
    let family = match query.question {
        CatalogCallableValuesQuestion::ReturnedCallable { .. } => {
            CallableValuesFamily::ReturnedCallables
        }
        CatalogCallableValuesQuestion::CallbackInvocation { .. } => {
            CallableValuesFamily::CallbackInvocations
        }
    };

    match query.question {
        CatalogCallableValuesQuestion::ReturnedCallable {
            result: result_ordinal,
        } => {
            let mut statement = connection
                .prepare(CALLABLE_VALUES_RETURNED_SQL)
                .map_err(|error| CatalogError::sqlite("prepare returned-callable query", error))?;
            let rows = statement
                .query_map(
                    params![
                        query.manifest_digest,
                        query.shard_id,
                        query.callable,
                        result_ordinal,
                        limit,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .map_err(|error| CatalogError::sqlite("query returned-callable rows", error))?;
            for row in rows {
                if cancellation.is_cancelled() {
                    result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                    break;
                }
                let row =
                    row.map_err(|error| CatalogError::sqlite("read returned-callable row", error))?;
                result.examined_records += 1;
                if result.examined_records > limits.max_records {
                    result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                        max_records: limits.max_records,
                    });
                    break;
                }
                let payload = CsmiCallableValuesPayload::ReturnedCallable {
                    callable: query.callable.to_owned(),
                    result: u32::try_from(row.1).map_err(|error| {
                        CatalogError::Integrity(format!(
                            "stored callable result ordinal is outside u32: {error}"
                        ))
                    })?,
                    target: row.2.clone(),
                };
                let fact = CallableValuesFact {
                    payload,
                    provenance: decode_json_column(&row.3, "callable fact provenance")?,
                };
                let anonymous_callable = match load_anonymous_callable_identity(
                    connection,
                    query.manifest_digest,
                    query.shard_id,
                    &row.2,
                    limits.max_records.saturating_sub(result.examined_records),
                    cancellation,
                )? {
                    AnonymousCallableIdentityRead::Missing => None,
                    AnonymousCallableIdentityRead::Found { identity, examined } => {
                        result.examined_records += examined;
                        Some(*identity)
                    }
                    AnonymousCallableIdentityRead::RecordBudgetExhausted { examined } => {
                        result.examined_records += examined;
                        result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                            max_records: limits.max_records,
                        });
                        None
                    }
                    AnonymousCallableIdentityRead::Cancelled { examined } => {
                        result.examined_records += examined;
                        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                        None
                    }
                };
                result.facts.push(CatalogCallableValueFact {
                    manifest_digest: query.manifest_digest.to_owned(),
                    shard_id: query.shard_id.to_owned(),
                    callable: query.callable.to_owned(),
                    ordinal: row.0,
                    fact,
                    anonymous_callable,
                });
                if result.gap.is_some() {
                    break;
                }
            }
        }
        CatalogCallableValuesQuestion::CallbackInvocation { callback, shape } => {
            let callback_json = json_text(callback, "callback query location")?;
            let mut statement =
                connection
                    .prepare(CALLABLE_VALUES_CALLBACK_SQL)
                    .map_err(|error| {
                        CatalogError::sqlite("prepare callback-invocation query", error)
                    })?;
            let rows = statement
                .query_map(
                    params![
                        query.manifest_digest,
                        query.shard_id,
                        query.callable,
                        callback_json,
                        shape.parameters,
                        shape.results,
                        limit,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, String>(7)?,
                        ))
                    },
                )
                .map_err(|error| CatalogError::sqlite("query callback-invocation rows", error))?;
            for row in rows {
                if cancellation.is_cancelled() {
                    result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                    break;
                }
                let row = row
                    .map_err(|error| CatalogError::sqlite("read callback-invocation row", error))?;
                result.examined_records += 1;
                if result.examined_records > limits.max_records {
                    result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                        max_records: limits.max_records,
                    });
                    break;
                }
                let payload = CsmiCallableValuesPayload::CallbackInvocation {
                    callable: query.callable.to_owned(),
                    callback: decode_json_column(&row.1, "callback input location")?,
                    shape: CsmiCallableValuesShape {
                        parameters: u16::try_from(row.2).map_err(|error| {
                            CatalogError::Integrity(format!(
                                "stored callback parameter shape is outside u16: {error}"
                            ))
                        })?,
                        results: u16::try_from(row.3).map_err(|error| {
                            CatalogError::Integrity(format!(
                                "stored callback result shape is outside u16: {error}"
                            ))
                        })?,
                    },
                    arguments: decode_json_column(&row.4, "callback arguments")?,
                    timing: match row.5.as_str() {
                        "during-call" => CsmiCallableValuesTiming::DuringCall,
                        value => {
                            return Err(CatalogError::Integrity(format!(
                                "unknown callable callback timing {value:?}"
                            )));
                        }
                    },
                    modality: match row.6.as_str() {
                        "may" => CsmiCallableValuesModality::May,
                        value => {
                            return Err(CatalogError::Integrity(format!(
                                "unknown callable callback modality {value:?}"
                            )));
                        }
                    },
                };
                if let Err(error) = validate_callable_profile_location(&payload) {
                    result.gap = Some(CatalogCallableValuesQueryGap::UnsupportedProjection(error));
                    break;
                }
                let fact = CallableValuesFact {
                    payload,
                    provenance: decode_json_column(&row.7, "callable fact provenance")?,
                };
                result.facts.push(CatalogCallableValueFact {
                    manifest_digest: query.manifest_digest.to_owned(),
                    shard_id: query.shard_id.to_owned(),
                    callable: query.callable.to_owned(),
                    ordinal: row.0,
                    fact,
                    anonymous_callable: None,
                });
            }
        }
    }

    if result.gap.is_none() && cancellation.is_cancelled() {
        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
    }
    if result.gap.is_none() {
        let remaining = limits.max_records.saturating_sub(result.examined_records);
        let coverage_limit = callable_values_sql_limit(remaining.saturating_add(1));
        let mut statement = connection
            .prepare(CALLABLE_VALUES_COVERAGE_SQL)
            .map_err(|error| CatalogError::sqlite("prepare callable coverage query", error))?;
        let rows = statement
            .query_map(
                params![
                    query.manifest_digest,
                    query.shard_id,
                    callable_values_family_name(family),
                    query.callable,
                    coverage_limit,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .map_err(|error| CatalogError::sqlite("query callable coverage rows", error))?;
        for row in rows {
            if cancellation.is_cancelled() {
                result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
                break;
            }
            let row =
                row.map_err(|error| CatalogError::sqlite("read callable coverage row", error))?;
            result.examined_records += 1;
            if result.examined_records > limits.max_records {
                result.gap = Some(CatalogCallableValuesQueryGap::RecordBudgetExhausted {
                    max_records: limits.max_records,
                });
                break;
            }
            let coverage = CallableValuesCoverage {
                family: parse_callable_values_family(&row.1)?,
                callable: query.callable.to_owned(),
                status: parse_coverage_status(&row.2)?,
                limitations: decode_json_column(&row.3, "callable coverage limitations")?,
                provenance: decode_json_column(&row.4, "callable coverage provenance")?,
            };
            result.coverage_claims.push(CatalogCallableValueCoverage {
                manifest_digest: query.manifest_digest.to_owned(),
                shard_id: query.shard_id.to_owned(),
                callable: query.callable.to_owned(),
                ordinal: row.0,
                coverage,
            });
        }
    }
    if result.gap.is_none() && cancellation.is_cancelled() {
        result.gap = Some(CatalogCallableValuesQueryGap::Cancelled);
    }
    Ok(result)
}

pub fn callable_values_publication_present(
    connection: &Connection,
    manifest_digest: &str,
    shard_id: &str,
) -> Result<bool, CatalogError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1
                         FROM active_catalog_semantic_rows_indexed_shards WHERE
                         manifest_digest=?1 AND shard_id=?2 AND index_version=4)",
            params![manifest_digest, shard_id],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check active semantic publication", error))
}

pub fn callable_values_index_missing_result(
    limits: CatalogCallableValuesQueryLimits,
) -> CatalogCallableValuesQueryResult {
    CatalogCallableValuesQueryResult {
        facts: Vec::new(),
        coverage_claims: Vec::new(),
        executable_coverage: CsmiCoverageStatus::Unknown,
        examined_records: 0,
        gap: Some(if limits.max_records == 0 {
            CatalogCallableValuesQueryGap::RecordBudgetExhausted { max_records: 0 }
        } else {
            CatalogCallableValuesQueryGap::IndexReconciliationRequired
        }),
    }
}

pub fn read_go_source_from_connection(
    connection: &Connection,
    request: &CatalogGoSourceRequest<'_>,
    limits: CatalogGoSourceReadLimits,
    cancellation: &CancellationToken,
) -> Result<Option<CatalogExactGoSourceSet>, CatalogError> {
    if cancellation.is_cancelled() {
        return Err(CatalogError::Cancelled);
    }
    if !is_lower_sha256(request.manifest_digest)
        || !is_lower_sha256(request.artifact_sha256)
        || request.manifest_digest.is_empty()
        || request.shard_id.is_empty()
        || request.package_import_path.is_empty()
        || !is_canonical_relative_path(request.file)
    {
        return Err(CatalogError::Integrity(
            "exact Go source request contains a non-canonical identity".to_owned(),
        ));
    }
    if limits.max_files == 0 || limits.max_source_bytes == 0 {
        return Err(CatalogError::SourceBudgetExhausted {
            max_files: limits.max_files,
            max_source_bytes: limits.max_source_bytes,
        });
    }
    let published: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM active_catalog_pack_shards
                         WHERE manifest_digest=?1 AND shard_id=?2)",
            params![request.manifest_digest, request.shard_id],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check exact Go source publication", error))?;
    if !published {
        return Ok(None);
    }
    let artifact_activated: bool = connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1
               FROM active_catalog_selectors
               WHERE manifest_digest = ?1
                 AND shard_id = ?2
                 AND artifact_sha256 = ?3)
             -- A generated selector binds the composite production input
             -- digest; the raw source digest is one recorded input slot of
             -- the production that this shard's own selector names. The shard is
             -- already known to be published and active.
             OR EXISTS(
               SELECT 1
               FROM catalog_selectors AS selector
               JOIN catalog_generated_productions AS production
                 ON production.input_digest = selector.production_input_digest
                AND production.manifest_digest = selector.manifest_digest
               JOIN catalog_production_inputs AS input
                 ON input.production_digest = production.production_digest
               WHERE selector.manifest_digest = ?1
                 AND selector.shard_id = ?2
                 AND lower(hex(input.sha256)) = ?3)",
            params![
                request.manifest_digest,
                request.shard_id,
                request.artifact_sha256,
            ],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check exact Go source activation", error))?;
    if !artifact_activated {
        return Ok(None);
    }
    let source_set_present: bool = connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM active_catalog_exact_go_source_sets
               WHERE manifest_digest = ?1 AND artifact_sha256 = ?2)",
            params![request.manifest_digest, request.artifact_sha256],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check exact Go source set", error))?;
    if !source_set_present {
        return Ok(None);
    }

    let mut file_statement = connection
        .prepare(
            "SELECT relative_path, source_text,
                    length(CAST(relative_path AS BLOB)),
                    length(CAST(source_text AS BLOB))
             FROM active_catalog_exact_go_source_files
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
             ORDER BY relative_path",
        )
        .map_err(|error| CatalogError::sqlite("prepare exact Go source files", error))?;
    let mut file_rows = file_statement
        .query(params![request.manifest_digest, request.artifact_sha256])
        .map_err(|error| CatalogError::sqlite("query exact Go source files", error))?;
    let mut entries = Vec::new();
    let mut source_bytes = 0_u64;
    while let Some(row) = file_rows
        .next()
        .map_err(|error| CatalogError::sqlite("read exact Go source files", error))?
    {
        if cancellation.is_cancelled() {
            return Err(CatalogError::Cancelled);
        }
        if entries.len() >= limits.max_files {
            return Err(CatalogError::SourceBudgetExhausted {
                max_files: limits.max_files,
                max_source_bytes: limits.max_source_bytes,
            });
        }
        let path_bytes = row
            .get::<_, i64>(2)
            .map_err(|error| CatalogError::sqlite("read exact Go source path length", error))?;
        let source_text_bytes = row
            .get::<_, i64>(3)
            .map_err(|error| CatalogError::sqlite("read exact Go source text length", error))?;
        let path_bytes = u64::try_from(path_bytes).map_err(|error| {
            CatalogError::Integrity(format!(
                "exact Go source path byte length is invalid: {error}"
            ))
        })?;
        let source_text_bytes = u64::try_from(source_text_bytes).map_err(|error| {
            CatalogError::Integrity(format!(
                "exact Go source text byte length is invalid: {error}"
            ))
        })?;
        source_bytes = source_bytes
            .checked_add(path_bytes)
            .and_then(|bytes| bytes.checked_add(source_text_bytes))
            .ok_or_else(|| {
                CatalogError::Integrity("exact Go source byte count overflowed".to_owned())
            })?;
        if source_bytes > limits.max_source_bytes {
            return Err(CatalogError::SourceBudgetExhausted {
                max_files: limits.max_files,
                max_source_bytes: limits.max_source_bytes,
            });
        }
        let path = row
            .get::<_, String>(0)
            .map_err(|error| CatalogError::sqlite("read exact Go source path", error))?;
        let source = row
            .get::<_, String>(1)
            .map_err(|error| CatalogError::sqlite("read exact Go source text", error))?;
        entries.push((path, source.into_bytes()));
    }
    drop(file_rows);
    drop(file_statement);

    let mut package_statement = connection
        .prepare(
            "SELECT package_ordinal, import_path, package_name,
                    length(CAST(import_path AS BLOB)),
                    length(CAST(package_name AS BLOB))
             FROM active_catalog_exact_go_packages
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
             ORDER BY package_ordinal",
        )
        .map_err(|error| CatalogError::sqlite("prepare exact Go packages", error))?;
    let mut package_rows = package_statement
        .query(params![request.manifest_digest, request.artifact_sha256])
        .map_err(|error| CatalogError::sqlite("query exact Go packages", error))?;
    let mut packages: Vec<(usize, GoPinnedPackage)> = Vec::new();
    while let Some(row) = package_rows
        .next()
        .map_err(|error| CatalogError::sqlite("read exact Go packages", error))?
    {
        if cancellation.is_cancelled() {
            return Err(CatalogError::Cancelled);
        }
        if packages.len() >= limits.max_files {
            return Err(CatalogError::SourceBudgetExhausted {
                max_files: limits.max_files,
                max_source_bytes: limits.max_source_bytes,
            });
        }
        let import_path_bytes = row
            .get::<_, i64>(3)
            .map_err(|error| CatalogError::sqlite("read exact Go import path length", error))?;
        let package_name_bytes = row
            .get::<_, i64>(4)
            .map_err(|error| CatalogError::sqlite("read exact Go package name length", error))?;
        let import_path_bytes = u64::try_from(import_path_bytes).map_err(|error| {
            CatalogError::Integrity(format!(
                "exact Go import path byte length is invalid: {error}"
            ))
        })?;
        let package_name_bytes = u64::try_from(package_name_bytes).map_err(|error| {
            CatalogError::Integrity(format!(
                "exact Go package name byte length is invalid: {error}"
            ))
        })?;
        source_bytes = source_bytes
            .checked_add(import_path_bytes)
            .and_then(|bytes| bytes.checked_add(package_name_bytes))
            .ok_or_else(|| {
                CatalogError::Integrity("exact Go source byte count overflowed".to_owned())
            })?;
        if source_bytes > limits.max_source_bytes {
            return Err(CatalogError::SourceBudgetExhausted {
                max_files: limits.max_files,
                max_source_bytes: limits.max_source_bytes,
            });
        }
        let ordinal = row
            .get::<_, i64>(0)
            .map_err(|error| CatalogError::sqlite("read exact Go package ordinal", error))?;
        let import_path = row
            .get::<_, String>(1)
            .map_err(|error| CatalogError::sqlite("read exact Go import path", error))?;
        let name = row
            .get::<_, String>(2)
            .map_err(|error| CatalogError::sqlite("read exact Go package name", error))?;
        let ordinal = usize::try_from(ordinal).map_err(|error| {
            CatalogError::Integrity(format!(
                "stored Go package ordinal is outside usize: {error}"
            ))
        })?;
        if ordinal != packages.len() {
            return Err(CatalogError::Integrity(format!(
                "stored Go package ordinals are not contiguous at {ordinal}"
            )));
        }
        packages.push((
            ordinal,
            GoPinnedPackage {
                import_path,
                name,
                files: Vec::new(),
            },
        ));
    }
    drop(package_rows);
    drop(package_statement);
    let mut file_statement = connection
        .prepare(
            "SELECT package_ordinal, file_ordinal, relative_path,
                    length(CAST(relative_path AS BLOB))
             FROM active_catalog_exact_go_package_files
             WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
             ORDER BY package_ordinal, file_ordinal",
        )
        .map_err(|error| CatalogError::sqlite("prepare exact Go package files", error))?;
    let mut file_rows = file_statement
        .query(params![request.manifest_digest, request.artifact_sha256])
        .map_err(|error| CatalogError::sqlite("query exact Go package files", error))?;
    let mut package_index = 0_usize;
    let mut current_package_ordinal = None;
    let mut next_file_ordinal = 0_usize;
    let mut membership_rows = 0_usize;
    while let Some(row) = file_rows
        .next()
        .map_err(|error| CatalogError::sqlite("read exact Go package files", error))?
    {
        if cancellation.is_cancelled() {
            return Err(CatalogError::Cancelled);
        }
        if membership_rows >= limits.max_files {
            return Err(CatalogError::SourceBudgetExhausted {
                max_files: limits.max_files,
                max_source_bytes: limits.max_source_bytes,
            });
        }
        let file_bytes = row.get::<_, i64>(3).map_err(|error| {
            CatalogError::sqlite("read exact Go package file path length", error)
        })?;
        let file_bytes = u64::try_from(file_bytes).map_err(|error| {
            CatalogError::Integrity(format!(
                "exact Go package file path byte length is invalid: {error}"
            ))
        })?;
        source_bytes = source_bytes.checked_add(file_bytes).ok_or_else(|| {
            CatalogError::Integrity("exact Go source byte count overflowed".to_owned())
        })?;
        if source_bytes > limits.max_source_bytes {
            return Err(CatalogError::SourceBudgetExhausted {
                max_files: limits.max_files,
                max_source_bytes: limits.max_source_bytes,
            });
        }
        let ordinal = row
            .get::<_, i64>(0)
            .map_err(|error| CatalogError::sqlite("read exact Go package ordinal", error))?;
        let file_ordinal = row
            .get::<_, i64>(1)
            .map_err(|error| CatalogError::sqlite("read exact Go file ordinal", error))?;
        let file = row
            .get::<_, String>(2)
            .map_err(|error| CatalogError::sqlite("read exact Go package file path", error))?;
        membership_rows += 1;
        let ordinal = usize::try_from(ordinal).map_err(|error| {
            CatalogError::Integrity(format!(
                "stored Go package ordinal is outside usize: {error}"
            ))
        })?;
        while package_index < packages.len() && packages[package_index].0 < ordinal {
            package_index += 1;
        }
        let Some((package_ordinal, package)) = packages.get_mut(package_index) else {
            return Err(CatalogError::Integrity(format!(
                "exact Go package file references missing package ordinal {ordinal}"
            )));
        };
        if *package_ordinal != ordinal {
            return Err(CatalogError::Integrity(format!(
                "exact Go package file references missing package ordinal {ordinal}"
            )));
        }
        let file_ordinal = usize::try_from(file_ordinal).map_err(|error| {
            CatalogError::Integrity(format!("stored Go file ordinal is outside usize: {error}"))
        })?;
        if current_package_ordinal != Some(ordinal) {
            next_file_ordinal = 0;
            current_package_ordinal = Some(ordinal);
        }
        if file_ordinal != next_file_ordinal {
            return Err(CatalogError::Integrity(format!(
                "stored Go file ordinals are not contiguous at package {ordinal}, file {file_ordinal}"
            )));
        }
        next_file_ordinal += 1;
        package.files.push(file);
    }
    drop(file_rows);
    drop(file_statement);
    let packages = packages
        .into_iter()
        .map(|(_, package)| package)
        .collect::<Vec<_>>();
    if !packages.iter().any(|package| {
        package.import_path == request.package_import_path
            && package.files.iter().any(|file| file == request.file)
    }) {
        return Ok(None);
    }
    let artifact = ExactArtifact::from_source_entries(
        PathBuf::from("<catalog exact Go source set>"),
        entries,
        limits.max_path_depth,
        &ArtifactProducerLimits {
            max_artifact_bytes: u64::MAX,
            ..ArtifactProducerLimits::default()
        },
    )
    .map_err(|diagnostic| CatalogError::Artifact(diagnostic.message))?;
    if artifact.sha256() != request.artifact_sha256 {
        return Err(CatalogError::Integrity(format!(
            "exact Go source rows hash to {}, expected {}",
            artifact.sha256(),
            request.artifact_sha256
        )));
    }
    validate_exact_go_source(&artifact, &packages)?;
    Ok(Some(CatalogExactGoSourceSet { artifact, packages }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurablePackSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
}

impl DurablePackSourceKind {
    pub fn as_str(self) -> &'static str {
        CatalogPackSourceKind::from(self).as_str()
    }

    pub fn parse(value: &str) -> Result<Self, CatalogError> {
        parse_semantic_pack_activation_source_kind(value)
            .and_then(durable_activation_kind)
            .ok_or_else(|| {
                CatalogError::Integrity(format!("unknown catalog source kind {value:?}"))
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogPackSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
    Embedded,
    EphemeralWorkspace,
}

impl CatalogPackSourceKind {
    pub const fn shard_database(self) -> super::active_models::CatalogShardDatabase {
        use super::active_models::CatalogShardDatabase;
        match self {
            Self::Embedded | Self::EphemeralWorkspace => CatalogShardDatabase::Session,
            _ => CatalogShardDatabase::Durable,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Generated => "generated",
            Self::PreShipped => "pre_shipped",
            Self::WorkspaceProduced => "workspace_produced",
            Self::Embedded => "embedded",
            Self::EphemeralWorkspace => "ephemeral_workspace",
        }
    }

    pub const fn precedence(self) -> u8 {
        match self {
            Self::Embedded => 0,
            Self::PreShipped => 1,
            Self::Installed => 2,
            Self::Generated => 3,
            Self::WorkspaceProduced => 4,
            Self::EphemeralWorkspace => 5,
        }
    }

    pub fn parse(value: &str) -> Result<Self, CatalogError> {
        parse_semantic_pack_activation_source_kind(value)
            .map(activation_catalog_kind)
            .ok_or_else(|| {
                CatalogError::Integrity(format!("unknown catalog source kind {value:?}"))
            })
    }
}

impl From<DurablePackSourceKind> for CatalogPackSourceKind {
    fn from(value: DurablePackSourceKind) -> Self {
        match value {
            DurablePackSourceKind::Installed => Self::Installed,
            DurablePackSourceKind::Generated => Self::Generated,
            DurablePackSourceKind::PreShipped => Self::PreShipped,
            DurablePackSourceKind::WorkspaceProduced => Self::WorkspaceProduced,
        }
    }
}

impl From<SessionPackSourceKind> for CatalogPackSourceKind {
    fn from(value: SessionPackSourceKind) -> Self {
        match value {
            SessionPackSourceKind::Embedded => Self::Embedded,
            SessionPackSourceKind::EphemeralWorkspace => Self::EphemeralWorkspace,
        }
    }
}

/// Open a private active view over a durable catalog and its shared session rows.
pub fn open_active_reader_connection(
    root: &std::path::Path,
    session_catalog: &Mutex<Option<SessionSemanticCatalog>>,
) -> Result<Connection, CatalogError> {
    let mut session = session_catalog
        .lock()
        .expect("session semantic catalog mutex poisoned");
    if session.is_none() {
        *session = Some(open_session_semantic_catalog()?);
    }
    let connection = brokk_bifrost_semantic::analyzer::semantic_model::catalog::db::open(
        root,
        CatalogOpenMode::ReadOnly,
    )?;
    brokk_bifrost_core::cache_db::sql_profile::install_catalog_active(&connection);
    // db::open also sets query_only, which forbids TEMP writes. The main
    // file remains protected by SQLITE_OPEN_READ_ONLY; membership is TEMP.
    connection
        .pragma_update(None, "query_only", false)
        .map_err(|error| CatalogError::sqlite("enable active TEMP membership", error))?;
    rows::attach_session_rows(
        &connection,
        session.as_ref().expect("session catalog initialized"),
    )?;
    Ok(connection)
}

/// Validation witness for a prepared pinned-reader connection. Stat-only
/// object identities allow WAL checkpoints without opening foreign descriptors
/// whose close would release SQLite's process-owned POSIX locks. The reader's
/// SQLite connection keeps its inode alive, preventing reuse while guarded by
/// this witness. SQLite's HAS_MOVED check also verifies both database files
/// it actually opened. VFS implementations without that control (including
/// Windows) retain the stat/schema checks and cannot detect a replacement
/// restored between the two path samples. These identities are never persisted.
/// In-place overwrite of a live SQLite database is unsupported.
#[derive(Clone)]
pub struct PinnedReaderValidation {
    files: Vec<PinnedReaderFile>,
    versions: (i64, i64),
}

#[derive(Clone, PartialEq, Eq)]
struct PinnedReaderFile {
    path: PathBuf,
    /// None when the path was missing or not a regular file at capture. Such
    /// a capture never matches, so preparation drops the handle and retries.
    witness: Option<PinnedFileWitness>,
}

/// What identifies a pinned catalog file across a WAL checkpoint: its volume
/// and, when the filesystem supplies a file index, its object identity. Size
/// and timestamps are excluded because a checkpoint changes them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PinnedFileWitness {
    volume: Option<u64>,
    object: Option<(u64, u64)>,
}

/// Stat a pinned catalog path without opening it. `Ok(None)` means the path
/// is missing or not a regular file, which can never be the pinned database.
fn pinned_file_witness(path: &Path) -> Result<Option<PinnedFileWitness>, CatalogError> {
    let identity = match brokk_bifrost_core::content_digest::file_identity(path) {
        Ok(identity) => identity,
        // A removed catalog file is a witness mismatch, not a failure: the
        // stale connection is discarded and preparation retries.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CatalogError::Integrity(format!(
                "stat pinned reader database {path:?}: {error}"
            )));
        }
    };
    Ok(identity.map(|identity| PinnedFileWitness {
        volume: identity.volume(),
        object: identity.object_identity(),
    }))
}

impl PinnedReaderValidation {
    pub fn capture(connection: &Connection) -> Result<Self, CatalogError> {
        let files = connection
            .prepare("PRAGMA database_list")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|error| CatalogError::sqlite("list pinned reader databases", error))?
            .into_iter()
            .filter(|(name, _)| name == "main" || name == "session")
            .map(|(_, path)| PathBuf::from(path))
            .collect::<Vec<_>>();
        let files = Self::capture_files(files)?;
        assert_eq!(files.len(), 2, "pinned reader attaches main and session");
        Ok(Self {
            files,
            versions: Self::versions(connection)?,
        })
    }

    fn capture_files(
        paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Vec<PinnedReaderFile>, CatalogError> {
        paths
            .into_iter()
            .map(|path| {
                let witness = pinned_file_witness(&path)?;
                Ok(PinnedReaderFile { path, witness })
            })
            .collect()
    }

    fn versions(connection: &Connection) -> Result<(i64, i64), CatalogError> {
        // SQLite's table-valued user_version pragma accepts no schema argument.
        // Qualifying the virtual table still reads main, so use explicit pragmas.
        let main = connection
            .query_row("PRAGMA main.user_version", [], |row| row.get(0))
            .map_err(|error| CatalogError::sqlite("validate main catalog version", error))?;
        let session = connection
            .query_row("PRAGMA session.user_version", [], |row| row.get(0))
            .map_err(|error| CatalogError::sqlite("validate session catalog version", error))?;
        Ok((main, session))
    }

    /// A false result discards the prepared connection before starting a read.
    pub fn matches(&self, connection: &Connection) -> Result<bool, CatalogError> {
        // These are exactly the schemas whose file witnesses capture records.
        for (schema, operation) in [
            (c"main", "validate SQLite-opened main catalog object"),
            (c"session", "validate SQLite-opened session catalog object"),
        ] {
            let mut moved: std::ffi::c_int = 0;
            // SAFETY: the connection outlives this call, schema names are static,
            // and HAS_MOVED writes one C int without retaining its pointer.
            // SQLite checks its own descriptor; no foreign descriptor is opened.
            let status = unsafe {
                rusqlite::ffi::sqlite3_file_control(
                    connection.handle(),
                    schema.as_ptr(),
                    rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
                    std::ptr::from_mut(&mut moved).cast(),
                )
            };
            match status {
                rusqlite::ffi::SQLITE_OK if moved != 0 => return Ok(false),
                rusqlite::ffi::SQLITE_OK | rusqlite::ffi::SQLITE_NOTFOUND => {}
                status => {
                    return Err(CatalogError::sqlite(
                        operation,
                        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(status), None),
                    ));
                }
            }
        }
        for file in &self.files {
            // Always stat the path, so an inaccessible catalog path is reported
            // even when no object witness exists. A path that is now missing
            // or not a regular file never matches. The volume is compared even
            // when the filesystem supplies no file index, so a move to another
            // volume is caught; a witness appearing or disappearing counts as a
            // different file. With no object witness on either side,
            // user_version remains the last validation witness.
            let Some(recorded) = file.witness else {
                return Ok(false);
            };
            if pinned_file_witness(&file.path)? != Some(recorded) {
                return Ok(false);
            }
        }
        // Sample versions last: a migration during path validation must not
        // leave an earlier compatible schema sample as the admission witness.
        self.schema_matches(connection)
    }

    /// Recheck both schema versions after the caller pins its read snapshots.
    pub fn schema_matches(&self, connection: &Connection) -> Result<bool, CatalogError> {
        Ok(Self::versions(connection)? == self.versions)
    }
}

/// Prepare request-independent TEMP schema for a pinned reader. No read
/// transaction is held until the caller begins and pins its own snapshot.
pub fn prepare_pinned_reader_connection(
    root: &std::path::Path,
    session_catalog: &Mutex<Option<SessionSemanticCatalog>>,
) -> Result<Connection, CatalogError> {
    prepare_validated_pinned_reader_connection(root, session_catalog)
        .map(|(connection, _)| connection)
}

/// Preserve the replacement guard's witness through checkout and check-in.
pub fn prepare_validated_pinned_reader_connection(
    root: &std::path::Path,
    session_catalog: &Mutex<Option<SessionSemanticCatalog>>,
) -> Result<(Connection, PinnedReaderValidation), CatalogError> {
    for _attempt in 0..2 {
        let session_path = {
            let mut session = session_catalog
                .lock()
                .expect("session semantic catalog mutex poisoned");
            if session.is_none() {
                *session = Some(open_session_semantic_catalog()?);
            }
            session
                .as_ref()
                .expect("session catalog initialized")
                .path
                .clone()
        };
        let before =
            PinnedReaderValidation::capture_files([root.join("catalog.db"), session_path])?;
        #[cfg(test)]
        pinned_validation_tests::between_validation_captures();
        let connection = prepare_pinned_reader_connection_once(root, session_catalog)?;
        #[cfg(test)]
        pinned_validation_tests::after_reader_open();
        let after = PinnedReaderValidation::capture(&connection)?;
        // Comparing paths as well as file identities also detects replacement of
        // the session catalog while preparation was outside its owner lock.
        if before == after.files && after.matches(&connection)? {
            // The read-only open fenced the main schema before preparation.
            // A concurrent migration can advance it before this capture.
            let main_version = after.versions.0;
            if main_version > CATALOG_SCHEMA_VERSION {
                return Err(CatalogError::CatalogTooNew {
                    found: main_version,
                    supported: CATALOG_SCHEMA_VERSION,
                });
            }
            if main_version < CATALOG_SCHEMA_VERSION {
                return Err(CatalogError::ReadOnlySchema {
                    found: main_version,
                    required: CATALOG_SCHEMA_VERSION,
                });
            }
            return Ok((connection, after));
        }
        // Drop the suspect handle before retrying the complete preparation.
    }
    Err(CatalogError::Unavailable)
}

fn prepare_pinned_reader_connection_once(
    root: &std::path::Path,
    session_catalog: &Mutex<Option<SessionSemanticCatalog>>,
) -> Result<Connection, CatalogError> {
    let connection = open_active_reader_connection(root, session_catalog)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(100))
        .map_err(|error| CatalogError::sqlite("bound pinned catalog wait", error))?;
    connection
        .execute_batch(
            "CREATE TEMP TABLE expected_catalog_shards(
            ordinal INTEGER NOT NULL, kind TEXT NOT NULL,
            production_digest TEXT, manifest_digest TEXT,
            shard_key INTEGER, status TEXT NOT NULL
            CHECK(status IN ('present','missing','quarantined','stale'))
        ) STRICT",
        )
        .map_err(|error| CatalogError::sqlite("create expected membership", error))?;
    Ok(connection)
}

/// A cloneable SQL-only bridge for active runtime publication.
///
/// The reader owns fixed database handles and, for an ephemeral catalog, the
/// root keepalive needed by SQLite. It never retains a catalog borrow or a
/// workspace-sized source index.
#[derive(Clone)]
pub struct CatalogRuntimeSourceReader {
    pub root: PathBuf,
    pub connection: Arc<Mutex<Connection>>,
    pub session_catalog: Arc<Mutex<Option<SessionSemanticCatalog>>>,
    pub _ephemeral_root: Option<Arc<TempDir>>,
}

/// One statement's column names and values, released from the reader lock.
#[derive(Debug)]
pub struct OwnedCatalogRows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<rusqlite::types::Value>>,
}

pub struct OwnedCatalogRow<'a> {
    columns: &'a [String],
    values: &'a [rusqlite::types::Value],
}

pub trait OwnedCatalogColumn {
    fn position(self, columns: &[String]) -> rusqlite::Result<usize>;
}

impl OwnedCatalogColumn for usize {
    fn position(self, columns: &[String]) -> rusqlite::Result<usize> {
        if self < columns.len() {
            Ok(self)
        } else {
            Err(rusqlite::Error::InvalidColumnIndex(self))
        }
    }
}

impl OwnedCatalogColumn for &str {
    fn position(self, columns: &[String]) -> rusqlite::Result<usize> {
        columns
            .iter()
            .position(|column| column == self)
            .ok_or_else(|| rusqlite::Error::InvalidColumnName(self.to_owned()))
    }
}

impl<'a> OwnedCatalogRow<'a> {
    pub fn column_index(&self, name: &str) -> rusqlite::Result<usize> {
        name.position(self.columns)
    }

    pub fn get<I: OwnedCatalogColumn, T: rusqlite::types::FromSql>(
        &self,
        index: I,
    ) -> rusqlite::Result<T> {
        let index = index.position(self.columns)?;
        let value = rusqlite::types::ValueRef::from(&self.values[index]);
        T::column_result(value).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(index, value.data_type(), Box::new(error))
        })
    }
}

impl OwnedCatalogRows {
    pub fn iter(&self) -> impl Iterator<Item = OwnedCatalogRow<'_>> {
        self.rows.iter().map(|values| OwnedCatalogRow {
            columns: &self.columns,
            values,
        })
    }
}

/// Bindings use names because catalog questions are shared by both readers.
pub trait CatalogRowReader: Send + Sync {
    /// Unknown dependency content admitted for this request, with closed causes.
    fn jvm_dependency_gaps(&self) -> &[JvmDependencyGap] {
        &[]
    }

    fn owned_rows(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        cancellation: &CancellationToken,
    ) -> Result<OwnedCatalogRows, CatalogError>;
}

/// Identity of the catalog rows visible to one JVM request reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReaderBinding(pub [u8; 32]);

#[derive(Clone)]
pub struct RequestRowReader {
    /// Analysis-owned extension, retained only by this request reader entry.
    pub derivation_extension: Arc<std::sync::OnceLock<Arc<dyn std::any::Any + Send + Sync>>>,
    /// Request-owned providers whose inventory was certified in this request.
    pub certified_providers: std::collections::HashSet<String>,
    pub inventory_generation: Option<i64>,
    /// Verified own publications after certification, shared only by clones
    /// of this OuterRequest's ReaderDerivationMemo entry.
    pub inventory_clock: Option<Arc<super::jvm_external_publication::JvmInventoryPublicationClock>>,
    pub reader: Arc<dyn CatalogRowReader + Send + Sync>,
    pub binding: ReaderBinding,
}

/// The owner of a request's JVM-family catalog rows (#9559). It never creates a request.
pub trait RequestRowReaderSource: std::fmt::Debug + Send + Sync {
    /// Publish activated external providers before readiness. Sources without
    /// external projections have nothing to publish.
    fn publish_activation(
        &self,
        _activation: &crate::analyzer::store::active_models::ResolvedActiveSemanticModels,
        _cancellation: &CancellationToken,
    ) -> Result<(), CatalogError> {
        Ok(())
    }

    fn identity(&self) -> Option<[u8; 32]> {
        None
    }
    /// Whether this source hands back the activation reader itself, so the
    /// activation owner also owns the request-owned shards.
    fn reads_through_activation(&self) -> bool {
        false
    }
    fn jvm_reader(
        &self,
        activation: &crate::analyzer::store::active_models::ResolvedActiveSemanticModels,
    ) -> Result<RequestRowReader, FamilyOpen>;
}

#[derive(Debug)]
pub struct RefusingRowReaderSource {
    pub reason: FamilyOpen,
}

impl RequestRowReaderSource for RefusingRowReaderSource {
    fn identity(&self) -> Option<[u8; 32]> {
        Some(
            brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes(
                b"jvm-refusing-row-source-v1",
                self.reason.reason.as_bytes(),
            ),
        )
    }
    fn jvm_reader(
        &self,
        _activation: &crate::analyzer::store::active_models::ResolvedActiveSemanticModels,
    ) -> Result<RequestRowReader, FamilyOpen> {
        brokk_bifrost_core::profiling::note_with(|| {
            format!("jvm_request_owner open reason={}", self.reason.reason)
        });
        Err(self.reason)
    }
}

/// The 3b-3 placeholder: every shard stays on the activation reader until
/// sub-step (e) replaces this with the request's pinned reader.
#[derive(Debug)]
pub struct ActivationRowReaderSource {
    reader: Arc<CatalogRuntimeSourceReader>,
    binding: ReaderBinding,
}

impl ActivationRowReaderSource {
    pub fn new(reader: Arc<CatalogRuntimeSourceReader>, active_model_set_hash: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"activation-row-reader-v1");
        digest.update(active_model_set_hash.as_bytes());
        Self {
            reader,
            binding: ReaderBinding(digest.finalize().into()),
        }
    }
}

impl RequestRowReaderSource for ActivationRowReaderSource {
    fn reads_through_activation(&self) -> bool {
        true
    }
    fn jvm_reader(
        &self,
        _activation: &crate::analyzer::store::active_models::ResolvedActiveSemanticModels,
    ) -> Result<RequestRowReader, FamilyOpen> {
        Ok(RequestRowReader {
            derivation_extension: Default::default(),
            certified_providers: Default::default(),
            inventory_generation: None,
            inventory_clock: None,
            reader: self.reader.clone(),
            binding: self.binding,
        })
    }
}

impl CatalogRowReader for CatalogRuntimeSourceReader {
    fn owned_rows(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        cancellation: &CancellationToken,
    ) -> Result<OwnedCatalogRows, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("active semantic reader mutex poisoned");
        let mut query = connection
            .prepare_cached(statement)
            .map_err(|error| CatalogError::sqlite("prepare semantic scalar question", error))?;
        let columns = query
            .column_names()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        let mut cursor = query
            .query(bindings)
            .map_err(|error| CatalogError::sqlite("query semantic scalar question", error))?;
        let mut rows = Vec::new();
        while let Some(row) = cursor
            .next()
            .map_err(|error| CatalogError::sqlite("step semantic scalar question", error))?
        {
            if cancellation.is_cancelled() {
                return Err(CatalogError::Cancelled);
            }
            let mut values = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                values.push(row.get(index).map_err(|error| {
                    CatalogError::sqlite("read semantic scalar question", error)
                })?);
            }
            rows.push(values);
        }
        Ok(OwnedCatalogRows { columns, rows })
    }
}

impl fmt::Debug for CatalogRuntimeSourceReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogRuntimeSourceReader")
            .finish_non_exhaustive()
    }
}

/// One raw result owns its record and shares only the selected shard metadata.
#[derive(Debug, Clone)]
pub struct CatalogRawRecord<T> {
    pub record: Arc<T>,
    pub shard: Arc<super::active_models::ActiveSemanticModelShardMetadata>,
}

/// A published active set has no per-question recovery from lost storage.
/// Never turn a failed read into a pack-blind empty semantic answer. An open
/// JVM-family part is not lost storage: it is returned so the caller can carry
/// it in its typed result.
pub fn semantic_catalog_question<T>(
    statement: &str,
    key: impl fmt::Debug,
    answer: Result<T, CatalogError>,
) -> Result<T, FamilyOpen> {
    match answer {
        Ok(answer) => Ok(answer),
        Err(CatalogError::FamilyOpen(open)) => Err(open),
        Err(CatalogError::Cancelled) => Err(FamilyOpen::jvm_cancelled()),
        Err(error) => panic!("active semantic question {statement}, key {key:?}: {error:?}"),
    }
}

/// Bounded questions are limited by their bindings, and their callers observe
/// cancellation between questions, so a bounded question itself never stops.
static UNCANCELLED_QUESTION: std::sync::LazyLock<CancellationToken> =
    std::sync::LazyLock::new(CancellationToken::new);

/// Decoding shared by every catalog row reader, so the activation and a
/// request's pinned reader answer one statement identically.
impl dyn CatalogRowReader + '_ {
    pub fn payload_family_presence(
        &self,
        identity: super::active_models::CatalogShardRowIdentity,
        family: brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily,
    ) -> Result<bool, CatalogError> {
        let source = match identity.database {
            super::active_models::CatalogShardDatabase::Durable => "durable",
            super::active_models::CatalogShardDatabase::Session => "session",
        };
        let rows = self.owned_rows(
            statements::PAYLOAD_FAMILY_PRESENCE,
            rusqlite::named_params! { ":source_db": source, ":shard_key": identity.shard_key,
            ":family": family.as_str() },
            &UNCANCELLED_QUESTION,
        )?;
        rows.iter()
            .next()
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
            .and_then(|row| row.get(0))
            .map_err(|error| CatalogError::sqlite("read semantic payload family presence", error))
    }
    /// Decode the result of one named product statement. Nothing is retained
    /// across questions. Source database is part of every physical row identity.
    pub fn raw_records<T: serde::de::DeserializeOwned>(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        shards: &[Arc<super::active_models::ActiveSemanticModelShard>],
    ) -> Result<Vec<CatalogRawRecord<T>>, CatalogError> {
        self.raw_rows(statement, bindings, shards, |row| {
            let json: String = row.get("record_json")?;
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    row.column_index("record_json")
                        .expect("record column exists"),
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
    }

    /// Request-local scalar projections which do not publish record handles.
    pub fn scalar_question<T>(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        mut read: impl FnMut(&OwnedCatalogRow<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>, CatalogError> {
        self.owned_rows(statement, bindings, &UNCANCELLED_QUESTION)?
            .iter()
            .map(|row| {
                read(&row)
                    .map_err(|error| CatalogError::sqlite("read semantic scalar question", error))
            })
            .collect()
    }

    /// Visit one statement's rows after the reader has released them, so the
    /// visitor never runs under a reader lock. The reader observes
    /// `cancellation` between rows; a read the caller cancelled visits nothing,
    /// and the caller observes its own token afterwards.
    pub fn visit_owned_rows(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        cancellation: Option<&CancellationToken>,
        mut visit: impl FnMut(&OwnedCatalogRow<'_>) -> rusqlite::Result<bool>,
    ) -> Result<(), CatalogError> {
        let rows = match self.owned_rows(
            statement,
            bindings,
            cancellation.unwrap_or(&UNCANCELLED_QUESTION),
        ) {
            Err(CatalogError::Cancelled)
                if cancellation.is_some_and(CancellationToken::is_cancelled) =>
            {
                return Ok(());
            }
            rows => rows?,
        };
        for row in rows.iter() {
            if !visit(&row)
                .map_err(|error| CatalogError::sqlite("read semantic scalar question", error))?
            {
                break;
            }
        }
        Ok(())
    }

    /// Column-only questions (relations, names and payload projections) use the
    /// same active-set/metadata join without inventing persisted JSON records.
    pub fn raw_rows<T>(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        shards: &[Arc<super::active_models::ActiveSemanticModelShard>],
        decode: impl Fn(&OwnedCatalogRow<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<CatalogRawRecord<T>>, CatalogError> {
        use super::active_models::CatalogShardDatabase;
        self.owned_rows(statement, bindings, &UNCANCELLED_QUESTION)?
            .iter()
            .map(|row| {
                let source: String = row.get("source_db")?;
                let shard_key: i64 = row.get("shard_key")?;
                let database = match source.as_str() {
                    "durable" => CatalogShardDatabase::Durable,
                    "session" => CatalogShardDatabase::Session,
                    _ => unreachable!("active view has a validated source database"),
                };
                let shard = shards
                    .iter()
                    .find(|shard| {
                        shard.row_store.is_some_and(|identity| {
                            identity.database == database && identity.shard_key == shard_key
                        })
                    })
                    .expect("active row belongs to selected shard metadata");
                Ok(CatalogRawRecord {
                    record: Arc::new(decode(&row)?),
                    shard: Arc::clone(&shard.metadata),
                })
            })
            .map(|record: rusqlite::Result<_>| {
                record.map_err(|error| CatalogError::sqlite("read raw semantic record", error))
            })
            .collect()
    }

    /// Follow same-shard callees with indexed ID questions. Missing IDs remain
    /// absent, and the visited set terminates cycles without loading the shard.
    pub fn procedure_summary_family<'a>(
        &self,
        shard: &Arc<super::active_models::ActiveSemanticModelShard>,
        roots: impl IntoIterator<Item = &'a str>,
    ) -> Result<Arc<[Arc<crate::analyzer::semantic_model::CompiledProcedureSummary>]>, CatalogError>
    {
        use super::active_models::CatalogShardDatabase;
        use crate::analyzer::semantic_model::CompiledSummaryEffect;
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        let identity = shard
            .row_store
            .expect("row-backed shard has a catalog identity");
        let source = match identity.database {
            CatalogShardDatabase::Durable => "durable",
            CatalogShardDatabase::Session => "session",
        };
        let mut pending = roots.into_iter().map(str::to_owned).collect::<Vec<_>>();
        let mut visited = std::collections::HashSet::new();
        let mut result = Vec::new();
        while let Some(id) = pending.pop() {
            if !visited.insert(id.clone()) {
                continue;
            }
            let records = self.raw_records::<crate::analyzer::semantic_model::CompiledProcedureSummary>(
                statements::SUMMARY_BY_ID,
                rusqlite::named_params! { ":source_db": source, ":shard_key": identity.shard_key, ":id": id },
                std::slice::from_ref(shard),
            )?;
            for record in records {
                for effect in &record.record.effects {
                    match effect {
                        CompiledSummaryEffect::Call { callee, .. } => pending.push(callee.clone()),
                        CompiledSummaryEffect::AmbiguousCall { candidates, .. } => {
                            pending.extend(candidates.iter().cloned())
                        }
                        _ => {}
                    }
                }
                result.push(record.record);
            }
        }
        result.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(result.into())
    }

    /// The first pair is only a fast comparison. The schema does not prove
    /// first (model_id, id) uniqueness across shards: the full-sequence tie-break
    /// is required and must not be removed as redundant.
    pub fn procedure_summary_shard_order(
        &self,
        selected: &Arc<super::active_models::ActiveSemanticModelShard>,
        shards: &[Arc<super::active_models::ActiveSemanticModelShard>],
    ) -> Result<usize, CatalogError> {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        let selected_first = self.summary_order_keys(selected, statements::SUMMARY_SHARD_FIRST)?;
        let mut selected_sequence = None;
        let mut rank = 0;
        for shard in shards.iter().filter(|shard| {
            shard.descriptor.payload_kind
                == crate::analyzer::semantic_model::PayloadKind::ProcedureSummaries
        }) {
            let order = shard.manifest.language.cmp(&selected.manifest.language);
            let order = if order.is_eq() {
                let first = self.summary_order_keys(shard, statements::SUMMARY_SHARD_FIRST)?;
                let order = first.cmp(&selected_first);
                if order.is_eq() {
                    let full = match &selected_sequence {
                        Some(full) => full,
                        None => selected_sequence.insert(
                            self.summary_order_keys(selected, statements::SUMMARY_SHARD_SEQUENCE)?,
                        ),
                    };
                    self.summary_order_keys(shard, statements::SUMMARY_SHARD_SEQUENCE)?
                        .cmp(full)
                } else {
                    order
                }
            } else {
                order
            };
            rank += usize::from(order.is_lt());
        }
        Ok(rank)
    }

    fn summary_order_keys(
        &self,
        shard: &Arc<super::active_models::ActiveSemanticModelShard>,
        statement: &str,
    ) -> Result<Vec<(String, String)>, CatalogError> {
        use super::active_models::CatalogShardDatabase;
        let identity = shard.row_store.expect("summary shard has catalog identity");
        let source = match identity.database {
            CatalogShardDatabase::Durable => "durable",
            CatalogShardDatabase::Session => "session",
        };
        self.owned_rows(
            statement,
            rusqlite::named_params! { ":source_db": source, ":shard_key": identity.shard_key },
            &UNCANCELLED_QUESTION,
        )?
        .iter()
        .map(|row| {
            row.get("model_id")
                .and_then(|model_id| Ok((model_id, row.get("record_id")?)))
                .map_err(|error| CatalogError::sqlite("read summary shard order", error))
        })
        .collect()
    }

    /// Exact payload presence, including present-empty payloads, from the marker.
    pub fn callable_values_presence(
        &self,
        identity: super::active_models::CatalogShardRowIdentity,
    ) -> Result<bool, CatalogError> {
        (self as &dyn CatalogRowReader).payload_family_presence(identity,
            brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily::CallableValues)
    }
}

/// Callable-value and Go source reads run several bounded statements on the
/// activation's own connection. They are not JVM row reads, so they stay on
/// the activation reader.
impl CatalogRuntimeSourceReader {
    /// Reopen an independent view using already admitted shard identities.
    /// Existing readers retain their original membership.
    pub fn reopen_with_shard_keys(
        &self,
        shards: impl IntoIterator<Item = crate::analyzer::store::active_models::CatalogShardRowIdentity>,
    ) -> Result<Self, CatalogError> {
        use crate::analyzer::store::active_models::CatalogShardDatabase;
        let connection = open_active_reader_connection(&self.root, &self.session_catalog)?;
        for shard in shards {
            let source = match shard.database {
                CatalogShardDatabase::Durable => "durable",
                CatalogShardDatabase::Session => "session",
            };
            connection
                .execute(
                    "INSERT INTO temp.active_shards(source_db, shard_key) VALUES (?1, ?2)",
                    params![source, shard.shard_key],
                )
                .map_err(|error| CatalogError::sqlite("reopen active shard membership", error))?;
        }
        Ok(Self {
            root: self.root.clone(),
            connection: Arc::new(Mutex::new(connection)),
            session_catalog: Arc::clone(&self.session_catalog),
            _ephemeral_root: self._ephemeral_root.as_ref().map(Arc::clone),
        })
    }

    pub fn query_callable_values(
        &self,
        query: &CatalogCallableValuesQuery<'_>,
        limits: CatalogCallableValuesQueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("active semantic reader mutex poisoned");
        // Publication is checked once when activation binds this connection.
        query_callable_values_on_connection(&connection, query, limits, cancellation)
    }

    pub fn read_go_source(
        &self,
        request: &CatalogGoSourceRequest<'_>,
        limits: CatalogGoSourceReadLimits,
        cancellation: &CancellationToken,
    ) -> Result<Option<CatalogExactGoSourceSet>, CatalogError> {
        let connection = self
            .connection
            .lock()
            .expect("active semantic reader mutex poisoned");
        read_go_source_from_connection(&connection, request, limits, cancellation)
    }
}

pub fn durable_activation_kind(
    kind: SemanticPackActivationSourceKind,
) -> Option<DurablePackSourceKind> {
    match kind {
        SemanticPackActivationSourceKind::Installed => Some(DurablePackSourceKind::Installed),
        SemanticPackActivationSourceKind::Generated => Some(DurablePackSourceKind::Generated),
        SemanticPackActivationSourceKind::PreShipped => Some(DurablePackSourceKind::PreShipped),
        SemanticPackActivationSourceKind::WorkspaceProduced => {
            Some(DurablePackSourceKind::WorkspaceProduced)
        }
        SemanticPackActivationSourceKind::Embedded
        | SemanticPackActivationSourceKind::EphemeralWorkspace => None,
    }
}

pub fn parse_semantic_pack_activation_source_kind(
    value: &str,
) -> Option<SemanticPackActivationSourceKind> {
    match value {
        "installed" => Some(SemanticPackActivationSourceKind::Installed),
        "generated" => Some(SemanticPackActivationSourceKind::Generated),
        "pre_shipped" => Some(SemanticPackActivationSourceKind::PreShipped),
        "workspace_produced" => Some(SemanticPackActivationSourceKind::WorkspaceProduced),
        "embedded" => Some(SemanticPackActivationSourceKind::Embedded),
        "ephemeral_workspace" => Some(SemanticPackActivationSourceKind::EphemeralWorkspace),
        _ => None,
    }
}

pub fn activation_catalog_kind(kind: SemanticPackActivationSourceKind) -> CatalogPackSourceKind {
    match kind {
        SemanticPackActivationSourceKind::Installed => CatalogPackSourceKind::Installed,
        SemanticPackActivationSourceKind::Generated => CatalogPackSourceKind::Generated,
        SemanticPackActivationSourceKind::PreShipped => CatalogPackSourceKind::PreShipped,
        SemanticPackActivationSourceKind::WorkspaceProduced => {
            CatalogPackSourceKind::WorkspaceProduced
        }
        SemanticPackActivationSourceKind::Embedded => CatalogPackSourceKind::Embedded,
        SemanticPackActivationSourceKind::EphemeralWorkspace => {
            CatalogPackSourceKind::EphemeralWorkspace
        }
    }
}

#[cfg(test)]
mod source_identity_properties {
    use super::*;
    use crate::analyzer::store::{AnalyzerStore, SemanticPackActiveReference};

    #[test]
    fn catalog_source_identities_round_trip_through_active_rows() {
        use SemanticPackActivationSourceKind as Activation;
        // Literal SQL spellings and expected kinds are the external contract;
        // identical digest/source pairs deliberately cannot disambiguate kinds.
        let cases = [
            (
                "installed",
                Activation::Installed,
                Some(DurablePackSourceKind::Installed),
            ),
            (
                "generated",
                Activation::Generated,
                Some(DurablePackSourceKind::Generated),
            ),
            (
                "pre_shipped",
                Activation::PreShipped,
                Some(DurablePackSourceKind::PreShipped),
            ),
            (
                "workspace_produced",
                Activation::WorkspaceProduced,
                Some(DurablePackSourceKind::WorkspaceProduced),
            ),
            ("embedded", Activation::Embedded, None),
            ("ephemeral_workspace", Activation::EphemeralWorkspace, None),
        ];
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sources.db");
        for (literal, activation, durable) in cases {
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            let source_kind = match durable {
                Some(kind) => {
                    assert_eq!(durable_activation_kind(activation), Some(kind));
                    CatalogPackSourceKind::from(kind)
                }
                None => CatalogPackSourceKind::from(match activation {
                    Activation::Embedded => SessionPackSourceKind::Embedded,
                    Activation::EphemeralWorkspace => SessionPackSourceKind::EphemeralWorkspace,
                    _ => unreachable!(),
                }),
            };
            let member = SemanticPackActiveReference {
                manifest_digest: "a".repeat(64),
                source_kind: activation,
                source_id: "same-source".into(),
                workspace_produced: matches!(
                    activation,
                    Activation::WorkspaceProduced | Activation::EphemeralWorkspace
                ),
            };
            store
                .replace_semantic_pack_active_set(std::slice::from_ref(&member))
                .unwrap();
            {
                let conn = Connection::open(&path).unwrap();
                let stored: String = conn
                    .query_row(
                        "SELECT source_kind FROM semantic_pack_active_members",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(stored, literal);
                assert_eq!(source_kind.as_str(), stored);
                assert_eq!(CatalogPackSourceKind::parse(&stored).unwrap(), source_kind);
                if let Some(kind) = durable {
                    assert_eq!(kind.as_str(), stored);
                    assert_eq!(DurablePackSourceKind::parse(&stored).unwrap(), kind);
                }
            }
            drop(store);
            let reopened = AnalyzerStore::open_persistent(&path).unwrap();
            assert_eq!(
                reopened
                    .semantic_pack_active_set()
                    .unwrap()
                    .unwrap()
                    .members,
                vec![member]
            );
        }
    }
}

#[cfg(test)]
mod semantic_row_plan_tests {
    use super::*;
    use crate::analyzer::store::planner_statistics::pinned_plans::{
        plan_rows, semantic_catalog_pins,
    };
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    fn seed(connection: &Connection) {
        seed_records(connection, 256);
    }

    fn seed_records(connection: &Connection, records: usize) {
        connection.execute_batch(&r#"
            INSERT INTO catalog_packs(manifest_digest,state) VALUES(printf('%064d',1),'verified');
            INSERT INTO catalog_pack_shards(manifest_digest,shard_id) VALUES(printf('%064d',1),'s');
            INSERT INTO catalog_semantic_rows_indexed_shards(shard_key,manifest_digest,shard_id,index_version) VALUES(1,printf('%064d',1),'s',4);
            WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<256)
            INSERT INTO catalog_declaration_types(record_key,shard_key,record_id,authored_path,record_json)
            SELECT v,1,'Type'||v,'src/source'||v||'.rs','{"type_kind":"trait"}' FROM n;
            INSERT INTO catalog_declaration_names(shard_key,record_key,name,language,namespace,identity_name)
            SELECT 1,record_key,record_id,'rust','type',1 FROM catalog_declaration_types;
            INSERT INTO catalog_declaration_members(record_key,shard_key,record_id,owner_id,name,language,authored_path,record_json)
            SELECT record_key,1,'member'||record_key,'Owner'||record_key,'name'||record_key,'rust','src/source'||record_key||'.rs','{}' FROM catalog_declaration_types;
            INSERT INTO catalog_member_aliases(shard_key,member_key,alias)
            SELECT 1,record_key,'alias'||record_key FROM catalog_declaration_members;
            INSERT INTO catalog_declaration_relations(shard_key,origin,record_id,from_id,to_id,relation_kind)
            SELECT 1,'relation_fact','relation'||record_key,record_id,'Base'||record_key,'references' FROM catalog_declaration_types;
            INSERT INTO catalog_procedure_summaries(shard_key,language,target_path,target_symbol,owner_fqn,member,has_receiver,declared_arity,variadic,minimum_actual_count,record_json)
            SELECT 1,'rust','path'||record_key,'symbol'||record_key,'Owner'||record_key,'name'||record_key,0,0,0,0,
              json_object('id','sum'||record_key,'model_id','pack.sum'||record_key) FROM catalog_declaration_types;
        "#.replace("v<256", &format!("v<{records}"))).unwrap();
    }

    #[test]
    fn semantic_source_locator_candidates_match_changed_path_containment() {
        use brokk_bifrost_core::analyzer::changed_paths::ChangedPaths;
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        use std::collections::BTreeSet;
        use std::path::Path;
        let durable = open_session_semantic_catalog().unwrap();
        let session = open_session_semantic_catalog().unwrap();
        for catalog in [&durable, &session] {
            seed(&catalog.connection);
            for table in ["catalog_declaration_types", "catalog_declaration_members"] {
                catalog.connection.execute(&format!("UPDATE {table} SET authored_path='src/source17.rs/nested.rs' WHERE record_key=18"), []).unwrap();
                catalog.connection.execute(&format!("UPDATE {table} SET authored_path='src2/source17.rs' WHERE record_key=19"), []).unwrap();
            }
        }
        rows::attach_session_rows(&durable.connection, &session).unwrap();
        for source in ["durable", "session"] {
            rows::select_active_shard_source(
                &durable.connection,
                &format!("{:064}", 1),
                "s",
                source,
            )
            .unwrap()
            .unwrap();
        }
        for (sql, table) in [
            (
                statements::SOURCE_TYPES_TOUCHING_PATH,
                "active_catalog_declaration_types",
            ),
            (
                statements::SOURCE_MEMBERS_TOUCHING_PATH,
                "active_catalog_declaration_members",
            ),
        ] {
            let protected = durable
                .connection
                .prepare(&format!("SELECT DISTINCT authored_path FROM {table}"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<BTreeSet<_>>>()
                .unwrap();
            for changed in [
                "src",
                "src/source17.rs",
                "src/source17.rs/nested.rs/child.rs",
                "src2",
                "src3",
            ] {
                let change = ChangedPaths::literal([Path::new(changed)]);
                let expected = protected
                    .iter()
                    .filter(|path| change.touches(Path::new(path)))
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let ancestors = serde_json::to_string(
                    &Path::new(changed)
                        .ancestors()
                        .filter(|path| !path.as_os_str().is_empty())
                        .map(|path| path.to_string_lossy().replace('\\', "/"))
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                let actual = durable
                    .connection
                    .prepare(sql)
                    .unwrap()
                    .query_map(
                        rusqlite::named_params! {
                            ":ancestors": &ancestors,
                            ":descendant_start": &format!("{changed}/"),
                            ":descendant_end": &format!("{changed}0"),
                        },
                        |row| row.get::<_, String>("authored_path"),
                    )
                    .unwrap()
                    .collect::<rusqlite::Result<BTreeSet<_>>>()
                    .unwrap();
                assert_eq!(actual, expected, "{table}: {changed}");
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6685: active views read the 7.8 MB manifest BLOB overflow chain on every row to check pack state"
    )]
    fn semantic_catalog_questions_never_recheck_pack_state_in_both_statistics_states() {
        use crate::analyzer::store::planner_statistics::pinned_plans::plan_rows_for_sql;
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements::RAW_STATEMENTS;
        for state in PlannerStatisticsState::BOTH {
            let durable = open_session_semantic_catalog().unwrap();
            let session = open_session_semantic_catalog().unwrap();
            seed(&durable.connection);
            seed(&session.connection);
            rows::attach_session_rows(&durable.connection, &session).unwrap();
            for source in ["durable", "session"] {
                assert!(
                    rows::select_active_shard_source(
                        &durable.connection,
                        &format!("{:064}", 1),
                        "s",
                        source
                    )
                    .unwrap()
                    .is_some()
                );
            }
            state.install(&durable.connection);
            let mut plans = semantic_catalog_pins()
                .into_iter()
                .map(|(query, _)| {
                    (
                        query.name.to_owned(),
                        plan_rows(&durable.connection, &query).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            for &(name, sql) in RAW_STATEMENTS {
                let count = durable.connection.prepare(sql).unwrap().parameter_count();
                let params = vec![rusqlite::types::Value::Null; count];
                plans.push((
                    name.to_owned(),
                    plan_rows_for_sql(&durable.connection, sql, &params).unwrap(),
                ));
            }
            for (name, plan) in plans {
                assert!(
                    plan.iter().all(|line| !line.contains("catalog_packs")),
                    "{state} {name}: active membership must not read pack metadata: {plan:?}"
                );
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6685: candidate search rescanned every owner name for each member spelling"
    )]
    fn semantic_catalog_keyed_questions_use_pinned_indexes_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let durable = open_session_semantic_catalog().unwrap();
            let session = open_session_semantic_catalog().unwrap();
            seed(&durable.connection);
            seed(&session.connection);
            rows::attach_session_rows(&durable.connection, &session).unwrap();
            rows::select_active_shard_source(
                &durable.connection,
                &format!("{:064}", 1),
                "s",
                "durable",
            )
            .unwrap();
            rows::select_active_shard_source(
                &durable.connection,
                &format!("{:064}", 1),
                "s",
                "session",
            )
            .unwrap();
            state.install(&durable.connection);
            for (query, index) in semantic_catalog_pins() {
                let plan = plan_rows(&durable.connection, &query).unwrap();
                let uses = plan
                    .iter()
                    .filter(|line| line.contains(index) && line.contains("SEARCH"))
                    .count();
                if query.name == "semantic_search_candidates" {
                    assert!(uses > 0, "{state}: owner map must be indexed: {plan:?}");
                    assert!(
                        plan.iter().any(|line| line
                            .contains("SEARCH o USING AUTOMATIC COVERING INDEX")
                            && line.contains("language=?")
                            && line.contains("owner_id=?")),
                        "{state}: owner lookup must seek both key columns: {plan:?}"
                    );
                    assert_eq!(
                        plan.iter()
                            .filter(|line| line.contains("MATERIALIZE owner_names"))
                            .count(),
                        1,
                        "{state}: owner JSON must be materialized once: {plan:?}"
                    );
                    assert_eq!(
                        plan.iter()
                            .filter(|line| line.contains("SCAN owner_json VIRTUAL TABLE"))
                            .count(),
                        1,
                        "{state}: owner JSON must be scanned only for materialization: {plan:?}"
                    );
                    assert!(
                        plan.iter().all(
                            |line| !line.contains("CORRELATED") && !line.starts_with("SCAN o ")
                        ),
                        "{state}: candidates cannot rescan the owner map: {plan:?}"
                    );
                    eprintln!("{state}: indexed search owner plan: {plan:?}");
                } else {
                    assert!(
                        uses >= 2,
                        "{state} {}: expected {index} in both source branches: {plan:?}",
                        query.name
                    );
                }
                if [
                    "semantic_search_owner_qualifications",
                    "semantic_search_types_by_ids",
                    "semantic_search_members_by_ids",
                ]
                .contains(&query.name.as_str())
                {
                    assert!(
                        plan.iter()
                            .all(|line| !line.contains("MATERIALIZE active_catalog_declaration_")),
                        "{state}: indexed search cannot materialize whole active records: {plan:?}"
                    );
                    assert_eq!(
                        plan.iter()
                            .filter(|line| line.contains("SCAN json_each VIRTUAL TABLE"))
                            .count(),
                        1,
                        "{state}: requested IDs must be decoded once: {plan:?}"
                    );
                }
                if ["semantic_source_type_paths", "semantic_source_member_paths"]
                    .contains(&query.name.as_str())
                {
                    assert!(
                        plan.iter().all(|line| line != "SCAN r"
                            && !line.starts_with("SCAN r ")
                            && !line.contains("MATERIALIZE active_catalog_declaration_")),
                        "{state} {}: locator paths must seek the existing path indexes: {plan:?}",
                        query.name
                    );
                }
                // A dotted name runs these once per dot boundary, so a scan
                // here multiplies by every policy locator (#10397).
                if [
                    "semantic_member_owner_name",
                    "semantic_member_qualified",
                    "semantic_member_alias_qualified",
                ]
                .contains(&query.name.as_str())
                {
                    // Inside the active views every record table is `r`. The
                    // split join seeked `r` on `shard_key` alone, which walks
                    // the whole shard, with the split table as the inner loop.
                    assert!(
                        plan.iter().all(|line| !line.starts_with("SCAN r")
                            && !(line.starts_with("SEARCH r ") && line.ends_with("(shard_key=?)"))
                            && !line.contains("VIRTUAL TABLE")
                            && !line.contains("MATERIALIZE")
                            && !line.contains("CO-ROUTINE")
                            && !line.contains("AUTOMATIC")),
                        "{state} {}: member lookups must seek every record table: {plan:?}",
                        query.name
                    );
                    eprintln!("{state} {}: member lookup plan: {plan:?}", query.name);
                }
                if query.name == "semantic_summary_id" {
                    let keyed = plan
                        .iter()
                        .filter(|line| {
                            line.contains(index) && line.contains("shard_key=? AND record_id=?")
                        })
                        .count();
                    assert!(
                        keyed >= 2,
                        "{state}: summary dependency reads must seek both ID-index columns: {plan:?}"
                    );
                    eprintln!("{state}: summary-ID keyed plan: {plan:?}");
                }
            }
            for (name, sql) in statements::RAW_STATEMENTS {
                durable
                    .connection
                    .prepare(sql)
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: the relation reads filtered every relation row of every active shard, about 10 ms a statement"
    )]
    fn overlay_relation_reads_return_the_rows_of_the_in_list_form_in_both_statistics_states() {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        // The shipped form before the plan fix, kept here as the oracle.
        let old_from = "SELECT r.* FROM active_catalog_declaration_relations AS r \
                        WHERE r.from_id IN (SELECT value FROM json_each(:owner_ids));";
        let old_to = "SELECT r.* FROM active_catalog_declaration_relations AS r \
                      WHERE r.to_id IN (SELECT value FROM json_each(:raw_targets));";
        for state in PlannerStatisticsState::BOTH {
            let durable = open_session_semantic_catalog().unwrap();
            let session = open_session_semantic_catalog().unwrap();
            seed(&durable.connection);
            seed(&session.connection);
            for connection in [&durable.connection, &session.connection] {
                // Several relations per endpoint, two kinds, and a shared target.
                connection
                    .execute_batch(
                        "INSERT INTO catalog_declaration_relations(shard_key,origin,record_id,from_id,to_id,relation_kind)
                         SELECT 1,'relation_fact','extra'||record_key,record_id,'Base'||(record_key%7),'extends'
                         FROM catalog_declaration_types;",
                    )
                    .unwrap();
            }
            rows::attach_session_rows(&durable.connection, &session).unwrap();
            for source in ["durable", "session"] {
                rows::select_active_shard_source(
                    &durable.connection,
                    &format!("{:064}", 1),
                    "s",
                    source,
                )
                .unwrap();
            }
            state.install(&durable.connection);
            let read = |sql: &str, ids: &str| {
                let mut statement = durable.connection.prepare(sql).unwrap();
                let columns = statement.column_count();
                let mut rows = statement
                    .query_map([ids], |row| {
                        (0..columns)
                            .map(|column| row.get::<_, rusqlite::types::Value>(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .map(|values| format!("{values:?}"))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                rows.sort();
                rows
            };
            let mut checked_rows = 0;
            for (old, new, prefix) in [
                (old_from, statements::OVERLAY_RELATIONS_FROM, "Type"),
                (old_to, statements::OVERLAY_RELATIONS_TO, "Base"),
            ] {
                for ids in [
                    r#"[]"#.to_owned(),
                    format!(r#"["{prefix}17"]"#),
                    format!(r#"["{prefix}17","{prefix}17","{prefix}3"]"#),
                    format!(r#"["{prefix}999","{prefix}5","{prefix}6"]"#),
                    format!(r#"["{prefix}999"]"#),
                ] {
                    let expected = read(old, &ids);
                    assert_eq!(read(new, &ids), expected, "{state} {prefix} {ids}");
                    checked_rows += expected.len();
                }
            }
            assert!(
                checked_rows > 0,
                "{state}: the fixture must return relation rows"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10397: dotted member lookup scanned the catalog for every split"
    )]
    fn dotted_member_lookup_steps_do_not_grow_with_the_catalog() {
        use brokk_bifrost_semantic::analyzer::semantic::oracle::dispatch::owner_member_splits;
        use rusqlite::StatementStatus;
        // `RowOverlay::symbols_named` runs these three statements for each dot
        // boundary of a qualified name.
        let lookup = |records: usize, state: PlannerStatisticsState| {
            let durable = open_session_semantic_catalog().unwrap();
            let session = open_session_semantic_catalog().unwrap();
            for connection in [&durable.connection, &session.connection] {
                seed_records(connection, records);
                connection
                    .execute_batch(
                        "UPDATE catalog_declaration_names SET name='std.io.'||name;
                         UPDATE catalog_declaration_members SET owner_id='Type'||record_key;",
                    )
                    .unwrap();
            }
            rows::attach_session_rows(&durable.connection, &session).unwrap();
            for source in ["durable", "session"] {
                rows::select_active_shard_source(
                    &durable.connection,
                    &format!("{:064}", 1),
                    "s",
                    source,
                )
                .unwrap();
            }
            state.install(&durable.connection);
            let (mut found, mut vm_steps, mut scan_steps) = (0, 0, 0);
            for (owner, member) in owner_member_splits("std.io.Type17.name17") {
                for sql in [
                    statements::MEMBERS_QUALIFIED,
                    statements::MEMBERS_ALIAS_QUALIFIED,
                    statements::MEMBERS_BY_OWNER_NAME,
                ] {
                    let mut statement = durable.connection.prepare(sql).unwrap();
                    found += statement
                        .query(rusqlite::params![owner, member])
                        .unwrap()
                        .mapped(|_| Ok(()))
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap()
                        .len();
                    vm_steps += statement.get_status(StatementStatus::VmStep);
                    scan_steps += statement.get_status(StatementStatus::FullscanStep);
                }
            }
            (found, vm_steps, scan_steps)
        };
        // Index depth can add a few VM steps; a catalog scan multiplies them
        // by the record count.
        for state in PlannerStatisticsState::BOTH {
            let small = lookup(256, state);
            let large = lookup(16384, state);
            assert!(
                small.0 > 0,
                "{state}: the qualified member must be found: {small:?}"
            );
            assert!(
                small.0 == large.0 && small.2 == large.2 && large.1 < 2 * small.1,
                "{state}: (rows, VM steps, full-scan steps) grew with the catalog: \
                 256 records {small:?}, 16384 records {large:?}"
            );
            eprintln!(
                "{state}: dotted member lookup (rows, VM steps, full-scan steps): 256 records {small:?}, 16384 records {large:?}"
            );
        }
    }
}

#[cfg(test)]
mod pinned_validation_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CaptureHooks {
        before_open: Box<dyn FnMut()>,
        after_open: Box<dyn FnMut()>,
    }

    thread_local! {
        static BETWEEN_VALIDATION_CAPTURES: RefCell<Option<CaptureHooks>> =
            const { RefCell::new(None) };
    }

    pub(super) fn between_validation_captures() {
        BETWEEN_VALIDATION_CAPTURES.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                (hook.before_open)();
            }
        });
    }

    pub(super) fn after_reader_open() {
        BETWEEN_VALIDATION_CAPTURES.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                (hook.after_open)();
            }
        });
    }

    /// `db::open` uses `SQLITE_OPEN_NOFOLLOW`, which refuses a symlink in any
    /// path component. The macOS temporary directory sits under `/var`, a
    /// symlink to `/private/var`, so create test roots in the canonical
    /// temporary directory, as product callers open from a canonical root.
    fn canonical_tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    fn with_capture_hook<T>(hook: impl FnMut() + 'static, read: impl FnOnce() -> T) -> T {
        with_capture_hooks(hook, || {}, read)
    }

    fn with_capture_hooks<T>(
        before_open: impl FnMut() + 'static,
        after_open: impl FnMut() + 'static,
        read: impl FnOnce() -> T,
    ) -> T {
        struct ResetHook;
        impl Drop for ResetHook {
            fn drop(&mut self) {
                BETWEEN_VALIDATION_CAPTURES.with(|hook| *hook.borrow_mut() = None);
            }
        }
        BETWEEN_VALIDATION_CAPTURES.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(CaptureHooks {
                before_open: Box::new(before_open),
                after_open: Box::new(after_open),
            });
        });
        let _reset = ResetHook;
        read()
    }

    #[test]
    #[hardwon("#14393: a WAL checkpoint was mistaken for replacement during reader preparation")]
    fn pinned_preparation_accepts_concurrent_checkpoint() {
        let root = canonical_tempdir();
        let writer = db::open(root.path(), CatalogOpenMode::ReadWrite).unwrap();
        writer
            .execute_batch("CREATE TABLE checkpoint_probe(value BLOB); VACUUM; PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let path = root.path().join("catalog.db");
        // None on a filesystem with no file index; the checkpoint must still
        // be accepted, and the witness (if any) must stay the same.
        let object = brokk_bifrost_core::content_digest::file_identity(&path)
            .unwrap()
            .unwrap()
            .object_identity();
        let schema: i64 = writer
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let session = Mutex::new(None);
        let prepared = with_capture_hook(
            move || {
                let before = std::fs::metadata(&path).unwrap().len();
                writer
                    .execute("INSERT INTO checkpoint_probe VALUES(zeroblob(8192))", [])
                    .unwrap();
                let checkpoint: (i64, i64, i64) = writer
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                    .unwrap();
                assert_eq!(checkpoint, (0, 0, 0));
                assert!(std::fs::metadata(&path).unwrap().len() > before);
                assert_eq!(
                    object,
                    brokk_bifrost_core::content_digest::file_identity(&path)
                        .unwrap()
                        .unwrap()
                        .object_identity()
                );
                assert_eq!(
                    writer
                        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    schema
                );
                observed.fetch_add(1, Ordering::SeqCst);
            },
            || prepare_validated_pinned_reader_connection(root.path(), &session),
        );
        let (reader, witness) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => panic!(
                "unchanged catalog object/schema refused after {} checkpoint windows: {error:?}",
                calls.load(Ordering::SeqCst)
            ),
        };
        assert!(witness.matches(&reader).unwrap());
        let rows: i64 = reader
            .query_row("SELECT count(*) FROM checkpoint_probe", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, i64::try_from(calls.load(Ordering::SeqCst)).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_preparation_refuses_replacement_between_captures() {
        let root = canonical_tempdir();
        drop(db::open(root.path(), CatalogOpenMode::ReadWrite).unwrap());
        let path = root.path().join("catalog.db");
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let session = Mutex::new(None);
        let prepared = with_capture_hook(
            move || {
                let original = brokk_bifrost_core::content_digest::file_identity(&path)
                    .unwrap()
                    .unwrap()
                    .object_identity()
                    .unwrap();
                let replacement = tempfile::tempdir_in(path.parent().unwrap()).unwrap();
                drop(db::open(replacement.path(), CatalogOpenMode::ReadWrite).unwrap());
                std::fs::rename(replacement.path().join("catalog.db"), &path).unwrap();
                assert_ne!(
                    original,
                    brokk_bifrost_core::content_digest::file_identity(&path)
                        .unwrap()
                        .unwrap()
                        .object_identity()
                        .unwrap()
                );
                observed.fetch_add(1, Ordering::SeqCst);
            },
            || prepare_validated_pinned_reader_connection(root.path(), &session),
        );
        assert!(matches!(prepared, Err(CatalogError::Unavailable)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#14393: restored pathname samples admitted a different SQLite-opened database")]
    fn pinned_preparation_refuses_restored_path_with_different_open_file() {
        let root = canonical_tempdir();
        let other = canonical_tempdir();
        for (directory, value) in [(root.path(), "A"), (other.path(), "B")] {
            let writer = db::open(directory, CatalogOpenMode::ReadWrite).unwrap();
            writer
                .execute_batch("CREATE TABLE object_probe(value TEXT); PRAGMA journal_mode=DELETE")
                .unwrap();
            writer
                .execute("INSERT INTO object_probe VALUES(?1)", [value])
                .unwrap();
        }
        let session = Mutex::new(None);
        assert_restored_path_refused(
            root.path(),
            &session,
            root.path().join("catalog.db"),
            other.path().join("catalog.db"),
            |reader| {
                reader
                    .query_row("SELECT value FROM object_probe", [], |r| r.get(0))
                    .unwrap()
            },
        );
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#14393: restored session path samples admitted a different attached database")]
    fn pinned_preparation_refuses_restored_session_with_different_open_file() {
        let root = canonical_tempdir();
        drop(db::open(root.path(), CatalogOpenMode::ReadWrite).unwrap());
        let session_a = open_session_semantic_catalog().unwrap();
        let session_b = open_session_semantic_catalog().unwrap();
        for (catalog, value) in [(&session_a, "A"), (&session_b, "B")] {
            catalog
                .connection
                .execute_batch("CREATE TABLE object_probe(value TEXT); PRAGMA journal_mode=DELETE")
                .unwrap();
            catalog
                .connection
                .execute("INSERT INTO object_probe VALUES(?1)", [value])
                .unwrap();
        }
        let path = session_a.path.clone();
        let path_b = session_b.path.clone();
        let session = Mutex::new(Some(session_a));
        assert_restored_path_refused(root.path(), &session, path, path_b, |reader| {
            reader
                .query_row("SELECT value FROM session.object_probe", [], |r| r.get(0))
                .unwrap()
        });
    }

    #[cfg(unix)]
    fn assert_restored_path_refused(
        root: &std::path::Path,
        session: &Mutex<Option<SessionSemanticCatalog>>,
        path: PathBuf,
        path_b: PathBuf,
        probe: impl FnOnce(&Connection) -> String,
    ) {
        let saved_a = path.with_file_name("saved-a.db");
        let original = brokk_bifrost_core::content_digest::file_identity(&path)
            .unwrap()
            .unwrap()
            .object_identity();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let prepared = with_capture_hooks(
            {
                let path = path.clone();
                let saved_a = saved_a.clone();
                let path_b = path_b.clone();
                move || {
                    std::fs::rename(&path, &saved_a).unwrap();
                    std::fs::rename(&path_b, &path).unwrap();
                }
            },
            move || {
                std::fs::rename(&path, &path_b).unwrap();
                std::fs::rename(&saved_a, &path).unwrap();
                assert_eq!(
                    original,
                    brokk_bifrost_core::content_digest::file_identity(&path)
                        .unwrap()
                        .unwrap()
                        .object_identity()
                );
                observed.fetch_add(1, Ordering::SeqCst);
            },
            || prepare_validated_pinned_reader_connection(root, session),
        );
        match prepared {
            Err(CatalogError::Unavailable) => {}
            Err(error) => panic!("unexpected restored-path refusal: {error:?}"),
            Ok((reader, _)) => {
                let opened = probe(&reader);
                panic!("pathname restored to A but reader admitted database {opened}");
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[hardwon("#14393: preparation adopted a catalog schema migrated after the open fence")]
    fn pinned_preparation_refuses_schema_migration_after_open() {
        let root = canonical_tempdir();
        let writer = db::open(root.path(), CatalogOpenMode::ReadWrite).unwrap();
        let session = Mutex::new(None);
        let prepared = with_capture_hooks(
            || {},
            move || {
                writer
                    .pragma_update(None, "user_version", CATALOG_SCHEMA_VERSION + 1)
                    .unwrap();
                let checkpoint: (i64, i64, i64) = writer
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                    .unwrap();
                assert_eq!(checkpoint, (0, 0, 0));
            },
            || prepare_validated_pinned_reader_connection(root.path(), &session),
        );
        match prepared {
            Err(CatalogError::CatalogTooNew { found, supported }) => {
                assert_eq!(found, CATALOG_SCHEMA_VERSION + 1);
                assert_eq!(supported, CATALOG_SCHEMA_VERSION);
            }
            Err(error) => panic!("unexpected schema-fence refusal: {error:?}"),
            Ok((reader, _)) => {
                let version: i64 = reader
                    .query_row("PRAGMA user_version", [], |r| r.get(0))
                    .unwrap();
                panic!("prepared reader adopted unsupported catalog schema {version}");
            }
        }
    }

    #[test]
    fn pinned_preparation_refuses_truncation_between_captures() {
        let root = canonical_tempdir();
        drop(db::open(root.path(), CatalogOpenMode::ReadWrite).unwrap());
        let path = root.path().join("catalog.db");
        let session = Mutex::new(None);
        let prepared = with_capture_hook(
            move || {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(0)
                    .unwrap()
            },
            || prepare_validated_pinned_reader_connection(root.path(), &session),
        );
        assert!(matches!(
            prepared,
            Err(CatalogError::ReadOnlySchema { found: 0, .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#14393: foreign descriptor closes released SQLite's process-owned locks")]
    fn pinned_validation_preserves_writer_lock() {
        const CHILD_PATH: &str = "BIFROST_14393_LOCK_PROBE_DATABASE";
        const TEST: &str = "analyzer::store::model_catalog::pinned_validation_tests::pinned_validation_preserves_writer_lock";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let probe = Connection::open(path).unwrap();
            probe.busy_timeout(std::time::Duration::ZERO).unwrap();
            match probe.execute_batch("BEGIN IMMEDIATE") {
                Err(error) => assert_eq!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                ),
                Ok(()) => {
                    probe.execute_batch("ROLLBACK").unwrap();
                    panic!("reader validation released another connection's writer lock");
                }
            }
            return;
        }
        let root = canonical_tempdir();
        drop(db::open(root.path(), CatalogOpenMode::ReadWrite).unwrap());
        let path = root.path().join("catalog.db");
        let writer = Connection::open(&path).unwrap();
        // A rollback-journal writer holds POSIX locks on the main database.
        // WAL writer locks live in -shm, a different inode from this witness.
        writer
            .execute_batch("PRAGMA journal_mode=DELETE; BEGIN IMMEDIATE")
            .unwrap();
        let session = Mutex::new(None);
        let (reader, witness) =
            prepare_validated_pinned_reader_connection(root.path(), &session).unwrap();
        assert!(witness.matches(&reader).unwrap());
        drop(witness);
        drop(reader);
        // SQLite also tracks locks inside the process; a second process is
        // required to observe whether the actual kernel lock survived.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD_PATH, &path)
            .output()
            .unwrap();
        writer.execute_batch("ROLLBACK").unwrap();
        assert!(
            output.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[hardwon(
        "#14393: a catalog path that became a directory matched a pinned witness recorded without a file index"
    )]
    fn pinned_witness_without_file_index_refuses_a_non_regular_path() {
        // The SQLite files stay untouched, so HAS_MOVED and user_version pass and
        // only the witness loop of PinnedReaderValidation::matches can refuse.
        // No standard test filesystem lacks file indexes, so the main entry's
        // recorded witness drops its object identity to stand in for one, and
        // its recorded path points at a separate file that becomes a directory.
        let root = tempfile::tempdir().unwrap();
        let main = root.path().join("catalog.db");
        let session = root.path().join("session.db");
        let connection = Connection::open(&main).unwrap();
        connection
            .execute("ATTACH ?1 AS session", [session.to_str().unwrap()])
            .unwrap();
        connection
            .execute_batch("PRAGMA main.user_version=7; PRAGMA session.user_version=3")
            .unwrap();
        let mut validation = PinnedReaderValidation::capture(&connection).unwrap();
        assert!(validation.matches(&connection).unwrap());
        let alias = root.path().join("replaced.db");
        std::fs::write(&alias, b"catalog").unwrap();
        let mut recorded = pinned_file_witness(&alias).unwrap().unwrap();
        recorded.object = None;
        let entry = validation
            .files
            .iter_mut()
            .find(|file| file.path == main.canonicalize().unwrap() || file.path == main)
            .expect("main catalog entry");
        entry.path = alias.clone();
        entry.witness = Some(recorded);
        std::fs::remove_file(&alias).unwrap();
        std::fs::create_dir(&alias).unwrap();
        assert!(!validation.matches(&connection).unwrap());
        // A removed path is a mismatch too, never an error, so the stale
        // connection is discarded and preparation retries.
        std::fs::remove_dir(&alias).unwrap();
        assert!(!validation.matches(&connection).unwrap());
    }

    #[test]
    fn pinned_validation_checks_versions_and_file_replacement() {
        let root = tempfile::tempdir().unwrap();
        let main = root.path().join("catalog.db");
        let session = root.path().join("session.db");
        let connection = Connection::open(&main).unwrap();
        connection
            .execute("ATTACH ?1 AS session", [session.to_str().unwrap()])
            .unwrap();
        connection
            .execute_batch("PRAGMA main.user_version=7; PRAGMA session.user_version=3")
            .unwrap();
        let witness = PinnedReaderValidation::capture(&connection).unwrap();
        assert!(witness.matches(&connection).unwrap());
        connection
            .execute_batch("PRAGMA session.user_version=4")
            .unwrap();
        assert!(!witness.matches(&connection).unwrap());
        let witness = PinnedReaderValidation::capture(&connection).unwrap();
        connection
            .execute_batch("PRAGMA main.user_version=8")
            .unwrap();
        assert!(!witness.matches(&connection).unwrap());
        #[cfg(unix)]
        {
            let witness = PinnedReaderValidation::capture(&connection).unwrap();
            let replacement = root.path().join("replacement.db");
            Connection::open(&replacement)
                .unwrap()
                .execute_batch("PRAGMA user_version=8")
                .unwrap();
            std::fs::rename(&replacement, &main).unwrap();
            assert!(!witness.matches(&connection).unwrap());
        }
    }
}

/// An idle prepared reader, evictable by the store retention budget.
pub struct PreparedPinnedReader {
    pub connection: std::sync::Mutex<Option<(Connection, PinnedReaderValidation)>>,
}
impl brokk_bifrost_core::retention_budget::RetainedBytes for PreparedPinnedReader {
    fn retained_bytes(&self) -> usize {
        // Two attached databases each use SQLite's default 2 MiB page cache.
        4 * 1024 * 1024 + std::mem::size_of::<Self>()
    }
}
