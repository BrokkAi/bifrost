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
use rusqlite::Connection;
use rusqlite::params;
use serde::Deserialize;
use serde::Serialize;

use std::fmt;
use std::path::PathBuf;

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
            "SELECT EXISTS(
               SELECT 1
               FROM catalog_callable_values_indexed_shards AS indexed
               JOIN catalog_packs AS pack
                 ON pack.manifest_digest = indexed.manifest_digest
               JOIN catalog_pack_shards AS shard
                 ON shard.manifest_digest = indexed.manifest_digest
                AND shard.shard_id = indexed.shard_id
               WHERE indexed.manifest_digest = ?1
                 AND indexed.shard_id = ?2
                 AND indexed.index_version = 1
                 AND pack.state = 'verified')",
            params![manifest_digest, shard_id],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check callable-values publication", error))
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
            "SELECT EXISTS(
               SELECT 1
               FROM catalog_packs AS pack
               JOIN catalog_pack_shards AS shard
                 ON shard.manifest_digest = pack.manifest_digest
               WHERE pack.manifest_digest = ?1
                 AND pack.state = 'verified'
                 AND shard.shard_id = ?2)",
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
               FROM catalog_selectors INDEXED BY catalog_selectors_artifact
               WHERE manifest_digest = ?1
                 AND shard_id = ?2
                 AND artifact_sha256 = ?3)",
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
               SELECT 1 FROM catalog_exact_go_source_sets
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
             FROM catalog_exact_go_source_files
                  INDEXED BY catalog_exact_go_source_files_read
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
             FROM catalog_exact_go_packages INDEXED BY catalog_exact_go_packages_read
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
             FROM catalog_exact_go_package_files
                  INDEXED BY catalog_exact_go_package_files_ordered_read
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

/// A cloneable SQL-only bridge for active runtime publication.
///
/// The reader owns fixed database handles and, for an ephemeral catalog, the
/// root keepalive needed by SQLite. It never retains a catalog borrow or a
/// workspace-sized source index.
#[derive(Clone)]
pub struct CatalogRuntimeSourceReader {
    pub durable_connection: Arc<Mutex<Connection>>,
    pub session_callable_values: Arc<Mutex<Option<SessionCallableValuesCatalog>>>,
    pub _ephemeral_root: Option<Arc<TempDir>>,
}

impl fmt::Debug for CatalogRuntimeSourceReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogRuntimeSourceReader")
            .finish_non_exhaustive()
    }
}

impl CatalogRuntimeSourceReader {
    pub fn query_callable_values(
        &self,
        query: &CatalogCallableValuesQuery<'_>,
        limits: CatalogCallableValuesQueryLimits,
        cancellation: &CancellationToken,
    ) -> Result<CatalogCallableValuesQueryResult, CatalogError> {
        let durable = self
            .durable_connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        if callable_values_publication_present(&durable, query.manifest_digest, query.shard_id)? {
            return query_callable_values_on_connection(&durable, query, limits, cancellation);
        }
        drop(durable);

        let session = self
            .session_callable_values
            .lock()
            .expect("session callable-values connection mutex poisoned");
        let Some(session) = session.as_ref() else {
            return Ok(callable_values_index_missing_result(limits));
        };
        if callable_values_publication_present(
            &session.connection,
            query.manifest_digest,
            query.shard_id,
        )? {
            return query_callable_values_on_connection(
                &session.connection,
                query,
                limits,
                cancellation,
            );
        }
        Ok(callable_values_index_missing_result(limits))
    }

    pub fn read_go_source(
        &self,
        request: &CatalogGoSourceRequest<'_>,
        limits: CatalogGoSourceReadLimits,
        cancellation: &CancellationToken,
    ) -> Result<Option<CatalogExactGoSourceSet>, CatalogError> {
        let durable = self
            .durable_connection
            .lock()
            .expect("semantic-pack catalog connection mutex poisoned");
        if let Some(source) =
            read_go_source_from_connection(&durable, request, limits, cancellation)?
        {
            return Ok(Some(source));
        }
        drop(durable);

        let session = self
            .session_callable_values
            .lock()
            .expect("session callable-values connection mutex poisoned");
        let Some(session) = session.as_ref() else {
            return Ok(None);
        };
        read_go_source_from_connection(&session.connection, request, limits, cancellation)
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
