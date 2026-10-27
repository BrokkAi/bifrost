//! Persistence for the canonical source-owned facts of one parsed blob.
//!
//! The rows in this module are deliberately content-local.  Source occurrence
//! ids and structural node ids are arena indices from the prepared file; the
//! only external ids are the already-prepared code-unit keys in the
//! declaration bridge.

use super::Result;
use super::StoreError;
use super::usize_to_i64;

use crate::CancellationToken;

use crate::analyzer::store::structural_vocabulary::STRUCTURAL_FACTS_VERSION;

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;

use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationBoundary;
use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind;
use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationPropertyFact;
use brokk_bifrost_core::analyzer::rust_facts::RustValueConstructorProperties;

use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId;

use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::source_facts::SourceImportId;

use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::ProjectFile;

use brokk_bifrost_core::hash::HashMap;

#[cfg(any(test, feature = "test-support"))]
use rusqlite::Connection;

use rusqlite::OptionalExtension;
use rusqlite::Transaction;
use rusqlite::params;

#[doc(hidden)]
pub mod declaration_read;
mod declaration_visibility;
#[doc(hidden)]
pub mod import_read;
#[doc(hidden)]
pub mod rust_items;

#[doc(hidden)]
pub use declaration_read::read_source_identity_rows;

pub(in crate::analyzer) use import_read::read_source_imports;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod declaration_visibility_tests;
#[cfg(test)]
mod go_tests;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod java_constructor_tests;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod java_go_publication_tests;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod java_tests;
#[cfg(any(test, feature = "test-support"))]
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod scala_tests;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_source_facts_match_across_mounts<T, F>(
    store: &super::AnalyzerStore,
    generation: super::GenerationId,
    first_file: &ProjectFile,
    second_file: &ProjectFile,
    mut read: impl FnMut(
        &super::AnalyzerStore,
        super::GenerationId,
        &ProjectFile,
        &dyn Fn() -> bool,
    ) -> Result<Option<T>>,
    facts: impl for<'a> Fn(&'a T) -> &'a F,
) -> (T, T)
where
    F: std::fmt::Debug + PartialEq,
{
    let first = read(store, generation, first_file, &|| true)
        .expect("read source facts at the first mount")
        .expect("source facts published at the first mount");
    let second = read(store, generation, second_file, &|| true)
        .expect("read source facts at the second mount")
        .expect("source facts published at the second mount");
    assert_eq!(facts(&first), facts(&second));
    (first, second)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_source_read_cancellation_retries<T>(
    mut read: impl FnMut(&dyn Fn() -> bool) -> Result<Option<T>>,
) {
    let visits = std::cell::Cell::new(0usize);
    assert!(
        read(&|| {
            visits.set(visits.get() + 1);
            visits.get() < 5
        })
        .expect("cancelled source-facts read")
        .is_none(),
        "source-facts read must stop when its visit budget expires"
    );
    assert!(
        visits.get() >= 5,
        "source-facts read skipped visit checkpoints"
    );
    assert!(
        read(&|| true).expect("retry source-facts read").is_some(),
        "a cancelled read must not poison the next source-facts read"
    );
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_missing_then_republished<T>(
    read: impl Fn() -> Result<Option<T>>,
    republish: impl FnOnce() -> Result<()>,
) {
    assert!(
        read().is_err(),
        "a missing source publication must fail to read"
    );
    republish().expect("republish source facts");
    assert!(
        read().expect("read republished source facts").is_some(),
        "a republished source family must be readable"
    );
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_reader_rejects_tampering<T>(
    tamper: impl FnOnce() -> Result<()>,
    read: impl FnOnce() -> Result<T>,
) {
    tamper().expect("tamper with sealed source facts");
    assert!(read().is_err(), "reader accepted tampered source facts");
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_source_lookup_plan(
    store: &super::AnalyzerStore,
    explain: impl Fn(&Connection) -> Vec<String>,
    mut read_published: impl FnMut() -> bool,
) {
    for refreshed in [false, true] {
        if refreshed {
            store
                .refresh_planner_statistics()
                .expect("refresh source publication planner statistics");
        }
        let connection = store.read_conn().expect("source publication reader");
        let plan = explain(&connection);
        assert!(
            plan.iter()
                .any(|step| step.contains("SEARCH blob") && step.contains("INDEX")),
            "source publication lookup did not seek its blob: {plan:#?}"
        );
        assert!(
            plan.iter().all(|step| !step.starts_with("SCAN ")),
            "source publication lookup must not scan: {plan:#?}"
        );
        drop(connection);
        assert!(
            read_published(),
            "source publication lookup returned no facts"
        );
    }
}

#[doc(hidden)]
pub fn source_occurrence(
    value: i64,
    label: &str,
) -> Result<brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId> {
    let value = checked_source_id(value, label, "source occurrence")?;
    Ok(brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId::new(value))
}

#[doc(hidden)]
pub fn source_import(value: i64, label: &str) -> Result<SourceImportId> {
    let value = checked_source_id(value, label, "source import")?;
    Ok(SourceImportId::new(value))
}

#[doc(hidden)]
pub fn checked_source_id(value: i64, label: &str, kind: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| StoreError::new(format!("invalid {label} {kind} id {value}")))
}

#[doc(hidden)]
pub fn nonnegative_usize(value: i64, label: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| StoreError::new(format!("invalid {label} value {value}")))
}

#[doc(hidden)]
pub fn strict_bool(value: i64, label: &str) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::new(format!("invalid {label} boolean {value}"))),
    }
}

/// Selected consumer view of one import's canonical token occurrences. The
/// ordinal selects the import; ranges are output attributes, never lookup keys.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct ImportSourceLocations {
    pub root_owned: bool,
    pub target: Option<brokk_bifrost_core::analyzer::structural::facts::Span>,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const IMPORT_SOURCE_LOCATIONS_SQL: &str = "
    WITH requested AS MATERIALIZED (
      SELECT imports.*
      FROM blobs AS keys
      JOIN source_fact_manifests AS manifest ON manifest.blob_id = keys.id
      JOIN source_rust_import_targets AS imports ON imports.blob_id = keys.id
      WHERE keys.blob_oid = ?1 AND keys.lang = 'rust'
        AND imports.ordinal = ?2 AND manifest.publication_state = 'complete'
        AND manifest.facts_version = ?3
    ), source_occurrences AS MATERIALIZED (
      SELECT occurrence.*
      FROM requested
      CROSS JOIN main.source_occurrences AS occurrence ON occurrence.blob_id = requested.blob_id
      WHERE occurrence.occurrence_id IN (
        requested.declaration_occurrence_id, requested.target_occurrence_id
      )
    )
    SELECT imports.owner_module = '' AND imports.local_start IS NULL AND imports.local_end IS NULL,
           target.start_byte, target.end_byte
    FROM requested AS imports
    JOIN source_occurrences AS declaration
      ON declaration.blob_id = imports.blob_id
     AND declaration.occurrence_id = imports.declaration_occurrence_id
    LEFT JOIN source_occurrences AS target
      ON target.blob_id = imports.blob_id
     AND target.occurrence_id = imports.target_occurrence_id";

#[doc(hidden)]
pub const RUST_DECLARATION_PROPERTY_MANIFEST_SQL: &str =
    "SELECT keys.blob_id, manifest.rust_declaration_property_count,
                    manifest.rust_constructor_field_count, manifest.declaration_unit_count
             FROM rust_published_fact_blobs AS keys
             JOIN source_fact_manifests AS manifest ON manifest.blob_id = keys.blob_id
             WHERE keys.blob_oid = ?1 AND keys.lang = 'rust' AND keys.generation = ?2
               AND manifest.facts_version = ?3";

#[doc(hidden)]
pub const RUST_DECLARATION_PROPERTIES_SQL: &str =
    "SELECT declaration_id, visibility, cfg_condition, constructor_non_exhaustive,
            declaration_kind, macro_exported, trait_impl_member,
            has_impl_or_trait_ancestor, nearest_declaration_boundary,
            json(derive_helper_attributes),
            generated_surface
             FROM source_rust_declaration_properties WHERE blob_id = ?1 ORDER BY declaration_id";

fn decode_rust_declaration_boundary(boundary: i64) -> Result<RustDeclarationBoundary> {
    Ok(match boundary {
        0 => RustDeclarationBoundary::ModuleOrFile,
        1 => RustDeclarationBoundary::LocalBlockOrFunction,
        2 => RustDeclarationBoundary::Impl,
        3 => RustDeclarationBoundary::Trait,
        _ => {
            return Err(StoreError::new(format!(
                "invalid Rust declaration boundary {boundary}"
            )));
        }
    })
}

pub(crate) fn decode_rust_declaration_kind(kind: i64) -> Result<RustDeclarationKind> {
    Ok(match kind {
        0 => RustDeclarationKind::Struct,
        1 => RustDeclarationKind::Enum,
        2 => RustDeclarationKind::Union,
        3 => RustDeclarationKind::Trait,
        4 => RustDeclarationKind::InlineModule,
        5 => RustDeclarationKind::ExternalModule,
        6 => RustDeclarationKind::Function,
        7 => RustDeclarationKind::FunctionSignature,
        8 => RustDeclarationKind::Field,
        9 => RustDeclarationKind::EnumVariant,
        10 => RustDeclarationKind::Const,
        11 => RustDeclarationKind::Static,
        12 => RustDeclarationKind::Macro,
        13 => RustDeclarationKind::TypeAlias,
        14 => RustDeclarationKind::AssociatedType,
        _ => {
            return Err(StoreError::new(format!(
                "invalid Rust declaration kind {kind}"
            )));
        }
    })
}

#[doc(hidden)]
pub const RUST_CONSTRUCTOR_FIELDS_SQL: &str =
    "SELECT declaration_id, ordinal, visibility FROM source_rust_constructor_fields
             WHERE blob_id = ?1 ORDER BY declaration_id, ordinal";

#[doc(hidden)]
pub const SOURCE_DECLARATION_UNITS_SQL: &str =
    "SELECT declaration_id, unit_key FROM source_declaration_units
             WHERE blob_id = ?1 ORDER BY declaration_id, unit_key";

// A test helper: `canonical_rust_primary_source_at` is its only caller and that
// is test-only too. No production statement asks a blob for its occurrences by
// exact source range, so the range index this named was dropped. A production
// point read of this shape would need the index back, because the blob-only
// primary-key prefix enumerates every occurrence of the file.
#[cfg(any(test, feature = "test-support"))]
pub(super) const RUST_PRIMARY_OCCURRENCES_AT_SQL: &str =
    "SELECT occurrence_id FROM source_occurrences
      WHERE blob_id = ?1 AND start_byte = ?2 AND end_byte = ?3
        AND provenance = 'primary_node'";

// Context-first access avoids enumerating every earlier source occurrence
// and sorting the result when a populated store has no planner statistics.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const RUST_PRIMARY_CONTEXTS_AT_SQL: &str = "SELECT context.occurrence_id
       FROM source_rust_item_contexts AS context
      WHERE context.blob_id = ?1 AND context.provenance = 0
        AND context.start_byte <= ?2 AND ?2 < context.end_byte
      ORDER BY context.ordinal";

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const RUST_PRIMARY_CONTEXT_MANIFEST_SQL: &str = "SELECT keys.blob_id
       FROM rust_published_fact_blobs AS keys
       JOIN source_fact_manifests AS manifest ON manifest.blob_id = keys.blob_id
       JOIN source_rust_item_manifests AS item ON item.blob_id = keys.blob_id
       JOIN source_rust_module_manifests AS module ON module.blob_id = keys.blob_id
      WHERE keys.blob_oid = ?1 AND keys.lang = 'rust' AND keys.generation = ?2
        AND manifest.publication_state = 'complete' AND manifest.facts_version = ?3
        AND item.facts_version = ?4 AND item.macro_facts_version = ?5
        AND item.type_forms_version = ?6 AND item.macro_contexts_version = ?7";

impl super::AnalyzerStore {
    /// Select query-side lexical context identities from canonical extents.
    /// Candidate declarations are joined by their source IDs, not these spans.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn rust_primary_contexts_at(
        &self,
        oid: git2::Oid,
        generation: super::GenerationId,
        reference_byte: usize,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<SourceOccurrenceId>>> {
        if !keep_going() {
            return Ok(None);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        super::require_current_generation(&tx, "rust", generation)?;
        let blob_id: i64 = tx
            .query_row(
                RUST_PRIMARY_CONTEXT_MANIFEST_SQL,
                params![
                    oid.to_string(), generation.get(), SOURCE_FACTS_VERSION,
                    rust_items::RUST_ITEM_SOURCE_FACTS_VERSION,
                    rust_items::RUST_MACRO_FACTS_VERSION,
                    rust_items::RUST_TYPE_FORMS_VERSION,
                    rust_items::RUST_MACRO_CONTEXTS_VERSION,
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::new(format!(
                    "canonical Rust query context publication unavailable for {oid} at {generation:?}"
                ))
            })?;
        let mut statement = tx.prepare_cached(RUST_PRIMARY_CONTEXTS_AT_SQL)?;
        let mut rows = statement.query(params![blob_id, usize_to_i64(reference_byte)?])?;
        let mut contexts = Vec::new();
        while let Some(row) = rows.next()? {
            if !keep_going() {
                return Ok(None);
            }
            contexts.push(source_occurrence(row.get(0)?, "primary context")?);
        }
        if !keep_going() {
            return Ok(None);
        }
        Ok(Some(contexts))
    }

    /// Translate a primary query AST location into canonical source identities.
    /// Spans only select the query location; declaration relationships are read
    /// through the returned IDs, never reconstructed from display ranges.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn rust_primary_occurrences_at(
        &self,
        oid: git2::Oid,
        generation: super::GenerationId,
        range: std::ops::Range<usize>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<SourceOccurrenceId>>> {
        assert!(
            range.start <= range.end,
            "query source range must be ordered"
        );
        if !keep_going() {
            return Ok(None);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        super::require_current_generation(&tx, "rust", generation)?;
        let blob_id: i64 = tx
            .query_row(
                RUST_DECLARATION_PROPERTY_MANIFEST_SQL,
                params![oid.to_string(), generation.get(), SOURCE_FACTS_VERSION],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::new(format!(
                    "canonical Rust query source publication unavailable for {oid} at {generation:?}"
                ))
            })?;
        let mut statement = tx.prepare_cached(RUST_PRIMARY_OCCURRENCES_AT_SQL)?;
        let mut rows = statement.query(params![
            blob_id,
            usize_to_i64(range.start)?,
            usize_to_i64(range.end)?,
        ])?;
        let mut occurrences = Vec::new();
        while let Some(row) = rows.next()? {
            if !keep_going() {
                return Ok(None);
            }
            occurrences.push(source_occurrence(row.get(0)?, "primary query")?);
        }
        if !keep_going() {
            return Ok(None);
        }
        Ok(Some(occurrences))
    }

    /// Read one exact publication and its creation-time declaration bridge.
    /// A CodeUnit can occur more than once; callers must retain every source ID.
    /// None means cancellation, never absent property publication.
    #[doc(hidden)]
    pub fn rust_declaration_properties<A: super::StoreLanguageAdapter>(
        &self,
        oid: git2::Oid,
        generation: super::GenerationId,
        adapter: &A,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<(CodeUnit, RustDeclarationPropertyFact)>>> {
        if !keep_going() {
            return Ok(None);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        super::require_current_generation(&tx, "rust", generation)?;
        let oid_text = oid.to_string();
        let publication = tx
            .query_row(
                RUST_DECLARATION_PROPERTY_MANIFEST_SQL,
                params![oid_text, generation.get(), SOURCE_FACTS_VERSION],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((blob_id, expected_properties, expected_fields, expected_links)) = publication
        else {
            return Err(StoreError::missing_required_source_facts(format!(
                "canonical Rust declaration publication unavailable for {oid} at {generation:?}"
            )));
        };
        let (blob_id, expected_properties, expected_fields, expected_links): (
            i64,
            usize,
            usize,
            usize,
        ) = (
            blob_id,
            expected_properties,
            expected_fields,
            expected_links,
        );
        let mut properties = HashMap::default();
        let mut statement = tx.prepare_cached(RUST_DECLARATION_PROPERTIES_SQL)?;
        let mut rows = statement.query([blob_id])?;
        while let Some(row) = rows.next()? {
            if !keep_going() {
                return Ok(None);
            }
            let declaration = SourceDeclarationId::new(row.get(0)?);
            let visibility_text: String = row.get(1)?;
            let cfg_text: String = row.get(2)?;
            let visibility = super::decode_rust_visibility(&visibility_text).ok_or_else(|| {
                StoreError::new(format!("invalid Rust declaration visibility {visibility_text:?} for {oid}/{declaration:?}"))
            })?;
            let cfg_condition = super::decode_rust_cfg_condition(&cfg_text).ok_or_else(|| {
                StoreError::new(format!(
                    "invalid Rust declaration cfg {cfg_text:?} for {oid}/{declaration:?}"
                ))
            })?;
            let value_constructor = row.get::<_, Option<bool>>(3)?.map(|non_exhaustive| {
                Box::new(RustValueConstructorProperties {
                    field_visibilities: Vec::new(),
                    non_exhaustive,
                })
            });
            let helper_attributes = row
                .get::<_, Option<String>>(9)?
                .map(|encoded| {
                    let names = serde_json::from_str::<Vec<String>>(&encoded).map_err(|error| {
                        StoreError::new(format!(
                            "invalid Rust derive-helper attribute names {encoded:?} for {oid}/{declaration:?}: {error}"
                        ))
                    })?;
                    if names.is_empty() || names.windows(2).any(|pair| pair[0] >= pair[1]) {
                        return Err(StoreError::new(format!(
                            "Rust derive-helper attribute names are not nonempty, sorted and distinct for {oid}/{declaration:?}: {names:?}"
                        )));
                    }
                    Ok(names)
                })
                .transpose()?;
            properties.insert(
                declaration,
                RustDeclarationPropertyFact {
                    declaration,
                    kind: decode_rust_declaration_kind(row.get(4)?)?,
                    macro_exported: row.get(5)?,
                    trait_impl_member: row.get(6)?,
                    has_impl_or_trait_ancestor: row.get(7)?,
                    nearest_declaration_boundary: decode_rust_declaration_boundary(row.get(8)?)?,
                    derive_helper_attributes: helper_attributes,
                    generated_surface: strict_bool(row.get(10)?, "generated surface")?,
                    visibility,
                    cfg_condition,
                    value_constructor,
                },
            );
        }
        drop(rows);
        drop(statement);
        if properties.len() != expected_properties {
            return Err(StoreError::new(format!(
                "incomplete Rust declaration properties for {oid}: {properties:?}; expected {expected_properties}"
            )));
        }
        let mut statement = tx.prepare_cached(RUST_CONSTRUCTOR_FIELDS_SQL)?;
        let mut rows = statement.query([blob_id])?;
        let mut field_count = 0usize;
        while let Some(row) = rows.next()? {
            if !keep_going() {
                return Ok(None);
            }
            let declaration = SourceDeclarationId::new(row.get(0)?);
            let ordinal: usize = row.get(1)?;
            let visibility_text: String = row.get(2)?;
            let constructor = properties
                .get_mut(&declaration)
                .and_then(|property| property.value_constructor.as_mut())
                .ok_or_else(|| {
                    StoreError::new(format!(
                        "Rust constructor field has no constructor for {oid}/{declaration:?}"
                    ))
                })?;
            if ordinal != constructor.field_visibilities.len() {
                return Err(StoreError::new(format!(
                    "non-dense Rust constructor field {ordinal} for {oid}/{declaration:?}: {constructor:?}"
                )));
            }
            constructor.field_visibilities.push(super::decode_rust_visibility(&visibility_text)
                .ok_or_else(|| StoreError::new(format!("invalid Rust constructor field visibility {visibility_text:?} for {oid}/{declaration:?}")))?);
            field_count += 1;
        }
        drop(rows);
        drop(statement);
        if field_count != expected_fields {
            return Err(StoreError::new(format!(
                "incomplete Rust constructor fields for {oid}: {properties:?}; expected {expected_fields}"
            )));
        }
        if !keep_going() {
            return Ok(None);
        }
        let Some(units) =
            super::read_unit_rows_while(&tx, &oid_text, "rust", adapter, file, keep_going)?
        else {
            return Ok(None);
        };
        let units: HashMap<_, _> = units.into_iter().map(|row| (row.key, row.unit)).collect();
        let mut statement = tx.prepare_cached(SOURCE_DECLARATION_UNITS_SQL)?;
        let mut rows = statement.query([blob_id])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            if !keep_going() {
                return Ok(None);
            }
            let declaration = SourceDeclarationId::new(row.get(0)?);
            let key: i64 = row.get(1)?;
            let property = properties.get(&declaration).ok_or_else(|| {
                StoreError::new(format!(
                    "Rust declaration bridge has no source properties for {oid}/{declaration:?}"
                ))
            })?;
            let unit = units.get(&key).ok_or_else(|| {
                StoreError::new(format!(
                    "Rust declaration bridge has no unit {key} for {oid}/{declaration:?}"
                ))
            })?;
            out.push((unit.clone(), property.clone()));
        }
        drop(rows);
        drop(statement);
        if out.len() != expected_links {
            return Err(StoreError::new(format!(
                "incomplete Rust declaration bridges for {oid}: {out:?}; expected {expected_links}"
            )));
        }
        if !keep_going() {
            return Ok(None);
        }
        tx.commit()?;
        Ok(Some(out))
    }

    /// Hydrate only the demanded import ordinals under one generation-checked
    /// snapshot. No complete source arena or unrelated import rows are loaded.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn load_rust_import_source_locations(
        &self,
        oid: git2::Oid,
        generation: super::GenerationId,
        ordinals: &std::collections::BTreeSet<usize>,
        cancellation: &CancellationToken,
    ) -> Result<Option<std::collections::BTreeMap<usize, ImportSourceLocations>>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        super::require_current_generation(&tx, "rust", generation)?;
        let oid = oid.to_string();
        let mut statement = tx.prepare_cached(IMPORT_SOURCE_LOCATIONS_SQL)?;
        let mut locations = std::collections::BTreeMap::new();
        for &ordinal in ordinals {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let row = statement
                .query_row(
                    params![oid, usize_to_i64(ordinal)?, SOURCE_FACTS_VERSION],
                    |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            row.get::<_, Option<usize>>(1)?,
                            row.get::<_, Option<usize>>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((root_owned, target_start, target_end)) = row else {
                return Ok(None);
            };
            use brokk_bifrost_core::analyzer::structural::facts::Span;
            let span = |start, end| match (start, end) {
                (Some(start_byte), Some(end_byte)) => Some(Span {
                    start_byte,
                    end_byte,
                }),
                (None, None) => None,
                mismatched => {
                    panic!("canonical import occurrence has half a range: {mismatched:?}")
                }
            };
            locations.insert(
                ordinal,
                ImportSourceLocations {
                    root_owned,
                    target: span(target_start, target_end),
                },
            );
        }
        drop(statement);
        tx.commit()?;
        Ok(Some(locations))
    }
}

/// The schema-41 source-facts manifest uses the structural vocabulary version
/// as its semantic row-version gate.  Keep this alias at the store boundary
/// so callers do not need to know which model version owns that vocabulary.
#[doc(hidden)]
pub const SOURCE_FACTS_VERSION: i64 = STRUCTURAL_FACTS_VERSION;

/// The code a provenance is stored under in the arena (milestone 5, lane ST).
/// The view `source_occurrences` turns it back into the label every statement
/// written before the fold expects.
#[doc(hidden)]
pub fn provenance_code(provenance: SourceOccurrenceProvenance) -> u8 {
    match provenance {
        SourceOccurrenceProvenance::PrimaryNode => 0,
        SourceOccurrenceProvenance::ExplicitSubspan => 1,
        SourceOccurrenceProvenance::Embedded => 2,
    }
}

fn provenance_from_code(code: i64) -> Result<SourceOccurrenceProvenance> {
    match code {
        0 => Ok(SourceOccurrenceProvenance::PrimaryNode),
        1 => Ok(SourceOccurrenceProvenance::ExplicitSubspan),
        2 => Ok(SourceOccurrenceProvenance::Embedded),
        other => Err(StoreError::new(format!(
            "invalid source occurrence provenance code {other}"
        ))),
    }
}

/// A blob's whole occurrence arena, as the JSON text the store holds as JSONB.
///
/// One array per occurrence, in occurrence-id order, positions
/// `[start_byte, end_byte, start_line, end_line, provenance]`. The id is the
/// position, which is why the array is dense and why nothing may reorder it.
/// The only whole-value reader is `read_source_identity_rows`; every other
/// reader goes through the `source_occurrences` view, and the hot ones read an
/// inline span column instead.
pub(in crate::analyzer) fn encode_occurrence_arena(
    occurrences: &[brokk_bifrost_core::analyzer::source_facts::SourceOccurrence],
) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(occurrences.len() * 24 + 2);
    out.push('[');
    for (index, occurrence) in occurrences.iter().enumerate() {
        let range = occurrence.range;
        let separator = if index == 0 { "" } else { "," };
        write!(
            out,
            "{separator}[{},{},{},{},{}]",
            range.start_byte,
            range.end_byte,
            range.start_line,
            range.end_line,
            provenance_code(occurrence.provenance),
        )
        .expect("writing to a String cannot fail");
    }
    out.push(']');
    out
}

struct StructuralFactJson {
    nodes: String,
    roles: String,
    occurrence_roles: String,
}

fn push_json_optional<T: std::fmt::Display>(out: &mut String, value: Option<T>) {
    use std::fmt::Write;
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
    .expect("writing to a String cannot fail");
}

/// Build the three positional JSON arrays of `source_structural_facts` (positions are
/// documented in migration 0128). Structural integrity is asserted before this runs:
/// `StructuralFactRows::new` checks the preorder subtree contract and
/// `ParsedSourceFacts::assert_storable` checks name ranges.
fn encode_structural_facts(
    facts: &ParsedSourceFacts,
    span_of: &impl Fn(SourceOccurrenceId) -> (usize, usize),
    cancellation: &CancellationToken,
) -> Result<StructuralFactJson> {
    use std::fmt::Write;
    let nodes = facts.structural.nodes();
    let node_count = nodes.len();
    let mut node_json = String::with_capacity(node_count * 40 + 2);
    node_json.push('[');
    for (index, node) in nodes.iter().enumerate() {
        check_cancelled(cancellation)?;
        let (start, end) = span_of(node.occurrence);
        let name = node.name.map(span_of);
        let (call_kind, call_coverage, continues) = match node.call_site.as_ref() {
            Some(call) => (
                call.call_kind.map(|kind| u32::from(kind.code())),
                Some(u32::from(call.coverage.code())),
                Some(u32::from(call.continues_callee_groups)),
            ),
            None => (None, None, None),
        };
        if index > 0 {
            node_json.push(',');
        }
        write!(node_json, "[{},", node.kind.code()).expect("writing to a String cannot fail");
        match node.boolean_value {
            Some(value) => write!(node_json, "{},", u8::from(value)),
            None => write!(node_json, "null,"),
        }
        .expect("writing to a String cannot fail");
        match node.construct.as_deref() {
            Some(construct) => node_json.push_str(
                &serde_json::to_string(construct).expect("a string always serializes to JSON"),
            ),
            None => node_json.push_str("null"),
        }
        write!(node_json, ",{start},{end},").expect("writing to a String cannot fail");
        push_json_optional(&mut node_json, name.map(|(start, _)| start));
        node_json.push(',');
        push_json_optional(&mut node_json, name.map(|(_, end)| end));
        node_json.push(',');
        push_json_optional(&mut node_json, node.parent);
        write!(node_json, ",{},", node.subtree_end).expect("writing to a String cannot fail");
        push_json_optional(&mut node_json, call_kind);
        node_json.push(',');
        push_json_optional(&mut node_json, call_coverage);
        node_json.push(',');
        push_json_optional(&mut node_json, continues);
        node_json.push(',');
        push_json_optional(&mut node_json, node.parenthesized.map(u8::from));
        node_json.push(',');
        match node.assignment_shape {
            Some(shape) => node_json.push_str(
                &serde_json::to_string(&shape)
                    .expect("a structural assignment-shape value always serializes to JSON"),
            ),
            None => node_json.push_str("null"),
        }
        node_json.push(',');
        match node.integer_literal_value.as_ref() {
            Some(value) => node_json
                .push_str(&serde_json::to_string(value).expect(
                    "a canonical integer-literal value always serializes to readable JSON",
                )),
            None => node_json.push_str("null"),
        }
        node_json.push(',');
        match node.duplicate_key {
            Some(value) => node_json.push_str(if value { "true" } else { "false" }),
            None => node_json.push_str("null"),
        }
        node_json.push(',');
        match node.string_value.as_deref() {
            Some(value) => node_json.push_str(
                &serde_json::to_string(value).expect("a decoded string value serializes as JSON"),
            ),
            None => node_json.push_str("null"),
        }
        node_json.push(',');
        match node.is_async {
            Some(value) => write!(node_json, "{}", u8::from(value)),
            None => write!(node_json, "null"),
        }
        .expect("writing to a String cannot fail");
        let provenance = node
            .call_site
            .as_ref()
            .and_then(|site| site.callee_provenance.as_ref());
        if let Some(fact) = provenance {
            write!(node_json, ",{},", fact.provenance.code()).expect("String write");
            push_json_optional(
                &mut node_json,
                fact.supplier.map(|supplier| supplier.code()),
            );
            node_json.push(',');
            push_json_optional(
                &mut node_json,
                fact.supplier.and_then(|supplier| supplier.ordinal()),
            );
            write!(node_json, ",{},", fact.shape.code()).expect("String write");
            node_json.push_str(&serde_json::to_string(&fact.bounds).expect("bound paths encode"));
        } else {
            node_json.push_str(",null,null,null,null,null");
        }
        node_json.push(',');
        match node.unsafe_context {
            Some(value) => node_json.push_str(if value { "true" } else { "false" }),
            None => node_json.push_str("null"),
        }
        node_json.push(']');
    }
    node_json.push(']');

    let mut role_json = String::with_capacity(facts.structural.role_count() * 32 + 2);
    role_json.push('[');
    let mut role_count = 0usize;
    for node_id in 0..node_count {
        check_cancelled(cancellation)?;
        let source_node_id = u32::try_from(node_id).expect("structural node ids must fit in u32");
        for role in facts.structural.roles(source_node_id) {
            let (start, end) = span_of(role.occurrence);
            let name = role.name.map(span_of);
            let keyword = role.keyword.map(span_of);
            assert!(start <= end, "structural role has an inverted span");
            if role_count > 0 {
                role_json.push(',');
            }
            role_count += 1;
            write!(
                role_json,
                "[{source_node_id},{},{},",
                role.role.code(),
                u8::from(role.spread)
            )
            .expect("writing to a String cannot fail");
            push_json_optional(&mut role_json, role.node);
            write!(role_json, ",{start},{end},").expect("writing to a String cannot fail");
            push_json_optional(&mut role_json, name.map(|(start, _)| start));
            role_json.push(',');
            push_json_optional(&mut role_json, name.map(|(_, end)| end));
            role_json.push(',');
            push_json_optional(&mut role_json, keyword.map(|(start, _)| start));
            role_json.push(',');
            push_json_optional(&mut role_json, keyword.map(|(_, end)| end));
            role_json.push(']');
        }
    }
    role_json.push(']');

    let mut occurrence_role_json =
        String::with_capacity(facts.structural.occurrence_role_count() * 8 + 2);
    occurrence_role_json.push('[');
    let mut occurrence_role_count = 0usize;
    for node_id in 0..node_count {
        check_cancelled(cancellation)?;
        let node_id = u32::try_from(node_id).expect("structural node ids must fit in u32");
        for role in facts.structural.occurrence_roles(node_id) {
            if occurrence_role_count > 0 {
                occurrence_role_json.push(',');
            }
            occurrence_role_count += 1;
            write!(occurrence_role_json, "[{node_id},{}]", role.code())
                .expect("writing to a String cannot fail");
        }
    }
    occurrence_role_json.push(']');

    Ok(StructuralFactJson {
        nodes: node_json,
        roles: role_json,
        occurrence_roles: occurrence_role_json,
    })
}

fn cancelled() -> StoreError {
    StoreError::new("source fact persistence was cancelled")
}

#[doc(hidden)]
pub fn check_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(cancelled())
    } else {
        Ok(())
    }
}

/// A language's paired accounting and insertion operations for canonical source facts.
///
/// Adapters bind this capability in their language-owned publication module. The
/// store passes its transaction to the writer and retains ownership of common
/// manifest creation, complete cost summation, and publication sealing.
#[derive(Debug)]
pub struct SourceFactStorage {
    // `None` means this capability does not own a populated family in the input.
    #[doc(hidden)]
    pub cost: fn(&ParsedSourceFacts) -> Option<(usize, usize)>,
    #[doc(hidden)]
    pub insert: fn(&Transaction<'_>, i64, &ParsedSourceFacts, &CancellationToken) -> Result<()>,
}

/// Return the admission accounting for canonical source facts.
///
/// Count occurrence/declaration/structural families, canonical module rows,
/// and the canonical import parents and children. Generic/Rust projection rows
/// are counted separately. Exact native and metadata bridges belong to the
/// common publication; optional declaration visibility owns its marker and rows.
/// Payload accounting includes UTF-8 labels and optional textual fields, but
/// not source bytes or numeric attributes. Each language family writes its own
/// manifest from the same `cost` function, so the totals agree by construction.
#[doc(hidden)]
pub fn source_fact_cost(
    storage: Option<&SourceFactStorage>,
    facts: &ParsedSourceFacts,
    declaration_units: &[(
        brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
        i64,
    )],
    metadata_links: &[(SourceDeclarationId, i64, i64)],
) -> (usize, usize) {
    let (declaration_visibility_rows, declaration_visibility_payload) =
        declaration_visibility::source_declaration_visibility_cost(facts, metadata_links);
    declaration_visibility::validate_native_declaration_bridges(facts);
    let imports = source_import_counts(facts);
    let family_cost = storage.and_then(|storage| (storage.cost)(facts));
    let selected_family_present = family_cost.is_some();
    assert_eq!(
        facts.adapter_source_family_count(),
        usize::from(selected_family_present),
        "canonical source facts contain an unhandled adapter family; selected family present: {selected_family_present}; facts: {facts:?}"
    );
    let (family_rows, family_payload) = family_cost.unwrap_or_default();
    let logical_rows = 1usize
        .saturating_add(facts.occurrences.occurrence_count())
        .saturating_add(facts.occurrences.declaration_count())
        .saturating_add(declaration_units.len())
        .saturating_add(metadata_links.len())
        .saturating_add(facts.native_declaration_sources.len())
        // One source_structural_facts row holds every node and role of the blob.
        .saturating_add(1)
        .saturating_add(facts.structural.recovered_regions().len())
        .saturating_add(imports.parents)
        .saturating_add(imports.segments)
        .saturating_add(imports.scopes)
        .saturating_add(imports.prefixes)
        .saturating_add(family_rows)
        .saturating_add(declaration_visibility_rows);

    let node_payload = facts
        .structural
        .nodes()
        .iter()
        // Integer kind and call codes carry no text payload.
        .map(|node| node.construct.as_ref().map_or(0, String::len))
        .fold(0usize, usize::saturating_add);
    let lexical_declaration_payload = facts
        .occurrences
        .lexical_declarations()
        .iter()
        .map(|fact| {
            fact.kind
                .label()
                .len()
                .saturating_add(fact.identifier.len())
        })
        .fold(0usize, usize::saturating_add);

    let import_payload = facts
        .imports
        .iter()
        .map(|import| {
            import
                .statement
                .len()
                .saturating_add(import.identifier.as_ref().map_or(0, String::len))
                .saturating_add(import.alias.as_ref().map_or(0, String::len))
                .saturating_add(import.path.as_ref().map_or(0, |path| {
                    path.kind
                        .map_or(0, |kind| kind.persist_tag().len())
                        .saturating_add(
                            path.segments
                                .iter()
                                .map(String::len)
                                .fold(0usize, usize::saturating_add),
                        )
                        .saturating_add(
                            path.lexical_prefixes
                                .iter()
                                .map(String::len)
                                .fold(0usize, usize::saturating_add),
                        )
                }))
        })
        .fold(0usize, usize::saturating_add);

    (
        logical_rows,
        node_payload
            .saturating_add(import_payload)
            .saturating_add(lexical_declaration_payload)
            .saturating_add(family_payload)
            .saturating_add(declaration_visibility_payload),
    )
}

#[derive(Default)]
struct SourceImportCounts {
    parents: usize,
    segments: usize,
    scopes: usize,
    prefixes: usize,
}

fn source_import_counts(facts: &ParsedSourceFacts) -> SourceImportCounts {
    facts
        .imports
        .iter()
        .fold(SourceImportCounts::default(), |mut counts, import| {
            counts.parents = counts.parents.saturating_add(1);
            if let Some(path) = &import.path {
                counts.segments = counts.segments.saturating_add(path.segments.len());
                counts.scopes = counts.scopes.saturating_add(path.lexical_scopes.len());
                counts.prefixes = counts.prefixes.saturating_add(path.lexical_prefixes.len());
            }
            counts
        })
}

/// Insert and seal one complete canonical source-facts publication.
pub(super) fn insert_source_facts_tx(
    storage: Option<&SourceFactStorage>,
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &ParsedSourceFacts,
    declaration_units: &[(
        brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
        i64,
    )],
    metadata_links: &[(SourceDeclarationId, i64, i64)],
    cancellation: &CancellationToken,
) -> Result<()> {
    check_cancelled(cancellation)?;
    // The seal no longer re-reads these rows (#3737). Every row count and id
    // below comes from the collection its insert loop iterates, and each
    // inline span comes from an arena lookup of the id written beside it, so
    // the remaining invariants are checked here, over the facts in memory.
    facts.assert_storable();
    let source_bytes = usize_to_i64(facts.source_bytes)?;
    let (logical_rows, payload_bytes) =
        source_fact_cost(storage, facts, declaration_units, metadata_links);
    let imports = source_import_counts(facts);
    tx.execute(
        "INSERT INTO source_fact_manifests(
           blob_id, facts_version, source_bytes, occurrence_count,
           declaration_count, declaration_unit_count, node_count, role_count,
           occurrence_role_count, import_count, import_segment_count, import_scope_count,
           import_prefix_count, logical_rows, payload_bytes, metadata_bridge_count, native_bridge_count, publication_state
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 'building')",
        params![
            blob_id,
            SOURCE_FACTS_VERSION,
            source_bytes,
            usize_to_i64(facts.occurrences.occurrence_count())?,
            usize_to_i64(facts.occurrences.declaration_count())?,
            usize_to_i64(declaration_units.len())?,
            usize_to_i64(facts.structural.nodes().len())?,
            usize_to_i64(facts.structural.role_count())?,
            usize_to_i64(facts.structural.occurrence_role_count())?,
            usize_to_i64(imports.parents)?,
            usize_to_i64(imports.segments)?,
            usize_to_i64(imports.scopes)?,
            usize_to_i64(imports.prefixes)?,
            usize_to_i64(logical_rows)?,
            usize_to_i64(payload_bytes)?,
            usize_to_i64(metadata_links.len())?,
            usize_to_i64(facts.native_declaration_sources.len())?,
        ],
    )?;

    // Spans go inline beside the occurrence id wherever a statement reads one
    // (milestone 5, lane ST). `span_of` resolves an id against the arena the
    // same facts value carries, which is the only place both are in hand.
    let span_of = |occurrence: SourceOccurrenceId| {
        let range = facts.occurrences.occurrence(occurrence).range;
        (range.start_byte, range.end_byte)
    };

    check_cancelled(cancellation)?;
    // One row a blob, not one a occurrence: on tract this is 962 inserts where
    // it was 1,240,271, and 45 percent of the cold-index writer's time.
    tx.prepare_cached(
        "INSERT INTO source_occurrence_arenas(blob_id, spans) VALUES(?1, jsonb(?2))",
    )?
    .execute(params![
        blob_id,
        encode_occurrence_arena(facts.occurrences.occurrences()),
    ])?;

    let mut import_statement = tx.prepare_cached(
        "INSERT INTO source_imports(blob_id, import_id, statement, is_wildcard, is_global,
            identifier, alias, path_kind, declaration_occurrence_id, target_occurrence_id,
            alias_occurrence_id, has_structured_path, is_macro_use,
            declaration_start_byte, declaration_end_byte, target_start_byte, target_end_byte,
            alias_start_byte, alias_end_byte)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
    )?;
    let mut segments = tx.prepare_cached(
        "INSERT INTO source_import_segments(blob_id, import_id, ordinal, segment)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut scopes = tx.prepare_cached(
        "INSERT INTO source_import_scopes(blob_id, import_id, ordinal, occurrence_id,
            start_byte, end_byte)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut prefixes = tx.prepare_cached(
        "INSERT INTO source_import_prefixes(blob_id, import_id, ordinal, prefix)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (index, import) in facts.imports.iter().enumerate() {
        check_cancelled(cancellation)?;
        let import_id = usize_to_i64(index)?;
        import_statement.execute(params![
            blob_id,
            import_id,
            &import.statement,
            i64::from(import.is_wildcard),
            i64::from(import.is_global),
            &import.identifier,
            &import.alias,
            import
                .path
                .as_ref()
                .and_then(|path| path.kind)
                .map(|kind| kind.persist_tag()),
            i64::from(import.declaration.get()),
            import.target.map(|id| i64::from(id.get())),
            import.alias_occurrence.map(|id| i64::from(id.get())),
            i64::from(import.path.is_some()),
            i64::from(import.is_macro_use),
            usize_to_i64(span_of(import.declaration).0)?,
            usize_to_i64(span_of(import.declaration).1)?,
            import
                .target
                .map(span_of)
                .map(|(start, _)| start)
                .map(usize_to_i64)
                .transpose()?,
            import
                .target
                .map(span_of)
                .map(|(_, end)| end)
                .map(usize_to_i64)
                .transpose()?,
            import
                .alias_occurrence
                .map(span_of)
                .map(|(start, _)| start)
                .map(usize_to_i64)
                .transpose()?,
            import
                .alias_occurrence
                .map(span_of)
                .map(|(_, end)| end)
                .map(usize_to_i64)
                .transpose()?,
        ])?;
        let Some(path) = &import.path else {
            continue;
        };
        for (ordinal, segment) in path.segments.iter().enumerate() {
            check_cancelled(cancellation)?;
            segments.execute(params![blob_id, import_id, usize_to_i64(ordinal)?, segment])?;
        }
        for (ordinal, scope) in path.lexical_scopes.iter().enumerate() {
            check_cancelled(cancellation)?;
            let (scope_start, scope_end) = span_of(*scope);
            scopes.execute(params![
                blob_id,
                import_id,
                usize_to_i64(ordinal)?,
                i64::from(scope.get()),
                usize_to_i64(scope_start)?,
                usize_to_i64(scope_end)?,
            ])?;
        }
        for (ordinal, prefix) in path.lexical_prefixes.iter().enumerate() {
            check_cancelled(cancellation)?;
            prefixes.execute(params![blob_id, import_id, usize_to_i64(ordinal)?, prefix])?;
        }
    }
    drop(import_statement);
    drop(segments);
    drop(scopes);
    drop(prefixes);

    let mut declarations = tx.prepare_cached(
        "INSERT INTO source_declarations(
           blob_id, declaration_id, occurrence_id, name_occurrence_id,
           lexical_kind, lexical_identifier,
           start_byte, end_byte, start_line, end_line,
           name_start_byte, name_end_byte, name_start_line, name_end_line,
           provenance
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
    )?;
    for (index, declaration) in facts.occurrences.declarations().iter().enumerate() {
        check_cancelled(cancellation)?;
        let declaration_id = SourceDeclarationId::try_from_index(index)
            .expect("source declaration ids must fit in a u32");
        let lexical = facts.occurrences.lexical_declaration(declaration_id);
        // The whole range, not just the byte span: the selected lexical
        // definition reader returns a Range and is on the point path.
        let occurrence = facts.occurrences.occurrence(declaration.occurrence);
        let range = occurrence.range;
        let name_range = declaration
            .name
            .map(|name| facts.occurrences.occurrence(name).range);
        declarations.execute(params![
            blob_id,
            usize_to_i64(index)?,
            i64::from(declaration.occurrence.get()),
            declaration.name.map(|name| i64::from(name.get())),
            lexical.map(|fact| fact.kind.label()),
            lexical.map(|fact| fact.identifier.as_str()),
            usize_to_i64(range.start_byte)?,
            usize_to_i64(range.end_byte)?,
            usize_to_i64(range.start_line)?,
            usize_to_i64(range.end_line)?,
            name_range
                .map(|range| usize_to_i64(range.start_byte))
                .transpose()?,
            name_range
                .map(|range| usize_to_i64(range.end_byte))
                .transpose()?,
            name_range
                .map(|range| usize_to_i64(range.start_line))
                .transpose()?,
            name_range
                .map(|range| usize_to_i64(range.end_line))
                .transpose()?,
            i64::from(provenance_code(occurrence.provenance)),
        ])?;
    }
    drop(declarations);

    let mut declaration_units_statement = tx.prepare_cached(
        "INSERT INTO source_declaration_units(blob_id, declaration_id, unit_key)
         VALUES(?1, ?2, ?3)",
    )?;
    for &(declaration_id, unit_key) in declaration_units {
        check_cancelled(cancellation)?;
        assert!(
            declaration_id.index() < facts.occurrences.declaration_count(),
            "source declaration-unit link points outside declaration rows"
        );
        assert!(
            unit_key >= 0,
            "source declaration-unit link has a negative unit key"
        );
        declaration_units_statement.execute(params![
            blob_id,
            i64::from(declaration_id.get()),
            unit_key,
        ])?;
    }
    drop(declaration_units_statement);

    if let Some(storage) = storage {
        (storage.insert)(tx, blob_id, facts, cancellation)?;
    }

    declaration_visibility::insert_source_native_declaration_bridges_tx(
        tx,
        blob_id,
        facts,
        cancellation,
    )?;
    declaration_visibility::insert_source_declaration_metadata_bridges_tx(
        tx,
        blob_id,
        facts,
        metadata_links,
        cancellation,
    )?;
    declaration_visibility::insert_source_declaration_visibility_facts_tx(
        tx,
        blob_id,
        facts,
        metadata_links,
        cancellation,
    )?;

    let structural = encode_structural_facts(facts, &span_of, cancellation)?;
    tx.prepare_cached(
        "INSERT INTO source_structural_facts(blob_id, nodes, roles, occurrence_roles)
         VALUES(?1, jsonb(?2), jsonb(?3), jsonb(?4))",
    )?
    .execute(params![
        blob_id,
        structural.nodes,
        structural.roles,
        structural.occurrence_roles,
    ])?;
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO source_structural_recovered_regions(blob_id, ordinal, start_byte, end_byte)
             VALUES(?1, ?2, ?3, ?4)",
        )?;
        for (ordinal, region) in facts.structural.recovered_regions().iter().enumerate() {
            check_cancelled(cancellation)?;
            insert.execute(params![
                blob_id,
                usize_to_i64(ordinal)?,
                usize_to_i64(region.start_byte)?,
                usize_to_i64(region.end_byte)?,
            ])?;
        }
    }

    check_cancelled(cancellation)?;
    tx.execute(
        "UPDATE source_fact_manifests
         SET publication_state = 'complete'
         WHERE blob_id = ?1",
        params![blob_id],
    )?;
    check_cancelled(cancellation)?;
    Ok(())
}

#[cfg(test)]
mod kotlin_publication_tests;

#[cfg(test)]
mod roundtrip_properties {
    use super::super::{AnalyzerStore, decode_structural_nodes, decode_structural_roles};
    use super::*;
    use brokk_bifrost_core::analyzer::Range;
    use brokk_bifrost_core::analyzer::parsed_file::{SourceImportFact, SourceImportPathFact};
    use brokk_bifrost_core::analyzer::source_facts::{
        SourceDeclaration, SourceFactRows, SourceOccurrence,
    };
    use brokk_bifrost_core::analyzer::structural::callable::CallSiteFacts;
    use brokk_bifrost_core::analyzer::structural::facts::{
        NormalizedNode, RoleTarget, StructuralFactRows,
    };
    use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
    use brokk_bifrost_core::compact_graph::CompactRows;

    #[test]
    fn source_families_roundtrip_distinct_ranges_flags_and_import_counts() {
        let occurrence =
            |start_byte, end_byte, start_line, end_line, provenance| SourceOccurrence {
                range: Range {
                    start_byte,
                    end_byte,
                    start_line,
                    end_line,
                },
                provenance,
            };
        let id = SourceOccurrenceId::new;
        let occurrences = SourceFactRows::new(
            vec![
                occurrence(0, 100, 1, 8, SourceOccurrenceProvenance::PrimaryNode),
                occurrence(10, 40, 2, 4, SourceOccurrenceProvenance::ExplicitSubspan),
                occurrence(20, 30, 3, 4, SourceOccurrenceProvenance::Embedded),
            ],
            vec![SourceDeclaration {
                occurrence: id(0),
                name: Some(id(1)),
            }],
        );
        let nodes = (0..4)
            .map(|index| NormalizedNode {
                kind: if index == 3 {
                    NormalizedKind::Call
                } else {
                    NormalizedKind::StringLiteral
                },
                boolean_value: None,
                parenthesized: [Some(true), Some(false), None, None][index],
                assignment_shape: None,
                integer_literal_value: None,
                duplicate_key: None,
                is_async: None,
                unsafe_context: None,
                string_value: None,
                construct: None,
                occurrence: id(0),
                parent: None,
                name: Some(id(1)),
                subtree_end: index as u32 + 1,
                call_site: (index == 3).then(|| CallSiteFacts::unrefined().continuing()),
            })
            .collect();
        let roles = [false, true]
            .into_iter()
            .map(|spread| RoleTarget {
                role: Role::Kwarg,
                spread,
                keyword: Some(id(2)),
                node: None,
                occurrence: id(0),
                name: Some(id(1)),
            })
            .collect();
        let facts = ParsedSourceFacts {
            js_ts: None,
            php: None,
            cpp: None,
            go: None,
            java: None,
            scala: None,
            ruby: None,
            python: None,
            source_bytes: 100,
            occurrences,
            structural: StructuralFactRows::new(
                nodes,
                CompactRows::from_parts(vec![0, 2, 2, 2, 2], roles),
                CompactRows::from_parts(vec![0, 0, 0, 0, 0], vec![]),
                vec![],
            ),
            native_site_occurrences: vec![],
            native_declaration_sources: vec![],
            declaration_visibilities: None,
            rust_declaration_properties: vec![],
            rust_modules: None,
            rust_types: vec![],
            rust_items: Default::default(),
            imports: vec![SourceImportFact {
                declaration: id(1),
                target: Some(id(2)),
                alias_occurrence: None,
                statement: "import a.b.c".into(),
                is_wildcard: false,
                is_global: false,
                is_macro_use: false,
                identifier: Some("c".into()),
                alias: None,
                path: Some(SourceImportPathFact {
                    kind: None,
                    segments: vec!["a".into(), "b".into(), "c".into()],
                    lexical_prefixes: vec!["outer".into(), "inner".into()],
                    lexical_scopes: vec![id(0)],
                }),
            }],
            generic_imports: vec![],
            rust_import_contexts: vec![],
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let stored_facts = facts.clone();
        let blob_id = store.conn.execute(move |conn| {
            let facts = stored_facts;
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'fixture')",
                ["1111111111111111111111111111111111111111"],
            )
            .unwrap();
            let blob_id = tx.last_insert_rowid();
            super::super::tests::roundtrip_blob_meta(&tx, blob_id, "");
            insert_source_facts_tx(
                None,
                &tx,
                blob_id,
                &facts,
                &[],
                &[],
                &CancellationToken::new(),
            )
            .unwrap();
            tx.commit().unwrap();
            blob_id
        });
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let mut conn = store.read_conn().unwrap();
        let tx = conn.transaction().unwrap();
        assert_eq!(
            read_source_identity_rows(&tx, blob_id, 3, 1, &|| true)
                .unwrap()
                .unwrap(),
            facts.occurrences
        );
        assert_eq!(
            read_source_imports(&tx, blob_id, &|| true)
                .unwrap()
                .unwrap(),
            facts.imports
        );
        let counts: (usize, usize, usize, usize) = tx.query_row(
            "SELECT import_count, import_segment_count, import_scope_count, import_prefix_count FROM source_fact_manifests WHERE blob_id=?1",
            [blob_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).unwrap();
        assert_eq!(counts, (1, 3, 1, 2));
        for (table, expected) in [
            ("source_imports", 1),
            ("source_import_segments", 3),
            ("source_import_scopes", 1),
            ("source_import_prefixes", 2),
        ] {
            let count: usize = tx
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_id=?1"),
                    [blob_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, expected, "{table}");
        }
        let mut statement = tx.prepare("SELECT start_byte, end_byte, start_line, end_line, provenance FROM source_occurrences WHERE blob_id=?1 ORDER BY occurrence_id").unwrap();
        let rows = statement
            .query_map([blob_id], |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    row.get::<_, usize>(1)?,
                    row.get::<_, usize>(2)?,
                    row.get::<_, usize>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                (0, 100, 1, 8, "primary_node".into()),
                (10, 40, 2, 4, "explicit_subspan".into()),
                (20, 30, 3, 4, "embedded".into())
            ]
        );
        let name_range: (usize, usize, usize, usize) = tx.query_row(
            "SELECT name_start_byte, name_end_byte, name_start_line, name_end_line FROM source_declarations WHERE blob_id=?1",
            [blob_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).unwrap();
        assert_eq!(name_range, (10, 40, 2, 4));
        let (nodes, roles): (String, String) = tx
            .query_row(
                "SELECT json(nodes), json(roles) FROM source_structural_facts WHERE blob_id=?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let nodes = decode_structural_nodes(&nodes).unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.parenthesized)
                .collect::<Vec<_>>(),
            vec![Some(true), Some(false), None, None]
        );
        assert!(nodes[3].call_site.as_ref().unwrap().continues_callee_groups);
        let roles = decode_structural_roles(&roles).unwrap();
        assert_eq!(
            roles.iter().map(|role| role.spread).collect::<Vec<_>>(),
            vec![false, true]
        );
        for role in roles {
            let keyword = role.keyword.unwrap();
            let name = role.name.unwrap();
            assert_eq!((keyword.start, keyword.end), (20, 30));
            assert_eq!((name.start, name.end), (10, 40));
        }
    }
}
