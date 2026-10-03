//! Exact selected projection from native definition semantics to parsed units.

use std::collections::BTreeSet;

use crate::CancellationToken;
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::resolution::{ResolutionLocalKey, SelectedResolutionMountOrdinal};
use crate::analyzer::{DeclarationKind, Range};

use super::resolution::with_resolution_read_progress_handler;
use super::resolution_selection::{SELECTED_MOUNT_PAGE_ROWS, SelectedResolutionMountInventory};
use super::{HydratedCandidateRow, Result, StoreError, hydrate_candidate_rows};

pub(crate) enum SelectedDefinitionUnitReadOutcome {
    Ready(
        Box<
            [(
                SelectedResolutionMountOrdinal,
                ResolutionLocalKey,
                HydratedCandidateRow,
            )],
        >,
    ),
    Cancelled,
}

pub(crate) enum SelectedDefinitionSemanticReadOutcome {
    Ready(Box<[(ResolutionLocalKey, HydratedCandidateRow)]>),
    Cancelled,
}

/// One source declaration behind a native definition semantic.
///
/// A value binder gets a lexical kind and a stored identifier from the parser
/// and no `CodeUnit`; an item the parser can name gets a `CodeUnit` and no
/// lexical kind. An item the parser cannot name gets neither: an associated
/// item of an `impl` whose self type is not a declarable path (`impl Output
/// for usize`, `impl PartialEq for dyn Lut`), an item inside a macro token
/// tree, or a second item declared under a different `cfg`. The declaration
/// row and the native bridge exist for all three, so this reader answers for
/// all three and the caller decides what each one means to it.
#[derive(Debug)]
pub(crate) enum SelectedDeclarationDefinition {
    Lexical(LexicalDefinition),
    /// The declaration's own source range. There is no stored identifier and
    /// no lexical kind to report, because the parser published neither.
    WithoutUnit(Range),
}

pub(crate) enum SelectedLexicalDefinitionReadOutcome {
    Ready(
        Vec<(
            SelectedResolutionMountOrdinal,
            ResolutionLocalKey,
            SelectedDeclarationDefinition,
        )>,
    ),
    Cancelled,
}

// Requests are bounded and every declaration/occurrence join uses canonical
// keys. Source ranges and spelling are presentation, never lookup predicates.
// `lexical_kind` and `lexical_identifier` are read, not filtered on: a
// declaration that carries neither is an item with no `CodeUnit`, which is a
// projection this reader must answer rather than drop.
pub(super) const SELECTED_LEXICAL_DEFINITIONS_SQL: &str =
    "SELECT request.mount_ordinal, request.key0,
            declaration.lexical_kind, declaration.lexical_identifier,
            declaration.start_byte, declaration.end_byte,
            declaration.start_line, declaration.end_line,
            declaration.name_start_byte, declaration.name_end_byte,
            declaration.name_start_line, declaration.name_end_line
     FROM temp.selected_resolution_typed_requests_1 AS request
     CROSS JOIN temp.selected_resolution_mounts AS mount
       ON mount.mount_ordinal = request.mount_ordinal
     CROSS JOIN main.resolution_fragment_interiors AS interior
       ON interior.blob_id = mount.blob_id
      AND interior.lang = mount.storage_language
      AND interior.semantic_language = mount.semantic_language
      AND interior.producer_epoch = mount.producer_epoch
      AND interior.interior_digest = mount.interior_digest
      AND interior.publication_state = 'complete'
     CROSS JOIN main.source_fact_manifests AS source
       ON source.blob_id = interior.blob_id AND source.publication_state = 'complete'
     CROSS JOIN main.resolution_semantic_sites AS semantic
       ON semantic.blob_id = interior.blob_id
      AND semantic.semantic_role = 'definition' AND semantic.semantic_key = request.key0
     CROSS JOIN main.source_native_declaration_bridges AS bridge
       ON bridge.blob_id = semantic.blob_id AND bridge.source_site = semantic.source_site
     CROSS JOIN main.source_declarations AS declaration
       ON declaration.blob_id = bridge.blob_id
      AND declaration.declaration_id = bridge.declaration_id
      AND declaration.name_occurrence_id IS NOT NULL";

/// The hydrated `code_units` columns every selected unit reader projects, in
/// the order `candidate_row_from_row` reads them.
const SELECTED_UNIT_COLUMNS: &str = "keys.blob_oid, units.lang, units.unit_key, units.kind,
     units.short_name, units.content_qualifier, units.signature,
     units.synthetic, units.is_type_alias, units.top_level_ordinal,
     units.in_declarations, units.in_definition_lookup,
     units.fq_anchor_kind, units.fq_anchor_pop,
     units.fq_package_tail_segments, units.fq_segment_count,
     units.exact_fqn_tail, units.fq_segment_bytes,
     units.normalized_fqn_tail";

/// The mount and interior joins every request-driven selected reader opens.
const SELECTED_REQUEST_INTERIOR_JOINS: &str =
    "FROM temp.selected_resolution_typed_requests_1 AS request
     CROSS JOIN temp.selected_resolution_mounts AS mount
       ON mount.mount_ordinal = request.mount_ordinal
     CROSS JOIN main.resolution_fragment_interiors AS interior
       ON interior.blob_id = mount.blob_id
      AND interior.lang = mount.storage_language
      AND interior.semantic_language = mount.semantic_language
      AND interior.producer_epoch = mount.producer_epoch
      AND interior.interior_digest = mount.interior_digest
      AND interior.publication_state = 'complete'";

/// Exact requested definition coordinates drive hydration independently of
/// unrelated units in the same blob or mounts elsewhere in the selection.
pub(super) static SELECTED_DEFINITION_UNITS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "SELECT {SELECTED_UNIT_COLUMNS}, request.mount_ordinal, request.key0
                     {SELECTED_REQUEST_INTERIOR_JOINS}
                     CROSS JOIN main.resolution_definition_unit_crosswalks AS crosswalk
                       ON crosswalk.blob_id = interior.blob_id
                      AND crosswalk.definition_semantic_key = request.key0
                     CROSS JOIN main.code_units AS units
                       ON units.blob_id = crosswalk.blob_id
                      AND units.unit_key = crosswalk.unit_key
                     CROSS JOIN main.blobs AS keys
                       ON keys.id = units.blob_id
                     CROSS JOIN main.blob_meta AS meta
                       ON meta.blob_id = units.blob_id
                     WHERE units.in_declarations = 1
                       AND {}
                     ORDER BY request.mount_ordinal, request.key0",
            super::PARSED_BLOB_COMPLETE_CONDITION
        )
    });

/// The same projection reached through the source declaration a definition
/// bridges to, rather than through the definition-to-unit crosswalk.
///
/// `resolution_definition_unit_crosswalks` is injective on `unit_key`: it
/// answers both directions, and the unit-to-definition direction needs one
/// definition per unit. The parser's own `source_declaration_units` relation
/// is not injective, and two declarations that share one `CodeUnit` are
/// ordinary Rust source: `pub fn value` twice in one `impl`, or the same item
/// declared under two `cfg`s. The first of them claims the crosswalk row and
/// the rest have none, so this reader answers the same question from the
/// relation that kept every link.
pub(super) static SELECTED_DECLARATION_UNITS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "SELECT {SELECTED_UNIT_COLUMNS}, request.mount_ordinal, request.key0
                     {SELECTED_REQUEST_INTERIOR_JOINS}
                     CROSS JOIN main.source_fact_manifests AS source
                       ON source.blob_id = interior.blob_id
                      AND source.publication_state = 'complete'
                     CROSS JOIN main.resolution_semantic_sites AS semantic
                       ON semantic.blob_id = interior.blob_id
                      AND semantic.semantic_role = 'definition'
                      AND semantic.semantic_key = request.key0
                     CROSS JOIN main.source_native_declaration_bridges AS bridge
                       ON bridge.blob_id = semantic.blob_id
                      AND bridge.source_site = semantic.source_site
                     CROSS JOIN main.source_declaration_units AS link
                       ON link.blob_id = bridge.blob_id
                      AND link.declaration_id = bridge.declaration_id
                     CROSS JOIN main.code_units AS units
                       ON units.blob_id = link.blob_id
                      AND units.unit_key = link.unit_key
                     CROSS JOIN main.blobs AS keys
                       ON keys.id = units.blob_id
                     CROSS JOIN main.blob_meta AS meta
                       ON meta.blob_id = units.blob_id
                     WHERE units.in_declarations = 1
                       AND {}
                     ORDER BY request.mount_ordinal, request.key0",
            super::PARSED_BLOB_COMPLETE_CONDITION
        )
    });

/// The `CodeUnit` of the crate-declared macro item one staged capsule
/// definition lowered.
///
/// A capsule parses its invocation at the host file's byte offsets, so the
/// definition it stages for an item sits at the byte range where declaration
/// replay recorded that item's name, and replay's declaration carries the
/// item's `CodeUnit`. Only an item the crate declared
/// (`rust_crate_macro_items`, a cross-file passthrough whose rules expand to
/// their arguments) is linked: a capsule lowers an invocation's arguments, not
/// its transcriber's output, so for any other macro the staged item and the
/// item the expansion really declares are not known to be the same one.
///
/// `?1` is the host mount, `?2`/`?3` the staged semantic's key and shared id,
/// `?4` the definition role code.
pub(super) static SELECTED_MACRO_ITEM_UNIT_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "SELECT DISTINCT {SELECTED_UNIT_COLUMNS}
             FROM temp.selected_resolution_stage_semantics AS staged
             CROSS JOIN temp.selected_resolution_mounts AS mount
               ON mount.mount_ordinal = staged.host_ordinal
             CROSS JOIN main.rust_crate_macro_items AS item
                 INDEXED BY rust_crate_macro_items_declaration
               ON item.blob_id = mount.blob_id
             CROSS JOIN main.source_declarations AS declaration
               ON declaration.blob_id = item.blob_id
              AND declaration.declaration_id = item.declaration_id
              AND declaration.name_start_byte = staged.start_byte
              AND declaration.name_end_byte = staged.end_byte
             CROSS JOIN main.source_declaration_units AS link
               ON link.blob_id = declaration.blob_id
              AND link.declaration_id = declaration.declaration_id
             CROSS JOIN main.code_units AS units
               ON units.blob_id = link.blob_id
              AND units.unit_key = link.unit_key
             CROSS JOIN main.blobs AS keys
               ON keys.id = units.blob_id
             CROSS JOIN main.blob_meta AS meta
               ON meta.blob_id = units.blob_id
             WHERE staged.host_ordinal = ?1
               AND staged.semantic_key IS ?2 AND staged.semantic_shared IS ?3
               AND staged.role = ?4
               AND units.in_declarations = 1
               AND EXISTS(SELECT 1 FROM selected_rust_crates AS selected
                          WHERE selected.topology_id = item.topology_id)
               AND {}",
            super::PARSED_BLOB_COMPLETE_CONDITION
        )
    });

#[cfg(test)]
thread_local! {
    static SELECTED_DEFINITION_UNIT_SQL_WORK: std::cell::Cell<(u64, u64)> = const {
        std::cell::Cell::new((0, 0))
    };
}

/// Executions and VM steps of the unit hydration statements only, excluding
/// request-table writes and subsequent candidate metadata hydration.
#[cfg(test)]
pub(super) fn take_selected_definition_unit_sql_work() -> (u64, u64) {
    SELECTED_DEFINITION_UNIT_SQL_WORK.with(|work| work.replace((0, 0)))
}

pub(super) const SELECTED_DEFINITION_BLOB_SQL: &str = "SELECT interior.blob_id FROM temp.selected_resolution_mounts AS mount CROSS JOIN main.resolution_fragment_interiors AS interior ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language AND interior.semantic_language=mount.semantic_language AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest AND interior.publication_state='complete' WHERE mount.mount_ordinal=?1";
pub(super) static DEFINITION_SEMANTICS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "SELECT {SELECTED_UNIT_COLUMNS},
                            crosswalk.definition_semantic_key
                     FROM main.resolution_fragment_interiors AS interior
                     JOIN main.resolution_definition_unit_crosswalks AS crosswalk
                       ON crosswalk.blob_id = interior.blob_id
                     JOIN main.code_units AS units
                       ON units.blob_id = crosswalk.blob_id
                      AND units.unit_key = crosswalk.unit_key
                     JOIN main.blobs AS keys
                       ON keys.id = units.blob_id
                     JOIN main.blob_meta AS meta
                       ON meta.blob_id = units.blob_id
                     WHERE interior.blob_id = ?1 AND interior.publication_state = 'complete'
                       AND units.in_declarations = 1
                       AND {}
                     ORDER BY crosswalk.definition_semantic_key",
            super::PARSED_BLOB_COMPLETE_CONDITION,
        )
    });

impl SelectedResolutionMountInventory<'_> {
    pub(crate) fn selected_lexical_definitions(
        &self,
        definitions: &[(SelectedResolutionMountOrdinal, ResolutionLocalKey)],
        cancellation: &CancellationToken,
    ) -> Result<SelectedLexicalDefinitionReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedLexicalDefinitionReadOutcome::Cancelled);
        }
        let mut all_rows = Vec::new();
        for page in definitions.chunks(SELECTED_MOUNT_PAGE_ROWS) {
            if !self.replace_resolution_requests_1(
                page.iter().map(|(mount, key)| (*mount, key.get())),
                cancellation,
            )? {
                return Ok(SelectedLexicalDefinitionReadOutcome::Cancelled);
            }
            let rows =
                with_resolution_read_progress_handler(self.connection(), cancellation, |conn| {
                    let mut statement = conn.prepare(SELECTED_LEXICAL_DEFINITIONS_SQL)?;
                    statement
                        .query_map([], |row| {
                            let range = |offset| -> rusqlite::Result<Range> {
                                Ok(Range {
                                    start_byte: row.get(offset)?,
                                    end_byte: row.get(offset + 1)?,
                                    start_line: row.get(offset + 2)?,
                                    end_line: row.get(offset + 3)?,
                                })
                            };
                            Ok((
                                SelectedResolutionMountOrdinal::new(row.get(0)?),
                                ResolutionLocalKey::new(row.get(1)?),
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                range(4)?,
                                range(8)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map_err(StoreError::from)
                });
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    return Ok(SelectedLexicalDefinitionReadOutcome::Cancelled);
                }
                Err(error) => return Err(error),
            };
            for (mount, definition, kind, identifier, declaration_range, name_range) in rows {
                // `source_declarations` checks that the lexical kind and the
                // lexical identifier are either both stored or both absent,
                // so the two halves cannot disagree here.
                let projected = match (kind, identifier) {
                    (Some(kind), Some(identifier)) => {
                        let kind = DeclarationKind::from_label(&kind).ok_or_else(|| {
                            StoreError::new(format!(
                                "invalid selected lexical declaration kind {kind:?}"
                            ))
                        })?;
                        SelectedDeclarationDefinition::Lexical(LexicalDefinition {
                            source_file: None,
                            identifier,
                            kind,
                            name_range,
                            declaration_range,
                        })
                    }
                    (None, None) => SelectedDeclarationDefinition::WithoutUnit(declaration_range),
                    (kind, identifier) => unreachable!(
                        "a source declaration stores its lexical kind and identifier together: {kind:?}, {identifier:?}"
                    ),
                };
                all_rows.push((mount, definition, projected));
            }
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedLexicalDefinitionReadOutcome::Cancelled);
        }
        Ok(SelectedLexicalDefinitionReadOutcome::Ready(all_rows))
    }

    /// Read every parser-unit crosswalk in one selected file.
    ///
    /// The caller compares the hydrated units with an analyzer-owned target;
    /// this reader deliberately stays in stored identity space and does not
    /// reconstruct a declaration from rendered names.
    pub(crate) fn selected_definition_semantics_for_mount(
        &self,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<SelectedDefinitionSemanticReadOutcome> {
        let blob: i64 = self
            .connection()
            .prepare_cached(SELECTED_DEFINITION_BLOB_SQL)?
            .query_row([i64::from(mount.get())], |row| row.get(0))?;
        self.definition_semantics_for_blob(blob, cancellation)
    }

    /// Hydrate one immutable blob's declaration crosswalk. An overlay reader
    /// uses its masked file version to locate the persisted base explicitly.
    pub(crate) fn definition_semantics_for_blob(
        &self,
        blob: i64,
        cancellation: &CancellationToken,
    ) -> Result<SelectedDefinitionSemanticReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedDefinitionSemanticReadOutcome::Cancelled);
        }
        let result =
            with_resolution_read_progress_handler(self.connection(), cancellation, |conn| {
                let mut statement = conn.prepare(&DEFINITION_SEMANTICS_SQL)?;
                let rows = statement
                    .query_map([blob], |row| {
                        Ok((
                            super::candidate_row_from_row(row)?,
                            ResolutionLocalKey::new(row.get::<_, i64>(19)?),
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(statement);
                hydrate_candidate_rows(conn, rows, Some(cancellation))
            })?;
        let Some(rows) = result else {
            return Ok(SelectedDefinitionSemanticReadOutcome::Cancelled);
        };
        // The key is the catalog position and a local runtime id is the mount
        // ordinal and that position, so no caller needs the identity the
        // crosswalk also stores. `resolution_definition_unit_crosswalks`
        // keeps writing `identity_digest` and nothing reads it; the column
        // goes with the schema, which this lane does not change.
        let decoded = rows
            .into_iter()
            .map(|(row, definition)| (definition, row))
            .collect::<Vec<_>>();
        Ok(SelectedDefinitionSemanticReadOutcome::Ready(
            decoded.into_boxed_slice(),
        ))
    }

    pub(crate) fn selected_definition_units(
        &self,
        definitions: &[(SelectedResolutionMountOrdinal, ResolutionLocalKey)],
        cancellation: &CancellationToken,
    ) -> Result<SelectedDefinitionUnitReadOutcome> {
        self.selected_units_by_coordinate(
            SELECTED_DEFINITION_UNITS_SQL.as_str(),
            definitions,
            cancellation,
        )
    }

    /// The same coordinates read through the source declaration each
    /// definition bridges to.
    ///
    /// A definition whose parser unit another definition already holds the
    /// crosswalk row for has no row in `selected_definition_units` and is
    /// still an ordinary declaration with an ordinary unit. See
    /// [`SELECTED_DECLARATION_UNITS_SQL`].
    pub(crate) fn selected_declaration_units(
        &self,
        definitions: &[(SelectedResolutionMountOrdinal, ResolutionLocalKey)],
        cancellation: &CancellationToken,
    ) -> Result<SelectedDefinitionUnitReadOutcome> {
        self.selected_units_by_coordinate(
            SELECTED_DECLARATION_UNITS_SQL.as_str(),
            definitions,
            cancellation,
        )
    }

    /// See [`SELECTED_MACRO_ITEM_UNIT_SQL`]. `None` when cancelled; an empty
    /// row when the staged definition is not a crate-declared item.
    pub(crate) fn selected_macro_item_unit(
        &self,
        host: SelectedResolutionMountOrdinal,
        definition: crate::analyzer::resolution::SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Option<HydratedCandidateRow>>> {
        let (key, shared) = super::resolution_stage::lexical::semantic_cells(definition);
        let result =
            with_resolution_read_progress_handler(self.connection(), cancellation, |conn| {
                let rows = conn
                    .prepare_cached(SELECTED_MACRO_ITEM_UNIT_SQL.as_str())?
                    .query_map(
                        rusqlite::params![
                            i64::from(host.get()),
                            key,
                            shared,
                            super::resolution_prepare::resolution_rows::semantic_role_code(
                                crate::analyzer::resolution::LoweredSemanticRole::Definition
                            )
                        ],
                        super::candidate_row_from_row,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                hydrate_candidate_rows(conn, rows, Some(cancellation))
            })?;
        let Some(mut rows) = result else {
            return Ok(None);
        };
        assert!(
            rows.len() <= 1,
            "one staged definition names one crate-declared item: {definition:?}"
        );
        Ok(Some(rows.pop()))
    }

    fn selected_units_by_coordinate(
        &self,
        sql: &str,
        definitions: &[(SelectedResolutionMountOrdinal, ResolutionLocalKey)],
        cancellation: &CancellationToken,
    ) -> Result<SelectedDefinitionUnitReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedDefinitionUnitReadOutcome::Cancelled);
        }
        let requests = definitions.iter().copied().collect::<BTreeSet<_>>();
        if requests.len() != definitions.len() {
            return Err(StoreError::new(
                "selected definition projection received duplicate coordinates",
            ));
        }
        let requests = requests.into_iter().collect::<Vec<_>>();
        let mut all_rows = Vec::new();
        for page in requests.chunks(SELECTED_MOUNT_PAGE_ROWS) {
            if !self.replace_resolution_requests_1(
                page.iter().map(|(mount, key)| (*mount, key.get())),
                cancellation,
            )? {
                return Ok(SelectedDefinitionUnitReadOutcome::Cancelled);
            }
            let result =
                with_resolution_read_progress_handler(self.connection(), cancellation, |conn| {
                    let mut statement = conn.prepare(sql)?;
                    let rows = statement
                        .query_map([], |row| {
                            Ok((
                                super::candidate_row_from_row(row)?,
                                (
                                    SelectedResolutionMountOrdinal::new(row.get::<_, u32>(19)?),
                                    ResolutionLocalKey::new(row.get::<_, i64>(20)?),
                                ),
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    #[cfg(test)]
                    SELECTED_DEFINITION_UNIT_SQL_WORK.with(|work| {
                        let (executions, steps) = work.get();
                        work.set((
                            executions + 1,
                            steps
                                + u64::try_from(
                                    statement.get_status(rusqlite::StatementStatus::VmStep),
                                )
                                .expect("SQLite VM steps are nonnegative"),
                        ));
                    });
                    drop(statement);
                    hydrate_candidate_rows(conn, rows, Some(cancellation))
                })?;
            let Some(rows) = result else {
                return Ok(SelectedDefinitionUnitReadOutcome::Cancelled);
            };
            all_rows.extend(rows);
            if cancellation.is_cancelled() {
                return Ok(SelectedDefinitionUnitReadOutcome::Cancelled);
            }
        }
        if all_rows.len() > requests.len() {
            return Err(StoreError::new(
                "selected definition projection returned duplicate parser units",
            ));
        }
        Ok(SelectedDefinitionUnitReadOutcome::Ready(
            all_rows
                .into_iter()
                .map(|(row, (mount, definition))| (mount, definition, row))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ))
    }
}
