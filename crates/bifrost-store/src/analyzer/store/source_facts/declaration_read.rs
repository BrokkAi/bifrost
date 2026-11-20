//! Shared materialization of a selected canonical declaration identity arena.

use super::super::{Result, StoreError};
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::model::DeclarationKind;
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclaration, SourceDeclarationId, SourceFactRows, SourceLexicalDeclarationFact,
    SourceOccurrence, SourceOccurrenceId,
};
use rusqlite::Connection;

#[doc(hidden)]
pub fn read_source_identity_rows(
    tx: &Connection,
    blob_id: i64,
    expected_occurrences: usize,
    expected_declarations: usize,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<SourceFactRows>> {
    #[cfg(any(debug_assertions, test))]
    {
        // C# source facts retire through the bundle epoch. Its readers must use
        // epoch-gated selection and ownership joins, never this raw blob API.
        let language: String =
            tx.query_row("SELECT lang FROM blobs WHERE id = ?1", [blob_id], |row| {
                row.get(0)
            })?;
        assert_ne!(
            language,
            brokk_bifrost_core::analyzer::Language::CSharp.config_label(),
            "C# source facts require epoch-gated selection and ownership joins"
        );
    }
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
    // The arena is one row: a JSONB array with one entry an occurrence, in id
    // order (lane ST, milestone 5). This is the only reader that takes it
    // whole, and the only one that wants the lines and the provenance.
    let mut occurrences = Vec::with_capacity(expected_occurrences);
    read_rows!(
        "SELECT json_extract(entry.value, '$[0]'), json_extract(entry.value, '$[1]'),
                json_extract(entry.value, '$[2]'), json_extract(entry.value, '$[3]'),
                json_extract(entry.value, '$[4]')
         FROM source_occurrence_arenas AS arena, json_each(arena.spans) AS entry
         WHERE arena.blob_id = ?1 ORDER BY entry.key",
        row,
        {
            let range = Range {
                start_byte: row.get(0)?,
                end_byte: row.get(1)?,
                start_line: row.get(2)?,
                end_line: row.get(3)?,
            };
            if range.start_byte > range.end_byte
                || range.start_line == 0
                || range.start_line > range.end_line
            {
                return Err(StoreError::new(format!(
                    "invalid canonical source occurrence {}: {range:?}",
                    occurrences.len()
                )));
            }
            occurrences.push(SourceOccurrence {
                range,
                provenance: super::provenance_from_code(row.get(4)?)?,
            });
        }
    );
    let mut declarations = Vec::new();
    let mut lexical_declarations = Vec::new();
    read_rows!(
        "SELECT declaration_id, occurrence_id, name_occurrence_id,
                    lexical_kind, lexical_identifier
                    FROM source_declarations WHERE blob_id = ?1 ORDER BY declaration_id",
        row,
        {
            let id: usize = row.get(0)?;
            let declaration_id = SourceDeclarationId::try_from_index(id).map_err(|_| {
                StoreError::new(format!("invalid canonical source declaration id {id}"))
            })?;
            let occurrence = SourceOccurrenceId::new(row.get(1)?);
            let name = row.get::<_, Option<u32>>(2)?.map(SourceOccurrenceId::new);
            let lexical_kind: Option<String> = row.get(3)?;
            let lexical_identifier: Option<String> = row.get(4)?;
            let lexical = match (lexical_kind, lexical_identifier) {
                (None, None) => None,
                (Some(kind), Some(identifier)) => {
                    let kind = DeclarationKind::from_label(&kind).ok_or_else(|| {
                        StoreError::new(format!(
                            "invalid canonical lexical declaration kind {kind:?}"
                        ))
                    })?;
                    if identifier.is_empty() {
                        return Err(StoreError::new(
                            "canonical lexical declaration identifier is empty",
                        ));
                    }
                    if name.is_none() {
                        return Err(StoreError::new(
                            "canonical lexical declaration is missing its name occurrence",
                        ));
                    }
                    Some(SourceLexicalDeclarationFact {
                        declaration: declaration_id,
                        kind,
                        identifier,
                    })
                }
                (kind, identifier) => {
                    return Err(StoreError::new(format!(
                        "canonical lexical declaration metadata has a half-null pair: {kind:?}, {identifier:?}"
                    )));
                }
            };
            if id != declarations.len()
                || occurrence.index() >= occurrences.len()
                || name.is_some_and(|name| {
                    name.index() >= occurrences.len()
                        || occurrences[name.index()].range.start_byte
                            < occurrences[occurrence.index()].range.start_byte
                        || occurrences[name.index()].range.end_byte
                            > occurrences[occurrence.index()].range.end_byte
                })
            {
                return Err(StoreError::new(format!(
                    "invalid canonical source declaration {id}: {occurrence:?}, {name:?}"
                )));
            }
            declarations.push(SourceDeclaration { occurrence, name });
            if let Some(lexical) = lexical {
                lexical_declarations.push(lexical);
            }
        }
    );
    if occurrences.len() != expected_occurrences || declarations.len() != expected_declarations {
        return Err(StoreError::new(
            "incomplete canonical source identity arena",
        ));
    }
    let source = SourceFactRows::new(occurrences, declarations)
        .with_lexical_declarations(lexical_declarations);

    Ok(Some(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "C# source facts require epoch-gated selection and ownership joins")]
    fn raw_csharp_identity_read_requires_selected_epoch_authority() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE blobs(id INTEGER PRIMARY KEY, lang TEXT NOT NULL)")
            .unwrap();
        conn.execute(
            "INSERT INTO blobs(id, lang) VALUES(1, ?1)",
            [brokk_bifrost_core::analyzer::Language::CSharp.config_label()],
        )
        .unwrap();
        // No source tables exist: the language guard must run before any arena read.
        assert!(
            read_source_identity_rows(&conn, 1, 0, 0, &|| true)
                .unwrap()
                .is_some()
        );
    }
}
