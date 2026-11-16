//! Replayable module invocation reads, independent of summary output cutoffs.
use super::{AnalyzerStore, Result, StoreError, WorkspaceSnapshots};
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::read_ledger::LookupQuestion;
use crate::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_core::cancellation::CancellationToken;
use rusqlite::{Connection, params, types::ValueRef};

#[derive(Debug)]
pub struct RustMacroInvocation {
    pub relative_path: String,
    pub macro_name: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub private_module_route: bool,
}

pub struct RustMacroInvocationsAnswer {
    pub digest: StableDigest,
    pub invocations: Vec<RustMacroInvocation>,
}

// Read the producer's module-inventory verdict, rather than rediscovering
// eligible invocations from source ranges. LEFT JOINs hash missing evidence,
// attachments and anchors as absence independently of summary output cutoffs.
const SQL: &str = "SELECT member.rel_path, blob.blob_oid,
 gap.gap_kind, gap.subject, gap.detail,
 head.macro_name, head.start_byte, head.end_byte, head.provenance,
 property.visibility, evidence.value
 FROM selected_rust_unit_summaries unit
 LEFT JOIN main.rust_resolution_unit_summary_gaps gap
 ON gap.summary_id=unit.summary_id AND gap.gap_kind='open_export_inventory'
 AND gap.subject=?2
 LEFT JOIN json_each(gap.detail,'$.evidence') evidence
 ON json_extract(evidence.value,'$.kind')='macro_invocation'
 AND json_extract(evidence.value,'$.name')=?3
 AND json_extract(evidence.value,'$.unit_key')=hex(unit.unit_key)
 LEFT JOIN main.resolution_unit_summary_members member
 ON member.summary_id=unit.summary_id
 AND member.blob_id=json_extract(evidence.value,'$.member_blob')
 LEFT JOIN temp.selected_unit_member_blobs attachment
 ON attachment.summary_id=member.summary_id AND attachment.member_ordinal=member.member_ordinal
 LEFT JOIN main.blobs blob ON blob.id=attachment.blob_id
 LEFT JOIN source_rust_macro_invocations head
 ON head.blob_id=blob.id
 AND head.occurrence_id=json_extract(evidence.value,'$.invocation_occurrence')
 LEFT JOIN main.resolution_unit_summary_placements placement
 ON placement.summary_id=unit.summary_id AND placement.member_ordinal=member.member_ordinal
 AND placement.container_path=CASE ?2 WHEN 'crate' THEN '' ELSE ?2 END
 AND NOT EXISTS(SELECT 1 FROM temp.selected_rust_unplaced_placements unplaced
 WHERE unplaced.summary_id=placement.summary_id AND unplaced.container_path=placement.container_path
 AND unplaced.member_ordinal=placement.member_ordinal)
 LEFT JOIN temp.surface_dense dense ON dense.blob_id=blob.id AND dense.id_space=7
 AND dense.surface_ordinal=placement.scope_surface_ordinal
 LEFT JOIN source_rust_module_scopes scope
 ON scope.blob_id=blob.id AND scope.ordinal=dense.dense_id
 LEFT JOIN source_rust_declaration_properties property
 ON property.blob_id=scope.blob_id AND property.declaration_id=scope.declaration_id
 WHERE unit.unit_key=?1
 ORDER BY gap.gap_kind,gap.subject,gap.detail,member.rel_path,blob.blob_oid,
 head.start_byte,head.end_byte,head.provenance,property.visibility,evidence.value";

pub(super) fn read(
    conn: &Connection,
    question: &LookupQuestion,
) -> Result<RustMacroInvocationsAnswer> {
    let LookupQuestion::RustMacroInvocations {
        unit_key,
        module_path,
        macro_name,
    } = question
    else {
        return Err(StoreError::corrupt(
            "invalid Rust macro invocation question",
        ));
    };
    let mut hash = CanonicalHasher::new(b"bifrost-rust-macro-invocations:v1");
    hash.field("unit", unit_key.as_bytes());
    hash.field("module", module_path.as_bytes());
    hash.field("name", macro_name.as_bytes());
    let mut statement = conn.prepare_cached(SQL)?;
    let mut rows = statement.query(params![
        unit_key.as_bytes().as_slice(),
        module_path.as_ref(),
        macro_name.as_ref()
    ])?;
    let mut invocations = Vec::new();
    let mut missing_anchor = false;
    while let Some(row) = rows.next()? {
        hash.value(b"row");
        for column in 0..11 {
            match row.get_ref(column)? {
                ValueRef::Null => hash.value(b"null"),
                ValueRef::Integer(value) => hash.value(&value.to_be_bytes()),
                ValueRef::Text(value) | ValueRef::Blob(value) => hash.value(value),
                ValueRef::Real(_) => unreachable!("invocation facts contain no real values"),
            }
        }
        if let Some(name) = row.get::<_, Option<String>>(5)? {
            invocations.push(RustMacroInvocation {
                relative_path: row.get(0)?,
                macro_name: name,
                start_byte: row.get(6)?,
                end_byte: row.get(7)?,
                private_module_route: row
                    .get::<_, Option<String>>(9)?
                    .is_some_and(|v| v != "public"),
            });
        } else if row.get::<_, Option<String>>(10)?.is_some() {
            missing_anchor = true;
        }
    }
    if missing_anchor {
        invocations.clear();
    }
    Ok(RustMacroInvocationsAnswer {
        digest: StableDigest::from_array(hash.finish()),
        invocations,
    })
}

impl AnalyzerStore {
    pub fn rust_macro_invocations_answer(
        &self,
        snapshots: &WorkspaceSnapshots,
        question: &LookupQuestion,
        cancellation: &CancellationToken,
    ) -> Result<RustMacroInvocationsAnswer> {
        let conn = self.read_conn_for_workspace(snapshots)?;
        super::resolution::with_resolution_read_progress_handler(&conn, cancellation, |conn| {
            read(conn, question)
        })
    }
}
