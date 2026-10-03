//! Relational publication of source-owned Ruby load facts.

use crate::CancellationToken;
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::ruby_facts::*;
use rusqlite::{Transaction, params};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.ruby.as_ref().map(cost),
    insert,
};

pub(crate) fn cost(facts: &RubySourceFacts) -> (usize, usize) {
    let constants = facts
        .loads
        .iter()
        .filter_map(|load| load.autoload_constant.as_ref());
    (
        1 + facts.loads.len() + constants.clone().map(Vec::len).sum::<usize>(),
        constants.flatten().map(String::len).sum(),
    )
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = &source.ruby else {
        return Ok(());
    };
    assert_eq!(
        facts.loads.len(),
        source.imports.len(),
        "every Ruby load has one canonical import"
    );
    if let Some((boundary, _)) = facts.runtime_boundary {
        assert!(
            boundary.index() < source.occurrences.occurrence_count(),
            "Ruby runtime boundary occurrence {boundary:?} is outside the blob's {} source occurrences",
            source.occurrences.occurrence_count()
        );
    }
    let mut loads = tx.prepare_cached("INSERT INTO source_ruby_loads(blob_id,import_id,kind,has_receiver,has_constant) VALUES(?1,?2,?3,?4,?5)")?;
    let mut constants = tx.prepare_cached("INSERT INTO source_ruby_load_constants(blob_id,import_id,ordinal,segment) VALUES(?1,?2,?3,?4)")?;
    for (index, load) in facts.loads.iter().enumerate() {
        check_cancelled(cancellation)?;
        assert_eq!(
            load.import.index(),
            index,
            "Ruby load/import identities are dense"
        );
        let kind = match load.kind {
            RubyLoadKind::Require => 0,
            RubyLoadKind::RequireRelative => 1,
            RubyLoadKind::Load => 2,
            RubyLoadKind::Autoload => 3,
        };
        loads.execute(params![
            blob_id,
            load.import.get(),
            kind,
            load.has_receiver,
            load.autoload_constant.is_some()
        ])?;
        if let Some(parts) = &load.autoload_constant {
            assert!(
                !parts.is_empty() && parts.iter().all(|part| !part.is_empty()),
                "Ruby constant paths contain nonempty AST segments"
            );
            for (ordinal, part) in parts.iter().enumerate() {
                check_cancelled(cancellation)?;
                constants.execute(params![
                    blob_id,
                    load.import.get(),
                    usize_to_i64(ordinal)?,
                    part
                ])?;
            }
        }
    }
    drop((loads, constants));
    let (rows, bytes) = cost(facts);
    tx.execute("INSERT INTO source_ruby_manifests(blob_id,facts_version,logical_rows,payload_bytes,has_parse_errors,runtime_boundary_occurrence_id,runtime_boundary_kind) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![blob_id,RUBY_SOURCE_FACTS_VERSION,usize_to_i64(rows)?,usize_to_i64(bytes)?,facts.has_parse_errors,facts.runtime_boundary.map(|(id,_)| id.get()),facts.runtime_boundary.map(|(_,kind)| kind as u8)])?;
    Ok(())
}
