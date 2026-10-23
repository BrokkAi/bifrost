#[cfg(test)]
#[cfg(not(test))]
use super::super::coordinates::PreparedStageCoordinates;

use super::*;
use crate::analyzer::resolution::{
    PerRequestSharedNames, ResolutionIdentityCatalogBuilder, ResolutionNodeIdentity,
    ResolutionPathIdentity, ResolutionSemanticIdentity, ResolutionStackVariableIdentity,
};

#[cfg(test)]
#[cfg(not(test))]
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionTempTransaction, selection_test_support::SelectionFixture,
};

#[doc(hidden)]
pub fn catalog() -> ResolutionIdentityCatalog {
    let names = PerRequestSharedNames::new();
    let mut builder =
        ResolutionIdentityCatalogBuilder::new(BindingFragmentId::at_ordinal(0), &names);
    builder.semantic(ResolutionSemanticIdentity::fragment_local([201; 32]));
    builder.shared_name([202; 32]);
    builder.node(ResolutionNodeIdentity::new([203; 32]));
    builder.path(ResolutionPathIdentity::new([204; 32]));
    builder.stack_variable(ResolutionStackVariableIdentity::new([205; 32]));
    builder.finish()
}

#[doc(hidden)]
pub fn producer(connection: &Connection, host: u32, marker: u8) -> Result<i64> {
    connection.execute(
        "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
        params![host,[marker;32].as_slice(),[marker;32].as_slice()],
    )?;
    Ok(connection.last_insert_rowid())
}

#[doc(hidden)]
pub fn counters(connection: &Connection) -> Vec<(u32, i64, i64)> {
    connection.prepare("SELECT host_ordinal,domain,next_key FROM temp.selected_resolution_stage_allocation_counters ORDER BY host_ordinal,domain").unwrap()
        .query_map([],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap()
        .collect::<rusqlite::Result<Vec<_>>>().unwrap()
}
