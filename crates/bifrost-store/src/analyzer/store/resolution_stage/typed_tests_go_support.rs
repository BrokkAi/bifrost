#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_23 {

    use crate::analyzer::store::resolution_stage::typed::*;

    #[doc(hidden)]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    pub fn begin_projection<'a>(
        selection: &'a SelectedResolutionMountInventory<'_>,
    ) -> &'a Connection {
        let connection = selection.connection();
        connection.execute_batch("BEGIN; INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,7,zeroblob(32),zeroblob(32))").unwrap();
        connection
    }
}
