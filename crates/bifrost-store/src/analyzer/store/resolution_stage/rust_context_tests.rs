#[cfg(any(test, feature = "test-support"))]
use self::rust_wave2_root_test_support::*;

use super::*;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution_stage::codec;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;

#[cfg(any(test, feature = "test-support"))]
use rusqlite::Connection;

#[cfg(any(test, feature = "test-support"))]
use rusqlite::params;

// These synthetic rows exercise storage decoding and planner growth only. The
// authenticated producer contract is exercised separately above.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn insert_context(
    connection: &Connection,
    producer: i64,
    host: u32,
    semantic: SemanticId,
    n: u32,
) -> Context {
    let cell = codec::encode_semantic(semantic);
    let (key, shared) = if cell < 0 {
        (None, Some(-cell))
    } else {
        (Some(cell), None)
    };
    let cfg = match n % 4 {
        0 => RustCfgCondition::Always,
        1 => RustCfgCondition::Atom("feature=enabled".into()),
        2 => RustCfgCondition::NotAtom("test".into()),
        _ => RustCfgCondition::Unknown,
    };
    let declaration = n
        .is_multiple_of(2)
        .then(|| SourceDeclarationId::new(4000 + n));
    connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3,zeroblob(32))",params![producer,host,{let mut digest=[0u8;32];digest[..8].copy_from_slice(&producer.to_le_bytes());digest}]).unwrap();
    connection.execute("INSERT INTO temp.selected_resolution_stage_semantic_coordinates(host_ordinal,producer_id,dense_key,runtime_key,shared_id,identity_digest) VALUES(?1,?2,0,?3,?4,zeroblob(32))",params![host,producer,key,shared]).unwrap();
    connection.execute("INSERT INTO temp.selected_resolution_stage_reference_contexts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,jsonb(?9),0,NULL,NULL)",
        params![host,producer,key,shared,1000+n,2000+n,3000+n,declaration.map(|d|d.get()),rust_authority::encode_cfg(&cfg)]).unwrap();
    SelectedTypedRow::new(
        BindingFragmentId::at_ordinal(host),
        LoweredRustReferenceContext::new(
            semantic,
            ResolutionSiteId::new(1000 + n),
            SourceOccurrenceId::new(2000 + n),
            SourceOccurrenceId::new(3000 + n),
            declaration,
        )
        .with_cfg_condition(cfg),
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_wave2_root_test_support {
    use super::*;

    use crate::analyzer::store::resolution_typed::SelectedResolutionTypedSource;

    #[doc(hidden)]
    pub type Context = SelectedTypedRow<LoweredRustReferenceContext>;
    #[doc(hidden)]
    pub fn collect(
        selection: &SelectedResolutionMountInventory<'_>,
        keys: &[SemanticId],
    ) -> Vec<Context> {
        let mut answer = Vec::new();
        let mut receive = |page: &[Context]| {
            answer.extend_from_slice(page);
            Ok(true)
        };
        let outcome = SelectedResolutionTypedSource::new_on_demand(selection)
            .visit_rust_reference_context_pages(
                TypedFactRequest::new(keys),
                &CancellationToken::new(),
                &mut TypedFactPageVisitor::new(&mut receive),
            )
            .unwrap();
        assert!(outcome.is_exhausted());
        answer
    }
}
