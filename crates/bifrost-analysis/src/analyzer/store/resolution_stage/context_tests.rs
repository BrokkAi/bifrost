use super::*;
use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, EndpointSignature, PartialPathId, PartialScopedSymbol,
    ResolutionCompletion, ResolutionIncompleteReason, SemanticId, SharedNameId, StackPattern,
    StackVariableId, WitnessStep,
};
use crate::analyzer::store::resolution_selection::tests::SelectionFixture;

fn path(reason: u64) -> PartialPath {
    let shared = SemanticId::shared_name(SharedNameId::per_request(19));
    let variable = StackVariableId::operation_local(0);
    let context = BindingNodeId::context_local((1 << 53) + 9);
    let foreign = BindingNodeId::local(1, 7);
    PartialPath::new(
        EndpointSignature::new_scoped(
            context,
            StackPattern::open(
                vec![PartialScopedSymbol::scoped(
                    shared,
                    StackPattern::open(vec![foreign, context], variable),
                )],
                variable,
            ),
            StackPattern::open(vec![foreign], variable),
        ),
        EndpointSignature::new_scoped(
            BindingNodeId::universal_root(),
            StackPattern::open(
                vec![PartialScopedSymbol::unscoped(SemanticId::context_local(
                    (1 << 53) + 11,
                ))],
                variable,
            ),
            StackPattern::closed(vec![context]),
        ),
        Vec::new(),
        vec![WitnessStep::Node(foreign)],
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
            SemanticId::context_local(reason),
        )]),
    )
}

fn read(
    connection: &Connection,
    context: SelectedContextPathToken,
    identity: CandidatePathIdentity,
) -> PartialPath {
    require_context(connection, context).unwrap();
    connection.query_row(
        "SELECT start_node,end_node,json(body) FROM temp.selected_resolution_context_paths WHERE context_id=?1 AND host_ordinal=?2 AND path=?3",
        params![context.get(),identity.fragment().ordinal(),codec::encode_path_id(identity.path())],
        |row| Ok(codec::decode_path(row.get(0)?,row.get(1)?,&row.get::<_,String>(2)?)),
    ).unwrap()
}

#[test]
fn context_paths_are_atomic_isolated_and_live_only_for_the_request() {
    let mut fixture = SelectionFixture::new(2);
    fixture.retain_one_reader();
    let selection = fixture.open_ready(&[]);
    let other_fixture = SelectionFixture::new(1);
    let other_selection = other_fixture.open_ready(&[]);
    let identity = CandidatePathIdentity::new(
        BindingFragmentId::at_ordinal(0),
        PartialPathId::context_local((1 << 53) + 15),
    );
    let first_path = path(23);
    let second_path = path(29);
    let live = CancellationToken::new();
    let base_authority = selection.candidate_coverage_fingerprint();
    let first;
    {
        let stage = SelectedResolutionStage::new(&selection);
        first = stage
            .publish_context_paths(&live, |writer| {
                assert!(writer.insert(identity, &first_path)?);
                writer.insert(identity, &first_path)
            })
            .unwrap()
            .unwrap();
        let second = stage
            .publish_context_paths(&live, |writer| writer.insert(identity, &second_path))
            .unwrap()
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(read(selection.connection(), first, identity), first_path);
        assert_eq!(read(selection.connection(), second, identity), second_path);
        let count = || {
            selection
                .connection()
                .query_row(
                    "SELECT count(*) FROM temp.selected_resolution_contexts",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
        };
        assert_eq!(count(), 2);
        assert!(
            stage
                .publish_context_paths(&live, |writer| {
                    assert!(writer.insert(identity, &first_path)?);
                    writer.insert(identity, &second_path)
                })
                .is_err()
        );
        assert_eq!(count(), 2);
        let missing_host =
            CandidatePathIdentity::new(BindingFragmentId::at_ordinal(99), identity.path());
        assert!(
            stage
                .publish_context_paths(&live, |writer| writer.insert(missing_host, &first_path))
                .is_err()
        );
        assert_eq!(count(), 2);
        let cancelled = CancellationToken::new();
        assert!(
            stage
                .publish_context_paths(&cancelled, |writer| {
                    assert!(writer.insert(identity, &first_path)?);
                    cancelled.cancel();
                    Ok(true)
                })
                .unwrap()
                .is_none()
        );
        assert_eq!(count(), 2);
        assert!(selection.connection().is_autocommit());
        stage.clear_facts().unwrap();
        assert_eq!(read(selection.connection(), first, identity), first_path);
        assert_eq!(selection.candidate_coverage_fingerprint(), base_authority);
        assert!(require_context(other_selection.connection(), first).is_err());
        let header: (Option<i64>,Option<i64>,Option<i64>,Option<i64>) = selection.connection().query_row(
            "SELECT start_lead_key,start_lead_shared,end_lead_key,end_lead_shared FROM temp.selected_resolution_context_paths WHERE context_id=?1",[first.get()],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap();
        assert_eq!(
            (header.0, header.1),
            lexical::semantic_cells(first_path.start().symbols().fixed()[0].symbol())
        );
        assert_eq!(
            (header.2, header.3),
            lexical::semantic_cells(first_path.end().symbols().fixed()[0].symbol())
        );
    }
    selection.with_owned_temp_write(|connection| {
        connection.execute_batch("CREATE TEMP TABLE context_request_reuse_marker(value INTEGER); INSERT INTO context_request_reuse_marker VALUES(71)")?;
        Ok(())
    }).unwrap();
    drop(selection);
    let reused = fixture.open_ready(&[]);
    assert_eq!(
        reused
            .connection()
            .query_row(
                "SELECT value FROM temp.context_request_reuse_marker",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        71,
        "the retained physical reader was reused"
    );
    assert!(require_context(reused.connection(), first).is_err());
    assert_eq!(
        reused
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_context_paths",
                [],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
        0
    );
    let stage = SelectedResolutionStage::new(&reused);
    let fresh = stage
        .publish_context_paths(&live, |writer| writer.insert(identity, &first_path))
        .unwrap()
        .unwrap();
    assert_ne!(fresh, first);
}
