//! Boundary proof: admitted embedded trees keep their own context through the
//! shared scheduler, even with older primary-tree sibling work still pending.
use super::*;
use brokk_bifrost_core::retention_budget::RetentionBudget;
use brokk_bifrost_semantic::analyzer::semantic::lowering::{
    ContextualWork, WorkSink, drive_contextual_procedure_work,
};
use brokk_bifrost_test_macros::hardwon;

struct Visitor<'tree> {
    primary: &'tree tree_sitter::Tree,
    fragment: &'tree tree_sitter::Tree,
    active: &'tree tree_sitter::Tree,
    initial: Node<'tree>,
    fragment_root: Node<'tree>,
    fragment_child: Node<'tree>,
    sibling: Node<'tree>,
    seen: Vec<Node<'tree>>,
    cancellation: CancellationToken,
    cancel_after: Option<usize>,
}

impl<'tree> Visitor<'tree> {
    fn visit(
        &mut self,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        queue: &mut WorkStack<'_, 'tree>,
    ) {
        assert!(std::ptr::eq(self.active, queue.context()));
        let expected = if node == self.initial || node == self.sibling {
            self.primary
        } else {
            self.fragment
        };
        assert!(std::ptr::eq(self.active, expected));
        self.seen.push(node);
        if node == self.initial {
            queue.push(Work::Expression {
                node: self.sibling,
                entry,
                next: EdgeTarget::normal(entry),
                scope,
            });
            queue.push_with_context(
                Work::Expression {
                    node: self.fragment_root,
                    entry,
                    next: EdgeTarget::normal(entry),
                    scope,
                },
                self.fragment,
            );
        } else if node == self.fragment_root {
            queue.push(Work::Expression {
                node: self.fragment_child,
                entry,
                next: EdgeTarget::normal(entry),
                scope,
            });
        }
        if self.cancel_after == Some(self.seen.len()) {
            self.cancellation.cancel();
        }
    }
}

impl<'tree> ProcedureWorkHandler<'tree, &'tree tree_sitter::Tree> for Visitor<'tree> {
    fn enter_work_context(&mut self, context: &'tree tree_sitter::Tree) {
        self.active = context;
    }
    fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }
    fn lower_statement(
        &mut self,
        _builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _next: EdgeTarget,
        scope: ScopeFrameId,
        queue: &mut WorkStack<'_, 'tree>,
    ) -> Result<(), RustLoweringError> {
        self.visit(node, entry, scope, queue);
        Ok(())
    }
    fn lower_expression(
        &mut self,
        _builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _next: EdgeTarget,
        scope: ScopeFrameId,
        queue: &mut WorkStack<'_, 'tree>,
    ) -> Result<(), RustLoweringError> {
        self.visit(node, entry, scope, queue);
        Ok(())
    }
    fn lower_condition(
        &mut self,
        _builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _targets: brokk_bifrost_semantic::analyzer::semantic::lowering::ConditionTargets,
        scope: ScopeFrameId,
        queue: &mut WorkStack<'_, 'tree>,
    ) -> Result<(), RustLoweringError> {
        self.visit(node, entry, scope, queue);
        Ok(())
    }
}

#[test]
fn admitted_fragment_context_survives_primary_siblings_and_cancellation() {
    let prepared = super::semantic_lowering_tests::prepare_fixture(
        "fn subject() { vec![{ inner!(); }, || 42]; sibling(); }",
    );
    let primary = prepared.tree();
    let body = primary
        .root_node()
        .named_child(0)
        .unwrap()
        .child_by_field_name("body")
        .unwrap();
    let initial = body.named_child(0).unwrap();
    let sibling = body.named_child(1).unwrap();
    let forest = brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxForest::parse(
        &RUST_STRUCTURAL_SPEC,
        primary.root_node(),
        prepared.source(),
        1000,
        None,
    )
    .unwrap();
    let fragment = forest
        .trees()
        .first()
        .expect("vec operand is admitted syntax");
    assert!(
        forest
            .trees_at_anchor(fragment.anchor)
            .unwrap()
            .any(|tree| std::ptr::eq(tree, fragment))
    );
    let fragment_root = fragment.root();
    let fragment_child = fragment_root.named_child(0).unwrap();
    let file = ProjectFile::new(std::env::temp_dir(), "ownership.rs");
    let seed_owner = RetentionBudget::new(64 * 1024 * 1024);
    let observed = with_rust_file_inputs(
        &file,
        &prepared,
        &SemanticBudget::default(),
        &CancellationToken::default(),
        &seed_owner,
        |_, inputs, specs, work, _, _| {
            assert!(
                specs.iter().any(|spec| !std::ptr::eq(spec.owner, primary)),
                "an embedded closure retains its own physical owner in the inventory"
            );
            let baseline: HashMap<_, _> = forest
                .trees()
                .iter()
                .map(|tree| {
                    let node = tree.root();
                    ((node.start_byte(), node.end_byte()), node)
                })
                .collect();
            assert_eq!(
                baseline.capacity(),
                inputs.operand_nodes.capacity(),
                "preserve the former collect capacity policy"
            );
            Ok(SemanticOutcome::Complete { value: (), work })
        },
    )
    .unwrap();
    assert!(matches!(observed, SemanticOutcome::Complete { .. }));
    assert_eq!(seed_owner.accounted_bytes(), 0);
    let seed = RustSemanticLowerer
        .lower(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &CancellationToken::default(),
            &seed_owner,
        )
        .unwrap()
        .available_value()
        .unwrap()[0]
        .clone();
    assert_eq!(
        seed_owner.accounted_bytes(),
        0,
        "file/spec/operand provenance is released after lowering"
    );
    for cancel_after in [None, Some(2)] {
        let cancellation = CancellationToken::default();
        let budget = SemanticBudget::default();
        let parts = ProcedureSemanticsParts::new(
            seed.id,
            seed.locator.clone(),
            seed.kind,
            SourceMappingId::new(0),
            EvidenceId::new(0),
        );
        let ProcedureLoweringStart {
            mut builder,
            entry,
            function_scope,
            ..
        } = ProcedureLoweringSession::start(parts, &budget, &cancellation).unwrap();
        let owner = RetentionBudget::new(64 * 1024 * 1024);
        let mut visitor = Visitor {
            primary,
            fragment: &fragment.tree,
            active: primary,
            initial,
            fragment_root,
            fragment_child,
            sibling,
            seen: Vec::new(),
            cancellation: cancellation.clone(),
            cancel_after,
        };
        let result = drive_contextual_procedure_work(
            &mut builder,
            ContextualWork {
                item: Work::Expression {
                    node: initial,
                    entry,
                    next: EdgeTarget::normal(entry),
                    scope: function_scope,
                },
                context: primary,
            },
            &owner,
            &cancellation,
            |builder, work, queue| {
                assert!(
                    owner.accounted_bytes() > u64::try_from(brokk_bifrost_semantic::analyzer::semantic::lowering::contextual_vec_bytes::<Work<'_>, &tree_sitter::Tree>(queue.capacity())).unwrap(),
                    "context slots and charge control are accounted before visiting"
                );
                dispatch_procedure_work(&mut visitor, builder, work, queue)
            },
        );
        if cancel_after.is_some() {
            assert!(matches!(result, Err(RustLoweringError::Cancelled(_))));
            assert_eq!(visitor.seen, [initial, fragment_root]);
        } else {
            result.unwrap();
            assert_eq!(
                visitor.seen,
                [initial, fragment_root, fragment_child, sibling]
            );
        }
        assert_eq!(
            owner.accounted_bytes(),
            0,
            "pending context allocation is released on every exit"
        );
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drive_contextual_procedure_work(
                &mut builder,
                ContextualWork {
                    item: initial,
                    context: primary,
                },
                &owner,
                &CancellationToken::default(),
                |_, _, queue| {
                    queue.push_with_context(fragment_root, &fragment.tree);
                    panic!("test visitor unwinds with foreign work pending");
                },
            )
            .unwrap();
        }));
        assert!(unwound.is_err());
        assert_eq!(
            owner.accounted_bytes(),
            0,
            "unwinding destroys work before its charge"
        );
    }
    assert_eq!(
        std::mem::size_of::<ContextualWork<Work<'_>, ()>>(),
        std::mem::size_of::<Work<'_>>()
    );
    type Frame<'tree> =
        brokk_bifrost_semantic::analyzer::semantic::inventory::ProcedureEnumerationFrame<'tree>;
    assert_eq!(
        std::mem::size_of::<ContextualWork<Frame<'_>, ()>>(),
        std::mem::size_of::<Frame<'_>>()
    );
}

#[test]
#[hardwon("#13958: stored initializer and break-value proofs lost their physical Tree owner")]
fn fragment_drop_proofs_retain_stored_expression_owners() {
    for source in [
        "fn subject() { return matches!(1, 1); vec![42]; }",
        "fn subject() { vec![{ return matches!(1, 1); }]; }",
        "fn subject() { let value = &matches!(1,1); vec![{ let _ = *value; }]; }",
        "fn subject() { vec![{ let value = matches!(1,1); value }]; }",
        "fn subject() { vec![{ let values = [matches!(1,1)]; values }]; }",
        "fn subject() { let values = &[matches!(1,1)]; vec![{ let _ = (*values)[0]; }]; }",
        "fn subject() { let values = loop { vec![{ break if true { [matches!(1, 1)] } else { [false] }; }]; }; }",
        "fn subject() { let values = 'out: { vec![{ break 'out if true { [matches!(1, 1)] } else { [false] }; }]; [false] }; }",
        "fn subject() { let values = loop { { vec![{ break if true { [matches!(1, 1), matches!(2, 2)] } else { [false, false] }; }]; } }; }",
    ] {
        let prepared = super::semantic_lowering_tests::prepare_fixture(source);
        let file = ProjectFile::new(std::env::temp_dir(), "proof-owner.rs");
        let owner = RetentionBudget::new(64 * 1024 * 1024);
        let result = RustSemanticLowerer.lower(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &CancellationToken::default(),
            &owner,
        );
        assert!(result.is_ok(), "{source}: {result:?}");
        let outcome = result.unwrap();
        assert!(
            outcome
                .available_value()
                .is_some_and(|procedures| !procedures.is_empty()),
            "{source}: {outcome:?}"
        );
        assert_eq!(owner.accounted_bytes(), 0);
    }
}
