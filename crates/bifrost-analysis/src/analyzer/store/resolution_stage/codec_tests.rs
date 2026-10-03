use super::*;

fn runtime_path(
    variables: [Option<StackVariableId>; 3],
    completion: ResolutionCompletion,
) -> PartialPath {
    let foreign = BindingNodeId::local((1 << 22) + 3, 11);
    let context = BindingNodeId::context_local((1 << 53) + 13);
    let shared = SemanticId::shared_name(SharedNameId::per_request(19));
    let local = SemanticId::local((1 << 22) + 7, 17);
    let operation = SemanticId::operation_local((1 << 53) + 23);
    let start = EndpointSignature::new_scoped(
        BindingNodeId::context_local(29),
        StackPattern::new(
            vec![
                PartialScopedSymbol::scoped(
                    shared,
                    StackPattern::new(vec![foreign, context], variables[0]),
                ),
                PartialScopedSymbol::unscoped(local),
                PartialScopedSymbol::scoped(operation, StackPattern::closed(Vec::new())),
            ],
            variables[1],
        ),
        StackPattern::new(vec![BindingNodeId::universal_root(), foreign], variables[0]),
    );
    let end = EndpointSignature::new_scoped(
        BindingNodeId::local(31, 37),
        StackPattern::new(
            vec![
                PartialScopedSymbol::scoped(
                    SemanticId::context_local(41),
                    StackPattern::new(vec![context, foreign], variables[2]),
                ),
                PartialScopedSymbol::scoped(shared, StackPattern::new(vec![foreign], variables[0])),
            ],
            variables[1],
        ),
        StackPattern::new(vec![context], variables[2]),
    );
    let precedence = ALL_PRECEDENCE_TIERS
        .iter()
        .enumerate()
        .map(|(index, &tier)| PrecedenceStep {
            tier,
            ordinal: u32::MAX - u32::try_from(index).unwrap(),
            semantic: [shared, local, operation][index % 3],
        })
        .collect::<Vec<_>>();
    let mut witness = vec![
        WitnessStep::Node(foreign),
        WitnessStep::Node(context),
        WitnessStep::Candidate {
            semantic: shared,
            outcome: CandidateOutcome::Selected,
        },
    ];
    witness.extend(
        ALL_REJECTION_REASONS
            .iter()
            .map(|&reason| WitnessStep::Candidate {
                semantic: operation,
                outcome: CandidateOutcome::Rejected(reason),
            }),
    );
    witness.extend(
        ALL_BOUNDARY_STATUSES
            .iter()
            .map(|&status| WitnessStep::Boundary {
                semantic: local,
                status,
            }),
    );
    PartialPath::new(start, end, precedence, witness, completion)
}

fn all_reasons() -> Vec<ResolutionIncompleteReason> {
    let mut reasons = vec![
        ResolutionIncompleteReason::CyclicExpansion(PartialPathId::local((1 << 22) + 43, 47)),
        ResolutionIncompleteReason::CyclicExpansion(PartialPathId::operation_local((1 << 53) + 53)),
        ResolutionIncompleteReason::CyclicExpansion(PartialPathId::context_local(59)),
        ResolutionIncompleteReason::UnmountedFile {
            fragment: BindingFragmentId::at_ordinal(61),
        },
    ];
    for semantic in [
        SemanticId::local((1 << 22) + 67, 71),
        SemanticId::operation_local((1 << 53) + 73),
        SemanticId::context_local((1 << 53) + 79),
        SemanticId::shared_name(SharedNameId::interned(83)),
        SemanticId::shared_name(SharedNameId::per_request(89)),
    ] {
        reasons.extend([
            ResolutionIncompleteReason::InconsistentPrecedence(semantic),
            ResolutionIncompleteReason::UnsupportedSemantic(semantic),
            ResolutionIncompleteReason::CyclicPrefixDependency(semantic),
            ResolutionIncompleteReason::ReceiverBudgetExhausted(semantic),
        ]);
        reasons.extend(
            ALL_BOUNDARY_STATUSES
                .iter()
                .map(|&status| ResolutionIncompleteReason::OpenBoundary { semantic, status }),
        );
    }
    reasons
}

fn round_trip(path: &PartialPath) -> PartialPath {
    decode_path(
        encode_node(path.start().node()),
        encode_node(path.end().node()),
        &encode_path(path),
    )
}

#[test]
fn scalar_cells_preserve_runtime_domains_and_integer_precision() {
    for ordinal in [
        0,
        7,
        (1 << 22) + 1,
        BindingFragmentId::unmounted().ordinal() - 1,
    ] {
        for key in [0, 1, 101, u32::MAX] {
            let semantic = SemanticId::local(ordinal, key);
            let node = BindingNodeId::local(ordinal, key);
            let path = PartialPathId::local(ordinal, key);
            assert_eq!(decode_semantic(encode_semantic(semantic)), semantic);
            assert_eq!(decode_node(encode_node(node)), node);
            assert_eq!(decode_path_id(encode_path_id(path)), path);
        }
    }
    for number in [0, 1, (1 << 53) + 1, CONTEXT_BASE - 1] {
        for semantic in [
            SemanticId::operation_local(number),
            SemanticId::context_local(number),
        ] {
            assert_eq!(decode_semantic(encode_semantic(semantic)), semantic);
        }
        for node in [
            BindingNodeId::operation_local(number),
            BindingNodeId::context_local(number),
        ] {
            assert_eq!(decode_node(encode_node(node)), node);
        }
        for path in [
            PartialPathId::operation_local(number),
            PartialPathId::context_local(number),
        ] {
            assert_eq!(decode_path_id(encode_path_id(path)), path);
        }
    }
    for shared in [
        SharedNameId::interned(1),
        SharedNameId::interned(i64::from(SharedNameId::PER_REQUEST_BASE - 1)),
        SharedNameId::per_request(0),
        SharedNameId::per_request(SharedNameId::PER_REQUEST_BASE - 1),
    ] {
        let semantic = SemanticId::shared_name(shared);
        assert_eq!(encode_semantic(semantic), -i64::from(shared.get()));
        assert_eq!(decode_semantic(encode_semantic(semantic)), semantic);
    }
    assert_eq!(
        decode_node(encode_node(BindingNodeId::universal_root())),
        BindingNodeId::universal_root()
    );
}

#[test]
fn nested_paths_round_trip_against_original_structured_values() {
    let empty_endpoint = EndpointSignature::new_scoped(
        BindingNodeId::universal_root(),
        StackPattern::closed(Vec::new()),
        StackPattern::closed(Vec::new()),
    );
    let empty = PartialPath::new(
        empty_endpoint.clone(),
        empty_endpoint,
        Vec::new(),
        Vec::new(),
        ResolutionCompletion::Complete,
    );
    assert_eq!(round_trip(&empty), empty);
    let completions = [
        ResolutionCompletion::Complete,
        ResolutionCompletion::incomplete(all_reasons()),
    ];
    for completion in completions {
        let closed = runtime_path([None; 3], completion.clone());
        assert_eq!(round_trip(&closed), closed);
        let canonical = runtime_path(
            [
                Some(StackVariableId::operation_local(0)),
                Some(StackVariableId::operation_local(1)),
                Some(StackVariableId::operation_local(2)),
            ],
            completion,
        );
        assert_eq!(round_trip(&canonical), canonical);
        assert_eq!(
            decode_endpoint(
                encode_node(canonical.start().node()),
                &encode_endpoint(canonical.start())
            ),
            *canonical.start()
        );
    }
}

#[test]
fn alpha_variables_keep_nested_aliases_across_both_endpoints() {
    let variables = [
        StackVariableId::local(97, 101),
        StackVariableId::operation_local((1 << 53) + 103),
        StackVariableId::context_local(107),
    ];
    for a in 0..3 {
        for b in 0..3 {
            for c in 0..3 {
                let original = runtime_path(
                    [Some(variables[a]), Some(variables[b]), Some(variables[c])],
                    ResolutionCompletion::Complete,
                );
                let decoded = round_trip(&original);
                // The model's alpha normalizer is independent of stage encoding.
                assert_eq!(
                    original.stack_effect_alpha_key_with_poll(&mut || false),
                    decoded.stack_effect_alpha_key_with_poll(&mut || false)
                );
                assert_eq!(original.precedence(), decoded.precedence());
                assert_eq!(original.witness(), decoded.witness());
                assert_eq!(original.completion(), decoded.completion());
            }
        }
    }
    let aliased = runtime_path([Some(variables[0]); 3], ResolutionCompletion::Complete);
    let split = runtime_path(
        [Some(variables[0]), Some(variables[1]), Some(variables[2])],
        ResolutionCompletion::Complete,
    );
    assert_ne!(
        round_trip(&aliased).stack_effect_alpha_key_with_poll(&mut || false),
        round_trip(&split).stack_effect_alpha_key_with_poll(&mut || false)
    );
}

#[test]
fn completion_variants_and_raw_reason_shapes_round_trip_exactly() {
    let mut reasons = all_reasons();
    reasons.reverse();
    reasons.push(reasons[0]);
    let raw = ResolutionCompletion::Incomplete(reasons.into());
    let empty_raw = ResolutionCompletion::Incomplete(Vec::new().into());
    for completion in [
        ResolutionCompletion::Complete,
        ResolutionCompletion::incomplete(all_reasons()),
        raw,
        empty_raw,
    ] {
        let encoded = encode_completion(&completion);
        assert_eq!(decode_completion(encoded.as_deref()), completion);
        let original = runtime_path([None; 3], completion);
        assert_eq!(round_trip(&original), original);
    }
}

#[test]
fn root_requests_retain_foreign_context_shared_and_proper_prefix_cells() {
    let cancellation = CancellationToken::new();
    let semantics = [
        SemanticId::local(7, 1),
        SemanticId::local((1 << 22) + 109, 113),
        SemanticId::operation_local((1 << 53) + 127),
        SemanticId::context_local((1 << 53) + 131),
        SemanticId::shared_name(SharedNameId::per_request(137)),
    ];
    for length in 0..=semantics.len() {
        for tail in [None, Some(StackVariableId::operation_local(0))] {
            let symbols = semantics[..length]
                .iter()
                .enumerate()
                .map(|(index, &semantic)| {
                    if index % 2 == 0 {
                        PartialScopedSymbol::unscoped(semantic)
                    } else {
                        PartialScopedSymbol::scoped(
                            semantic,
                            StackPattern::closed(vec![BindingNodeId::local(139, 149)]),
                        )
                    }
                })
                .collect::<Vec<_>>();
            let request = BatchCandidateRequest::new(
                151,
                EndpointSignature::new_scoped(
                    BindingNodeId::universal_root(),
                    StackPattern::new(symbols, tail),
                    StackPattern::closed(Vec::new()),
                ),
            );
            let encoded = root_candidate_request(157, &request, &cancellation).unwrap();
            let request_cells: Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(request_cells[0], json!(157));
            assert_eq!(request_cells[2], json!(i64::from(tail.is_some())));
            assert_eq!(request_cells[3], json!(1));
            let expected = semantics[..length]
                .iter()
                .enumerate()
                .map(|(index, semantic)| match semantic.shared_name_id() {
                    Some(shared) => json!([null, shared.get(), index % 2]),
                    None => json!([semantic.get(), null, index % 2]),
                })
                .collect::<Vec<_>>();
            let key = request_cells[1].as_str().unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(key).unwrap(),
                Value::Array(expected.clone())
            );
            let boundaries = request_cells[4].as_array().unwrap();
            assert_eq!(boundaries.len(), length);
            for (prefix_length, boundary) in boundaries.iter().enumerate() {
                let offset = usize::try_from(boundary.as_u64().unwrap()).unwrap();
                let prefix = format!("{}]", &key[..offset]);
                assert_eq!(
                    serde_json::from_str::<Value>(&prefix).unwrap(),
                    json!(expected[..prefix_length])
                );
            }
        }
    }
    cancellation.cancel();
    let request = BatchCandidateRequest::new(
        0,
        runtime_path([None; 3], ResolutionCompletion::Complete)
            .start()
            .clone(),
    );
    assert!(root_candidate_request(0, &request, &cancellation).is_none());
}

#[test]
fn invalid_runtime_cells_fail_at_the_stage_boundary() {
    let shared =
        i64::try_from(SemanticId::shared_name(SharedNameId::per_request(0)).get()).unwrap();
    let reserved = i64::try_from(BindingNodeId::universal_root().get()).unwrap();
    let unmounted =
        i64::try_from(SemanticId::local(BindingFragmentId::unmounted().ordinal(), 0).get())
            .unwrap();
    for cell in [
        shared,
        reserved,
        reserved + 1,
        unmounted,
        i64::MAX,
        i64::MIN,
    ] {
        assert!(
            std::panic::catch_unwind(|| decode_semantic(cell)).is_err(),
            "invalid semantic {cell}"
        );
    }
    for cell in [-1, shared, reserved + 1, unmounted, i64::MAX, i64::MIN] {
        assert!(
            std::panic::catch_unwind(|| decode_node(cell)).is_err(),
            "invalid node {cell}"
        );
    }
    for cell in [
        -1,
        shared,
        reserved,
        reserved + 1,
        unmounted,
        i64::MAX,
        i64::MIN,
    ] {
        assert!(
            std::panic::catch_unwind(|| decode_path_id(cell)).is_err(),
            "invalid path {cell}"
        );
    }
    assert!(
        std::panic::catch_unwind(|| encode_semantic(SemanticId::shared_name(
            SharedNameId::interned(0)
        )))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| encode_node(BindingNodeId::local(
            BindingFragmentId::unmounted().ordinal(),
            0
        )))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| encode_path_id(PartialPathId::local(
            BindingFragmentId::unmounted().ordinal(),
            0
        )))
        .is_err()
    );
}

#[test]
fn malformed_nested_cells_and_cancelled_completion_are_rejected() {
    let original = runtime_path([None; 3], ResolutionCompletion::Complete);
    let body: Value = serde_json::from_str(&encode_path(&original)).unwrap();
    let mut invalid_scope = body.clone();
    invalid_scope[0][0][1][0] = json!(-1);
    let mut fractional_semantic = body.clone();
    fractional_semantic[0][0][0] = json!(1.5);
    let mut negative_variable = body;
    negative_variable[0][0][2] = json!(-1);
    for invalid in [invalid_scope, fractional_semantic, negative_variable] {
        assert!(
            std::panic::catch_unwind(|| decode_path(
                encode_node(original.start().node()),
                encode_node(original.end().node()),
                &invalid.to_string()
            ))
            .is_err()
        );
    }
    for invalid in [
        "null",
        "[[]]",
        "[[7,0]]",
        "[[0,-1]]",
        "[[1,0,0]]",
        "[[2,0]]",
        "[[6,-1]]",
    ] {
        assert!(
            std::panic::catch_unwind(|| decode_completion(Some(invalid))).is_err(),
            "invalid completion {invalid}"
        );
    }
    let cancelled = ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]);
    assert!(std::panic::catch_unwind(|| encode_completion(&cancelled)).is_err());
}
