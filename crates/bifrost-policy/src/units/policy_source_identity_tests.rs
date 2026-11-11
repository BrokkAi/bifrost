use super::*;

#[test]
fn authored_policy_source_changes_verification_input_without_changing_semantics() {
    const SOURCE: &str = r#"(policy :id "test.source-identity" :name "Source"
        :message "Source" :severity warning
        :analysis (analysis :type match :selector (rql (language python (class)))))"#;
    let first = crate::test_support::registry_with_policy(
        "test:source-identity-first",
        SOURCE,
        "valid source identity policy",
    );
    let second = crate::test_support::registry_with_policy(
        "test:source-identity-second",
        &format!("; authored comment\n{SOURCE}"),
        "valid source identity policy with comment",
    );
    let first = first.policies().next().expect("first policy");
    let second = second.policies().next().expect("second policy");
    assert_eq!(first.semantic_hash(), second.semantic_hash());
    assert_ne!(first.source_hash(), second.source_hash());

    let inputs = WorkspaceUnitInputs {
        model_read_digest: brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
            None,
        ),
        configuration: StableDigest::sha256("configuration"),
        models: StableDigest::sha256(NO_ACTIVE_MODELS),
        epoch: policy_substrate_epoch(StableDigest::sha256("test-lowering")),
    };
    assert_eq!(
        inputs.unit_key(first, UnitPartition::Whole),
        inputs.unit_key(second, UnitPartition::Whole),
    );
    assert_ne!(
        inputs.head_inputs(first).policy_source,
        inputs.head_inputs(second).policy_source,
        "verification must see a source edit even when the compiled policy is unchanged",
    );
}

#[test]
fn unit_lookup_separates_configuration_model_and_engine_inputs() {
    let registry = crate::test_support::registry_with_policy(
        "test:lookup-inputs",
        r#"(policy :id "test.lookup-inputs" :name "Inputs" :message "Inputs"
            :severity warning :analysis (analysis :type match
              :selector (rql (language python (class)))))"#,
        "valid lookup inputs policy",
    );
    let policy = registry.policies().next().expect("policy");
    let original = WorkspaceUnitInputs {
        model_read_digest: brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
            None,
        ),
        configuration: StableDigest::sha256("configuration a"),
        models: StableDigest::sha256("models a"),
        epoch: policy_substrate_epoch(StableDigest::sha256("test-lowering")),
    };
    let changed_configuration = WorkspaceUnitInputs {
        model_read_digest: brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
            None,
        ),
        configuration: StableDigest::sha256("configuration b"),
        ..original
    };
    let changed_models = WorkspaceUnitInputs {
        model_read_digest: brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
            None,
        ),
        models: StableDigest::sha256("models b"),
        ..original
    };
    let changed_epoch = WorkspaceUnitInputs {
        model_read_digest: brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
            None,
        ),
        epoch: StableDigest::sha256("next engine epoch"),
        ..original
    };
    let original_key = row_key(&original.unit_key(policy, UnitPartition::Whole));
    for changed in [changed_configuration, changed_models, changed_epoch] {
        assert_ne!(
            original_key,
            row_key(&changed.unit_key(policy, UnitPartition::Whole)),
            "a changed execution input must miss persisted units",
        );
    }
}

#[test]
fn distinct_binding_partitions_have_distinct_persisted_keys() {
    let registry = crate::test_support::registry_with_policy(
        "test:binding-partitions",
        r#"(policy :id "test.binding-partitions" :name "Bindings" :message "Bindings"
            :severity warning :analysis (analysis :type match
              :selector (rql (language python (class)))))"#,
        "valid binding partitions policy",
    );
    let policy = registry.policies().next().expect("policy");
    let inputs = WorkspaceUnitInputs {
        model_read_digest: brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
            None,
        ),
        configuration: StableDigest::sha256("configuration"),
        models: StableDigest::sha256(NO_ACTIVE_MODELS),
        epoch: policy_substrate_epoch(StableDigest::sha256("test-lowering")),
    };
    let blob = Oid::from_str("0000000000000000000000000000000000000000").expect("blob id");
    let partition = |binding: &str| UnitPartition::Binding {
        binding: binding.into(),
        language: Language::Python,
        rel_path: "src/module.py".into(),
        blob,
    };
    let first = row_key(&inputs.unit_key(policy, partition("source")));
    let second = row_key(&inputs.unit_key(policy, partition("target")));
    assert_ne!(
        first, second,
        "one binding cannot load another binding's rows"
    );
}

#[test]
fn a_head_only_widening_reason_does_not_describe_the_base() {
    let id = PolicyId::new("test.head-only-widening").expect("policy id");
    let head =
        PolicyIncrementalReview::evaluated_in_full([id.clone()], WidenReason::UnitNotExhaustive);
    let base = PolicyIncrementalReview {
        base: IncrementalBaseState::Evaluated,
        policies: vec![PolicyIncrementalRun {
            mode: IncrementalMode::Sliced,
            widen_reason: None,
            ..PolicyIncrementalRun::evaluated_in_full(id, WidenReason::WholePolicyFamily)
        }],
    };
    let combined = head.with_base_runs(&base);
    let run = combined.policies().first().expect("policy run");
    assert_eq!(run.widen_reason, Some(WidenReason::UnitNotExhaustive));
    assert_eq!(run.base_widen_reason, None);
}
