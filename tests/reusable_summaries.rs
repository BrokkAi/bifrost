use brokk_bifrost::Language;
use brokk_bifrost::analyzer::LanguageDialect;
use brokk_bifrost::analyzer::dataflow::*;
use brokk_bifrost::analyzer::semantic::*;

fn anchor(byte: u32) -> SourceAnchor {
    let position = SourcePosition::new(byte, 0, byte);
    SourceAnchor::new(
        SourceSpan::new(position, position).expect("fixture span is ordered"),
        0,
    )
}

fn declaration(name: &str) -> DeclarationLocator {
    DeclarationLocator::new(vec![
        DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor(0), 0)
            .expect("fixture declaration name is valid"),
    ])
    .expect("fixture declaration locator is non-empty")
}

fn artifact(name: &str, source: &[u8]) -> SemanticArtifactKey {
    artifact_with(
        name,
        source,
        b"adapter-v1",
        b"semantic-ir-v1",
        b"configuration-v1",
        b"artifact-dependencies-v1",
    )
}

fn artifact_with(
    name: &str,
    source: &[u8],
    adapter: &[u8],
    ir: &[u8],
    configuration: &[u8],
    dependencies: &[u8],
) -> SemanticArtifactKey {
    SemanticArtifactKey::new(
        WorkspaceMountId::hash_bytes(b"reusable-summary-test-mount"),
        WorkspaceRelativePath::new(format!("src/{name}.java")).expect("fixture path is portable"),
        LanguageDialect::Standard(Language::Java),
        SourceRevision::Disk {
            content: ContentIdentity::hash_bytes(source),
        },
        AdapterSemanticsVersion::hash_bytes("reusable-summary-test-java", adapter)
            .expect("adapter name is non-empty"),
        SemanticIrVersion::hash_bytes(ir),
        ConfigurationFingerprint::hash_bytes(configuration),
        DependencyFingerprint::hash_bytes(dependencies),
    )
}

fn identity(name: &str) -> ProcedureSummaryIdentity {
    identity_with(
        artifact(name, name.as_bytes()),
        name,
        SummarySemanticsVersion::hash_bytes(b"summary-semantics-v1"),
        SummaryContextKey::hash_bytes(b"context-insensitive"),
        SummaryBehaviorKey::hash_bytes(b"conservative-unknown-calls"),
        SummaryOrigin::Inferred,
    )
}

fn identity_with(
    artifact: SemanticArtifactKey,
    name: &str,
    semantics: SummarySemanticsVersion,
    context: SummaryContextKey,
    behavior: SummaryBehaviorKey,
    origin: SummaryOrigin,
) -> ProcedureSummaryIdentity {
    ProcedureSummaryIdentity::new(
        artifact,
        declaration(name),
        SummarySchemaVersion::CURRENT,
        semantics,
        context,
        behavior,
        origin,
    )
}

fn key(name: &str) -> ProcedureSummaryKey {
    key_for(identity(name), &[])
}

fn key_for(
    identity: ProcedureSummaryIdentity,
    dependencies: &[SummaryDependencyKey],
) -> ProcedureSummaryKey {
    ProcedureSummaryKey::try_new(identity, dependencies, None)
        .expect("fixture dependency set is bounded")
}

fn recursive_key_for(
    identity: ProcedureSummaryIdentity,
    dependencies: &[SummaryDependencyKey],
    group: SummaryRecursiveGroupKey,
) -> ProcedureSummaryKey {
    ProcedureSummaryKey::try_new(identity, dependencies, Some(group))
        .expect("fixture recursive dependency set is bounded")
}

fn transfer(input: SummaryPort, output: SummaryPort) -> SummaryTransfer {
    SummaryTransfer::try_new(
        input,
        SummaryExit::try_new(SummaryExitKind::Normal, output)
            .expect("fixture exit is structurally valid"),
        SummaryEvidence::proven_complete(),
    )
    .expect("fixture transfer is structurally valid")
}

fn exceptional(input: SummaryPort, output: SummaryPort) -> SummaryTransfer {
    SummaryTransfer::try_new(
        input,
        SummaryExit::try_new(SummaryExitKind::Exceptional, output)
            .expect("fixture exit is structurally valid"),
        SummaryEvidence::proven_complete(),
    )
    .expect("fixture transfer is structurally valid")
}

fn summary(
    key: ProcedureSummaryKey,
    transfers: Vec<SummaryTransfer>,
    effects: Vec<SummaryEffect>,
    dependencies: Vec<SummaryDependencyKey>,
    recursive_group: Option<SummaryRecursiveGroupKey>,
    completeness: SummaryCompleteness,
) -> SemanticProcedureSummary {
    assert_eq!(key.recursive_group(), recursive_group);
    SemanticProcedureSummary::try_new(key, transfers, effects, dependencies, completeness)
        .expect("fixture summary is valid")
}

fn call_effect(dependency: SummaryDependencyKey) -> SummaryEffect {
    SummaryEffect::new(
        SummaryEffectKey::Call {
            event: SummaryEventKey::hash_bytes(b"call"),
            callee: Box::new(dependency),
        },
        SummaryEvidence::proven_complete(),
    )
}

fn external_summary(name: &str, content: &[u8]) -> SemanticProcedureSummary {
    external_summary_with_completeness(name, content, SummaryCompleteness::Complete)
}

fn external_compatibility(
    summary: &SemanticProcedureSummary,
    behavior: UnmodeledCallBehavior,
) -> ExternalSummaryCompatibilityKey {
    ExternalSummaryCompatibilityKey::new(
        summary.key().schema(),
        summary.key().semantics(),
        summary.key().context(),
        summary.key().behavior(),
        summary.key().artifact().dependencies(),
        behavior,
    )
}

fn external_summary_with_completeness(
    name: &str,
    content: &[u8],
    completeness: SummaryCompleteness,
) -> SemanticProcedureSummary {
    let origin = ExternalSummaryOrigin::new(
        ExternalSummaryModelId::new(format!("test.{name}")).unwrap(),
        ExternalSummaryContentHash::hash_bytes(content),
        1,
    )
    .unwrap();
    let identity = identity_with(
        artifact(name, name.as_bytes()),
        name,
        SummarySemanticsVersion::hash_bytes(b"summary-semantics-v1"),
        SummaryContextKey::hash_bytes(b"context-insensitive"),
        SummaryBehaviorKey::hash_bytes(b"external-summary"),
        SummaryOrigin::External(origin),
    );
    summary(
        key_for(identity, &[]),
        vec![transfer(
            SummaryPort::Parameter(0),
            SummaryPort::NormalReturn,
        )],
        Vec::new(),
        Vec::new(),
        None,
        completeness,
    )
}

#[test]
fn external_summary_set_matches_structured_targets_and_hashes_content() {
    let first = external_summary("ExternalApi", b"v1");
    let first_compatibility = external_compatibility(&first, UnmodeledCallBehavior::Paranoid);
    let artifact = first.key().artifact().clone();
    let declaration = first.key().declaration().clone();
    let locator = SemanticLocator::new(
        artifact.mount(),
        artifact.path().clone(),
        artifact.language(),
        declaration,
        SemanticRole::Procedure,
        anchor(42),
    );
    let first_set = ExternalSemanticSummarySet::try_new(vec![first], first_compatibility).unwrap();
    assert!(first_set.summary_for(&locator).is_some());

    let partial = external_summary_with_completeness(
        "PartialExternalApi",
        b"partial-v1",
        SummaryCompleteness::partial(vec![SummaryIncompleteReason::Cancelled]).unwrap(),
    );
    let partial_compatibility = external_compatibility(&partial, UnmodeledCallBehavior::Paranoid);
    let partial_set = ExternalSemanticSummarySet::try_new(vec![partial], partial_compatibility)
        .expect("partial external summaries remain usable without claiming complete coverage");
    assert_eq!(partial_set.entries().len(), 1);

    let second = external_summary("ExternalApi", b"v2");
    let second_compatibility = external_compatibility(&second, UnmodeledCallBehavior::Paranoid);
    let second_set =
        ExternalSemanticSummarySet::try_new(vec![second], second_compatibility).unwrap();
    assert_ne!(first_set.fingerprint(), second_set.fingerprint());

    let duplicate_first = external_summary("ExternalApi", b"v1");
    let duplicate_compatibility =
        external_compatibility(&duplicate_first, UnmodeledCallBehavior::Paranoid);
    let duplicate = ExternalSemanticSummarySet::try_new(
        vec![duplicate_first, external_summary("ExternalApi", b"v2")],
        duplicate_compatibility,
    );
    assert_eq!(
        duplicate.unwrap_err(),
        ExternalSummarySetError::AmbiguousTarget
    );
    assert_eq!(
        {
            let inferred = summary(
                key("inferred"),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                SummaryCompleteness::Complete,
            );
            let compatibility = external_compatibility(&inferred, UnmodeledCallBehavior::Paranoid);
            ExternalSemanticSummarySet::try_new(vec![inferred], compatibility).unwrap_err()
        },
        ExternalSummarySetError::InferredSummary
    );
}

#[test]
fn summary_behavior_identity_partitions_unmodeled_call_profiles() {
    let base = SummaryBehaviorKey::hash_bytes(b"analysis-specific-behavior");
    let paranoid = base.with_unmodeled_call_behavior(UnmodeledCallBehavior::Paranoid);
    let optimistic = base.with_unmodeled_call_behavior(UnmodeledCallBehavior::Optimistic);
    let require_model = base.with_unmodeled_call_behavior(UnmodeledCallBehavior::RequireModel);

    assert_eq!(
        paranoid,
        base.with_unmodeled_call_behavior(UnmodeledCallBehavior::Paranoid)
    );
    assert_ne!(paranoid, optimistic);
    assert_ne!(paranoid, require_model);
    assert_ne!(optimistic, require_model);
}

#[test]
fn procedure_key_changes_for_every_summary_validity_dimension() {
    let base = key("helper");
    let base_identity = base.identity();
    let changed_artifacts = [
        artifact("helper", b"changed source"),
        artifact_with(
            "helper",
            b"helper",
            b"adapter-v2",
            b"semantic-ir-v1",
            b"configuration-v1",
            b"artifact-dependencies-v1",
        ),
        artifact_with(
            "helper",
            b"helper",
            b"adapter-v1",
            b"semantic-ir-v2",
            b"configuration-v1",
            b"artifact-dependencies-v1",
        ),
        artifact_with(
            "helper",
            b"helper",
            b"adapter-v1",
            b"semantic-ir-v1",
            b"configuration-v2",
            b"artifact-dependencies-v1",
        ),
        artifact_with(
            "helper",
            b"helper",
            b"adapter-v1",
            b"semantic-ir-v1",
            b"configuration-v1",
            b"artifact-dependencies-v2",
        ),
    ];
    for changed_artifact in changed_artifacts {
        assert_ne!(
            base,
            key_for(
                identity_with(
                    changed_artifact,
                    "helper",
                    base_identity.semantics(),
                    base_identity.context(),
                    base_identity.behavior(),
                    base_identity.origin().clone(),
                ),
                &[],
            )
        );
    }

    for changed_identity in [
        identity_with(
            base_identity.artifact().clone(),
            "helper",
            SummarySemanticsVersion::hash_bytes(b"summary-semantics-v2"),
            base_identity.context(),
            base_identity.behavior(),
            base_identity.origin().clone(),
        ),
        identity_with(
            base_identity.artifact().clone(),
            "helper",
            base_identity.semantics(),
            SummaryContextKey::hash_bytes(b"one-call-site"),
            base_identity.behavior(),
            base_identity.origin().clone(),
        ),
        identity_with(
            base_identity.artifact().clone(),
            "helper",
            base_identity.semantics(),
            base_identity.context(),
            SummaryBehaviorKey::hash_bytes(b"abstain-on-unknown-calls"),
            base_identity.origin().clone(),
        ),
        identity_with(
            base_identity.artifact().clone(),
            "helper",
            base_identity.semantics(),
            base_identity.context(),
            base_identity.behavior(),
            SummaryOrigin::External(
                ExternalSummaryOrigin::new(
                    ExternalSummaryModelId::new("java/runtime").expect("model identity is valid"),
                    ExternalSummaryContentHash::hash_bytes(b"model-v1"),
                    1,
                )
                .expect("model origin is valid"),
            ),
        ),
    ] {
        assert_ne!(base, key_for(changed_identity, &[]));
    }

    let dependency = SummaryDependencyKey::complete(key("callee"));
    assert_ne!(base, key_for(base_identity.clone(), &[dependency]));

    let external = |content: &[u8]| {
        key_for(
            identity_with(
                base_identity.artifact().clone(),
                "helper",
                base_identity.semantics(),
                base_identity.context(),
                base_identity.behavior(),
                SummaryOrigin::External(
                    ExternalSummaryOrigin::new(
                        ExternalSummaryModelId::new("java/runtime")
                            .expect("model identity is valid"),
                        ExternalSummaryContentHash::hash_bytes(content),
                        1,
                    )
                    .expect("model origin is valid"),
                ),
            ),
            &[],
        )
    };
    assert_ne!(external(b"model-v1"), external(b"model-v2"));
}

#[test]
fn recursive_group_key_invalidates_every_member_when_an_outgoing_dependency_changes() {
    let left_identity = identity("recursive-left");
    let right_identity = identity("recursive-right");
    let external_v1 = key_for(
        identity_with(
            artifact("external", b"version one"),
            "external",
            left_identity.semantics(),
            left_identity.context(),
            left_identity.behavior(),
            SummaryOrigin::Inferred,
        ),
        &[],
    );
    let external_v2 = key_for(
        identity_with(
            artifact("external", b"version two"),
            "external",
            left_identity.semantics(),
            left_identity.context(),
            left_identity.behavior(),
            SummaryOrigin::Inferred,
        ),
        &[],
    );
    let recursive_edges = [
        SummaryRecursiveEdge::new(left_identity.clone(), right_identity.clone()),
        SummaryRecursiveEdge::new(right_identity.clone(), left_identity.clone()),
    ];
    let group_v1 = SummaryRecursiveGroupKey::from_closure(
        &[left_identity.clone(), right_identity.clone()],
        &recursive_edges,
        std::slice::from_ref(&external_v1),
    )
    .expect("first recursive closure is bounded");
    let group_v2 = SummaryRecursiveGroupKey::from_closure(
        &[left_identity.clone(), right_identity.clone()],
        &recursive_edges,
        std::slice::from_ref(&external_v2),
    )
    .expect("second recursive closure is bounded");
    let changed_topology = [
        SummaryRecursiveEdge::new(left_identity.clone(), right_identity.clone()),
        SummaryRecursiveEdge::new(right_identity.clone(), right_identity.clone()),
    ];
    let group_with_changed_topology = SummaryRecursiveGroupKey::from_closure(
        &[left_identity.clone(), right_identity.clone()],
        &changed_topology,
        std::slice::from_ref(&external_v1),
    )
    .expect("changed recursive topology is bounded");
    let unchanged_direct_dependency = SummaryDependencyKey::recursive(right_identity);

    assert_ne!(group_v1, group_v2);
    assert_ne!(group_v1, group_with_changed_topology);
    assert_ne!(
        recursive_key_for(
            left_identity.clone(),
            std::slice::from_ref(&unchanged_direct_dependency),
            group_v1,
        ),
        recursive_key_for(
            left_identity,
            std::slice::from_ref(&unchanged_direct_dependency),
            group_v2,
        )
    );
}

#[test]
fn evidence_frontier_distinguishes_alternative_join_from_sequential_conjunction() {
    let proven_partial =
        SummaryEvidence::try_new(Vec::new(), vec!["candidate set truncated".into()])
            .expect("fixture evidence is valid");
    let unproven_complete = SummaryEvidence::try_new(vec!["ambiguous dispatch".into()], Vec::new())
        .expect("fixture evidence is valid");
    let frontier = proven_partial
        .join(&unproven_complete)
        .expect("alternative join is bounded");
    assert_eq!(frontier.alternatives().len(), 2);
    assert!(frontier.is_proven());
    assert!(frontier.is_complete());

    let sequential = proven_partial
        .conjoin(&unproven_complete)
        .expect("sequential conjunction is bounded");
    assert_eq!(sequential.alternatives().len(), 1);
    assert!(!sequential.is_proven());
    assert!(!sequential.is_complete());

    let strong = transfer(SummaryPort::Parameter(0), SummaryPort::NormalReturn);
    let weak = SummaryTransfer::try_new(
        SummaryPort::Parameter(0),
        SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::NormalReturn)
            .expect("fixture exit is valid"),
        sequential,
    )
    .expect("fixture transfer is valid");
    let result = summary(
        key("canonical"),
        vec![weak, strong],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    assert_eq!(result.transfers().len(), 1);
    assert_eq!(result.transfers()[0].evidence().alternatives().len(), 1);
    assert_eq!(
        result.transfers()[0].evidence().alternatives()[0].quality(),
        PathQuality::PROVEN_COMPLETE
    );
}

#[test]
fn complete_summary_rejects_rows_without_a_complete_alternative() {
    let incomplete = SummaryTransfer::try_new(
        SummaryPort::Parameter(0),
        SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::NormalReturn)
            .expect("fixture exit is valid"),
        SummaryEvidence::try_new(Vec::new(), vec!["missing callee".into()])
            .expect("fixture evidence is valid"),
    )
    .expect("fixture transfer is valid");

    assert_eq!(
        SemanticProcedureSummary::try_new(
            key("incomplete"),
            vec![incomplete],
            Vec::new(),
            Vec::new(),
            SummaryCompleteness::Complete,
        ),
        Err(SummaryValidationError::CompleteSummaryHasIncompleteTransfer)
    );
}

#[test]
fn summary_composition_is_associative_and_preserves_exceptional_rows_and_effects() {
    let middle = SummaryPort::Heap(SummaryLocationKey::hash_bytes(b"middle"));
    let output = SummaryPort::Heap(SummaryLocationKey::hash_bytes(b"output"));
    let first_key = key("first");
    let second_key = key("second");
    let third_key = key("third");
    let first = summary(
        first_key.clone(),
        vec![
            transfer(SummaryPort::Parameter(0), SummaryPort::NormalReturn),
            exceptional(SummaryPort::Parameter(1), SummaryPort::ExceptionalReturn),
        ],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let second = summary(
        second_key.clone(),
        vec![transfer(SummaryPort::Parameter(0), middle.clone())],
        vec![SummaryEffect::new(
            SummaryEffectKey::UnknownCall {
                event: SummaryEventKey::hash_bytes(b"unknown"),
                input: SummaryPort::Parameter(0),
            },
            SummaryEvidence::try_new(vec!["unknown target".into()], Vec::new())
                .expect("fixture evidence is valid"),
        )],
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let third = summary(
        third_key.clone(),
        vec![transfer(SummaryPort::Receiver, output.clone())],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let first_to_second = SummaryBoundaryMap::try_new(vec![
        SummaryBoundaryBinding::try_new(SummaryPort::NormalReturn, SummaryPort::Parameter(0))
            .expect("fixture boundary is valid"),
    ])
    .expect("fixture boundary map is non-empty");
    let second_to_third = SummaryBoundaryMap::try_new(vec![
        SummaryBoundaryBinding::try_new(middle, SummaryPort::Receiver)
            .expect("fixture boundary is valid"),
    ])
    .expect("fixture boundary map is non-empty");

    let first_second = first
        .compose(
            &second,
            SummaryEventKey::hash_bytes(b"call-12"),
            &first_to_second,
        )
        .expect("first composition succeeds");
    let left = first_second
        .compose(
            &third,
            SummaryEventKey::hash_bytes(b"call-23"),
            &second_to_third,
        )
        .expect("left-associated composition succeeds");
    let second_third = second
        .compose(
            &third,
            SummaryEventKey::hash_bytes(b"call-23"),
            &second_to_third,
        )
        .expect("second composition succeeds");
    let right = first
        .compose(
            &second_third,
            SummaryEventKey::hash_bytes(b"call-12"),
            &first_to_second,
        )
        .expect("right-associated composition succeeds");

    assert_eq!(left, right);
    assert!(
        left.transfers().iter().any(|row| {
            row.input() == &SummaryPort::Parameter(0) && row.exit().port() == &output
        })
    );
    assert!(left.transfers().iter().any(|row| {
        row.input() == &SummaryPort::Parameter(1)
            && row.exit().kind() == SummaryExitKind::Exceptional
    }));
    let unknown_effect = left
        .effects()
        .iter()
        .find(|effect| matches!(effect.key(), SummaryEffectKey::UnknownCall { .. }))
        .expect("nested unknown-call effect is preserved");
    assert!(!unknown_effect.evidence().is_proven());
}

#[test]
fn composition_derives_a_dependency_key_that_tracks_the_callee_revision() {
    let caller = summary(
        key("revision-caller"),
        vec![transfer(
            SummaryPort::Parameter(0),
            SummaryPort::NormalReturn,
        )],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let caller_identity = caller.key().identity();
    let callee = |source: &[u8]| {
        let identity = identity_with(
            artifact("revision-callee", source),
            "revision-callee",
            caller_identity.semantics(),
            caller_identity.context(),
            caller_identity.behavior(),
            SummaryOrigin::Inferred,
        );
        summary(
            key_for(identity, &[]),
            vec![transfer(
                SummaryPort::Parameter(0),
                SummaryPort::NormalReturn,
            )],
            Vec::new(),
            Vec::new(),
            None,
            SummaryCompleteness::Complete,
        )
    };
    let boundaries = SummaryBoundaryMap::try_new(vec![
        SummaryBoundaryBinding::try_new(SummaryPort::NormalReturn, SummaryPort::Parameter(0))
            .expect("fixture boundary is valid"),
    ])
    .expect("fixture boundary map is non-empty");
    let first = caller
        .compose(
            &callee(b"version one"),
            SummaryEventKey::hash_bytes(b"revision-call"),
            &boundaries,
        )
        .expect("first composition succeeds");
    let second = caller
        .compose(
            &callee(b"version two"),
            SummaryEventKey::hash_bytes(b"revision-call"),
            &boundaries,
        )
        .expect("second composition succeeds");

    assert_ne!(first.key(), second.key());
    assert_ne!(first.dependencies(), second.dependencies());
}

#[test]
fn composition_root_is_part_of_the_exact_lookup_key_even_without_a_reachable_call() {
    let caller = summary(
        key("root-key-caller"),
        vec![transfer(
            SummaryPort::Parameter(0),
            SummaryPort::NormalReturn,
        )],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let callee = summary(
        key("root-key-callee"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let unreachable = SummaryBoundaryMap::try_new(vec![
        SummaryBoundaryBinding::try_new(
            SummaryPort::Heap(SummaryLocationKey::hash_bytes(b"unreachable")),
            SummaryPort::Parameter(0),
        )
        .expect("fixture boundary is valid"),
    ])
    .expect("fixture boundary map is non-empty");
    let composed = caller
        .compose(
            &callee,
            SummaryEventKey::hash_bytes(b"unreachable-call"),
            &unreachable,
        )
        .expect("unreachable composition remains a valid artifact");

    assert_eq!(caller.dependencies(), composed.dependencies());
    assert_ne!(caller.key(), composed.key());
    assert!(caller.key().composition_root().is_none());
    assert!(composed.key().composition_root().is_some());
}

#[test]
fn composition_retains_a_reachable_nonreturning_callee_and_its_effects() {
    let caller = summary(
        key("nonreturning-caller"),
        vec![transfer(
            SummaryPort::Parameter(0),
            SummaryPort::NormalReturn,
        )],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let callee = summary(
        key("nonreturning-callee"),
        Vec::new(),
        vec![SummaryEffect::new(
            SummaryEffectKey::UnknownCall {
                event: SummaryEventKey::hash_bytes(b"nonreturning-unknown"),
                input: SummaryPort::Parameter(0),
            },
            SummaryEvidence::proven_complete(),
        )],
        Vec::new(),
        None,
        SummaryCompleteness::partial(vec![SummaryIncompleteReason::Cancelled])
            .expect("fixture partial summary has a reason"),
    );
    let boundaries = SummaryBoundaryMap::try_new(vec![
        SummaryBoundaryBinding::try_new(SummaryPort::NormalReturn, SummaryPort::Parameter(0))
            .expect("fixture boundary is valid"),
    ])
    .expect("fixture boundary map is non-empty");
    let composed = caller
        .compose(
            &callee,
            SummaryEventKey::hash_bytes(b"nonreturning-call"),
            &boundaries,
        )
        .expect("non-returning composition succeeds");

    assert!(composed.transfers().is_empty());
    assert!(!composed.completeness().is_complete());
    assert_eq!(
        composed.dependencies(),
        &[SummaryDependencyKey::complete(callee.key().clone())]
    );
    assert!(
        composed
            .effects()
            .iter()
            .any(|effect| matches!(effect.key(), SummaryEffectKey::Call { .. }))
    );
    assert!(composed.effects().iter().any(|effect| matches!(
        effect.key(),
        SummaryEffectKey::UnknownCall { event, .. }
            if *event == SummaryEventKey::hash_bytes(b"nonreturning-unknown")
    )));
}

#[test]
fn join_is_deterministic_idempotent_and_never_crosses_origin_keys() {
    let summary_key = key("joined");
    let first = summary(
        summary_key.clone(),
        vec![transfer(
            SummaryPort::Parameter(1),
            SummaryPort::NormalReturn,
        )],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let second = summary(
        summary_key.clone(),
        vec![transfer(
            SummaryPort::Parameter(0),
            SummaryPort::NormalReturn,
        )],
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    assert_eq!(first.join(&second), second.join(&first));
    assert_eq!(first.join(&first), Ok(first.clone()));

    let external_identity = identity_with(
        summary_key.artifact().clone(),
        "joined",
        summary_key.semantics(),
        summary_key.context(),
        summary_key.behavior(),
        SummaryOrigin::External(
            ExternalSummaryOrigin::new(
                ExternalSummaryModelId::new("java-runtime/closeable")
                    .expect("model identity is valid"),
                ExternalSummaryContentHash::hash_bytes(b"external-summary"),
                1,
            )
            .expect("external origin is versioned"),
        ),
    );
    let external = summary(
        key_for(external_identity, &[]),
        second.transfers().to_vec(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    assert_eq!(
        first.join(&external),
        Err(SummaryCompositionError::KeyMismatch)
    );
}

#[test]
fn algebra_limits_bound_work_without_breaking_maximum_size_join_idempotence() {
    let maximum = summary(
        key("maximum"),
        (0..MAX_SUMMARY_TRANSFERS as u32)
            .map(|ordinal| transfer(SummaryPort::Parameter(ordinal), SummaryPort::NormalReturn))
            .collect(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    assert_eq!(maximum.join(&maximum), Ok(maximum.clone()));

    let row_count = 1_001_u32;
    let first_key = key("work-first");
    let first = summary(
        first_key.clone(),
        (0..row_count)
            .map(|ordinal| transfer(SummaryPort::Parameter(ordinal), SummaryPort::NormalReturn))
            .collect(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let second = summary(
        key("work-second"),
        (0..row_count)
            .map(|ordinal| transfer(SummaryPort::Parameter(ordinal), SummaryPort::NormalReturn))
            .collect(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let boundaries = SummaryBoundaryMap::try_new(
        (0..row_count)
            .map(|ordinal| {
                SummaryBoundaryBinding::try_new(
                    SummaryPort::NormalReturn,
                    SummaryPort::Parameter(ordinal),
                )
                .expect("fixture boundary is valid")
            })
            .collect(),
    )
    .expect("fixture boundary map is non-empty");
    assert_eq!(
        first.compose(
            &second,
            SummaryEventKey::hash_bytes(b"work-call"),
            &boundaries,
        ),
        Err(SummaryCompositionError::CompositionWorkExceeded {
            limit: MAX_SUMMARY_COMPOSITION_STEPS,
        })
    );
}

#[test]
fn curated_models_reject_transfer_sets_before_unbounded_canonicalization() {
    let row = transfer(SummaryPort::Parameter(0), SummaryPort::NormalReturn);
    let error = CuratedCallModel::try_new(
        ExternalSummaryModelId::new("bounded-curated-model").unwrap(),
        ExternalSummaryContentHash::hash_bytes(b"bounded-curated-model-v1"),
        vec![row; MAX_SUMMARY_TRANSFERS + 1],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SummaryValidationError::TooManyTransfers {
            actual,
            limit: MAX_SUMMARY_TRANSFERS,
        } if actual == MAX_SUMMARY_TRANSFERS + 1
    ));
}

#[test]
fn repository_validates_dependencies_and_publishes_recursive_groups_atomically() {
    let leaf = summary(
        key("leaf"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let leaf_dependency = SummaryDependencyKey::complete(leaf.key().clone());
    let caller_key = key_for(identity("caller"), std::slice::from_ref(&leaf_dependency));
    let caller = summary(
        caller_key,
        Vec::new(),
        vec![call_effect(leaf_dependency.clone())],
        vec![leaf_dependency],
        None,
        SummaryCompleteness::Complete,
    );
    let mut repository = CompleteSummaryRepository::new();
    assert_eq!(
        repository.publish(caller.clone()),
        Err(SummaryPublicationError::MissingDependency)
    );
    repository.publish(leaf).expect("leaf publication succeeds");
    repository
        .publish(caller)
        .expect("caller publication succeeds after its dependency");

    let left_identity = identity("left-recursive");
    let right_identity = identity("right-recursive");
    let recursive_edges = [
        SummaryRecursiveEdge::new(left_identity.clone(), right_identity.clone()),
        SummaryRecursiveEdge::new(right_identity.clone(), left_identity.clone()),
    ];
    let group = SummaryRecursiveGroupKey::from_closure(
        &[left_identity.clone(), right_identity.clone()],
        &recursive_edges,
        &[],
    )
    .expect("fixture recursive group is valid");
    let left_dependency = SummaryDependencyKey::recursive(right_identity.clone());
    let right_dependency = SummaryDependencyKey::recursive(left_identity.clone());
    let left_key = recursive_key_for(left_identity, std::slice::from_ref(&left_dependency), group);
    let right_key = recursive_key_for(
        right_identity,
        std::slice::from_ref(&right_dependency),
        group,
    );
    let left = summary(
        left_key.clone(),
        vec![transfer(
            SummaryPort::Parameter(0),
            SummaryPort::NormalReturn,
        )],
        vec![call_effect(left_dependency.clone())],
        vec![left_dependency],
        Some(group),
        SummaryCompleteness::Complete,
    );
    let partial_right = summary(
        right_key.clone(),
        Vec::new(),
        vec![call_effect(right_dependency.clone())],
        vec![right_dependency.clone()],
        Some(group),
        SummaryCompleteness::partial(vec![SummaryIncompleteReason::Cancelled])
            .expect("partial summary has a reason"),
    );
    assert_eq!(
        repository.publish(left.clone()),
        Err(SummaryPublicationError::RequiresAtomicScc)
    );
    assert_eq!(
        repository.publish_scc(vec![left.clone(), partial_right]),
        Err(SummaryPublicationError::IncompleteSummary)
    );
    assert!(repository.get(&left_key).is_none());

    let right = summary(
        right_key.clone(),
        vec![transfer(SummaryPort::Receiver, SummaryPort::NormalReturn)],
        vec![call_effect(right_dependency.clone())],
        vec![right_dependency],
        Some(group),
        SummaryCompleteness::Complete,
    );
    assert_eq!(
        repository
            .publish_scc(vec![right.clone(), left.clone()])
            .expect("complete SCC publication succeeds"),
        SummaryPublicationOutcome::Inserted
    );
    assert_eq!(repository.get(&left_key), Some(&left));
    assert_eq!(repository.get(&right_key), Some(&right));

    let unreachable_recursive_boundary = SummaryBoundaryMap::try_new(vec![
        SummaryBoundaryBinding::try_new(
            SummaryPort::Heap(SummaryLocationKey::hash_bytes(b"unreachable-recursive")),
            SummaryPort::Receiver,
        )
        .expect("fixture unreachable recursive boundary is valid"),
    ])
    .expect("fixture unreachable recursive boundary map is non-empty");
    let unreachable_composition = left
        .compose(
            &right,
            SummaryEventKey::hash_bytes(b"unreachable-recursive-call"),
            &unreachable_recursive_boundary,
        )
        .expect("unreachable same-SCC composition remains valid");
    assert_eq!(unreachable_composition.dependencies(), left.dependencies());
    assert_eq!(
        unreachable_composition.recursive_topology(),
        left.recursive_topology()
    );

    let recursive_boundary = SummaryBoundaryMap::try_new(vec![
        SummaryBoundaryBinding::try_new(SummaryPort::NormalReturn, SummaryPort::Receiver)
            .expect("fixture recursive boundary is valid"),
    ])
    .expect("fixture recursive boundary map is non-empty");
    let composed_left = left
        .compose(
            &right,
            SummaryEventKey::hash_bytes(b"recursive-call"),
            &recursive_boundary,
        )
        .expect("recursive member composition succeeds");
    let mut composed_repository = CompleteSummaryRepository::new();
    composed_repository
        .publish_scc(vec![composed_left.clone(), right.clone()])
        .expect("composed recursive group remains publishable");
    assert_eq!(
        composed_repository.get(composed_left.key()),
        Some(&composed_left)
    );
    assert_eq!(
        repository
            .publish_scc(vec![left, right])
            .expect("identical SCC publication is idempotent"),
        SummaryPublicationOutcome::AlreadyPresent
    );
}

#[test]
fn repository_rejects_a_declared_recursive_batch_that_is_not_an_scc() {
    let left_identity = identity("not-scc-left");
    let right_identity = identity("not-scc-right");
    let recursive_edges = [
        SummaryRecursiveEdge::new(left_identity.clone(), right_identity.clone()),
        SummaryRecursiveEdge::new(right_identity.clone(), right_identity.clone()),
    ];
    let group = SummaryRecursiveGroupKey::from_closure(
        &[left_identity.clone(), right_identity.clone()],
        &recursive_edges,
        &[],
    )
    .expect("fixture recursive group is valid");
    let left_dependency = SummaryDependencyKey::recursive(right_identity.clone());
    let right_dependency = SummaryDependencyKey::recursive(right_identity.clone());
    let left = summary(
        recursive_key_for(left_identity, std::slice::from_ref(&left_dependency), group),
        Vec::new(),
        vec![call_effect(left_dependency.clone())],
        vec![left_dependency],
        Some(group),
        SummaryCompleteness::Complete,
    );
    let right = summary(
        recursive_key_for(
            right_identity,
            std::slice::from_ref(&right_dependency),
            group,
        ),
        Vec::new(),
        vec![call_effect(right_dependency.clone())],
        vec![right_dependency],
        Some(group),
        SummaryCompleteness::Complete,
    );
    let mut repository = CompleteSummaryRepository::new();

    assert_eq!(
        repository.publish_scc(vec![left, right]),
        Err(SummaryPublicationError::SccNotStronglyConnected)
    );
    assert!(repository.is_empty());
}

#[test]
fn repository_capacity_rejection_is_atomic() {
    let first = summary(
        key("capacity-first"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let second = summary(
        key("capacity-second"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        SummaryCompleteness::Complete,
    );
    let mut repository = CompleteSummaryRepository::with_limits(SummaryRepositoryLimits {
        max_entries: 1,
        max_bytes: usize::MAX,
    });
    repository
        .publish(first.clone())
        .expect("first summary fits");
    assert_eq!(repository.retained_bytes(), first.retained_bytes());
    assert!(matches!(
        repository.publish(second.clone()),
        Err(SummaryPublicationError::CapacityExceeded { .. })
    ));
    assert_eq!(repository.get(first.key()), Some(&first));
    assert!(repository.get(second.key()).is_none());

    repository.clear();
    assert!(repository.is_empty());
    assert_eq!(repository.retained_bytes(), 0);
    repository
        .publish(second.clone())
        .expect("owner-driven rotation restores capacity");
    assert_eq!(repository.get(second.key()), Some(&second));
}

#[test]
fn malformed_boundaries_external_identity_and_ambiguous_effects_are_rejected() {
    assert_eq!(
        ExternalSummaryModelId::new(" external/model "),
        Err(SummaryValidationError::InvalidExternalModelId)
    );
    assert_eq!(
        SummaryEffectKey::ambiguous_call(
            SummaryEventKey::hash_bytes(b"call"),
            SummaryPort::Receiver,
            Vec::new(),
        ),
        Err(SummaryValidationError::EmptyAmbiguousCallees)
    );
    assert_eq!(
        SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::ExceptionalReturn),
        Err(SummaryValidationError::IncompatibleExitPort)
    );
    assert_eq!(
        SummaryTransfer::try_new(
            SummaryPort::NormalReturn,
            SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::NormalReturn)
                .expect("normal return is a valid normal exit"),
            SummaryEvidence::proven_complete(),
        ),
        Err(SummaryValidationError::InvalidTransferInputPort)
    );
    assert_eq!(
        SummaryBoundaryBinding::try_new(SummaryPort::ExceptionalReturn, SummaryPort::Parameter(0),),
        Err(SummaryValidationError::InvalidBoundaryOutputPort)
    );
}

#[test]
fn evidence_join_rejects_a_union_larger_than_the_publication_bound() {
    let left = SummaryEvidence::try_new(
        (0..MAX_SUMMARY_EVIDENCE_REASONS)
            .map(|index| format!("left-{index}"))
            .collect(),
        Vec::new(),
    )
    .expect("each input is independently bounded");
    let right = SummaryEvidence::try_new(
        (0..MAX_SUMMARY_EVIDENCE_REASONS)
            .map(|index| format!("right-{index}"))
            .collect(),
        Vec::new(),
    )
    .expect("each input is independently bounded");

    assert_eq!(
        left.join(&right),
        Err(SummaryValidationError::TooManyEvidenceReasons {
            actual: MAX_SUMMARY_EVIDENCE_REASONS * 2,
            limit: MAX_SUMMARY_EVIDENCE_REASONS,
        })
    );
}
