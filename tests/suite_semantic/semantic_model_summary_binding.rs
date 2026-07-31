use brokk_bifrost::Language;
use brokk_bifrost::analyzer::dataflow::{
    ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey, SemanticProcedureSummary,
    SummaryBehaviorKey, SummaryCompleteness, SummaryContextKey, SummaryDependencyKey,
    SummaryEffectKey, SummaryExitKind, SummaryIncompleteReason, SummaryOrigin, SummaryPort,
    SummarySchemaVersion, SummarySemanticsVersion, UnmodeledCallBehavior,
};
use brokk_bifrost::analyzer::semantic::{
    AdapterSemanticsVersion, ConfigurationFingerprint, ContentIdentity, DeclarationLocator,
    DeclarationSegment, DeclarationSegmentKind, DependencyFingerprint, SemanticArtifactKey,
    SemanticIrVersion, SemanticLanguage, SemanticLocator, SemanticRole, SourceAnchor,
    SourcePosition, SourceRevision, SourceSpan, WorkspaceMountId, WorkspaceRelativePath,
};
use brokk_bifrost::analyzer::semantic_model::{
    CompiledProcedureSummary, CompiledProcedureTarget, CompiledSummaryEffect,
    CompiledSummaryExitKind, CompiledSummaryInput, CompiledSummaryLocation, CompiledSummaryOutput,
    CompiledSummaryTransfer, CompilerOptions, Completeness, DecodeLimits,
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, ProcedureSummaryBindingError, SourceFormat,
    bind_compiled_procedure_summaries, compile_source, decode_shard_for_manifest,
};

const PROCEDURES_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/procedure-summaries-v1.json");

fn fixture_summaries() -> Vec<CompiledProcedureSummary> {
    let pack = compile_source(
        SourceFormat::Json,
        PROCEDURES_JSON,
        &CompilerOptions::default(),
    )
    .expect("procedure fixture compiles");
    let shard = decode_shard_for_manifest(
        &pack.manifest,
        &pack.shards[0].descriptor,
        &pack.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .expect("compiled procedure shard decodes");
    shard
        .payload()
        .procedure_summaries()
        .expect("fixture is one procedure-summary family")
        .to_vec()
}

fn compatibility(dependencies: DependencyFingerprint) -> ExternalSummaryCompatibilityKey {
    ExternalSummaryCompatibilityKey::new(
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(b"compiled-model-summary-semantics-v1"),
        SummaryContextKey::hash_bytes(b"compiled-model-summary-context-v1"),
        SummaryBehaviorKey::hash_bytes(b"compiled-model-summary-behavior-v1"),
        dependencies,
        UnmodeledCallBehavior::RequireModel,
    )
}

fn anchor(offset: u32) -> SourceAnchor {
    let position = SourcePosition::new(offset, 0, offset);
    SourceAnchor::new(SourceSpan::new(position, position).unwrap(), 0)
}

fn exact_binding(
    summary: &CompiledProcedureSummary,
    mount_material: &[u8],
    source_offset: u32,
    dependencies: DependencyFingerprint,
) -> ExactProcedureSummaryTargetBinding {
    let mount = WorkspaceMountId::hash_bytes(mount_material);
    let path = WorkspaceRelativePath::new(&summary.target.path).unwrap();
    let language = SemanticLanguage::Standard(Language::Java);
    let artifact = SemanticArtifactKey::new(
        mount,
        path.clone(),
        language,
        SourceRevision::Disk {
            content: ContentIdentity::hash_bytes(b"same exact mounted artifact bytes"),
        },
        AdapterSemanticsVersion::hash_bytes("summary-binding-test", b"adapter-v1").unwrap(),
        SemanticIrVersion::current(),
        ConfigurationFingerprint::hash_bytes(b"summary-binding-config"),
        dependencies,
    );
    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(
            DeclarationSegmentKind::Method,
            summary.id.clone(),
            anchor(source_offset),
            0,
        )
        .unwrap(),
    ])
    .unwrap();
    let procedure = SemanticLocator::new(
        mount,
        path,
        language,
        declaration,
        SemanticRole::Procedure,
        anchor(source_offset),
    );
    let receiver = summary
        .target
        .has_receiver
        .then_some(ExactProcedureSummaryReceiver);
    let parameters = (0..summary.target.parameter_count)
        .map(ExactProcedureSummaryParameter::new)
        .collect();
    ExactProcedureSummaryTargetBinding::new(
        summary.id.clone(),
        summary.target.clone(),
        artifact,
        procedure,
        ExactProcedureSummaryBoundary::new(receiver, parameters),
    )
}

fn bindings(
    summaries: &[CompiledProcedureSummary],
    mount_material: &[u8],
    source_offset: u32,
    dependencies: DependencyFingerprint,
) -> Vec<ExactProcedureSummaryTargetBinding> {
    summaries
        .iter()
        .enumerate()
        .map(|(index, summary)| {
            exact_binding(
                summary,
                mount_material,
                source_offset + u32::try_from(index).unwrap(),
                dependencies,
            )
        })
        .collect()
}

fn summary_id(summary: &SemanticProcedureSummary) -> &str {
    match summary.origin() {
        SummaryOrigin::External(origin) => origin.model().as_str(),
        SummaryOrigin::Inferred => panic!("binder emitted inferred summary"),
    }
}

fn summary_with_model_id<'a>(
    set: &'a ExternalSemanticSummarySet,
    model_id: &str,
) -> &'a SemanticProcedureSummary {
    set.entries()
        .map(|(_, summary)| summary)
        .find(|summary| summary_id(summary) == model_id)
        .unwrap_or_else(|| panic!("missing summary `{model_id}`"))
}

fn effect_event(effect: &SummaryEffectKey) -> brokk_bifrost::analyzer::dataflow::SummaryEventKey {
    match effect {
        SummaryEffectKey::Allocation { event, .. }
        | SummaryEffectKey::Call { event, .. }
        | SummaryEffectKey::Escape { event, .. }
        | SummaryEffectKey::UnknownCall { event, .. }
        | SummaryEffectKey::UnknownCallBoundary { event }
        | SummaryEffectKey::AmbiguousCall { event, .. } => *event,
    }
}

#[test]
fn compiled_records_lower_every_supported_boundary_and_effect_honestly() {
    let summaries = fixture_summaries();
    let dependencies = DependencyFingerprint::hash_bytes(b"fixture-dependencies");
    let set = bind_compiled_procedure_summaries(
        &summaries,
        bindings(&summaries, b"first-workspace-root", 10, dependencies),
        compatibility(dependencies),
    )
    .unwrap();

    let helper = summary_with_model_id(&set, "acme.procedure-summaries#summary.helper");
    let helper_origin = match helper.origin() {
        SummaryOrigin::External(origin) => origin,
        SummaryOrigin::Inferred => unreachable!(),
    };
    assert_eq!(
        helper_origin.content().to_string(),
        summaries
            .iter()
            .find(|summary| summary.id == "summary.helper")
            .unwrap()
            .content_sha256
    );
    assert_eq!(helper.transfers().len(), 5);
    assert!(helper.transfers().iter().any(|transfer| {
        transfer.input() == &SummaryPort::Parameter(0)
            && transfer.exit().kind() == SummaryExitKind::Normal
            && transfer.exit().port() == &SummaryPort::NormalReturn
    }));
    assert!(helper.transfers().iter().any(|transfer| {
        transfer.input() == &SummaryPort::Receiver
            && transfer.exit().port() == &SummaryPort::Receiver
    }));
    assert!(helper.transfers().iter().any(|transfer| {
        transfer.exit().kind() == SummaryExitKind::Exceptional
            && transfer.exit().port() == &SummaryPort::ExceptionalReturn
    }));
    assert!(
        helper
            .transfers()
            .iter()
            .any(|transfer| { matches!(transfer.exit().port(), SummaryPort::Capture(_)) })
    );
    assert!(
        helper
            .transfers()
            .iter()
            .any(|transfer| { matches!(transfer.exit().port(), SummaryPort::Heap(_)) })
    );
    assert!(
        helper
            .transfers()
            .iter()
            .all(|transfer| !transfer.evidence().is_proven() && !transfer.evidence().is_complete())
    );
    assert!(matches!(
        helper.completeness(),
        SummaryCompleteness::Partial(reasons)
            if matches!(reasons.as_ref(), [SummaryIncompleteReason::ExternalModelIncomplete(_)])
    ));

    assert!(helper.effects().iter().any(|effect| matches!(
        effect.key(),
        SummaryEffectKey::Allocation {
            output: SummaryPort::Heap(_),
            ..
        }
    )));
    assert!(helper.effects().iter().any(|effect| matches!(
        effect.key(),
        SummaryEffectKey::Escape {
            input: SummaryPort::Parameter(0),
            ..
        }
    )));
    assert!(helper.effects().iter().any(|effect| matches!(
        effect.key(),
        SummaryEffectKey::UnknownCall {
            input: SummaryPort::Receiver,
            ..
        }
    )));
    assert!(
        helper
            .effects()
            .iter()
            .any(|effect| matches!(effect.key(), SummaryEffectKey::UnknownCallBoundary { .. }))
    );
    assert!(
        helper
            .effects()
            .iter()
            .all(|effect| { !effect.evidence().is_proven() && !effect.evidence().is_complete() })
    );

    let wrapper = summary_with_model_id(&set, "acme.procedure-summaries#summary.wrapper");
    assert!(wrapper.completeness().is_complete());
    assert!(
        wrapper.transfers().iter().all(|transfer| {
            !transfer.evidence().is_proven() && transfer.evidence().is_complete()
        })
    );
    assert!(wrapper.effects().iter().any(|effect| matches!(
        effect.key(),
        SummaryEffectKey::Call {
            callee,
            ..
        } if matches!(callee.as_ref(), SummaryDependencyKey::Complete(_))
    )));
    assert!(wrapper.effects().iter().any(|effect| matches!(
        effect.key(),
        SummaryEffectKey::AmbiguousCall { candidates, .. }
            if candidates.iter().any(|candidate| matches!(candidate, SummaryDependencyKey::Complete(_)))
                && candidates.iter().any(|candidate| matches!(candidate, SummaryDependencyKey::Recursive(_)))
    )));
    assert!(wrapper.recursive_group().is_some());
    assert_eq!(wrapper.dependencies().len(), 2);
}

#[test]
fn record_order_and_target_ephemera_do_not_change_stable_model_identity() {
    let summaries = fixture_summaries();
    let dependencies = DependencyFingerprint::hash_bytes(b"stable-dependencies");
    let baseline = bind_compiled_procedure_summaries(
        &summaries,
        bindings(&summaries, b"workspace-root-a", 10, dependencies),
        compatibility(dependencies),
    )
    .unwrap();

    let mut reordered = summaries.clone();
    reordered.reverse();
    let mut reordered_bindings = bindings(&reordered, b"workspace-root-b", 900, dependencies);
    reordered_bindings.reverse();
    let alternate = bind_compiled_procedure_summaries(
        &reordered,
        reordered_bindings,
        compatibility(dependencies),
    )
    .unwrap();

    assert_eq!(baseline.fingerprint(), alternate.fingerprint());
    for model_id in [
        "acme.procedure-summaries#summary.helper",
        "acme.procedure-summaries#summary.wrapper",
    ] {
        let first = summary_with_model_id(&baseline, model_id);
        let second = summary_with_model_id(&alternate, model_id);
        assert_eq!(first.key().fingerprint(), second.key().fingerprint());
        assert_eq!(first.recursive_group(), second.recursive_group());
        assert_eq!(first.transfers(), second.transfers());
        assert_eq!(
            first
                .effects()
                .iter()
                .map(|effect| effect_event(effect.key()))
                .collect::<Vec<_>>(),
            second
                .effects()
                .iter()
                .map(|effect| effect_event(effect.key()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn missing_duplicate_ambiguous_and_mismatched_targets_fail_closed() {
    let summaries = fixture_summaries();
    let dependencies = DependencyFingerprint::hash_bytes(b"target-errors");
    let exact = bindings(&summaries, b"target-errors-root", 10, dependencies);

    let missing = bind_compiled_procedure_summaries(
        &summaries,
        vec![exact[0].clone()],
        compatibility(dependencies),
    )
    .unwrap_err();
    assert!(matches!(
        missing,
        ProcedureSummaryBindingError::MissingBinding { .. }
    ));

    let duplicate = bind_compiled_procedure_summaries(
        &summaries,
        vec![exact[0].clone(), exact[0].clone(), exact[1].clone()],
        compatibility(dependencies),
    )
    .unwrap_err();
    assert!(matches!(
        duplicate,
        ProcedureSummaryBindingError::AmbiguousTarget { .. }
    ));

    let mut wrong_target = exact.clone();
    wrong_target[0] = ExactProcedureSummaryTargetBinding::new(
        wrong_target[0].summary_id(),
        CompiledProcedureTarget {
            symbol: "different()".to_owned(),
            ..wrong_target[0].target().clone()
        },
        wrong_target[0].artifact().clone(),
        wrong_target[0].procedure().clone(),
        wrong_target[0].boundary().clone(),
    );
    assert!(matches!(
        bind_compiled_procedure_summaries(&summaries, wrong_target, compatibility(dependencies)),
        Err(ProcedureSummaryBindingError::TargetMismatch { .. })
    ));

    let shared_procedure = exact[0].procedure().clone();
    let shared_artifact = exact[0].artifact().clone();
    let ambiguous = vec![
        exact[0].clone(),
        ExactProcedureSummaryTargetBinding::new(
            exact[1].summary_id(),
            exact[1].target().clone(),
            shared_artifact,
            shared_procedure,
            exact[1].boundary().clone(),
        ),
    ];
    assert!(matches!(
        bind_compiled_procedure_summaries(&summaries, ambiguous, compatibility(dependencies)),
        Err(ProcedureSummaryBindingError::AmbiguousTarget { .. })
    ));
}

#[test]
fn compatibility_callees_and_locations_return_typed_errors() {
    let summaries = fixture_summaries();
    let dependencies = DependencyFingerprint::hash_bytes(b"typed-errors");
    let exact = bindings(&summaries, b"typed-errors-root", 10, dependencies);
    assert!(matches!(
        bind_compiled_procedure_summaries(
            &summaries,
            exact.clone(),
            compatibility(DependencyFingerprint::hash_bytes(b"wrong"))
        ),
        Err(ProcedureSummaryBindingError::IncompatibleCompatibilityKey { .. })
    ));

    let mut unbound = summaries.clone();
    let wrapper = unbound
        .iter_mut()
        .find(|summary| summary.id == "summary.wrapper")
        .unwrap();
    wrapper.effects.push(CompiledSummaryEffect::Call {
        event: "event.wrapper.missing".to_owned(),
        callee: "summary.missing".to_owned(),
    });
    assert!(matches!(
        bind_compiled_procedure_summaries(&unbound, exact.clone(), compatibility(dependencies)),
        Err(ProcedureSummaryBindingError::UnboundCallee { .. })
    ));

    let mut unsupported = summaries.clone();
    let helper = unsupported
        .iter_mut()
        .find(|summary| summary.id == "summary.helper")
        .unwrap();
    helper.transfers.push(CompiledSummaryTransfer {
        input: CompiledSummaryInput::Parameter { ordinal: 0 },
        exit_kind: CompiledSummaryExitKind::Normal,
        output: CompiledSummaryOutput::Heap {
            location: "location.missing".to_owned(),
        },
    });
    assert!(matches!(
        bind_compiled_procedure_summaries(&unsupported, exact, compatibility(dependencies)),
        Err(ProcedureSummaryBindingError::UnsupportedLocationBinding { .. })
    ));

    let mut invalid_content = summaries.clone();
    invalid_content[0].content_sha256 = "not-a-sha256".to_owned();
    let invalid_content_bindings =
        bindings(&invalid_content, b"invalid-content-root", 10, dependencies);
    assert!(matches!(
        bind_compiled_procedure_summaries(
            &invalid_content,
            invalid_content_bindings,
            compatibility(dependencies)
        ),
        Err(ProcedureSummaryBindingError::InvalidContentHash { .. })
    ));
}

fn recursive_record(id: usize, count: usize) -> CompiledProcedureSummary {
    let next = (id + 1) % count;
    CompiledProcedureSummary {
        id: format!("summary.{id}"),
        model_id: format!("recursion-pack#summary.{id}"),
        contract_version: 1,
        content_sha256: "00".repeat(32),
        target: CompiledProcedureTarget {
            path: format!("models/Procedure{id}.class"),
            symbol: format!("procedure{id}()"),
            has_receiver: false,
            parameter_count: 0,
        },
        completeness: Completeness::Complete,
        locations: Vec::<CompiledSummaryLocation>::new(),
        transfers: Vec::new(),
        effects: vec![CompiledSummaryEffect::Call {
            event: format!("event.{id}"),
            callee: format!("summary.{next}"),
        }],
    }
}

#[test]
fn oversized_recursive_closure_returns_the_typed_recursion_error() {
    let count = 4_097;
    let summaries = (0..count)
        .map(|id| recursive_record(id, count))
        .collect::<Vec<_>>();
    let dependencies = DependencyFingerprint::hash_bytes(b"recursive-errors");
    let exact = bindings(&summaries, b"recursive-errors-root", 10, dependencies);
    assert_eq!(
        bind_compiled_procedure_summaries(&summaries, exact, compatibility(dependencies)),
        Err(ProcedureSummaryBindingError::InvalidRecursion)
    );
}
