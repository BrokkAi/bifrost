use super::*;
use brokk_bifrost_analysis::analyzer::semantic::*;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CompilerOptions, SourceFormat, compile_source,
};
use brokk_bifrost_analysis::test_support::{
    complete_semantic_capabilities, minimal_semantic_procedure, source_anchor,
};
use brokk_bifrost_flow::dataflow::*;
use brokk_bifrost_flow::taint::SourceClassId;
use std::sync::Arc;

// Exact binding admits a receiverless summary without an override claim, and
// that complete, effect-free summary certifies the call's continuation even
// over a partial external body (#12568). An overridable receiver call without
// the claim gets no closure, so its boundary evidence passes through.
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12856: exact summary binding erased partial external continuation evidence"
)]
#[brokk_bifrost_test_macros::hardwon(
    "#12568: an exact receiverless summary never certified its call's continuation"
)]
fn override_claim_binding_and_external_continuations() {
    for (has_receiver, exact) in [(false, true), (true, false)] {
        let mut pack = serde_json::json!({
            "schema_version": 2, "pack_id": "test.override-claim", "version": "1.0.0",
            "producer": {"name": "test", "version": "1.0.0"},
            "language": "python", "ecosystem": "python",
            "compatibility": {"bifrost": ">=0.12.0, <1.0.0", "toolchains": []},
            "provenance": {"source": "Synthetic override-claim regression", "revision": "#12846"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "test", "activation": [{"targets": []}]}]
        });
        pack["shards"][0]["payload"] = serde_json::json!({"kind":"procedure_summaries", "summaries":[{
            "id":"summary.test", "target":{"path":"external.py", "symbol":"external.call", "has_receiver":has_receiver,"parameter_count":0},
            "completeness":"complete", "transfers":[], "effects":[]
        }]});
        compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&pack).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        pack["shards"][0]["payload"]["summaries"][0]["covers_overrides"] = true.into();
        assert_eq!(
            compile_source(
                SourceFormat::Json,
                &serde_json::to_vec(&pack).unwrap(),
                &CompilerOptions::default()
            )
            .is_ok(),
            has_receiver,
            "validation permits override claims only on receiver targets",
        );
        let anchor = source_anchor(0, 0, 0);
        let target = SemanticLocator::new(
            unmaterialized_external_mount(),
            unmaterialized_external_path(),
            SemanticLanguage::Standard(Language::Python),
            DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    if has_receiver {
                        DeclarationSegmentKind::Method
                    } else {
                        DeclarationSegmentKind::Function
                    },
                    "call",
                    anchor,
                    0,
                )
                .unwrap(),
            ])
            .unwrap(),
            SemanticRole::Procedure,
            anchor,
        );
        let internal =
            ExternalSummaryTarget::internal_summary_locator(&target, "test.override").unwrap();
        let key = SemanticArtifactKey::new(
            internal.mount(),
            internal.path().clone(),
            internal.language(),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"test"),
            },
            AdapterSemanticsVersion::hash_bytes("test", b"v1").unwrap(),
            SemanticIrVersion::current(),
            ConfigurationFingerprint::hash_bytes(b"test"),
            DependencyFingerprint::hash_bytes(b"test"),
        );
        let origin = ExternalSummaryOrigin::new(
            ExternalSummaryModelId::new("test.override").unwrap(),
            ExternalSummaryContentHash::hash_bytes(b"test"),
            1,
            false,
        )
        .unwrap();
        let identity = ProcedureSummaryIdentity::new(
            key.clone(),
            internal.declaration().clone(),
            SummarySchemaVersion::CURRENT,
            SummarySemanticsVersion::hash_bytes(b"test"),
            SummaryContextKey::hash_bytes(b"test"),
            SummaryBehaviorKey::hash_bytes(b"test"),
            SummaryOrigin::External(origin.clone()),
        );
        let summary = SemanticProcedureSummary::try_new(
            ProcedureSummaryKey::try_new(identity, &[], None).unwrap(),
            vec![],
            vec![],
            vec![],
            SummaryCompleteness::Complete,
        )
        .unwrap();
        let compatibility = ExternalSummaryCompatibilityKey::new(
            SummarySchemaVersion::CURRENT,
            SummarySemanticsVersion::hash_bytes(b"test"),
            SummaryContextKey::hash_bytes(b"test"),
            SummaryBehaviorKey::hash_bytes(b"test"),
            key.dependencies(),
            UnmodeledCallBehavior::Paranoid,
        );
        let binding = brokk_bifrost_analysis::analyzer::semantic_model::UnmaterializedExternalSummaryCallShapeBinding { actual_locator:target.clone(), formal_locator: target.clone(), actual_to_formal:None, receiver_binds_first_formal:false, model_id:origin.model().as_str().into(), content:origin.content().digest(),contract_version:1,covers_overrides:false };
        let summaries =
            ExternalSemanticSummarySet::try_new_with_unmaterialized_call_shape_bindings(
                vec![],
                vec![(binding, summary)],
                compatibility,
            )
            .unwrap();
        let caller_key = SemanticArtifactKey::new(
            key.mount(),
            WorkspaceRelativePath::new("caller.py").unwrap(),
            key.language(),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"caller"),
            },
            AdapterSemanticsVersion::hash_bytes("test", b"v1").unwrap(),
            SemanticIrVersion::current(),
            ConfigurationFingerprint::hash_bytes(b"test"),
            DependencyFingerprint::hash_bytes(b"test"),
        );
        let caller_locator = SemanticLocator::new(
            caller_key.mount(),
            caller_key.path().clone(),
            caller_key.language(),
            DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::Function, "caller", anchor, 0)
                    .unwrap(),
            ])
            .unwrap(),
            SemanticRole::Procedure,
            anchor,
        );
        let mut parts = minimal_semantic_procedure(
            ProcedureId::new(0),
            caller_locator,
            ProcedureKind::Function,
        );
        let value = ValueId::new(0);
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        parts.values.push(SemanticValue {
            actual_borrow: Default::default(),
            static_type_origin: None,
            static_type_class: Default::default(),
            id: value,
            kind: SemanticValueKind::Callable,
            source,
            evidence,
        });
        parts.call_sites.push(SemanticCallSite {
            id: CallSiteId::new(0),
            point: ProgramPointId::new(0),
            invocation_mode: CallInvocationMode::Ordinary,
            execution_timing: ExecutionTiming::SameEvaluation,
            callee: value,
            receiver: has_receiver.then_some(value),
            member_selection: None,
            arguments: Box::default(),
            normal_results: Box::default(),
            result: None,
            thrown: None,
            declared_targets: CallableTargetResolution::Proven(CallableTarget::External(
                target.clone(),
            )),
            target_evidence: evidence,
            normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
            exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(2)),
            source,
            evidence,
        });
        let mut events = parts.points[0].events.to_vec();
        events.push(SemanticEvent::new(
            SemanticEffect::Invoke {
                call_site: CallSiteId::new(0),
            },
            source,
            evidence,
        ));
        parts.points[0].events = events.into_boxed_slice();
        for (point, kind) in [
            (1, CallContinuationKind::Normal),
            (2, CallContinuationKind::Exceptional),
        ] {
            let mut events = parts.points[point].events.to_vec();
            events.insert(
                0,
                SemanticEvent::new(
                    SemanticEffect::CallContinuation {
                        call_site: CallSiteId::new(0),
                        kind,
                    },
                    source,
                    evidence,
                ),
            );
            parts.points[point].events = events.into_boxed_slice();
        }
        let artifact = Arc::new(
            SemanticArtifact::try_new(
                caller_key,
                complete_semantic_capabilities(&[
                    SemanticCapability::Calls,
                    SemanticCapability::Values,
                    SemanticCapability::NormalCallContinuation,
                    SemanticCapability::ExceptionalCallContinuation,
                ]),
                vec![parts],
            )
            .unwrap(),
        );
        let caller = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
        let call = caller.call_site_handle(CallSiteId::new(0)).unwrap();
        let kind = DispatchBoundaryKind::External(Some(target));
        let closures = authored_call_closures(&call, &[&kind], &summaries, exact);
        assert_eq!(
            !closures.is_empty(),
            exact,
            "plan closure: receiver={has_receiver}"
        );
        let models = CallModels {
            curated: None,
            summaries: Some(summaries),
            resolved_external: exact,
            receiver_storage_available: true,
        };
        let universe = TaintUniverse::new(vec![SourceClassId::new("input").unwrap()]).unwrap();
        for completeness in [
            EvidenceCompleteness::Partial("external body unavailable".into()),
            EvidenceCompleteness::Complete,
        ] {
            let complete = completeness == EvidenceCompleteness::Complete;
            let mut boundaries = vec![DispatchBoundary {
                kind: kind.clone(),
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Proven,
                completeness,
                partial_cause: None,
                provenance: Box::default(),
            }];
            brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::attach_dispatch_provenance(&call,&mut [],&mut boundaries,None,None,OracleLimits::default()).unwrap();
            let result = DispatchResult::new(
                &call,
                vec![],
                boundaries,
                CandidateCoverage::Exhaustive,
                OracleLimits::default(),
            )
            .unwrap();
            let model = covering_model(&models, &call, Some(&result), &universe);
            let quality = continuation_quality(&models, model.as_ref(), &call, Some(&result));
            let expected = if exact {
                HopQuality::CERTAIN
            } else {
                HopQuality::new(true, complete)
            };
            assert_eq!(
                quality, expected,
                "continuation evidence: receiver={has_receiver}, exact={exact}"
            );
        }
    }
}
