use super::*;

#[test]
fn endpoint_descriptor_fields_charge_owned_storage() {
    use crate::definition::{PolicyCategoryId, TaintImpact, TaintLabel};
    use crate::resolved::PolicyDependencyPath;

    let mut name = String::with_capacity(128);
    name.push_str("argument");
    let binding = PolicyEndpointBinding::ArgumentName { name };
    assert_eq!(
        binding.retained_size(),
        size_of::<PolicyEndpointBinding>() + 128
    );
    assert_eq!(
        PolicyEndpointBinding::ArgumentIndex { index: 2 }.retained_size(),
        size_of::<PolicyEndpointBinding>()
    );

    let labels = vec![TaintLabel::new("user-input").unwrap()];
    let source = EndpointTaintSemantics::Source {
        labels,
        threat_model: None,
        evidence: None,
    };
    let EndpointTaintSemantics::Source { labels, .. } = &source else {
        unreachable!()
    };
    assert_eq!(
        source.retained_size(),
        size_of::<EndpointTaintSemantics>() + retained_extra(labels)
    );
    let sink = EndpointTaintSemantics::Sink {
        accepts: vec![TaintLabel::new("untrusted").unwrap()],
        tags: Vec::new(),
        impacts: vec![TaintImpact::new("confidentiality").unwrap()],
    };
    let EndpointTaintSemantics::Sink {
        accepts,
        tags,
        impacts,
    } = &sink
    else {
        unreachable!()
    };
    assert_eq!(
        sink.retained_size(),
        size_of::<EndpointTaintSemantics>()
            + retained_extra(accepts)
            + retained_extra(tags)
            + retained_extra(impacts)
    );

    let path = PolicyDependencyPath::new("/dependencies/endpoints/source").unwrap();
    let origin = EndpointOrigin::PolicyLocal { path };
    let EndpointOrigin::PolicyLocal { path } = &origin else {
        unreachable!()
    };
    assert_eq!(
        origin.retained_size(),
        size_of::<EndpointOrigin>() + retained_extra(path)
    );
    let origin = EndpointOrigin::ExactMatch {
        path: PolicyDependencyPath::new("/dependencies/endpoints/match").unwrap(),
        source: PolicySourceIdentity::new("policies/endpoints.rqlp"),
    };
    let EndpointOrigin::ExactMatch { path, source } = &origin else {
        unreachable!()
    };
    assert_eq!(
        origin.retained_size(),
        size_of::<EndpointOrigin>() + retained_extra(path) + retained_extra(source)
    );
    let categories = vec![PolicyCategoryId::new("input.user-controlled").unwrap()];
    let predicate = CategoryPredicate::Any { categories };
    let CategoryPredicate::Any { categories } = &predicate else {
        unreachable!()
    };
    assert_eq!(
        predicate.retained_size(),
        size_of::<CategoryPredicate>() + retained_extra(categories)
    );
}

#[test]
fn diff_review_fields_respect_exact_batch_byte_boundary() {
    let policy_id = PolicyId::new(format!("test.{}", "p".repeat(180))).unwrap();
    let unqualified = PolicyDiffUnqualifiedPolicy::new(
        policy_id.clone(),
        "incomplete",
        "d".repeat(100_000),
        vec!["diagnostic".into()],
    );
    assert_eq!(
        unqualified.retained_size(),
        size_of::<PolicyDiffUnqualifiedPolicy>()
            + retained_extra(&policy_id)
            + unqualified.completion.capacity()
            + unqualified.completion_detail.capacity()
            + retained_extra(&unqualified.diagnostics)
    );
    let fixed =
        PolicyDiffFixedFinding::new(policy_id.clone(), PolicyFindingId::from_bytes([7; 32]));
    assert_eq!(
        fixed.retained_size(),
        size_of::<PolicyDiffFixedFinding>() + retained_extra(&policy_id)
    );
    let review = PolicyDiffReview::new(
        "revision".into(),
        "c".repeat(2000),
        false,
        vec![unqualified],
        PolicyDiffCounts {
            new: 0,
            persisting: 0,
            fixed: 1,
        },
        vec![fixed],
    );
    let expected_review = size_of::<PolicyDiffReview>()
        + review.base_revision.capacity()
        + review.base_commit.capacity()
        + retained_vec_size_from_parts(
            &review.unqualified_policies,
            review.unqualified_policies.len(),
        )
        + retained_extra(&review.fixed);
    let base = empty_document_retained_bytes();
    let exact = base + expected_review - size_of::<PolicyDiffReview>();
    assert!(exact > minimum_construction_budget());
    let mut admitted = PolicyReportBuilder::new(batch_budget_capped_at(exact), 0).unwrap();
    admitted.set_diff(review.clone()).unwrap();
    admitted.finish().unwrap();
    let mut refused = PolicyReportBuilder::new(batch_budget_capped_at(exact - 1), 0).unwrap();
    assert!(matches!(
        refused.set_diff(review),
        Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. }) if max_bytes == exact - 1
    ));
}

#[test]
fn execution_progress_charges_pending_ids_at_batch_boundary() {
    let pending = PolicyId::new(format!("test.{}", "p".repeat(180))).unwrap();
    let execution = PolicyExecutionMetadata::try_new(
        0,
        Vec::new(),
        Some(PolicyExecutionTermination::DeadlineExceeded),
        Some(PolicyExecutionStage::PolicySelection),
        None,
        PolicyExecutionProgress {
            pending: vec![pending],
            ..Default::default()
        },
    )
    .unwrap();
    let expected = size_of::<PolicyExecutionMetadata>()
        + retained_extra(&execution.active_policy_id)
        + retained_extra(&execution.stage_timings)
        + retained_extra(&execution.completed_policy_ids)
        + retained_extra(&execution.pending_policy_ids)
        + retained_extra(&execution.interrupted_policy_ids)
        + retained_extra(&execution.timed_out_policy_ids);
    let anchor = PolicyPackActivationReview::new_with_mode(
        "a".repeat(100_000),
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        Vec::new(),
    );
    let exact = empty_document_retained_bytes() + retained_extra(&anchor) + expected
        - size_of::<PolicyExecutionMetadata>();
    assert!(exact > minimum_construction_budget());
    let mut admitted = PolicyReportBuilder::new(batch_budget_capped_at(exact), 0).unwrap();
    admitted.set_packs(anchor.clone()).unwrap();
    admitted.set_execution(execution.clone()).unwrap();
    admitted.finish().unwrap();
    let mut refused = PolicyReportBuilder::new(batch_budget_capped_at(exact - 1), 0).unwrap();
    refused.set_packs(anchor).unwrap();
    assert!(matches!(refused.set_execution(execution.clone()),
            Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. }) if max_bytes == exact - 1));
    assert_eq!(execution.retained_size(), expected);
}

#[test]
fn incremental_review_charges_each_policy_identity() {
    use crate::units::WidenReason;
    let policy_id = PolicyId::new(format!("test.{}", "i".repeat(180))).unwrap();
    let review = PolicyIncrementalReview::evaluated_in_full(
        vec![policy_id.clone()],
        WidenReason::WholePolicyFamily,
    );
    assert_eq!(
        review.policies()[0].retained_size(),
        size_of::<PolicyIncrementalRun>() + policy_id.as_str().len()
    );
    assert_eq!(
        review.retained_size(),
        size_of::<PolicyIncrementalReview>()
            + retained_vec_size_from_parts(review.policies(), review.policies().len())
    );
}

#[test]
fn message_variants_charge_only_owned_text() {
    use crate::definition::GeneratedRelation;
    let mut text = String::with_capacity(128);
    text.push_str("message");
    let static_message = PolicyMessageSpec::Static { text };
    assert_eq!(
        static_message.retained_size(),
        size_of::<PolicyMessageSpec>() + 128
    );
    let generated = PolicyMessageSpec::Generated {
        relation: GeneratedRelation::CanReach,
    };
    assert_eq!(generated.retained_size(), size_of::<PolicyMessageSpec>());
}

#[test]
fn pack_summary_evidence_is_complete_and_charged_to_the_batch() {
    let evidence = (0..MAX_PACK_PROCEDURE_SUMMARY_EVIDENCE - 1)
        .map(|index| {
            PolicyPackProcedureSummaryEvidence::new(
                format!("summary-{index}"),
                format!("symbol-{index}"),
                1,
            )
        })
        .collect::<Vec<_>>();
    let sample = &evidence[0];
    assert_eq!(
        sample.retained_size(),
        size_of::<PolicyPackProcedureSummaryEvidence>()
            + sample.summary_id.capacity()
            + sample.symbol.capacity()
    );
    let mut reason = String::with_capacity(100_000);
    reason.push_str("reviewed");
    let decision = PolicyPackDecision::new(
        "pack".into(),
        PolicyPackDecisionStatus::Selected,
        Some(reason),
    )
    .with_summary_matches(evidence.clone());
    assert_eq!(
        decision.retained_size(),
        size_of::<PolicyPackDecision>()
            + decision.pack.capacity()
            + decision.reason.as_ref().unwrap().capacity()
            + retained_extra(&decision.summary_matches)
    );
    let review = PolicyPackActivationReview::new_with_mode(
        "activation".into(),
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        vec![decision],
    );
    let exact = empty_document_retained_bytes() + retained_extra(&review);
    assert!(exact > minimum_construction_budget());
    let mut admitted = PolicyReportBuilder::new(batch_budget_capped_at(exact), 0).unwrap();
    admitted.set_packs(review.clone()).unwrap();
    let document = admitted.finish().unwrap();
    let reported = &document.packs().unwrap().decisions()[0];
    assert!(!reported.summary_matches_truncated());
    assert_eq!(reported.summary_matches().len(), evidence.len());
    for item in &evidence {
        assert!(reported.summary_matches().contains(item));
    }
    let mut refused = PolicyReportBuilder::new(batch_budget_capped_at(exact - 1), 0).unwrap();
    assert!(matches!(refused.set_packs(review),
            Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. }) if max_bytes == exact - 1));
}

#[test]
fn endpoint_dependency_charges_all_origin_storage() {
    use crate::resolved::PolicyDependencyPath;
    use brokk_bifrost_analysis::schema_version::SchemaVersionOrigin;
    let schema = SchemaVersionResolution {
        version: 1,
        origin: SchemaVersionOrigin::Explicit,
    };
    let mut display_name = String::with_capacity(128);
    display_name.push_str("example");
    let mut dependency = crate::test_support::resolved_endpoint_dependency(
        ResolvedEndpointIdentity::Local {
            policy_id: PolicyId::new("test.policy").unwrap(),
            entry_id: "example".parse().unwrap(),
        },
        schema,
        PolicySelectorPath::new("/selector").unwrap(),
        schema,
        ResolvedEndpointModel::new(
            EndpointRole::Source,
            display_name,
            Vec::new(),
            PolicyEndpointBinding::ReturnValue,
            None,
            Vec::new(),
        ),
        PolicyDependencyPath::new("/dependencies/source").unwrap(),
        1,
        2,
    );
    dependency.origins = vec![
        EndpointOrigin::PolicyLocal {
            path: PolicyDependencyPath::new("/dependencies/first").unwrap(),
        },
        EndpointOrigin::PolicyLocal {
            path: PolicyDependencyPath::new("/dependencies/second").unwrap(),
        },
    ];
    let ResolvedEndpointIdentity::Local {
        policy_id,
        entry_id,
    } = dependency.identity()
    else {
        unreachable!()
    };
    assert_eq!(
        dependency.identity().retained_size(),
        size_of::<ResolvedEndpointIdentity>()
            + retained_extra(policy_id)
            + retained_extra(entry_id)
    );
    assert_eq!(
        dependency.model().retained_size(),
        size_of::<ResolvedEndpointModel>()
            + 128
            + retained_extra(&dependency.model().categories)
            + retained_extra(&dependency.model().binding)
            + retained_extra(&dependency.model().taint)
            + retained_extra(&dependency.model().supersedes)
    );
    let origins_extra =
        retained_vec_size_from_parts(dependency.origins(), dependency.origins_capacity())
            - size_of::<Vec<EndpointOrigin>>();
    assert!(origins_extra > 0);
    assert_eq!(
        dependency.retained_size(),
        size_of::<ResolvedEndpointDependency>()
            + retained_extra(dependency.identity())
            + retained_extra(dependency.selector_path())
            + retained_extra(dependency.model())
            + origins_extra
    );

    let entry = ResolvedEndpointManifestEntry::from(&dependency);
    assert_eq!(
        entry.retained_size(),
        size_of::<ResolvedEndpointManifestEntry>() + retained_extra(&entry.identity)
    );
    let manifest = ResolvedMatchDirectoryManifest::try_new(
        PolicyDependencyPath::new("/dependencies/directory").unwrap(),
        WorkspaceRelativePath::new("policies/endpoints").unwrap(),
        crate::definition::DirectoryScope::Recursive,
        Some(EndpointRole::Source),
        CategoryPredicate::Any {
            categories: Vec::new(),
        },
        vec![entry],
    )
    .unwrap();
    let selected_extra =
        retained_vec_size_from_parts(manifest.selected(), manifest.selected_capacity())
            - size_of::<Vec<ResolvedEndpointManifestEntry>>();
    assert!(selected_extra > 0);
    assert_eq!(
        manifest.retained_size(),
        size_of::<ResolvedMatchDirectoryManifest>()
            + retained_extra(manifest.path())
            + retained_extra(manifest.directory())
            + retained_extra(manifest.categories())
            + selected_extra
    );
}

#[test]
fn catalog_and_endpoint_set_identities_charge_nested_storage() {
    use crate::definition::TaintCatalogHash;
    use crate::identity::EndpointSetSemanticHash;
    use crate::resolved::{PolicyDependencyPath, ResolvedEndpointSetDependency};

    let catalog = ResolvedCatalogIdentity::try_new(
        PolicyId::new("test.catalog").unwrap(),
        1,
        TaintCatalogHash::from_bytes([1; 32]),
    )
    .unwrap();
    let identity = ResolvedEndpointIdentity::Catalog {
        catalog,
        entry_id: "entry".parse().unwrap(),
    };
    let ResolvedEndpointIdentity::Catalog { catalog, entry_id } = &identity else {
        unreachable!()
    };
    assert_eq!(
        identity.retained_size(),
        size_of::<ResolvedEndpointIdentity>() + retained_extra(catalog) + retained_extra(entry_id)
    );

    let dependency = ResolvedEndpointSetDependency {
        source: PolicySourceIdentity::new("policies/endpoint-set.json"),
        semantic_hash: EndpointSetSemanticHash::from_bytes([2; 32]),
        entries: vec![
            PolicyDependencyPath::new("/entries/first").unwrap(),
            PolicyDependencyPath::new("/entries/second").unwrap(),
        ],
    };
    let entries_extra =
        retained_vec_size_from_parts(dependency.entries(), dependency.entries_capacity())
            - size_of::<Vec<PolicyDependencyPath>>();
    assert!(entries_extra > 0);
    assert_eq!(
        dependency.retained_size(),
        size_of::<ResolvedEndpointSetDependency>()
            + retained_extra(dependency.source())
            + entries_extra
    );
}

#[test]
fn precedence_edges_charge_both_identity_allocations() {
    use crate::definition::TypestateExpectationId;
    let dominant = ResolvedEndpointIdentity::Local {
        policy_id: PolicyId::new("test.dominant").unwrap(),
        entry_id: "source".parse().unwrap(),
    };
    let dominated = ResolvedEndpointIdentity::Local {
        policy_id: PolicyId::new("test.dominated").unwrap(),
        entry_id: "sink".parse().unwrap(),
    };
    let edge = ResolvedPrecedenceEdge::Endpoint {
        dominant,
        dominated,
    };
    let ResolvedPrecedenceEdge::Endpoint {
        dominant,
        dominated,
    } = &edge
    else {
        unreachable!()
    };
    assert_eq!(
        edge.retained_size(),
        size_of::<ResolvedPrecedenceEdge>() + retained_extra(dominant) + retained_extra(dominated)
    );

    let edge = ResolvedPrecedenceEdge::TypestateExpectation {
        dominant: TypestateExpectationId::new("closed-at-exit").unwrap(),
        dominated: TypestateExpectationId::new("released-at-exit").unwrap(),
    };
    let ResolvedPrecedenceEdge::TypestateExpectation {
        dominant,
        dominated,
    } = &edge
    else {
        unreachable!()
    };
    assert_eq!(
        edge.retained_size(),
        size_of::<ResolvedPrecedenceEdge>() + retained_extra(dominant) + retained_extra(dominated)
    );
}

#[test]
fn report_serializes_related_source_range_end() {
    let diagnostic = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "invalid policy",
        Some(PolicySourceIdentity::new("policy.rqlp")),
        None,
        vec![PolicySourceRelatedDiagnostic {
            source: PolicySourceIdentity::new("policy.rqlp"),
            range: 4..9,
            message: "related source".into(),
        }],
    )
    .unwrap();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    builder.register_primary_diagnostic(diagnostic).unwrap();
    let report = serde_json::to_value(builder.finish().unwrap()).unwrap();
    assert_eq!(
        report["diagnostics"][0]["related"][0]["byte_range"]["start"],
        4
    );
    assert_eq!(
        report["diagnostics"][0]["related"][0]["byte_range"]["end"],
        9
    );
}

#[test]
fn report_diagnostic_text_obeys_exact_byte_limit_and_safe_characters() {
    let diagnostic = |message: String| {
        PolicyReportDiagnostic::try_new(
            PolicyReportDiagnosticCode::PolicyLoadFailed,
            PolicyDiagnosticSeverity::Error,
            message,
            None,
            None,
            Vec::new(),
        )
    };
    assert!(diagnostic("a".repeat(MAX_REPORT_TEXT_BYTES)).is_ok());
    assert!(matches!(
        diagnostic("a".repeat(MAX_REPORT_TEXT_BYTES + 1)),
        Err(PolicyReportValueError::TextTooLong {
            field: "report diagnostic message",
            max_bytes: MAX_REPORT_TEXT_BYTES
        })
    ));
    assert!(matches!(
        diagnostic("safe prefix\nunsafe suffix".into()),
        Err(PolicyReportValueError::UnsafeText {
            field: "report diagnostic message"
        })
    ));
}
