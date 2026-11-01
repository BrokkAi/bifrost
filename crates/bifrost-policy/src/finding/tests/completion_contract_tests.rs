use super::*;

fn checked_run(completion: PolicyRunCompletion) -> Result<PolicyRun, PolicyRunError> {
    let loaded = loaded_match_policy();
    PolicyRun::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        PolicyAnalysisType::Match,
        completion,
        Vec::new(),
        Vec::new(),
        false,
        PolicyWorkReport::default(),
        &PolicyBudget::default(),
    )
}

fn paths(count: usize) -> Vec<WorkspaceRelativePath> {
    (0..count)
        .map(|n| WorkspaceRelativePath::new(format!("src/{n:03}.rs")).unwrap())
        .collect()
}

#[test]
fn run_wide_cause_widens_a_file_scoped_completion() {
    let mut completion = PolicyRunCompletion::inconclusive_in(
        vec![PolicyIncompleteReason::PartialDiscovery],
        InconclusiveScope::of_files(&paths(1)),
    )
    .unwrap();
    assert!(completion.mark_inconclusive(PolicyIncompleteReason::BatchFindingLimit));
    let run = checked_run(completion).unwrap();
    assert_eq!(
        run.completion().inconclusive_scope(),
        Some(&InconclusiveScope::Run)
    );
    assert!(!run.completion().is_exhaustive());
}

#[test]
fn file_scope_reader_requires_a_canonical_bounded_set() {
    let exact = paths(MAX_INCONCLUSIVE_FILES);
    let scope = InconclusiveScope::of_files(&exact);
    assert!(
        matches!(&scope, InconclusiveScope::Files { truncated: false, files } if files.len() == MAX_INCONCLUSIVE_FILES)
    );
    let completion = |scope| PolicyRunCompletion::Inconclusive {
        reasons: vec![PolicyIncompleteReason::PartialDiscovery],
        scope,
    };
    assert!(checked_run(completion(scope)).is_ok());
    assert!(matches!(
        checked_run(completion(InconclusiveScope::Files {
            files: paths(MAX_INCONCLUSIVE_FILES + 1)
                .iter()
                .map(|p| p.as_str().to_owned())
                .collect(),
            truncated: false,
        })),
        Err(PolicyRunError::InvalidCompletion(
            CompletionReasonError::TooMany {
                max_items: MAX_INCONCLUSIVE_FILES
            }
        ))
    ));
    assert!(matches!(
        checked_run(completion(InconclusiveScope::Files {
            files: vec!["src/a.rs".into(), "src/a.rs".into()],
            truncated: false,
        })),
        Err(PolicyRunError::InvalidCompletion(
            CompletionReasonError::NonCanonical
        ))
    ));
}

#[test]
fn scope_overflow_stays_visible_across_aggregation() {
    let overflow = InconclusiveScope::of_files(&paths(MAX_INCONCLUSIVE_FILES + 1));
    assert!(matches!(
        &overflow,
        InconclusiveScope::Files {
            truncated: true,
            ..
        }
    ));
    // Reuse a retained path: a new 257th path would set truncation again and
    // hide whether the first operand's truncation survived the union.
    let extra = paths(1).pop().unwrap();
    let combined = overflow.union(InconclusiveScope::of_files(&[extra]));
    assert!(matches!(
        &combined,
        InconclusiveScope::Files {
            truncated: true,
            ..
        }
    ));
    let a = WorkspaceRelativePath::new("src/a.rs").unwrap();
    let b = WorkspaceRelativePath::new("src/b.rs").unwrap();
    let combined = InconclusiveScope::of_files(&[a]).union(InconclusiveScope::of_files(&[b]));
    let run = checked_run(PolicyRunCompletion::Inconclusive {
        reasons: vec![PolicyIncompleteReason::PartialDiscovery],
        scope: combined,
    })
    .unwrap();
    assert!(
        matches!(run.completion().inconclusive_scope(), Some(InconclusiveScope::Files { files, truncated: false }) if files == &["src/a.rs", "src/b.rs"])
    );
}

#[test]
fn unavailable_capability_limit_is_inclusive() {
    let completion = |count| PolicyRunCompletion::NotRun {
        unavailable_capabilities: (0..count)
            .map(|n| UnavailablePolicyCapability {
                label: format!("feature_{n:03}"),
                reason: "missing".into(),
            })
            .collect(),
        selected_by: PolicySelectionProvenance::ExplicitPolicyId,
    };
    assert!(checked_run(completion(MAX_CAPABILITIES)).is_ok());
    assert!(matches!(
        checked_run(completion(MAX_CAPABILITIES + 1)),
        Err(PolicyRunError::InvalidCompletion(
            CompletionReasonError::TooMany {
                max_items: MAX_CAPABILITIES
            }
        ))
    ));
}

#[test]
fn capability_identifiers_are_validated_on_run_load() {
    for capability in [
        PolicyCapability::QueryFeature {
            language: "rust".into(),
            feature: "feature name".into(),
        },
        PolicyCapability::QueryDomain {
            domain: "code".into(),
            capability: None,
            reason: "bad reason".into(),
        },
    ] {
        assert!(matches!(
            checked_run(PolicyRunCompletion::Unsupported { capability }),
            Err(PolicyRunError::InvalidCompletion(_))
        ));
    }
}
