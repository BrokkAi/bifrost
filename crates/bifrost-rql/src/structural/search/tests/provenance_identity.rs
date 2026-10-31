use super::*;

// Detailed execution is the policy adapter boundary; terminal rows and the
// evidence consumed by policies must name the same authored receiver.
#[test]
fn receiver_rows_and_policy_evidence_agree_on_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("class Service { run() {} }\nexport function caller() { const service = new Service(); const alias = service; alias.run(); }\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    for terminal in [None, Some("receiver_outcome"), Some("receiver_evidence")] {
        let mut steps = vec![json!({"op": "points_to", "capture": "receiver"})];
        if let Some(terminal) = terminal {
            steps.push(json!({"op": terminal}));
        }
        let query = CodeQuery::from_json(&json!({
            "match": {"kind": "call", "callee": {"name": "run"}, "receiver": {"capture": "receiver"}},
            "steps": steps,
            "result_detail": "full"
        })).unwrap();
        let detailed = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );
        assert!(!detailed.result.results.is_empty(), "{detailed:?}");
        assert_eq!(detailed.result.results.len(), detailed.evidence.len());
        for (item, evidence) in detailed.result.results.iter().zip(&detailed.evidence) {
            for trace in &item.provenance {
                for step in &trace.steps {
                    if let CodeQueryResultRef::ReceiverEvidence { id, site_id, .. } = &step.result {
                        let CodeQueryResultValue::ReceiverEvidence { value } = &item.value else {
                            panic!("unexpected evidence witness: {item:?}");
                        };
                        assert_eq!(id, &value.id);
                        assert_eq!(site_id, &value.site_id);
                    }
                }
            }
            for reference in evidence
                .provenance
                .iter()
                .flat_map(|trace| &trace.steps)
                .map(|step| &step.result)
            {
                match &reference.key {
                    DetailedCodeQueryKey::ReceiverAnalysis { capture, .. } => {
                        assert_eq!(capture.as_deref(), Some("receiver"))
                    }
                    DetailedCodeQueryKey::ReceiverOutcome { id, .. } => {
                        assert_eq!(reference.domain, DetailedCodeQueryDomain::ReceiverOutcome);
                        let CodeQueryResultValue::ReceiverOutcome { value } = &item.value else {
                            panic!("{item:?}")
                        };
                        assert_eq!(id, &value.id);
                    }
                    DetailedCodeQueryKey::ReceiverEvidence { id, .. } => {
                        let CodeQueryResultValue::ReceiverEvidence { value } = &item.value else {
                            panic!("{item:?}")
                        };
                        assert_eq!(id, &value.id);
                    }
                    _ => {}
                }
            }
            match (&item.value, &evidence.key) {
                (
                    CodeQueryResultValue::ReceiverAnalysis { .. },
                    DetailedCodeQueryKey::ReceiverAnalysis { capture, .. },
                ) => {
                    assert_eq!(capture.as_deref(), Some("receiver"));
                }
                (
                    CodeQueryResultValue::ReceiverOutcome { value },
                    DetailedCodeQueryKey::ReceiverOutcome { id, site_id },
                ) => {
                    assert_eq!(evidence.domain, DetailedCodeQueryDomain::ReceiverOutcome);
                    assert_eq!(id, &value.id);
                    assert_eq!(site_id, &value.site_id);
                }
                (
                    CodeQueryResultValue::ReceiverEvidence { value },
                    DetailedCodeQueryKey::ReceiverEvidence { id, site_id },
                ) => {
                    assert_ne!(value.id, value.site_id);
                    assert_eq!(id, &value.id);
                    assert_eq!(site_id, &value.site_id);
                }
                other => panic!("row/evidence mismatch: {other:?}"),
            }
        }
    }
}

#[test]
fn declaration_policy_key_agrees_with_public_declaration_id() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("export function selected() { return 1; }\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "selected"},
        "steps": [{"op": "enclosing_decl"}],
        "result_detail": "full"
    }))
    .unwrap();
    let public = execute(&analyzer, &query);
    assert_eq!(public.results.len(), 1);
    let CodeQueryResultValue::Declaration { value } = &public.results[0].value else {
        panic!("{public:?}");
    };
    assert!(value.id.is_some());
    assert_eq!(value.fq_name, "selected");
    let detailed =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);
    assert_eq!(detailed.evidence.len(), 1);
    let DetailedCodeQueryKey::Declaration {
        analyzer_id,
        fq_name,
        ..
    } = &detailed.evidence[0].key
    else {
        panic!("{detailed:?}");
    };
    assert_eq!(fq_name, &value.fq_name);
    assert_eq!(analyzer_id, &value.id);
    let references: Vec<_> = detailed.evidence[0]
        .provenance
        .iter()
        .flat_map(|trace| &trace.steps)
        .filter_map(|step| match &step.result.key {
            DetailedCodeQueryKey::Declaration { analyzer_id, .. } => Some(analyzer_id),
            _ => None,
        })
        .collect();
    assert!(!references.is_empty());
    for analyzer_id in references {
        assert_eq!(analyzer_id, &value.id);
    }
}

#[test]
fn reference_policy_key_names_the_selected_declaration() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("export function selected() { return 1; }\nexport function caller() { return selected(); }\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let declaration_query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "selected"},
        "steps": [{"op": "enclosing_decl"}],
        "result_detail": "full"
    }))
    .unwrap();
    let public = execute(&analyzer, &declaration_query);
    assert_eq!(public.results.len(), 1);
    let CodeQueryResultValue::Declaration { value } = &public.results[0].value else {
        panic!("{public:?}");
    };
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "selected"},
        "steps": [{"op": "enclosing_decl"}, {"op": "references_of"}],
        "result_detail": "full"
    }))
    .unwrap();
    let detailed =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);
    assert!(!detailed.evidence.is_empty(), "{detailed:?}");
    for evidence in &detailed.evidence {
        let DetailedCodeQueryKey::ReferenceSite {
            target_id,
            target_fq_name,
        } = &evidence.key
        else {
            panic!("{evidence:?}");
        };
        assert_eq!(target_id, &value.id);
        assert_eq!(target_fq_name, &value.fq_name);
        let references: Vec<_> = evidence
            .provenance
            .iter()
            .flat_map(|trace| &trace.steps)
            .filter_map(|step| match &step.result.key {
                DetailedCodeQueryKey::ReferenceSite { target_id, .. } => Some(target_id),
                _ => None,
            })
            .collect();
        assert!(!references.is_empty());
        for target_id in references {
            assert_eq!(target_id, &value.id);
        }
    }
}
