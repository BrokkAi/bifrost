use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::read_ledger::{
    LookupKind, LookupQuestion, ReadKey, ReadLedger,
};
use brokk_bifrost_analysis::analyzer::read_verification::{
    ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers, replay_lookup,
    verify_read_set,
};
use brokk_bifrost_analysis::analyzer::usages::{
    ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageQueryCompletion, find_usages,
    query_usages, reusable_usage_answer_digest, usage_answer_digest,
};
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};
use brokk_bifrost_core::analyzer::usages::model::{UsageHitKind, UsageProof, UsageProofAuthority};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_test_macros::hardwon;
use std::sync::Arc;

#[test]
#[hardwon("#11442: a narrow replay memo fill hid a wider fresh usage answer")]
fn usage_answer_replay_memo_preserves_limits_and_full_publication() {
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/census\n\ngo 1.23\n")
        .file("a.go", "package census\nfunc Target() {}\n")
        .file("b.go", "package census\nfunc Reader() { Target() }\n")
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let target = analyzer
        .get_declarations(&fixture.file("a.go"))
        .into_iter()
        .find(|unit| unit.identifier() == "Target")
        .expect("target");
    let wide = LookupReplayLimits::default();
    let narrow = LookupReplayLimits {
        max_usage_files: 0,
        ..wide
    };
    let question = LookupQuestion::declaration(&target);
    let mut memo = LookupMemo::new();
    assert!(
        memo.answer(
            &workspace,
            LookupKind::Usages,
            &question,
            narrow,
            &NoSummaryAnswers
        )
        .is_none()
    );
    assert!(
        memo.is_empty(),
        "a refused query must not fill the replay memo"
    );
    let narrow_query = UsageFinder::new().query(analyzer, std::slice::from_ref(&target), 0, 1000);
    let narrow_digest = usage_answer_digest(&narrow_query, &target);
    let wide_hit = memo
        .answer(
            &workspace,
            LookupKind::Usages,
            &question,
            wide,
            &NoSummaryAnswers,
        )
        .expect("wide answer");
    let wide_fill = replay_lookup(
        &workspace,
        LookupKind::Usages,
        &question,
        wide,
        &NoSummaryAnswers,
    )
    .expect("fresh wide answer");
    assert_ne!(narrow_digest, wide_hit);
    assert_eq!(wide_hit, wide_fill);
    let key = ReadKey::lookup(LookupKind::Usages, question, narrow_digest);
    let inputs = HeadInputs {
        models: wide_fill,
        policy_semantic_hash: wide_fill,
        policy_source: wide_fill,
        configuration: wide_fill,
        epoch: wide_fill,
    };
    let changed = ChangedFacts::between(&workspace, &workspace);
    for memo in [&mut memo, &mut LookupMemo::new()] {
        assert!(
            !verify_read_set(
                &workspace,
                &changed,
                &inputs,
                std::slice::from_ref(&key),
                wide,
                &NoSummaryAnswers,
                memo
            )
            .is_unchanged()
        );
    }
    // The key still binds every limit even for other replay funnels that can
    // return a digest for a bounded answer.
    let narrow_callers = LookupReplayLimits {
        call_relations:
            brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
                max_files: 0,
                ..wide.call_relations
            },
        ..wide
    };
    let question = LookupQuestion::declaration(&target);
    let narrow_callers_digest = memo.answer(
        &workspace,
        LookupKind::Callers,
        &question,
        narrow_callers,
        &NoSummaryAnswers,
    );
    let wide_callers_hit = memo.answer(
        &workspace,
        LookupKind::Callers,
        &question,
        wide,
        &NoSummaryAnswers,
    );
    assert_ne!(narrow_callers_digest, wide_callers_hit);
    assert_eq!(
        wide_callers_hit,
        replay_lookup(
            &workspace,
            LookupKind::Callers,
            &question,
            wide,
            &NoSummaryAnswers
        )
    );
    let ledger = Arc::new(ReadLedger::new());
    let query = {
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
        query_usages(
            analyzer,
            std::slice::from_ref(&target),
            wide.max_usage_files,
            wide.max_usages,
        )
    };
    assert!(query.has_complete_coverage());
    assert_eq!(usage_answer_digest(&query, &target), wide_fill);
    assert!(ledger.keys().iter().any(|key| matches!(key, ReadKey::Lookup { kind: LookupKind::Usages, digest, .. } if *digest == wide_fill)));
}

#[test]
#[hardwon(
    "#11442: usage v1 conflated cancelled emptiness and convenience results hid cancellation"
)]
fn usage_answer_digest_distinguishes_coverage_and_proof_tiers() {
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/census\n\ngo 1.23\n")
        .file(
            "a.go",
            "package census\nfunc Target() {}\nfunc Unused() {}\n",
        )
        .file("b.go", "package census\nfunc Reader() { Target() }\n")
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let declarations = analyzer.get_declarations(&fixture.file("a.go"));
    let target = declarations
        .iter()
        .find(|unit| unit.identifier() == "Target")
        .expect("target");
    let unused = declarations
        .iter()
        .find(|unit| unit.identifier() == "Unused")
        .expect("unused");
    let token = CancellationToken::default();
    token.cancel();
    let cancelled = UsageFinder::new().with_cancellation(token.clone()).query(
        analyzer,
        std::slice::from_ref(unused),
        1000,
        1000,
    );
    let complete = UsageFinder::new().query(analyzer, std::slice::from_ref(unused), 1000, 1000);
    {
        let _scope = AnalyzerQueryScope::with_cancellation(analyzer, &token);
        for result in [
            find_usages(analyzer, std::slice::from_ref(unused)),
            UsageFinder::new()
                .with_cancellation(token.clone())
                .find_usages_default(analyzer, std::slice::from_ref(unused)),
        ] {
            assert!(
                matches!(result, FuzzyResult::Failure { reason_kind, .. } if reason_kind == "cancelled")
            );
        }
    }
    assert_eq!(cancelled.completion, UsageQueryCompletion::Cancelled);
    assert!(reusable_usage_answer_digest(&cancelled, unused).is_none());
    assert!(complete.has_complete_coverage());
    assert!(cancelled.result.all_hits_including_imports().is_empty());
    assert!(complete.result.all_hits_including_imports().is_empty());
    assert_ne!(
        usage_answer_digest(&cancelled, unused),
        usage_answer_digest(&complete, unused)
    );
    let provider =
        ExplicitCandidateProvider::new(Arc::new([fixture.file("b.go")].into_iter().collect()));
    let truncated = UsageFinder::new().query_with_provider(
        analyzer,
        std::slice::from_ref(unused),
        Some(&provider),
        0,
        1000,
    );
    let complete = UsageFinder::new().query_with_provider(
        analyzer,
        std::slice::from_ref(unused),
        Some(&provider),
        1000,
        1000,
    );
    assert_eq!(
        truncated.completion,
        UsageQueryCompletion::CandidateFilesBudgetExhausted
    );
    assert!(reusable_usage_answer_digest(&truncated, unused).is_none());
    assert!(truncated.result.all_hits_including_imports().is_empty());
    assert_ne!(
        usage_answer_digest(&truncated, unused),
        usage_answer_digest(&complete, unused)
    );

    let source_limited = UsageFinder::new().query_with_provider_and_source_budget(
        analyzer,
        std::slice::from_ref(unused),
        Some(&provider),
        1000,
        1000,
        Some(0),
    );
    assert_eq!(
        source_limited.completion,
        UsageQueryCompletion::SourceBytesBudgetExhausted
    );
    assert!(reusable_usage_answer_digest(&source_limited, unused).is_none());
    assert_ne!(
        usage_answer_digest(&source_limited, unused),
        usage_answer_digest(&complete, unused)
    );

    let mut query = UsageFinder::new().query(analyzer, std::slice::from_ref(target), 1000, 1000);
    let original = usage_answer_digest(&query, target);
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = &query.result
    else {
        panic!("expected success")
    };
    let hit = hits_by_overload[target].first().expect("reader").clone();
    let mut shifted = hit.clone();
    shifted.start_offset += 23;
    shifted.end_offset += 23;
    shifted.line += 1;
    shifted.snippet = format!("// padding\n{}", shifted.snippet);
    query.result = FuzzyResult::success(target.clone(), [shifted].into_iter().collect());
    assert_eq!(original, usage_answer_digest(&query, target));
    for edited in [
        hit.clone().with_reason_kind("unresolved_receiver"),
        hit.clone().with_reference_kind(
            brokk_bifrost_core::analyzer::usages::model::ReferenceKind::FieldWrite,
        ),
        {
            let mut hit = hit.clone();
            hit.kind = UsageHitKind::Import;
            hit
        },
        {
            let mut hit = hit.clone();
            hit.proof = UsageProof::Unproven;
            hit
        },
    ] {
        query.result = FuzzyResult::success(target.clone(), [edited].into_iter().collect());
        assert_ne!(original, usage_answer_digest(&query, target));
    }
    query.result = FuzzyResult::success_with_unproven(
        target.clone(),
        [hit.clone()].into_iter().collect(),
        [hit].into_iter().collect(),
    );
    let unproven = usage_answer_digest(&query, target);
    assert_ne!(original, unproven);
    let FuzzyResult::Success {
        unproven_total_by_overload,
        ..
    } = &mut query.result
    else {
        unreachable!()
    };
    *unproven_total_by_overload
        .get_mut(target)
        .expect("unproven count") += 1;
    assert_ne!(unproven, usage_answer_digest(&query, target));
    assert!(
        reusable_usage_answer_digest(&query, target).is_none(),
        "omitted unproven evidence is a limit cut"
    );
    let native = usage_answer_digest(&query, target);
    assert_eq!(query.proof_authority, UsageProofAuthority::Native);
    query.proof_authority = UsageProofAuthority::Legacy;
    assert_ne!(native, usage_answer_digest(&query, target));
}

#[test]
#[hardwon("#11443: truncated Go package-variable census hid a write")]
fn go_package_function_value_refuses_a_write_outside_candidate_budget() {
    use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;
    use brokk_bifrost_go_analysis::analyzer::go::GoSupport;
    let declaration = "package census\nvar F = func() {}\nfunc Caller() { F() }\n";
    let mut fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/census\n\ngo 1.23\n")
        .file("a.go", declaration);
    for index in 0..1001 {
        fixture = fixture.file(
            format!("f{index:04}.go"),
            format!("package census\nfunc Local{index}() {{ F := 1; _ = F }}\n"),
        );
    }
    let fixture = fixture
        .file(
            "zzz_writer.go",
            "package census\nfunc Write() { F = func() {} }\n",
        )
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let variable = analyzer
        .get_declarations(&fixture.file("a.go"))
        .into_iter()
        .find(|unit| unit.identifier() == "F")
        .expect("package variable");
    let bounded = UsageFinder::new().query(analyzer, std::slice::from_ref(&variable), 1000, 1000);
    assert_eq!(
        bounded.completion,
        UsageQueryCompletion::CandidateFilesBudgetExhausted
    );
    assert!(
        !bounded
            .candidate_files
            .contains(&fixture.file("zzz_writer.go")),
        "fixture must omit the write"
    );
    assert!(
        matches!(bounded.result, FuzzyResult::Success { .. }),
        "the old result-only proof saw Success"
    );
    // The old result-only validator saw only the declaring name and a
    // proven direct call: no unproven site or retained write already refused it.
    // These byte ranges name the fixed fixture's F declaration and F() callee.
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        unproven_total_by_overload,
    } = &bounded.result
    else {
        unreachable!()
    };
    assert_eq!(
        unproven_total_by_overload
            .get(&variable)
            .copied()
            .unwrap_or_default(),
        0
    );
    assert!(
        unproven_by_overload
            .get(&variable)
            .is_none_or(|hits| hits.is_empty())
    );
    let hits = hits_by_overload
        .get(&variable)
        .expect("retained direct call");
    assert!(
        hits.iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == (49, 50))
    );
    assert!(
        hits.iter().all(|hit| hit.file == fixture.file("a.go")
            && ((hit.start_offset, hit.end_offset) == (19, 20)
                || ((hit.start_offset, hit.end_offset) == (49, 50)
                    && hit.kind
                        == brokk_bifrost_core::analyzer::usages::model::UsageHitKind::Reference))),
        "unexpected bounded evidence: {hits:?}"
    );
    let proof = GoSupport
        .stable_package_function_value_proof(analyzer, &variable, declaration)
        .expect("package var proof applies");
    let reason = proof.expect_err("incomplete census must not certify no writes");
    assert!(reason.contains("incomplete coverage"), "{reason}");
    let complete = UsageFinder::new().query(analyzer, std::slice::from_ref(&variable), 2000, 2000);
    assert!(complete.has_complete_coverage());
    assert!(
        complete
            .result
            .all_hits_including_imports()
            .iter()
            .any(|hit| hit.file == fixture.file("zzz_writer.go")),
        "complete census sees the assignment"
    );
}

#[test]
#[hardwon("#11442: group coverage inventory cannot be replayed as a single-overload answer")]
fn usage_answer_group_fill_replays_per_overload_and_ignores_irrelevant_candidates() {
    let build = |extra: Option<&str>| {
        let mut project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/census\n\ngo 1.23\n")
            .file(
                "a.go",
                "package census\nfunc First() {}\nfunc Second() {}\n",
            )
            .file("b.go", "package census\nfunc ReaderFirst() { First() }\n")
            .file("c.go", "package census\nfunc ReaderSecond() { Second() }\n");
        if let Some(extra) = extra {
            project = project.file("d.go", extra);
        }
        project.build()
    };
    let fixture = build(None);
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let targets = analyzer
        .get_declarations(&fixture.file("a.go"))
        .into_iter()
        .filter(|unit| matches!(unit.identifier(), "First" | "Second"))
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    let ledger = Arc::new(ReadLedger::new());
    let group = {
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
        query_usages(analyzer, &targets, 1000, 1000)
    };
    let reads = ledger
        .keys()
        .into_iter()
        .filter(|key| {
            matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::Usages,
                    ..
                }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(reads.len(), 2);
    for target in &targets {
        assert_eq!(
            reusable_usage_answer_digest(&group, target),
            replay_lookup(
                &workspace,
                LookupKind::Usages,
                &LookupQuestion::declaration(target),
                LookupReplayLimits::default(),
                &NoSummaryAnswers
            )
        );
    }
    let irrelevant = build(Some("package census\nfunc Unrelated() {}\n"));
    let irrelevant_workspace = irrelevant.workspace_analyzer(AnalyzerConfig::default());
    let added_hit = build(Some("package census\nfunc AddedReader() { First() }\n"));
    let added_hit_workspace = added_hit.workspace_analyzer(AnalyzerConfig::default());
    let digest = usage_answer_digest(&group, &targets[0]);
    let inputs = HeadInputs {
        models: digest,
        policy_semantic_hash: digest,
        policy_source: digest,
        configuration: digest,
        epoch: digest,
    };
    for (head, unchanged) in [(&irrelevant_workspace, true), (&added_hit_workspace, false)] {
        let changed = ChangedFacts::between(&workspace, head);
        assert_eq!(
            verify_read_set(
                head,
                &changed,
                &inputs,
                &reads,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new()
            )
            .is_unchanged(),
            unchanged
        );
    }
    let refused_ledger = Arc::new(ReadLedger::new());
    let refused = {
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&refused_ledger));
        query_usages(analyzer, &targets, 0, 1000)
    };
    assert!(
        targets
            .iter()
            .all(|target| refused.complete_answer(target).is_none())
    );
    assert!(refused_ledger.reuse_refused());
    assert!(refused_ledger.publishable_keys().is_none());
    assert!(!refused_ledger.keys().iter().any(|key| matches!(
        key,
        ReadKey::Lookup {
            kind: LookupKind::Usages,
            ..
        }
    )));
}

#[test]
#[hardwon("#11442: ranked usage answers must reject a target change within the same file")]
fn usage_answer_ranked_sites_replay_prefix_edits_and_reject_target_changes() {
    let source = "package census\nfunc Target() {}\nfunc Other() {}\nfunc Reader() { Target() }\n";
    let build = |source: &str| {
        InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/census\n\ngo 1.23\n")
            .file("a.go", source)
            .build()
    };
    let base = build(source);
    let workspace = base.workspace_analyzer(AnalyzerConfig::default());
    let target = workspace
        .analyzer()
        .get_declarations(&base.file("a.go"))
        .into_iter()
        .find(|unit| unit.identifier() == "Target")
        .unwrap();
    let ledger = Arc::new(ReadLedger::new());
    let answer = {
        let _scope =
            AnalyzerQueryScope::with_read_ledger(workspace.analyzer(), Arc::clone(&ledger));
        query_usages(workspace.analyzer(), &[target], 1000, 1000)
    };
    assert!(answer.has_complete_coverage());
    let keys = ledger.keys();
    let semantic = keys
        .iter()
        .filter(|key| {
            matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::Usages,
                    ..
                }
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(semantic.len(), 1);
    assert!(
        keys.iter().any(
            |key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "a.go")
        )
    );
    for (source, unchanged) in [
        (
            format!("// padding before every declaration\n{source}"),
            true,
        ),
        (
            source.replace("Reader() { Target()", "Reader() { Other()"),
            false,
        ),
    ] {
        let head = build(&source);
        let head = head.workspace_analyzer(AnalyzerConfig::default());
        let changed = ChangedFacts::between(&workspace, &head);
        let inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
        let verify = |reads: &[ReadKey]| {
            verify_read_set(
                &head,
                &changed,
                &inputs,
                reads,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
            .is_unchanged()
        };
        assert_eq!(verify(&semantic), unchanged);
        assert!(
            !verify(&keys),
            "published coordinates depend on file content"
        );
    }
}

#[test]
#[hardwon("#11442: unproven usage coordinates need file reads just like proven coordinates")]
fn usage_publication_records_unproven_site_positions() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("defs.py", "class Service:\n    def update(self): pass\nclass Other:\n    def update(self): pass\n")
        .file("proven.py", "from defs import Service\ndef caller():\n    Service().update()\n")
        .file("unknown.py", "def caller(receiver):\n    receiver.update()\n")
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let target = analyzer
        .get_definitions("defs.Service.update")
        .into_iter()
        .next()
        .unwrap();
    let ledger = Arc::new(ReadLedger::new());
    let query = {
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
        query_usages(analyzer, std::slice::from_ref(&target), 1000, 1000)
    };
    let (hits, unproven) = match &query.result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        }
        | FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            ..
        } => (hits_by_overload, unproven_by_overload),
        other => panic!("expected usage evidence: {other:?}"),
    };
    assert!(
        hits.get(&target).is_some_and(|hits| !hits.is_empty()),
        "{:?}",
        query.result
    );
    let unknown = unproven.get(&target).expect("unproven candidates");
    assert!(
        unknown
            .iter()
            .any(|hit| hit.file == fixture.file("unknown.py")),
        "{:?}",
        query.result
    );
    let keys = ledger.keys();
    for hit in hits.values().chain(unproven.values()).flatten() {
        assert!(keys.iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == brokk_bifrost_analysis::path_utils::rel_path_string(&hit.file))), "missing file dependency for {hit:?}: {keys:?}");
    }
}
