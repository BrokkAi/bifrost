mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageHit};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ProjectFile, RustAnalyzer};
use common::InlineTestProject;
use std::collections::BTreeSet;
use std::sync::Arc;

fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn authoritative_hits(
    analyzer: &RustAnalyzer,
    target: &CodeUnit,
    files: HashSet<ProjectFile>,
) -> BTreeSet<UsageHit> {
    let provider = ExplicitCandidateProvider::new(Arc::new(files));
    match UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            100,
            100,
        )
        .result
    {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload.into_values().flatten().collect(),
        other => panic!("expected authoritative Rust usage success, got {other:#?}"),
    }
}

#[test]
fn associated_type_bindings_resolve_the_exact_imported_trait_alias() {
    let consumer = r#"
use crate::decoy_one::MakeWriter as FirstDecoy;
use crate::decoy_two::MakeWriter as SecondDecoy;
use crate::writer::MakeWriter as WriterFactory;

fn first<'a, A>()
where
    A: WriterFactory<'a, Writer = String>,
{}

fn second<'a, A>()
where
    A: WriterFactory<'a, Writer = Vec<u8>>,
{}

fn first_decoy<'a, A>()
where
    A: FirstDecoy<'a, Writer = String>,
{}

fn second_decoy<'a, A>()
where
    A: SecondDecoy<'a, Writer = String>,
{}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "mod consumer; mod decoy_one; mod decoy_two; mod writer;\n",
        )
        .file(
            "src/writer.rs",
            "pub trait MakeWriter<'a> { type Writer; }\n",
        )
        .file(
            "src/decoy_one.rs",
            "pub trait MakeWriter<'a> { type Writer; }\n",
        )
        .file(
            "src/decoy_two.rs",
            "pub trait MakeWriter<'a> { type Writer; }\n",
        )
        .file("src/consumer.rs", consumer)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "writer.MakeWriter.Writer");
    let found = authoritative_hits(
        &analyzer,
        &target,
        analyzer.get_analyzed_files().into_iter().collect(),
    );
    let expected: Vec<_> = consumer
        .match_indices("WriterFactory<'a, Writer")
        .map(|(start, _)| start + "WriterFactory<'a, ".len())
        .map(|start| (start, start + "Writer".len()))
        .collect();

    assert_eq!(2, expected.len());
    assert_eq!(
        2,
        found.len(),
        "same-named decoy traits must not match: {found:#?}"
    );
    assert!(expected.into_iter().all(|range| {
        found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == range)
    }));
}
