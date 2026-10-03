//! R9.3 measurement harness: per-phase cost of one Rust blob's production.
//!
//! The lazy interior makes the first demand on a blob pay the Rust producer
//! plus `prepare_resolution_bundle`. This probe runs exactly those phases on
//! one file, over a size series cut at top-level item boundaries, so the
//! exponent of each phase is measured rather than guessed. It is ignored by
//! default and reads its inputs from the environment:
//!
//! * `BIFROST_P3_SOURCE`: absolute path to the Rust file to measure.
//! * `BIFROST_P3_DENOMS`: comma-separated size denominators, default `8,4,2,1`.
//! * `BIFROST_P3_REPEATS`: timed repetitions per size, default `1`.

use std::time::Instant;

use crate::CancellationToken;
use crate::analyzer::resolution::BindingFragmentId;
use crate::analyzer::store::resolution_prepare::{
    ResolutionInteriorPreparation, prepare_resolution_bundle_with_unit_keys,
};
use crate::analyzer::{CodeUnit, Language, ProjectFile};
use crate::hash::HashMap;

/// Prefixes of `source` cut at item boundaries, one per denominator.
///
/// The cut points come from tree-sitter nodes, not from scanning the text, so
/// every prefix is a compilation unit the producer can parse. A file whose top
/// level is one huge item (`tflite_generated.rs` is one module) has no useful
/// series at the root, so the cut container is the node with the most named
/// children along the spine of largest children, and the text after that
/// container's last child is kept as the suffix that closes it.
fn item_prefixes(source: &str, denominators: &[usize]) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("rust grammar");
    let tree = parser.parse(source, None).expect("parse probe source");
    let mut container = tree.root_node();
    let mut node = tree.root_node();
    loop {
        let mut cursor = node.walk();
        if node.named_child_count() > container.named_child_count() {
            container = node;
        }
        let Some(largest) = node
            .named_children(&mut cursor)
            .max_by_key(|child| child.end_byte() - child.start_byte())
        else {
            break;
        };
        node = largest;
    }
    let mut cursor = container.walk();
    let ends = container
        .named_children(&mut cursor)
        .map(|item| item.end_byte())
        .collect::<Vec<_>>();
    assert!(!ends.is_empty(), "probe source has items to cut on");
    let suffix = &source[*ends.last().expect("cut container has items")..];
    denominators
        .iter()
        .map(|&denominator| {
            assert!(denominator > 0, "probe denominators are positive");
            let items = ends.len().div_ceil(denominator).max(1);
            format!("{}{suffix}", &source[..ends[items - 1]])
        })
        .collect()
}

#[test]
#[ignore = "R9.3 measurement harness; set BIFROST_P3_SOURCE"]
fn rust_blob_production_cost_series() {
    let path = std::path::PathBuf::from(
        std::env::var_os("BIFROST_P3_SOURCE").expect("set BIFROST_P3_SOURCE to a Rust file"),
    );
    let denominators = std::env::var("BIFROST_P3_DENOMS")
        .unwrap_or_else(|_| "8,4,2,1".to_owned())
        .split(',')
        .map(|value| value.trim().parse::<usize>().expect("probe denominator"))
        .collect::<Vec<_>>();
    let repeats = std::env::var("BIFROST_P3_REPEATS")
        .map(|value| value.trim().parse::<usize>().expect("probe repeats"))
        .unwrap_or(1);
    let whole = std::fs::read_to_string(&path).expect("read probe source");
    let root = tempfile::tempdir().expect("probe project root");
    let relative = std::path::Path::new("src/probe.rs");

    eprintln!(
        "[p3] file={} bytes={} lines={}",
        path.display(),
        whole.len(),
        whole.lines().count()
    );
    for prefix in item_prefixes(&whole, &denominators) {
        let source = prefix.as_str();
        let length = source.len();
        for repeat in 0..repeats {
            let file = ProjectFile::new(root.path().to_path_buf(), relative);
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .expect("rust grammar");

            let start = Instant::now();
            let tree = parser.parse(source, None).expect("parse probe prefix");
            let parse_ms = start.elapsed().as_secs_f64() * 1000.0;

            let start = Instant::now();
            let mut parsed =
                brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
            let producer_ms = start.elapsed().as_secs_f64() * 1000.0;
            parsed.add_file_scope(&file, source);

            let facts = &parsed.resolution_facts;
            let fact_counts = [
                ("names", facts.names.len()),
                ("scopes", facts.scopes.len()),
                ("sites", facts.sites.len()),
                ("identifiers", facts.identifiers.len()),
                ("binders", facts.binders.len()),
                ("type_slots", facts.type_slots.len()),
                ("type_transfers", facts.type_transfers.len()),
                ("calls", facts.calls.len()),
                ("call_arguments", facts.call_arguments.len()),
                ("member_owners", facts.member_owners.len()),
                ("gaps", facts.gaps.len()),
            ];

            let unit_keys = parsed
                .declarations()
                .iter()
                .enumerate()
                .map(|(index, unit)| {
                    (
                        unit.clone(),
                        i64::try_from(index).expect("probe unit count fits i64"),
                    )
                })
                .collect::<HashMap<CodeUnit, i64>>();

            let start = Instant::now();
            let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                BindingFragmentId::for_test(b"digest-7"),
                crate::analyzer::resolution::test_shared_names(),
                Language::Rust,
                &parsed.resolution_facts,
            );
            let lowering_ms = start.elapsed().as_secs_f64() * 1000.0;

            let cancellation = CancellationToken::default();
            let start = Instant::now();
            let prepared =
                prepare_resolution_bundle_with_unit_keys(&lowered, Some(&unit_keys), &cancellation);
            let prepare_ms = start.elapsed().as_secs_f64() * 1000.0;
            let ResolutionInteriorPreparation::Prepared(bundle) = prepared else {
                panic!("uncancelled probe preparation must finish")
            };

            let catalog = lowered.identities();
            let catalog_counts = format!(
                "catalog_semantics={} catalog_nodes={} catalog_paths={} \
                 catalog_stack_variables={} catalog_lookup_recipes={}",
                catalog.semantics().len(),
                catalog.nodes().len(),
                catalog.paths().len(),
                catalog.stack_variables().len(),
                catalog.lookup_recipes().len(),
            );
            let counts = fact_counts
                .iter()
                .map(|(label, count)| format!("{label}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            eprintln!(
                "[p3] bytes={length} repeat={repeat} parse_ms={parse_ms:.1} \
                 producer_ms={producer_ms:.1} lowering_ms={lowering_ms:.1} \
                 prepare_ms={prepare_ms:.1} declarations={} rows={} payload_bytes={} \
                 {catalog_counts} {counts}",
                parsed.declarations().len(),
                bundle.logical_rows(),
                bundle.payload_bytes(),
            );
        }
    }
}
