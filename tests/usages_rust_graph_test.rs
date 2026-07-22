mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, UsageAnalyzer, UsageFinder, UsageHit, UsageHitKind,
};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, RustAnalyzer,
};
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

fn rust_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, RustAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Rust);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[test]
fn usage_finder_routes_seeded_public_rust_export_through_graph() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("expected Rust graph or fallback success");
    assert_eq!(1, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_import_hits_ignore_unrelated_aliased_use_path() {
    let consumer = r#"
use crate::target::Target;
use crate::other::Target as OtherTarget;

fn run(value: Target, other: OtherTarget) {}
"#;
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub mod target;\npub mod other;\npub mod consumer;\n",
        ),
        ("src/target.rs", "pub struct Target;\n"),
        ("src/other.rs", "pub struct Target;\n"),
        ("src/consumer.rs", consumer),
    ]);

    let target = definition(&analyzer, "target.Target");
    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);
    let editor_hits = result.all_hits_including_imports();
    let target_import_line = consumer[..consumer.find("use crate::target::Target").unwrap()]
        .matches('\n')
        .count()
        + 1;
    let other_import_line = consumer[..consumer.find("use crate::other::Target").unwrap()]
        .matches('\n')
        .count()
        + 1;

    assert!(
        editor_hits.iter().any(|hit| hit.line == target_import_line),
        "expected target import hit: {editor_hits:#?}"
    );
    assert!(
        editor_hits.iter().all(|hit| hit.line != other_import_line),
        "unrelated aliased import must not be reported as target hit: {editor_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_same_file_private_function_calls() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/searchtools.rs",
        r#"
fn summarize_symbol_targets() {}

pub fn get_summaries() {
    summarize_symbol_targets();
}
"#,
    )]);

    let target = definition(&analyzer, "searchtools.summarize_symbol_targets");
    let candidates = BTreeSet::new();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates.into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("expected same-file private function usage");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_same_file_exact_functions_survive_shadow_checks_in_and_outside_token_trees() {
    let source = r#"
macro_rules! evaluate { ($expression:expr) => { $expression }; }

fn exact_value(value: usize) -> usize {
    value
}

fn nested_calls(left: usize, right: usize) -> bool {
    exact_value(left) < exact_value(right)
}

fn token_tree_calls(left: usize, right: usize) -> bool {
    evaluate!(exact_value(left) < exact_value(right))
}

fn lexical_shadows(value: usize) -> usize {
    let exact_value = |value| value + 2;
    exact_value(value)
}

mod shadowed {
    fn exact_value(value: usize) -> usize { value + 1 }
    fn nested_call(value: usize) -> usize { exact_value(value) }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);

    let target_function = definition(&analyzer, "exact_value");
    let function_hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[target_function])
        .all_hits();
    let ordinary_first = source
        .find("exact_value(left)")
        .expect("first nested comparison call");
    let ordinary_second = source
        .find("exact_value(right)")
        .expect("second nested comparison call");
    let token_tree_start = source.find("evaluate!(").expect("token-tree call");
    let token_tree_first = token_tree_start
        + source[token_tree_start..]
            .find("exact_value(left)")
            .expect("first token-tree comparison call");
    let token_tree_second = token_tree_start
        + source[token_tree_start..]
            .find("exact_value(right)")
            .expect("second token-tree comparison call");
    assert_eq!(
        vec![
            ordinary_first,
            ordinary_second,
            token_tree_first,
            token_tree_second,
        ],
        function_hits
            .iter()
            .filter(|hit| hit.file == project.file("src/lib.rs"))
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "exact ordinary and token-tree calls must survive while lexical and item shadows stay excluded: {function_hits:#?}"
    );
}

#[test]
fn rust_bare_token_tree_nominals_require_one_structured_namespace_identity() {
    let consumer = r#"
use crate::defs::Ambiguous;
use crate::defs::UniqueType;
use crate::defs::unique_value;

macro_rules! declarations_and_bindings {
    ($UniqueType:ident) => {
        struct UniqueType;
        fn unique_value() {}
        let UniqueType = ();
        'UniqueType: loop { break 'UniqueType; }
        $UniqueType;
    };
}

macro_rules! references {
    () => {
        let _: Option<UniqueType> = None; // BARE_TYPE_BODY
        unique_value(); // BARE_VALUE_BODY
        let _: crate::defs::UniqueType; // QUALIFIED_TYPE_BODY
        let _: Option<Ambiguous> = None; // AMBIGUOUS_TYPE
        Ambiguous(); // AMBIGUOUS_VALUE
    };
}

macro_rules! consume_type { ($ty:ty) => {}; }
consume_type!(UniqueType); // BARE_TYPE_ARGUMENT
references!();
"#;
    let binary = r#"
struct UniqueType;
macro_rules! unrelated { () => { let _: Option<UniqueType> = None; }; }
unrelated!();
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"tokens\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub mod defs;\npub mod consumer;\n"),
        (
            "src/defs.rs",
            "pub struct UniqueType;\npub struct Ambiguous;\n#[allow(non_snake_case)] pub fn Ambiguous() {}\npub fn unique_value() {}\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", binary),
    ]);
    let candidates: HashSet<ProjectFile> = analyzer.get_analyzed_files().into_iter().collect();

    let unique_type = definition(&analyzer, "defs.UniqueType");
    let type_hits = authoritative_hits(&analyzer, &unique_type, candidates.clone());
    let body_type = consumer.find("Option<UniqueType>").expect("body type") + "Option<".len();
    let qualified_type = consumer
        .rfind("crate::defs::UniqueType")
        .expect("qualified macro-body type")
        + "crate::defs::".len();
    let argument_type = consumer
        .find("consume_type!(UniqueType)")
        .expect("macro type argument")
        + "consume_type!(".len();
    assert_eq!(
        vec![body_type, qualified_type, argument_type],
        type_hits
            .iter()
            .filter(|hit| {
                hit.file == project.file("src/consumer.rs") && hit.kind == UsageHitKind::Reference
            })
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "bare and qualified nominal references must be exact while declarations, bindings, labels, metavariables, and the binary target stay excluded: {type_hits:#?}"
    );
    assert!(
        type_hits
            .iter()
            .all(|hit| hit.file != project.file("src/main.rs")),
        "an unrelated Cargo target must not contribute token-tree hits: {type_hits:#?}"
    );

    let defs_module = analyzer
        .get_definitions("defs")
        .into_iter()
        .find(CodeUnit::is_module)
        .expect("defs module");
    let module_hits = authoritative_hits(&analyzer, &defs_module, candidates.clone());
    let qualified_module = consumer
        .rfind("crate::defs::UniqueType")
        .expect("qualified macro-body module")
        + "crate::".len();
    assert!(
        module_hits.iter().any(|hit| {
            hit.file == project.file("src/consumer.rs")
                && hit.kind == UsageHitKind::Reference
                && hit.start_offset == qualified_module
                && hit.end_offset == qualified_module + "defs".len()
        }),
        "qualified token-tree paths must preserve the exact module segment: {module_hits:#?}"
    );

    let unique_value = definition(&analyzer, "defs.unique_value");
    let value_hits = authoritative_hits(&analyzer, &unique_value, candidates.clone());
    let value_reference = consumer
        .find("unique_value(); // BARE_VALUE_BODY")
        .expect("body value");
    assert_eq!(
        vec![value_reference],
        value_hits
            .iter()
            .filter(|hit| {
                hit.file == project.file("src/consumer.rs") && hit.kind == UsageHitKind::Reference
            })
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "the function declaration token must not be reported as its usage: {value_hits:#?}"
    );

    let ambiguous = analyzer.get_definitions("defs.Ambiguous");
    let ambiguous_type = ambiguous
        .iter()
        .find(|definition| definition.is_class())
        .cloned()
        .expect("same-name type");
    let ambiguous_value = ambiguous
        .iter()
        .find(|definition| definition.is_function())
        .cloned()
        .expect("same-name value");
    let ambiguous_type_hits = authoritative_hits(&analyzer, &ambiguous_type, candidates.clone());
    assert!(
        ambiguous_type_hits.iter().all(|hit| {
            hit.file != project.file("src/consumer.rs") || hit.kind != UsageHitKind::Reference
        }),
        "raw token-tree syntax must fail closed for a type/value collision: {ambiguous_type_hits:#?}"
    );
    let ambiguous_value_hits = authoritative_hits(&analyzer, &ambiguous_value, candidates);
    assert!(
        ambiguous_value_hits.iter().all(|hit| {
            hit.file != project.file("src/consumer.rs") || hit.kind != UsageHitKind::Reference
        }),
        "raw token-tree syntax must fail closed for a value/type collision: {ambiguous_value_hits:#?}"
    );
}

#[test]
fn rust_bare_token_tree_values_use_exact_forward_module_identity() {
    let source = r#"
macro_rules! evaluate { ($expression:expr) => { $expression }; }

const EXACT: usize = 1;

struct Other;
impl Other {
    const EXACT: usize = 2;
}

fn module_reference() -> usize {
    evaluate!(EXACT) + evaluate!(EXACT | 8)
}

fn associated_decoy() -> usize {
    evaluate!(Other::EXACT)
}

fn lexical_decoy() -> usize {
    let EXACT = 3;
    evaluate!(EXACT)
}

fn local_item_decoy() -> usize {
    const EXACT: usize = 4;
    evaluate!(EXACT)
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);
    let target = definition(&analyzer, "_module_.EXACT");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[target])
        .all_hits();
    let expected = ["evaluate!(EXACT)", "evaluate!(EXACT | 8)"]
        .into_iter()
        .map(|expression| {
            source
                .find(expression)
                .expect("module token-tree reference")
                + "evaluate!(".len()
        })
        .collect::<Vec<_>>();
    let token_tree_offsets = source
        .match_indices("evaluate!(EXACT")
        .map(|(offset, _)| offset + "evaluate!(".len())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected,
        hits.iter()
            .filter(|hit| {
                hit.file == project.file("src/lib.rs") && hit.kind == UsageHitKind::Reference
            })
            .map(|hit| hit.start_offset)
            .filter(|offset| token_tree_offsets.contains(offset))
            .collect::<Vec<_>>(),
        "the module constant must resolve while associated, lexical, and local-item names remain exact decoys: {hits:#?}"
    );
}

#[test]
fn rust_bare_function_values_in_comma_separated_macro_arguments_remain_references() {
    let baseline = r#"
use criterion::{criterion_group, Criterion};

fn bench(_: &mut Criterion) {}
fn other(_: &mut Criterion) {}

criterion_group!(benches, bench); // EXACT_BENCH_VALUE
criterion_group!(others, other); // OTHER_VALUE_DECOY

fn lexical_decoy() {
    let bench = other;
    criterion_group!(local, bench); // LEXICAL_VALUE_DECOY
}
"#;
    let same_fqn_decoy = r#"
use criterion::{criterion_group, Criterion};

fn bench(_: &mut Criterion) {}
criterion_group!(benches, bench); // SAME_FQN_OTHER_TARGET
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"macro-args\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("src/lib.rs", "pub fn library() {}\n"),
        ("benches/baseline.rs", baseline),
        ("benches/enter_span.rs", same_fqn_decoy),
    ]);
    let file = project.file("benches/baseline.rs");
    let target = analyzer
        .get_definitions("benches.bench")
        .into_iter()
        .find(|candidate| candidate.source() == &file)
        .expect("baseline bench definition");
    let hits = rust_graph_hits_for_target(&analyzer, target);
    let expected = baseline
        .find("bench); // EXACT_BENCH_VALUE")
        .expect("exact comma-separated macro value");

    assert_eq!(
        vec![expected],
        hits.iter()
            .filter(|hit| hit.file == file && hit.kind == UsageHitKind::Reference)
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "the exact bare function value must survive comma-separated macro arguments while lexical and same-name item decoys remain excluded: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("benches/enter_span.rs")),
        "the independent same-FQN bench target must remain physically unrelated: {hits:#?}"
    );
}

#[test]
fn rust_bare_token_tree_roles_distinguish_casts_bindings_aliases_and_operators() {
    let consumer = r#"
use crate::defs::{x, CastType, Choice, Other, LEFT, MODULE_CONST, RIGHT};
use crate::defs::Choice::Variant;

macro_rules! capture { ($($tokens:tt)*) => {}; }
macro_rules! outer { ($($tokens:tt)*) => {}; }

fn witnesses(value: usize) {
    capture!(value as CastType); // CAST_TYPE_REFERENCE
    capture!(type CastType = Other); // TYPE_DECLARATION
    capture!(use crate::defs::Other as CastType); // IMPORT_ALIAS
    capture!(let CastType = value); // PATTERN_BINDING

    capture!(LEFT | RIGHT); // BITWISE_REFERENCES
    capture!(|LEFT, RIGHT| LEFT | RIGHT); // CLOSURE_BINDINGS
    outer!(inner!(|LEFT, RIGHT| LEFT | RIGHT)); // NESTED_CLOSURE_BINDINGS
    capture!(match value { x => x }); // MATCH_BINDING
    capture!(if let x = value { x }); // IF_LET_BINDING
    capture!(match value { Variant => 1, _ => 0 }); // UNIT_VARIANT_PATTERN
    capture!(if let Variant = value { 1 } else { 0 }); // IF_LET_VARIANT
    capture!(while let Variant = value {}); // WHILE_LET_VARIANT
    capture!(match value { MODULE_CONST => 1, _ => 0 }); // MODULE_CONST_PATTERN
    capture!(if let MODULE_CONST = value { 1 } else { 0 }); // IF_LET_CONST
    capture!(match value { Choice::ASSOCIATED => 1, _ => 0 }); // ASSOCIATED_CONST_PATTERN
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "pub mod defs;\npub mod consumer;\n"),
        (
            "src/defs.rs",
            "pub trait CastType {}\npub struct Other;\npub enum Choice { Variant }\nimpl Choice { pub const ASSOCIATED: usize = 3; }\npub const MODULE_CONST: usize = 4;\npub const LEFT: usize = 1;\npub const RIGHT: usize = 2;\npub fn x() {}\n",
        ),
        ("src/consumer.rs", consumer),
    ]);
    let file = project.file("src/consumer.rs");
    let candidates: HashSet<ProjectFile> = [file.clone()].into_iter().collect();

    let cast_type = definition(&analyzer, "defs.CastType");
    let cast_hits = authoritative_hits(&analyzer, &cast_type, candidates.clone());
    let cast_reference = consumer
        .find("CastType); // CAST_TYPE_REFERENCE")
        .expect("cast type reference");
    assert_eq!(
        vec![cast_reference],
        cast_hits
            .iter()
            .filter(|hit| hit.file == file && hit.kind == UsageHitKind::Reference)
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "a cast type must remain a type reference while declaration, alias, and pattern roles stay excluded: {cast_hits:#?}"
    );

    for (fqn, marker) in [
        ("defs._module_.LEFT", "LEFT | RIGHT); // BITWISE_REFERENCES"),
        ("defs._module_.RIGHT", "RIGHT); // BITWISE_REFERENCES"),
    ] {
        let target = definition(&analyzer, fqn);
        let hits = authoritative_hits(&analyzer, &target, candidates.clone());
        let expected = consumer.find(marker).expect("bitwise reference");
        assert_eq!(
            vec![expected],
            hits.iter()
                .filter(|hit| hit.file == file && hit.kind == UsageHitKind::Reference)
                .map(|hit| hit.start_offset)
                .collect::<Vec<_>>(),
            "bitwise operands must remain references while both direct and nested multi-parameter closure bindings stay excluded for {fqn}: {hits:#?}"
        );
    }

    let function = definition(&analyzer, "defs.x");
    let function_hits = authoritative_hits(&analyzer, &function, candidates);
    assert!(
        function_hits
            .iter()
            .all(|hit| hit.file != file || hit.kind != UsageHitKind::Reference),
        "a bare match-arm binding and its body uses must not become references to a same-named global function: {function_hits:#?}"
    );

    let variant = analyzer
        .exact_member(&project.file("src/defs.rs"), "Choice", "Variant", false)
        .expect("Choice::Variant definition");
    let variant_hits =
        authoritative_hits(&analyzer, &variant, [file.clone()].into_iter().collect());
    let variant_reference = consumer
        .find("Variant => 1")
        .expect("unit variant pattern reference");
    assert!(
        variant_hits.iter().any(|hit| {
            hit.file == file
                && hit.kind == UsageHitKind::Reference
                && hit.start_offset == variant_reference
        }),
        "a Pattern role may resolve only through the exact enum-variant member path: {variant_hits:#?}"
    );
    for marker in ["if let Variant", "while let Variant"] {
        let expected =
            consumer.find(marker).expect("variant let pattern") + marker.len() - "Variant".len();
        assert!(
            variant_hits
                .iter()
                .any(|hit| hit.file == file && hit.start_offset == expected),
            "{marker} must retain the exact imported enum variant identity: {variant_hits:#?}"
        );
    }

    let module_const = definition(&analyzer, "defs._module_.MODULE_CONST");
    let module_const_hits = authoritative_hits(
        &analyzer,
        &module_const,
        [file.clone()].into_iter().collect(),
    );
    for (marker, prefix) in [("MODULE_CONST =>", ""), ("if let MODULE_CONST", "if let ")] {
        let expected = consumer.find(marker).expect("module const pattern") + prefix.len();
        assert!(
            module_const_hits
                .iter()
                .any(|hit| hit.file == file && hit.start_offset == expected),
            "{marker} must resolve the exact imported module constant: {module_const_hits:#?}"
        );
    }

    let associated = analyzer
        .exact_member(&project.file("src/defs.rs"), "Choice", "ASSOCIATED", false)
        .expect("Choice::ASSOCIATED definition");
    let associated_hits =
        authoritative_hits(&analyzer, &associated, [file.clone()].into_iter().collect());
    let associated_reference = consumer
        .find("Choice::ASSOCIATED =>")
        .expect("associated const pattern")
        + "Choice::".len();
    assert!(
        associated_hits
            .iter()
            .any(|hit| hit.file == file && hit.start_offset == associated_reference),
        "a qualified associated const pattern must keep exact member identity: {associated_hits:#?}"
    );
}

#[test]
fn rust_tuple_and_unit_structs_have_exact_value_constructor_identities() {
    let definitions = r#"
pub struct Tuple(pub usize);
pub struct Unit;
pub struct Named { pub value: usize }
#[allow(non_snake_case)]
pub fn Named() -> usize { 0 }

pub fn local() {
    let _: Tuple = Tuple(0);
    let _: Unit = Unit;
    let _ = Named { value: 0 };
    let _ = Named();
}
"#;
    let consumer = r#"
use crate::definitions::{Named, Tuple, Unit};

pub fn imported() {
    let _: Tuple = Tuple(1);
    let _: Unit = Unit;
    let _ = Named { value: 1 };
    let _ = Named();
}

pub fn qualified() {
    let _ = crate::definitions::Tuple(2);
    let _ = crate::definitions::Unit;
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"constructors\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub mod definitions;\npub mod consumer;\n"),
        ("src/definitions.rs", definitions),
        ("src/consumer.rs", consumer),
        (
            "examples/decoy.rs",
            "struct Tuple(usize);\nstruct Unit;\nfn run() { let _ = Tuple(9); let _ = Unit; }\n",
        ),
    ]);
    let tuple = analyzer
        .get_definitions("definitions.Tuple")
        .into_iter()
        .find(CodeUnit::is_class)
        .expect("tuple struct definition");
    let unit = analyzer
        .get_definitions("definitions.Unit")
        .into_iter()
        .find(CodeUnit::is_class)
        .expect("unit struct definition");
    let named = analyzer
        .get_definitions("definitions.Named")
        .into_iter()
        .find(CodeUnit::is_class)
        .expect("named-field struct definition");

    let tuple_hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[tuple])
        .all_hits();
    let unit_hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[unit])
        .all_hits();
    let named_hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[named])
        .all_hits();

    let expected_tuple = [
        (
            project.file("src/definitions.rs"),
            definitions
                .find("Tuple(0)")
                .expect("local tuple constructor"),
        ),
        (
            project.file("src/consumer.rs"),
            consumer
                .find("Tuple(1)")
                .expect("imported tuple constructor"),
        ),
        (
            project.file("src/consumer.rs"),
            consumer
                .find("crate::definitions::Tuple(2)")
                .expect("qualified tuple constructor")
                + "crate::definitions::".len(),
        ),
    ];
    for (file, offset) in expected_tuple {
        assert!(
            tuple_hits
                .iter()
                .any(|hit| hit.file == file && hit.start_offset == offset),
            "missing exact tuple constructor at {file}:{offset}: {tuple_hits:#?}"
        );
    }

    let expected_unit = [
        (
            project.file("src/definitions.rs"),
            definitions.find("= Unit;").expect("local unit constructor") + 2,
        ),
        (
            project.file("src/consumer.rs"),
            consumer.find("= Unit;").expect("imported unit constructor") + 2,
        ),
        (
            project.file("src/consumer.rs"),
            consumer
                .find("crate::definitions::Unit;")
                .expect("qualified unit constructor")
                + "crate::definitions::".len(),
        ),
    ];
    for (file, offset) in expected_unit {
        assert!(
            unit_hits
                .iter()
                .any(|hit| hit.file == file && hit.start_offset == offset),
            "missing exact unit constructor at {file}:{offset}: {unit_hits:#?}"
        );
    }

    for (file, source) in [
        (project.file("src/definitions.rs"), definitions),
        (project.file("src/consumer.rs"), consumer),
    ] {
        let literal = source.find("Named { value").expect("named struct literal");
        let function = source.find("Named();").expect("same-name function call");
        assert!(
            named_hits
                .iter()
                .any(|hit| hit.file == file && hit.start_offset == literal),
            "named-field struct literals remain type references: {named_hits:#?}"
        );
        assert!(
            named_hits
                .iter()
                .all(|hit| hit.file != file || hit.start_offset != function),
            "the same-name value function must not become a struct constructor: {named_hits:#?}"
        );
    }
    assert!(
        tuple_hits
            .iter()
            .chain(unit_hits.iter())
            .all(|hit| hit.file != project.file("examples/decoy.rs")),
        "constructors from an independent Cargo example must remain unrelated"
    );
}

#[test]
fn rust_tuple_constructor_identities_respect_fields_and_non_exhaustive_boundaries() {
    let definitions = r#"
pub struct PrivateTuple(usize);
pub struct PublicTuple(pub usize);
#[non_exhaustive]
pub struct LocalNonExhaustive(pub usize);

fn local() {
    let _ = PrivateTuple(0); // PRIVATE_LOCAL
    let _ = PublicTuple(0); // PUBLIC_LOCAL
    let _ = LocalNonExhaustive(0); // NON_EXHAUSTIVE_LOCAL
}
"#;
    let sibling = r#"
use crate::definitions::{LocalNonExhaustive, PrivateTuple};
fn calls() {
    let _ = PrivateTuple(1); // PRIVATE_SIBLING_INVALID
    let _ = LocalNonExhaustive(1); // NON_EXHAUSTIVE_SAME_CRATE
}
"#;
    let external = r#"
use constructors::{LocalNonExhaustive, PublicTuple};
fn calls() {
    let _ = PublicTuple(2); // PUBLIC_EXTERNAL
    let _ = LocalNonExhaustive(2); // NON_EXHAUSTIVE_EXTERNAL_INVALID
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"constructors\", \"consumer\"]\nresolver = \"2\"\n",
        ),
        (
            "constructors/Cargo.toml",
            "[package]\nname = \"constructors\"\nversion = \"0.1.0\"\n",
        ),
        (
            "constructors/src/lib.rs",
            "pub mod definitions;\npub use definitions::{LocalNonExhaustive, PublicTuple};\nmod sibling;\n",
        ),
        ("constructors/src/definitions.rs", definitions),
        ("constructors/src/sibling.rs", sibling),
        (
            "consumer/Cargo.toml",
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nconstructors = { path = \"../constructors\" }\n",
        ),
        ("consumer/src/lib.rs", external),
    ]);
    let definitions_file = project.file("constructors/src/definitions.rs");
    let class = |name: &str| {
        analyzer
            .declarations(&definitions_file)
            .into_iter()
            .find(|unit| unit.is_class() && unit.identifier() == name)
            .unwrap_or_else(|| panic!("missing {name} class"))
    };
    let candidates: HashSet<ProjectFile> = analyzer.get_analyzed_files().into_iter().collect();
    let private_hits = authoritative_hits(&analyzer, &class("PrivateTuple"), candidates.clone());
    let public_hits = authoritative_hits(&analyzer, &class("PublicTuple"), candidates.clone());
    let non_exhaustive_hits =
        authoritative_hits(&analyzer, &class("LocalNonExhaustive"), candidates);

    let private_local = definitions.find("PrivateTuple(0)").expect("private local");
    assert!(
        private_hits
            .iter()
            .any(|hit| { hit.file == definitions_file && hit.start_offset == private_local })
    );
    assert!(
        private_hits.iter().all(|hit| {
            hit.file != project.file("constructors/src/sibling.rs")
                || hit.start_offset != sibling.find("PrivateTuple(1)").expect("private sibling")
        }),
        "a tuple field's private visibility must keep its constructor module-private: {private_hits:#?}"
    );

    let public_external = external.find("PublicTuple(2)").expect("public external");
    assert!(
        public_hits.iter().any(|hit| {
            hit.file == project.file("consumer/src/lib.rs") && hit.start_offset == public_external
        }),
        "a fully public tuple constructor must remain externally visible: {public_hits:#?}"
    );

    let same_crate = sibling
        .find("LocalNonExhaustive(1)")
        .expect("same-crate non-exhaustive");
    assert!(non_exhaustive_hits.iter().any(|hit| {
        hit.file == project.file("constructors/src/sibling.rs") && hit.start_offset == same_crate
    }));
    assert!(
        non_exhaustive_hits.iter().all(|hit| {
            hit.file != project.file("consumer/src/lib.rs")
                || hit.start_offset
                    != external
                        .find("LocalNonExhaustive(2)")
                        .expect("external non-exhaustive")
        }),
        "a non-exhaustive constructor must not escape its defining crate: {non_exhaustive_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_same_file_private_module_function_calls() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod agent;\n"),
        (
            "src/agent.rs",
            r#"
fn parse_setup_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_flag(value: &str) -> Option<bool> {
    parse_setup_bool(value)
}

fn parse_other(value: &str) -> Option<bool> {
    match parse_setup_bool(value) {
        Some(value) => Some(value),
        None => None,
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "agent.parse_setup_bool");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("expected same-file private module function usages");

    assert_eq!(
        2,
        hits.len(),
        "expected both same-file call sites: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_private_member_usages_without_export_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod tracker;\nmod consumer;\n"),
        (
            "src/tracker.rs",
            r#"
struct RequestTracker;

impl RequestTracker {
    fn run_request(&self) {}
}
"#,
        ),
        (
            "src/consumer.rs",
            r#"
use crate::tracker::RequestTracker;

fn drive(tracker: RequestTracker) {
    tracker.run_request();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/tracker.rs"),
        "RequestTracker",
        "run_request",
    );
    let candidates: HashSet<ProjectFile> = analyzer.get_analyzed_files().into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<BTreeSet<_>>(),
        other => panic!("expected private member usage success, got {other:#?}"),
    };

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/consumer.rs")
                && hit.snippet.contains("tracker.run_request")),
        "expected private member call in consumer.rs: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_imported_type_impl_target_usages_without_export_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "pub mod ast;\npub mod utils;\n"),
        ("src/ast.rs", "pub struct StorageField;\n"),
        ("src/utils/mod.rs", "pub mod language;\n"),
        (
            "src/utils/language.rs",
            r#"
use crate::ast::StorageField;

pub trait Format {
    fn format(&self);
}

impl Format for StorageField {
    fn format(&self) {}
}

pub fn render(field: StorageField) {
    field.format();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "ast.StorageField");
    assert_eq!(project.file("src/ast.rs"), *target.source());

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<BTreeSet<_>>(),
        other => panic!("expected imported type impl target usage success, got {other:#?}"),
    };

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/utils/language.rs")
                && hit.snippet.contains("StorageField")
        }),
        "expected local imported type references in language.rs: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_pub_cfg_test_async_function_calls() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/db.rs",
        r#"
#[cfg(test)]
pub async fn memory_pool() {}

#[cfg(test)]
pub async fn caller_one() {
    memory_pool().await;
}
"#,
    )]);

    let target = definition(&analyzer, "db.memory_pool");
    let candidates = BTreeSet::new();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates.into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("expected cfg(test) async function usages");
    assert_eq!(1, hits.len(), "expected the memory_pool() call: {hits:?}");
}

#[test]
fn rust_graph_strategy_does_not_treat_negated_cfg_test_as_same_file_only() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/db.rs",
            r#"
#[cfg(not(test))]
pub fn runtime_pool() {}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod db;

use crate::db::runtime_pool;

pub fn caller() {
    runtime_pool();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "db.runtime_pool");
    let candidates = BTreeSet::new();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates.into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("expected public function usages outside cfg(test) fast path");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/lib.rs")),
        "expected cross-file runtime_pool() usage, got {hits:?}"
    );
}

#[test]
fn rust_graph_strategy_respects_explicit_candidate_files() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
        ("src/other.rs", "fn unrelated() {}\n"),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = [project.file("src/other.rs")].into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result.into_either().expect("expected success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_finds_aliased_import_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Service as S;

fn run() {
    let _ = S {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result.into_either().expect("aliased import success").len()
    );
}

#[test]
fn rust_graph_strategy_finds_grouped_import_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;
pub struct Helper;
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::{Service, Helper};

fn run() {
    let _ = Service {};
    let _ = Helper {};
}
"#,
        ),
    ]);

    let service = definition(&analyzer, "service.Service");
    let helper = definition(&analyzer, "service.Helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&service), &candidates, 1000)
            .into_either()
            .expect("grouped Service success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000)
            .into_either()
            .expect("grouped Helper success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_finds_self_import_module_qualified_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub fn factory() {}\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::{self};

fn run() {
    service::factory();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.factory");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(1, result.into_either().expect("self import success").len());
}

#[test]
fn rust_graph_strategy_finds_public_reexport_alias_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/index.rs",
            "pub use crate::service::Service as PublicService;\n",
        ),
        (
            "src/main.rs",
            r#"
mod service;
mod index;
use crate::index::PublicService;

fn run() {
    let _ = PublicService {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result.into_either().expect("reexport alias success").len()
    );
}

#[test]
fn rust_graph_strategy_resolves_relative_module_layouts() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod pkg;\n"),
        ("src/pkg/mod.rs", "mod service;\nmod nested;\n"),
        ("src/pkg/service.rs", "pub struct Service;\n"),
        (
            "src/pkg/nested/mod.rs",
            r#"
use super::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result
            .into_either()
            .expect("relative module layout success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_counts_function_parameter_type_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod service;\nmod searchtools;\n"),
        ("src/service.rs", "pub struct SearchSymbolsParams;\n"),
        (
            "src/searchtools.rs",
            r#"
use crate::service::SearchSymbolsParams;

pub fn search_symbols(
    analyzer: &dyn IAnalyzer,
    params: SearchSymbolsParams,
) {
    let _ = analyzer;
    let _ = params;
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.SearchSymbolsParams");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result.into_either().expect("parameter type success").len()
    );
}

#[test]
fn private_rust_items_do_not_seed_graph_exports() {
    let (project, analyzer) = rust_analyzer_with_files(&[("src/service.rs", "struct Service;\n")]);
    let index = analyzer.export_index_of(&project.file("src/service.rs"));
    assert!(!index.exports_by_name.contains_key("Service"));
}

#[test]
fn local_definition_shadows_imported_rust_name() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Service;

struct Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert!(result.into_either().expect("shadowed success").is_empty());
}

#[test]
fn rust_graph_shadow_detection_uses_tree_sitter_declaration_nodes() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

struct /* local shadow */ Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert!(
        result
            .into_either()
            .expect("tree-sitter shadowed success")
            .is_empty()
    );
}

#[test]
fn private_unseeded_rust_target_scans_to_empty_success() {
    let (_project, analyzer) = rust_analyzer_with_files(&[("src/service.rs", "struct Service;\n")]);
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("private local target scan success");
    assert!(hits.is_empty(), "expected empty local scan: {hits:#?}");
}

#[test]
fn rust_graph_strategy_filters_non_rust_candidates_without_widening() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
        ("README.md", "# notes\n"),
        ("Cargo.toml", "[package]\nname = \"demo\"\n"),
    ]);

    let target = definition(&analyzer, "service.Service");
    let broad_candidates = analyzer.get_analyzed_files().into_iter().collect();
    let non_rust_only = [ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "README.md",
    )]
    .into_iter()
    .collect();

    let broad = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &broad_candidates,
        1000,
    );
    let narrowed = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &non_rust_only,
        1000,
    );

    assert_eq!(1, broad.into_either().expect("broad success").len());
    assert!(narrowed.into_either().expect("narrowed success").is_empty());
}

#[test]
fn rust_graph_strategy_returns_too_many_callsites_when_hits_exceed_limit() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod service;\nmod first;\nmod second;\n"),
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/first.rs",
            r#"
use crate::service::Service;
fn first() { let _ = Service {}; }
"#,
        ),
        (
            "src/second.rs",
            r#"
use crate::service::Service;
fn second() { let _ = Service {}; }
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );

    match result {
        FuzzyResult::TooManyCallsites { limit, .. } => assert_eq!(1, limit),
        other => panic!("expected TooManyCallsites, got {other:?}"),
    }
}

#[test]
fn rust_graph_strategy_finds_same_file_struct_references_in_types_and_literals() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/summary.rs",
        r#"
pub struct RenderedSummary {
    pub label: String,
    pub text: String,
}

pub fn summarize_inputs(inputs: &[String]) -> Result<Vec<RenderedSummary>, String> {
    inputs
        .iter()
        .map(|input| summarize_input(input))
        .collect()
}

fn summarize_input(input: &str) -> Result<RenderedSummary, String> {
    Ok(RenderedSummary {
        label: input.to_string(),
        text: input.to_string(),
    })
}
"#,
    )]);

    let target = definition(&analyzer, "summary.RenderedSummary");
    let candidates = std::collections::HashSet::default();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        3,
        result
            .into_either()
            .expect("same-file struct success")
            .len()
    );
}

#[test]
fn private_same_file_function_without_call_produces_no_hit() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/searchtools.rs",
        r#"
fn summarize_symbol_targets() {}

pub fn get_summaries() {}
"#,
    )]);

    let target = definition(&analyzer, "searchtools.summarize_symbol_targets");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &std::collections::HashSet::default(),
        1000,
    );
    assert!(result.into_either().expect("no-call success").is_empty());
}

#[test]
fn local_binding_shadows_private_same_file_function() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/searchtools.rs",
        r#"
fn summarize_symbol_targets() {}

pub fn get_summaries() {
    let summarize_symbol_targets = 1;
    let _ = summarize_symbol_targets;
}
"#,
    )]);

    let target = definition(&analyzer, "searchtools.summarize_symbol_targets");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &std::collections::HashSet::default(),
        1000,
    );
    assert!(
        result
            .into_either()
            .expect("shadowed same-file success")
            .is_empty()
    );
}

#[test]
fn usage_finder_routes_rust_targets_through_multi_analyzer_delegate() {
    let (project, rust) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);
    let analyzer = MultiAnalyzer::new(std::collections::BTreeMap::from([(
        Language::Rust,
        AnalyzerDelegate::Rust(rust),
    )]));

    let target = analyzer
        .get_definitions("service.Service")
        .into_iter()
        .next()
        .expect("missing multi-analyzer target");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("expected Rust graph success via MultiAnalyzer");

    assert_eq!(1, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

fn member(
    analyzer: &RustAnalyzer,
    file: &ProjectFile,
    owner_name: &str,
    member_name: &str,
) -> CodeUnit {
    analyzer
        .exact_member(file, owner_name, member_name, true)
        .or_else(|| analyzer.exact_member(file, owner_name, member_name, false))
        .unwrap_or_else(|| panic!("missing member {owner_name}.{member_name}"))
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
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected authoritative Rust usage success, got {other:#?}"),
    }
}

#[test]
fn authoritative_rust_usage_finds_bare_types_imported_from_private_file_module() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("crates/cli/src/lib.rs", "mod ux;\nmod analyze;\n"),
        ("crates/cli/src/ux.rs", "pub struct CheckResult;\n"),
        (
            "crates/cli/src/analyze.rs",
            r#"
use crate::ux::CheckResult;

fn group_checks(first: &CheckResult, rest: Vec<CheckResult>) {}
"#,
        ),
    ]);
    let target = definition(&analyzer, "crates.cli.src.ux.CheckResult");
    let analyze = project.file("crates/cli/src/analyze.rs");

    let hits = authoritative_hits(&analyzer, &target, [analyze.clone()].into_iter().collect());
    let references: Vec<_> = hits
        .iter()
        .filter(|hit| hit.kind == UsageHitKind::Reference)
        .collect();

    assert_eq!(
        2,
        references.len(),
        "expected both imported bare type annotations: {hits:#?}"
    );
    assert!(references.iter().all(|hit| hit.file == analyze));
}

fn assert_capital_self_reference_hits(
    result: &FuzzyResult,
    file: &ProjectFile,
    expected_token_hits: usize,
) {
    let external_hits = result.all_hits();
    let editor_hits = result.all_hits_including_imports();
    let source = file.read_to_string().expect("read self-reference fixture");
    for (surface, hits) in [("external", external_hits), ("editor", editor_hits)] {
        let self_hits: Vec<_> = hits
            .iter()
            .filter(|hit| &hit.file == file && "Self" == &source[hit.start_offset..hit.end_offset])
            .collect();
        assert_eq!(
            expected_token_hits,
            self_hits.len(),
            "capital-Self hits on {surface} surface: {hits:#?}"
        );
        assert!(
            self_hits
                .iter()
                .all(|hit| hit.kind == UsageHitKind::Reference),
            "capital Self must be an ordinary type reference: {hits:#?}"
        );
    }
}

fn assert_lowercase_self_receiver_omitted(result: &FuzzyResult, file: &ProjectFile) {
    let source = file.read_to_string().expect("read self-reference fixture");
    for (surface, hits) in [
        ("external", result.all_hits()),
        ("editor", result.all_hits_including_imports()),
    ] {
        assert!(
            hits.iter()
                .all(|hit| "self" != &source[hit.start_offset..hit.end_offset]),
            "lowercase self is not a type reference on the {surface} surface: {hits:#?}"
        );
    }
}

#[test]
fn rust_class_usage_records_bare_self_as_type_reference() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service {}

impl Service {
    fn same_type() -> Self {
        Self {}
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_capital_self_reference_hits(&result, &file, 2);
}

#[test]
fn rust_class_usage_records_self_path_owner_as_type_reference() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service;

impl Service {
    fn make() {}

    fn caller() {
        Self::make();
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_capital_self_reference_hits(&result, &file, 1);
}

#[test]
fn rust_class_usage_omits_lowercase_self_receiver() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service {
    value: usize,
}

impl Service {
    fn read(&self) -> usize {
        self.value
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_lowercase_self_receiver_omitted(&result, &file);
}

#[test]
fn rust_class_self_hits_require_the_matching_impl_owner() {
    let source = r#"
pub struct Service {
    value: usize,
}

pub struct Other {
    value: usize,
}

impl Service {
    fn copy(&self) -> Self {
        let _ = self.value;
        Self { value: 0 }
    }
}

impl Other {
    fn copy(&self) -> Self {
        let _ = self.value;
        Self { value: 0 }
    }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/service.rs", source)]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_capital_self_reference_hits(&result, &file, 2);
    assert_lowercase_self_receiver_omitted(&result, &file);
    let editor_hits = result.all_hits_including_imports();
    let service_hits: Vec<_> = editor_hits
        .iter()
        .filter(|hit| "Self" == &source[hit.start_offset..hit.end_offset])
        .collect();
    let other_impl = source.find("impl Other").expect("Other impl");
    assert!(
        service_hits.iter().all(|hit| hit.start_offset < other_impl),
        "unrelated Other impl must not contribute self hits: {editor_hits:#?}"
    );
}

#[test]
fn authoritative_rust_usage_finds_enum_variant_through_self() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/status.rs",
        r#"
pub enum Status {
    Ready,
}

impl Status {
    fn current() -> Self {
        Self::Ready
    }
}
"#,
    )]);
    let file = project.file("src/status.rs");
    let target = member(&analyzer, &file, "Status", "Ready");

    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());

    assert_eq!(
        1,
        hits.len(),
        "expected terminal Self::Ready hit: {hits:#?}"
    );
    assert!(hits.iter().all(|hit| hit.file == file));
    assert!(hits.iter().all(|hit| hit.snippet.contains("Self::Ready")));
}

#[test]
fn authoritative_rust_field_initializers_are_not_routed_to_same_named_trait_methods() {
    let source = r#"
pub trait Link {
    fn pointers(&self) -> usize;
}

pub struct Waiter {
    pub pointers: usize,
}

impl Link for Waiter {
    fn pointers(&self) -> usize {
        self.pointers
    }
}

impl Waiter {
    fn from_self(pointers: usize) -> Self {
        Self { pointers }
    }
}

fn from_explicit(pointers: usize) -> Waiter {
    Waiter { pointers }
}

fn call_trait_method(waiter: &impl Link) -> usize {
    waiter.pointers()
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/model.rs", source)]);
    let file = project.file("src/model.rs");
    let target = analyzer
        .get_definitions("model.Waiter.pointers")
        .into_iter()
        .find(|candidate| candidate.is_field() && !analyzer.is_type_alias(candidate))
        .expect("Waiter.pointers field");

    let hits = authoritative_hits(&analyzer, &target, [file].into_iter().collect());
    let expected: Vec<_> = ["Self { pointers }", "Waiter { pointers }"]
        .into_iter()
        .map(|initializer| {
            source.find(initializer).expect("field initializer")
                + initializer.find("pointers").expect("initializer field")
        })
        .collect();
    let trait_call = source
        .find("waiter.pointers()")
        .expect("same-named trait method call")
        + "waiter.".len();

    for start in expected {
        assert!(
            hits.iter()
                .any(|hit| (hit.start_offset, hit.end_offset) == (start, start + "pointers".len())),
            "explicit-owner and Self initializers must resolve to the struct field: {hits:#?}"
        );
    }
    assert!(
        hits.iter()
            .all(|hit| (hit.start_offset, hit.end_offset)
                != (trait_call, trait_call + "pointers".len())),
        "same-named trait method calls must not resolve to the struct field: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_struct_expression_fields_keep_their_physical_owner() {
    let valuable = r#"
struct User {
    name: String,
}

struct Other {
    name: String,
}

fn build(name: String, other: Other) {
    let _ = User {
        name: "Arwen Undomiel".to_string(), // EXPLICIT_FIELD
    };
    let _ = User { name }; // SHORTHAND_FIELD
    let _ = User { name: name.clone() }; // EXPLICIT_WITH_LOCAL_VALUE
    let Other { name } = other; // UNRELATED_PATTERN_BINDING
    let _ = Other { name }; // UNRELATED_SHORTHAND_FIELD
}
"#;
    let valuable_json = r#"
struct User {
    name: String,
}

fn build(name: String) {
    let _ = User { name }; // SIBLING_SAME_FQN_FIELD
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("examples/examples/valuable.rs", valuable),
        ("examples/examples/valuable_json.rs", valuable_json),
    ]);
    let target_file = project.file("examples/examples/valuable.rs");
    let sibling_file = project.file("examples/examples/valuable_json.rs");
    let target = member(&analyzer, &target_file, "User", "name");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = authoritative_hits(&analyzer, &target, candidates);

    let explicit = valuable
        .find("name: \"Arwen")
        .expect("explicit field label");
    let shorthand = valuable
        .find("name }; // SHORTHAND")
        .expect("shorthand label");
    let explicit_with_local = valuable
        .find("name: name.clone()")
        .expect("explicit field with local value");
    let expected = vec![explicit, shorthand, explicit_with_local];
    let local_value = explicit_with_local + "name: ".len();
    let pattern_binding = valuable
        .find("name } = other")
        .expect("unrelated pattern binding");
    let unrelated_shorthand = valuable
        .find("name }; // UNRELATED_SHORTHAND")
        .expect("unrelated shorthand field");

    assert_eq!(
        expected,
        hits.iter()
            .filter(|hit| hit.file == target_file)
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "explicit and shorthand struct-expression labels must retain exact identifier ranges: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| hit.file != sibling_file),
        "same-FQN sibling fields must remain excluded: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            hit.file != target_file
                || ![local_value, pattern_binding, unrelated_shorthand].contains(&hit.start_offset)
        }),
        "local values, pattern bindings, and unrelated field labels must remain excluded: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.end_offset == hit.start_offset + "name".len()),
        "field hits must cover only the field identifier: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_struct_expression_fields_use_the_importing_cargo_target_owner() {
    let consumer = r#"
use crate::User;

fn build(name: String) {
    let _ = User { name }; // IMPORTED_OWNER
    let _ = crate::User { name: String::new() }; // QUALIFIED_OWNER
}
"#;
    let binary = r#"
struct User { name: String }
fn build(name: String) { let _ = User { name }; } // BINARY_DECOY
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"field-owner\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "pub struct User { pub name: String }\nmod consumer;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", binary),
    ]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "User", "name");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        analyzer.get_analyzed_files().into_iter().collect(),
    );
    let expected = [
        consumer
            .find("name }; // IMPORTED")
            .expect("imported label"),
        consumer.find("name: String::new").expect("qualified label"),
    ];

    assert!(
        expected.into_iter().all(|start| {
            hits.iter().any(|hit| {
                hit.file == project.file("src/consumer.rs")
                    && (hit.start_offset, hit.end_offset) == (start, start + "name".len())
            })
        }),
        "same-FQN owners must be narrowed through the consumer's Cargo target: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("src/main.rs")),
        "the binary's same-FQN field must remain unrelated: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_enum_variants_are_not_routed_to_same_named_trait_methods() {
    let source = r#"
#[allow(non_snake_case)]
pub trait Transition {
    fn Ready(&self) -> bool;
}

pub enum Status {
    Ready,
}

#[allow(non_snake_case)]
impl Transition for Status {
    fn Ready(&self) -> bool {
        true
    }
}

impl Status {
    fn from_self() -> Self {
        Self::Ready
    }
}

fn from_explicit() -> Status {
    Status::Ready
}

fn call_trait_method(status: &impl Transition) -> bool {
    status.Ready()
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/model.rs", source)]);
    let file = project.file("src/model.rs");
    let target = analyzer
        .get_definitions("model.Status.Ready")
        .into_iter()
        .find(|candidate| candidate.is_field())
        .expect("Status::Ready variant");

    let hits = authoritative_hits(&analyzer, &target, [file].into_iter().collect());
    let expected: Vec<_> = ["Self::Ready", "Status::Ready"]
        .into_iter()
        .map(|expression| {
            source.find(expression).expect("variant expression")
                + expression.find("Ready").expect("variant name")
        })
        .collect();
    let trait_call = source
        .find("status.Ready()")
        .expect("same-named trait method call")
        + "status.".len();

    for start in expected {
        assert!(
            hits.iter()
                .any(|hit| (hit.start_offset, hit.end_offset) == (start, start + "Ready".len())),
            "explicit-owner and Self variant expressions must preserve enum identity: {hits:#?}"
        );
    }
    assert!(
        hits.iter()
            .all(|hit| (hit.start_offset, hit.end_offset)
                != (trait_call, trait_call + "Ready".len())),
        "same-named trait method calls must not resolve to the enum variant: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_usage_finds_private_self_associated_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service;

impl Service {
    fn target() {}

    fn caller() {
        Self::target();
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = member(&analyzer, &file, "Service", "target");

    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());

    assert_eq!(
        1,
        hits.len(),
        "expected terminal Self::target hit: {hits:#?}"
    );
    assert!(hits.iter().all(|hit| hit.file == file));
    assert!(hits.iter().all(|hit| hit.snippet.contains("Self::target")));
}

#[test]
fn authoritative_rust_usage_finds_private_field_in_macro_tokens() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
macro_rules! capture {
    ($($tokens:tt)*) => {};
}

pub struct Service {
    secret: usize,
}

impl Service {
    fn caller(&self) {
        capture!(self.secret);
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = member(&analyzer, &file, "Service", "secret");

    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());

    assert_eq!(1, hits.len(), "private macro field hits: {hits:#?}");
    assert!(hits.iter().all(|hit| hit.file == file));
    assert!(hits.iter().all(|hit| hit.snippet.contains("self.secret")));
}

#[test]
fn authoritative_rust_usage_resolves_every_qualified_macro_path_segment() {
    let lib_source = r#"
pub mod wanted;
pub mod decoy;

macro_rules! define_calls {
    () => {{
        $crate::wanted::free();
        $crate::wanted::Owner::assoc();
    }};
}

macro_rules! consume { ($($tokens:tt)*) => {}; }

pub fn invoke() {
    consume!(wanted::free());
    consume!({ wanted::Owner::assoc(); });
    consume!((wanted::Alias));
    consume!({ decoy::free(); });
    consume!({ decoy::Owner::assoc(); });
    consume!((decoy::Alias));
}
"#;
    let owner_source = r#"
pub struct Owner;
pub type Alias = Owner;
impl Owner { pub fn assoc() {} }
pub fn free() {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", lib_source),
        ("src/wanted.rs", owner_source),
        ("src/decoy.rs", owner_source),
    ]);
    let file = project.file("src/lib.rs");

    for (target_fqn, expected, required_snippets) in [
        (
            "wanted",
            5,
            vec!["$crate::wanted::free", "consume!(wanted::free())"],
        ),
        (
            "wanted.Owner",
            2,
            vec!["$crate::wanted::Owner::assoc", "wanted::Owner::assoc"],
        ),
        ("wanted.Alias", 1, vec!["wanted::Alias"]),
        (
            "wanted.free",
            2,
            vec!["$crate::wanted::free", "consume!(wanted::free())"],
        ),
        (
            "wanted.Owner.assoc",
            2,
            vec!["$crate::wanted::Owner::assoc", "wanted::Owner::assoc"],
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let hits = authoritative_hits(
            &analyzer,
            &target,
            analyzer.get_analyzed_files().into_iter().collect(),
        );
        let macro_hits: Vec<_> = hits.iter().filter(|hit| hit.file == file).collect();
        assert_eq!(expected, macro_hits.len(), "{target_fqn} hits: {hits:#?}");
        for snippet in required_snippets {
            assert!(
                macro_hits.iter().any(|hit| hit.snippet.contains(snippet)),
                "{target_fqn} should include `{snippet}`: {hits:#?}"
            );
        }
        let expected_segment = target_fqn
            .rsplit('.')
            .next()
            .expect("qualified target terminal");
        assert!(
            macro_hits.iter().all(|hit| {
                lib_source.get(hit.start_offset..hit.end_offset) == Some(expected_segment)
            }),
            "{target_fqn} must retain its exact segment ranges: {hits:#?}"
        );
    }
}

#[test]
fn rust_qualified_macro_import_owner_ignores_same_named_field() {
    let consumer = r#"
use crate::options;

macro_rules! consume { ($($tokens:tt)*) => {}; }

pub fn run() {
    consume!(options::Extension);
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"owner_filter\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod parser;\npub use parser::options;\npub mod consumer;\n",
        ),
        (
            "src/parser/mod.rs",
            "pub mod options;\npub struct Parser { pub options: usize }\n",
        ),
        ("src/parser/options.rs", "pub struct Extension;\n"),
        ("src/consumer.rs", consumer),
    ]);
    let target = definition(&analyzer, "parser.options");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        analyzer.get_analyzed_files().into_iter().collect(),
    );
    let expected = consumer
        .find("options::Extension")
        .expect("qualified macro owner");
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/consumer.rs")
                && (hit.start_offset, hit.end_offset) == (expected, expected + "options".len())
        }),
        "an imported module owner must win over a same-named struct field in its declaring file: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_private_members_respect_candidate_scope_and_owner_identity() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub struct Service {
    secret: usize,
}

pub mod child;
mod other;

impl Service {
    fn hidden(&self) {}
}
"#,
        ),
        (
            "src/child.rs",
            r#"
use crate::Service;

fn caller(service: &Service) {
    let _ = service.secret;
    service.hidden();
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub struct Service {
    secret: usize,
}

impl Service {
    fn hidden(&self) {
        let _ = self.secret;
    }
}
"#,
        ),
    ]);
    let service = project.file("src/lib.rs");
    let child = project.file("src/child.rs");
    let other = project.file("src/other.rs");
    let field = member(&analyzer, &service, "Service", "secret");
    let method = member(&analyzer, &service, "Service", "hidden");

    let field_hits = authoritative_hits(
        &analyzer,
        &field,
        [child.clone(), other.clone()].into_iter().collect(),
    );
    assert_eq!(1, field_hits.len(), "private field hits: {field_hits:#?}");
    assert!(field_hits.iter().all(|hit| hit.file == child));

    let method_hits = authoritative_hits(
        &analyzer,
        &method,
        [child.clone(), other.clone()].into_iter().collect(),
    );
    assert_eq!(
        1,
        method_hits.len(),
        "private method hits: {method_hits:#?}"
    );
    assert!(method_hits.iter().all(|hit| hit.file == child));
    assert!(
        method_hits
            .iter()
            .all(|hit| hit.kind == UsageHitKind::Reference)
    );

    assert!(
        authoritative_hits(&analyzer, &field, [other.clone()].into_iter().collect()).is_empty(),
        "same-named unrelated owner must not match the private field"
    );
    assert!(
        authoritative_hits(&analyzer, &method, [other].into_iter().collect()).is_empty(),
        "same-named unrelated owner must not match the private method"
    );
}

#[test]
fn rust_self_receiver_is_editor_only_member_usage() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Foo;
impl Foo {
    pub fn target(&self) {}
    pub fn caller(&self) {
        self.target();
    }
}
"#,
    )]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "target");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));

    assert!(
        result.all_hits().is_empty(),
        "scan_usages/external surface must not count self-receiver hits: {:?}",
        result.all_hits()
    );
    let editor_hits = result.all_hits_including_imports();
    assert_eq!(1, editor_hits.len(), "editor hits: {editor_hits:?}");
    assert!(
        editor_hits
            .iter()
            .all(|hit| hit.snippet.contains("self.target"))
    );
}

#[test]
fn rust_self_receiver_preserves_external_generic_impl_owner() {
    let source = r#"
use std::cell::RefCell;

struct Ast;

impl<'a> arena_tree::Node<'a, RefCell<Ast>> {
    pub fn collect_text(&'a self) {
        self.collect_text_append();
    }

    pub fn collect_text_append(&'a self) {}
}

impl<'a> other_tree::Node<'a, RefCell<Ast>> {
    pub fn collect_text(&'a self) {
        self.collect_text_append();
    }

    pub fn collect_text_append(&'a self) {}
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/nodes.rs", source)]);
    let file = project.file("src/nodes.rs");
    let target = definition(&analyzer, "arena_tree.Node.collect_text_append");

    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());
    let expected = source
        .find("self.collect_text_append")
        .expect("target call")
        + "self.".len();
    let unrelated = source
        .rfind("self.collect_text_append")
        .expect("same-named unrelated call")
        + "self.".len();

    assert_eq!(
        1,
        hits.len(),
        "expected only the matching impl call: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == file
                && hit.kind == UsageHitKind::SelfReceiver
                && (hit.start_offset, hit.end_offset)
                    == (expected, expected + "collect_text_append".len())
        }),
        "direct self call must retain its external generic impl owner: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            (hit.start_offset, hit.end_offset)
                != (unrelated, unrelated + "collect_text_append".len())
        }),
        "same-named method on another external generic impl must not match: {hits:#?}"
    );
}

#[test]
fn rust_self_receiver_hits_do_not_trigger_external_usage_cap() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Foo;
impl Foo {
    pub fn target(&self) {}
    pub fn caller(&self) {
        self.target();
        self.target();
    }
}
"#,
    )]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "target");
    let result = UsageFinder::new()
        .query(&analyzer, std::slice::from_ref(&target), 1000, 0)
        .result;

    assert!(
        !matches!(result, FuzzyResult::TooManyCallsites { .. }),
        "self-receiver hits are editor-visible but must not count against the external usage cap: {result:?}"
    );
    assert!(result.all_hits().is_empty(), "result: {result:?}");
    assert_eq!(2, result.all_hits_including_imports().len());
}

// Issue #1014 (detection facet): a trait-impl method calling an inherent-impl sibling
// through a Pin adapter — `ready!(self.as_mut().poll_elapsed(cx))` in tokio's
// `impl Future for Sleep` — produced no hit on any surface. The adapter-chained self
// receiver must be detected as a SelfReceiver hit. Assert on the authoritative
// detection surface (not the scan_usages/`all_hits` policy surface, which is issue
// #1014's escalated policy facet).
fn self_receiver_detected(hits: &BTreeSet<UsageHit>, file: &ProjectFile, member: &str) -> bool {
    hits.iter().any(|hit| {
        hit.file == *file && hit.kind == UsageHitKind::SelfReceiver && hit.snippet.contains(member)
    })
}

#[test]
fn rust_adapter_chained_self_receiver_in_macro_is_detected() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/sleep.rs",
        r#"
pub struct Sleep;

macro_rules! ready {
    ($e:expr) => {
        match $e {
            x => x,
        }
    };
}

impl Sleep {
    fn poll_elapsed(self: Pin<&mut Self>) {}
}

impl Future for Sleep {
    fn poll(mut self: Pin<&mut Self>) {
        ready!(self.as_mut().poll_elapsed());
    }
}
"#,
    )]);

    let file = project.file("src/sleep.rs");
    let target = member(&analyzer, &file, "Sleep", "poll_elapsed");
    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());
    assert!(
        self_receiver_detected(&hits, &file, "poll_elapsed"),
        "adapter-chained self receiver inside ready!(...) must be detected as a self-receiver hit: {hits:#?}"
    );
}

#[test]
fn rust_adapter_chained_self_receiver_without_macro_is_detected() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/sleep.rs",
        r#"
pub struct Sleep;

impl Sleep {
    fn poll_elapsed(self: Pin<&mut Self>) {}
}

impl Future for Sleep {
    fn poll(mut self: Pin<&mut Self>) {
        self.as_mut().poll_elapsed();
    }
}
"#,
    )]);

    let file = project.file("src/sleep.rs");
    let target = member(&analyzer, &file, "Sleep", "poll_elapsed");
    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());
    assert!(
        self_receiver_detected(&hits, &file, "poll_elapsed"),
        "plain `self.as_mut().poll_elapsed()` must be detected as a self-receiver hit: {hits:#?}"
    );
}

// Negative control: `self.other().target()` where `other()` returns a *different*
// workspace type that has its own `target`. Existing type inference must resolve the
// call to that other type's method, so it is a (regular) reference to `Inner.target`
// and never a self hit on `Outer`.
#[test]
fn rust_non_adapter_receiver_resolves_to_returned_type_not_self() {
    let source = r#"
pub struct Inner;
impl Inner {
    fn target(&self) {}
}

pub struct Outer {
    inner: Inner,
}
impl Outer {
    fn other(&self) -> &Inner {
        &self.inner
    }
    fn target(&self) {}
    fn caller(&self) {
        self.other().target();
    }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/svc.rs", source)]);
    let file = project.file("src/svc.rs");
    let call = source.find("self.other().target").expect("call site") + "self.other().".len();
    let span = (call, call + "target".len());

    // The call resolves to Inner.target via inference (a regular reference), not self.
    let inner_target = member(&analyzer, &file, "Inner", "target");
    let inner_hits = authoritative_hits(
        &analyzer,
        &inner_target,
        [file.clone()].into_iter().collect(),
    );
    assert!(
        inner_hits.iter().any(|hit| {
            hit.file == file
                && hit.kind == UsageHitKind::Reference
                && (hit.start_offset, hit.end_offset) == span
        }),
        "adapter-returning receiver must resolve to Inner.target: {inner_hits:#?}"
    );

    // Scanning Outer.target must NOT claim that same call site as a self hit.
    let outer_target = member(&analyzer, &file, "Outer", "target");
    let outer_hits = authoritative_hits(
        &analyzer,
        &outer_target,
        [file.clone()].into_iter().collect(),
    );
    assert!(
        outer_hits
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != span),
        "receiver resolved to Inner must not become an Outer hit: {outer_hits:#?}"
    );
}

// Negative control: a non-allowlisted adapter (`mystery`) whose return type is
// unresolvable must NOT be proven as a self hit. It is neither an allowlisted adapter
// nor inference-resolvable, so no hit is produced at that call site.
#[test]
fn rust_unknown_adapter_receiver_produces_no_self_hit() {
    let source = r#"
pub struct Sleep;

impl Sleep {
    fn poll_elapsed(self: Pin<&mut Self>) {}
    fn mystery(&self) -> Mystery {
        Mystery
    }
}

impl Future for Sleep {
    fn poll(mut self: Pin<&mut Self>) {
        self.mystery().poll_elapsed();
        self.poll_elapsed();
    }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/sleep.rs", source)]);
    let file = project.file("src/sleep.rs");
    let target = member(&analyzer, &file, "Sleep", "poll_elapsed");
    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());

    // The bare `self.poll_elapsed()` anchors a Success result with one self hit,
    // proving the scan ran; the unknown-adapter call must contribute no extra hit.
    let mystery_call =
        source.find("self.mystery().poll_elapsed").expect("call") + "self.mystery().".len();
    let mystery_span = (mystery_call, mystery_call + "poll_elapsed".len());
    assert!(
        hits.iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != mystery_span),
        "unresolvable non-allowlisted adapter must not be proven as a self hit: {hits:#?}"
    );
    assert!(
        self_receiver_detected(&hits, &file, "self.poll_elapsed"),
        "the bare self control call must still be detected: {hits:#?}"
    );
}

// Cross-impl bare-self regression guard: a trait impl calling an inherent sibling by
// bare `self.poll_elapsed()` must be detected. This is proved by the enclosing impl's
// Self type, not by physical range containment of the target inside the trait impl
// (the inherent `impl Sleep` is a different impl block than `impl Future for Sleep`).
#[test]
fn rust_cross_impl_bare_self_receiver_is_detected() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/sleep.rs",
        r#"
pub struct Sleep;

impl Sleep {
    fn poll_elapsed(&self) {}
}

impl Future for Sleep {
    fn poll(&self) {
        self.poll_elapsed();
    }
}
"#,
    )]);

    let file = project.file("src/sleep.rs");
    let target = member(&analyzer, &file, "Sleep", "poll_elapsed");
    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());
    assert!(
        self_receiver_detected(&hits, &file, "poll_elapsed"),
        "cross-impl bare self call must be detected as a self-receiver hit: {hits:#?}"
    );
}

// Whole-workspace export scope also proves adapter-chained self receivers as
// SelfReceiver hits (not merely unproven candidates): a public inherent method called
// through `self.as_mut()` from a trait impl, both directly and inside a macro.
#[test]
fn rust_adapter_chained_self_receiver_proven_on_export_surface() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "pub mod sleep;\n"),
        (
            "src/sleep.rs",
            r#"
use std::pin::Pin;

pub struct Sleep;

macro_rules! ready {
    ($e:expr) => { match $e { x => x } };
}

impl Sleep {
    pub fn poll_elapsed(self: Pin<&mut Self>) {}
}

impl Future for Sleep {
    fn poll(mut self: Pin<&mut Self>) {
        self.as_mut().poll_elapsed();
        ready!(self.as_mut().poll_elapsed());
    }
}
"#,
        ),
    ]);
    let file = project.file("src/sleep.rs");
    let target = member(&analyzer, &file, "Sleep", "poll_elapsed");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let editor_hits = result.all_hits_including_imports();
    let self_hits: Vec<_> = editor_hits
        .iter()
        .filter(|hit| hit.file == file && hit.kind == UsageHitKind::SelfReceiver)
        .collect();
    assert_eq!(
        2,
        self_hits.len(),
        "both the plain and macro adapter calls must be proven self hits on the export surface: {editor_hits:#?}"
    );
}

#[test]
fn rust_seedless_local_external_hits_still_enforce_usage_cap() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Foo;
impl Foo {
    pub fn target(&self) {}
}

fn caller(foo: Foo) {
    foo.target();
    foo.target();
}
"#,
    )]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "target");
    let result = UsageFinder::new()
        .query(&analyzer, std::slice::from_ref(&target), 1000, 1)
        .result;

    match result {
        FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            ..
        } => {
            assert_eq!(2, total_callsites);
            assert_eq!(1, limit);
        }
        other => panic!("expected seedless local external hits to enforce cap, got {other:?}"),
    }
}

#[test]
fn usage_finder_routes_rust_member_targets_through_graph() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;
impl Service {
    pub fn run(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn main() {
    let service: Service = Service {};
    service.run();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Service", "run");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("expected member graph success");
    assert_eq!(1, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_exact_member_lookup_is_stable_across_repeated_calls() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service;
impl Service {
    pub fn run(&self) {}
}
"#,
    )]);

    let file = project.file("src/service.rs");
    let first = analyzer
        .exact_member(&file, "Service", "run", true)
        .expect("first member");
    let second = analyzer
        .exact_member(&file, "Service", "run", true)
        .expect("second member");

    assert_eq!(first, second);
    assert!(!first.is_synthetic());
}

#[test]
fn rust_member_candidate_funnel_keeps_likely_files_and_drops_unrelated_ones() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;
impl Service {
    pub fn run(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Service;
fn main() {
    let service: Service = Service {};
    service.run();
}
"#,
        ),
        (
            "src/other.rs",
            r#"
fn unrelated() {
    let value = 1;
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Service", "run");
    let candidates =
        analyzer.rust_usage_candidate_files(["Service".to_string()].into_iter().collect(), &target);

    assert!(candidates.contains(&project.file("src/main.rs")));
    assert!(!candidates.contains(&project.file("src/other.rs")));
}

#[test]
fn rust_graph_strategy_resolves_typed_receiver_instance_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    let y: Foo = x;
    y.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("typed receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_constructor_and_alias_receivers() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn new() -> Foo { Foo }
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let a = Foo::new();
    a.bar();
    let b = Foo {};
    b.bar();
    let c = a;
    c.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("constructor receiver success");
    assert_eq!(3, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_ast_constructor_return_shapes() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/models.rs",
            r#"
pub struct MemoryRepository;
pub struct Error;

impl MemoryRepository {
    pub fn new() -> Self { Self }
    pub fn scoped() -> crate::models::MemoryRepository { MemoryRepository }
    pub fn boxed() -> Box<Self> { Box::new(Self) }
    pub fn maybe() -> Option<Self> { Some(Self) }
    pub fn fallible() -> Result<Self, Error> { Ok(Self) }
    pub fn many() -> Vec<Self> { vec![Self] }
    pub fn save(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::models::MemoryRepository;

fn run() {
    let direct = MemoryRepository::new();
    direct.save();

    let scoped = MemoryRepository::scoped();
    scoped.save();

    let boxed = MemoryRepository::boxed();
    boxed.save();

    let maybe = MemoryRepository::maybe().unwrap();
    maybe.save();

    let fallible = MemoryRepository::fallible().expect("repository");
    fallible.save();

    let many = MemoryRepository::many();
    many.save();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/models.rs"),
        "MemoryRepository",
        "save",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("AST constructor return receiver success");
    assert_eq!(5, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_multiline_constructor_receiver() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn new() -> Foo { Foo }
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let a = Foo::new(
    );
    a.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("multiline constructor receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_associated_method_and_const_without_receiver_inference() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub const CONST: usize = 1;
    pub fn make() -> Foo { Foo }
}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;

use crate::service::Foo;

fn run() {
    let _ = Foo::make();
    let _ = Foo::CONST;
}
"#,
        ),
    ]);

    let make = member(&analyzer, &project.file("src/service.rs"), "Foo", "make");
    let constant = member(&analyzer, &project.file("src/service.rs"), "Foo", "CONST");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&make), &candidates, 1000)
            .into_either()
            .expect("associated make success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&constant),
                &candidates,
                1000
            )
            .into_either()
            .expect("associated const success")
            .len()
    );
}

#[test]
fn authoritative_rust_usage_finds_same_file_explicit_associated_calls() {
    let source = r#"
struct OptionalWriter<T>(Option<T>);

impl<T> OptionalWriter<T> {
    fn none() -> Self { Self(None) }
    fn some(value: T) -> Self { Self(Some(value)) }
}

fn build() {
    let _ = OptionalWriter::some(1usize); // SOME_ONE
    let _ = OptionalWriter::some(2usize); // SOME_TWO
    let _: OptionalWriter<usize> = OptionalWriter::none(); // NONE
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/writer.rs", source)]);
    let file = project.file("src/writer.rs");
    let candidates: HashSet<ProjectFile> = [file.clone()].into_iter().collect();
    let some = member(&analyzer, &file, "OptionalWriter", "some");
    let none = member(&analyzer, &file, "OptionalWriter", "none");

    let some_hits = authoritative_hits(&analyzer, &some, candidates.clone());
    let none_hits = authoritative_hits(&analyzer, &none, candidates);

    assert_eq!(
        2,
        some_hits.len(),
        "same-file OptionalWriter::some: {some_hits:#?}"
    );
    assert!(some_hits.iter().any(|hit| hit.snippet.contains("SOME_ONE")));
    assert!(some_hits.iter().any(|hit| hit.snippet.contains("SOME_TWO")));
    assert_eq!(
        1,
        none_hits.len(),
        "same-file OptionalWriter::none: {none_hits:#?}"
    );
    assert!(none_hits.iter().all(|hit| hit.snippet.contains("NONE")));
}

#[test]
fn authoritative_rust_associated_calls_resolve_canonical_owner_routes() {
    let library = r#"
pub struct OptionalWriter;

impl OptionalWriter {
    pub(crate) fn some() -> Self { Self }
    pub(crate) fn none() -> Self { Self }
}

pub struct OtherWriter;
impl OtherWriter {
    pub(crate) fn some() -> Self { Self }
}

pub mod facade {
    pub use crate::OptionalWriter;
}

mod named;
mod globbed;
mod reexported;
mod qualified;
mod decoy;

fn local() {
    let _ = OptionalWriter::some(); // SAME_FILE
    let _ = OptionalWriter::none(); // SAME_OWNER_OTHER_MEMBER
    let _ = OtherWriter::some(); // SAME_MEMBER_OTHER_OWNER
}
"#;
    let named = r#"
use crate::OptionalWriter;
fn call() { let _ = OptionalWriter::some(); } // NAMED_IMPORT
"#;
    let globbed = r#"
use crate::*;
fn call() { let _ = OptionalWriter::some(); } // GLOB_IMPORT
"#;
    let reexported = r#"
use crate::facade::OptionalWriter;
fn call() { let _ = OptionalWriter::some(); } // REEXPORTED_OWNER
"#;
    let qualified = r#"
fn call() { let _ = crate::OptionalWriter::some(); } // CRATE_QUALIFIED
"#;
    let decoy = r#"
struct OptionalWriter;
impl OptionalWriter { fn some() -> Self { Self } }
fn call() { let _ = OptionalWriter::some(); } // SAME_NAME_OWNER_MEMBER
"#;
    let binary = r#"
struct OptionalWriter;
impl OptionalWriter { fn some() -> Self { Self } }
fn main() { let _ = OptionalWriter::some(); } // INDEPENDENT_CARGO_TARGET
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"associated-routes\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", library),
        ("src/named.rs", named),
        ("src/globbed.rs", globbed),
        ("src/reexported.rs", reexported),
        ("src/qualified.rs", qualified),
        ("src/decoy.rs", decoy),
        ("src/main.rs", binary),
    ]);
    let target = member(
        &analyzer,
        &project.file("src/lib.rs"),
        "OptionalWriter",
        "some",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = authoritative_hits(&analyzer, &target, candidates);

    for (path, marker) in [
        ("src/lib.rs", "SAME_FILE"),
        ("src/named.rs", "NAMED_IMPORT"),
        ("src/globbed.rs", "GLOB_IMPORT"),
        ("src/reexported.rs", "REEXPORTED_OWNER"),
        ("src/qualified.rs", "CRATE_QUALIFIED"),
    ] {
        assert!(
            hits.iter()
                .any(|hit| hit.file == project.file(path) && hit.snippet.contains(marker)),
            "missing associated call through {marker}: {hits:#?}"
        );
    }
    assert_eq!(
        5,
        hits.len(),
        "unexpected associated-call matches: {hits:#?}"
    );
    let other_member =
        library.find("OptionalWriter::none").expect("other member") + "OptionalWriter::".len();
    let other_owner =
        library.find("OtherWriter::some").expect("other owner") + "OtherWriter::".len();
    let library_file = project.file("src/lib.rs");
    assert!(
        hits.iter().all(|hit| {
            hit.file != library_file || ![other_member, other_owner].contains(&hit.start_offset)
        }),
        "same-owner/different-member and different-owner/same-member calls must stay excluded: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            hit.file != project.file("src/decoy.rs") && hit.file != project.file("src/main.rs")
        }),
        "same-name owners and independent Cargo targets must stay excluded: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_associated_calls_canonicalize_cross_file_imported_impl_owners() {
    let implementation = r#"
use crate::model::Builder;

impl Builder {
    pub(crate) fn build() -> Self { Self }
}
"#;
    let consumer = r#"
use crate::model::Builder;
fn call() { let _ = Builder::build(); } // IMPORTED_IMPL_OWNER
"#;
    let binary = r#"
struct Builder;
impl Builder { fn build() -> Self { Self } }
fn call() { let _ = Builder::build(); } // BINARY_IMPL_DECOY
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"imported-impl\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod model;\nmod implementation;\nmod consumer;\n",
        ),
        ("src/model.rs", "pub struct Builder;\n"),
        ("src/implementation.rs", implementation),
        ("src/consumer.rs", consumer),
        ("src/main.rs", binary),
    ]);
    let target = member(
        &analyzer,
        &project.file("src/implementation.rs"),
        "Builder",
        "build",
    );
    let hits = authoritative_hits(
        &analyzer,
        &target,
        analyzer.get_analyzed_files().into_iter().collect(),
    );
    let expected = consumer.find("build();").expect("consumer call");

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/consumer.rs")
                && (hit.start_offset, hit.end_offset) == (expected, expected + "build".len())
        }),
        "an imported inherent impl owner must canonicalize to its declaration: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("src/main.rs")),
        "an independent Cargo target's same-FQN impl must remain unrelated: {hits:#?}"
    );
}

#[test]
fn rust_graph_counts_static_qualifier_references_for_struct_targets() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub const CONST: usize = 1;
    pub fn assoc_fn() -> Foo { Foo }
}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Foo;

fn run() {
    let _ = Foo::assoc_fn();
    let _ = Foo::CONST;
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let hits = rust_graph_hits(&analyzer, &target.fq_name());

    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("Foo::assoc_fn()")),
        "expected associated function qualifier hit: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("Foo::CONST")),
        "expected associated const qualifier hit: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_ufcs_trait_method_through_implementer() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/contracts.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::contracts::Trait;

pub struct Foo;
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod contracts;
mod service;

use crate::contracts::Trait;
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "Trait",
        "frobnicate",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("UFCS trait method success");

    assert_eq!(1, hits.len(), "hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_graph_strategy_resolves_trait_ufcs_through_barrel_reexport() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Worker {
    fn run(&self);
}

pub struct Local;

impl Worker for Local {
    fn run(&self) {}
}
"#,
        ),
        (
            "src/facade.rs",
            r#"
pub use crate::service::{Local, Worker};

pub type LocalAlias = Local;

pub fn build() -> Local { Local }
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;
pub mod facade;

pub use facade::Worker;

pub fn consume() {
    let worker = facade::build();
    Worker::run(&worker);
    let other: facade::LocalAlias = facade::build();
    Worker::run(&other);
}
"#,
        ),
    ]);

    let run = member(&analyzer, &project.file("src/service.rs"), "Worker", "run");
    let worker = definition(&analyzer, "service.Worker");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    let run_hits = strategy
        .find_usages(&analyzer, &[run], &candidates, 1000)
        .into_either()
        .expect("barrel-reexported trait method lookup should succeed");
    assert_eq!(
        2,
        run_hits
            .iter()
            .filter(|hit| hit.file == project.file("src/lib.rs"))
            .count(),
        "both Worker::run calls should resolve to the trait method: {run_hits:#?}"
    );
    assert!(
        run_hits.iter().all(
            |hit| hit.file != project.file("src/facade.rs") && !hit.snippet.contains("pub use")
        ),
        "import and re-export sites stay filtered: {run_hits:#?}"
    );

    let worker_hits = strategy
        .find_usages(&analyzer, &[worker], &candidates, 1000)
        .into_either()
        .expect("barrel-reexported trait qualifier lookup should succeed");
    assert_eq!(
        2,
        worker_hits
            .iter()
            .filter(|hit| {
                hit.file == project.file("src/lib.rs") && hit.snippet.contains("Worker::run")
            })
            .count(),
        "both UFCS qualifiers should resolve to the original trait: {worker_hits:#?}"
    );
    assert!(
        worker_hits.iter().all(
            |hit| hit.file != project.file("src/facade.rs") && !hit.snippet.contains("pub use")
        ),
        "import and re-export sites stay filtered: {worker_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_trait_ufcs_through_aliased_barrel_namespace() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            "pub trait Worker { fn run(&self); }\npub struct Local;\nimpl Worker for Local { fn run(&self) {} }\n",
        ),
        (
            "src/facade.rs",
            "pub use crate::service::{Local, Worker};\npub fn build() -> Local { Local }\n",
        ),
        (
            "src/lib.rs",
            "mod service;\npub mod facade;\nuse crate::facade as api;\npub fn consume() { let worker = api::build(); api::Worker::run(&worker); }\n",
        ),
    ]);
    let run = member(&analyzer, &project.file("src/service.rs"), "Worker", "run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, &[run], &candidates, 1000)
        .into_either()
        .expect("aliased barrel UFCS lookup should succeed");

    assert_eq!(
        vec![4],
        hits.iter()
            .filter(|hit| hit.file == project.file("src/lib.rs"))
            .map(|hit| hit.line)
            .collect::<Vec<_>>(),
        "the aliased namespace call should resolve through the barrel: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_prefers_local_declaration_over_glob_reexport() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub trait Worker { fn run(); }\n"),
        ("src/facade.rs", "pub use crate::service::Worker;\n"),
        (
            "src/lib.rs",
            "mod service;\nmod facade;\nuse crate::facade::*;\nstruct Worker;\nimpl Worker { fn run() {} }\nfn consume() { Worker::run(); }\n",
        ),
    ]);
    let run = member(&analyzer, &project.file("src/service.rs"), "Worker", "run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, &[run], &candidates, 1000)
        .into_either()
        .expect("shadowed glob lookup should complete");

    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("src/lib.rs")),
        "the local Worker must shadow the glob-reexported trait: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_impl_side_trait_method_through_implementer_export() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub struct Bson;

impl From<i32> for Bson {
    fn from(_value: i32) -> Self {
        Bson
    }
}

pub mod caller;
"#,
        ),
        (
            "src/caller.rs",
            r#"
use crate::Bson;

pub fn make() {
    let _ = Bson::from(1);
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/lib.rs"), "Bson", "from");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("impl-side trait method success");

    assert_eq!(1, hits.len(), "hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/caller.rs"))
    );
}

#[test]
fn rust_graph_strategy_resolves_ufcs_trait_method_through_module_qualified_implementer() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;

use crate::service::{self, Trait};

fn run() {
    service::Foo::frobnicate();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Trait",
        "frobnicate",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("module-qualified UFCS trait method success");

    assert_eq!(1, hits.len(), "hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_graph_strategy_requires_visible_trait_for_ufcs_trait_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service;

fn run() {
    service::Foo::frobnicate();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Trait",
        "frobnicate",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("non-visible UFCS trait method success");

    assert!(hits.is_empty(), "hits: {hits:?}");
}

#[test]
fn rust_graph_strategy_prefers_inherent_static_method_over_trait_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;
impl Foo {
    pub fn frobnicate() {}
}
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;

use crate::service::Trait;
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let trait_method = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Trait",
        "frobnicate",
    );
    let inherent_method = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Foo",
        "frobnicate",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&trait_method),
                &candidates,
                1000
            )
            .into_either()
            .expect("trait method success")
            .is_empty()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&inherent_method),
                &candidates,
                1000
            )
            .into_either()
            .expect("inherent method success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_does_not_guess_ambiguous_ufcs_trait_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/contracts.rs",
            r#"
pub trait One {
    fn frobnicate();
}

pub trait Two {
    fn frobnicate();
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::contracts::{One, Two};

pub struct Foo;
impl One for Foo {}
impl Two for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::contracts::{One, Two};
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let one = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "One",
        "frobnicate",
    );
    let two = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "Two",
        "frobnicate",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&one), &candidates, 1000)
            .into_either()
            .expect("ambiguous One success")
            .is_empty()
    );
    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&two), &candidates, 1000)
            .into_either()
            .expect("ambiguous Two success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_filters_ufcs_trait_candidates_by_visible_trait() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/contracts.rs",
            r#"
pub trait One {
    fn frobnicate();
}

pub trait Two {
    fn frobnicate();
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::contracts::{One, Two};

pub struct Foo;
impl One for Foo {}
impl Two for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod contracts;
mod service;

use crate::contracts::One;
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let one = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "One",
        "frobnicate",
    );
    let two = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "Two",
        "frobnicate",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&one), &candidates, 1000)
            .into_either()
            .expect("visible One success")
            .len()
    );
    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&two), &candidates, 1000)
            .into_either()
            .expect("hidden Two success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_resolves_comment_separated_member_references() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub const CONST: usize = 1;
    pub fn make() -> Foo { Foo }
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;

use crate::service::Foo;

fn run(x: Foo) {
    x. /* member */ bar();
    let _ = Foo:: /* static */ make();
    let _ = Foo:: /* const */ CONST;
}
"#,
        ),
    ]);

    let bar = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let make = member(&analyzer, &project.file("src/service.rs"), "Foo", "make");
    let constant = member(&analyzer, &project.file("src/service.rs"), "Foo", "CONST");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&bar), &candidates, 1000)
            .into_either()
            .expect("commented instance member success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&make), &candidates, 1000)
            .into_either()
            .expect("commented static method success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&constant),
                &candidates,
                1000
            )
            .into_either()
            .expect("commented static const success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_finds_in_crate_member_usages_on_private_owner() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
struct Foo;
impl Foo {
    pub fn public(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.public();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "public");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either();
    assert_eq!(1, hits.expect("private owner member local scan").len());
}

#[test]
fn rust_graph_strategy_does_not_cross_match_duplicate_owner_names() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let x: Foo = Foo {};
    x.bar();
}
"#,
        ),
    ]);

    let service_target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let other_target = member(&analyzer, &project.file("src/other.rs"), "Foo", "bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&service_target),
                &candidates,
                1000,
            )
            .into_either()
            .expect("service foo member success")
            .len()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&other_target),
                &candidates,
                1000
            )
            .into_either()
            .expect("other foo member success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_uses_function_parameter_type_as_receiver_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("parameter receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_finds_private_same_file_function_call_inside_closure() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/summary.rs",
        r#"
pub struct RenderedSummary;

pub fn summarize_inputs(inputs: &[String]) -> Result<Vec<RenderedSummary>, String> {
    inputs
        .iter()
        .map(|input| summarize_input(input))
        .collect()
}

fn summarize_input(input: &str) -> Result<RenderedSummary, String> {
    Ok(RenderedSummary)
}
"#,
    )]);

    let target = definition(&analyzer, "summary.summarize_input");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &std::collections::HashSet::default(),
            1000,
        )
        .into_either()
        .expect("closure private call success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_cross_match_same_private_function_name_in_another_module() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/a.rs",
            r#"
fn summarize_symbol_targets(targets: Vec<String>) -> SummaryResult {
    SummaryResult {}
}
"#,
        ),
        (
            "src/b.rs",
            r#"
fn summarize_symbol_targets(targets: Vec<String>) -> SummaryResult {
    SummaryResult {}
}

pub fn get_summaries(params: SummariesParams) -> SummaryResult {
    summarize_symbol_targets(params.targets)
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "a.summarize_symbol_targets");
    let candidates = [ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "src/b.rs",
    )]
    .into_iter()
    .collect();

    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("cross-module private success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_does_not_seed_pub_self_exports() {
    let (_project, analyzer) =
        rust_analyzer_with_files(&[("src/service.rs", "pub(self) struct Hidden;\n")]);
    let target = definition(&analyzer, "service.Hidden");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("pub(self) local declaration scan success");
    assert!(
        hits.is_empty(),
        "pub(self) item has no references: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_keeps_pub_crate_exports_graph_visible() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub(crate) struct Local;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Local;

fn run() {
    let _ = Local {};
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "service.Local");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("pub(crate) success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_reads_visibility_from_tree_sitter_nodes() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub(in crate::service) struct Scoped;
pub/**/ struct CommentedPublic;
struct Private;

fn internal(scoped: Scoped, private: Private) { // VALID_IN_DOMAIN
    let _ = (scoped, private);
}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::{CommentedPublic, Private, Scoped};

fn run() {
    let _ = Scoped {}; // INVALID_SCOPED_DECOY
    let _ = CommentedPublic {}; // VALID_PUBLIC
    let _ = Private {}; // INVALID_PRIVATE_DECOY
}
"#,
        ),
    ]);
    let scoped = definition(&analyzer, "service.Scoped");
    let commented = definition(&analyzer, "service.CommentedPublic");
    let private = definition(&analyzer, "service.Private");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    let scoped_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&scoped), &candidates, 1000)
        .into_either()
        .expect("scoped visibility success");
    assert_eq!(1, scoped_hits.len(), "scoped visibility: {scoped_hits:#?}");
    assert!(
        scoped_hits
            .iter()
            .all(|hit| hit.file == project.file("src/service.rs")),
        "pub(in crate::service) must stay inside service: {scoped_hits:#?}"
    );

    let commented_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&commented),
            &candidates,
            1000,
        )
        .into_either()
        .expect("commented pub visibility success");
    assert_eq!(
        1,
        commented_hits.len(),
        "commented pub visibility: {commented_hits:#?}"
    );
    assert!(
        commented_hits
            .iter()
            .all(|hit| hit.file == project.file("src/main.rs")),
        "comment-separated pub must remain public: {commented_hits:#?}"
    );

    let private_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&private), &candidates, 1000)
        .into_either()
        .expect("private local declaration scan success");
    assert_eq!(
        1,
        private_hits.len(),
        "private visibility: {private_hits:#?}"
    );
    assert!(
        private_hits
            .iter()
            .all(|hit| hit.file == project.file("src/service.rs")),
        "private item must stay inside service: {private_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_barrel_reexport_from_private_module() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service;
mod consumer;
pub use service::Foo;
"#,
        ),
        ("src/service.rs", "pub struct Foo;\n"),
        (
            "src/consumer.rs",
            r#"
use crate::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    let hits = result.into_either().expect("barrel reexport success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_treat_self_reexport_as_public_barrel() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service;
mod child;
pub(self) use service::Foo;

fn local(value: Foo) { // VALID_ROOT_USE
    let _ = value;
}
"#,
        ),
        ("src/service.rs", "pub struct Foo;\n"),
        (
            "src/child.rs",
            r#"
use super::Foo;

fn child(value: Foo) { // VALID_DESCENDANT_USE
    let _ = value;
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::Foo;

fn run() {
    let _ = Foo {}; // INVALID_CROSS_ROOT_DECOY
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("pub(self) local declaration scan success");
    assert_eq!(2, hits.len(), "module-private alias routing: {hits:#?}");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/lib.rs"))
            && hits
                .iter()
                .any(|hit| hit.file == project.file("src/child.rs")),
        "pub(self) alias must remain usable in its module and descendants: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("src/main.rs")),
        "pub(self) use must not expose Foo as a public barrel reexport: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_chained_and_aliased_barrel_reexports() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub struct Bar;
"#,
        ),
        (
            "src/first.rs",
            r#"
pub use crate::service::{Foo, Bar as PublicBar};
"#,
        ),
        (
            "src/second.rs",
            r#"
pub use crate::first::Foo;
pub use crate::first::PublicBar;
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;
mod first;
mod second;
use crate::second::{Foo, PublicBar};

fn run() {
    let _ = Foo {};
    let _ = PublicBar {};
}
"#,
        ),
    ]);

    let foo = definition(&analyzer, "service.Foo");
    let bar = definition(&analyzer, "service.Bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&foo), &candidates, 1000)
            .into_either()
            .expect("chained Foo success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&bar), &candidates, 1000)
            .into_either()
            .expect("chained Bar success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_uses_simple_type_alias_as_receiver_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

type Alias = Foo;

fn run(value: Alias) {
    value.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("type alias receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_uses_self_like_constructor_chain_as_receiver_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct ChangeDelta;
pub struct ProjectChangeWatcher;
impl ProjectChangeWatcher {
    pub fn start() -> Result<Self, String> {
        todo!()
    }
    pub fn other() -> ChangeDelta {
        todo!()
    }
    pub fn take_changed_files(&self) -> ChangeDelta {
        todo!()
    }
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::ProjectChangeWatcher;

fn run() {
    let watcher = ProjectChangeWatcher::start().unwrap();
    watcher.take_changed_files();
}

fn unrelated() {
    let delta = ProjectChangeWatcher::other();
    delta.take_changed_files();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "ProjectChangeWatcher",
        "take_changed_files",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("self-like constructor success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_bounded_glob_imports_for_public_exports_only() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
struct Hidden;
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let _ = Foo {};
    let _ = Hidden {};
}
"#,
        ),
    ]);

    let foo = definition(&analyzer, "service.Foo");
    let hidden = definition(&analyzer, "service.Hidden");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&foo), &candidates, 1000)
            .into_either()
            .expect("glob Foo success")
            .len()
    );
    let hidden_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&hidden), &candidates, 1000)
        .into_either()
        .expect("private glob local declaration scan success");
    assert!(
        hidden_hits.is_empty(),
        "glob imports only bind public exports: {hidden_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_bounded_glob_reexports() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Foo;\n"),
        ("src/index.rs", "pub use crate::service::*;\n"),
        (
            "src/main.rs",
            r#"
mod service;
mod index;
use crate::index::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let foo = definition(&analyzer, "service.Foo");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&foo),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("glob reexport success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_enum_variants_as_associated_fields() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub enum Foo {
    Variant,
    TupleVariant(usize),
    StructVariant { value: usize },
}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;

use crate::service::Foo;

fn run() {
    let _ = Foo::Variant;
    let _ = Foo::TupleVariant(1);
    let _ = Foo::StructVariant { value: 1 };
}
"#,
        ),
    ]);

    let variant = member(&analyzer, &project.file("src/service.rs"), "Foo", "Variant");
    let tuple_variant = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Foo",
        "TupleVariant",
    );
    let struct_variant = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Foo",
        "StructVariant",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&variant), &candidates, 1000)
            .into_either()
            .expect("variant success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&tuple_variant),
                &candidates,
                1000,
            )
            .into_either()
            .expect("tuple variant success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&struct_variant),
                &candidates,
                1000,
            )
            .into_either()
            .expect("struct variant success")
            .len()
    );
}

#[test]
fn rust_reexported_types_and_tuple_variant_patterns_keep_exact_identity() {
    let consumer = r#"
use crate::{Lifecycle, PublicType};
use dep_alias::{Lifecycle as DepLifecycle, PublicType as DepPublicType};

fn named(_: PublicType) {}
fn qualified(_: crate::PublicType) {}
fn dependency(_: DepPublicType) {}

fn named_pattern(value: Lifecycle) {
    match value {
        Lifecycle::Completed(_) => {} // NAMED_VARIANT
        Lifecycle::Ready => {}
    }
}

fn qualified_pattern(value: crate::Lifecycle) {
    match value {
        crate::Lifecycle::Completed(_) => {} // CRATE_QUALIFIED_VARIANT
        crate::Lifecycle::Ready => {}
    }
}

fn dependency_pattern(value: DepLifecycle) {
    match value {
        DepLifecycle::Completed(_) => {} // DEPENDENCY_VARIANT_DECOY
        DepLifecycle::Ready => {}
    }
}
"#;
    let binary = r#"
struct PublicType;
enum Lifecycle { Completed(usize), Ready }
fn main() {
    let _: Option<PublicType> = None;
    if let Lifecycle::Completed(_) = Lifecycle::Ready {} // CARGO_TARGET_VARIANT_DECOY
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"identity-routes\"\nversion = \"0.1.0\"\n[dependencies]\ndep_alias = { path = \"dep\" }\n",
        ),
        (
            "src/lib.rs",
            "mod model; mod consumer;\npub use model::{Lifecycle, PublicType};\n",
        ),
        (
            "src/model.rs",
            "pub struct PublicType;\npub enum Lifecycle { Completed(usize), Ready }\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", binary),
        (
            "dep/Cargo.toml",
            "[package]\nname = \"dep_alias\"\nversion = \"0.1.0\"\n",
        ),
        (
            "dep/src/lib.rs",
            "pub struct PublicType;\npub enum Lifecycle { Completed(usize), Ready }\n",
        ),
    ]);
    let model_file = project.file("src/model.rs");
    let consumer_file = project.file("src/consumer.rs");
    let public_type = definition(&analyzer, "model.PublicType");
    let completed = member(&analyzer, &model_file, "Lifecycle", "Completed");
    let candidates: HashSet<ProjectFile> = analyzer.get_analyzed_files().into_iter().collect();

    let type_hits = authoritative_hits(&analyzer, &public_type, candidates.clone());
    let variant_hits = authoritative_hits(&analyzer, &completed, candidates);
    let named_type = consumer.find("named(_: PublicType)").expect("named type") + "named(_: ".len();
    let qualified_type = consumer
        .find("qualified(_: crate::PublicType)")
        .expect("qualified type")
        + "qualified(_: crate::".len();
    assert_eq!(
        vec![named_type, qualified_type],
        type_hits
            .iter()
            .filter(|hit| hit.file == consumer_file)
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "named and crate-qualified uses must resolve through the public re-export: {type_hits:#?}"
    );
    assert!(
        type_hits.iter().all(|hit| {
            hit.file != project.file("dep/src/lib.rs") && hit.file != project.file("src/main.rs")
        }),
        "same-name dependency and Cargo-target types must stay unrelated: {type_hits:#?}"
    );

    let named_variant = consumer
        .find("Lifecycle::Completed")
        .expect("named variant pattern")
        + "Lifecycle::".len();
    let qualified_variant = consumer
        .find("crate::Lifecycle::Completed")
        .expect("qualified variant pattern")
        + "crate::Lifecycle::".len();
    assert_eq!(
        vec![named_variant, qualified_variant],
        variant_hits
            .iter()
            .filter(|hit| hit.file == consumer_file)
            .map(|hit| hit.start_offset)
            .collect::<Vec<_>>(),
        "named and crate-qualified tuple-variant patterns must retain exact terminal ranges: {variant_hits:#?}"
    );
    assert!(
        variant_hits.iter().all(|hit| {
            hit.file != project.file("dep/src/lib.rs") && hit.file != project.file("src/main.rs")
        }),
        "same-name dependency and Cargo-target variants must stay unrelated: {variant_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_associated_type_as_static_field() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Trait {
    type AssocType;
}

pub struct Foo;
impl Trait for Foo {
    type AssocType = usize;
}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;

use crate::service::{Foo, Trait};

fn run(_: Foo::AssocType) {}
"#,
        ),
    ]);

    let assoc_type = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Trait",
        "AssocType",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&assoc_type),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("associated type success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_resolve_private_item_behind_barrel_reexport() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service;
pub use service::Hidden;
"#,
        ),
        ("src/service.rs", "struct Hidden;\n"),
        (
            "src/main.rs",
            r#"
use crate::Hidden;

fn run() {
    let _ = Hidden {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Hidden");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("private item behind reexport local scan success");
    assert!(
        hits.iter().all(|hit| hit.file
            != ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs")),
        "private item is not exposed as a public barrel reexport: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_seeds_receiver_from_self_field_as_ref_let_else() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct ChangeDelta;
pub struct ProjectChangeWatcher;
impl ProjectChangeWatcher {
    pub fn take_changed_files(&self) -> ChangeDelta {
        todo!()
    }
}

pub struct SearchToolsService {
    watcher: Option<ProjectChangeWatcher>,
}
impl SearchToolsService {
    pub fn apply_watcher_delta(&mut self) {
        let Some(watcher) = self.watcher.as_ref() else {
            return;
        };
        watcher.take_changed_files();
    }
}
"#,
    )]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "ProjectChangeWatcher",
        "take_changed_files",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("self field let-else success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_seed_receiver_from_wrapped_pattern_destructuring() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct ProjectChangeWatcher;
impl ProjectChangeWatcher {
    pub fn take_changed_files(&self) {}
}

pub struct Other;
impl Other {
    pub fn take_changed_files(&self) {}
}

pub struct SearchToolsService {
    watcher: Option<(ProjectChangeWatcher, Other)>,
}
impl SearchToolsService {
    pub fn apply_watcher_delta(&mut self) {
        let Some((watcher, other)) = self.watcher.as_ref() else {
            return;
        };
        watcher.take_changed_files();
        other.take_changed_files();
    }
}
"#,
    )]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "ProjectChangeWatcher",
        "take_changed_files",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("wrapped destructuring success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_does_not_seed_receiver_from_tuple_destructuring_patterns() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn foo_method(&self) {}
}

pub struct Bar;
impl Bar {
    pub fn foo_method(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{Bar, Foo};

fn tuple_parameter((foo, _bar): (Foo, Bar)) {
    foo.foo_method();
}

fn tuple_let(pair: (Foo, Bar)) {
    let (foo, _bar): (Foo, Bar) = pair;
    foo.foo_method();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Bar",
        "foo_method",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("tuple destructuring success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_resolves_trait_method_for_explicit_trait_path_and_proven_receiver() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub trait Worker {
    fn work(&self);
}
impl Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
mod service;

use crate::service::{Foo, Worker};

fn run() {
    let x: Foo = Foo {};
    Worker::work(&x);
    x.work();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Worker", "work");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("trait method success");
    assert_eq!(2, hits.len());
}

#[test]
fn rust_graph_strategy_reads_trait_impls_from_tree_sitter_nodes() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/traits.rs",
            r#"
pub trait Worker {
    fn work(&self);
}
"#,
        ),
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl /* trait impl */ crate::traits::Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.work();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/traits.rs"), "Worker", "work");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("commented trait impl success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_requires_proven_trait_impl_and_receiver_type() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub trait Worker {
    fn work(&self);
}
pub trait Other {
    fn work(&self);
}
impl Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn known() {
    let x: Foo = Foo {};
    x.work();
}

fn unknown(x: impl std::fmt::Debug) {
    x.work();
}
"#,
        ),
    ]);

    let worker = member(&analyzer, &project.file("src/service.rs"), "Worker", "work");
    let other = member(&analyzer, &project.file("src/service.rs"), "Other", "work");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&worker), &candidates, 1000)
            .into_either()
            .expect("Worker trait receiver success")
            .len()
    );
    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&other), &candidates, 1000)
            .into_either()
            .expect("Other trait receiver success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_resolves_cross_file_trait_impl_to_trait_owner_file() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/traits.rs",
            r#"
pub trait Worker {
    fn work(&self);
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub trait Worker {
    fn work(&self);
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::traits::Worker;

pub struct Foo;
impl Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.work();
}
"#,
        ),
    ]);

    let traits_target = member(
        &analyzer,
        &ProjectFile::new(analyzer.project().root().to_path_buf(), "src/traits.rs"),
        "Worker",
        "work",
    );
    let other_target = member(
        &analyzer,
        &ProjectFile::new(analyzer.project().root().to_path_buf(), "src/other.rs"),
        "Worker",
        "work",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&traits_target),
                &candidates,
                1000,
            )
            .into_either()
            .expect("traits owner success")
            .len()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&other_target),
                &candidates,
                1000,
            )
            .into_either()
            .expect("other owner success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_resolves_dyn_and_impl_trait_receivers() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub trait Worker {
    fn work(&self);
}
pub trait Other {
    fn work(&self);
}
impl Worker for Foo {
    fn work(&self) {}
}
pub struct Inherent;
impl Inherent {
    pub fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{Inherent, Other, Worker};

fn generic<T: Worker>(x: T) {
    x.work();
}

fn opaque(x: impl Worker) {
    x.work();
}

fn dynamic(x: &dyn Worker) {
    x.work();
}

fn bounded_opaque(x: impl Worker + Send) {
    x.work();
}

fn bounded_dynamic(x: &dyn Worker + Send) {
    x.work();
}

fn higher_ranked_dynamic(x: &dyn for<'a> Worker) {
    x.work();
}

fn other_opaque(x: impl Other) {
    x.work();
}

fn other_dynamic(x: &dyn Other) {
    x.work();
}

fn other_bounded_opaque(x: impl Other + Send) {
    x.work();
}

fn other_bounded_dynamic(x: &dyn Other + Send) {
    x.work();
}

fn other_higher_ranked_dynamic(x: &dyn for<'a> Other) {
    x.work();
}

fn inherent(x: &Inherent) {
    x.work();
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();
    for (owner, expected) in [("Worker", 5), ("Other", 5), ("Inherent", 1)] {
        let target = member(&analyzer, &project.file("src/service.rs"), owner, "work");
        let hits = strategy
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
            .into_either()
            .expect("structured trait receiver success");
        assert_eq!(
            expected,
            hits.len(),
            "{owner}.work receiver hits: {hits:#?}"
        );
    }
}

#[test]
fn rust_graph_strategy_resolves_public_inline_module_exports() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub mod service;
mod consumer;
pub mod inline {
    pub struct Inline;
}
"#,
        ),
        ("src/service.rs", "pub struct FileBacked;\n"),
        (
            "src/consumer.rs",
            r#"
use crate::service::FileBacked;
use crate::inline::Inline;

fn run() {
    let _ = FileBacked {};
    let _ = Inline {};
}
"#,
        ),
    ]);

    let file_backed = definition(&analyzer, "service.FileBacked");
    let inline = definition(&analyzer, "inline.Inline");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&file_backed),
                &candidates,
                1000
            )
            .into_either()
            .expect("file-backed module success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&inline), &candidates, 1000)
            .into_either()
            .expect("inline module success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_resolves_basic_crate_import_struct_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Service;

fn run() {
    let _ = Service::new();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("crate import success");
    assert_eq!(1, hits.len());
}

#[test]
fn authoritative_rust_member_scan_resolves_associated_call_through_star_reexport() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "pub mod layer;\npub mod filter;\n"),
        (
            "src/layer/mod.rs",
            "mod context;\npub use self::context::*;\n",
        ),
        (
            "src/layer/context.rs",
            r#"
pub struct Context<S> {
    value: Option<S>,
}

impl<S> Context<S> {
    pub(crate) fn none() -> Self {
        Self { value: None }
    }
}
"#,
        ),
        (
            "src/filter.rs",
            r#"
use crate::layer::Context;

pub fn disabled<S>() -> bool {
    let _ = Context::<S>::none();
    true
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/layer/context.rs"),
        "Context",
        "none",
    );
    let candidates = [project.file("src/filter.rs")].into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("authoritative associated call lookup");

    assert_eq!(
        1,
        hits.len(),
        "associated call through star reexport: {hits:#?}"
    );
    assert!(
        hits.iter()
            .next()
            .is_some_and(|hit| hit.snippet.contains("Context::<S>::none"))
    );
}

#[test]
fn rust_associated_generic_owner_resolution_is_qualified_alias_exact_and_glob_safe() {
    let consumer = r#"
use crate::facade::AliasedContext;

fn valid() {
    let _ = crate::target::Context::<u8>::none(); // QUALIFIED_GENERIC_OWNER
    let _ = AliasedContext::<u8>::none(); // ALIASED_GENERIC_OWNER
}
"#;
    let ambiguous = r#"
use crate::decoy::*;
use crate::target::*;

fn invalid() {
    let _ = Context::<u8>::none(); // AMBIGUOUS_GLOB_OWNER
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub mod target;\npub mod facade;\npub mod decoy;\nmod consumer;\nmod ambiguous;\n",
        ),
        (
            "src/target.rs",
            "pub struct Context<S>(pub Option<S>);\nimpl<S> Context<S> { pub fn none() -> Self { Self(None) } }\n",
        ),
        (
            "src/decoy.rs",
            "pub struct Context<S>(pub Option<S>);\nimpl<S> Context<S> { pub fn none() -> Self { Self(None) } }\n",
        ),
        (
            "src/facade.rs",
            "pub use crate::target::Context as AliasedContext;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/ambiguous.rs", ambiguous),
    ]);
    let target = member(&analyzer, &project.file("src/target.rs"), "Context", "none");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("generic associated-owner scan");

    assert_eq!(2, hits.len(), "qualified/aliased generic owners: {hits:#?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/consumer.rs"))
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("QUALIFIED_GENERIC_OWNER"))
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("ALIASED_GENERIC_OWNER"))
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("AMBIGUOUS_GLOB_OWNER"))
    );
}

#[test]
fn rust_associated_owner_resolution_rejects_same_fqn_from_another_physical_root() {
    let consumer = r#"
fn valid() {
    let _ = crate::Context::<u8>::none(); // LIBRARY_CONTEXT_OWNER
}
"#;
    let main = r#"
struct Context<S>(Option<S>);
impl<S> Context<S> { fn none() -> Self { Self(None) } }
fn invalid() {
    let _ = Context::<u8>::none(); // BINARY_CONTEXT_DECOY
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub struct Context<S>(pub Option<S>);\nimpl<S> Context<S> { pub fn none() -> Self { Self(None) } }\nmod consumer;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "Context", "none");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("same-FQN owner scan");

    assert_eq!(1, hits.len(), "same-FQN physical owners: {hits:#?}");
    let hit = hits.iter().next().expect("library owner usage");
    assert_eq!(project.file("src/consumer.rs"), hit.file);
    assert!(hit.snippet.contains("LIBRARY_CONTEXT_OWNER"));
}

#[test]
fn rust_trait_associated_fallback_preserves_exact_same_fqn_implementer() {
    let consumer = r#"
use crate::{Foo, T};
fn valid() { Foo::f(); } // LIBRARY_TRAIT_ASSOCIATED
"#;
    let main = r#"
trait T { fn f(); }
struct Foo;
impl T for Foo {}
fn decoy() { Foo::f(); } // BINARY_TRAIT_DECOY
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub trait T { fn f(); }\npub struct Foo;\nimpl T for Foo {}\nmod consumer;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "T", "f");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("exact same-FQN trait implementer scan");

    assert_eq!(1, hits.len(), "same-FQN trait implementers: {hits:#?}");
    let hit = hits.iter().next().expect("library trait associated usage");
    assert_eq!(project.file("src/consumer.rs"), hit.file);
    assert!(hit.snippet.contains("LIBRARY_TRAIT_ASSOCIATED"));
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("BINARY_TRAIT_DECOY"))
    );
}

#[test]
fn rust_inherent_associated_owner_resolves_exact_type_alias_without_cross_root_decoy() {
    let consumer = r#"
use crate::Alias;
fn valid() { let _ = Alias::new(); } // LIBRARY_ALIAS_ASSOCIATED
"#;
    let main = r#"
struct Other;
impl Other { fn new() -> Self { Self } }
type Alias = Other;
fn decoy() { let _ = Alias::new(); } // BINARY_ALIAS_DECOY
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub struct Foo;\nimpl Foo { pub fn new() -> Self { Self } }\npub type Alias = Foo;\nmod consumer;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "Foo", "new");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("exact inherent alias owner scan");

    assert_eq!(1, hits.len(), "same-named alias roots: {hits:#?}");
    let hit = hits.iter().next().expect("library alias associated usage");
    assert_eq!(project.file("src/consumer.rs"), hit.file);
    assert!(hit.snippet.contains("LIBRARY_ALIAS_ASSOCIATED"));
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("BINARY_ALIAS_DECOY"))
    );
}

#[test]
fn rust_token_tree_associated_owner_rejects_same_fqn_physical_decoy() {
    let consumer = r#"
macro_rules! wrap { ($value:expr) => { $value }; }
use crate::Foo;
fn valid() { let _ = wrap!(Foo::new()); } // LIBRARY_TOKEN_ASSOCIATED
"#;
    let main = r#"
macro_rules! wrap { ($value:expr) => { $value }; }
struct Foo;
impl Foo { fn new() -> Self { Self } }
fn decoy() { let _ = wrap!(Foo::new()); } // BINARY_TOKEN_DECOY
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub struct Foo;\nimpl Foo { pub fn new() -> Self { Self } }\nmod consumer;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "Foo", "new");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("exact token-tree owner scan");

    assert_eq!(1, hits.len(), "same-FQN token owners: {hits:#?}");
    let hit = hits.iter().next().expect("library token-tree usage");
    assert_eq!(project.file("src/consumer.rs"), hit.file);
    assert!(hit.snippet.contains("LIBRARY_TOKEN_ASSOCIATED"));
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("BINARY_TOKEN_DECOY"))
    );
}

#[test]
fn rust_qualified_token_tree_trait_call_preserves_exact_implementer() {
    let consumer = r#"
macro_rules! wrap { ($value:expr) => { $value }; }
use crate::T;
fn valid() { wrap!(crate::Foo::f()); } // LIBRARY_QUALIFIED_TOKEN_TRAIT
"#;
    let main = r#"
macro_rules! wrap { ($value:expr) => { $value }; }
trait T { fn f(); }
struct Foo;
impl T for Foo {}
fn decoy() { wrap!(Foo::f()); } // BINARY_QUALIFIED_TOKEN_DECOY
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub trait T { fn f(); }\npub struct Foo;\nimpl T for Foo {}\nmod consumer;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "T", "f");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("qualified token-tree trait scan");

    assert_eq!(1, hits.len(), "qualified token trait owners: {hits:#?}");
    let hit = hits.iter().next().expect("qualified library token usage");
    assert_eq!(project.file("src/consumer.rs"), hit.file);
    assert!(hit.snippet.contains("LIBRARY_QUALIFIED_TOKEN_TRAIT"));
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("BINARY_QUALIFIED_TOKEN_DECOY"))
    );
}

#[test]
fn rust_trait_visibility_respects_function_local_import_extent() {
    let source = r#"
mod model {
    pub trait T { fn f(); }
    pub struct Foo;
    impl T for Foo {}
}

use model::Foo;
fn valid() {
    use model::T;
    Foo::f(); // LOCAL_TRAIT_VISIBLE
}
fn sibling() {
    Foo::f(); // LOCAL_TRAIT_OUT_OF_SCOPE
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "T", "f");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("function-local trait visibility scan");

    assert_eq!(1, hits.len(), "function-local trait imports: {hits:#?}");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("LOCAL_TRAIT_VISIBLE"))
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("LOCAL_TRAIT_OUT_OF_SCOPE"))
    );
}

#[test]
fn rust_trait_visibility_rejects_cross_root_same_fqn_local_trait() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"demo-app\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "pub trait Trait { fn f(); }\npub struct Foo;\nimpl Trait for Foo {}\n",
        ),
        (
            "src/main.rs",
            r#"
use demo_app::Foo;
trait Trait { fn f(); }
fn decoy() { Foo::f(); } // LOCAL_SAME_FQN_TRAIT_DECOY
"#,
        ),
    ]);
    let target = member(&analyzer, &project.file("src/lib.rs"), "Trait", "f");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("cross-root trait visibility scan");

    assert!(
        hits.is_empty(),
        "cross-root same-FQN trait decoy: {hits:#?}"
    );
}

#[test]
fn rust_associated_member_visibility_distinguishes_crate_and_dependency_domains() {
    let dependency_consumer = r#"
use crate::PublicOwner;
fn valid() { let _ = PublicOwner::hidden(); } // SAME_CRATE_HIDDEN
"#;
    let downstream_consumer = r#"
use dep_alias::PublicOwner;
fn run() {
    let _ = PublicOwner::hidden(); // DOWNSTREAM_HIDDEN_DECOY
    let _ = PublicOwner::visible(); // DOWNSTREAM_PUBLIC
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ndep_alias = { package = \"dep-package\", path = \"dep\" }\n",
        ),
        ("src/lib.rs", "mod consumer;\n"),
        ("src/consumer.rs", downstream_consumer),
        (
            "dep/Cargo.toml",
            "[package]\nname = \"dep-package\"\nversion = \"0.1.0\"\n",
        ),
        (
            "dep/src/lib.rs",
            "pub struct PublicOwner;\nimpl PublicOwner { pub(crate) fn hidden() {} pub fn visible() {} }\nmod local_consumer;\n",
        ),
        ("dep/src/local_consumer.rs", dependency_consumer),
    ]);
    let hidden = member(
        &analyzer,
        &project.file("dep/src/lib.rs"),
        "PublicOwner",
        "hidden",
    );
    let visible = member(
        &analyzer,
        &project.file("dep/src/lib.rs"),
        "PublicOwner",
        "visible",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();
    let hidden_hits = strategy
        .find_usages(&analyzer, &[hidden], &candidates, 1000)
        .into_either()
        .expect("pub(crate) associated visibility");
    let visible_hits = strategy
        .find_usages(&analyzer, &[visible], &candidates, 1000)
        .into_either()
        .expect("public dependency associated visibility");

    assert_eq!(
        1,
        hidden_hits.len(),
        "pub(crate) visibility: {hidden_hits:#?}"
    );
    let hidden_hit = hidden_hits.iter().next().expect("same-crate hidden usage");
    assert_eq!(project.file("dep/src/local_consumer.rs"), hidden_hit.file);
    assert!(hidden_hit.snippet.contains("SAME_CRATE_HIDDEN"));
    assert!(
        hidden_hits
            .iter()
            .all(|hit| !hit.snippet.contains("DOWNSTREAM_HIDDEN_DECOY"))
    );
    assert_eq!(
        1,
        visible_hits.len(),
        "public visibility: {visible_hits:#?}"
    );
    let visible_hit = visible_hits.iter().next().expect("dependency public usage");
    assert_eq!(project.file("src/consumer.rs"), visible_hit.file);
    assert!(visible_hit.snippet.contains("DOWNSTREAM_PUBLIC"));
}

#[test]
fn rust_graph_strategy_counts_type_argument_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Foo;\n"),
        (
            "src/main.rs",
            r#"
mod service;
use crate::service::Foo;
use std::collections::HashMap;

struct Holder {
    a: Vec<Foo>,
    b: Option<Foo>,
    c: HashMap<String, Foo>,
    d: Result<Vec<Foo>, Error>,
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("type argument success");
    assert_eq!(4, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_resolve_private_inherent_associated_items() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    fn private(&self) {}
    const PRIVATE: usize = 1;
    type Private = usize;
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let x: Foo = Foo {};
    x.private();
    let _ = Foo::PRIVATE;
    let _: Foo::Private;
}
"#,
        ),
    ]);

    let private_method = member(&analyzer, &project.file("src/service.rs"), "Foo", "private");
    let private_const = member(&analyzer, &project.file("src/service.rs"), "Foo", "PRIVATE");
    let private_type = member(&analyzer, &project.file("src/service.rs"), "Foo", "Private");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&private_method),
                &candidates,
                1000,
            )
            .into_either()
            .expect("private method success")
            .is_empty()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&private_const),
                &candidates,
                1000,
            )
            .into_either()
            .expect("private const success")
            .is_empty()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&private_type),
                &candidates,
                1000,
            )
            .into_either()
            .expect("private type success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_records_external_frontier_for_unresolved_public_reexport() {
    let (project, analyzer) =
        rust_analyzer_with_files(&[("src/index.rs", "pub use external_crate::Foo;\n")]);

    let index_file = project.file("src/index.rs");
    let candidates = [index_file.clone()].into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::find_export_usages(
        &analyzer,
        &index_file,
        "Foo",
        None,
        &candidates,
        1000,
    );

    assert!(result.hits.is_empty());
    assert!(
        result
            .external_frontier_specifiers
            .contains("external_crate")
    );
}

#[test]
fn rust_graph_strategy_records_external_frontier_for_unresolved_glob_reexport() {
    let (project, analyzer) =
        rust_analyzer_with_files(&[("src/index.rs", "pub use external_crate::*;\n")]);

    let index_file = project.file("src/index.rs");
    let candidates = [index_file.clone()].into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::find_export_usages(
        &analyzer,
        &index_file,
        "Foo",
        None,
        &candidates,
        1000,
    );

    assert!(result.hits.is_empty());
    assert!(
        result
            .external_frontier_specifiers
            .contains("external_crate")
    );
}

#[test]
fn rust_graph_strategy_finds_private_inline_module_usages_via_named_import() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service {
    pub struct Foo;
}
mod consumer;
"#,
        ),
        (
            "src/consumer.rs",
            r#"
use crate::service::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    assert_eq!(
        1,
        result
            .into_either()
            .expect("private inline module local scan success")
            .len()
    );
}

#[test]
fn rust_graph_seeds_keep_same_named_inline_declarations_distinct() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
mod left {
    pub struct Owner;

    fn consume(value: Owner) { // LEFT_OWNER_USE
        let _ = value;
    }
}

mod right {
    pub struct Owner;

    fn consume(value: Owner) { // RIGHT_OWNER_USE
        let _ = value;
    }
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "left.Owner");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("LEFT_OWNER_USE")),
        "expected the exact inline-module declaration usage: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("RIGHT_OWNER_USE")),
        "same-named declaration in a sibling inline module must not match: {hits:#?}"
    );
}

#[test]
fn rust_graph_seeds_preserve_exact_inline_identity_through_reexport_aliases() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod left { pub struct Owner; }
mod right { pub struct Owner; }

pub use left::Owner as LeftOwner;
pub use right::Owner as RightOwner;
mod consumer;
"#,
        ),
        (
            "src/consumer.rs",
            r#"
use crate::{LeftOwner, RightOwner};

fn consume_left(value: LeftOwner) { // LEFT_ALIAS_USE
    let _ = value;
}

fn consume_right(value: RightOwner) { // RIGHT_ALIAS_USE
    let _ = value;
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "left.Owner");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("LEFT_ALIAS_USE")),
        "expected the alias chain rooted at the exact declaration: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("RIGHT_ALIAS_USE")),
        "the sibling declaration's alias chain must remain distinct: {hits:#?}"
    );
}

#[test]
fn rust_graph_seeds_keep_same_named_nested_private_modules_distinct() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
mod left {
    mod shared { pub struct Item; }
    use self::shared as selected;
    fn consume(_: selected::Item) {} // LEFT_SHARED_USE
}
mod right {
    mod shared { pub struct Item; }
    use self::shared as selected;
    fn consume(_: selected::Item) {} // RIGHT_SHARED_USE
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "left.shared.Item");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("LEFT_SHARED_USE")),
        "expected the exact nested module usage: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("RIGHT_SHARED_USE")),
        "same-named nested private module must not cross-match: {hits:#?}"
    );
}

#[test]
fn rust_graph_aliases_preserve_type_and_value_namespaces() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
mod source {
    pub struct Same { pub value: usize }
    #[allow(non_snake_case)]
    pub fn Same() {}
}
use source::Same as Alias;
fn type_consumer(_: Alias) {} // TYPE_ALIAS_USE

// namespace separation padding
// namespace separation padding
// namespace separation padding
// namespace separation padding
// namespace separation padding
fn value_consumer() { Alias(); } // VALUE_ALIAS_USE
"#,
    )]);
    let definitions = analyzer.get_definitions("source.Same");
    let type_target = definitions
        .iter()
        .find(|definition| definition.is_class())
        .cloned()
        .expect("type declaration");
    let value_target = definitions
        .iter()
        .find(|definition| definition.is_function())
        .cloned()
        .expect("value declaration");
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let type_hits = strategy
        .find_usages(&analyzer, &[type_target], &candidates, 1000)
        .into_either()
        .expect("type alias usage success");
    let value_hits = strategy
        .find_usages(&analyzer, &[value_target], &candidates, 1000)
        .into_either()
        .expect("value alias usage success");

    assert!(
        type_hits
            .iter()
            .any(|hit| hit.snippet.contains("TYPE_ALIAS_USE"))
    );
    assert!(
        type_hits
            .iter()
            .all(|hit| !hit.snippet.contains("VALUE_ALIAS_USE"))
    );
    assert!(
        value_hits
            .iter()
            .any(|hit| hit.snippet.contains("VALUE_ALIAS_USE"))
    );
    assert!(
        value_hits
            .iter()
            .all(|hit| !hit.snippet.contains("TYPE_ALIAS_USE"))
    );
}

#[test]
fn rust_graph_aliases_preserve_macro_and_value_namespaces() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
macro_rules! same { () => {}; }
fn same() {}
mod consumer {
    use super::same as alias;
    fn run() {
        alias!(); // MACRO_ALIAS_USE

        // namespace separation padding
        // namespace separation padding
        // namespace separation padding
        // namespace separation padding
        // namespace separation padding
        alias(); // VALUE_ALIAS_USE
    }
}

"#,
    )]);
    let definitions = analyzer.get_definitions("same");
    let macro_target = definitions
        .iter()
        .find(|definition| definition.is_macro())
        .cloned()
        .expect("macro declaration");
    let value_target = definitions
        .iter()
        .find(|definition| definition.is_function())
        .cloned()
        .expect("value declaration");
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let macro_hits = strategy
        .find_usages(&analyzer, &[macro_target], &candidates, 1000)
        .into_either()
        .expect("macro alias usage success");
    let value_hits = strategy
        .find_usages(&analyzer, &[value_target], &candidates, 1000)
        .into_either()
        .expect("value alias usage success");

    assert!(
        macro_hits
            .iter()
            .any(|hit| hit.snippet.contains("MACRO_ALIAS_USE"))
    );
    assert!(
        macro_hits
            .iter()
            .all(|hit| !hit.snippet.contains("VALUE_ALIAS_USE"))
    );
    assert!(
        value_hits
            .iter()
            .any(|hit| hit.snippet.contains("VALUE_ALIAS_USE"))
    );
    assert!(
        value_hits
            .iter()
            .all(|hit| !hit.snippet.contains("MACRO_ALIAS_USE"))
    );
}

#[test]
fn rust_graph_tracks_bare_macro_invocations_through_structured_visibility() {
    let definitions = r#"
macro_rules! target_macro { () => {}; }
macro_rules! wrapper { ($($tokens:tt)*) => {}; }
pub(crate) use target_macro;
pub fn target_macro() {}
fn direct() {
    let target_macro = 1;
    target_macro!(); // DIRECT_MACRO_USE
    let _ = target_macro; // SAME_NAME_VALUE_USE
    wrapper! { target_macro!() } // NESTED_MACRO_USE
    wrapper!(target_macro); // BARE_MACRO_ARGUMENT
}
"#;
    let consumer = r#"
use crate::definitions::target_macro as imported_macro;
use crate::exports::exported_macro;
fn target_macro() {}
fn run() {
    let target_macro = 1;
    target_macro!(); // MACRO_USE_INHERITED
    imported_macro!(); // MACRO_USE_IMPORTED
    exported_macro!(); // MACRO_USE_REEXPORTED
    crate::definitions::target_macro!(); // MACRO_USE_QUALIFIED
    target_macro(); // SAME_NAME_FUNCTION_USE
    let _ = target_macro; // SAME_NAME_LOCAL_USE
}
mod shadowed {
    macro_rules! target_macro { () => {}; }
    fn run() { target_macro!(); } // SHADOW_MACRO_USE
}
"#;
    let early = "target_macro!(); // INVISIBLE_EARLY_USE\n";
    let private_consumer = "private_macro!(); // INVISIBLE_PRIVATE_USE\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"macro-demo\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "mod early;\n#[macro_use]\npub mod definitions;\npub(crate) use definitions::target_macro;\nmacro_rules! rooted_call { () => { $crate::target_macro!(); }; }\npub mod exports;\npub mod consumer;\nmod private_macros;\nmod private_consumer;\n",
        ),
        ("src/definitions.rs", definitions),
        (
            "src/exports.rs",
            "pub(crate) use crate::definitions::target_macro as exported_macro;\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/early.rs", early),
        (
            "src/private_macros.rs",
            "macro_rules! private_macro { () => {}; }\n",
        ),
        ("src/private_consumer.rs", private_consumer),
    ]);
    let target = analyzer
        .get_definitions("definitions.target_macro")
        .into_iter()
        .find(CodeUnit::is_macro)
        .expect("target macro definition");
    assert!(target.is_macro(), "expected macro target: {target:?}");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits: Vec<_> = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, &[target], &candidates, 1000)
        .into_either()
        .expect("target macro usage scan")
        .into_iter()
        .collect();

    for (file, source, needle, name) in [
        (
            "src/definitions.rs",
            definitions,
            "target_macro!(); // DIRECT_MACRO_USE",
            "target_macro",
        ),
        (
            "src/consumer.rs",
            consumer,
            "target_macro!(); // MACRO_USE_INHERITED",
            "target_macro",
        ),
        (
            "src/definitions.rs",
            definitions,
            "target_macro!() } // NESTED_MACRO_USE",
            "target_macro",
        ),
        (
            "src/lib.rs",
            "mod early;\n#[macro_use]\npub mod definitions;\npub(crate) use definitions::target_macro;\nmacro_rules! rooted_call { () => { $crate::target_macro!(); }; }\npub mod exports;\npub mod consumer;\nmod private_macros;\nmod private_consumer;\n",
            "target_macro!(); }; }",
            "target_macro",
        ),
        (
            "src/consumer.rs",
            consumer,
            "imported_macro!(); // MACRO_USE_IMPORTED",
            "imported_macro",
        ),
        (
            "src/consumer.rs",
            consumer,
            "exported_macro!(); // MACRO_USE_REEXPORTED",
            "exported_macro",
        ),
        (
            "src/consumer.rs",
            consumer,
            "target_macro!(); // MACRO_USE_QUALIFIED",
            "target_macro",
        ),
    ] {
        let expected = source.find(needle).expect("positive macro invocation");
        assert!(
            hits.iter().any(|hit| {
                hit.file == project.file(file)
                    && hit.start_offset == expected
                    && hit.end_offset == expected + name.len()
            }),
            "missing {needle}: {hits:#?}"
        );
    }
    for (file, source, needle) in [
        (
            "src/definitions.rs",
            definitions,
            "target_macro; // SAME_NAME_VALUE_USE",
        ),
        (
            "src/consumer.rs",
            consumer,
            "target_macro(); // SAME_NAME_FUNCTION_USE",
        ),
        (
            "src/consumer.rs",
            consumer,
            "target_macro; // SAME_NAME_LOCAL_USE",
        ),
        (
            "src/consumer.rs",
            consumer,
            "target_macro!(); } // SHADOW_MACRO_USE",
        ),
        (
            "src/definitions.rs",
            definitions,
            "target_macro); // BARE_MACRO_ARGUMENT",
        ),
    ] {
        let excluded = source.find(needle).expect("same-name negative");
        assert!(
            hits.iter()
                .all(|hit| hit.file != project.file(file) || hit.start_offset != excluded),
            "same-name non-target `{needle}` leaked: {hits:#?}"
        );
    }
    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("src/early.rs")),
        "macro imported after `mod early` must not be visible there: {hits:#?}"
    );
    let private_target = analyzer
        .get_definitions("private_macros.private_macro")
        .into_iter()
        .find(CodeUnit::is_macro)
        .expect("private macro definition");
    let private_hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, &[private_target], &candidates, 1000)
        .into_either()
        .expect("private macro usage scan");
    assert!(
        private_hits
            .iter()
            .all(|hit| hit.file != project.file("src/private_consumer.rs")),
        "private sibling macro must not leak: {private_hits:#?}"
    );
}

#[test]
fn rust_macro_scope_uses_definition_order_and_exact_declaration_identity() {
    let consumer = r#"
fn before_shadow() { target_macro!(); } // IMPORTED_BEFORE_SHADOW
macro_rules! target_macro { () => {}; }
fn between_shadows() { target_macro!(); } // FIRST_LOCAL_SHADOW
macro_rules! target_macro { () => {}; }
fn after_shadow() { target_macro!(); } // SECOND_LOCAL_SHADOW
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "#[macro_use]\npub mod definitions;\npub mod consumer;\n",
        ),
        (
            "src/definitions.rs",
            "macro_rules! target_macro { () => {}; }\npub(crate) use target_macro;\n",
        ),
        ("src/consumer.rs", consumer),
    ]);
    let imported = analyzer
        .get_definitions("definitions.target_macro")
        .into_iter()
        .find(CodeUnit::is_macro)
        .expect("imported macro");
    let imported_hits = rust_graph_hits_for_target(&analyzer, imported);
    let before = consumer.find("target_macro!(); } // IMPORTED").unwrap();
    let first_shadow = consumer.find("target_macro!(); } // FIRST_LOCAL").unwrap();
    let second_shadow = consumer
        .rfind("target_macro!(); } // SECOND_LOCAL")
        .unwrap();
    assert!(
        imported_hits.iter().any(|hit| {
            hit.file == project.file("src/consumer.rs") && hit.start_offset == before
        }),
        "imported target before local shadow: {imported_hits:#?}"
    );
    for shadow in [first_shadow, second_shadow] {
        assert!(imported_hits.iter().all(|hit| {
            hit.file != project.file("src/consumer.rs") || hit.start_offset != shadow
        }));
    }
}

#[test]
fn rust_macro_scope_edges_do_not_cross_disjoint_cargo_targets() {
    let lib_consumer = "fn use_macro() { target_macro!(); } // LIB_TARGET_USE\n";
    let main = r#"
#[macro_use]
mod child { macro_rules! target_macro { () => {}; } }
fn main() { target_macro!(); } // BIN_DECOY_USE
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"macro-targets\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "#[macro_use]\nmod child;\nmod lib_consumer;\n",
        ),
        ("src/child.rs", "macro_rules! target_macro { () => {}; }\n"),
        ("src/lib_consumer.rs", lib_consumer),
        ("src/main.rs", main),
    ]);
    let target = analyzer
        .get_definitions("child.target_macro")
        .into_iter()
        .find(|definition| {
            definition.is_macro() && definition.source() == &project.file("src/child.rs")
        })
        .expect("library child macro");
    let hits = rust_graph_hits_for_target(&analyzer, target);
    let expected = lib_consumer.find("target_macro!").unwrap();
    let decoy = main.find("target_macro!(); } // BIN").unwrap();
    assert!(hits.iter().any(|hit| {
        hit.file == project.file("src/lib_consumer.rs") && hit.start_offset == expected
    }));
    assert!(
        hits.iter()
            .all(|hit| { hit.file != project.file("src/main.rs") || hit.start_offset != decoy })
    );
}

#[test]
fn rust_graph_routes_imports_through_chained_namespace_aliases() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
mod target { pub struct Item; }
use target as namespace;
mod consumer {
    use super::namespace::Item as Imported;
    fn consume(_: Imported) {} // CHAINED_NAMESPACE_ALIAS_USE
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "target.Item");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("CHAINED_NAMESPACE_ALIAS_USE")),
        "expected import through a parent namespace alias: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_private_inline_module_when_explicitly_reexported() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service {
    pub struct Foo;
}
pub use service::Foo;
mod consumer;
"#,
        ),
        (
            "src/consumer.rs",
            r#"
use crate::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("private inline reexport success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_finds_public_and_private_inline_module_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub mod service {
    pub struct Foo;
    struct Hidden;

    fn internal() {
        let _ = Hidden {};
    }
}

fn run() {
    let _ = service::Foo {};
}
"#,
    )]);

    let foo = definition(&analyzer, "service.Foo");
    let hidden = definition(&analyzer, "service.Hidden");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&foo), &candidates, 1000)
            .into_either()
            .expect("public inline item success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&hidden), &candidates, 1000)
            .into_either()
            .expect("private inline local declaration scan success")
            .len()
    );
}

// Regression for #233: references that reach the crate's public API only through a
// `pub use` re-export of a private module must resolve on the graph path — a
// re-exported free function call, a method on a constructor-returned local, and a
// struct field read through a `self.field` receiver. Before this, seed inference
// bailed on the empty per-file export index and the regex fallback masked the gap.
fn build_233_reexport_project() -> (common::BuiltInlineTestProject, RustAnalyzer) {
    rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct MemoryRepository {
    pub last: String,
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn execute(&self) -> &str {
        &self.repository.last
    }
}

pub fn build_service() -> Service {
    Service {
        repository: MemoryRepository {
            last: "demo".to_string(),
        },
    }
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{build_service, MemoryRepository, Service};

pub fn run() -> String {
    let service = build_service();
    service.execute().to_string()
}
"#,
        ),
    ])
}

fn rust_graph_hits(analyzer: &RustAnalyzer, fq_name: &str) -> Vec<brokk_bifrost::usages::UsageHit> {
    let target = definition(analyzer, fq_name);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .unwrap_or_else(|_| panic!("expected graph success (not a fallback/failure) for {fq_name}"))
        .into_iter()
        .collect()
}

fn rust_graph_hits_for_target(
    analyzer: &RustAnalyzer,
    target: CodeUnit,
) -> Vec<brokk_bifrost::usages::UsageHit> {
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("expected graph success for explicit Rust target")
        .into_iter()
        .collect()
}

#[test]
fn rust_graph_strategy_finds_unique_trait_associated_function_candidate() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;

impl Trait for Foo {}

fn bar() {
    Foo::frobnicate();
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "Trait.frobnicate");
    assert_eq!(
        1,
        hits.len(),
        "expected the Foo::frobnicate() call to hit Trait.frobnicate: {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("Foo::frobnicate()")),
        "hit should be the static associated call site: {hits:?}"
    );
}

#[test]
fn rust_graph_strategy_ignores_ambiguous_trait_associated_function_candidates() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Trait {
    fn frobnicate();
}

pub trait OtherTrait {
    fn frobnicate();
}

pub struct Foo;

impl Trait for Foo {}
impl OtherTrait for Foo {}

fn bar() {
    Foo::frobnicate();
}
"#,
    )]);

    let trait_hits = rust_graph_hits(&analyzer, "Trait.frobnicate");
    let other_hits = rust_graph_hits(&analyzer, "OtherTrait.frobnicate");
    assert!(
        trait_hits.is_empty() && other_hits.is_empty(),
        "ambiguous trait candidates must not emit partial hits: Trait={trait_hits:?}, OtherTrait={other_hits:?}"
    );
}

#[test]
fn rust_graph_strategy_counts_type_aliases_used_as_static_qualifiers() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub mod left;
pub mod right;

fn run() {
    let _ = left::Alias::new();
    let _ = right::Alias::new();
}
"#,
        ),
        (
            "src/left.rs",
            "pub struct Owner;\nimpl Owner { pub fn new() -> Self { Self } }\npub type Alias = Owner;\n",
        ),
        (
            "src/right.rs",
            "pub struct Owner;\nimpl Owner { pub fn new() -> Self { Self } }\npub type Alias = Owner;\n",
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "left.Alias");
    assert_eq!(1, hits.len(), "alias qualifier hits: {hits:?}");
    assert!(hits[0].snippet.contains("left::Alias::new"));
}

#[test]
fn rust_graph_strategy_resolves_bare_module_const_and_turbofish_free_function() {
    let consumer = r#"
fn run() {
    let _ = crate::fixtures::MANIFESTS;
    let _ = crate::other::MANIFESTS;
    crate::is_unpin::<u8>();
    crate::other::is_unpin::<u8>();
}
"#;
    let main = r#"
fn run() {
    let _ = crate::fixtures::MANIFESTS; // INVALID_LIB_MAIN_DECOY
    let _ = crate::other::MANIFESTS;
    crate::is_unpin::<u8>(); // INVALID_LIB_MAIN_DECOY
    crate::other::is_unpin::<u8>();
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub mod fixtures;
pub mod other;
pub mod consumer;
pub fn is_unpin<T>() {}
"#,
        ),
        ("src/fixtures.rs", "pub const MANIFESTS: &[&str] = &[];\n"),
        (
            "src/other.rs",
            "pub const MANIFESTS: &[&str] = &[];\npub fn is_unpin<T>() {}\n",
        ),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);

    let constant_hits = rust_graph_hits(&analyzer, "fixtures._module_.MANIFESTS");
    let constant_start = consumer
        .find("crate::fixtures::MANIFESTS")
        .expect("valid const use")
        + "crate::fixtures::".len();
    assert_eq!(
        1,
        constant_hits.len(),
        "module const hits: {constant_hits:?}"
    );
    assert_eq!(project.file("src/consumer.rs"), constant_hits[0].file);
    assert_eq!(
        (constant_start, constant_start + "MANIFESTS".len()),
        (constant_hits[0].start_offset, constant_hits[0].end_offset)
    );

    let function_hits = rust_graph_hits(&analyzer, "is_unpin");
    let function_start = consumer
        .find("crate::is_unpin::<u8>()")
        .expect("valid function use")
        + "crate::".len();
    assert_eq!(1, function_hits.len(), "turbofish hits: {function_hits:?}");
    assert_eq!(project.file("src/consumer.rs"), function_hits[0].file);
    assert_eq!(
        (function_start, function_start + "is_unpin".len()),
        (function_hits[0].start_offset, function_hits[0].end_offset)
    );
}

#[test]
fn authoritative_rust_usage_resolves_private_root_function_and_nested_module_constant() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "mod blocking;\nmod consumer;\nfn is_unpin<T>() {}\n",
        ),
        ("src/blocking.rs", "pub(crate) const LIMIT: usize = 8;\n"),
        (
            "src/consumer.rs",
            r#"
#[cfg(test)]
mod tests {
    use crate::blocking::LIMIT;

    fn first() { let _ = LIMIT; }
    fn second() {
        let n = 1;
        let _ = LIMIT - n;
        crate::is_unpin::<()>();
    }
}
"#,
        ),
    ]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();

    let limit = definition(&analyzer, "blocking._module_.LIMIT");
    let limit_hits = authoritative_hits(&analyzer, &limit, candidates.clone());
    let references: Vec<_> = limit_hits
        .iter()
        .filter(|hit| hit.kind == UsageHitKind::Reference)
        .collect();
    assert_eq!(2, references.len(), "nested constant hits: {limit_hits:#?}");
    assert!(
        references
            .iter()
            .all(|hit| hit.file == project.file("src/consumer.rs"))
    );

    let is_unpin = definition(&analyzer, "is_unpin");
    let function_hits = authoritative_hits(&analyzer, &is_unpin, candidates);
    assert_eq!(
        1,
        function_hits.len(),
        "private turbofish hits: {function_hits:#?}"
    );
    assert!(
        function_hits
            .iter()
            .all(|hit| hit.snippet.contains("crate::is_unpin::<()>"))
    );
}

#[test]
fn authoritative_rust_usage_keeps_impl_self_associated_type_identity() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Future { type Output; }
pub struct Flush;
impl Future for Flush {
    type Output = ();
    fn poll() -> Self::Output { () }
}

pub struct Decoy;
impl Future for Decoy {
    type Output = ();
    fn poll() -> Self::Output { () }
}
"#,
    )]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();

    let output = definition(&analyzer, "Flush.Output");
    let hits = authoritative_hits(&analyzer, &output, candidates);
    assert_eq!(1, hits.len(), "impl Self::Output hits: {hits:#?}");
    assert!(hits.iter().all(|hit| hit.snippet.contains("Self::Output")));
}

#[test]
fn authoritative_rust_usage_resolves_glob_imported_paths_in_nested_macro_tokens() {
    let lib_source = r#"
pub mod task;
pub mod other_task;
mod runtime;
pub struct EventInfo;
impl EventInfo { pub fn default() -> Self { Self } }
pub struct OtherInfo;
impl OtherInfo { pub fn default() -> Self { Self } }

mod tests {
    use super::*;
    macro_rules! consume { ($($tokens:tt)*) => {}; }

    fn run() {
        consume!([EventInfo::default(), EventInfo::default()]);
        consume!([OtherInfo::default()]);
    }
}
"#;
    let coop_source = r#"
use super::*;
macro_rules! consume { ($($tokens:tt)*) => {}; }
fn run() {
    consume!({ task::spawn(); });
    consume!({ other_task::spawn(); });
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", lib_source),
        ("src/task.rs", "pub fn spawn() {}\n"),
        ("src/other_task.rs", "pub fn spawn() {}\n"),
        (
            "src/runtime/mod.rs",
            "use crate::{other_task, task};\nmod coop;\n",
        ),
        ("src/runtime/coop.rs", coop_source),
    ]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();

    let event_ranges: Vec<_> = lib_source
        .match_indices("EventInfo::default")
        .map(|(start, _)| (start, start + "EventInfo".len()))
        .collect();
    let default_ranges: Vec<_> = event_ranges
        .iter()
        .map(|(start, _)| {
            let start = start + "EventInfo::".len();
            (start, start + "default".len())
        })
        .collect();
    let task_start = coop_source.find("task::spawn").expect("task macro path");
    let other_event_start = lib_source
        .find("OtherInfo::default()")
        .expect("decoy event macro path");
    let other_default_start = other_event_start + "OtherInfo::".len();
    let other_task_start = coop_source
        .find("other_task::spawn")
        .expect("decoy task macro path");
    for (target_fqn, file, expected, forbidden) in [
        (
            "EventInfo",
            "src/lib.rs",
            event_ranges,
            vec![(other_event_start, other_event_start + "OtherInfo".len())],
        ),
        (
            "EventInfo.default",
            "src/lib.rs",
            default_ranges,
            vec![(other_default_start, other_default_start + "default".len())],
        ),
        (
            "task",
            "src/runtime/coop.rs",
            vec![(task_start, task_start + "task".len())],
            vec![(other_task_start, other_task_start + "other_task".len())],
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let hits = authoritative_hits(&analyzer, &target, candidates.clone());
        let expected_file = project.file(file);
        let actual: Vec<_> = hits
            .iter()
            .filter(|hit| hit.file == expected_file)
            .map(|hit| (hit.start_offset, hit.end_offset))
            .collect();
        assert!(
            expected.iter().all(|range| actual.contains(range)),
            "{target_fqn} expected macro ranges {expected:?}: {hits:#?}"
        );
        assert!(
            forbidden.iter().all(|range| !actual.contains(range)),
            "{target_fqn} crossed into decoy macro ranges {forbidden:?}: {hits:#?}"
        );
    }
}

#[test]
fn authoritative_rust_usage_resolves_crate_module_paths_in_macro_tokens() {
    let source = r#"
pub mod task;
pub mod other_task;

macro_rules! call_task {
    () => { $crate::task::spawn(); };
}
macro_rules! call_other_task {
    () => { $crate::other_task::spawn(); };
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", source),
        ("src/task.rs", "pub fn spawn() {}\n"),
        ("src/other_task.rs", "pub fn spawn() {}\n"),
    ]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "task");
    let hits = authoritative_hits(&analyzer, &target, candidates);
    let expected_start = source.find("$crate::task").expect("crate task path") + "$crate::".len();
    let forbidden_start =
        source.find("$crate::other_task").expect("decoy crate path") + "$crate::".len();
    let actual: Vec<_> = hits
        .iter()
        .filter(|hit| hit.file == project.file("src/lib.rs"))
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();

    assert!(
        actual.contains(&(expected_start, expected_start + "task".len())),
        "crate-qualified macro module segment must be found: {hits:#?}"
    );
    assert!(
        !actual.contains(&(forbidden_start, forbidden_start + "other_task".len())),
        "crate-qualified macro module segment must preserve identity: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_tracing_macro_paths_reject_disjoint_crate_roots() {
    let lib_source = r#"
pub mod field;
pub use tracing_core::metadata;
mod macros;

pub mod __macro_support {
    pub use tracing_core::__macro_support::Marker;
}
"#;
    let macro_source = r#"
macro_rules! tracing_event {
    () => {
        let _: $crate::__macro_support::Marker;
        let _: $crate::field::Value;
        let _ = $crate::metadata::Kind::EVENT;
    };
}
"#;
    let binary_source = r#"
mod field { pub struct Value; }
mod metadata { pub enum Kind { EVENT } }
mod __macro_support { pub struct Marker; }

macro_rules! tracing_event {
    () => {
        let _: $crate::__macro_support::Marker;
        let _: $crate::field::Value;
        let _ = $crate::metadata::Kind::EVENT;
    };
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"tracing\", \"tracing-core\"]\nresolver = \"2\"\n",
        ),
        (
            "tracing/Cargo.toml",
            "[package]\nname = \"tracing\"\nversion = \"0.1.0\"\n[dependencies]\ntracing-core = { path = \"../tracing-core\" }\n",
        ),
        ("tracing/src/lib.rs", lib_source),
        ("tracing/src/macros.rs", macro_source),
        ("tracing/src/field.rs", "pub use tracing_core::field::*;\n"),
        ("tracing/src/bin/decoy.rs", binary_source),
        (
            "tracing-core/Cargo.toml",
            "[package]\nname = \"tracing-core\"\nversion = \"0.1.0\"\n",
        ),
        (
            "tracing-core/src/lib.rs",
            "pub mod field;\npub mod metadata;\npub mod __macro_support { pub struct Marker; }\n",
        ),
        ("tracing-core/src/field.rs", "pub struct Value;\n"),
        (
            "tracing-core/src/metadata.rs",
            "pub enum Kind { EVENT, SPAN }\n",
        ),
    ]);
    let candidates: HashSet<_> = [project.file("tracing/src/macros.rs")]
        .into_iter()
        .collect();

    for (target_fqn, token) in [
        ("tracing.src.__macro_support", "__macro_support"),
        ("tracing.src.field", "field"),
        ("tracing-core.src.metadata.Kind", "Kind"),
    ] {
        let target = definition(&analyzer, target_fqn);
        let hits = authoritative_hits(&analyzer, &target, candidates.clone());
        let expected = macro_source
            .rfind(token)
            .expect("tracing-shaped macro token");
        let decoy = binary_source
            .rfind(token)
            .expect("disjoint binary macro token");

        assert!(
            hits.iter().any(|hit| {
                hit.file == project.file("tracing/src/macros.rs")
                    && hit.start_offset == expected
                    && hit.end_offset == expected + token.len()
            }),
            "{target_fqn} must retain its rooted token-tree reference: {hits:#?}"
        );
        assert!(
            hits.iter().all(|hit| {
                hit.file != project.file("tracing/src/bin/decoy.rs") || hit.start_offset != decoy
            }),
            "{target_fqn} must not cross into a Cargo-disjoint crate root: {hits:#?}"
        );
    }
}

#[test]
fn rust_graph_strategy_counts_associated_functions_used_as_values() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub struct Left;
impl Left { pub fn new() -> Self { Self } }
pub struct Right;
impl Right { pub fn new() -> Self { Self } }

fn run(value: Option<()>) {
    let _ = value.map(|_| Left::new);
    let _ = value.map(|_| Right::new);
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "Left.new");
    assert_eq!(1, hits.len(), "associated function value hits: {hits:?}");
    assert!(hits[0].snippet.contains("Left::new"));
}

#[test]
fn rust_graph_strategy_resolves_self_associated_types_to_the_exact_trait_owner() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Left {
    type Handle;
    fn consume(_: Self::Handle);
}

pub trait Right {
    type Handle;
    fn consume(_: Self::Handle);
}
"#,
    )]);

    let left_hits = rust_graph_hits(&analyzer, "Left.Handle");
    let right_hits = rust_graph_hits(&analyzer, "Right.Handle");
    assert_eq!(
        1,
        left_hits.len(),
        "left associated type hits: {left_hits:?}"
    );
    assert_eq!(
        1,
        right_hits.len(),
        "right associated type hits: {right_hits:?}"
    );
    assert!(left_hits[0].snippet.contains("Self::Handle"));
}

#[test]
fn rust_graph_strategy_resolves_concrete_owner_trait_associated_types() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Trait { type Handle; }
pub struct Owner;
impl Trait for Owner { type Handle = usize; }
pub trait OtherTrait { type Handle; }
pub struct OtherOwner;
impl OtherTrait for OtherOwner { type Handle = usize; }

fn consume(_: Owner::Handle) {}
fn consume_other(_: OtherOwner::Handle) {}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "Trait.Handle");
    assert_eq!(1, hits.len(), "trait associated type hits: {hits:?}");
    assert!(hits[0].snippet.contains("Owner::Handle"));
}

#[test]
fn rust_graph_strategy_finds_reexported_free_function_call() {
    let (project, analyzer) = build_233_reexport_project();
    let hits = rust_graph_hits(&analyzer, "service.build_service");
    assert_eq!(
        1,
        hits.len(),
        "expected the build_service() call in run(): {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/lib.rs")),
        "hit should be the call site in lib.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_method_call_on_constructor_returned_local() {
    let (project, analyzer) = build_233_reexport_project();
    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert_eq!(
        1,
        hits.len(),
        "expected service.execute() in run(): {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/lib.rs")),
        "hit should be the call site in lib.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_field_read_through_self_field_receiver() {
    let (project, analyzer) = build_233_reexport_project();
    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    // Two references to `MemoryRepository.last`: the `self.repository.last` read
    // in `Service::execute`, and the `MemoryRepository { last: .. }` struct-literal
    // field initializer in `build_service` (a struct-literal field read).
    let lines: std::collections::BTreeSet<usize> = hits.iter().map(|hit| hit.line).collect();
    assert_eq!(
        [12usize, 19]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        lines,
        "expected the self.repository.last read and the struct-literal field init: {hits:?}",
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/service.rs")),
        "hits should be in service.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_field_assignment_through_direct_self_receiver() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub const DEFAULT_PREFIX: &str = "job";

#[derive(Default)]
pub struct MemoryRepository {
    pub last: String,
}

impl MemoryRepository {
    pub fn save(&mut self, value: &str) -> String {
        self.last = value.to_string();
        value.trim().to_string()
    }
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(mut self, name: &str) -> String {
        let stored = self.repository.save(name);
        format!("{DEFAULT_PREFIX}:{stored}")
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::{DEFAULT_PREFIX, MemoryRepository, Service, build_service};

pub fn run_demo() -> String {
    let mut repository = MemoryRepository::default();
    repository.save("Ada");
    let service = build_service(repository);
    service.execute(" Grace ")
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert_eq!(
        1,
        hits.len(),
        "expected self.last assignment in MemoryRepository::save: {hits:?}",
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("self.last = value.to_string()")),
        "expected hit snippet to include the self.last assignment: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_grouped_reexported_free_function_call_with_argument() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub const DEFAULT_PREFIX: &str = "job";

#[derive(Default)]
pub struct MemoryRepository {
    pub last: String,
}

impl MemoryRepository {
    pub fn save(&mut self, value: &str) -> String {
        self.last = value.to_string();
        value.trim().to_string()
    }
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(mut self, name: &str) -> String {
        let stored = self.repository.save(name);
        format!("{DEFAULT_PREFIX}:{stored}")
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::{DEFAULT_PREFIX, MemoryRepository, Service, build_service};

pub fn run_demo() -> String {
    let mut repository = MemoryRepository::default();
    repository.save("Ada");
    let service = build_service(repository);
    service.execute(" Grace ")
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.build_service");
    assert_eq!(
        1,
        hits.len(),
        "expected build_service(repository) call in run_demo: {hits:?}",
    );
    assert!(
        hits.iter().any(|hit| hit.file == project.file("src/lib.rs")
            && hit.snippet.contains("build_service(repository)")),
        "expected hit snippet to include the grouped re-exported bare call: {hits:?}",
    );
}

#[test]
fn rust_usage_finder_finds_macro_method_call_on_grouped_reexported_factory_returned_local() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub const DEFAULT_PREFIX: &str = "job";

#[derive(Default)]
pub struct MemoryRepository {
    pub last: String,
}

impl MemoryRepository {
    pub fn save(&mut self, value: &str) -> String {
        self.last = value.to_string();
        value.trim().to_string()
    }
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(mut self, name: &str) -> String {
        let stored = self.repository.save(name);
        format!("{DEFAULT_PREFIX}:{stored}")
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::{DEFAULT_PREFIX, MemoryRepository, Service, build_service};

pub fn run_demo() -> String {
    let mut repository = MemoryRepository::default();
    repository.save("Ada");
    let service = build_service(repository);
    format!("{}:done", service.execute(" Grace "))
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service.execute");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("expected Rust graph success");

    assert!(
        hits.iter().any(|hit| hit.file == project.file("src/lib.rs")
            && hit.snippet.contains(r#"service.execute(" Grace ")"#)),
        "expected macro argument method call on factory-returned local: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_direct_self_field_in_qualified_cross_module_impl() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct MemoryRepository {
    pub last: String,
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::MemoryRepository;

impl crate::service::MemoryRepository {
    pub fn save(&mut self, value: &str) {
        self.last = value.to_string();
    }
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert_eq!(
        1,
        hits.len(),
        "expected self.last assignment in qualified cross-module impl: {hits:?}",
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/lib.rs")),
        "hit should be the field assignment in lib.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_count_direct_self_field_on_other_impl() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct MemoryRepository {
    pub last: String,
}

pub struct Other {
    pub last: String,
}

impl Other {
    pub fn save(&mut self, value: &str) {
        self.last = value.to_string();
    }
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert!(
        hits.is_empty(),
        "Other::save self.last assignment must not count as MemoryRepository.last usage: {hits:?}",
    );
}

// A field whose declared type only *wraps* the owner (a map value here) is not a
// field of the owner type, so a read through it must not be a false-positive usage.
#[test]
fn rust_graph_strategy_does_not_treat_map_valued_field_as_owner_receiver() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
use std::collections::HashMap;

pub struct MemoryRepository {
    pub last: String,
}

pub struct Cache {
    entries: HashMap<String, MemoryRepository>,
}

impl Cache {
    pub fn peek(&self) -> bool {
        self.entries.last.is_empty()
    }
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{Cache, MemoryRepository};
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert!(
        hits.is_empty(),
        "self.entries.last where entries is a HashMap must not be a MemoryRepository.last usage: {hits:?}",
    );
}

// A free function whose return type only *wraps* the owner (a `Vec` here) is not a
// constructor of the owner, so a method call on the local it binds must not resolve.
#[test]
fn rust_graph_strategy_does_not_treat_vec_returning_function_as_constructor() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) -> &str {
        ""
    }
}

pub fn list_all() -> Vec<Service> {
    Vec::new()
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{list_all, Service};

pub fn run() {
    let items = list_all();
    let _ = items.execute();
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert!(
        hits.is_empty(),
        "items.execute() where items is Vec<Service> must not be a Service.execute usage: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_treat_unbound_bare_call_as_constructor() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) -> &str {
        ""
    }
}

pub fn build_service() -> Service {
    Service
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{build_service, Service};
"#,
        ),
        (
            "src/client.rs",
            r#"
use crate::Service;

struct Other;

fn build_service() -> Other {
    Other
}

pub fn run() {
    let service = build_service();
    let _ = service.execute();
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert!(
        hits.is_empty(),
        "a local build_service() returning another type must not seed Service receivers: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_treat_option_result_return_as_direct_receiver() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) -> &str {
        ""
    }
}

pub fn maybe_service() -> Option<Service> {
    Some(Service)
}

pub fn result_service() -> Result<Service, String> {
    Ok(Service)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{maybe_service, result_service, Service};

pub fn run() {
    let maybe = maybe_service();
    let _ = maybe.execute();
    let result = result_service();
    let _ = result.execute();
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert!(
        hits.is_empty(),
        "Option<Service> and Result<Service, _> values must not be direct Service receivers: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_match_qualified_field_type_by_final_segment() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
use crate::other;

pub struct MemoryRepository {
    pub last: String,
}

pub struct Cache {
    repository: other::MemoryRepository,
}

impl Cache {
    pub fn peek(&self) -> bool {
        self.repository.last.is_empty()
    }
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub struct MemoryRepository {
    pub last: String,
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod other;
mod service;

pub use service::{Cache, MemoryRepository};
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert!(
        hits.is_empty(),
        "other::MemoryRepository.last must not be counted as service::MemoryRepository.last: {hits:?}",
    );
}

#[test]
fn rust_graph_resolves_fields_on_explicitly_typed_same_fqn_local_receivers() {
    let target_source = r#"
#[derive(FromArgs)]
#[argh(description = "proxy")]
pub struct Args {
    #[argh(option)] log_format: usize,
    #[argh(option)] server_addr: usize,
}
pub struct OtherArgs { log_format: usize, server_addr: usize }

fn make_args() -> Args { todo!() }
fn make_other() -> OtherArgs { todo!() }
fn run() {
    let args: Args = make_args();
    let other: OtherArgs = make_other();
    let _ = args.log_format;
    let _ = args.server_addr;
    let _ = other.log_format;
    let _ = other.server_addr;
}
"#;
    let sibling_source = r#"
#[derive(FromArgs)]
pub struct Args {
    #[argh(option)] log_format: usize,
    #[argh(option)] server_addr: usize,
}

fn make_args() -> Args { todo!() }
fn run() {
    let args: Args = make_args();
    let _ = args.log_format;
    let _ = args.server_addr;
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("examples/examples/proxy.rs", target_source),
        ("examples/examples/toggle.rs", sibling_source),
    ]);
    let target_file = project.file("examples/examples/proxy.rs");
    let target = analyzer
        .declarations(&target_file)
        .into_iter()
        .find(|unit| unit.is_field() && unit.short_name() == "Args.log_format")
        .expect("proxy Args.log_format field");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let found = authoritative_hits(&analyzer, &target, candidates);
    let expected = target_source
        .find("args.log_format")
        .map(|start| start + "args.".len())
        .map(|start| (start, start + "log_format".len()))
        .expect("typed target receiver field");

    assert!(
        found.iter().any(|hit| {
            hit.file == target_file && (hit.start_offset, hit.end_offset) == expected
        }),
        "the local physical Args declaration must survive a sibling same-FQN Args: {found:#?}"
    );
    assert!(
        found
            .iter()
            .all(|hit| hit.file == target_file && !hit.snippet.contains("other.log_format")),
        "sibling and explicitly unrelated receiver fields must not cross-match: {found:#?}"
    );
}

#[test]
fn rust_graph_proves_field_through_self_field_receiver_chain() {
    let source = r#"
pub struct BlockHeader { pub start_index: usize }
pub struct Block { pub header: BlockHeader }
pub struct OtherHeader { pub start_index: usize }
pub struct OtherBlock { pub header: OtherHeader }

impl Block {
    fn next(&self) -> usize { self.header.start_index.wrapping_add(1) }
}
impl OtherBlock {
    fn next(&self) -> usize { self.header.start_index.wrapping_add(1) }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("tokio/src/block.rs", source)]);
    let file = project.file("tokio/src/block.rs");
    let target = analyzer
        .declarations(&file)
        .into_iter()
        .find(|unit| unit.is_field() && unit.short_name() == "BlockHeader.start_index")
        .expect("BlockHeader.start_index field");
    let found = authoritative_hits(&analyzer, &target, [file].into_iter().collect());
    let expected = source
        .find("self.header.start_index")
        .map(|start| start + "self.header.".len())
        .map(|start| (start, start + "start_index".len()))
        .expect("self field receiver chain");

    assert_eq!(
        1,
        found.len(),
        "only the BlockHeader field may match: {found:#?}"
    );
    let hit = found.iter().next().expect("the BlockHeader field hit");
    assert_eq!(
        expected,
        (hit.start_offset, hit.end_offset),
        "self.header must prove the terminal field owner"
    );
}

#[test]
fn rust_graph_proves_method_through_cross_file_self_field_receiver_chain() {
    let metrics = r#"
use crate::handle::Handle;

impl Handle {
    fn injection_queue_depth(&self) -> usize {
        self.shared.injection_queue_depth()
    }

    fn unrelated_queue_depth(&self) -> usize {
        self.other_shared.injection_queue_depth()
    }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "mod handle; mod metrics; mod other_worker; mod worker;\n",
        ),
        (
            "src/worker.rs",
            r#"
pub(crate) struct Shared;
impl Shared {
    pub(crate) fn injection_queue_depth(&self) -> usize { 1 }
}
"#,
        ),
        (
            "src/other_worker.rs",
            r#"
pub(crate) struct Shared;
impl Shared {
    pub(crate) fn injection_queue_depth(&self) -> usize { 2 }
}
"#,
        ),
        (
            "src/handle.rs",
            r#"
use crate::{other_worker, worker};

pub(crate) struct Handle {
    pub(super) shared: worker::Shared,
    pub(super) other_shared: other_worker::Shared,
}
"#,
        ),
        ("src/metrics.rs", metrics),
    ]);
    let target = definition(&analyzer, "worker.Shared.injection_queue_depth");
    let found = authoritative_hits(
        &analyzer,
        &target,
        analyzer.get_analyzed_files().into_iter().collect(),
    );
    let expected = metrics
        .find("self.shared.injection_queue_depth")
        .map(|start| start + "self.shared.".len())
        .map(|start| (start, start + "injection_queue_depth".len()))
        .expect("method through declared self field");

    assert_eq!(
        1,
        found.len(),
        "unrelated same-name owner must not match: {found:#?}"
    );
    let hit = found.iter().next().expect("worker Shared method hit");
    assert_eq!(project.file("src/metrics.rs"), hit.file);
    assert_eq!(expected, (hit.start_offset, hit.end_offset));
}

#[test]
fn rust_graph_resolves_dotted_member_chains_inside_macro_token_trees() {
    let source = r#"
pub struct AlertType;
impl AlertType { pub fn default_title(&self) -> &'static str { "Alert" } }
pub struct OtherAlertType;
impl OtherAlertType { pub fn default_title(&self) -> &'static str { "Other" } }
pub struct NodeAlert { pub alert_type: AlertType }
pub struct OtherAlert { pub alert_type: OtherAlertType }

fn render(output: &mut String, alert: &NodeAlert, other: &OtherAlert) {
    write!(output, "{}", alert.alert_type.default_title());
    write!(output, "{}", other.alert_type.default_title());
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);
    let target = definition(&analyzer, "AlertType.default_title");
    let found = authoritative_hits(
        &analyzer,
        &target,
        [project.file("src/lib.rs")].into_iter().collect(),
    );
    let expected = source
        .find("alert.alert_type.default_title")
        .map(|start| start + "alert.alert_type.".len())
        .map(|start| (start, start + "default_title".len()))
        .expect("macro token-tree member chain");

    assert_eq!(
        1,
        found.len(),
        "the unrelated macro chain must not match: {found:#?}"
    );
    let hit = found.iter().next().expect("the AlertType method hit");
    assert_eq!(
        expected,
        (hit.start_offset, hit.end_offset),
        "the token-tree receiver chain must retain its intermediate field type"
    );
}

#[test]
fn rust_usage_routes_pub_crate_type_through_private_parent_binding() {
    let consumer = r#"
use super::Style;
use crate::decoy::Style as DecoyStyle;

fn consume(value: Style, decoy: DecoyStyle) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod decoy; mod style; mod value;\n"),
        ("src/style.rs", "pub(crate) struct Style;\n"),
        ("src/decoy.rs", "pub(crate) struct Style;\n"),
        ("src/value/mod.rs", "use crate::style::Style;\nmod map;\n"),
        ("src/value/map.rs", consumer),
    ]);

    let target = definition(&analyzer, "style.Style");
    let found = UsageFinder::new()
        .find_usages_default(&analyzer, &[target])
        .into_either()
        .expect("Rust graph usage success");
    let expected = consumer
        .find("value: Style")
        .map(|start| start + "value: ".len())
        .expect("target Style use");

    assert_eq!(
        1,
        found.len(),
        "only the routed Style use may match: {found:#?}"
    );
    let hit = found.iter().next().expect("routed Style usage");
    assert_eq!(project.file("src/value/map.rs"), hit.file);
    assert_eq!(
        (expected, expected + "Style".len()),
        (hit.start_offset, hit.end_offset)
    );
}

#[test]
fn rust_usage_routes_restricted_named_and_glob_reexports() {
    let consumer = r#"
use crate::facade::{Globbed, Named};

fn consume(named: Named, globbed: Globbed) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod facade;\n"),
        (
            "src/facade/mod.rs",
            "mod consumer; mod globbed; mod named;\npub(crate) use self::named::Named;\npub(in crate::facade) use self::globbed::*;\n",
        ),
        ("src/facade/named.rs", "pub(crate) struct Named;\n"),
        ("src/facade/globbed.rs", "pub(crate) struct Globbed;\n"),
        ("src/facade/consumer.rs", consumer),
    ]);

    for (target_fqn, marker) in [
        ("facade.named.Named", "named: Named"),
        ("facade.globbed.Globbed", "globbed: Globbed"),
    ] {
        let target = definition(&analyzer, target_fqn);
        let found = UsageFinder::new()
            .find_usages_default(&analyzer, std::slice::from_ref(&target))
            .into_either()
            .expect("Rust graph usage success");
        let expected = consumer
            .find(marker)
            .map(|start| start + marker.find(':').expect("type separator") + 2)
            .expect("restricted re-export use");
        assert_eq!(
            1,
            found.len(),
            "restricted route for {target_fqn}: {found:#?}"
        );
        let hit = found.iter().next().expect("restricted re-export usage");
        assert_eq!(project.file("src/facade/consumer.rs"), hit.file);
        assert_eq!(expected, hit.start_offset);
    }
}

#[test]
fn rust_qualified_resolution_respects_module_and_local_import_extents() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
mod wanted { pub fn ping() {} }
use crate::wanted as selected;

fn outer() { selected::ping(); } // VALID_PARENT_IMPORT

mod child {
    mod selected { pub fn ping() {} }
    fn run() { selected::ping(); } // SHADOWED_CHILD_PATH
}

fn local() {
    use crate::wanted as local_selected;
    local_selected::ping(); // VALID_LOCAL_IMPORT
}

fn outside() { local_selected::ping(); } // LEAKED_LOCAL_IMPORT
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "wanted.ping");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("VALID_PARENT_IMPORT"))
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("VALID_LOCAL_IMPORT"))
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("SHADOWED_CHILD_PATH"))
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("LEAKED_LOCAL_IMPORT"))
    );
}

#[test]
fn rust_qualified_resolution_respects_item_shadowing_inside_and_outside_macros() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
mod wanted { pub struct Owner; }
use wanted::Owner;
macro_rules! preserve { ($($tokens:tt)*) => {}; }

fn valid(_: Owner) {} // VALID_OWNER_USE

fn shadowed() {
    struct Owner;
    let _ = Owner::VALUE; // SHADOWED_ORDINARY_PATH
    preserve!(Owner::VALUE); // SHADOWED_MACRO_PATH
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "wanted.Owner");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("VALID_OWNER_USE"))
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("SHADOWED_ORDINARY_PATH"))
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("SHADOWED_MACRO_PATH"))
    );
}

#[test]
fn rust_qualified_resolution_does_not_bypass_private_visibility() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
mod hidden {
    struct Secret;
    fn valid(_: Secret) {} // VALID_PRIVATE_USE
}

fn invalid(_: crate::hidden::Secret) {} // INVALID_PRIVATE_USE
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "hidden.Secret");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("VALID_PRIVATE_USE"))
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("INVALID_PRIVATE_USE"))
    );
}

#[test]
fn rust_qualified_resolution_rejects_colliding_glob_reexport_origins() {
    let source = r#"
mod left { pub struct Item; }
mod right { pub struct Item; }

mod facade {
    pub use crate::left::*;
    pub use crate::right::*;
}

use facade::*;
fn ambiguous(_: Item) {} // AMBIGUOUS_GLOB_ORIGIN
fn exact(_: left::Item) {} // EXACT_LEFT_ORIGIN
"#;
    let (_project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);

    let hits = rust_graph_hits(&analyzer, "left.Item");
    let ambiguous =
        source.find("ambiguous(_: Item)").expect("ambiguous use") + "ambiguous(_: ".len();
    let exact = source.find("exact(_: left::Item)").expect("exact use") + "exact(_: left::".len();
    assert!(
        hits.iter()
            .any(|hit| hit.start_offset == exact && hit.end_offset == exact + "Item".len())
    );
    assert!(
        hits.iter().all(|hit| hit.start_offset != ambiguous),
        "a colliding glob alias must preserve both canonical origins: {hits:#?}"
    );
}

#[test]
fn rust_direct_resolution_respects_private_owner_module_domain() {
    let source = r#"
mod outer {
    mod hidden {
        pub struct Item;
        fn inside(_: Item) {} // VALID_INSIDE_PRIVATE_MODULE
    }
}

mod sibling {
    fn invalid(_: crate::outer::hidden::Item) {} // INVALID_SIBLING_PRIVATE_MODULE
}
"#;
    let (_project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);
    let hits = rust_graph_hits(&analyzer, "outer.hidden.Item");
    let inside = source.find("inside(_: Item)").expect("inside use") + "inside(_: ".len();
    let invalid = source
        .find("invalid(_: crate::outer::hidden::Item)")
        .expect("invalid sibling use")
        + "invalid(_: crate::outer::hidden::".len();

    assert!(
        hits.iter()
            .any(|hit| hit.start_offset == inside && hit.end_offset == inside + "Item".len()),
        "the item must resolve inside its private owner module: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| hit.start_offset != invalid),
        "a public item must not bypass its private owner module: {hits:#?}"
    );
}

#[test]
fn rust_direct_resolution_allows_physical_root_item_in_inline_descendant() {
    let source = r#"
pub struct RootItem;
mod descendant {
    fn valid(_: super::RootItem) {}
}

"#;
    let (_project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);
    let hits = rust_graph_hits(&analyzer, "RootItem");
    let expected = source.find("super::RootItem").expect("descendant use") + "super::".len();

    assert!(
        hits.iter().any(
            |hit| hit.start_offset == expected && hit.end_offset == expected + "RootItem".len()
        ),
        "physical-root items must remain visible in inline descendants: {hits:#?}"
    );
}

#[test]
fn rust_physical_owners_do_not_attach_file_to_inline_module() {
    let lib = r#"
pub struct RootItem;
mod shadow {
    fn valid(_: super::RootItem) {}
}
"#;
    let detached = "fn invalid(_: crate::RootItem) {}\n";
    let (project, analyzer) =
        rust_analyzer_with_files(&[("src/lib.rs", lib), ("src/shadow.rs", detached)]);
    let hits = rust_graph_hits(&analyzer, "RootItem");
    let valid = lib.find("super::RootItem").expect("inline valid use") + "super::".len();
    let invalid = detached.find("crate::RootItem").expect("detached use") + "crate::".len();

    assert!(hits.iter().any(|hit| {
        hit.file == project.file("src/lib.rs")
            && hit.start_offset == valid
            && hit.end_offset == valid + "RootItem".len()
    }));
    assert!(
        hits.iter().all(|hit| {
            hit.file != project.file("src/shadow.rs") || hit.start_offset != invalid
        }),
        "an inline module must not attach a same-named analyzed file: {hits:#?}"
    );
}

#[test]
fn rust_rooted_import_requires_shared_physical_owner() {
    let consumer = r#"
use crate::fixtures::MANIFESTS;
fn valid() { let _ = MANIFESTS; }
"#;
    let main = r#"
use crate::fixtures::MANIFESTS;
fn invalid() { let _ = MANIFESTS; }
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "pub mod fixtures;\npub mod consumer;\n"),
        ("src/fixtures.rs", "pub const MANIFESTS: &[&str] = &[];\n"),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);
    let hits = rust_graph_hits(&analyzer, "fixtures._module_.MANIFESTS");
    let valid = consumer.find("let _ = MANIFESTS").expect("valid use") + "let _ = ".len();
    let invalid = main.find("let _ = MANIFESTS").expect("invalid use") + "let _ = ".len();

    assert!(hits.iter().any(|hit| {
        hit.file == project.file("src/consumer.rs")
            && hit.start_offset == valid
            && hit.end_offset == valid + "MANIFESTS".len()
    }));
    assert!(
        hits.iter()
            .all(|hit| { hit.file != project.file("src/main.rs") || hit.start_offset != invalid }),
        "a rooted import must not cross unrelated crate roots: {hits:#?}"
    );
}

#[test]
fn rust_rooted_import_does_not_attach_undeclared_orphan_modules() {
    let orphan = r#"
use crate::orphan_target::Thing;
fn invalid(_: Thing) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn root() {}\n"),
        ("src/orphan_target.rs", "pub struct Thing;\n"),
        ("src/orphan_consumer.rs", orphan),
    ]);
    let hits = rust_graph_hits(&analyzer, "orphan_target.Thing");
    let invalid = orphan.find("invalid(_: Thing)").expect("orphan use") + "invalid(_: ".len();

    assert!(
        hits.iter().all(|hit| {
            hit.file != project.file("src/orphan_consumer.rs") || hit.start_offset != invalid
        }),
        "analyzed files absent from every module tree must remain unrelated: {hits:#?}"
    );
}

#[test]
fn rust_binary_only_passthrough_macro_owns_its_external_module() {
    let main = r#"
macro_rules! cfg_items { ($($item:item)*) => { $($item)* }; }
cfg_items! { mod fixtures; }

use crate::fixtures::VALUE;
fn valid() { let _ = VALUE; }
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nautolib = false\n",
        ),
        ("src/main.rs", main),
        ("src/fixtures.rs", "pub const VALUE: usize = 1;\n"),
    ]);
    let hits = rust_graph_hits(&analyzer, "fixtures._module_.VALUE");
    let expected = main.find("let _ = VALUE").expect("binary use") + "let _ = ".len();

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/main.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "VALUE".len()
        }),
        "the binary target must own modules emitted by its item-passthrough macro: {hits:#?}"
    );
}

#[test]
fn rust_nested_path_module_shares_its_cargo_target_without_escaping_workspace() {
    let consumer = "use super::mapped::VALUE;\nfn valid() { let _ = VALUE; }\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod outer {\n    #[path = \"mapped.rs\"]\n    pub mod mapped;\n    pub mod consumer;\n}\n#[path = \"/outside.rs\"]\nmod outside;\n",
        ),
        ("src/outer/mapped.rs", "pub const VALUE: usize = 1;\n"),
        ("src/outer/consumer.rs", consumer),
    ]);
    let hits = rust_graph_hits(&analyzer, "outer.mapped._module_.VALUE");
    let expected = consumer.find("let _ = VALUE").expect("nested path use") + "let _ = ".len();

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/outer/consumer.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "VALUE".len()
        }),
        "a contained nested #[path] module must inherit its actual Cargo target: {hits:#?}"
    );
}

#[test]
fn rust_unrooted_local_import_requires_shared_physical_owner() {
    let consumer = r#"
use fixtures::MANIFESTS;
fn valid() { let _ = MANIFESTS; }
"#;
    let main = r#"
use fixtures::MANIFESTS;
fn invalid() { let _ = MANIFESTS; }
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "pub mod fixtures;\npub mod consumer;\n"),
        ("src/fixtures.rs", "pub const MANIFESTS: &[&str] = &[];\n"),
        ("src/consumer.rs", consumer),
        ("src/main.rs", main),
    ]);
    let hits = rust_graph_hits(&analyzer, "fixtures._module_.MANIFESTS");
    let valid = consumer.find("let _ = MANIFESTS").expect("valid use") + "let _ = ".len();
    let invalid = main.find("let _ = MANIFESTS").expect("invalid use") + "let _ = ".len();

    assert!(hits.iter().any(|hit| {
        hit.file == project.file("src/consumer.rs")
            && hit.start_offset == valid
            && hit.end_offset == valid + "MANIFESTS".len()
    }));
    assert!(
        hits.iter()
            .all(|hit| { hit.file != project.file("src/main.rs") || hit.start_offset != invalid }),
        "an unrooted local import must not cross unrelated crate roots: {hits:#?}"
    );
}

#[test]
fn rust_binary_can_import_own_library_crate_name_through_alias() {
    let main = r#"
use demo_app as own_library;
use own_library::Item as LibraryItem;
fn consume(_: LibraryItem) {}
fn consume_absolute(_: ::demo_app::Item) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"demo-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("src/lib.rs", "pub struct Item;\n"),
        ("src/main.rs", main),
    ]);
    let hits = rust_graph_hits(&analyzer, "Item");
    let expected = main
        .find("consume(_: LibraryItem)")
        .expect("own-library use")
        + "consume(_: ".len();

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/main.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "LibraryItem".len()
        }),
        "a binary target must resolve its own Cargo library through an alias: {hits:#?}"
    );
    let absolute = main
        .find("::demo_app::Item")
        .expect("leading-absolute own-library use")
        + "::demo_app::".len();
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/main.rs")
                && hit.start_offset == absolute
                && hit.end_offset == absolute + "Item".len()
        }),
        "a Rust 2018+ binary must resolve its own library through the extern prelude: {hits:#?}"
    );
}

#[test]
fn rust_path_dependency_alias_chain_preserves_external_provenance() {
    let consumer = r#"
use dep_alias::model as external_model;
use external_model as chained_model;
fn valid(_: chained_model::Item) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ndep_alias = { package = \"dep-package\", path = \"dep\" }\n",
        ),
        ("src/lib.rs", "mod consumer;\n"),
        ("src/consumer.rs", consumer),
        (
            "dep/Cargo.toml",
            "[package]\nname = \"dep-package\"\nversion = \"0.1.0\"\n",
        ),
        ("dep/src/lib.rs", "pub mod model;\n"),
        ("dep/src/model.rs", "pub struct Item;\n"),
    ]);
    let hits = rust_graph_hits(&analyzer, "dep.src.model.Item");
    let expected = consumer
        .find("chained_model::Item")
        .expect("path-dependency use")
        + "chained_model::".len();

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/consumer.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "Item".len()
        }),
        "a path dependency must retain External provenance through module aliases: {hits:#?}"
    );
}

#[test]
fn rust_dependency_module_qualifier_from_nested_module_is_exact() {
    let consumer = "pub fn consume(_: &toml_parser::parser::Event) {}\npub fn unrelated(_: &other_parser::parser::Event) {}\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/toml_parser/Cargo.toml",
            "[package]\nname = \"toml_parser\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/toml_parser/src/lib.rs", "pub mod parser;\n"),
        ("crates/toml_parser/src/parser.rs", "pub struct Event;\n"),
        (
            "crates/other_parser/Cargo.toml",
            "[package]\nname = \"other_parser\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/other_parser/src/lib.rs", "pub mod parser;\n"),
        ("crates/other_parser/src/parser.rs", "pub struct Event;\n"),
        (
            "crates/toml/Cargo.toml",
            "[package]\nname = \"toml\"\nversion = \"0.1.0\"\n[dependencies]\ntoml_parser = { path = \"../toml_parser\" }\nother_parser = { path = \"../other_parser\" }\n",
        ),
        ("crates/toml/src/lib.rs", "pub mod de;\n"),
        ("crates/toml/src/de/mod.rs", "pub mod parser;\n"),
        ("crates/toml/src/de/parser/mod.rs", "pub mod document;\n"),
        ("crates/toml/src/de/parser/document.rs", consumer),
    ]);
    let target = definition(&analyzer, "crates.toml_parser.src.parser");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[target])
        .all_hits_including_imports();
    let expected = consumer.find("::parser").expect("module qualifier") + 2;
    let unrelated = consumer.rfind("::parser").expect("unrelated qualifier") + 2;

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("crates/toml/src/de/parser/document.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "parser".len()
                && hit.kind == UsageHitKind::Reference
        }),
        "expected exact dependency module-qualifier hit: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            hit.file != project.file("crates/toml/src/de/parser/document.rs")
                || hit.start_offset != unrelated
        }),
        "a same-named module reached through another dependency must stay unrelated: {hits:#?}"
    );
}

#[test]
fn rust_rooted_module_qualifier_inside_use_path_is_exact() {
    let consumer =
        "use crate::de::DeString;\nuse crate::other::de::Thing;\npub type Alias = DeString;\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"toml\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod de;\npub mod detable;\npub mod other { pub mod de { pub struct Thing; } }\n",
        ),
        ("src/de.rs", "pub struct DeString;\n"),
        ("src/detable.rs", consumer),
    ]);
    let target = definition(&analyzer, "de");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[target])
        .all_hits_including_imports();
    let expected = consumer.find("::de").expect("module qualifier") + 2;
    let unrelated = consumer.rfind("::de").expect("unrelated qualifier") + 2;

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/detable.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "de".len()
                && hit.kind == UsageHitKind::Import
        }),
        "expected exact module-prefix import hit: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            hit.file != project.file("src/detable.rs") || hit.start_offset != unrelated
        }),
        "a nested same-named module qualifier must stay unrelated: {hits:#?}"
    );
}

#[test]
fn rust_grouped_use_module_qualifier_reconstructs_outer_dependency_path() {
    let consumer = "use toml_parser::{parser::Event};\nuse other_parser::{parser::Other};\npub fn consume(_: Event) {}\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/toml_parser/Cargo.toml",
            "[package]\nname = \"toml_parser\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/toml_parser/src/lib.rs", "pub mod parser;\n"),
        ("crates/toml_parser/src/parser.rs", "pub struct Event;\n"),
        (
            "crates/other_parser/Cargo.toml",
            "[package]\nname = \"other_parser\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/other_parser/src/lib.rs", "pub mod parser;\n"),
        ("crates/other_parser/src/parser.rs", "pub struct Other;\n"),
        (
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntoml_parser = { path = \"../toml_parser\" }\nother_parser = { path = \"../other_parser\" }\n",
        ),
        ("crates/app/src/lib.rs", consumer),
    ]);
    let target = definition(&analyzer, "crates.toml_parser.src.parser");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[target])
        .all_hits_including_imports();
    let expected = consumer.find("parser::Event").expect("grouped qualifier");
    let unrelated = consumer.find("parser::Other").expect("collision qualifier");

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("crates/app/src/lib.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "parser".len()
                && hit.kind == UsageHitKind::Import
        }),
        "a grouped use qualifier must retain its outer dependency path: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            hit.file != project.file("crates/app/src/lib.rs") || hit.start_offset != unrelated
        }),
        "the same qualifier under a different grouped dependency must stay unrelated: {hits:#?}"
    );
}

#[test]
fn rust_grouped_glob_module_qualifier_reconstructs_outer_dependency_path() {
    let consumer =
        "use toml_parser::{parser::*};\nuse other_parser::{parser::*};\npub fn marker() {}\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/toml_parser/Cargo.toml",
            "[package]\nname = \"toml_parser\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/toml_parser/src/lib.rs", "pub mod parser;\n"),
        ("crates/toml_parser/src/parser.rs", "pub struct Event;\n"),
        (
            "crates/other_parser/Cargo.toml",
            "[package]\nname = \"other_parser\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/other_parser/src/lib.rs", "pub mod parser;\n"),
        ("crates/other_parser/src/parser.rs", "pub struct Other;\n"),
        (
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntoml_parser = { path = \"../toml_parser\" }\nother_parser = { path = \"../other_parser\" }\n",
        ),
        ("crates/app/src/lib.rs", consumer),
    ]);
    let target = definition(&analyzer, "crates.toml_parser.src.parser");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[target])
        .all_hits_including_imports();
    let expected = consumer.find("parser::*").expect("grouped glob qualifier");
    let unrelated = consumer
        .rfind("parser::*")
        .expect("collision glob qualifier");

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("crates/app/src/lib.rs")
                && hit.start_offset == expected
                && hit.end_offset == expected + "parser".len()
                && hit.kind == UsageHitKind::Import
        }),
        "a grouped glob qualifier must retain its outer dependency path: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| {
            hit.file != project.file("crates/app/src/lib.rs") || hit.start_offset != unrelated
        }),
        "the same glob qualifier under another dependency must stay unrelated: {hits:#?}"
    );
}

#[test]
fn rust_grouped_leading_absolute_use_prefers_dependency_over_same_named_local_module() {
    let app = r#"
mod upstream;
use ::upstream::{nested::Item};

pub fn consume(_: Item) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/upstream/Cargo.toml",
            "[package]\nname = \"upstream\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "crates/upstream/src/lib.rs",
            "pub mod nested { pub struct Item; }\n",
        ),
        (
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nupstream = { path = \"../upstream\" }\n",
        ),
        ("crates/app/src/lib.rs", app),
        (
            "crates/app/src/upstream.rs",
            "pub mod nested { pub struct Item; }\n",
        ),
    ]);
    let candidate = project.file("crates/app/src/lib.rs");
    let files: HashSet<ProjectFile> = [candidate.clone()].into_iter().collect();
    let import_item = app.find("Item};").expect("absolute grouped import item");

    let dependency_item = definition(&analyzer, "crates.upstream.src.nested.Item");
    let dependency_hits = authoritative_hits(&analyzer, &dependency_item, files.clone());
    assert!(
        dependency_hits.iter().any(|hit| {
            hit.file == candidate
                && hit.start_offset == import_item
                && hit.kind == UsageHitKind::Import
        }),
        "leading-absolute grouped use must resolve through the Cargo dependency: {dependency_hits:#?}"
    );

    let local_item = definition(&analyzer, "crates.app.src.upstream.nested.Item");
    let local_hits = authoritative_hits(&analyzer, &local_item, files);
    assert!(
        local_hits
            .iter()
            .all(|hit| hit.file != candidate || hit.start_offset != import_item),
        "a same-named local module must not capture a leading-absolute grouped use: {local_hits:#?}"
    );
}

#[test]
fn rust_qualified_type_path_ignores_value_shadow_but_respects_item_shadow() {
    let app = r#"
pub fn value_shadow() {
    let value = 0;
    let _: Option<value::Type> = None; // VALUE_SHADOW
}

pub fn item_shadow() {
    struct value;
    let _: Option<value::Type> = None; // ITEM_SHADOW
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/value/Cargo.toml",
            "[package]\nname = \"value\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/value/src/lib.rs", "pub struct Type;\n"),
        (
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nvalue = { path = \"../value\" }\n",
        ),
        ("crates/app/src/lib.rs", app),
    ]);
    let candidate = project.file("crates/app/src/lib.rs");
    let target = definition(&analyzer, "crates.value.src.Type");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        [candidate.clone()].into_iter().collect(),
    );
    let value_shadow = app
        .find("Type> = None; // VALUE_SHADOW")
        .expect("value-shadowed qualified type");
    let item_shadow = app
        .find("Type> = None; // ITEM_SHADOW")
        .expect("item-shadowed qualified type");

    assert!(
        hits.iter()
            .any(|hit| hit.file == candidate && hit.start_offset == value_shadow),
        "a value binding must not shadow a qualified type/module root: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file != candidate || hit.start_offset != item_shadow),
        "a local item in the type namespace must shadow the imported module root: {hits:#?}"
    );
}

#[test]
fn rust_direct_module_imports_preserve_grouped_parent_and_lexical_module_routes() {
    let app = r#"
use tokio::{sync::Semaphore, task};
use ::tokio::{task as absolute_task};
use other_runtime::{task as other_task};

pub fn run(_: Semaphore) {
    task::spawn(); // GROUPED_MODULE
    absolute_task::spawn(); // ABSOLUTE_GROUPED_MODULE
    other_task::spawn(); // OTHER_DEPENDENCY
}

mod inline_consumer {
    use tokio::{task};
    pub fn run() { task::spawn(); } // INLINE_GROUPED_MODULE
}
"#;
    let maybe_done_source = r#"
pub fn maybe_done() {}
mod miri_tests {
    use super::maybe_done; // SUPER_MODULE_IMPORT
    fn run() { maybe_done(); }
}
"#;
    let bench = r#"
use tokio::{sync::Semaphore, task};
async fn task(_: Semaphore) {}
fn run(value: Semaphore) { task::spawn(task(value)); } // SAME_PACKAGE_BENCH
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/tokio/Cargo.toml",
            "[package]\nname = \"tokio\"\nversion = \"0.1.0\"\n",
        ),
        (
            "crates/tokio/src/lib.rs",
            "pub mod sync;\npub mod task;\npub mod future;\n",
        ),
        ("crates/tokio/src/sync/mod.rs", "pub struct Semaphore;\n"),
        ("crates/tokio/src/task/mod.rs", "pub fn spawn() {}\n"),
        ("crates/tokio/src/future/mod.rs", "pub mod maybe_done;\n"),
        ("crates/tokio/src/future/maybe_done.rs", maybe_done_source),
        (
            "crates/other_runtime/Cargo.toml",
            "[package]\nname = \"other_runtime\"\nversion = \"0.1.0\"\n",
        ),
        (
            "crates/other_runtime/src/lib.rs",
            "pub mod task { pub fn spawn() {} }\n",
        ),
        (
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = { path = \"../tokio\" }\nother_runtime = { path = \"../other_runtime\" }\n",
        ),
        ("crates/app/src/lib.rs", app),
        (
            "crates/benches/Cargo.toml",
            "[package]\nname = \"benches\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = { path = \"../tokio\" }\n[[bench]]\nname = \"sync_semaphore\"\npath = \"sync_semaphore.rs\"\nharness = false\n",
        ),
        ("crates/benches/sync_semaphore.rs", bench),
    ]);
    let task = definition(&analyzer, "crates.tokio.src.task");
    let task_hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&task))
        .all_hits_including_imports();
    for marker in [
        "task::spawn(); // GROUPED_MODULE",
        "absolute_task::spawn(); // ABSOLUTE_GROUPED_MODULE",
        "task::spawn(); } // INLINE_GROUPED_MODULE",
    ] {
        let expected = app.find(marker).expect("task module witness");
        assert!(
            task_hits.iter().any(|hit| {
                hit.file == project.file("crates/app/src/lib.rs")
                    && hit.start_offset == expected
                    && hit.kind == UsageHitKind::Reference
            }),
            "missing direct grouped module reference `{marker}`: {task_hits:#?}"
        );
    }
    let bench_reference = bench.find("task::spawn").expect("bench module witness");
    assert!(
        task_hits.iter().any(|hit| {
            hit.file == project.file("crates/benches/sync_semaphore.rs")
                && hit.start_offset == bench_reference
                && hit.kind == UsageHitKind::Reference
        }),
        "missing direct grouped module reference from a same-package Cargo bench: {task_hits:#?}"
    );
    let bench_hits = authoritative_hits(
        &analyzer,
        &task,
        [project.file("crates/benches/sync_semaphore.rs")]
            .into_iter()
            .collect(),
    );
    assert!(
        bench_hits
            .iter()
            .any(|hit| hit.start_offset == bench_reference),
        "authoritative exact-file scope must retain the grouped module qualifier: {bench_hits:#?}"
    );
    let other = app.find("other_task::spawn").expect("dependency decoy");
    assert!(
        task_hits.iter().all(|hit| {
            hit.file != project.file("crates/app/src/lib.rs") || hit.start_offset != other
        }),
        "same-named module from another dependency must remain unrelated: {task_hits:#?}"
    );

    let maybe_done = definition(&analyzer, "crates.tokio.src.future.maybe_done");
    let maybe_done_hits = UsageFinder::new()
        .find_usages_default(&analyzer, &[maybe_done])
        .all_hits_including_imports();
    let super_use = maybe_done_source
        .find("use super::maybe_done")
        .expect("super import")
        + "use super::".len();
    assert!(
        maybe_done_hits.iter().any(|hit| {
            hit.file == project.file("crates/tokio/src/future/maybe_done.rs")
                && hit.start_offset == super_use
                && hit.kind == UsageHitKind::Import
        }),
        "missing same-named item imported through its enclosing module: {maybe_done_hits:#?}"
    );
}

#[test]
fn rust_2015_leading_absolute_path_resolves_local_crate_module() {
    let source = r#"
mod local {
    pub struct Type;
}

pub fn consume(_: ::local::Type) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"legacy\"\nversion = \"0.1.0\"\nedition = \"2015\"\n",
        ),
        ("src/lib.rs", source),
    ]);
    let candidate = project.file("src/lib.rs");
    let target = analyzer
        .declarations(&candidate)
        .into_iter()
        .find(|declaration| declaration.identifier() == "Type")
        .expect("local Type definition");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        [candidate.clone()].into_iter().collect(),
    );
    let expected = source.find("Type) {}").expect("leading-absolute type");

    assert!(
        hits.iter()
            .any(|hit| hit.file == candidate && hit.start_offset == expected),
        "Rust 2015 leading-absolute paths must retain crate-local module semantics: {hits:#?}"
    );
}

#[test]
fn rust_authoritative_explicit_bench_resolves_leading_absolute_dev_dependency_path() {
    let bench = r#"
mod parser_dep {
    pub mod decoder {
        pub struct Encoding;
    }
}

fn exercise(_: ::parser_dep::decoder::Encoding) {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"3\"\n\n[workspace.package]\nedition = \"2024\"\n",
        ),
        (
            "crates/parser-dep/Cargo.toml",
            "[package]\nname = \"parser-dep\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
        ),
        ("crates/parser-dep/src/lib.rs", "pub mod decoder;\n"),
        (
            "crates/parser-dep/src/decoder/mod.rs",
            "pub struct Encoding;\n",
        ),
        (
            "crates/benches/Cargo.toml",
            "[package]\nname = \"benches\"\nversion = \"0.1.0\"\nedition.workspace = true\n\n[dev-dependencies]\nparser_dep = { package = \"parser-dep\", path = \"../parser-dep\" }\n\n[[bench]]\nname = \"routes\"\nharness = false\n",
        ),
        ("crates/benches/benches/routes.rs", bench),
    ]);
    let candidate = project.file("crates/benches/benches/routes.rs");
    let candidates: HashSet<ProjectFile> = [candidate.clone()].into_iter().collect();

    for (target_fqn, marker, expected_len) in [
        (
            "crates.parser-dep.src.decoder",
            "decoder::Encoding",
            "decoder".len(),
        ),
        (
            "crates.parser-dep.src.decoder.Encoding",
            "Encoding) {}",
            "Encoding".len(),
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let hits = authoritative_hits(&analyzer, &target, candidates.clone());
        let expected = bench.find(marker).expect("route witness");
        assert!(
            hits.iter().any(|hit| {
                hit.file == candidate
                    && hit.start_offset == expected
                    && hit.end_offset == expected + expected_len
            }),
            "missing authoritative explicit-bench route for {target_fqn}: {hits:#?}"
        );
    }

    let local_encoding = analyzer
        .declarations(&candidate)
        .into_iter()
        .find(|declaration| declaration.identifier() == "Encoding")
        .expect("same-named local Encoding decoy");
    let absolute_encoding = bench
        .find("Encoding) {}")
        .expect("absolute dependency type");
    let local_hits = authoritative_hits(&analyzer, &local_encoding, candidates);
    assert!(
        local_hits
            .iter()
            .all(|hit| { hit.file != candidate || hit.start_offset != absolute_encoding }),
        "a leading-absolute dependency path must not resolve through a same-named local module: {local_hits:#?}"
    );
}

#[test]
fn rust_authoritative_inline_test_super_glob_keeps_parent_imported_module_paths() {
    let dispatcher = r#"
use crate::{marker, span};

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(_: &span::Attributes) -> span::Id {
        span::Id::from_u64(1)
    }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"tracing-core\"]\nresolver = \"2\"\n",
        ),
        (
            "tracing-core/Cargo.toml",
            "[package]\nname = \"tracing-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "tracing-core/src/lib.rs",
            "pub mod dispatcher;\npub mod marker;\npub mod span;\n",
        ),
        ("tracing-core/src/marker.rs", "pub struct Marker;\n"),
        (
            "tracing-core/src/span.rs",
            "pub struct Id;\npub struct Attributes;\nimpl Id { pub fn from_u64(_: u64) -> Self { Self } }\n",
        ),
        ("tracing-core/src/dispatcher.rs", dispatcher),
    ]);
    let candidate = project.file("tracing-core/src/dispatcher.rs");
    let candidates: HashSet<ProjectFile> = [candidate.clone()].into_iter().collect();

    for (fqn, marker) in [
        ("tracing-core.src.span.Attributes", "Attributes"),
        ("tracing-core.src.span.Id", "Id {"),
    ] {
        let target = definition(&analyzer, fqn);
        let hits = authoritative_hits(&analyzer, &target, candidates.clone());
        let expected = dispatcher.find(marker).expect("scoped type reference");
        assert!(
            hits.iter()
                .any(|hit| hit.file == candidate && hit.start_offset == expected),
            "missing inherited parent-module path for {fqn}: {hits:#?}"
        );
    }

    let id = definition(&analyzer, "tracing-core.src.span.Id");
    let id_hits = authoritative_hits(&analyzer, &id, candidates.clone());
    for expected in dispatcher
        .match_indices("span::Id")
        .map(|(offset, _)| offset + "span::".len())
    {
        assert!(
            id_hits
                .iter()
                .any(|hit| hit.file == candidate && hit.start_offset == expected),
            "missing inherited span::Id reference at {expected}: {id_hits:#?}"
        );
    }

    let span = definition(&analyzer, "tracing-core.src.span");
    let span_hits = authoritative_hits(&analyzer, &span, candidates);
    for expected in dispatcher.match_indices("span::").map(|(offset, _)| offset) {
        assert!(
            span_hits
                .iter()
                .any(|hit| hit.file == candidate && hit.start_offset == expected),
            "missing inherited span module qualifier at {expected}: {span_hits:#?}"
        );
    }
}

#[test]
fn rust_authoritative_examples_resolve_own_library_nested_types_and_aliases() {
    let manifest_example =
        "fn parse<T>() {}\nfn exercise() { parse::<::toml_benchmarks::manifest::Manifest>(); }\n";
    let alias_example =
        "fn exercise(_: comrak::nodes::AstNode) {}\nfn invalid(_: comrak::nodes::Private) {}\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"toml-benchmarks\", \"comrak\"]\nresolver = \"2\"\n",
        ),
        (
            "toml-benchmarks/Cargo.toml",
            "[package]\nname = \"toml_benchmarks\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("toml-benchmarks/src/lib.rs", "pub mod manifest;\n"),
        ("toml-benchmarks/src/manifest.rs", "pub struct Manifest;\n"),
        ("toml-benchmarks/examples/bench.rs", manifest_example),
        (
            "comrak/Cargo.toml",
            "[package]\nname = \"comrak\"\nversion = \"0.1.0\"\n",
        ),
        ("comrak/src/lib.rs", "pub mod nodes;\n"),
        (
            "comrak/src/nodes.rs",
            "pub type AstNode = usize;\npub(crate) struct Private;\n",
        ),
        ("comrak/examples/custom.rs", alias_example),
    ]);

    for (target_fqn, path, source, marker, expected_len) in [
        (
            "toml-benchmarks.src.manifest.Manifest",
            "toml-benchmarks/examples/bench.rs",
            manifest_example,
            "Manifest>();",
            "Manifest".len(),
        ),
        (
            "comrak.src.nodes.AstNode",
            "comrak/examples/custom.rs",
            alias_example,
            "AstNode) {}",
            "AstNode".len(),
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let candidate = project.file(path);
        let hits = authoritative_hits(
            &analyzer,
            &target,
            [candidate.clone()].into_iter().collect(),
        );
        let expected = source.find(marker).expect("own-library type witness");
        assert!(
            hits.iter().any(|hit| {
                hit.file == candidate
                    && hit.start_offset == expected
                    && hit.end_offset == expected + expected_len
            }),
            "missing authoritative own-library route for {target_fqn}: {hits:#?}"
        );
    }

    let private = definition(&analyzer, "comrak.src.nodes.Private");
    let alias_candidate = project.file("comrak/examples/custom.rs");
    let private_hits = authoritative_hits(
        &analyzer,
        &private,
        [alias_candidate.clone()].into_iter().collect(),
    );
    let private_reference = alias_example.find("Private) {}").expect("private witness");
    assert!(
        private_hits
            .iter()
            .all(|hit| { hit.file != alias_candidate || hit.start_offset != private_reference }),
        "a separate example crate must not see a pub(crate) current-library type: {private_hits:#?}"
    );
}

#[test]
fn rust_authoritative_relative_module_alias_resolves_associated_owner_type() {
    let consumer = r#"
use super::value;
fn exercise(value: &str) { value::ValueSerializer::with_style(); }
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"toml\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "mod ser;\n"),
        ("src/ser/mod.rs", "mod document;\nmod value;\n"),
        ("src/ser/document.rs", consumer),
        (
            "src/ser/value.rs",
            "pub struct ValueSerializer;\nimpl ValueSerializer { pub fn with_style() {} }\n",
        ),
    ]);
    let target = definition(&analyzer, "ser.value.ValueSerializer");
    let candidate = project.file("src/ser/document.rs");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        [candidate.clone()].into_iter().collect(),
    );
    let expected = consumer
        .find("ValueSerializer::with_style")
        .expect("associated owner");

    assert!(
        hits.iter().any(|hit| {
            hit.file == candidate
                && hit.start_offset == expected
                && hit.end_offset == expected + "ValueSerializer".len()
        }),
        "relative module alias must retain the exact associated owner type: {hits:#?}"
    );
}

#[test]
fn rust_authoritative_self_type_keeps_independent_example_identity() {
    let first = "struct FooError;\nimpl FooError { fn new() -> Self { Self } }\n";
    let second = "struct FooError;\nimpl FooError { fn new() -> Self { Self } }\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"examples\"]\nresolver = \"2\"\n",
        ),
        (
            "examples/Cargo.toml",
            "[package]\nname = \"examples\"\nversion = \"0.1.0\"\n\n[[example]]\nname = \"first\"\npath = \"examples/first.rs\"\n\n[[example]]\nname = \"second\"\npath = \"examples/second.rs\"\n",
        ),
        ("examples/src/lib.rs", "pub fn library_marker() {}\n"),
        ("examples/examples/first.rs", first),
        ("examples/examples/second.rs", second),
    ]);
    let first_file = project.file("examples/examples/first.rs");
    let second_file = project.file("examples/examples/second.rs");
    let target = analyzer
        .declarations(&first_file)
        .into_iter()
        .find(|declaration| declaration.is_class() && declaration.identifier() == "FooError")
        .expect("first example FooError");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        [first_file.clone(), second_file.clone()]
            .into_iter()
            .collect(),
    );
    let expected = first.find("Self { Self").expect("first Self return type");

    assert!(
        hits.iter().any(|hit| {
            hit.file == first_file
                && (hit.start_offset, hit.end_offset) == (expected, expected + "Self".len())
        }),
        "same-FQN examples must retain the physical Self owner: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| hit.file != second_file),
        "the independent same-FQN example must remain unrelated: {hits:#?}"
    );
}

#[test]
fn rust_authoritative_self_call_resolves_separate_inherent_impl_by_physical_owner() {
    let first = r#"
trait Service { fn call(); }
struct Svc;
impl Service for Svc { fn call() { Self::handle_request(); } }
impl Svc { fn handle_request() {} }
"#;
    let second = r#"
trait Service { fn call(); }
struct Svc;
impl Service for Svc { fn call() { Self::handle_request(); } }
impl Svc { fn handle_request() {} }
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"examples\"]\nresolver = \"2\"\n",
        ),
        (
            "examples/Cargo.toml",
            "[package]\nname = \"examples\"\nversion = \"0.1.0\"\n\n[[example]]\nname = \"first\"\npath = \"examples/first.rs\"\n\n[[example]]\nname = \"second\"\npath = \"examples/second.rs\"\n",
        ),
        ("examples/src/lib.rs", "pub fn library_marker() {}\n"),
        ("examples/examples/first.rs", first),
        ("examples/examples/second.rs", second),
    ]);
    let first_file = project.file("examples/examples/first.rs");
    let second_file = project.file("examples/examples/second.rs");
    let target = analyzer
        .exact_member(&first_file, "Svc", "handle_request", true)
        .expect("first Svc::handle_request");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        [first_file.clone(), second_file.clone()]
            .into_iter()
            .collect(),
    );
    let expected = first
        .find("handle_request();")
        .expect("first Self-associated terminal");

    assert!(
        hits.iter().any(|hit| {
            hit.file == first_file
                && (hit.start_offset, hit.end_offset)
                    == (expected, expected + "handle_request".len())
        }),
        "Self in a trait impl must resolve a separate inherent impl on the same physical owner: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| hit.file != second_file),
        "an independent same-FQN owner must remain unrelated: {hits:#?}"
    );
}

#[test]
fn rust_authoritative_self_associated_type_keeps_physical_impl_owner() {
    let first = r#"
trait Service { type Future; fn call() -> Self::Future; }
struct Svc;
impl Service for Svc {
    type Future = ();
    fn call() -> Self::Future { () }
}
"#;
    let second = r#"
trait Service { type Future; fn call() -> Self::Future; }
struct Svc;
impl Service for Svc {
    type Future = ();
    fn call() -> Self::Future { () }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"examples\"]\nresolver = \"2\"\n",
        ),
        (
            "examples/Cargo.toml",
            "[package]\nname = \"examples\"\nversion = \"0.1.0\"\n\n[[example]]\nname = \"first\"\npath = \"examples/first.rs\"\n\n[[example]]\nname = \"second\"\npath = \"examples/second.rs\"\n",
        ),
        ("examples/src/lib.rs", "pub fn library_marker() {}\n"),
        ("examples/examples/first.rs", first),
        ("examples/examples/second.rs", second),
    ]);
    let first_file = project.file("examples/examples/first.rs");
    let second_file = project.file("examples/examples/second.rs");
    let target = analyzer
        .exact_member(&first_file, "Svc", "Future", false)
        .expect("first Svc::Future associated type");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        [first_file.clone(), second_file.clone()]
            .into_iter()
            .collect(),
    );
    let expected = first
        .rfind("Self::Future")
        .expect("first associated type reference")
        + "Self::".len();

    assert!(
        hits.iter().any(|hit| {
            hit.file == first_file
                && (hit.start_offset, hit.end_offset) == (expected, expected + "Future".len())
        }),
        "Self::Future must retain its physical trait-impl associated type: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| hit.file != second_file),
        "an independent same-FQN associated type must remain unrelated: {hits:#?}"
    );
}

#[test]
fn rust_authoritative_dependency_reexport_resolves_associated_call_owner() {
    let consumer = "use tracing_error::ErrorLayer;\nfn install() { let _ = ErrorLayer::default(); let _ = ErrorLayer::hidden(); }\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"tracing-error\", \"examples\"]\nresolver = \"2\"\n",
        ),
        (
            "tracing-error/Cargo.toml",
            "[package]\nname = \"tracing-error\"\nversion = \"0.1.0\"\n",
        ),
        (
            "tracing-error/src/lib.rs",
            "mod layer;\npub use self::layer::ErrorLayer;\n",
        ),
        (
            "tracing-error/src/layer.rs",
            "pub struct ErrorLayer;\nimpl Default for ErrorLayer { fn default() -> Self { Self } }\ntrait Hidden { fn hidden() -> Self; }\nimpl Hidden for ErrorLayer { fn hidden() -> Self { Self } }\n",
        ),
        (
            "examples/Cargo.toml",
            "[package]\nname = \"examples\"\nversion = \"0.1.0\"\n\n[dependencies]\ntracing_error = { package = \"tracing-error\", path = \"../tracing-error\" }\n",
        ),
        ("examples/src/lib.rs", consumer),
    ]);
    let target = analyzer
        .exact_member(
            &project.file("tracing-error/src/layer.rs"),
            "ErrorLayer",
            "default",
            true,
        )
        .expect("ErrorLayer::default");
    let candidate = project.file("examples/src/lib.rs");
    let hits = authoritative_hits(
        &analyzer,
        &target,
        [candidate.clone()].into_iter().collect(),
    );
    let expected = consumer.rfind("default").expect("associated terminal");

    assert!(
        hits.iter().any(|hit| {
            hit.file == candidate
                && (hit.start_offset, hit.end_offset) == (expected, expected + "default".len())
        }),
        "an associated call through a dependency's public owner reexport must resolve physically: {hits:#?}"
    );

    let hidden = analyzer
        .exact_member(
            &project.file("tracing-error/src/layer.rs"),
            "ErrorLayer",
            "hidden",
            true,
        )
        .expect("private Hidden::hidden impl");
    let hidden_hits = authoritative_hits(
        &analyzer,
        &hidden,
        [candidate.clone()].into_iter().collect(),
    );
    assert!(
        hidden_hits.is_empty(),
        "a private dependency trait must not become callable through its public impl owner: {hidden_hits:#?}"
    );
}

#[test]
fn rust_authoritative_associated_member_declared_on_type_alias_is_scanned_as_member() {
    let source = r#"
pub enum EitherWriter<A, B> { A(A), B(B) }
pub type OptionalWriter<T> = EitherWriter<T, ()>;

impl<T> OptionalWriter<T> {
    pub fn some(value: T) -> Self { EitherWriter::A(value) }
}

fn make() { let _ = OptionalWriter::some(1usize); }
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);
    let file = project.file("src/lib.rs");
    let target = analyzer
        .exact_member(&file, "OptionalWriter", "some", true)
        .expect("OptionalWriter::some declaration");
    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());
    let expected = source.rfind("some").expect("associated call terminal");

    assert!(
        hits.iter().any(|hit| {
            hit.file == file
                && (hit.start_offset, hit.end_offset) == (expected, expected + "some".len())
        }),
        "an impl member declared through a type alias must use member routing: {hits:#?}"
    );
}

#[test]
fn rust_cargo_dependency_kinds_scope_public_inverse_resolution() {
    let library = r#"
fn normal(_: normal_dep::Shared) {}
#[cfg(test)]
mod tests { fn development(_: dev_dep::Shared) {} }
fn invalid_build(_: build_dep::Shared) {}
"#;
    let example = "fn development(_: dev_dep::Shared) {}\n";
    let build_script =
        "fn build_only(_: build_dep::Shared) {}\nfn invalid_normal(_: normal_dep::Shared) {}\n";
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"normal\", \"development\", \"build-dep\"]\nresolver = \"2\"\n",
        ),
        (
            "normal/Cargo.toml",
            "[package]\nname = \"normal-package\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("normal/src/lib.rs", "pub struct Shared;\n"),
        (
            "development/Cargo.toml",
            "[package]\nname = \"development-package\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("development/src/lib.rs", "pub struct Shared;\n"),
        (
            "build-dep/Cargo.toml",
            "[package]\nname = \"build-package\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("build-dep/src/lib.rs", "pub struct Shared;\n"),
        (
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nnormal_dep = { package = \"normal-package\", path = \"../normal\" }\n\n[dev-dependencies]\ndev_dep = { package = \"development-package\", path = \"../development\" }\n\n[build-dependencies]\nbuild_dep = { package = \"build-package\", path = \"../build-dep\" }\n",
        ),
        ("app/src/lib.rs", library),
        ("app/examples/demo.rs", example),
        ("app/build.rs", build_script),
    ]);

    let normal_hits = rust_graph_hits(&analyzer, "normal.src.Shared");
    let normal = library.find("normal_dep::Shared").unwrap() + "normal_dep::".len();
    let invalid_normal = build_script.find("normal_dep::Shared").unwrap() + "normal_dep::".len();
    assert!(
        normal_hits.iter().any(|hit| {
            hit.file == project.file("app/src/lib.rs") && hit.start_offset == normal
        }),
        "{normal_hits:#?}"
    );
    assert!(normal_hits.iter().all(|hit| {
        hit.file != project.file("app/build.rs") || hit.start_offset != invalid_normal
    }));

    let development_hits = rust_graph_hits(&analyzer, "development.src.Shared");
    let unit_test = library.find("dev_dep::Shared").unwrap() + "dev_dep::".len();
    let example_use = example.find("dev_dep::Shared").unwrap() + "dev_dep::".len();
    for (path, start) in [
        ("app/src/lib.rs", unit_test),
        ("app/examples/demo.rs", example_use),
    ] {
        assert!(
            development_hits
                .iter()
                .any(|hit| { hit.file == project.file(path) && hit.start_offset == start })
        );
    }

    let build_hits = rust_graph_hits(&analyzer, "build-dep.src.Shared");
    let build_use = build_script.find("build_dep::Shared").unwrap() + "build_dep::".len();
    let invalid_build = library.find("build_dep::Shared").unwrap() + "build_dep::".len();
    assert!(
        build_hits.iter().any(|hit| {
            hit.file == project.file("app/build.rs") && hit.start_offset == build_use
        }),
        "{build_hits:#?}"
    );
    assert!(build_hits.iter().all(|hit| {
        hit.file != project.file("app/src/lib.rs") || hit.start_offset != invalid_build
    }));
}
