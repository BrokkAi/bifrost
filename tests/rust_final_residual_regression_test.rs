mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageHit};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, RustAnalyzer};
use common::InlineTestProject;
use std::collections::BTreeSet;
use std::sync::Arc;

fn analyzer_for(source: &str) -> (common::BuiltInlineTestProject, RustAnalyzer) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn definition_in_file(
    analyzer: &RustAnalyzer,
    file: &brokk_bifrost::ProjectFile,
    name: &str,
) -> CodeUnit {
    analyzer
        .declarations(file)
        .into_iter()
        .find(|unit| unit.identifier() == name)
        .unwrap_or_else(|| panic!("missing definition {name} in {file}"))
}

fn member(analyzer: &RustAnalyzer, owner: &str, name: &str) -> CodeUnit {
    let file = analyzer
        .get_analyzed_files()
        .into_iter()
        .next()
        .expect("Rust test file");
    analyzer
        .exact_member(&file, owner, name, true)
        .or_else(|| analyzer.exact_member(&file, owner, name, false))
        .unwrap_or_else(|| panic!("missing member {owner}.{name}"))
}

fn hits(analyzer: &RustAnalyzer, target: CodeUnit) -> Vec<UsageHit> {
    UsageFinder::new()
        .find_usages_default(analyzer, &[target])
        .into_either()
        .expect("Rust inverse lookup")
        .into_iter()
        .collect()
}

fn authoritative_hits(
    analyzer: &RustAnalyzer,
    target: CodeUnit,
    candidates: HashSet<brokk_bifrost::ProjectFile>,
) -> BTreeSet<UsageHit> {
    let max_files = candidates.len();
    let provider = ExplicitCandidateProvider::new(Arc::new(candidates));
    match UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(analyzer, &[target], Some(&provider), max_files, 100)
        .result
    {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload.into_values().flatten().collect(),
        other => panic!("expected authoritative Rust usage success, got {other:#?}"),
    }
}

#[test]
fn inverse_rust_associated_member_uses_physical_owner_beneath_reexport() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"owner-seed\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "mod ready;\npub use ready::Ready;\nmod consumer;\n",
        )
        .file(
            "src/ready.rs",
            "pub struct Ready(usize);\nimpl Ready { pub(crate) fn from_usize(value: usize) -> Self { Self(value) } }\n",
        )
        .file(
            "src/consumer.rs",
            "use crate::ready::Ready;\nfn make() { let _ = Ready::from_usize(1); }\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = analyzer
        .exact_member(&project.file("src/ready.rs"), "Ready", "from_usize", true)
        .expect("Ready::from_usize declaration");
    let found = authoritative_hits(
        &analyzer,
        target,
        [project.file("src/consumer.rs")].into_iter().collect(),
    );
    let source = "use crate::ready::Ready;\nfn make() { let _ = Ready::from_usize(1); }\n";
    let start = source.find("from_usize").expect("associated call");

    assert!(
        found.iter().any(|hit| {
            hit.file == project.file("src/consumer.rs")
                && (hit.start_offset, hit.end_offset) == (start, start + "from_usize".len())
        }),
        "a public reexport must not replace the physical associated owner seed: {found:#?}"
    );
}

#[test]
fn inverse_rust_preserves_external_module_visibility_through_item_macro_routes() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"macro-modules\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "macro_rules! cfg_item { ($($item:item)*) => { $(#[cfg(any())] $item)* }; }\nmod parent { cfg_item! { pub(crate) mod child; mod hidden; } }\nmod consumer;\nmod outsider;\nmod outsider_two;\n",
        )
        .file("src/parent/child.rs", "pub(crate) const TARGET: usize = 1;\n")
        .file("src/parent/hidden.rs", "pub(crate) const HIDDEN: usize = 2;\n")
        .file(
            "src/consumer.rs",
            "mod nested { use crate::parent::child::TARGET; fn value() { let _ = TARGET; } }\n",
        )
        .file(
            "src/outsider.rs",
            "fn values() { let _ = crate::parent::child::TARGET; let _ = crate::parent::hidden::HIDDEN; }\n",
        )
        .file(
            "src/outsider_two.rs",
            "fn values() { let _ = crate::parent::child::TARGET; let _ = crate::parent::hidden::HIDDEN; }\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition_in_file(&analyzer, &project.file("src/parent/child.rs"), "TARGET");
    for candidate in ["src/outsider.rs", "src/outsider_two.rs"] {
        let target_hits = authoritative_hits(
            &analyzer,
            target.clone(),
            [project.file(candidate)].into_iter().collect(),
        );
        assert_eq!(
            1,
            target_hits.len(),
            "pub(crate) module visibility must survive the proven item-macro route in {candidate}: {target_hits:#?}"
        );
    }
    let nested_hits = authoritative_hits(
        &analyzer,
        target,
        [project.file("src/consumer.rs")].into_iter().collect(),
    );
    assert_eq!(
        2,
        nested_hits.len(),
        "an import owned by an inline module must retain the exact physical target: {nested_hits:#?}"
    );
    assert!(nested_hits.iter().any(|hit| hit.start_offset == 68));

    let hidden = definition_in_file(&analyzer, &project.file("src/parent/hidden.rs"), "HIDDEN");
    for candidate in ["src/outsider.rs", "src/outsider_two.rs"] {
        let hidden_hits = authoritative_hits(
            &analyzer,
            hidden.clone(),
            [project.file(candidate)].into_iter().collect(),
        );
        assert!(
            hidden_hits.is_empty(),
            "a private macro-routed module must remain inaccessible in {candidate}: {hidden_hits:#?}"
        );
    }
}

#[test]
fn inverse_rust_resolves_descendants_through_imported_module_aliases() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"module-alias\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub(crate) mod util;\nmod consumer;\n")
        .file("src/util/mod.rs", "pub(crate) mod time;\n")
        .file(
            "src/util/time.rs",
            "pub(crate) fn next_expiration_time() {}\n",
        )
        .file(
            "src/consumer.rs",
            "use crate::util;\nfn call() { util::time::next_expiration_time(); }\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition_in_file(
        &analyzer,
        &project.file("src/util/time.rs"),
        "next_expiration_time",
    );
    let found = authoritative_hits(
        &analyzer,
        target,
        [project.file("src/consumer.rs")].into_iter().collect(),
    );
    let source = "use crate::util;\nfn call() { util::time::next_expiration_time(); }\n";
    let start = source
        .rfind("next_expiration_time")
        .expect("qualified call");

    assert!(found.iter().any(|hit| {
        hit.file == project.file("src/consumer.rs")
            && (hit.start_offset, hit.end_offset) == (start, start + "next_expiration_time".len())
    }));
}

#[test]
fn inverse_rust_macro_export_crosses_own_library_example_boundary() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"own-macros\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "#[macro_export]\nmacro_rules! exported_dbg { () => {} }\nmacro_rules! private_dbg { () => {} }\n",
        )
        .file(
            "examples/demo.rs",
            "use own_macros::{exported_dbg, private_dbg};\nfn main() { exported_dbg!(); private_dbg!(); }\n",
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let candidate: HashSet<brokk_bifrost::ProjectFile> =
        [project.file("examples/demo.rs")].into_iter().collect();

    let exported = definition_in_file(&analyzer, &project.file("src/lib.rs"), "exported_dbg");
    let exported_hits = authoritative_hits(&analyzer, exported, candidate.clone());
    let example = "use own_macros::{exported_dbg, private_dbg};\nfn main() { exported_dbg!(); private_dbg!(); }\n";
    let exported_call = example.find("exported_dbg!").expect("exported call");
    assert!(
        exported_hits
            .iter()
            .any(|hit| hit.start_offset == exported_call),
        "macro_export must be public to the package example target: {exported_hits:#?}"
    );

    let private = definition_in_file(&analyzer, &project.file("src/lib.rs"), "private_dbg");
    let private_hits = authoritative_hits(&analyzer, private, candidate);
    assert!(
        private_hits.is_empty(),
        "an unexported macro must not cross into the package example target: {private_hits:#?}"
    );
}

#[test]
fn inverse_rust_usages_find_unqualified_tuple_pattern_variants() {
    let source = r#"
enum ExpectedValue { I64(i64), Other }
enum Decoy { I64(i64) }

fn same(left: ExpectedValue, right: ExpectedValue) -> bool {
    use ExpectedValue::*;
    match (left, right) {
        (I64(a), I64(b)) => a == b,
        _ => false,
    }
}

fn decoy(value: Decoy) -> i64 {
    match value { Decoy::I64(inner) => inner }
}
"#;
    let (_project, analyzer) = analyzer_for(source);
    let variant = member(&analyzer, "ExpectedValue", "I64");
    let found = hits(&analyzer, variant);
    let expected: Vec<_> = source
        .match_indices("I64")
        .skip(2)
        .take(2)
        .map(|(start, name)| (start, start + name.len()))
        .collect();

    assert_eq!(2, found.len(), "tuple-pattern variant hits: {found:#?}");
    assert!(expected.into_iter().all(|range| {
        found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == range)
    }));
}

#[test]
fn inverse_rust_tuple_pattern_variants_fail_closed_on_shadowing_and_ambiguity() {
    let source = r#"
enum Wanted { I64(i64), Other }
enum Decoy { I64(i64), Other }

fn explicit_decoy(value: Decoy) -> i64 {
    use Wanted::*;
    use Decoy::I64;
    match value { I64(inner) => inner, _ => 0 }
}

fn ambiguous(value: Wanted) -> i64 {
    use Wanted::*;
    use Decoy::*;
    match value { I64(inner) => inner, _ => 0 }
}

fn local_item() -> i64 {
    use Wanted::*;
    struct I64(i64);
    let value = I64(1);
    match value { I64(inner) => inner }
}

fn scoped_decoy(value: Decoy) -> i64 {
    match value { Decoy::I64(inner) => inner, _ => 0 }
}
"#;
    let (_project, analyzer) = analyzer_for(source);
    let wanted = member(&analyzer, "Wanted", "I64");
    let found = hits(&analyzer, wanted);

    assert!(
        found.is_empty(),
        "decoy, ambiguous, local-item, and scoped-decoy patterns must not cross-match: {found:#?}"
    );
}

#[test]
fn inverse_rust_usages_keep_nested_struct_initializer_field_owner() {
    let source = r#"
struct Waiter { pointers: usize }
struct WaiterCell(Waiter);
struct Recv { waiter: WaiterCell }
struct Decoy { pointers: usize }

fn make() -> Recv {
    Recv { waiter: WaiterCell(Waiter { pointers: 1 }) }
}

fn decoy() -> Decoy {
    Decoy { pointers: 2 }
}
"#;
    let (_project, analyzer) = analyzer_for(source);
    let field = member(&analyzer, "Waiter", "pointers");
    let found = hits(&analyzer, field);
    let expected = source
        .match_indices("pointers")
        .nth(2)
        .map(|(start, name)| (start, start + name.len()))
        .expect("Waiter initializer field");

    assert_eq!(1, found.len(), "nested initializer field hits: {found:#?}");
    assert_eq!(
        expected,
        (found[0].start_offset, found[0].end_offset),
        "the Decoy field must not cross-match"
    );
}

#[test]
fn inverse_rust_usages_keep_both_nested_same_file_calls() {
    let source = r#"
pub struct Level(usize);
pub struct LevelFilter(Option<Level>);

fn filter_as_usize(value: &Option<Level>) -> usize { value.is_some() as usize }

impl Ord for LevelFilter {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        filter_as_usize(&other.0).cmp(&filter_as_usize(&self.0))
    }
}

fn shadowed(filter_as_usize: fn(&Option<Level>) -> usize) -> usize {
    filter_as_usize(&None)
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"tracing-core\"]\nresolver = \"2\"\n",
        )
        .file(
            "tracing-core/Cargo.toml",
            "[package]\nname = \"tracing-core\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "tracing-core/src/lib.rs",
            "#[macro_export]\nmacro_rules! metadata { () => {} }\npub mod metadata;\n",
        )
        .file("tracing-core/src/metadata.rs", source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "tracing-core.src.metadata.filter_as_usize");
    let candidates: HashSet<_> = [project.file("tracing-core/src/metadata.rs")]
        .into_iter()
        .collect();
    let found = authoritative_hits(&analyzer, target, candidates);
    let expected: Vec<_> = source
        .match_indices("filter_as_usize")
        .skip(1)
        .take(2)
        .map(|(start, name)| (start, start + name.len()))
        .collect();

    assert_eq!(2, found.len(), "nested same-file call hits: {found:#?}");
    assert!(expected.into_iter().all(|range| {
        found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == range)
    }));
}

#[test]
fn inverse_rust_usages_resolve_nested_self_crate_import_through_private_module_reexport() {
    let consumer = r#"
macro_rules! consume { ($value:expr) => {}; }

fn small() {
    use demo::{Arena, Options};
    let _arena = Arena;
    consume!(Options::default());
}

fn large() {
    use demo::Options;
    let _options = Options::default();
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "mod parser;\npub struct Arena;\npub use parser::Options;\n",
        )
        .file(
            "src/parser/mod.rs",
            "pub mod options;\npub use crate::parser::options::Options;\n",
        )
        .file(
            "src/parser/options.rs",
            "#[derive(Default)]\npub struct Options;\n",
        )
        .file("src/main.rs", "pub struct Options;\n")
        .file("build.rs", "pub struct Options;\n")
        .file("examples/client.rs", consumer)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "parser.options.Options");
    let candidates = [project.file("examples/client.rs")].into_iter().collect();
    let found = authoritative_hits(&analyzer, target, candidates);
    let expected: Vec<_> = consumer
        .match_indices("Options::default")
        .map(|(start, _)| (start, start + "Options".len()))
        .collect();

    assert!(
        expected.iter().all(|expected| found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == *expected)),
        "nested import must resolve through the public re-export chain: {found:#?}"
    );

    for decoy_file in [project.file("src/main.rs"), project.file("build.rs")] {
        let decoy = definition_in_file(&analyzer, &decoy_file, "Options");
        let candidates = [project.file("examples/client.rs")].into_iter().collect();
        let decoy_hits = authoritative_hits(&analyzer, decoy, candidates);
        assert!(
            decoy_hits.is_empty(),
            "the crate-name import must route only to the Cargo library root: {decoy_hits:#?}"
        );
    }
}

#[test]
fn inverse_rust_usages_canonicalize_self_owner_through_type_alias() {
    let consumer = r#"
use demo::{ListStyleType, options};

impl From<ListStyleType> for options::ListStyleType {
    fn from(_: ListStyleType) -> Self {
        Self::Plus
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "mod parser;\npub use parser::options;\npub type ListStyleType = parser::options::ListStyleType;\n",
        )
        .file("src/parser/mod.rs", "pub mod options;\n")
        .file(
            "src/parser/options.rs",
            "pub enum ListStyleType { Plus, Dash }\n",
        )
        .file("src/main.rs", consumer)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "parser.options.ListStyleType");
    let candidates = [project.file("src/main.rs")].into_iter().collect();
    let found = authoritative_hits(&analyzer, target, candidates);
    let expected = consumer
        .rfind("Self")
        .map(|start| (start, start + "Self".len()))
        .expect("Self variant owner reference");

    assert!(
        found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == expected),
        "Self must resolve through the root type alias to the physical enum: {found:#?}"
    );
}

#[test]
fn inverse_rust_usages_reject_ambiguous_self_owner_alias() {
    let consumer = r#"
pub enum ListStyleType { Plus }

impl From<ListStyleType> for ListStyleType {
    fn from(_: ListStyleType) -> Self {
        Self::Plus
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "mod parser;\npub type ListStyleType = parser::ListStyleType;\n",
        )
        .file("src/parser.rs", "pub enum ListStyleType { Plus, Dash }\n")
        .file("src/main.rs", consumer)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let physical = definition(&analyzer, "parser.ListStyleType");
    let candidates = [project.file("src/main.rs")].into_iter().collect();
    let found = authoritative_hits(&analyzer, physical, candidates);
    let self_range = consumer
        .rfind("Self")
        .map(|start| (start, start + "Self".len()))
        .expect("Self variant owner reference");

    assert!(
        found
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != self_range),
        "ambiguous root owner identity must not canonicalize to the physical enum: {found:#?}"
    );
}

#[test]
fn inverse_rust_usages_do_not_shadow_imported_type_with_impl_associated_type_name() {
    let consumer = r#"
use super::Error;

pub struct KeySerializer;
impl Serializer for KeySerializer {
    type Error = Error;
    type Sequence = Impossible<Self::Error, Error>;

    fn failure(&self) -> Result<(), Error> {
        let _value: Error = Error;
        Ok(())
    }

    fn associated(&self) -> Option<Self::Error> {
        None
    }
}

fn local_alias() {
    type Error = ();
    let _: Error;
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub mod ser;\n")
        .file(
            "src/ser.rs",
            "pub mod key;\npub struct Error;\npub trait Serializer { type Error; type Sequence; }\npub struct Impossible<A, B>(A, B);\n",
        )
        .file("src/ser/key.rs", consumer)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "ser.Error");
    let candidates = [project.file("src/ser/key.rs")].into_iter().collect();
    let found = authoritative_hits(&analyzer, target, candidates);
    let direct_rhs = consumer
        .find("type Error = Error")
        .map(|start| start + "type Error = ".len())
        .map(|start| (start, start + "Error".len()))
        .expect("direct associated type RHS reference");
    let generic_rhs = consumer
        .find("Impossible<Self::Error, Error>")
        .map(|start| start + "Impossible<Self::Error, ".len())
        .map(|start| (start, start + "Error".len()))
        .expect("generic Error reference");
    let self_associated = consumer
        .find("Self::Error")
        .map(|start| start + "Self::".len())
        .map(|start| (start, start + "Error".len()))
        .expect("Self associated type reference");
    let method_import_references: Vec<_> = ["Result<(), Error>", "_value: Error", "= Error;"]
        .into_iter()
        .map(|needle| {
            consumer
                .find(needle)
                .map(|start| start + needle.rfind("Error").expect("Error in method marker"))
                .map(|start| (start, start + "Error".len()))
                .unwrap_or_else(|| panic!("missing method Error reference marker {needle}"))
        })
        .collect();
    let method_self_associated = consumer
        .rfind("Self::Error")
        .map(|start| start + "Self::".len())
        .map(|start| (start, start + "Error".len()))
        .expect("method Self associated type reference");
    let local_alias_reference = consumer
        .find("let _: Error")
        .map(|start| start + "let _: ".len())
        .map(|start| (start, start + "Error".len()))
        .expect("local type alias reference");

    for expected in [direct_rhs, generic_rhs]
        .into_iter()
        .chain(method_import_references)
    {
        assert!(
            found
                .iter()
                .any(|hit| (hit.start_offset, hit.end_offset) == expected),
            "an associated type name must not shadow imported RHS type references: {found:#?}"
        );
    }
    assert!(
        found.iter().all(|hit| ![
            self_associated,
            method_self_associated,
            local_alias_reference
        ]
        .contains(&(hit.start_offset, hit.end_offset))),
        "associated and local aliases must remain distinct from the imported type: {found:#?}"
    );
}

#[test]
fn inverse_rust_usages_find_impl_associated_type_through_self_in_macro_owner() {
    let source = r#"
pub trait Stream { type Item; }

pin_project! {
    pub struct TimeoutRepeating<S> {
        stream: S,
    }
}

pub struct Other;

impl<S: Stream> Stream for TimeoutRepeating<S> {
    type Item = Result<S::Item, ()>;

    fn poll_next(&mut self) -> Option<Self::Item> {
        None
    }
}


impl Stream for Other {
    type Item = ();

    fn poll_next(&mut self) -> Option<Self::Item> {
        None
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "TimeoutRepeating.Item");
    assert_eq!(
        analyzer.parent_of(&target).as_ref().map(CodeUnit::fq_name),
        Some("TimeoutRepeating".to_string()),
        "macro-defined impl members must retain their structural owner"
    );
    let candidates = [project.file("src/lib.rs")].into_iter().collect();
    let found = authoritative_hits(&analyzer, target, candidates);
    let target_impl = source.find("impl<S: Stream>").expect("target impl");
    let expected = source[target_impl..]
        .find("Self::Item")
        .map(|start| target_impl + start + "Self::".len())
        .map(|start| (start, start + "Item".len()))
        .expect("Self::Item reference");
    let other_impl = source.find("impl Stream for Other").expect("other impl");
    let unrelated = source[other_impl..]
        .find("Self::Item")
        .map(|start| other_impl + start + "Self::".len())
        .map(|start| (start, start + "Item".len()))
        .expect("unrelated Self::Item reference");

    assert!(
        found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == expected),
        "Self::Item must resolve to the impl associated type: {found:#?}"
    );
    assert!(
        found
            .iter()
            .all(|hit| (hit.start_offset, hit.end_offset) != unrelated),
        "Self::Item in another impl must not resolve to the target: {found:#?}"
    );
}
