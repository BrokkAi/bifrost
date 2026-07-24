//! Same-owner scan-usages surface policy — #1014 facet B.
//!
//! The default `scan_usages` surface keeps excluding same-owner hits (a call
//! whose receiver is the current instance / own type), but the exclusion is now
//! uniform, honest, and inspectable:
//!
//! - same-owner sites are counted as `same_owner_sites`, never silently dropped;
//! - a zero-external result with same-owner sites reports `no_external_usages`,
//!   never the confident `verified_absent` lie both tokio repros hit;
//! - `include_same_owner: true` lists the sites, kind-tagged `self_receiver`.
//!
//! Scala is intentionally not in the uniformity matrix below: its usage graph
//! uses an event-driven catalog that does not carry receiver shape to the record
//! site, so its same-owner classification is deferred (see the facet-B report).

mod common;

use brokk_bifrost::{
    AnalyzerConfig, Language,
    searchtools::{
        ScanUsagesByReferenceParams, ScanUsagesEntry, ScanUsagesStatus, scan_usages_by_reference,
    },
};
use common::InlineTestProject;

fn scan(
    language: Language,
    files: &[(&str, &str)],
    symbol: &str,
    include_same_owner: bool,
) -> ScanUsagesEntry {
    let mut project = InlineTestProject::with_language(language);
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();
    let workspace = built.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let mut result = scan_usages_by_reference(
        analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec![symbol.to_string()],
            include_tests: true,
            paths: None,
            include_same_owner,
        },
    );
    assert_eq!(
        result.results.len(),
        1,
        "expected exactly one scan result for {symbol}: {result:#?}"
    );
    result.results.pop().expect("one result")
}

/// A same-owner-only caller yields `no_external_usages` with one same-owner site
/// and zero external hits — never `verified_absent`.
fn assert_same_owner_only(language: Language, files: &[(&str, &str)], symbol: &str) {
    let entry = scan(language, files, symbol, false);
    assert_eq!(
        entry.status,
        ScanUsagesStatus::NoExternalUsages,
        "{language:?} {symbol} should report no_external_usages, not verified_absent: {entry:#?}"
    );
    assert_eq!(
        entry.total_hits,
        Some(0),
        "{language:?} {symbol} should have zero external hits: {entry:#?}"
    );
    assert_eq!(
        entry.same_owner_sites,
        Some(1),
        "{language:?} {symbol} should report one same-owner site: {entry:#?}"
    );
    // The site is not listed unless requested.
    assert!(
        entry.same_owner_files.is_empty(),
        "{language:?} {symbol} must not list same-owner sites by default: {entry:#?}"
    );
}

/// A genuinely uncalled symbol stays `verified_absent` with no same-owner sites.
fn assert_verified_absent(language: Language, files: &[(&str, &str)], symbol: &str) {
    let entry = scan(language, files, symbol, false);
    assert_eq!(
        entry.status,
        ScanUsagesStatus::VerifiedAbsent,
        "{language:?} {symbol} should report verified_absent: {entry:#?}"
    );
    assert_eq!(
        entry.same_owner_sites, None,
        "{language:?} {symbol} should have no same-owner sites: {entry:#?}"
    );
}

// --- Per-language fixtures: `target` is called only via a same-owner receiver,
// `uncalled` has no callers at all. ---------------------------------------------

const JAVA: &[(&str, &str)] = &[(
    "Foo.java",
    "class Foo {\n  void target() {}\n  void caller() { this.target(); }\n  void uncalled() {}\n}\n",
)];

const PYTHON: &[(&str, &str)] = &[(
    "foo.py",
    "class Foo:\n    def target(self):\n        pass\n    def caller(self):\n        self.target()\n    def uncalled(self):\n        pass\n",
)];

const RUBY: &[(&str, &str)] = &[(
    "foo.rb",
    "class Foo\n  def target\n  end\n  def caller\n    self.target\n  end\n  def uncalled\n  end\nend\n",
)];

const PHP: &[(&str, &str)] = &[(
    "Foo.php",
    "<?php\nclass Foo {\n  function target() {}\n  function caller() { $this->target(); }\n  function uncalled() {}\n}\n",
)];

const CSHARP: &[(&str, &str)] = &[(
    "Foo.cs",
    "class Foo {\n  void target() {}\n  void caller() { this.target(); }\n  void uncalled() {}\n}\n",
)];

const GO: &[(&str, &str)] = &[
    ("go.mod", "module example.com/m\n"),
    (
        "p/foo.go",
        "package p\ntype Foo struct{}\nfunc (f *Foo) target() {}\nfunc (f *Foo) caller() { f.target() }\nfunc (f *Foo) uncalled() {}\n",
    ),
];

const RUST: &[(&str, &str)] = &[(
    "foo.rs",
    "pub struct Foo;\nimpl Foo {\n    pub fn target(&self) {}\n    pub fn caller(&self) { self.target(); }\n    pub fn uncalled(&self) {}\n}\n",
)];

const TYPESCRIPT: &[(&str, &str)] = &[(
    "foo.ts",
    "export class Foo {\n  target() {}\n  caller() { this.target(); }\n  uncalled() {}\n}\n",
)];

const JAVASCRIPT: &[(&str, &str)] = &[(
    "foo.js",
    "export class Foo {\n  target() {}\n  caller() { this.target(); }\n  uncalled() {}\n}\n",
)];

const CPP: &[(&str, &str)] = &[(
    "foo.cpp",
    "class Foo {\npublic:\n  void target() {}\n  void caller() { this->target(); }\n  void uncalled() {}\n};\n",
)];

macro_rules! uniformity_case {
    ($name:ident, $lang:expr, $files:expr) => {
        #[test]
        fn $name() {
            assert_same_owner_only($lang, $files, "Foo.target");
            assert_verified_absent($lang, $files, "Foo.uncalled");
        }
    };
}

uniformity_case!(java_same_owner_only, Language::Java, JAVA);
uniformity_case!(python_same_owner_only, Language::Python, PYTHON);
uniformity_case!(ruby_same_owner_only, Language::Ruby, RUBY);
uniformity_case!(php_same_owner_only, Language::Php, PHP);
uniformity_case!(csharp_same_owner_only, Language::CSharp, CSHARP);
uniformity_case!(rust_same_owner_only, Language::Rust, RUST);
uniformity_case!(typescript_same_owner_only, Language::TypeScript, TYPESCRIPT);
uniformity_case!(javascript_same_owner_only, Language::JavaScript, JAVASCRIPT);
uniformity_case!(cpp_same_owner_only, Language::Cpp, CPP);

// Go's fq_name is import-path-qualified; resolve the method by its owner-scoped
// name.
#[test]
fn go_same_owner_only() {
    assert_same_owner_only(Language::Go, GO, "Foo.target");
    assert_verified_absent(Language::Go, GO, "Foo.uncalled");
}

// --- Mixed: one external caller + one same-owner caller -> found, external 1,
// same-owner 1. Also the different-instance negative: `other.target()` through a
// distinct `&Foo` stays external. ----------------------------------------------

#[test]
fn mixed_external_and_same_owner() {
    let files: &[(&str, &str)] = &[(
        "foo.rs",
        "pub struct Foo;\nimpl Foo {\n    pub fn target(&self) {}\n    pub fn sibling(&self) { self.target(); }\n}\npub fn external(f: &Foo) { f.target(); }\n",
    )];
    let entry = scan(Language::Rust, files, "Foo.target", false);
    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");
    assert_eq!(entry.total_hits, Some(1), "external hit only: {entry:#?}");
    assert_eq!(
        entry.same_owner_sites,
        Some(1),
        "one same-owner: {entry:#?}"
    );
}

#[test]
fn different_instance_of_same_type_stays_external() {
    // Within `Foo`, a call through a *different* `&Foo` parameter is an external
    // usage, not a same-owner site.
    let files: &[(&str, &str)] = &[(
        "foo.rs",
        "pub struct Foo;\nimpl Foo {\n    pub fn target(&self) {}\n    pub fn caller(&self, other: &Foo) { other.target(); }\n}\n",
    )];
    let entry = scan(Language::Rust, files, "Foo.target", false);
    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");
    assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
    assert_eq!(
        entry.same_owner_sites, None,
        "a different instance is not a same-owner site: {entry:#?}"
    );
}

// --- include_same_owner lists the sites, kind-tagged. ---------------------------

#[test]
fn include_same_owner_lists_kind_tagged_sites() {
    let default = scan(Language::Rust, RUST, "Foo.target", false);
    assert!(
        default.same_owner_files.is_empty(),
        "default omits same-owner site listing: {default:#?}"
    );

    let listed = scan(Language::Rust, RUST, "Foo.target", true);
    assert_eq!(listed.status, ScanUsagesStatus::NoExternalUsages);
    assert_eq!(listed.same_owner_sites, Some(1));
    let locations: Vec<_> = listed
        .same_owner_files
        .iter()
        .flat_map(|group| group.hits.iter())
        .collect();
    assert_eq!(locations.len(), 1, "one listed site: {listed:#?}");
    assert_eq!(
        locations[0].kind.as_deref(),
        Some("self_receiver"),
        "listed same-owner site must be kind-tagged: {listed:#?}"
    );
}

// --- The verified_absent gate on the tokio repro-B shape (self-receiver sibling
// call on a generic owner). ----------------------------------------------------

#[test]
fn verified_absent_gate_repro_b_shape() {
    // `next_many` calls `self.poll_next_many(...)`; poll_next_many's only caller
    // is that same-owner sibling. Before facet B this returned `verified_absent`
    // with total_hits 0 (the confident lie). Now it reports `no_external_usages`
    // with one same-owner site.
    let files: &[(&str, &str)] = &[(
        "stream_map.rs",
        "pub struct StreamMap<K, V> { _k: std::marker::PhantomData<(K, V)> }\nimpl<K, V> StreamMap<K, V> {\n    pub fn poll_next_many(&self) {}\n    pub fn next_many(&self) { self.poll_next_many(); }\n}\n",
    )];
    let entry = scan(Language::Rust, files, "StreamMap.poll_next_many", false);
    assert_eq!(
        entry.status,
        ScanUsagesStatus::NoExternalUsages,
        "repro-B shape must not report verified_absent: {entry:#?}"
    );
    assert_eq!(entry.total_hits, Some(0), "{entry:#?}");
    assert_eq!(entry.same_owner_sites, Some(1), "{entry:#?}");
}
