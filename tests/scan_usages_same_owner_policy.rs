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
//! All eleven languages participate in the uniformity matrix below, including
//! Scala: its event-driven usage graph threads the receiver shape through the
//! shared `hit_kind` slot so `this.m()`, an implicit bare `m()`, and an
//! own-object `Obj.m()` classify as same-owner while `super.m()` and a call
//! through a different variable stay external (#1014 facet B / #1138).

mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{
    AnalyzerConfig, IAnalyzer, Language,
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

/// The fq_name of the (single) function/method named `identifier` in the
/// project. Language-agnostic: reads the analyzer's own declarations so the
/// dead-code report round-trips through `get_definitions`.
fn function_fqname(analyzer: &dyn IAnalyzer, identifier: &str) -> String {
    for file in analyzer.analyzed_files() {
        for unit in analyzer.declarations(&file) {
            if unit.is_function() && unit.identifier() == identifier {
                return unit.fq_name();
            }
        }
    }
    panic!("no function named {identifier} in the project");
}

/// Dead-code / inverted-builder alignment (#1138): a method whose ONLY caller is
/// a same-owner receiver must read INCONCLUSIVE — never a confident proven
/// inbound edge (alive from the self-edge alone), never confidently dead. The
/// same-owner call is recorded as *unproven* inbound, matching Rust/Java.
fn assert_same_owner_only_inconclusive(
    language: Language,
    files: &[(&str, &str)],
    target_identifier: &str,
) {
    let mut project = InlineTestProject::with_language(language);
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();
    let workspace = built.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let fq_name = function_fqname(analyzer, target_identifier);
    let file_paths = files.iter().map(|(path, _)| path.to_string()).collect();
    let report = report_dead_code_and_unused_abstraction_smells(
        analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths,
            fq_names: vec![fq_name.clone()],
            ..Default::default()
        },
    )
    .report;
    assert!(
        report.contains("could not be proven or disproven"),
        "{language:?} {fq_name}: a same-owner-only caller must be inconclusive: {report}"
    );
    assert!(
        !report.contains("one workspace inbound edge"),
        "{language:?} {fq_name}: same-owner call must not be a proven inbound edge: {report}"
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

const SCALA: &[(&str, &str)] = &[(
    "Foo.scala",
    "class Foo {\n  def target(): Unit = {}\n  def caller(): Unit = this.target()\n  def uncalled(): Unit = {}\n}\n",
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
uniformity_case!(scala_same_owner_only, Language::Scala, SCALA);

// Go's fq_name is import-path-qualified; resolve the method by its owner-scoped
// name.
#[test]
fn go_same_owner_only() {
    assert_same_owner_only(Language::Go, GO, "Foo.target");
    assert_verified_absent(Language::Go, GO, "Foo.uncalled");
}

// --- Inverted-builder / dead-code alignment (#1138): the same-owner-only caller
// must be INCONCLUSIVE for every language whose inverted builder now routes
// same-owner references to unproven inbound (all nine; Scala is out of scope). --

macro_rules! inconclusive_case {
    ($name:ident, $lang:expr, $files:expr) => {
        #[test]
        fn $name() {
            assert_same_owner_only_inconclusive($lang, $files, "target");
        }
    };
}

inconclusive_case!(java_same_owner_only_inconclusive, Language::Java, JAVA);
inconclusive_case!(
    python_same_owner_only_inconclusive,
    Language::Python,
    PYTHON
);
inconclusive_case!(ruby_same_owner_only_inconclusive, Language::Ruby, RUBY);
inconclusive_case!(php_same_owner_only_inconclusive, Language::Php, PHP);
inconclusive_case!(
    csharp_same_owner_only_inconclusive,
    Language::CSharp,
    CSHARP
);
inconclusive_case!(rust_same_owner_only_inconclusive, Language::Rust, RUST);
inconclusive_case!(
    typescript_same_owner_only_inconclusive,
    Language::TypeScript,
    TYPESCRIPT
);
inconclusive_case!(
    javascript_same_owner_only_inconclusive,
    Language::JavaScript,
    JAVASCRIPT
);
inconclusive_case!(go_same_owner_only_inconclusive, Language::Go, GO);
inconclusive_case!(scala_same_owner_only_inconclusive, Language::Scala, SCALA);

// C++ member candidates route through the precise per-symbol path (no bulk usage
// graph for members), which reports them as inconclusive (the precise strategy is
// unavailable for the inline single-file project) rather than the graph-path
// "could not be proven or disproven" wording. Either way the invariant holds: the
// same-owner-only method is never confidently dead nor confidently alive. (The
// inverted `this->m()` -> record_unproven change itself is exercised by the scan
// surface, `cpp_same_owner_only`.)
#[test]
fn cpp_same_owner_only_inconclusive() {
    let mut project = InlineTestProject::with_language(Language::Cpp);
    for (path, contents) in CPP {
        project = project.file(*path, *contents);
    }
    let built = project.build();
    let workspace = built.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let fq_name = function_fqname(analyzer, "target");
    let report = report_dead_code_and_unused_abstraction_smells(
        analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: CPP.iter().map(|(path, _)| path.to_string()).collect(),
            fq_names: vec![fq_name.clone()],
            ..Default::default()
        },
    )
    .report;
    assert!(
        report.contains("inconclusive"),
        "Cpp {fq_name}: a same-owner-only caller must be inconclusive: {report}"
    );
    assert!(
        !report.contains("no non-self usages found"),
        "Cpp {fq_name}: same-owner-only method must not be confidently dead: {report}"
    );
    assert!(
        !report.contains("one workspace inbound edge"),
        "Cpp {fq_name}: same-owner call must not be a proven inbound edge: {report}"
    );
}

// --- C# scan-side widening (#1014 deferral, now unlocked by the inverted
// record_unproven routing): a bare implicit-this call and an own-type static call
// classify as same-owner; a bare method-group *value* stays external. -----------

#[test]
fn csharp_bare_implicit_this_call_is_same_owner() {
    // `caller()` calls `target()` with no receiver — an implicit-this call on the
    // current instance. Before the widening this counted as an external usage
    // (found, 1 hit); now it is a same-owner site.
    let files: &[(&str, &str)] = &[(
        "Foo.cs",
        "class Foo {\n  void target() {}\n  void caller() { target(); }\n}\n",
    )];
    assert_same_owner_only(Language::CSharp, files, "Foo.target");
}

#[test]
fn csharp_own_type_static_call_is_same_owner() {
    // `Foo.target()` from within `Foo` names the own type as a static receiver — a
    // same-owner site, mirroring Java's own-type-static rule.
    let files: &[(&str, &str)] = &[(
        "Foo.cs",
        "class Foo {\n  static void target() {}\n  void caller() { Foo.target(); }\n}\n",
    )];
    assert_same_owner_only(Language::CSharp, files, "Foo.target");
}

#[test]
fn csharp_bare_method_group_value_stays_external() {
    // A bare method-group *value* (delegate capture) is a genuine usage even
    // within the owning type — it is not a self-receiver *call*, so it stays on
    // the external surface (must not flatten to same-owner).
    let files: &[(&str, &str)] = &[(
        "Foo.cs",
        "using System;\nclass Foo {\n  void target() {}\n  void caller() { Action a = target; a(); }\n}\n",
    )];
    let entry = scan(Language::CSharp, files, "Foo.target", false);
    assert_eq!(
        entry.status,
        ScanUsagesStatus::Found,
        "a bare method-group value is an external usage: {entry:#?}"
    );
    assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
    assert_eq!(
        entry.same_owner_sites, None,
        "a method-group value must not be classified same-owner: {entry:#?}"
    );
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

// --- Scala-specific same-owner receiver shapes (#1014 facet B / #1138). --------

#[test]
fn scala_bare_implicit_this_call_is_same_owner() {
    // A bare `target()` with no receiver is an implicit-this call on the current
    // instance — a same-owner site, not an external usage.
    let files: &[(&str, &str)] = &[(
        "Foo.scala",
        "class Foo {\n  def target(): Unit = {}\n  def caller(): Unit = target()\n}\n",
    )];
    assert_same_owner_only(Language::Scala, files, "Foo.target");
}

#[test]
fn scala_own_object_call_is_same_owner() {
    // `Obj.target()` from within `Obj` names the enclosing singleton object as the
    // receiver — a same-owner site, mirroring Java/C#'s own-type-static rule.
    let files: &[(&str, &str)] = &[(
        "Obj.scala",
        "object Obj {\n  def target(): Unit = {}\n  def caller(): Unit = Obj.target()\n}\n",
    )];
    assert_same_owner_only(Language::Scala, files, "Obj.target");
}

#[test]
fn scala_super_call_stays_external() {
    // `super.render()` is a deliberate up-call to a supertype's member on the
    // current instance — an external usage, never a same-owner site.
    let files: &[(&str, &str)] = &[(
        "Foo.scala",
        "class Base {\n  def render(): Unit = {}\n}\nclass Foo extends Base {\n  override def render(): Unit = super.render()\n}\n",
    )];
    let entry = scan(Language::Scala, files, "Base.render", false);
    assert_eq!(
        entry.same_owner_sites, None,
        "a super call must not be classified same-owner: {entry:#?}"
    );
    assert_eq!(
        entry.status,
        ScanUsagesStatus::Found,
        "a super call is an external usage: {entry:#?}"
    );
}

#[test]
fn scala_different_instance_of_same_type_stays_external() {
    // Within `Foo`, a call through a *different* `Foo` parameter is an external
    // usage, not a same-owner site.
    let files: &[(&str, &str)] = &[(
        "Foo.scala",
        "class Foo {\n  def target(): Unit = {}\n  def caller(other: Foo): Unit = other.target()\n}\n",
    )];
    let entry = scan(Language::Scala, files, "Foo.target", false);
    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");
    assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
    assert_eq!(
        entry.same_owner_sites, None,
        "a different instance is not a same-owner site: {entry:#?}"
    );
}

#[test]
fn scala_include_same_owner_lists_kind_tagged_site() {
    let listed = scan(Language::Scala, SCALA, "Foo.target", true);
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
