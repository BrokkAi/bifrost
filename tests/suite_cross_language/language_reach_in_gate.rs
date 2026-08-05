//! Framework code in `brokk-bifrost-analysis` must not name a language.
//!
//! The permanent regression guard for
//! `.agents/plans/analysis-language-registry-spi.md`: every per-language decision
//! reaches framework code through the `LanguageSupport` registry, so a framework file
//! that imports `analyzer::rust`, `usages::rust_graph` or a `RustAnalyzer` has
//! reintroduced exactly the dispatch the plan deleted, and the next language extraction
//! would have to find it by hand.
//!
//! Syntax-aware rather than token-scanning, because the real reach-in forms carry no
//! `analyzer::rust::` token: `use crate::analyzer::usages::rust_graph::
//! RustExportUsageGraphStrategy;` and `use crate::analyzer::RustAnalyzer;` are both
//! invisible to a text search for the module path, and blanking comments and strings
//! would only fix false positives. Parsing also makes the raw-string fixtures in
//! `analyzer/rust/diagnostics.rs` and `searchtools/tests.rs` non-issues.
//!
//! The walk starts at `lib.rs` and follows `mod` declarations rather than globbing
//! files, because sixteen `tests.rs` files carry no in-file `#[cfg(test)]` -- the
//! attribute sits on the parent's `mod tests;` -- and two of them
//! (`analyzer/structural/search/tests.rs`, `searchtools/tests.rs`) would false-fire
//! under a file-independent walker.

use proc_macro2::TokenTree;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use syn::visit::Visit;

/// Module directories that are per-language by construction. Reaching *into* one from
/// framework code is the violation; naming a language freely *inside* one is the point.
const LANGUAGE_MODULES: &[&str] = &[
    "cpp",
    "csharp",
    "go",
    "java",
    "javascript",
    "js_ts",
    "jvm",
    "kotlin",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "typescript",
];

/// Name stems of the per-language usage-graph modules, `<stem>_graph`.
const GRAPH_MODULE_STEMS: &[&str] = &[
    "cpp", "csharp", "go", "java", "js_ts", "kotlin", "php", "python", "ruby", "rust", "scala",
];

/// The concrete type families a language owns. Matched as prefix plus suffix rather than
/// by suffix alone, so `IAnalyzer`, `MultiAnalyzer`, `EmptyAnalyzer`, `UsageAnalyzer` and
/// `GraphUsageAnalyzer` -- the framework's own polymorphic names -- never false-fire.
const LANGUAGE_TYPE_PREFIXES: &[&str] = &[
    "CSharp",
    "Cpp",
    "Go",
    "Java",
    "JavaScript",
    "Javascript",
    "JsTs",
    "Jvm",
    "Kotlin",
    "Php",
    "Python",
    "Ruby",
    "Rust",
    "Scala",
    "TypeScript",
    "Typescript",
];

/// Suffixes completing a concrete per-language type name. An infix is allowed, because
/// the strategies spell themselves `RustExportUsageGraphStrategy`.
const LANGUAGE_TYPE_SUFFIXES: &[&str] = &["Adapter", "Analyzer", "Support", "UsageGraphStrategy"];

/// Framework files permitted to name a language, each for a recorded reason.
///
/// Every entry is a considered exception, not a deferral: adding one means asserting the
/// reference is assembly-layer or deliberately single-language public API. The census
/// behind these is `.agents/docs/registry-preflight-census-2026-08.md` section 4.
const ALLOWLIST: &[(&str, &str)] = &[
    // The re-export hub feeding the facade's curated public surface. Assembly-adjacent
    // public API, not dispatch.
    (
        "analyzer/mod.rs",
        "re-export hub for the facade's public surface",
    ),
    // Eleven `<Lang>UsageGraphStrategy` re-exports, all still reached by the root
    // integration suites through `brokk_bifrost::usages`.
    (
        "analyzer/usages/mod.rs",
        "public-surface re-exports of the per-language usage strategies",
    ),
    // Eight production signatures typed `&JavaAnalyzer`, `pub` at the crate root and
    // re-exported from the facade. Intentionally Java-specific public API, the same class
    // as `activate_python_environment_packs`.
    ("summary.rs", "intentionally Java-specific public API"),
    // Python-specific workspace surface (`activate_python_environment_packs` and the
    // semantic-pack resolver), deliberately public API.
    ("analyzer/workspace.rs", "Python-specific workspace surface"),
    // The crate root's public re-export surface, the same class as `analyzer/mod.rs`
    // one level down.
    ("lib.rs", "crate-root re-export surface"),
    // The per-language definition-resolution hub: an eleven-arm dispatch into its own
    // `<lang>` submodules plus the navigation and diagnostic helpers each contributes.
    // Census section 6 documents it for the extraction plan rather than milestone 1;
    // converting it means moving a per-language implementation set, not adding a method.
    (
        "analyzer/usages/get_definition/mod.rs",
        "per-language definition-resolution hub over its own submodules (census section 6)",
    ),
    // Ten file-local `<lang>_call_reference_candidate` families plus two helpers whose
    // siblings live in the get_definition per-language modules. Census section 6: a
    // per-language implementation set in a framework file, the same class as
    // `exception_handling.rs`.
    (
        "analyzer/usages/get_definition/call_sites.rs",
        "per-language call-node implementation set (census section 6)",
    ),
    // Re-export hub for its own twelve per-language submodules. The dispatch it used to
    // hold became the `type_lookup` capability in milestone 1b.
    (
        "analyzer/usages/get_type/mod.rs",
        "re-export hub over its own per-language submodules",
    ),
    // Per-language scoring (`bulk_graph_finding`'s eight file-local `<lang>_graph_finding`
    // implementations) plus two differently-scoped implicit-entry-point predicate sets.
    // Milestone 1c moved the edge builds onto `DeadCodeBulkProof` and deliberately left
    // the scoring; unifying the two entry-point sets would change which languages each
    // call site consults, so it is a redesign rather than a capability addition.
    // The C# prerequisite pass moved `csharp_implicit_entry_point` and its three helpers
    // into `usages::csharp_graph`, so every entry-point predicate that carries grammar or
    // test-runner knowledge now delegates into its language module (Go's
    // `go_implicit_entry_point`, C++'s `is_cpp_global_main`, C#'s
    // `csharp_implicit_entry_point`); what stays is the name-shape scoring the JVM realm
    // shares. Follow-up: revisit with the extraction plan alongside `exception_handling.rs`.
    (
        "code_quality/dead_code_smells.rs",
        "per-language dead-code scoring; follow-up",
    ),
    (
        // Census section 6 class: per-language node-kind classification in a
        // framework file. Upstream #1641-era C++ recovery added a direct cpp
        // module import (cpp_is_range_for_binding_name); it re-points through
        // the shim when the C++ crate extracts.
        "analyzer/reference_candidates.rs",
        "per-language node-kind classification; cpp import pends the C++ crate",
    ),
    // Java's receiver route: it answers `None` to `structural_receiver` by design and runs
    // a resolution session instead, and `BoundedJavaResolution` carries the work accounting
    // the receiver query threads back through its budget. A capability would put that Java
    // type in a framework signature -- a type-level leak, not a method addition. This is the
    // class of leak that `ScalaExportInfo` was until it moved to the core model layer.
    // Follow-up: lower `BoundedJavaResolution` with the extraction plan.
    (
        "analyzer/usages/receiver_query/mod.rs",
        "Java resolution-session route; follow-up",
    ),
    // The #1474 resolution trace's boundary and import evidence: `boundary_evidence`
    // and its import-declaration companion each answer "is this name external, and
    // does the build say so?" per language, which is Java's `external_boundary_evidence`
    // for Java and the semantic overlay plus dependency-discovery evidence elsewhere.
    // Same class as `get_definition/mod.rs`: a per-language implementation set living
    // in a framework file, not a dispatch a single capability method would absorb --
    // the Java arm needs a resolver-typed answer the other arms have no analogue for.
    // Follow-up: revisit alongside `receiver_query.rs` with the extraction plan.
    (
        "analyzer/usages/get_definition/trace.rs",
        "per-language external-boundary evidence set (census section 6); follow-up",
    ),
];

/// Files whose whole job is to know every language.
const ASSEMBLY_FILES: &[&str] = &["analyzer/languages.rs", "analyzer/multi_analyzer.rs"];

struct Violation {
    file: String,
    line: usize,
    column: usize,
    what: String,
}

fn is_language_module(segment: &str) -> bool {
    LANGUAGE_MODULES.contains(&segment)
        || GRAPH_MODULE_STEMS.iter().any(|stem| {
            segment.len() == stem.len() + 6
                && segment.starts_with(stem)
                && segment.ends_with("_graph")
        })
}

fn is_language_type(ident: &str) -> bool {
    LANGUAGE_TYPE_PREFIXES.iter().any(|prefix| {
        ident
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(char::is_uppercase))
    }) && LANGUAGE_TYPE_SUFFIXES
        .iter()
        .any(|suffix| ident.ends_with(suffix))
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr.meta.require_list().is_ok_and(|list| {
                list.tokens
                    .clone()
                    .into_iter()
                    .any(|token| matches!(&token, TokenTree::Ident(ident) if ident == "test"))
            })
    })
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        other => panic!("unhandled item shape {other:?}"),
    }
}

/// One source file's scan. `exempt` files are still walked, because a per-language or
/// allowlisted module still declares submodules the gate must reach.
struct FileScan<'a> {
    file: &'a str,
    exempt: bool,
    /// `dir` of this file's submodules: `foo.rs` and `foo/mod.rs` both own `foo/`.
    module_dir: PathBuf,
    children: Vec<PathBuf>,
    test_only_children: Vec<PathBuf>,
    violations: Vec<Violation>,
}

impl FileScan<'_> {
    fn record(&mut self, span: proc_macro2::Span, what: String) {
        if self.exempt {
            return;
        }
        let start = span.start();
        self.violations.push(Violation {
            file: self.file.to_string(),
            line: start.line,
            column: start.column + 1,
            what,
        });
    }

    fn check_path(&mut self, path: &syn::Path, rendered: &str) {
        for segment in &path.segments {
            let ident = segment.ident.to_string();
            if is_language_module(&ident) {
                self.record(
                    segment.ident.span(),
                    format!("language module `{ident}` in `{rendered}`"),
                );
            } else if is_language_type(&ident) {
                self.record(
                    segment.ident.span(),
                    format!("per-language type `{ident}` in `{rendered}`"),
                );
            }
        }
    }

    fn check_use_tree(&mut self, tree: &syn::UseTree, prefix: &str) {
        match tree {
            syn::UseTree::Path(node) => {
                let ident = node.ident.to_string();
                let rendered = format!("{prefix}{ident}::");
                self.check_segment(&node.ident, &ident, &format!("{prefix}{ident}"));
                self.check_use_tree(&node.tree, &rendered);
            }
            syn::UseTree::Name(node) => {
                let ident = node.ident.to_string();
                self.check_segment(&node.ident, &ident, &format!("{prefix}{ident}"));
            }
            syn::UseTree::Rename(node) => {
                let ident = node.ident.to_string();
                self.check_segment(&node.ident, &ident, &format!("{prefix}{ident}"));
            }
            syn::UseTree::Glob(_) => {}
            syn::UseTree::Group(node) => {
                for item in &node.items {
                    self.check_use_tree(item, prefix);
                }
            }
        }
    }

    fn check_segment(&mut self, ident: &syn::Ident, name: &str, rendered: &str) {
        if is_language_module(name) {
            self.record(
                ident.span(),
                format!("language module `{name}` in `use {rendered}`"),
            );
        } else if is_language_type(name) {
            self.record(
                ident.span(),
                format!("per-language type `{name}` in `use {rendered}`"),
            );
        }
    }

    /// Macro bodies are opaque to `syn`, so their identifiers are scanned directly.
    /// Concrete type names only: a bare `go` or `java` identifier inside a macro is
    /// ordinary code far more often than it is a module path.
    fn check_macro_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        for token in tokens {
            match token {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    if is_language_type(&name) {
                        self.record(
                            ident.span(),
                            format!("per-language type `{name}` inside a macro invocation"),
                        );
                    }
                }
                TokenTree::Group(group) => self.check_macro_tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

impl Visit<'_> for FileScan<'_> {
    fn visit_item(&mut self, item: &syn::Item) {
        if is_cfg_test(item_attrs(item)) {
            if let syn::Item::Mod(module) = item
                && module.content.is_none()
            {
                self.test_only_children
                    .push(self.module_dir.join(module.ident.to_string()));
            }
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, module: &syn::ItemMod) {
        assert!(
            !module.attrs.iter().any(|attr| attr.path().is_ident("path")),
            "{}: `#[path]` module declarations need explicit resolution in this gate",
            self.file
        );
        match &module.content {
            Some((_, items)) => {
                for item in items {
                    self.visit_item(item);
                }
            }
            None => self
                .children
                .push(self.module_dir.join(module.ident.to_string())),
        }
    }

    fn visit_impl_item(&mut self, item: &syn::ImplItem) {
        let attrs = match item {
            syn::ImplItem::Const(item) => &item.attrs,
            syn::ImplItem::Fn(item) => &item.attrs,
            syn::ImplItem::Type(item) => &item.attrs,
            syn::ImplItem::Macro(item) => &item.attrs,
            _ => &[][..],
        };
        if is_cfg_test(attrs) {
            return;
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_item_use(&mut self, node: &syn::ItemUse) {
        self.check_use_tree(&node.tree, "");
    }

    fn visit_path(&mut self, path: &syn::Path) {
        let rendered = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        self.check_path(path, &rendered);
        syn::visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, node: &syn::Macro) {
        self.check_macro_tokens(node.tokens.clone());
        syn::visit::visit_macro(self, node);
    }
}

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/bifrost-analysis/src")
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .expect("every walked file lives under the crate source root")
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_exempt(rel: &str) -> bool {
    if ASSEMBLY_FILES.contains(&rel) || ALLOWLIST.iter().any(|(file, _)| *file == rel) {
        return true;
    }
    let under =
        |prefix: &str| rel == format!("{prefix}.rs") || rel.starts_with(&format!("{prefix}/"));
    LANGUAGE_MODULES.iter().any(|language| {
        under(&format!("analyzer/{language}"))
            || under(&format!("analyzer/usages/get_definition/{language}"))
            || under(&format!("analyzer/usages/get_type/{language}"))
    }) || GRAPH_MODULE_STEMS
        .iter()
        .any(|stem| under(&format!("analyzer/usages/{stem}_graph")))
}

/// `mod foo;` resolves to `foo.rs` or `foo/mod.rs`, and both own the submodule directory
/// `foo/`.
fn module_file(stem: &Path) -> PathBuf {
    let flat = stem.with_extension("rs");
    if flat.is_file() {
        return flat;
    }
    let nested = stem.join("mod.rs");
    assert!(
        nested.is_file(),
        "module declaration resolves to neither {} nor {}",
        flat.display(),
        nested.display()
    );
    nested
}

fn scan_file<'a>(file: &Path, rel: &'a str, exempt: bool) -> FileScan<'a> {
    let source = std::fs::read_to_string(file).expect("readable source file");
    let parsed = syn::parse_file(&source)
        .unwrap_or_else(|error| panic!("{rel} does not parse as Rust: {error}"));
    let mut file_scan = FileScan {
        file: rel,
        exempt,
        module_dir: file
            .parent()
            .expect("source files have a parent directory")
            .join(
                if file
                    .file_name()
                    .is_some_and(|name| name == "mod.rs" || name == "lib.rs")
                {
                    String::new()
                } else {
                    file.file_stem()
                        .expect("source files have a stem")
                        .to_string_lossy()
                        .into_owned()
                },
            ),
        children: Vec::new(),
        test_only_children: Vec::new(),
        violations: Vec::new(),
    };
    for item in &parsed.items {
        file_scan.visit_item(item);
    }
    file_scan
}

/// A `#[cfg(test)] mod` subtree is exempt from policing, but its files must
/// still be accounted for or the completeness check misreads them as missed.
/// Test modules can be directories with their own submodules (the structural
/// search suite split into one), so this descends purely for accounting.
fn account_test_module(file: &Path, walked: &mut BTreeSet<PathBuf>) {
    if !walked.insert(file.to_path_buf()) {
        return;
    }
    let source = std::fs::read_to_string(file).expect("readable test module file");
    let parsed = syn::parse_file(&source)
        .unwrap_or_else(|error| panic!("{} does not parse as Rust: {error}", file.display()));
    let dir = file
        .parent()
        .expect("source files have a parent directory")
        .join(if file.file_name().is_some_and(|name| name == "mod.rs") {
            String::new()
        } else {
            file.file_stem()
                .expect("source files have a stem")
                .to_string_lossy()
                .into_owned()
        });
    for item in &parsed.items {
        if let syn::Item::Mod(module) = item
            && module.content.is_none()
        {
            account_test_module(&module_file(&dir.join(module.ident.to_string())), walked);
        }
    }
}

fn scan(file: &Path, root: &Path, violations: &mut Vec<Violation>, walked: &mut BTreeSet<PathBuf>) {
    assert!(walked.insert(file.to_path_buf()), "{file:?} walked twice");
    let rel = relative(file, root);
    let scanned = scan_file(file, &rel, is_exempt(&rel));
    violations.extend(scanned.violations);
    for child in scanned.test_only_children {
        account_test_module(&module_file(&child), walked);
    }
    for child in scanned.children {
        scan(&module_file(&child), root, violations, walked);
    }
}

#[test]
fn framework_code_never_names_a_language() {
    let root = crate_src();
    let mut violations = Vec::new();
    let mut walked = BTreeSet::new();
    scan(&root.join("lib.rs"), &root, &mut violations, &mut walked);

    let mut on_disk = BTreeSet::new();
    collect_sources(&root, &mut on_disk);
    let unreached: Vec<_> = on_disk
        .difference(&walked)
        .map(|path| relative(path, &root))
        .collect();
    assert!(
        unreached.is_empty(),
        "the module walk missed source files, so the gate does not police them: {unreached:?}"
    );

    if violations.is_empty() {
        return;
    }
    let mut report = format!(
        "{} framework reach-ins into per-language code. Convert each onto a \
         LanguageSupport capability, or add a named allowlist entry stating why it is \
         assembly-layer or deliberately single-language API:\n",
        violations.len()
    );
    for violation in &violations {
        writeln!(
            report,
            "  {}:{}:{}: {}",
            violation.file, violation.line, violation.column, violation.what
        )
        .expect("writing to a String cannot fail");
    }
    panic!("{report}");
}

fn collect_sources(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            collect_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.insert(path);
        }
    }
}

/// The allowlist earns its keep only if every entry still needs to be there. A stale entry
/// silently widens the gate over a file nobody re-examined, which is how an exception list
/// stops describing the code it exempts.
#[test]
fn every_allowlist_entry_is_still_load_bearing() {
    let root = crate_src();
    for file in ASSEMBLY_FILES {
        assert!(root.join(file).is_file(), "assembly file {file} is missing");
    }
    let stale: Vec<_> = ALLOWLIST
        .iter()
        .filter(|(file, reason)| {
            let path = root.join(file);
            assert!(
                path.is_file(),
                "allowlisted file {file} ({reason}) no longer exists"
            );
            scan_file(&path, file, false).violations.is_empty()
        })
        .map(|(file, _)| *file)
        .collect();
    assert!(
        stale.is_empty(),
        "these files no longer name a language, so drop their allowlist entries: {stale:?}"
    );
}
