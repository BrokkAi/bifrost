//! Attribute/subscript-target over-declaration audit — pattern 4 from
//! `.agent/PARITY_CROSS_LANGUAGE_GENERALIZATION.md`.
//!
//! Assigning to a *member* of some object — `obj.x = 1`, `$obj->x = 1`,
//! `o.X = 1` — must not spuriously declare a top-level member named `x`. Python
//! had this bug (fixed by skipping `attribute`/`subscript` targets in
//! `collect_assigned_names`); this suite audits the other extractors the doc
//! flagged.
//!
//! Result of the audit: Ruby, PHP, and Go are already correct (guarded here).
//! JS/TS over-declare `obj.x` from a *plain-local* member assignment, but the
//! fix is not the blanket skip that worked for Python — the same
//! `js_member_assignment_name` path also carries legitimate JS/TS member
//! declarations (`Foo.prototype.m = …`, `Namespace.foo = …`), so narrowing it
//! correctly needs scope awareness. Those two are `#[ignore]` documenting the
//! gap.

mod common;

use brokk_bifrost::{
    GoAnalyzer, IAnalyzer, JavascriptAnalyzer, PhpAnalyzer, RubyAnalyzer, TypescriptAnalyzer,
};
use common::InlineTestProject;

const SPURIOUS: &str = "spuriousmember";

fn assert_no_spurious_member(decls: Vec<String>) {
    assert!(
        !decls.iter().any(|d| d.contains(SPURIOUS)),
        "member-assignment target over-declared a `{SPURIOUS}` member; decls = {decls:?}"
    );
}

fn declaration_fqns(analyzer: &dyn IAnalyzer) -> Vec<String> {
    analyzer
        .get_all_declarations()
        .into_iter()
        .map(|c| c.fq_name().to_string())
        .collect()
}

#[test]
fn ruby_member_assignment_does_not_declare() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::Ruby)
        .file("m.rb", "obj = Object.new\nobj.spuriousmember = 1\n")
        .build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    assert_no_spurious_member(declaration_fqns(&analyzer));
}

#[test]
fn php_arrow_assignment_does_not_declare() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::Php)
        .file(
            "m.php",
            "<?php\n$obj = new stdClass();\n$obj->spuriousmember = 1;\n",
        )
        .build();
    let analyzer = PhpAnalyzer::from_project(project.project().clone());
    assert_no_spurious_member(declaration_fqns(&analyzer));
}

#[test]
fn go_field_assignment_does_not_declare_unknown_member() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::Go)
        .file(
            "m.go",
            "package m\n\ntype T struct{}\n\nfunc f(o *T) {\n\to.spuriousmember = 1\n}\n",
        )
        .build();
    let analyzer = GoAnalyzer::from_project(project.project().clone());
    assert_no_spurious_member(declaration_fqns(&analyzer));
}

#[ignore = "pattern 4 gap: JS declares `obj.x` from a plain-local member assignment; \
            needs scope-aware narrowing (the same path carries prototype/namespace decls)"]
#[test]
fn javascript_local_member_assignment_does_not_declare() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::JavaScript)
        .file("m.js", "const obj = {};\nobj.spuriousmember = 1;\n")
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    assert_no_spurious_member(declaration_fqns(&analyzer));
}

#[ignore = "pattern 4 gap: TS shares the JS member-assignment declarer; same scope-aware fix"]
#[test]
fn typescript_local_member_assignment_does_not_declare() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::TypeScript)
        .file("m.ts", "const obj: any = {};\nobj.spuriousmember = 1;\n")
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    assert_no_spurious_member(declaration_fqns(&analyzer));
}
