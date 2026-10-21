#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::classify_owner_relation;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::test_support::Fixture;

    #[test]
    #[hardwon("#1645: free-function namespaces and type owners were misclassified as unknown")]
    fn a_namespace_owner_and_a_type_owner_are_external() {
        /// One language's contribution: the sources, the free callable, and
        /// the type-owned target it calls.
        struct Case {
            language: Language,
            sources: &'static [(&'static str, &'static str)],
            caller: &'static str,
            target: &'static str,
        }

        let cases: &[Case] = &[
            // Rust: the caller sits at the crate root, which the qualified
            // name spells by carrying no scope segment.
            Case {
                language: Language::Rust,
                sources: &[(
                    "src/lib.rs",
                    "pub struct Widget;\n\nimpl Widget {\n    pub fn new() -> Widget {\n        Widget\n    }\n\n    pub fn run(&self) -> usize {\n        1\n    }\n}\n\npub fn drive() -> usize {\n    let s = Widget::new();\n    s.run()\n}\n",
                )],
                caller: "drive",
                target: "Widget.run",
            },
            // Rust again, with a named module owner: containing the target's
            // type is not owning the target.
            Case {
                language: Language::Rust,
                sources: &[(
                    "src/lib.rs",
                    "pub mod thing {\n    pub struct Widget;\n    impl Widget {\n        pub fn run(&self) -> usize { 1 }\n    }\n    pub fn drive(w: &Widget) -> usize {\n        w.run()\n    }\n}\n",
                )],
                caller: "thing.drive",
                target: "thing.Widget.run",
            },
            // Go: the package prefix is a `Path` segment.
            Case {
                language: Language::Go,
                sources: &[(
                    "main.go",
                    "package main\n\ntype Widget struct{}\n\nfunc (w Widget) Run() int { return 1 }\n\nfunc Drive() int {\n\tw := Widget{}\n\treturn w.Run()\n}\n",
                )],
                caller: "main.Drive",
                target: "main.Widget.Run",
            },
            // PHP: a namespaced function.
            Case {
                language: Language::Php,
                sources: &[(
                    "app.php",
                    "<?php\nnamespace App;\n\nclass Widget {\n    public function run() { return 1; }\n}\n\nfunction drive() {\n    $w = new Widget();\n    return $w->run();\n}\n",
                )],
                caller: "App.drive",
                target: "App.Widget.run",
            },
            // Kotlin: a top-level function in a package.
            Case {
                language: Language::Kotlin,
                sources: &[(
                    "src/app.kt",
                    "package fixture\n\nclass Widget {\n    fun run(): Int = 1\n}\n\nfun drive(): Int {\n    val w = Widget()\n    return w.run()\n}\n",
                )],
                caller: "fixture.drive",
                target: "fixture.Widget.run",
            },
            // Ruby: a top-level method, whose type-owned counterpart carries a
            // `Nested` prefix rather than a namespace one.
            Case {
                language: Language::Ruby,
                sources: &[(
                    "app.rb",
                    "class Widget\n  def run\n    1\n  end\nend\n\ndef drive\n  w = Widget.new\n  w.run\nend\n",
                )],
                caller: "drive",
                target: "Widget.run",
            },
            // JavaScript: the same js/ts model, listed separately because it
            // is a separately claimed language.
            Case {
                language: Language::JavaScript,
                sources: &[
                    (
                        "widget.js",
                        "export class Widget {\n  run() { return 1; }\n}\n",
                    ),
                    (
                        "app.js",
                        "import { Widget } from './widget.js';\nexport function drive() {\n  const w = new Widget();\n  return w.run();\n}\n",
                    ),
                ],
                caller: "drive",
                target: "Widget.run",
            },
            // TypeScript: the module scope is the file and is unnamed, but the
            // caller still provably belongs to no type.
            Case {
                language: Language::TypeScript,
                sources: &[
                    (
                        "widget.ts",
                        "export class Widget {\n  run(): number { return 1; }\n}\n",
                    ),
                    (
                        "app.ts",
                        "import { Widget } from './widget';\nexport function drive(): number {\n  const w = new Widget();\n  return w.run();\n}\n",
                    ),
                ],
                caller: "drive",
                target: "Widget.run",
            },
        ];
        for case in cases {
            let language = case.language;
            let fixture = Fixture::new(language, case.sources);
            let analyzer = fixture.analyzer();
            let caller = fixture.declaration(case.caller);
            let target = fixture.declaration(case.target);
            assert_eq!(
                classify_owner_relation(analyzer, Some(&caller), &target),
                OwnerRelation::External,
                "{language:?}: {caller:?} owns no type, {target:?} does"
            );
            assert_eq!(
                classify_owner_relation(analyzer, Some(&target), &caller),
                OwnerRelation::External,
                "{language:?}: the relation is symmetric across the two scopes"
            );
        }
    }
}
