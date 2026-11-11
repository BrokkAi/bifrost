#[cfg(test)]
mod line_data_admission_tests {
    use brokk_bifrost_analysis::analyzer::semantic::source_admission::SourceAdmissionRefusal;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::source_admission_test_support::parse;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{BoundedParse, LanguageAdapter};
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
    use brokk_bifrost_csharp_analysis::analyzer::csharp::adapter::CSharpAdapter;
    use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
    use brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter;
    use brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter;
    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
    use brokk_bifrost_jvm_analysis::analyzer::kotlin::adapter::KotlinAdapter;
    use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;
    use brokk_bifrost_php_analysis::analyzer::php::adapter::PhpAdapter;
    use brokk_bifrost_python_analysis::analyzer::python::PythonAdapter;
    use brokk_bifrost_ruby_analysis::analyzer::ruby::adapter::RubyAdapter;
    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    #[derive(Debug, PartialEq)]
    enum Outcome {
        Admitted,
        Refused,
    }

    fn outcome<A: LanguageAdapter>(adapter: &A, source: &str) -> Outcome {
        match parse(adapter, source, None) {
            BoundedParse::Complete(tree) => {
                assert!(!tree.root_node().has_error(), "{source:.200}");
                Outcome::Admitted
            }
            BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. }) => {
                Outcome::Refused
            }
            BoundedParse::Refused(reason) => {
                panic!("unexpected refusal {reason:?} for {source:.200}")
            }
            _ => panic!("admission neither completed nor refused for {source:.200}"),
        }
    }

    /// One language's cases: a long string line, a long interpolated string
    /// line where the language has interpolation, and a long code line.
    struct Cases<'a> {
        string: String,
        interpolated: Option<String>,
        code: String,
        adapter: &'a dyn Fn(&str) -> Outcome,
    }

    /// Every language admits a line that is long only because of string data
    /// and refuses one whose length is code, including an interpolation.
    #[test]
    fn every_language_admits_long_data_lines_and_refuses_long_code_lines() {
        let p = "x".repeat(17_000);
        let code = |statement: &str| statement.repeat(17_000 / statement.len() + 1);
        let rust = |source: &str| outcome(&RustAdapter::for_tests(), source);
        let go = |source: &str| outcome(&GoAdapter, source);
        let java = |source: &str| outcome(&JavaAdapter, source);
        let kotlin = |source: &str| outcome(&KotlinAdapter, source);
        let scala = |source: &str| outcome(&ScalaAdapter, source);
        let csharp = |source: &str| outcome(&CSharpAdapter::default(), source);
        let php = |source: &str| outcome(&PhpAdapter, source);
        let ruby = |source: &str| outcome(&RubyAdapter, source);
        let cpp = |source: &str| outcome(&CppAdapter, source);
        let javascript = |source: &str| outcome(&JavascriptAdapter, source);
        let typescript = |source: &str| outcome(&TypescriptAdapter, source);
        let python = |source: &str| outcome(&PythonAdapter::default(), source);
        let languages = [
            (
                Language::Rust,
                Cases {
                    string: format!("pub const DATA: &str = r#\"{p}\"#;\n"),
                    interpolated: None,
                    code: format!("pub fn f() {{ {} }}\n", code("let a = b; ")),
                    adapter: &rust,
                },
            ),
            (
                Language::Go,
                Cases {
                    string: format!("package p\n\nconst Data = `{p}`\n"),
                    interpolated: None,
                    code: format!("package p\n\nfunc f() {{ {} }}\n", code("a = b; ")),
                    adapter: &go,
                },
            ),
            (
                Language::Java,
                Cases {
                    string: format!("class A {{ String s = \"{p}\"; }}\n"),
                    interpolated: None,
                    code: format!("class A {{ void f() {{ {} }} }}\n", code("a = b; ")),
                    adapter: &java,
                },
            ),
            (
                Language::Kotlin,
                Cases {
                    string: format!("val s = \"{p}\"\n"),
                    interpolated: Some(format!("val s = \"{p}${{x}}\"\n")),
                    code: format!("fun f() {{ {} }}\n", code("a = b; ")),
                    adapter: &kotlin,
                },
            ),
            (
                Language::Scala,
                Cases {
                    string: format!("object A {{ val s = \"{p}\" }}\n"),
                    interpolated: Some(format!("object A {{ val s = s\"{p}$x\" }}\n")),
                    code: format!("object A {{ def f() = {{ {} }} }}\n", code("a = b; ")),
                    adapter: &scala,
                },
            ),
            (
                Language::CSharp,
                Cases {
                    string: format!("class A {{ string s = @\"{p}\"; }}\n"),
                    interpolated: Some(format!("class A {{ string s = $\"{p}{{x}}\"; }}\n")),
                    code: format!("class A {{ void F() {{ {} }} }}\n", code("a = b; ")),
                    adapter: &csharp,
                },
            ),
            (
                Language::Php,
                Cases {
                    string: format!("<?php\n$s = '{p}';\n"),
                    interpolated: Some(format!("<?php\n$s = \"{p}$x\";\n")),
                    code: format!("<?php\n{}\n", code("$a = $b; ")),
                    adapter: &php,
                },
            ),
            (
                Language::Ruby,
                Cases {
                    string: format!("S = \"{p}\"\n"),
                    interpolated: Some(format!("S = \"{p}#{{x}}\"\n")),
                    code: format!("{}\n", code("a = b; ")),
                    adapter: &ruby,
                },
            ),
            (
                Language::Cpp,
                Cases {
                    string: format!("const char *s = \"{p}\";\n"),
                    interpolated: None,
                    code: format!("void f() {{ {} }}\n", code("a = b; ")),
                    adapter: &cpp,
                },
            ),
            (
                Language::JavaScript,
                Cases {
                    string: format!("const s = \"{p}\";\n"),
                    interpolated: Some(format!("const s = `{p}${{x}}`;\n")),
                    code: format!("{}\n", code("a = b; ")),
                    adapter: &javascript,
                },
            ),
            (
                Language::TypeScript,
                Cases {
                    string: format!("const s: string = `{p}`;\n"),
                    interpolated: Some(format!("const s: string = `{p}${{x}}`;\n")),
                    code: format!("{}\n", code("a = b; ")),
                    adapter: &typescript,
                },
            ),
            (
                Language::Python,
                Cases {
                    string: format!("s = b'{p}'\n"),
                    interpolated: Some(format!("s = f'{p}{{x}}'\n")),
                    code: format!("{}\n", code("a = b; ")),
                    adapter: &python,
                },
            ),
        ];
        assert_eq!(languages.len(), Language::ANALYZABLE.len());
        for language in Language::ANALYZABLE {
            let (_, cases) = languages
                .iter()
                .find(|(covered, _)| *covered == language)
                .unwrap_or_else(|| panic!("{language:?} has no line-data cases"));
            assert_eq!(
                (cases.adapter)(&cases.string),
                Outcome::Admitted,
                "{language:?}"
            );
            if let Some(interpolated) = &cases.interpolated {
                assert_eq!(
                    (cases.adapter)(interpolated),
                    Outcome::Refused,
                    "{language:?}"
                );
            }
            assert_eq!(
                (cases.adapter)(&cases.code),
                Outcome::Refused,
                "{language:?}"
            );
        }
        // Composites: a numeric table, signed elements and nested lists are data.
        let numbers = "0x0123456789abcdef,".repeat(1000);
        assert_eq!(
            cpp(&format!("int data[] = {{{{-1, +2}}, {{{numbers}}}}};\n")),
            Outcome::Admitted
        );
        assert_eq!(
            rust(&format!("pub const DATA: [u64; 1000] = [{numbers}];\n")),
            Outcome::Admitted
        );
        assert_eq!(
            python(&format!("DATA = ({numbers} -1, [1, 2])\n")),
            Outcome::Admitted
        );
        // A comment is not data, even among data elements or string parts.
        assert_eq!(
            cpp(&format!("int data[] = {{1, /* {p} */ 2}};\n")),
            Outcome::Refused
        );
        assert_eq!(
            python(&format!("s = ('a'  # {p}\n     'b')\n")),
            Outcome::Refused
        );
        // Each data node is excluded on its own: a call among the data costs
        // only its own bytes, and enough calls overflow the line.
        assert_eq!(
            cpp(&format!("int data[] = {{{numbers} f()}};\n")),
            Outcome::Admitted
        );
        assert_eq!(
            cpp(&format!(
                "int data[] = {{{numbers} {}}};\n",
                "f(), ".repeat(4000)
            )),
            Outcome::Refused
        );
    }

    /// Every analyzable language declares line-data tables, and every kind and
    /// token they name exists in each grammar the language parses with.
    #[test]
    fn line_data_tables_name_kinds_of_their_grammars() {
        fn check<A: LanguageAdapter>(adapter: &A) {
            let kinds = adapter.line_data_kinds();
            let language = adapter.language();
            assert!(
                !kinds.literals.is_empty(),
                "{language:?} declares no literals"
            );
            assert!(
                !kinds.composites.is_empty(),
                "{language:?} declares no composites"
            );
            for (key, grammar) in adapter.storage_language_keys() {
                for (kind, named) in kinds.kinds() {
                    assert_ne!(
                        grammar.id_for_node_kind(kind, named),
                        0,
                        "{language:?} {key}: {kind:?} (named={named}) is not a node kind"
                    );
                }
            }
        }
        let mut checked = Vec::new();
        let mut record = |language: Language| checked.push(language);
        check(&RustAdapter::for_tests());
        record(Language::Rust);
        check(&GoAdapter);
        record(Language::Go);
        check(&JavaAdapter);
        record(Language::Java);
        check(&KotlinAdapter);
        record(Language::Kotlin);
        check(&ScalaAdapter);
        record(Language::Scala);
        check(&CSharpAdapter::default());
        record(Language::CSharp);
        check(&PhpAdapter);
        record(Language::Php);
        check(&RubyAdapter);
        record(Language::Ruby);
        check(&CppAdapter);
        record(Language::Cpp);
        check(&JavascriptAdapter);
        record(Language::JavaScript);
        check(&TypescriptAdapter);
        record(Language::TypeScript);
        check(&PythonAdapter::default());
        record(Language::Python);
        let mut expected = Language::ANALYZABLE.to_vec();
        expected.sort_by_key(|language| format!("{language:?}"));
        checked.sort_by_key(|language| format!("{language:?}"));
        assert_eq!(checked, expected);
    }
}
