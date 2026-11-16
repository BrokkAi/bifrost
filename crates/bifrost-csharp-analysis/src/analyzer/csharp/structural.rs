//! C#'s structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_csharp::structural::CSHARP_STRUCTURAL_SPEC`]. This assertion
//! runs through `structural::adapter_helpers`, the analysis-owned test support,
//! so it stays on this side of the crate line -- exactly as Python's and Rust's
//! did.

#[cfg(test)]
mod structural_spec_tests {
    use brokk_bifrost_csharp::structural::CSHARP_KIND_TABLE;

    #[test]
    fn csharp_kind_table_matches_grammar() {
        brokk_bifrost_core::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_c_sharp::LANGUAGE.into(),
            "tree-sitter-c-sharp",
            CSHARP_KIND_TABLE,
        );
    }
}

#[cfg(test)]
mod constructor_initializer_tests {
    use brokk_bifrost_analysis::analyzer::structural::extract::extract_file_facts;
    use brokk_bifrost_analysis::analyzer::structural::kinds::{NormalizedKind, Role};
    use brokk_bifrost_core::analyzer::structural::callable::CallKind;
    use brokk_bifrost_core::analyzer::structural::facts::{ArgumentMode, Span};
    use brokk_bifrost_csharp::structural::CSHARP_STRUCTURAL_SPEC;
    use brokk_bifrost_test_macros::hardwon;

    /// One call fact as the structural arena states it: the call text, its
    /// kind, its callee and its written arguments as
    /// `(keyword, value text, passing mode)`, in source order.
    #[derive(Debug, Clone, PartialEq)]
    struct CallRow {
        text: String,
        kind: Option<CallKind>,
        callee: Option<String>,
        arguments: Vec<(Option<String>, String, ArgumentMode)>,
    }

    fn row(
        text: &str,
        kind: Option<CallKind>,
        callee: &str,
        arguments: &[(Option<&str>, &str, ArgumentMode)],
    ) -> CallRow {
        CallRow {
            text: text.to_owned(),
            kind,
            callee: Some(callee.to_owned()),
            arguments: arguments
                .iter()
                .map(|(keyword, value, mode)| {
                    (keyword.map(str::to_owned), (*value).to_owned(), *mode)
                })
                .collect(),
        }
    }

    /// Every call fact of `source`, in fact order.
    fn call_rows_of(source: &str) -> Vec<CallRow> {
        let facts = extract_file_facts(
            &CSHARP_STRUCTURAL_SPEC,
            &tree_sitter_c_sharp::LANGUAGE.into(),
            source,
        )
        .expect("structural extraction should succeed for the fixture");
        let text = |span: Span| source[span.start_byte..span.end_byte].to_owned();
        (0..facts.nodes().len() as u32)
            .filter(|&id| facts.node(id).kind == NormalizedKind::Call)
            .map(|id| {
                let node = facts.node(id);
                CallRow {
                    text: text(node.span()),
                    kind: node.call_site.as_ref().and_then(|site| site.call_kind),
                    callee: facts
                        .role_targets(id, Role::Callee)
                        .next()
                        .map(|target| text(target.span)),
                    arguments: facts
                        .roles(id)
                        .iter()
                        .filter(|target| matches!(target.role, Role::Arg | Role::Kwarg))
                        .map(|target| (target.keyword.map(text), text(target.span), target.mode))
                        .collect(),
                }
            })
            .collect()
    }

    /// A `constructor_initializer` is a constructor call that no `new`
    /// spells. It was not a call fact, so queries over calls and their
    /// arguments missed it and reported complete. Its arguments keep their
    /// `ref`, `out`, `in` or plain mode, and a named argument becomes a
    /// keyword argument, through the helper that ordinary calls use.
    #[test]
    #[hardwon("#10319: constructor initializers were not call facts and queries reported complete")]
    fn csharp_constructor_initializers_are_constructor_calls_with_written_arguments() {
        use ArgumentMode::{In, Out, Plain, Ref};
        let source = concat!(
            "class Base { public Base(int a, int b) {} public Base(ref int r) {} }\n",
            "class Derived : Base {\n",
            "    public Derived(int y) : base(ref y) { }\n",
            "    public Derived(int z, bool flag) : this(z) { }\n",
            "    public Derived(int a) : base(a, b: 2) { }\n",
            "    public Derived(in int i, out int o) : base(in i, out o) { o = 0; }\n",
            "    public Derived() : this(1, 2) { var c = new Base(1, 2); Log(3); }\n",
            "    void Log(int n) {}\n",
            "}\n",
        );
        let rows = call_rows_of(source);
        let ctor = Some(CallKind::Constructor);
        let (chaining, controls): (Vec<_>, Vec<_>) =
            rows.into_iter().partition(|row| row.text.starts_with(':'));
        assert_eq!(
            chaining,
            vec![
                row(": base(ref y)", ctor, "base", &[(None, "y", Ref)]),
                row(": this(z)", ctor, "this", &[(None, "z", Plain)]),
                row(
                    ": base(a, b: 2)",
                    ctor,
                    "base",
                    &[(None, "a", Plain), (Some("b"), "2", Plain)],
                ),
                row(
                    ": base(in i, out o)",
                    ctor,
                    "base",
                    &[(None, "i", In), (None, "o", Out)],
                ),
                row(
                    ": this(1, 2)",
                    ctor,
                    "this",
                    &[(None, "1", Plain), (None, "2", Plain)],
                ),
            ]
        );
        // Ordinary calls and creations in the same file keep their rows.
        assert_eq!(
            controls,
            vec![
                row(
                    "new Base(1, 2)",
                    ctor,
                    "Base",
                    &[(None, "1", Plain), (None, "2", Plain)],
                ),
                row("Log(3)", None, "Log", &[(None, "3", Plain)]),
            ]
        );
    }
}
