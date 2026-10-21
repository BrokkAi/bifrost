#[cfg(test)]
mod php_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::BindingKind;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::BindingOfOutcome;

    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::binding_of;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::binding;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::reached;
    /// An unbraced `namespace N;` makes the rest of the file that namespace,
    /// so a `use` written under it binds over the file scope. PHP resolves the
    /// imported name at compile time but sequentially: a reference written
    /// above the `use` does not resolve through it, which is `SourceOrder`.
    #[test]
    fn php_use_aliases_bind_from_their_declaration_over_an_unbraced_namespace() {
        let source = concat!(
            "<?php\n",
            "\n",
            "namespace App\\Util;\n",
            "\n",
            "use App\\Model\\Widget as Gadget;\n",
            "\n",
            "function make(): Gadget {\n",
            "    return new Gadget();\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Php, "src/make.php", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let gadget = binding(&env, "Gadget");
        assert_eq!(gadget.kind, BindingKind::ImportBinder);
        assert_eq!(gadget.hoisting, HoistingClass::SourceOrder);
        assert_eq!(
            gadget.declaring_scope, 0,
            "an unbraced namespace does not open a body, so the file scope is the namespace scope"
        );
        let detail = gadget
            .import
            .as_ref()
            .expect("an import binder carries a detail");
        assert_eq!(detail.alias.as_deref(), Some("Gadget"));
        assert_eq!(detail.imported_name.as_deref(), Some("Widget"));
        assert_eq!(detail.target_segments, ["App", "Model", "Widget"]);
        assert!(!detail.wildcard, "PHP has no wildcard import");

        assert_eq!(
            reached(&env, "Gadget", fixture.at("new Gadget()")).node,
            gadget.node,
            "the alias is in effect below its declaration"
        );
        assert_eq!(
            binding_of(&env, "Gadget", fixture.at("namespace App"), None),
            BindingOfOutcome::NoBinding,
            "and not above it"
        );

        assert_eq!(
            env.package
                .package_fq
                .as_ref()
                .map(|fq| fq.display(brokk_bifrost_core::analyzer::fq_name::segment_interner())),
            Some("App.Util".to_owned())
        );
        assert!(
            env.package.syntactic,
            "PHP writes its namespace in the source"
        );
    }

    /// A braced `namespace N { ... }` is its own scope, and the `use` names it
    /// imports stop at its closing brace.
    #[test]
    fn php_use_aliases_stop_at_the_end_of_a_braced_namespace() {
        let source = concat!(
            "<?php\n",
            "\n",
            "namespace First {\n",
            "    use App\\Model\\Widget as Gadget;\n",
            "\n",
            "    function first(): Gadget {\n",
            "        return new Gadget();\n",
            "    }\n",
            "}\n",
            "\n",
            "namespace Second {\n",
            "    function second(): int {\n",
            "        return 1;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Php, "src/braced.php", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let gadget = binding(&env, "Gadget");
        assert_eq!(gadget.kind, BindingKind::ImportBinder);
        let namespace = env.scope(gadget.declaring_scope);
        assert_eq!(
            namespace.anchor.kind(),
            Some(NormalizedKind::Module),
            "a braced namespace body is the scope its imports are written in"
        );
        assert_eq!(
            gadget.activation.end_byte, namespace.range.end_byte,
            "and the alias stops where that namespace does"
        );
        assert_eq!(
            reached(&env, "Gadget", fixture.at("new Gadget()")).node,
            gadget.node
        );
        assert_eq!(
            binding_of(&env, "Gadget", fixture.at("return 1"), None),
            BindingOfOutcome::NoBinding,
            "the sibling namespace never sees it"
        );
    }
}
