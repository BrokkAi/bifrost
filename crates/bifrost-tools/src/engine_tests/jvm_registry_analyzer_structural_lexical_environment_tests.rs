#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::BindingKind;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::BindingOfOutcome;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::Fixture;

    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::ImportBinderDetail;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::WILDCARD_IMPORT_NAME;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::binding;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::binding_of;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::reached;

    /// Two wildcard imports in one file can both supply a simple name, which is
    /// exactly the collision the Java resolver answers today by returning
    /// nothing. The row keeps it explicit instead.
    #[test]
    fn java_colliding_wildcard_imports_are_reported_as_ambiguous() {
        let source = concat!(
            "package app;\n",
            "import java.util.*;\n",
            "import java.awt.*;\n",
            "class Widget {\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        let wildcards: Vec<&ImportBinderDetail> = env
            .bindings
            .iter()
            .filter_map(|row| row.import.as_ref())
            .filter(|detail| detail.wildcard)
            .collect();
        assert_eq!(
            wildcards
                .iter()
                .map(|detail| (detail.local_name.as_str(), detail.wildcard_ambiguous))
                .collect::<Vec<_>>(),
            vec![
                (WILDCARD_IMPORT_NAME, Some(true)),
                (WILDCARD_IMPORT_NAME, Some(true)),
            ],
            "bindings: {:?}",
            env.bindings
        );
        assert_eq!(
            binding_of(&env, WILDCARD_IMPORT_NAME, fixture.at("class Widget"), None),
            BindingOfOutcome::NoBinding,
            "a wildcard row is evidence, never a name that reaches"
        );
    }
    /// A Scala `import` is a statement, so one written inside a block is in
    /// effect from the import onward and not from the block's first byte. A
    /// file-level import stays scope-wide, which is what every other language
    /// reports for every import (#2925).
    #[brokk_bifrost_test_macros::hardwon(
        "317af407fd3b: Scala imports and contextual parameters need their exact lexical scope"
    )]
    #[test]
    fn a_scala_block_local_import_is_in_effect_only_below_the_import() {
        let source = concat!(
            "package app\n",
            "\n",
            "import scala.util.Try\n",
            "\n",
            "object Host {\n",
            "  def run(seed: Int): Int = {\n",
            "    val guarded = Try(seed).getOrElse(0)\n",
            "    import scala.math.max\n",
            "    max(guarded, 2)\n",
            "  }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Scala, "src/Host.scala", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let file_level = binding(&env, "Try");
        assert_eq!(file_level.kind, BindingKind::ImportBinder);
        assert_eq!(file_level.hoisting, HoistingClass::ScopeWide);
        assert_eq!(file_level.declaring_scope, 0);
        assert_eq!(file_level.activation, env.scopes[0].range);

        let block_local = binding(&env, "max");
        assert_eq!(block_local.kind, BindingKind::ImportBinder);
        assert_eq!(block_local.hoisting, HoistingClass::SourceOrder);
        let block = env.scope(block_local.declaring_scope);
        assert_eq!(
            block.anchor.kind(),
            Some(NormalizedKind::Block),
            "a block-local import is declared in the block: {block:?}"
        );
        assert_eq!(
            block_local.activation.start_byte,
            fixture.at("import scala.math.max") + "import scala.math.max".len(),
            "the import is in effect from the end of its own statement"
        );
        assert_eq!(block_local.activation.end_byte, block.range.end_byte);

        assert_eq!(
            binding_of(&env, "max", fixture.at("Try(seed)"), None),
            BindingOfOutcome::NoBinding,
            "a read above the import reaches no binding of the imported name"
        );
        assert_eq!(
            reached(&env, "max", fixture.at("max(guarded")).node,
            block_local.node,
            "a read below the import reaches it"
        );
        assert_eq!(
            reached(&env, "Try", fixture.at("Try(seed)")).node,
            file_level.node,
            "the file-level import reaches the whole file"
        );
    }
    /// A `given` and an `extension` are scopes of their own, so their
    /// parameters bind inside the definition rather than being excluded as
    /// members of the template they are written in (#2925).
    #[brokk_bifrost_test_macros::hardwon(
        "317af407fd3b: Scala imports and contextual parameters need their exact lexical scope"
    )]
    #[test]
    fn scala_given_and_extension_parameters_bind_inside_their_definition() {
        let source = concat!(
            "package app\n",
            "\n",
            "trait Ord[T]\n",
            "\n",
            "object Host {\n",
            "  given ordering(using base: Int): Ord[Int] = build(base)\n",
            "\n",
            "  extension (value: String) {\n",
            "    def twice(sep: String): String = value + sep + value\n",
            "  }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Scala, "src/Host.scala", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let template = env
            .scopes
            .iter()
            .find(|scope| scope.anchor.kind() == Some(NormalizedKind::Class))
            .unwrap_or_else(|| panic!("the object is a scope: {:?}", env.scopes));

        let base = binding(&env, "base");
        assert_eq!(base.kind, BindingKind::Parameter);
        assert_eq!(base.hoisting, HoistingClass::ScopeWide);
        let given = env.scope(base.declaring_scope);
        assert_ne!(
            given.index, template.index,
            "a given parameter is not a member of the enclosing object: {given:?}"
        );
        assert_eq!(
            &source[given.range.start_byte..given.range.end_byte],
            "given ordering(using base: Int): Ord[Int] = build(base)"
        );
        assert_eq!(base.activation, given.range);

        let value = binding(&env, "value");
        assert_eq!(value.kind, BindingKind::Parameter);
        assert_eq!(value.hoisting, HoistingClass::ScopeWide);
        let extension = env.scope(value.declaring_scope);
        assert_ne!(
            extension.index, template.index,
            "an extension parameter is not a member of the enclosing object: {extension:?}"
        );
        assert!(
            source[extension.range.start_byte..extension.range.end_byte]
                .starts_with("extension (value: String)"),
            "the extension group is the scope: {extension:?}"
        );
        assert_eq!(value.activation, extension.range);

        let sep = binding(&env, "sep");
        assert_eq!(sep.kind, BindingKind::Parameter);
        assert_eq!(
            env.scope(sep.declaring_scope).anchor.kind(),
            Some(NormalizedKind::Method),
            "the extension method scopes its own parameters"
        );

        assert_eq!(
            reached(&env, "base", fixture.at("build(base)") + "build(".len()).node,
            base.node,
            "the given parameter is reached in the given's body"
        );
        assert_eq!(
            binding_of(&env, "base", fixture.at("value + sep"), None),
            BindingOfOutcome::NoBinding,
            "and nowhere else"
        );
        assert_eq!(
            reached(&env, "value", fixture.at("value + sep")).node,
            value.node,
            "the extension parameter is reached in the extension method's body"
        );
        assert_eq!(
            binding_of(&env, "value", fixture.at("build(base)"), None),
            BindingOfOutcome::NoBinding,
            "and nowhere else"
        );
    }
}
