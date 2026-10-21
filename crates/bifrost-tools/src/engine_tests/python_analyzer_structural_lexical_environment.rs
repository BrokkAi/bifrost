#[cfg(test)]
mod python_residency_tests {

    use brokk_bifrost_core::analyzer::structural::resolution::BindingKind;

    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::ScopeAnchor;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::binding;

    use brokk_bifrost_analysis::analyzer::structural::lexical_environment::test_support::reached;
    #[test]
    fn python_function_local_assigned_in_a_block_reaches_after_the_block() {
        let source = concat!(
            "def render(choose):\n",
            "    if choose:\n",
            "        value = 1\n",
            "    return value\n",
        );
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let env = fixture.environment();

        let value = binding(&env, "value");
        assert_eq!(value.kind, BindingKind::Local);
        assert_eq!(
            env.scope(value.declaring_scope).anchor.kind(),
            Some(NormalizedKind::Function),
            "Python's if block does not open a lexical scope"
        );
        assert_eq!(
            reached(&env, "value", fixture.at("return value") + "return ".len()).node,
            value.node
        );
    }
    #[test]
    fn python_module_root_keeps_top_level_imports_in_file_scope() {
        let fixture = Fixture::new(
            Language::Python,
            "src/app.py",
            "import json\nvalue = json\n",
        );
        let env = fixture.environment();

        assert_eq!(env.scopes.len(), 1, "scopes: {:?}", env.scopes);
        let json = binding(&env, "json");
        assert_eq!(json.declaring_scope, 0);
        assert_eq!(env.scope(json.declaring_scope).anchor, ScopeAnchor::File);
    }
    /// One import statement can introduce several names, and a rename can make
    /// two rows' spellings collide with each other's targets. The binder token
    /// is joined by the adapter-recorded span (#1600), so each row lands on
    /// its own alias token; a spelling comparison would send the first row to
    /// the second selector's *name* token, which also spells `beta`.
    #[test]
    fn python_swapped_import_aliases_keep_their_own_binder_tokens() {
        let source = "from pkg import alpha as beta, beta as alpha\n";
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let env = fixture.environment();

        let beta = binding(&env, "beta");
        let alpha = binding(&env, "alpha");
        assert_eq!(beta.kind, BindingKind::ImportBinder);
        assert_eq!(alpha.kind, BindingKind::ImportBinder);
        // Both rows keep the scope-wide interval the shared default states:
        // Python does not override `import_binder_activation`, so #2925 left
        // its rows exactly as they were.
        assert_eq!(beta.hoisting, HoistingClass::ScopeWide);
        assert_eq!(alpha.hoisting, HoistingClass::ScopeWide);
        assert_eq!(beta.activation, env.scopes[0].range);
        assert_eq!(alpha.activation, env.scopes[0].range);
        assert_eq!(
            beta.range.start_byte,
            fixture.at("beta,"),
            "the row bound as beta anchors on its own alias token: {beta:?}"
        );
        assert_eq!(
            alpha.range.start_byte,
            fixture.at("as alpha") + "as ".len(),
            "the row bound as alpha anchors on its own alias token: {alpha:?}"
        );
        assert_ne!(
            beta.node, alpha.node,
            "two rows of one declaration keep distinct AST identities"
        );
    }
}
