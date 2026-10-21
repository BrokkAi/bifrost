#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_analysis::analyzer::semantic_model::model::Signature;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::class;

    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::method;

    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::overlay;
    #[test]
    #[hardwon(
        "6ecf92322c56: Ruby constructor results used receiver instead of declared return type"
    )]
    fn ruby_constructor_result_uses_the_declared_type_instead_of_the_receiver() {
        use brokk_bifrost_ruby_analysis::analyzer::ruby::constant_identity::RubyOverlayConstants;

        let mut factory = class("Example::Factory", "ruby");
        factory.id = RubyOverlayConstants::declaration_id(&factory.qualified_name);
        let mut product = class("Example::Product", "ruby");
        product.id = RubyOverlayConstants::declaration_id(&product.qualified_name);
        let mut constructor = method(
            &factory,
            "example.new",
            "new",
            Some(Signature {
                type_parameters: Vec::new(),
                parameters: Vec::new(),
                returns: Some(TypeRef::Declared {
                    id: product.id.clone(),
                    arguments: Vec::new(),
                    nullable: false,
                }),
            }),
        );
        constructor.is_static = true;
        let overlay = overlay(vec![factory, product, constructor], Vec::new());
        let constants = RubyOverlayConstants::new(Some(&overlay));
        let owner = constants.unique_type("Example::Factory").unwrap();
        assert_eq!(
            constants
                .declared_result(constants.callable(owner, "new", 0).unwrap())
                .unwrap()
                .qualified_name,
            "Example::Product"
        );
        assert!(constants.callable(owner, "new", 1).is_none());
        assert!(
            RubyOverlayConstants::new(None)
                .declared_result(constants.callable(owner, "new", 0).unwrap())
                .is_none()
        );
    }
}
