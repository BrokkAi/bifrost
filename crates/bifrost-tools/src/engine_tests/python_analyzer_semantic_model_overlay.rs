#[cfg(test)]
mod python_extraction_tests {

    pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::class;

    pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::method;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::Signature;
    use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;
    pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::overlay;
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::extends;

    #[test]
    #[hardwon("#4619: a same-module short base name blocked inherited __exit__ lookup")]
    fn python_external_member_lookup_resolves_unqualified_bases_in_the_stub_module() {
        let mut base = class("_io._IOBase", "python");
        base.locator_path = Some("_io.pyi".to_string());
        let mut derived = class("_io._BufferedIOBase", "python");
        derived.locator_path = Some("_io.pyi".to_string());
        let exit = method(
            &base,
            "member.io-base-exit",
            "__exit__",
            Some(Signature {
                type_parameters: Vec::new(),
                parameters: Vec::new(),
                returns: Some(TypeRef::Named {
                    name: "None".to_string(),
                    arguments: Vec::new(),
                    nullable: true,
                }),
            }),
        );
        let model = overlay(
            vec![base.clone(), derived.clone(), exit],
            vec![extends(&derived, "_IOBase")],
        );

        let declaration = brokk_bifrost_python_analysis::python_external_member_declaration(
            &model,
            &derived.id,
            "__exit__",
        )
        .expect("the declared same-module base contributes its effective method");
        assert_eq!(declaration.qualified_name, "_io._IOBase.__exit__");
    }
}
