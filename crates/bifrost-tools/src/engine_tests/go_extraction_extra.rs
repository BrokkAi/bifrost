#[cfg(test)]
mod go_extraction_tests_extra {
    mod go_move_0 {

        pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::class;

        pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::method;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::Signature;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::Visibility;

        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbol;
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbolKind;

        pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::overlay;

        fn go_package_function(
            owner: &SemanticModelSymbol,
            id: &str,
            name: &str,
            returns: TypeRef,
        ) -> SemanticModelSymbol {
            let mut function = method(
                owner,
                id,
                name,
                Some(Signature {
                    type_parameters: Vec::new(),
                    parameters: Vec::new(),
                    returns: Some(returns),
                }),
            );
            function.kind = SemanticModelSymbolKind::Function;
            function.is_static = true;
            function
        }
        #[test]
        fn go_visible_symbol_checks_uniqueness_before_language_and_visibility() {
            use brokk_bifrost_go_analysis::analyzer::go::package_identity::GoOverlayPackages;

            let public = class("example.com/external.Widget", "go");
            let unique = overlay(vec![public.clone()], Vec::new());
            assert!(
                GoOverlayPackages::new(Some(&unique))
                    .visible_symbol("example.com/external.Widget")
                    .is_some(),
                "one public Go declaration is visible"
            );

            let mut private = public.clone();
            private.id = "type.example.com/external.Widget.private".to_owned();
            private.visibility = Visibility::Private;
            private.provenance.pack_digest = "private-pack".to_owned();
            let visibility_conflict = overlay(vec![public.clone(), private], Vec::new());
            assert!(
                GoOverlayPackages::new(Some(&visibility_conflict))
                    .visible_symbol("example.com/external.Widget")
                    .is_none(),
                "a private same-name record cannot be filtered out before uniqueness"
            );

            let mut ambiguous = public;
            ambiguous.provenance.ambiguous = true;
            let ambiguous = overlay(vec![ambiguous], Vec::new());
            assert!(
                GoOverlayPackages::new(Some(&ambiguous))
                    .visible_symbol("example.com/external.Widget")
                    .is_none(),
                "one individually ambiguous record is not visible"
            );
        }
        #[test]
        fn go_package_member_publication_unifies_both_storage_names_before_uniqueness() {
            use brokk_bifrost_go_analysis::analyzer::go::package_identity::GoOverlayPackages;

            let public_type = class("example.com/external.Widget", "go");
            let type_only = overlay(vec![public_type.clone()], Vec::new());
            assert!(
                GoOverlayPackages::new(Some(&type_only))
                    .publishes_member("example.com/external", "Widget"),
                "the canonical package-type name remains supported"
            );

            let mut module = class("example.com/external._module_", "go");
            module.kind = SemanticModelSymbolKind::Module;
            module.visibility = Visibility::Package;
            let function = go_package_function(
                &module,
                "member.example-widget",
                "Widget",
                TypeRef::Named {
                    name: "string".to_owned(),
                    arguments: Vec::new(),
                    nullable: false,
                },
            );
            let module_only = overlay(vec![module.clone(), function.clone()], Vec::new());
            assert!(
                GoOverlayPackages::new(Some(&module_only))
                    .publishes_member("example.com/external", "Widget"),
                "the generated module-scope member name remains supported"
            );

            let competing_shapes = overlay(
                vec![public_type.clone(), module.clone(), function],
                Vec::new(),
            );
            assert!(
                !GoOverlayPackages::new(Some(&competing_shapes))
                    .publishes_member("example.com/external", "Widget"),
                "a type and module-scope member with the same selected name conflict"
            );

            let mut private_type = public_type;
            private_type.id = "type.example.com/external.Widget.private".to_owned();
            private_type.visibility = Visibility::Private;
            private_type.provenance.pack_digest = "private-pack".to_owned();
            let public_function = go_package_function(
                &module,
                "member.example-widget.public",
                "Widget",
                TypeRef::Named {
                    name: "string".to_owned(),
                    arguments: Vec::new(),
                    nullable: false,
                },
            );
            let cross_name_visibility_conflict =
                overlay(vec![module, public_function, private_type], Vec::new());
            assert!(
                !GoOverlayPackages::new(Some(&cross_name_visibility_conflict))
                    .publishes_member("example.com/external", "Widget"),
                "a private record under the alternate accepted name remains a conflict"
            );
        }
    }
}
