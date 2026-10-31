#[cfg(test)]
mod go_extraction_tests_extra {
    mod go_move_0 {

        pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::class;

        pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::method;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::ReceiverFact;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::Signature;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::Visibility;

        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelCompleteness;

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
        #[test]
        fn go_callable_results_require_exact_declared_nominals_and_ordinals() {
            use brokk_bifrost_go_analysis::analyzer::go::package_identity::GoModeledNominalType;

            use brokk_bifrost_go_analysis::analyzer::go::package_identity::GoOverlayPackages;

            let mut package = class("example.com/external", "go");
            package.kind = SemanticModelSymbolKind::Module;
            package.visibility = Visibility::Package;
            package.provenance.completeness = SemanticModelCompleteness::Partial;
            let mut first = class("testing.T", "go");
            first.kind = SemanticModelSymbolKind::Struct;
            let mut second = class("testing.F", "go");
            second.kind = SemanticModelSymbolKind::Struct;
            let mut file = class("os.File", "go");
            file.kind = SemanticModelSymbolKind::Struct;
            let function = go_package_function(
                &package,
                "member.make-pair",
                "MakePair",
                TypeRef::Tuple {
                    elements: vec![
                        TypeRef::Pointer {
                            element: Box::new(TypeRef::Declared {
                                id: first.id.clone(),
                                arguments: Vec::new(),
                                nullable: false,
                            }),
                        },
                        TypeRef::Declared {
                            id: second.id.clone(),
                            arguments: Vec::new(),
                            nullable: false,
                        },
                        TypeRef::Named {
                            name: "custom.Result".to_owned(),
                            arguments: Vec::new(),
                            nullable: false,
                        },
                        TypeRef::Declared {
                            id: first.id.clone(),
                            arguments: vec![TypeRef::Named {
                                name: "string".to_owned(),
                                arguments: Vec::new(),
                                nullable: false,
                            }],
                            nullable: false,
                        },
                        TypeRef::Slice {
                            element: Box::new(TypeRef::Declared {
                                id: first.id.clone(),
                                arguments: Vec::new(),
                                nullable: false,
                            }),
                        },
                    ],
                },
            );
            let mut listen = go_package_function(
                &package,
                "member.listen",
                "Listen",
                TypeRef::Tuple {
                    elements: vec![
                        TypeRef::Declared {
                            id: second.id.clone(),
                            arguments: Vec::new(),
                            nullable: false,
                        },
                        TypeRef::Named {
                            name: "error".to_owned(),
                            arguments: Vec::new(),
                            nullable: false,
                        },
                    ],
                },
            );
            listen.provenance.completeness = SemanticModelCompleteness::Partial;
            let mut public_field = method(
                &first,
                "member.testing-t-name",
                "Name",
                Some(Signature {
                    type_parameters: Vec::new(),
                    parameters: Vec::new(),
                    returns: Some(TypeRef::Named {
                        name: "string".to_owned(),
                        arguments: Vec::new(),
                        nullable: false,
                    }),
                }),
            );
            public_field.kind = SemanticModelSymbolKind::Field;
            public_field.receiver = None;
            let mut public_value_field = method(
                &second,
                "member.testing-f-label",
                "Label",
                Some(Signature {
                    type_parameters: Vec::new(),
                    parameters: Vec::new(),
                    returns: Some(TypeRef::Named {
                        name: "string".to_owned(),
                        arguments: Vec::new(),
                        nullable: false,
                    }),
                }),
            );
            public_value_field.kind = SemanticModelSymbolKind::Field;
            public_value_field.receiver = None;
            let mut stat = method(
                &file,
                "member.os-file-stat",
                "Stat",
                Some(Signature {
                    type_parameters: Vec::new(),
                    parameters: Vec::new(),
                    returns: Some(TypeRef::Tuple {
                        elements: vec![
                            TypeRef::Declared {
                                id: second.id.clone(),
                                arguments: Vec::new(),
                                nullable: false,
                            },
                            TypeRef::Named {
                                name: "error".to_owned(),
                                arguments: Vec::new(),
                                nullable: false,
                            },
                        ],
                    }),
                }),
            );
            stat.receiver = Some(ReceiverFact { pointer: true });
            let overlay = overlay(
                vec![
                    package,
                    first,
                    second,
                    file,
                    function,
                    listen,
                    public_field,
                    public_value_field,
                    stat,
                ],
                Vec::new(),
            );
            let packages = GoOverlayPackages::new(Some(&overlay));

            assert!(matches!(
                packages.callable_result_type_ref("example.com/external", "Listen", false, 0, 0),
                Some(TypeRef::Declared { id, .. }) if id == "type.testing.F"
            ));
            assert!(matches!(
                packages.callable_result_type_ref("example.com/external", "Listen", false, 0, 1),
                Some(TypeRef::Named {
                    name,
                    arguments,
                    nullable: false,
                }) if name == "error" && arguments.is_empty()
            ));

            assert_eq!(
                packages.callable_result_nominal_type(
                    "example.com/external",
                    "MakePair",
                    false,
                    0,
                    0,
                ),
                Some(GoModeledNominalType {
                    declaration_id: "type.testing.T".to_owned(),
                    qualified_name: "testing.T".to_owned(),
                    pointer: true,
                }),
                "a unique positive fact remains usable from a partial package"
            );
            assert_eq!(
                packages.callable_result_nominal_type(
                    "example.com/external",
                    "MakePair",
                    false,
                    0,
                    1,
                ),
                Some(GoModeledNominalType {
                    declaration_id: "type.testing.F".to_owned(),
                    qualified_name: "testing.F".to_owned(),
                    pointer: false,
                })
            );
            assert_eq!(
                packages.callable_result_nominal_type("os.File", "Stat", true, 0, 0,),
                Some(GoModeledNominalType {
                    declaration_id: "type.testing.F".to_owned(),
                    qualified_name: "testing.F".to_owned(),
                    pointer: false,
                }),
                "an exact receiver callable preserves its own tuple result ordinal"
            );
            assert!(
                packages
                    .callable_result_nominal_type("os.File", "Stat", true, 0, 1,)
                    .is_none(),
                "the receiver call's named error result is not a modeled nominal receiver"
            );
            assert!(matches!(
                packages.callable_result_type_ref("os.File", "Stat", true, 0, 1),
                Some(TypeRef::Named {
                    name,
                    arguments,
                    nullable: false,
                }) if name == "error" && arguments.is_empty()
            ));
            assert!(
                packages
                    .callable_result_type_ref("os.File", "Stat", true, 0, 2)
                    .is_none(),
                "an absent tuple ordinal is not a result type fact"
            );
            for ordinal in [2, 3, 4, 5] {
                assert!(
                    packages
                        .callable_result_nominal_type(
                            "example.com/external",
                            "MakePair",
                            false,
                            0,
                            ordinal,
                        )
                        .is_none(),
                    "unsupported or missing result ordinal {ordinal} must remain open"
                );
            }
            assert!(
                packages
                    .callable_result_nominal_type("example.com/external", "MakePair", false, 1, 0,)
                    .is_none(),
                "a wrong call arity must not borrow the zero-arity declaration"
            );
        }
        #[test]
        fn go_callable_result_lookup_abstains_on_competing_or_nonstatic_facts() {
            use brokk_bifrost_go_analysis::analyzer::go::package_identity::GoOverlayPackages;

            let mut package = class("example.com/external", "go");
            package.kind = SemanticModelSymbolKind::Module;
            package.visibility = Visibility::Package;
            let mut result = class("testing.T", "go");
            result.kind = SemanticModelSymbolKind::Struct;
            let returns = TypeRef::Declared {
                id: result.id.clone(),
                arguments: Vec::new(),
                nullable: false,
            };
            let first = go_package_function(&package, "member.first", "Make", returns.clone());
            let second = go_package_function(&package, "member.second", "Make", returns.clone());
            let conflict = overlay(
                vec![package.clone(), result.clone(), first, second],
                Vec::new(),
            );
            assert!(
                GoOverlayPackages::new(Some(&conflict))
                    .callable_result_nominal_type("example.com/external", "Make", false, 0, 0,)
                    .is_none(),
                "competing exact declarations are not a positive fact"
            );

            let mut nonstatic = go_package_function(&package, "member.nonstatic", "Make", returns);
            nonstatic.is_static = false;
            let malformed = overlay(vec![package, result, nonstatic], Vec::new());
            assert!(
                GoOverlayPackages::new(Some(&malformed))
                    .callable_result_nominal_type("example.com/external", "Make", false, 0, 0,)
                    .is_none(),
                "a nonstatic member cannot prove a package function call"
            );

            let mut forged_package = class("example.com/forged", "go");
            forged_package.kind = SemanticModelSymbolKind::Module;
            forged_package.visibility = Visibility::Package;
            let mut forged_type = class("example.com/external.Forged", "go");
            forged_type.kind = SemanticModelSymbolKind::Function;
            let forged_return = TypeRef::Declared {
                id: forged_type.id.clone(),
                arguments: Vec::new(),
                nullable: false,
            };
            let callable =
                go_package_function(&forged_package, "member.forged", "Make", forged_return);
            let forged = overlay(
                vec![forged_package, forged_type.clone(), callable],
                Vec::new(),
            );
            let packages = GoOverlayPackages::new(Some(&forged));
            assert!(
                packages
                    .declared_type_qualified_name(&forged_type.id)
                    .is_none(),
                "a top-level callable-shaped symbol cannot satisfy a Declared type reference"
            );
            assert!(
                packages
                    .callable_result_nominal_type("example.com/forged", "Make", false, 0, 0)
                    .is_none(),
                "a forged callable symbol cannot become a modeled nominal result"
            );
        }
    }
}
