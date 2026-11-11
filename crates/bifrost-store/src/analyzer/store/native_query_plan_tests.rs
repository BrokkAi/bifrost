//! Plan the production SQL, including function-local constants, without keeping
//! a second copy of the statements. Syn reads Rust syntax; SQLite reads SQL.

use super::*;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod shared_support {
    use super::*;

    use syn::visit::Visit;

    #[derive(Default)]
    #[doc(hidden)]
    pub struct Registry {
        #[doc(hidden)]
        pub statements: Vec<(String, String)>,
        file: PathBuf,
        scope: Vec<String>,
        #[doc(hidden)]
        pub dynamic: Vec<String>,
        #[doc(hidden)]
        pub schemas: Vec<String>,
        prepared: std::collections::HashSet<String>,
        referenced: std::collections::HashSet<String>,
    }
    impl Registry {
        pub(super) fn record(&mut self, name: &str, expression: &syn::Expr) {
            let value = sql_value(expression, &self.file);
            if let Some(sql) = value {
                if sql.contains("CREATE TEMP") && !sql.contains('?') {
                    self.schemas.push(sql.clone());
                }
                self.statements.push((
                    format!("{}::{}::{name}", self.file.display(), self.scope.join("::")),
                    sql,
                ));
            }
        }
    }
    pub(super) fn sql_value(expression: &syn::Expr, file: &Path) -> Option<String> {
        match expression {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => Some(value.value()),
            syn::Expr::Macro(value) if value.mac.path.is_ident("include_str") => {
                let path: syn::LitStr = syn::parse2(value.mac.tokens.clone()).unwrap();
                Some(std::fs::read_to_string(file.parent().unwrap().join(path.value())).unwrap())
            }
            syn::Expr::Macro(value) if value.mac.path.is_ident("concat") => {
                use syn::parse::Parser;
                let parts =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                        .parse2(value.mac.tokens.clone())
                        .unwrap();
                parts
                    .iter()
                    .map(|part| sql_value(part, file))
                    .collect::<Option<Vec<_>>>()
                    .map(|parts| parts.concat())
            }
            _ => None,
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#7573: fixed store reads bypassed the statement cache")]
    fn fixed_sql_in_native_adapter_store_files_uses_the_statement_cache() {
        #[derive(Default)]
        struct DirectFixedSql(Vec<String>);
        impl<'ast> Visit<'ast> for DirectFixedSql {
            fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                if item.attrs.iter().any(|attr| attr.path().is_ident("test")) {
                    return;
                }
                syn::visit::visit_item_fn(self, item);
            }
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                if item.attrs.iter().any(|attr| {
                    attr.path().is_ident("cfg")
                        && attr
                            .parse_args::<syn::Path>()
                            .is_ok_and(|path| path.is_ident("test"))
                }) {
                    return;
                }
                syn::visit::visit_item_mod(self, item);
            }
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if matches!(
                    call.method.to_string().as_str(),
                    "query_row" | "prepare" | "execute" | "query_map"
                ) && let Some(first) = call.args.first()
                    && (matches!(
                        first,
                        syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(_),
                            ..
                        })
                    ) || matches!(first, syn::Expr::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident.to_string().chars().all(|ch| ch.is_ascii_uppercase() || ch == '_'))))
                {
                    self.0.push(call.method.to_string());
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/analyzer/store");
        let mut files: Vec<_> = walkdir::WalkDir::new(root.join("resolution_operation"))
            .into_iter()
            .map(|entry| entry.unwrap().into_path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .collect();
        files.extend(
            std::fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    let name = path.file_name().unwrap().to_string_lossy();
                    path.extension().is_some_and(|ext| ext == "rs")
                        && ["python_", "go_", "jvm_", "rust_"]
                            .iter()
                            .any(|prefix| name.starts_with(prefix))
                }),
        );
        files.sort();
        // Scans src/analyzer/store/resolution_operation/ and the root store files
        // prefixed python_, go_, jvm_ or rust_. The C# adapter files (csharp_) and
        // the other store files are not scanned yet (#8637).
        // Allowed exceptions are listed here with their reasons. There are none.
        const ALLOWLIST: &[&str] = &[];
        let mut failures = Vec::new();
        for file in files {
            let mut visitor = DirectFixedSql::default();
            visitor.visit_file(&syn::parse_file(&std::fs::read_to_string(&file).unwrap()).unwrap());
            if !visitor.0.is_empty() && !ALLOWLIST.contains(&file.to_str().unwrap()) {
                failures.push((file, visitor.0));
            }
        }
        assert!(
            failures.is_empty(),
            "fixed SQL bypasses the statement cache: {failures:?}"
        );
    }
    impl<'ast> Visit<'ast> for Registry {
        fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
            if expression.mac.path.is_ident("format") {
                use syn::parse::Parser;
                let arguments =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                        .parse2(expression.mac.tokens.clone())
                        .unwrap();
                for argument in &arguments {
                    syn::visit::visit_expr(self, argument);
                }
            }
            syn::visit::visit_expr_macro(self, expression);
        }

        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.attrs.iter().any(|attr| {
                attr.path().is_ident("cfg")
                    && attr
                        .parse_args::<syn::Path>()
                        .is_ok_and(|path| path.is_ident("test"))
            }) {
                return;
            }
            syn::visit::visit_item_mod(self, item);
        }

        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.referenced
                .insert(path.path.segments.last().unwrap().ident.to_string());
            syn::visit::visit_expr_path(self, path);
        }

        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.attrs.iter().any(|attr| attr.path().is_ident("test")) {
                return;
            }
            self.scope.push(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
            self.scope.pop();
        }

        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.record(&item.ident.to_string(), &item.expr);
            syn::visit::visit_item_const(self, item);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "execute_batch"
                && let Some(sql) = call.args.first()
            {
                self.record("schema", sql);
            }
            if (call.method == "execute" || call.method == "query_row")
                && let Some(sql) = call.args.first()
            {
                self.record(&call.method.to_string(), sql);
            }
            if call.method == "prepare_cached" || call.method == "prepare" {
                match call.args.first().unwrap() {
                    syn::Expr::Lit(_) | syn::Expr::Macro(_) => {
                        self.record(&call.method.to_string(), &call.args[0])
                    }
                    syn::Expr::Path(path) => {
                        let name = path.path.segments.last().unwrap().ident.to_string();
                        if name.chars().any(|ch| ch.is_ascii_lowercase()) {
                            self.dynamic.push(format!(
                                "{}::{}: runtime SQL variable {name}",
                                self.file.display(),
                                self.scope.join("::")
                            ));
                        }
                        self.prepared.insert(name);
                    } // The constant's declaration is registered above.
                    other => self.dynamic.push(format!(
                        "{}::{:?}: {other:?}",
                        self.file.display(),
                        self.scope
                    )),
                }
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    #[doc(hidden)]
    pub fn registry() -> Registry {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/analyzer/store");
        let mut files: Vec<_> = walkdir::WalkDir::new(root.join("resolution_operation"))
            .into_iter()
            .map(|entry| entry.unwrap().into_path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .collect();
        files.push(root.join("source_facts.rs"));
        files.extend(
            ["unit_summaries.rs", "unit_schedule.rs", "rust_crates.rs"].map(|name| root.join(name)),
        );
        files.extend(
            std::fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    let name = path.file_name().unwrap().to_str().unwrap();
                    name.ends_with("_package_context.rs") || name.ends_with("_unit_summaries.rs")
                }),
        );
        files.sort();
        let mut registry = Registry::default();
        for file in files {
            let syntax = syn::parse_file(&std::fs::read_to_string(&file).unwrap()).unwrap();
            registry.file = file;
            registry.visit_file(&syntax);
        }
        registry
            .schemas
            .push(crate::analyzer::store::REQUESTED_PARSED_BLOBS_DDL.to_owned());
        registry
            .schemas
            .push(crate::analyzer::store::REQUESTED_ANALYSIS_PROJECTIONS_DDL.to_owned());
        // Reverse nomination arms in resolution_operation read this request
        // TEMP table; its DDL lives in reverse_candidates.rs, outside the scan.
        registry.schemas.push(
            crate::analyzer::store::resolution_operation::REVERSE_CANDIDATE_KEYS_DDL.to_owned(),
        );
        registry.statements.retain(|(name, sql)| {
            let constant = name.rsplit("::").next().unwrap();
            let first = sql
                .lines()
                .map(str::trim_start)
                .find(|line| !line.is_empty() && !line.starts_with("--"))
                .and_then(|line| line.split_whitespace().next());
            matches!(
                constant,
                "prepare_cached" | "prepare" | "execute" | "query_row"
            ) || registry.prepared.contains(constant)
                || (registry.referenced.contains(constant)
                // This fragment is registered through its compiled accessor.
                && constant != "TARGET_SCOPED_REFERENCE_INVENTORY_GAPS_SQL"
                && matches!(
                    first,
                    Some("SELECT" | "WITH" | "INSERT" | "UPDATE" | "DELETE")
                ))
        });
        // These production statements expand SQL macros or lazy compositions.
        // Read their compiled values rather than reimplementing Rust expansion.
        use super::super::{
            go_reverse_rows, imports, rust_crate_context, rust_crate_rows, rust_reverse_rows,
        };
        use crate::analyzer::store::{go_unit_summaries, rust_unit_summaries, selected_definition};
        for (name, sql) in [
            (
                "MISSING_PUBLISHED_COMPLETE_ANALYSIS_SQL",
                crate::analyzer::store::MISSING_PUBLISHED_COMPLETE_ANALYSIS_SQL,
            ),
            (
                "REQUIRED_EXISTING_ANALYSIS_PROJECTIONS_SQL",
                crate::analyzer::store::REQUIRED_EXISTING_ANALYSIS_PROJECTIONS_SQL,
            ),
            (
                "csharp_compilation::SELECTED_CONFIGURATION_MASK_SQL",
                crate::analyzer::store::csharp_compilation::SELECTED_CONFIGURATION_MASK_SQL,
            ),
            (
                "csharp_demand::NAMESPACE_ROUTE",
                super::super::csharp_demand::NAMESPACE_ROUTE,
            ),
            (
                "csharp_namespaces::NAMESPACE_CANDIDATES",
                super::super::csharp_namespaces::NAMESPACE_CANDIDATES,
            ),
            (
                "csharp_demand::TYPE_WITH_EXPLICIT_BASES",
                super::super::csharp_demand::TYPE_WITH_EXPLICIT_BASES,
            ),
            (
                "csharp_namespaces::ORDINARY_CANDIDATES",
                super::super::csharp_namespaces::ORDINARY_CANDIDATES,
            ),
            (
                "csharp_namespaces::STAGED_CANDIDATES",
                super::super::csharp_namespaces::STAGED_CANDIDATES,
            ),
            (
                "csharp_namespaces::VERIFY_NAMESPACE",
                super::super::csharp_namespaces::VERIFY_NAMESPACE,
            ),
            ("imports::POINT", imports::POINT),
            ("imports::ENUMERATE", imports::ENUMERATE),
            (
                "python_unit_summaries::LIVE",
                crate::analyzer::store::python_unit_summaries::LIVE,
            ),
            (
                "python_binding_rows::IMPORT_MODULE_OPERAND_SQL",
                crate::analyzer::store::python_binding_rows::IMPORT_MODULE_OPERAND_SQL,
            ),
            (
                "python_member_rows::BUILTIN_NAMESPACE_CLOSED_SQL",
                crate::analyzer::store::python_member_rows::BUILTIN_NAMESPACE_CLOSED_SQL,
            ),
            (
                "python_member_rows::UNIVERSE_REFERENCE_NAME_SQL",
                crate::analyzer::store::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL,
            ),
            (
                "reverse_nomination::REVERSE_DEFINITION_SITE_SQL",
                crate::analyzer::store::resolution_operation::reverse_nomination::REVERSE_DEFINITION_SITE_SQL,
            ),
            (
                "rust_crate_derivation::SQL_RUST_CRATE_MEMBER_IDENTITY",
                crate::analyzer::store::rust_crates::derivation::SQL_RUST_CRATE_MEMBER_IDENTITY,
            ),
            ("imports::SCOPE_NAMED", imports::SCOPE_NAMED),
            ("imports::AT_SITE", imports::AT_SITE),
            (
                "unit_summaries::LIVE_SUMMARY_SQL",
                crate::analyzer::store::unit_summaries::LIVE_SUMMARY_SQL,
            ),
            (
                "rust_crate_rows::IMPL_ITEM_TRAITS",
                rust_crate_rows::IMPL_ITEM_TRAITS,
            ),
            (
                "rust_crate_rows::TRAIT_IMPL_MEMBER_AT",
                rust_crate_rows::TRAIT_IMPL_MEMBER_AT,
            ),
            (
                "rust_crate_rows::TRAIT_VISIBLE_AT",
                rust_crate_rows::TRAIT_VISIBLE_AT,
            ),
            (
                "rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT",
                rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT,
            ),
            (
                "go_unit_summaries::GO_LIVE_SUMMARY_SQL",
                go_unit_summaries::GO_LIVE_SUMMARY_SQL,
            ),
            (
                "file_context::PeerSelection::RELATION",
                crate::analyzer::store::resolution_operation::go_same_package::PACKAGE_PEER_MOUNTS,
            ),
            (
                "rust_unit_summaries::DEPENDENCY_REEXPORT_WITNESS_SQL",
                rust_unit_summaries::DEPENDENCY_REEXPORT_WITNESS_SQL,
            ),
            (
                "rust_copy_absence::RUST_COPY_ABSENCE_SQL",
                crate::analyzer::store::rust_copy_absence::RUST_COPY_ABSENCE_SQL,
            ),
            (
                "rust_copy_absence::RUST_COPY_ABSENCE_QUESTION_SQL",
                crate::analyzer::store::rust_copy_absence::RUST_COPY_ABSENCE_QUESTION_SQL,
            ),
            (
                "selected_definition::SELECTED_DEFINITION_BLOB_SQL",
                selected_definition::SELECTED_DEFINITION_BLOB_SQL,
            ),
            (
                "rust_crate_context::DEPENDENCY",
                rust_crate_context::DEPENDENCY.as_str(),
            ),
            (
                "rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE",
                rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE.as_str(),
            ),
            (
                "go_reverse_rows::GO_TARGET_DEFINITION_SEMANTICS_SQL",
                go_reverse_rows::GO_TARGET_DEFINITION_SEMANTICS_SQL.as_str(),
            ),
            (
                "go_facts::GO_SOURCE_HEADER_SQL",
                brokk_bifrost_core::analyzer::go_facts::GO_SOURCE_HEADER_SQL,
            ),
            (
                "rust_reverse_rows::initial_reference_inventory_gap_locators_sql",
                rust_reverse_rows::initial_reference_inventory_gap_locators_sql(),
            ),
            (
                "rust_reverse_rows::target_scoped_reference_inventory_gaps_sql",
                rust_reverse_rows::target_scoped_reference_inventory_gaps_sql(),
            ),
            (
                "rust_reverse_rows::DEFINITION_SITE_SQL",
                rust_reverse_rows::DEFINITION_SITE_SQL,
            ),
            (
                "go_package_context::OUTSIDE_SELECTED_BUILD_FILES_SQL",
                crate::analyzer::store::go_package_context::OUTSIDE_SELECTED_BUILD_FILES_SQL,
            ),
            (
                "resolution_lexical::SELECTED_MOUNT_OF_BLOB_SQL",
                crate::analyzer::store::resolution_lexical::SELECTED_MOUNT_OF_BLOB_SQL,
            ),
            (
                "resolution_lexical::RUST_UNENUMERABLE_MEMBER_DISPATCH_SQL",
                crate::analyzer::store::resolution_lexical::RUST_UNENUMERABLE_MEMBER_DISPATCH_SQL,
            ),
        ] {
            registry.statements.push((name.to_owned(), sql.to_owned()));
        }
        for query in crate::analyzer::store::planner_statistics::pinned_plans::pinned_queries()
            .into_iter()
            .filter(|query| {
                matches!(
                    query.name.as_str(),
                    "generic_parameter_declarations"
                        | "qualified_route_mounts"
                        | "selected_typed_shared_membership"
                        | "selected_typed_shared_membership_64"
                        | "go_hierarchy_selection_coverage"
                )
            })
        {
            registry.statements.push((query.name, query.sql));
        }
        let missing: Vec<_> = registry
            .prepared
            .iter()
            .filter(|name| {
                name.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_')
                    && !registry.statements.iter().any(|(registered, _)| {
                        registered.rsplit("::").next() == Some(name.as_str())
                    })
            })
            .collect();
        assert!(
            missing.is_empty(),
            "production SQL constants missing from the plan registry: {missing:?}"
        );
        registry
    }
}
