#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_analysis::analyzer::store::relational_query::tests::explain_query_plan;
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::relational_query::content_sql;

    use brokk_bifrost_analysis::analyzer::store::relational_query::render_name;

    use brokk_bifrost_analysis::analyzer::store::relational_query::split_view_sources;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::fq_name::segment_interner;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_core::analyzer::{
        DefinitionLanguageScope, RelationalDefinitionQuery, RelationalDefinitionRequest,
        RelationalName, symbol_path::parse_symbol_path_fq,
    };

    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    /// Regression pin for issue #2588: `AnalyzerDefinitionLookup` (see
    /// `crates/bifrost-analysis/src/analyzer/analyzer_definition_lookup.rs`)
    /// issues small, per-owner/per-name `ExactName`, `NormalizedName`,
    /// `StructuralChildren`, and `StructuralMembers` requests -- almost
    /// always below `SET_QUERY_MIN_REQUESTS` -- so they are served by the
    /// point-query path in `definition_values` instead of the batched
    /// `set_*` functions above.
    ///
    /// Before the fix, that point-query path queried the wide `UNION ALL`
    /// compound views (`live_definition_exact_names`,
    /// `live_definition_normalized_names`, `live_structural_members`)
    /// directly. Their anchored arm cannot seek
    /// `idx_code_units_anchored_parent_identifier` by the request's
    /// parent/identifier, because that index's leading columns
    /// (`fq_anchor_kind`, `fq_anchor_pop`) are supplied by a correlated join
    /// to `workspace_file_anchors`, not a request literal; SQLite instead
    /// drove that arm from `workspace_file_anchors` filtered by language
    /// alone (`SEARCH anchors USING COVERING INDEX
    /// idx_workspace_file_anchors_lookup (lang=?)`), and unconditionally
    /// computed the path-derived arm's per-language `path_symbol_units` scan
    /// even though `content_sql`'s `source_kind <> 'path'` predicate
    /// discards 100% of its rows.
    ///
    /// This test calls the real `split_view_sources` (the function
    /// `definition_values` uses to decide what to query) with a real
    /// `JavaAdapter` and asserts both that it routes these four shapes
    /// through the lean, `INDEXED BY`-forced views from migration
    /// `0027-relational-definition-set-views.sql`, and that each resulting
    /// query seeks its intended partial index, drives from `units` rather
    /// than `workspace_file_anchors`, and never references
    /// `path_symbol_units`/`import_statements` at all (the split views omit
    /// the path arm by construction). If `split_view_sources` is changed to
    /// return `None` for any of these shapes -- reproducing the pre-fix
    /// behavior of falling back to the wide compound views -- the
    /// `.unwrap_or_else` below panics and this test fails.
    #[test]
    #[hardwon("#2588: hot definition point queries regressed from indexed views to broad scans")]
    fn definition_point_queries_seek_split_view_indexes() {
        for state in PlannerStatisticsState::BOTH {
            definition_point_queries_seek_split_view_indexes_in(state);
        }
    }
    /// `live_definition_identifiers` (0026) remains in place for its other
    /// caller (the blob-local lookup pinned by
    /// `relational_definition_views_enforce_identity_constraints_and_index_name_lookups`
    /// in `crates/bifrost-core/src/cache_db.rs`) and for `path_units`'s
    /// path-derived-row fallback, which still queries the wide view
    /// directly. This pin documents that its identifier-prefix shape still
    /// seeks the identifier index rather than scanning, even though
    /// `definition_values`'s hot point-query path no longer reaches it for
    /// `IdentifierPrefix` (see
    /// `definition_point_queries_seek_split_view_indexes` for the lean
    /// `live_stable_definition_identifiers` / `live_anchored_definition_identifiers`
    /// route that shape uses instead).
    #[test]
    #[hardwon(
        "9527ec801458: identifier lookups walked revision membership before narrowing by name"
    )]
    fn identifier_definition_queries_narrow_before_revision_membership() {
        for state in PlannerStatisticsState::BOTH {
            identifier_definition_queries_narrow_before_revision_membership_in(state);
        }
    }
    fn definition_point_queries_seek_split_view_indexes_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        state.install(&connection);
        let explain = |sql: String, bindings: &[&str]| {
            explain_query_plan(&connection, "definition", &sql, bindings)
        };
        let assert_seeks_units_index = |case_name: &str,
                                        view: &str,
                                        index: &str,
                                        plan: &[String]| {
            assert!(
                plan.iter().any(|detail| detail.contains(index)),
                "{case_name} ({view}) must seek {index} {state}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("SCAN units")
                        && !detail.contains("SCAN code_units")),
                "{case_name} ({view}) must not scan code_units {state}: {plan:#?}"
            );
            // Revision membership must follow a selective name/anchor seek,
            // never drive the query. On Elasticsearch, allowing `workspace_file_versions`
            // to drive made every definition request walk all 15,711 Java
            // paths before probing the requested name. Stable names drive
            // directly from the partial unit-name index. Anchored names drive
            // from the requested package-name index, which supplies the
            // anchor kind/pop needed for the anchored unit index.
            let units_step = plan
                .iter()
                .position(|detail| detail.contains("units"))
                .unwrap_or_else(|| {
                    panic!("the requested units index appears in the plan {state}: {plan:#?}")
                });
            let anchored = view.contains("anchored");
            let anchor_driven = anchored && index != "idx_code_units_lang_identifier_lookup";
            let versions_step = plan
                .iter()
                .position(|detail| {
                    if anchor_driven {
                        detail.contains("SEARCH files USING INTEGER PRIMARY KEY")
                    } else {
                        detail.contains("idx_workspace_file_versions_snapshot_blob")
                    }
                })
                .unwrap_or_else(|| {
                    panic!("revision membership appears in the plan {state}: {plan:#?}")
                });
            let driver_step = if anchor_driven {
                let anchor_step = plan
                    .iter()
                    .position(|detail| detail.contains("idx_workspace_file_anchor_rows_package"))
                    .unwrap_or_else(|| {
                        panic!(
                            "anchored lookup starts from the requested package {state}: {plan:#?}"
                        )
                    });
                assert!(
                    anchor_step < units_step,
                    "{case_name} ({view}) must bind anchor kind/pop before seeking units {state}: {plan:#?}"
                );
                anchor_step
            } else {
                units_step
            };
            assert!(
                driver_step < versions_step,
                "{case_name} ({view}) must narrow by name before revision membership {state}: {plan:#?}"
            );
            if !anchor_driven {
                assert!(
                    plan.iter().any(|detail| {
                        detail.contains("idx_workspace_file_versions_snapshot_blob")
                    }),
                    "{case_name} ({view}) must seek revision membership by candidate blob {state}: {plan:#?}"
                );
            }
            assert!(
                plan.iter().all(|detail| !detail.contains("SCAN anchors")
                    && !detail.contains("SCAN workspace_file_anchors")),
                "{case_name} ({view}) must not scan workspace_file_anchors {state}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("symbols") && !detail.contains("imports")),
                "{case_name} ({view}) must not touch path_symbol_units or import_statements {state}: {plan:#?}"
            );
        };

        let adapter = JavaAdapter;
        let widget_name = RelationalName::stable(parse_symbol_path_fq(
            Language::Java,
            "demo.Widget",
            segment_interner(),
        ));
        let request_for = |query: RelationalDefinitionQuery| RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: widget_name.clone(),
            query,
        };

        let cases: [(&str, RelationalDefinitionQuery, &[&str]); 4] = [
            (
                "exact name",
                RelationalDefinitionQuery::ExactName,
                &[
                    "idx_code_units_stable_parent_identifier",
                    "idx_code_units_anchored_parent_identifier",
                ],
            ),
            (
                "structural children",
                RelationalDefinitionQuery::StructuralChildren,
                &[
                    "idx_code_units_stable_parent_identifier",
                    "idx_code_units_anchored_parent_identifier",
                ],
            ),
            (
                "structural members",
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: "run".to_string(),
                },
                &[
                    "idx_code_units_stable_parent_identifier",
                    "idx_code_units_anchored_parent_identifier",
                ],
            ),
            (
                "identifier",
                RelationalDefinitionQuery::Identifier { file: None },
                &[
                    "idx_code_units_lang_identifier_lookup",
                    "idx_code_units_lang_identifier_lookup",
                ],
            ),
        ];

        for (case_name, query, expected_indexes) in cases {
            let request = request_for(query);
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let sources = split_view_sources(&adapter, &request, &prefix, &tail)
                .unwrap_or_else(|| panic!("{case_name} must route through split_view_sources"));
            assert_eq!(
                sources.len(),
                expected_indexes.len(),
                "{case_name} must query exactly the stable and anchored split views"
            );
            for ((view, predicate, values), index) in sources.iter().zip(expected_indexes) {
                let bindings: Vec<&str> = std::iter::once("java")
                    .chain(values.iter().map(String::as_str))
                    .collect();
                let plan = explain(content_sql(view, predicate), &bindings);
                assert_seeks_units_index(case_name, view, index, &plan);
            }
        }

        // NormalizedName additionally covers the "unchanged tail" case
        // (normalized_tail IS NULL, so the exact tail doubles as the
        // normalized one), which falls back to the parent-name views
        // instead of the normalized-name views. Four sources total.
        let normalized_request = request_for(RelationalDefinitionQuery::NormalizedName);
        let (prefix, tail, _) = render_name(&adapter, &normalized_request.name);
        let sources = split_view_sources(&adapter, &normalized_request, &prefix, &tail)
            .expect("normalized name must route through split_view_sources");
        let expected_indexes = [
            "idx_code_units_stable_normalized_tail",
            "idx_code_units_anchored_normalized_tail",
            "idx_code_units_stable_parent_identifier",
            "idx_code_units_anchored_parent_identifier",
        ];
        assert_eq!(
            sources.len(),
            expected_indexes.len(),
            "normalized name must query the changed-tail and unchanged-tail split views"
        );
        for ((view, predicate, values), index) in sources.iter().zip(expected_indexes) {
            let bindings: Vec<&str> = std::iter::once("java")
                .chain(values.iter().map(String::as_str))
                .collect();
            let plan = explain(content_sql(view, predicate), &bindings);
            assert_seeks_units_index("normalized name", view, index, &plan);
        }

        // `IdentifierPrefix`'s terminal segment must already be a decoration
        // range (see `decorated_identifier_prefix_successor`'s own
        // assertion): production only ever builds one from
        // `decorated_identifier_seeks`, which appends a trailing backtick
        // for C#'s CLR-arity spellings (for example ``Widget`1``). Use a
        // name shaped the same way rather than the plain `widget_name` above.
        let decorated_name = RelationalName::stable(parse_symbol_path_fq(
            Language::Java,
            "demo.Widget`",
            segment_interner(),
        ));
        let prefix_request = RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: decorated_name,
            query: RelationalDefinitionQuery::IdentifierPrefix { file: None },
        };
        let (decorated_prefix, decorated_tail, _) = render_name(&adapter, &prefix_request.name);
        let sources = split_view_sources(
            &adapter,
            &prefix_request,
            &decorated_prefix,
            &decorated_tail,
        )
        .expect("identifier prefix must route through split_view_sources");
        assert_eq!(
            sources.len(),
            2,
            "identifier prefix must query exactly the stable and anchored identifier views"
        );
        for (view, predicate, values) in &sources {
            let bindings: Vec<&str> = std::iter::once("java")
                .chain(values.iter().map(String::as_str))
                .collect();
            let plan = explain(content_sql(view, predicate), &bindings);
            assert_seeks_units_index(
                "identifier prefix",
                view,
                "idx_code_units_lang_identifier_lookup",
                &plan,
            );
        }

        // The file-scoped variants of both shapes (`file: Some(_)`) route
        // through the same two lean views with an added `rel_path`
        // predicate.
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "demo/Widget.java".to_string(),
        );
        for (case_name, name, query) in [
            (
                "file identifier",
                widget_name.clone(),
                RelationalDefinitionQuery::Identifier {
                    file: Some(file.clone()),
                },
            ),
            (
                "file identifier prefix",
                prefix_request.name.clone(),
                RelationalDefinitionQuery::IdentifierPrefix {
                    file: Some(file.clone()),
                },
            ),
        ] {
            let request = RelationalDefinitionRequest {
                ordinal: 0,
                language_scope: DefinitionLanguageScope::Language(Language::Java),
                name,
                query,
            };
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let sources = split_view_sources(&adapter, &request, &prefix, &tail)
                .unwrap_or_else(|| panic!("{case_name} must route through split_view_sources"));
            assert_eq!(
                sources.len(),
                2,
                "{case_name} must query exactly the stable and anchored identifier views"
            );
            for (view, predicate, values) in &sources {
                let bindings: Vec<&str> = std::iter::once("java")
                    .chain(values.iter().map(String::as_str))
                    .collect();
                let plan = explain(content_sql(view, predicate), &bindings);
                assert_seeks_units_index(
                    case_name,
                    view,
                    "idx_code_units_lang_identifier_lookup",
                    &plan,
                );
            }
        }

        // The two package-type shapes route through the lean content views
        // added by Part 2 of the plan. `live_anchored_package_types` is not
        // the wide view's anchored arm copied: driving from the anchor rows
        // is what binds `fq_anchor_kind`/`fq_anchor_pop` from the request's
        // own prefix, so the seek reaches `package_fqn_tail` and
        // `simple_type_name` in the same index instead of ranging on
        // `fq_anchor_kind` alone.
        for (case_name, query) in [
            (
                "package types",
                RelationalDefinitionQuery::PackageTypes {
                    simple_name: "Widget".to_string(),
                },
            ),
            (
                "package types in package",
                RelationalDefinitionQuery::PackageTypesInPackage,
            ),
        ] {
            let request = request_for(query);
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let sources = split_view_sources(&adapter, &request, &prefix, &tail)
                .unwrap_or_else(|| panic!("{case_name} must route through split_view_sources"));
            let expected_indexes = [
                "idx_code_units_stable_package_type",
                "idx_code_units_anchored_package_type",
            ];
            assert_eq!(
                sources.len(),
                expected_indexes.len(),
                "{case_name} must query exactly the stable and anchored package-type views"
            );
            for ((view, predicate, values), index) in sources.iter().zip(expected_indexes) {
                let bindings: Vec<&str> = std::iter::once("java")
                    .chain(values.iter().map(String::as_str))
                    .collect();
                let plan = explain(content_sql(view, predicate), &bindings);
                assert_seeks_units_index(case_name, view, index, &plan);
            }
        }

        // Shapes with no split-view equivalent keep using the wide view
        // through `definition_values`'s fallback path.
        assert!(
            split_view_sources(
                &adapter,
                &request_for(RelationalDefinitionQuery::VisibleMembers {
                    identifier: "run".to_string(),
                }),
                &prefix,
                &tail,
            )
            .is_none(),
            "VisibleMembers has no split-view equivalent and must stay on the wide-view fallback"
        );
    }
    fn identifier_definition_queries_narrow_before_revision_membership_in(
        state: PlannerStatisticsState,
    ) {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        state.install(&connection);
        let adapter = JavaAdapter;
        let name = RelationalName::stable(parse_symbol_path_fq(
            Language::Java,
            "demo.Widget`",
            segment_interner(),
        ));
        for query in [
            RelationalDefinitionQuery::Identifier { file: None },
            RelationalDefinitionQuery::IdentifierPrefix { file: None },
        ] {
            let request = RelationalDefinitionRequest {
                ordinal: 0,
                language_scope: DefinitionLanguageScope::Language(Language::Java),
                name: name.clone(),
                query,
            };
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let sources = split_view_sources(&adapter, &request, &prefix, &tail)
                .expect("identifier lookups use split content views");
            assert_eq!(sources.len(), 2, "stable and anchored identifier views");
            for (view, predicate, values) in sources {
                let sql = content_sql(view, &predicate);
                let bindings = std::iter::once("java")
                    .chain(values.iter().map(String::as_str))
                    .collect::<Vec<_>>();
                let plan =
                    explain_query_plan(&connection, "identifier definition", &sql, &bindings);
                let identifier_step = plan
                    .iter()
                    .position(|detail| detail.contains("idx_code_units_lang_identifier_lookup"))
                    .unwrap_or_else(|| panic!("identifier index missing {state}: {plan:#?}"));
                let membership_step = plan
                    .iter()
                    .position(|detail| detail.contains("idx_workspace_file_versions_snapshot_blob"))
                    .unwrap_or_else(|| panic!("revision membership missing {state}: {plan:#?}"));
                assert!(
                    identifier_step < membership_step,
                    "{view} must narrow by identifier before revision membership {state}: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| {
                        !detail.contains("SCAN units")
                            && !detail.contains("SCAN code_units")
                            && !detail.contains("SCAN files")
                    }),
                    "{view} must not scan persisted unit or file tables {state}: {plan:#?}"
                );
            }
        }
    }
}
