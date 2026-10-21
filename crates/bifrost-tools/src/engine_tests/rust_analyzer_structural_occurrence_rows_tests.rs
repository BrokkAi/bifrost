#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::Fixture;

    use brokk_bifrost_core::analyzer::structural::occurrences::Namespace;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceClass;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceCompleteness;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceFileResult;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceIncompleteReason;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceRow;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceTarget;

    use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

    use brokk_bifrost_core::analyzer::structural::resolution::RejectionReason;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::ResolutionTraceResult;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCandidate;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCandidateRef;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::expect_row;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::trace_of;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCompleteness;
    #[test]
    fn rust_raw_identifiers_decode_and_declaration_heads_keep_their_namespace() {
        let source = concat!(
            "struct Widget {\n",
            "    label: String,\n",
            "}\n",
            "\n",
            "fn render(r#type: &str) -> String {\n",
            "    r#type.to_owned()\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);
        let result = fixture.result();

        let struct_name = expect_row(&result.rows, fixture.at("Widget {"), "struct name");
        assert_eq!(struct_name.role, OccurrenceRole::DeclarationName);
        assert_eq!(struct_name.namespace, Namespace::Type);

        let function_name = expect_row(&result.rows, fixture.at("render("), "function name");
        assert_eq!(function_name.namespace, Namespace::Value);

        let raw_binder = expect_row(&result.rows, fixture.at("r#type:"), "raw-identifier binder");
        assert_eq!(raw_binder.role, OccurrenceRole::Binder);
        assert_eq!(raw_binder.raw_spelling, "r#type");
        assert_eq!(raw_binder.decoded_spelling.as_deref(), Some("type"));
        assert_eq!(raw_binder.effective_spelling(), "type");

        let plain = expect_row(&result.rows, fixture.at("label: String"), "field name");
        assert_eq!(
            plain.decoded_spelling, None,
            "unescaped spellings decode to nothing"
        );
    }

    /// A Rust path scope segment can be a module or a type, and the syntax
    /// does not decide which; it resolves in the qualifier namespace, which is
    /// [`Namespace::PathPrefix`]. The row is kept and the role is covered:
    /// dropping it lost the only evidence that `std` and `HashMap` are
    /// mentioned at all (#3064).
    #[brokk_bifrost_test_macros::hardwon(
        "#3064: Rust path qualifier occurrences were dropped instead of using the path-prefix namespace"
    )]
    #[test]
    fn rust_path_segments_are_kept_in_the_path_prefix_namespace() {
        let source = "use std::collections::HashMap;\nfn take(map: HashMap<u32, u32>) -> usize { map.len() }\n";
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);
        let result = fixture.result();

        let segments: Vec<(&str, Namespace)> = result
            .rows
            .iter()
            .filter(|row| row.role == OccurrenceRole::PathSegment)
            .map(|row| (row.effective_spelling(), row.namespace))
            .collect();
        assert_eq!(
            segments,
            [
                ("std", Namespace::PathPrefix),
                ("collections", Namespace::PathPrefix),
            ],
        );
        assert!(result.completeness.covers(OccurrenceRole::PathSegment));
        assert!(result.completeness.covers(OccurrenceRole::Binder));
        if let OccurrenceCompleteness::Incomplete { reasons, .. } = &result.completeness {
            assert!(
                !reasons.iter().any(|reason| matches!(
                    reason,
                    OccurrenceIncompleteReason::NamespaceUnknown(_)
                )),
                "no row is dropped for want of a namespace: {reasons:?}"
            );
        }
    }

    fn rejections(trace: &ResolutionTraceResult, reason: RejectionReason) -> Vec<&TraceCandidate> {
        trace
            .rejected()
            .filter(|row| row.outcome.rejection() == Some(reason))
            .collect()
    }

    /// The mined `61c223586` shape: an inner binding shadows an outer one of
    /// the same name. The read between them selects the inner binder at the
    /// lexical tier, and the outer binder is reported as a rejected candidate
    /// with the reason that discarded it.
    #[test]
    fn a_shadowed_rust_binding_is_reported_as_rejected_beside_the_selected_local() {
        let source = concat!(
            "fn render() -> usize {\n",
            "    let label = 1;\n",
            "    {\n",
            "        let label = 2;\n",
            "        return label;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);
        let result = fixture.traced_result();
        let trace = trace_of(&result.rows, fixture.at("label;"), "shadowed read");

        assert_eq!(
            trace.completeness,
            TraceCompleteness::SelectionOnly,
            "native Rust retains these lexical rejections but does not instrument every rejected path"
        );
        assert!(
            trace.selects_at(PrecedenceTier::LexicalBinding),
            "the inner binder is the selection: {:?}",
            trace.candidates
        );
        let shadowed = rejections(trace, RejectionReason::ShadowedByNearer);
        assert_eq!(
            shadowed.len(),
            1,
            "exactly the outer binder loses: {:?}",
            trace.candidates
        );
        assert_eq!(shadowed[0].tier, Some(PrecedenceTier::LexicalBinding));
        match &shadowed[0].candidate {
            TraceCandidateRef::Binding { name, .. } => assert_eq!(name, "label"),
            other => panic!("a shadowed binder is an environment binding row, got {other:?}"),
        }
    }

    /// Identity-only derivation is the same rows, minus the definition batch.
    ///
    /// This is the #1452 lever: resolving every reference is the dominant cost
    /// of deriving a large file's occurrences, and a consumer that joins rows
    /// by AST identity never reads the result. The contract that makes
    /// skipping it safe is that nothing else about the rows changes and the
    /// omission is stated in the row rather than looking like a failed
    /// resolution.
    #[test]
    fn identity_only_rows_match_resolved_rows_and_state_that_targets_were_not_derived() {
        let fixture = Fixture::new(
            Language::Rust,
            "src/lib.rs",
            "pub fn order(mut values: Vec<usize>) -> usize {\n    values.sort();\n    values.len()\n}\n",
        );
        let resolved = fixture.result();
        let identity_only = fixture.identity_only_result();

        let key = |rows: &OccurrenceFileResult| {
            rows.rows
                .iter()
                .map(|row| {
                    (
                        row.ast_id(),
                        row.id(),
                        row.role,
                        row.class,
                        row.namespace,
                        row.range.start_byte,
                        row.range.end_byte,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            key(&identity_only),
            key(&resolved),
            "identity, role, class, namespace and position must not depend on target derivation"
        );
        assert_eq!(
            identity_only.completeness, resolved.completeness,
            "skipping the definition batch says nothing about the file's completeness"
        );

        let reference_rows: Vec<&OccurrenceRow> = identity_only
            .rows
            .iter()
            .filter(|row| row.class == OccurrenceClass::Reference)
            .collect();
        assert!(
            !reference_rows.is_empty(),
            "the fixture must contain reference-class rows for this to prove anything"
        );
        for row in reference_rows {
            assert!(
                matches!(row.target, OccurrenceTarget::NotDerived),
                "a reference row derived without targets must say so rather than look unresolved; got {:?}",
                row.target
            );
            assert!(row.resolution_status.is_none());
        }
        for row in identity_only
            .rows
            .iter()
            .filter(|row| row.class != OccurrenceClass::Reference)
        {
            assert!(
                matches!(row.target, OccurrenceTarget::None),
                "a non-reference row has nothing to resolve either way; got {:?}",
                row.target
            );
            assert!(row.resolution_status.is_none());
        }
        assert!(
            resolved.rows.iter().any(|row| !matches!(
                row.target,
                OccurrenceTarget::None | OccurrenceTarget::NotDerived
            )),
            "the resolved derivation must actually resolve something, or the comparison is vacuous"
        );
    }
}
