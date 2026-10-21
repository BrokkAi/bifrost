#[cfg(test)]
mod python_residency_tests {
    use brokk_bifrost_analysis::analyzer::structural::materialization_rows::{
        MaterializationCompleteness, MaterializationIncompleteReason,
    };

    use brokk_bifrost_core::analyzer::structural::materialization::ExportForm;

    use brokk_bifrost_analysis::analyzer::structural::materialization_rows::test_support::Fixture;

    use brokk_bifrost_core::analyzer::structural::materialization::MaterializationAxis;

    use brokk_bifrost_core::analyzer::structural::materialization::SourceExportLocalDefinition;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::structural::materialization::SourceExportBindingKind;
    /// Python `@overload` stubs are declaration-only state rows linked to the
    /// runnable implementation; a stub without one links to an explicit
    /// absence.
    #[test]
    fn python_overload_stubs_link_to_their_implementation() {
        let fixture = Fixture::new(
            Language::Python,
            "over.py",
            concat!(
                "from typing import overload\n",
                "@overload\n",
                "def parse(value: int) -> int: ...\n",
                "@overload\n",
                "def parse(value: str) -> str: ...\n",
                "def parse(value):\n",
                "    return value\n",
                "@overload\n",
                "def orphan(value: int) -> int: ...\n",
            ),
        );
        let rows = fixture.rows();

        // Each overload stub is its own declaration-only unit: two `parse`
        // stubs plus the orphan.
        let stubs: Vec<_> = rows
            .states
            .iter()
            .filter(|row| row.declaration_only)
            .collect();
        assert_eq!(stubs.len(), 3, "states: {:?}", rows.states);

        assert_eq!(rows.links.len(), 3, "links: {:?}", rows.links);
        let parse_links: Vec<_> = rows
            .links
            .iter()
            .filter(|link| link.stub.identifier() == "parse")
            .collect();
        assert_eq!(parse_links.len(), 2);
        for link in parse_links {
            let implementation = link
                .implementation
                .as_ref()
                .expect("each parse stub links to the runnable def");
            assert_eq!(implementation.identifier(), "parse");
            assert!(
                !rows
                    .state_of(implementation)
                    .expect("implementation state row")
                    .declaration_only,
                "the linked implementation must be runnable"
            );
        }
        let orphan_link = rows
            .links
            .iter()
            .find(|link| link.stub.identifier() == "orphan")
            .expect("orphan stub link");
        assert_eq!(orphan_link.implementation, None);
    }
    #[test]
    fn python_all_exports_keep_literal_ranges_and_dynamic_coverage() {
        let fixture = Fixture::new(
            Language::Python,
            "exports.py",
            "__all__ = [\"public\", \"other\", \"public\"]\npublic = 1\n",
        );
        let rows = fixture.rows();
        assert!(rows.completeness.covers(MaterializationAxis::Exports));
        assert_eq!(
            rows.exports
                .iter()
                .map(|row| (row.form, row.exported_name.as_str(), row.range.start_byte))
                .collect::<Vec<_>>(),
            vec![
                (ExportForm::PythonAll, "public", fixture.at("\"public\"")),
                (ExportForm::PythonAll, "other", fixture.at("\"other\"")),
            ]
        );
        assert!(rows.exports.iter().all(|row| row.target.is_none()));
        assert!(matches!(
            &rows.exports[0].local_definition,
            Some(SourceExportLocalDefinition::Defined { binding })
                if binding.name == "public"
                    && binding.kind == SourceExportBindingKind::Binding
                    && binding.range.start_byte == fixture.at("public =")
        ));
        assert!(matches!(
            &rows.exports[1].local_definition,
            Some(SourceExportLocalDefinition::Undefined)
        ));

        let dynamic = Fixture::new(
            Language::Python,
            "dynamic.py",
            "__all__ = [\"known\", *computed]\n",
        );
        let dynamic_rows = dynamic.rows();
        assert!(
            !dynamic_rows
                .completeness
                .covers(MaterializationAxis::Exports)
        );
        assert_eq!(dynamic_rows.exports.len(), 1);
        assert_eq!(dynamic_rows.exports[0].exported_name, "known");
        assert!(matches!(
            &dynamic_rows.exports[0].local_definition,
            Some(SourceExportLocalDefinition::Undefined)
        ));
        assert!(matches!(
            &dynamic_rows.completeness,
            MaterializationCompleteness::Incomplete { reasons, .. }
                if reasons.contains(&MaterializationIncompleteReason::DynamicExportSurface)
        ));

        let dynamic_definitions = Fixture::new(
            Language::Python,
            "dynamic-definitions.py",
            "__all__ = [\"late\", \"present\"]\npresent = 1\nglobals()[\"late\"] = 2\n",
        );
        let dynamic_definition_rows = dynamic_definitions.rows();
        assert!(
            !dynamic_definition_rows
                .completeness
                .covers(MaterializationAxis::Exports)
        );
        assert!(matches!(
            &dynamic_definition_rows.exports[0].local_definition,
            Some(SourceExportLocalDefinition::Unknown)
        ));
        assert!(matches!(
            &dynamic_definition_rows.exports[1].local_definition,
            Some(SourceExportLocalDefinition::Defined { binding }) if binding.name == "present"
        ));
        assert!(matches!(
            &dynamic_definition_rows.completeness,
            MaterializationCompleteness::Incomplete { reasons, .. }
                if reasons.contains(&MaterializationIncompleteReason::DynamicExportDefinition)
        ));

        let star_import = Fixture::new(
            Language::Python,
            "star-import.py",
            "__all__ = [\"late\"]\nfrom unknown_module import *\n",
        );
        let star_import_rows = star_import.rows();
        assert!(matches!(
            &star_import_rows.exports[0].local_definition,
            Some(SourceExportLocalDefinition::Unknown)
        ));
        assert!(matches!(
            &star_import_rows.completeness,
            MaterializationCompleteness::Incomplete { reasons, .. }
                if reasons.contains(&MaterializationIncompleteReason::DynamicExportDefinition)
        ));

        let recovered = Fixture::new(Language::Python, "recovered.py", "__all__ =\n");
        let recovered_rows = recovered.rows();
        assert!(
            !recovered_rows
                .completeness
                .covers(MaterializationAxis::Exports)
        );

        let recovered_annotation = Fixture::new(
            Language::Python,
            "recovered-annotation.py",
            "__all__: list[str] =\n",
        );
        assert!(
            !recovered_annotation
                .rows()
                .completeness
                .covers(MaterializationAxis::Exports)
        );

        let annotation = Fixture::new(Language::Python, "annotation.py", "__all__: list[str]\n");
        let annotation_rows = annotation.rows();
        assert!(
            annotation_rows
                .completeness
                .covers(MaterializationAxis::Exports)
        );
        assert!(annotation_rows.exports.is_empty());

        let local = Fixture::new(
            Language::Python,
            "local.py",
            "def build():\n    __all__ = [\"local_only\"]\n",
        );
        let local_rows = local.rows();
        assert!(local_rows.completeness.covers(MaterializationAxis::Exports));
        assert!(local_rows.exports.is_empty());
    }
}
