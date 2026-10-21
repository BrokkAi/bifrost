#[cfg(test)]
mod rust_departing_wave3_tests_tests {
    use crate::analyzer::semantic::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    const RUST_FIELD_SOURCE: &str = "struct Config { password: &'static str }\nfn log_sink(_: &str) {}\nfn caller(config: &Config) { log_sink(config.password); }\nfn main() {}\n";

    const RUST_PARAMETER_SOURCE: &str = "fn caller(password: &str) {}\n";

    const RUST_CONST_SOURCE: &str =
        "const KEY: [u8; 4] = [0u8; 4];\nfn use_key(_: &[u8]) {}\nfn caller() { use_key(&KEY); }\n";

    fn rust_fixture(files: &[(&str, &str)]) -> AnalyzerFixture {
        AnalyzerFixture::new_for_language(Language::Rust, files)
    }

    #[test]
    fn field_member_source_falls_back_to_observable_field_load() {
        let fixture = rust_fixture(&[("main.rs", RUST_FIELD_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "main.rs");
        let start_byte = RUST_FIELD_SOURCE
            .find("config.password")
            .expect("field access")
            + "config.".len();
        let end_byte = start_byte + "password".len();
        let range = Range {
            start_byte,
            end_byte,
            start_line: RUST_FIELD_SOURCE[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            end_line: RUST_FIELD_SOURCE[..end_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
        };
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .pointees_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("field member source points-to query");
        let points_to = outcome
            .available_value()
            .expect("field member source retains points-to evidence");
        assert!(
            !points_to.observations().is_empty(),
            "field member must address an observable field load: {outcome:?}"
        );
    }

    #[test]
    fn parameter_source_observes_the_procedure_input_at_entry() {
        let fixture = rust_fixture(&[("main.rs", RUST_PARAMETER_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "main.rs");
        let start_byte = RUST_PARAMETER_SOURCE
            .find("password: &str")
            .expect("parameter binder");
        let end_byte = start_byte + "password: &str".len();
        let range = Range {
            start_byte,
            end_byte,
            start_line: 0,
            end_line: 0,
        };
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .pointees_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("parameter source points-to query");
        let points_to = outcome
            .available_value()
            .expect("parameter source retains points-to evidence");
        assert!(
            !points_to.observations().is_empty(),
            "parameter binder must observe the input at procedure entry: {outcome:?}"
        );
    }

    #[test]
    fn const_read_source_projects_the_literal_definition_to_the_read() {
        let fixture = rust_fixture(&[("main.rs", RUST_CONST_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "main.rs");
        let start_byte = RUST_CONST_SOURCE.find("&KEY").expect("const read") + "&".len();
        let end_byte = start_byte + "KEY".len();
        let range = Range {
            start_byte,
            end_byte,
            start_line: RUST_CONST_SOURCE[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            end_line: RUST_CONST_SOURCE[..end_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
        };
        let oracle = fixture.analyzer.semantic_oracle_provider();
        assert_eq!(
            oracle.rust_literal_const_read_range(&file, range),
            Some(range),
            "the const read must resolve to its literal initializer"
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .pointees_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("const source points-to query");
        let points_to = outcome
            .available_value()
            .expect("const read retains point-sensitive evidence");
        assert!(
            !points_to.observations().is_empty(),
            "const read must observe the value at its executable read: {outcome:?}"
        );
    }
}
