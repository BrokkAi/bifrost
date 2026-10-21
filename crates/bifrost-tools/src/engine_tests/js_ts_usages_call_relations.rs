#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_analysis::CodeUnitIndex;
    use brokk_bifrost_analysis::analyzer::QueryScope;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallBindingCache;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallBindingStatus;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnostic;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSyntaxCache;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::IncomingCallOmission;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::analyzer::usages::model::UsageHit;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::append_incoming_projection_omission;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::bind_call_site_arguments;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::call_span;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::generous_limits;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::project_incoming_call_hit;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::resolve_outgoing_call_candidate;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    fn empty_typescript_analyzer() -> (tempfile::TempDir, TypescriptAnalyzer, ProjectFile) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        (temp, analyzer, file)
    }
    #[test]
    fn exact_dispatch_resolves_one_nested_call_without_resolving_its_neighbor() {
        let source = "function outer(value: number) { return value; }\nfunction inner() { return 1; }\nfunction caller() { return outer(inner()); }\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("nested.ts", source)]);
        let file = ProjectFile::new(fixture.project_root(), "nested.ts");
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file,
                call_span: call_span(source, "inner()"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(lookup.targets[0].definition.fq_name(), "inner");
        assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
        assert!(!lookup.cancelled);
        assert!(!lookup.budget_exhausted);
        assert!(!lookup.truncated);
    }
    /// #2495: Python and TypeScript publish the same exact declaration
    /// identities for the ordinary statically knowable call forms. This is the
    /// source-owned pin beneath the policy fixtures: it asks the normalized
    /// dispatch relation directly, so no rendered callee spelling can stand in
    /// for target proof.
    #[brokk_bifrost_test_macros::hardwon(
        "#2725: Cross-language analyzer fixtures compare Python and TypeScript static dispatch proofs and preserve their language-specific target identities"
    )]
    #[test]
    fn exact_dispatch_proves_python_and_typescript_static_targets() {
        const PYTHON: &str = r#"from typing import final

def module_function() -> None:
    pass

@final
class Store:
    def __init__(self, tag: str) -> None:
        self.tag = tag

    def put(self, value: str) -> None:
        pass

    def self_call(self) -> None:
        self.put("self")

@final
class Cache:
    def __init__(self, tag: str) -> None:
        self.tag = tag

    def put(self, value: str) -> None:
        pass

def caller() -> None:
    module_function()
    Store("direct")
    store = Store("local")
    cache = Cache("local")
    store.put("store")
    cache.put("cache")
"#;
        const TYPESCRIPT: &str = r#"export function moduleFunction(): void {}

export class Store {
  private constructor(public tag: string) {}
  put(value: string): void {}
  selfCall(): void { this.put("this"); }
  static direct(): Store { return new Store("direct"); }
  static local(): void {
    const store = new Store("local");
    const cache = Cache.create("local");
    store.put("store");
    cache.put("cache");
  }
}

export class Cache {
  private constructor(public tag: string) {}
  put(value: string): void {}
  static create(tag: string): Cache { return new Cache(tag); }
}

export function caller(): void { moduleFunction(); }
"#;

        let cases = [
            (
                Language::Python,
                "static_targets.py",
                PYTHON,
                vec![
                    ("module_function()", "module_function", None),
                    ("Store(\"direct\")", "Store", None),
                    ("store.put(\"store\")", "put", Some("Store")),
                    ("cache.put(\"cache\")", "put", Some("Cache")),
                    ("self.put(\"self\")", "put", Some("Store")),
                ],
            ),
            (
                Language::TypeScript,
                "static_targets.ts",
                TYPESCRIPT,
                vec![
                    ("moduleFunction()", "moduleFunction", None),
                    ("new Store(\"direct\")", "Store", None),
                    ("store.put(\"store\")", "put", Some("Store")),
                    ("cache.put(\"cache\")", "put", Some("Cache")),
                    ("this.put(\"this\")", "put", Some("Store")),
                ],
            ),
        ];

        for (language, path, source, calls) in cases {
            let fixture = AnalyzerFixture::new_for_language(language, &[(path, source)]);
            let analyzer = fixture.analyzer.analyzer();
            for (call, identifier, owner) in calls {
                let scope = AnalyzerQueryScope::new(analyzer);
                let lookup = CallRelationService::dispatch_at_bounded(
                    analyzer,
                    scope.token(),
                    &ExactCallLocation {
                        file: ProjectFile::new(fixture.project_root(), path),
                        call_span: call_span(source, call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::Resolved),
                    "{language:?} {call}: {lookup:#?}"
                );
                assert_eq!(lookup.targets.len(), 1, "{language:?} {call}: {lookup:#?}");
                let target = &lookup.targets[0];
                assert_eq!(
                    target.proof,
                    UsageProof::Proven,
                    "{language:?} {call}: {lookup:#?}"
                );
                assert_eq!(
                    target.definition.identifier(),
                    identifier,
                    "{language:?} {call}: {lookup:#?}"
                );
                if let Some(owner) = owner {
                    assert!(
                        target.definition.fq_name().contains(owner),
                        "{language:?} {call} resolved to the wrong same-named owner: {lookup:#?}"
                    );
                }
                assert!(
                    lookup.boundaries.is_empty(),
                    "{language:?} {call}: {lookup:#?}"
                );
            }
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "bc14f106eeaa: exact dispatch reuses parsed syntax without changing requested call order"
    )]
    #[test]
    fn exact_dispatch_session_charges_one_parse_and_preserves_reverse_call_order() {
        let source: Arc<str> = Arc::from(
            "function first() {}\nfunction second() {}\nfunction caller() { first(); second(); }\n",
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("sample.ts", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "sample.ts");
        let spans = [
            call_span(&source, "first()"),
            call_span(&source, "second()"),
        ];
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let mut session = CallRelationService::dispatch_session(file.clone(), Arc::clone(&source));
        assert_eq!(
            session.retained_bytes(),
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::prepared_syntax_retained_bytes(
                source.len()
            )
            .saturating_add(file.retained_bytes()),
            "the retained session owns both its parsed source and exact project path"
        );
        let second = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[1],
            generous_limits().max_candidates,
            None,
        );
        let first = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[0],
            generous_limits().max_candidates,
            None,
        );

        assert_eq!(second.work.scanned_files, 1);
        assert_eq!(second.work.scanned_source_bytes, source.len());
        assert_eq!(second.work.examined_candidates, 1);
        assert_eq!(first.work.scanned_files, 0);
        assert_eq!(first.work.scanned_source_bytes, 0);
        assert_eq!(first.work.examined_candidates, 1);
        assert_eq!(first.targets[0].definition.fq_name(), "first");
        assert_eq!(second.targets[0].definition.fq_name(), "second");

        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let single = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file,
                call_span: spans[1],
            },
            source,
            generous_limits(),
            None,
        );
        assert_eq!(single.work.scanned_files, 1);
        assert_eq!(
            single.work.scanned_source_bytes,
            second.work.scanned_source_bytes
        );
        assert_eq!(single.work.examined_candidates, 1);
        assert_eq!(single.status, second.status);
        assert_eq!(single.targets, second.targets);
        assert_eq!(single.boundaries, second.boundaries);
    }
    #[test]
    fn exact_dispatch_session_cancellation_does_not_reclassify_prior_calls() {
        let source: Arc<str> = Arc::from(
            "function first() {}\nfunction second() {}\nfunction caller() { first(); second(); }\n",
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::TypeScript, &[("sample.ts", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "sample.ts");
        let spans = [
            call_span(&source, "first()"),
            call_span(&source, "second()"),
        ];
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let cancellation = CancellationToken::default();
        let source_len = source.len();
        let mut session = CallRelationService::dispatch_session(file, source);

        let first = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[0],
            generous_limits().max_candidates,
            Some(&cancellation),
        );
        cancellation.cancel();
        let second = session.dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &spans[1],
            generous_limits().max_candidates,
            Some(&cancellation),
        );

        assert!(!first.cancelled);
        assert_eq!(first.work.scanned_source_bytes, source_len);
        assert!(second.cancelled);
        assert_eq!(second.work.scanned_files, 0);
        assert_eq!(second.work.scanned_source_bytes, 0);
        assert_eq!(second.work.examined_candidates, 0);
    }
    #[test]
    fn binding_status_distinguishes_missing_layout_from_known_empty_layout() {
        let (_temp, analyzer, missing_file) = empty_typescript_analyzer();
        let missing = CodeUnit::new(missing_file.clone(), CodeUnitType::Function, "", "missing");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        };
        let mut missing_site = CallSite {
            file: missing_file,
            range,
            callee_range: range,
            caller: missing.clone(),
            callee: missing,
            kind: CallSyntaxKind::Function,
            proof: UsageProof::Proven,
            receiver: None,
            arguments: Vec::new(),
        };
        assert_eq!(
            bind_call_site_arguments(
                &analyzer,
                &mut missing_site,
                &mut CallBindingCache::default(),
            ),
            CallBindingStatus::Unavailable
        );

        let source = "export function noArgs() {}\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/app.ts");
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let no_args = analyzer
            .all_declarations()
            .find(|unit| unit.short_name() == "noArgs")
            .expect("known callable");
        let mut known_site = CallSite {
            file,
            range,
            callee_range: range,
            caller: no_args.clone(),
            callee: no_args,
            kind: CallSyntaxKind::Function,
            proof: UsageProof::Proven,
            receiver: None,
            arguments: Vec::new(),
        };
        assert_eq!(
            bind_call_site_arguments(&analyzer, &mut known_site, &mut CallBindingCache::default(),),
            CallBindingStatus::Complete
        );
    }
    #[test]
    fn incoming_projection_reports_an_unmappable_enclosing_unit() {
        let (_temp, analyzer, file) = empty_typescript_analyzer();
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let enclosing = CodeUnit::new(file.clone(), CodeUnitType::Field, "", "value");
        let hit = UsageHit::new(file, 1, 0, 6, enclosing, 1.0, "target()");

        assert_eq!(
            project_incoming_call_hit(
                &analyzer,
                &mut CallSyntaxCache::default(),
                &target,
                hit,
                UsageProof::Proven,
            ),
            Err(IncomingCallOmission::CallerUnavailable)
        );
    }
    #[test]
    fn incoming_projection_reports_unavailable_structured_call_syntax() {
        let (_temp, analyzer, file) = empty_typescript_analyzer();
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let hit = UsageHit::new(file, 1, 0, 6, caller, 1.0, "target()");

        assert_eq!(
            project_incoming_call_hit(
                &analyzer,
                &mut CallSyntaxCache::default(),
                &target,
                hit,
                UsageProof::Proven,
            ),
            Err(IncomingCallOmission::SyntaxUnavailable)
        );
    }
    #[test]
    fn incoming_projection_omission_replaces_ambiguity_advisory() {
        let (_temp, _analyzer, file) = empty_typescript_analyzer();
        let target = CodeUnit::new(file, CodeUnitType::Function, "", "target");
        let mut diagnostics = vec![CallRelationDiagnostic::new(
            CallRelationDiagnosticCode::TargetsAmbiguous,
            "ambiguous".to_string(),
            target.fq_name().to_string(),
        )];

        append_incoming_projection_omission(&mut diagnostics, &target, 1);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CallRelationDiagnosticCode::CandidatesOmitted
        );
        assert_eq!(diagnostics[0].context, target.fq_name());
    }
    #[test]
    fn ambiguous_outgoing_targets_count_empty_and_unmappable_definitions_as_omitted() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        let callable = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let non_callable = CodeUnit::new(file, CodeUnitType::Field, "", "value");

        let empty = resolve_outgoing_call_candidate(
            &analyzer,
            DefinitionLookupStatus::Ambiguous,
            Vec::new(),
        );
        assert_eq!(empty.omitted, 1);
        assert!(empty.callees.is_empty());
        assert!(!empty.fully_retained);

        let partial = resolve_outgoing_call_candidate(
            &analyzer,
            DefinitionLookupStatus::Ambiguous,
            vec![callable, non_callable],
        );
        assert_eq!(partial.callees.len(), 1);
        assert_eq!(partial.omitted, 1);
        assert!(!partial.fully_retained);
    }
}
