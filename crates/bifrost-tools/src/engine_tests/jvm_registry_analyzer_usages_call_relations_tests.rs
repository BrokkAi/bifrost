#[cfg(test)]
mod jvm_registry_tests {

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::call_span;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::registry_fixture_support::dispatch_kotlin_call;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::registry_fixture_support::dispatch_kotlin_external_member;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::generous_limits;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    #[cfg(test)]
    #[test]
    fn scala_outgoing_relations_keep_nested_partial_function_and_given_calls_separate() {
        let source = r#"
package example

object Calls {
  def nestedCall(): Int = 1
  def matchCall(): Int = 2
  def directCall(): Int = 3

  def outer(value: Int): Int = {
    val partial: PartialFunction[Int, Int] = { case _ => nestedCall() }
    given generated: Int = nestedCall()
    val matched = value match { case _ => matchCall() }
    directCall()
  }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Scala, &[("Calls.scala", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let caller = analyzer
            .definitions("example.Calls$.outer")
            .next()
            .expect("Scala caller");

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let relation = CallRelationService::outgoing_bounded(
            analyzer,
            token,
            &caller,
            generous_limits(),
            None,
        );
        let callees = relation
            .sites
            .iter()
            .map(|site| site.callee.fq_name())
            .collect::<Vec<_>>();

        assert_eq!(
            callees,
            vec![
                "example.Calls$.matchCall".to_string(),
                "example.Calls$.directCall".to_string(),
            ],
            "{relation:#?}"
        );
    }
    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "#2823: Kotlin unknown receiver chain stays without an external identity when structured receiver resolution is incomplete"
    )]
    #[test]
    fn kotlin_unknown_receiver_chain_stays_identityless() {
        let source = r#"package app

class Holder(val value: MissingType)

fun caller(holder: Holder): String = holder.value.toString()
"#;
        let call = "holder.value.toString()";
        let fixture = AnalyzerFixture::new_for_language(Language::Kotlin, &[("App.kt", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "App.kt"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert!(
            lookup.boundaries.iter().all(|boundary| !matches!(
                boundary,
                CallDispatchBoundaryKind::External {
                    callee_text: Some(_),
                    ..
                }
            )),
            "an unknown Kotlin receiver chain must not become bindable: {lookup:#?}"
        );
    }
    #[cfg(test)]
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[brokk_bifrost_test_macros::hardwon(
        "#2823: An imported Kotlin external member resolves through an activated declaration pack and publishes the canonical package identity"
    )]
    #[test]
    fn kotlin_imported_external_member_publishes_resolver_proven_identity() {
        dispatch_kotlin_external_member("Ext.wrap");
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "#2823: A fully qualified Kotlin external member resolves to the same pack-backed identity without an import binder"
    )]
    #[test]
    fn kotlin_fully_qualified_external_member_publishes_resolver_proven_identity() {
        dispatch_kotlin_external_member("com.example.ext.Ext.wrap");
    }
    #[cfg(test)]
    #[test]
    fn kotlin_concrete_receiver_local_binding_publishes_external_identity() {
        let source = "package app\n\nimport com.example.ext.Ext\n\nfun caller(value: String): String {\n    val ext = Ext(value)\n    return ext.wrap(value)\n}\n";
        let call = "ext.wrap(value)";
        let lookup = dispatch_kotlin_call(source, call);

        assert!(
            lookup.targets.is_empty(),
            "an external declaration is not a workspace target: {lookup:#?}"
        );
        assert_eq!(
            lookup.status,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            "the external receiver must report the import-boundary status: {lookup:#?}"
        );
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("com.example.ext.Ext.wrap".into()),
                normalized_static_owner: None,
                external_callee_identity: None,
            }],
            "a caller-local value constructed from the imported external type must keep its package-rooted identity: {lookup:#?}"
        );
    }
}
