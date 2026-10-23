#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::registry_fixture_support::assert_nested_call_reference_names;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::registry_fixture_support::assert_signature_context;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::byte_range;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::file;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::registry_fixture_support::offset_after;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_reference_range_for_call;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_reference_ranges_in_tree;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_signature_context;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;

    #[test]
    fn exact_java_call_span_uses_the_named_method_field() {
        let source = "class Nested { static int outer(int value) { return value; } static int inner() { return 1; } int call() { return outer(inner()); } }";
        assert_nested_call_reference_names("Nested.java", Language::Java, source);
    }
    #[test]
    fn exact_scala_call_spans_use_the_terminal_direct_callee() {
        let source = r#"
object Calls {
  class Box[A](value: Int)
  class Curried(value: Int)(label: String)
  class Service {
    def curried[A](value: Int)(label: String): Int = value
    def combine(other: Service): Service = this
    def ping: Int = 1
  }
  def ordinary(value: Int): Int = value
  def caller(service: Service, other: Service, head: Int, tail: List[Int]): Unit = {
    ordinary(1)
    ordinary[Int](1)
    service.curried[Int](1)("label")
    new Box[Int](1)
    new Curried(1)("label")
    service combine other
    service ping
    head :: tail
  }
}
"#;
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("Scala syntax tree");

        for (call, callee) in [
            ("ordinary(1)", "ordinary"),
            ("ordinary[Int](1)", "ordinary"),
            ("service.curried[Int](1)(\"label\")", "curried"),
            ("new Box[Int](1)", "Box"),
            ("new Curried(1)(\"label\")", "Curried"),
            ("service combine other", "combine"),
            ("service ping", "ping"),
            ("head :: tail", "::"),
        ] {
            let reference =
                call_reference_range_for_call(&tree, Language::Scala, &byte_range(source, call))
                    .unwrap_or_else(|| panic!("missing exact Scala call reference for `{call}`"));
            assert_eq!(
                &source[reference.start_byte..reference.end_byte],
                callee,
                "wrong exact Scala callee for `{call}`"
            );
        }
    }
    #[test]
    fn scala_call_candidates_prune_partial_functions_and_givens_but_not_match_cases() {
        let outer = r#"def outer(value: Int): Int = {
    val partial: PartialFunction[Int, Int] = { case _ => nestedCall() }
    given generated: Int = nestedCall()
    val matched = value match { case _ => matchCall() }
    directCall()
  }"#;
        let source = format!(
            "object Calls {{ def nestedCall(): Int = 1; def matchCall(): Int = 2; def directCall(): Int = 3; {outer} }}"
        );
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, &source).expect("Scala syntax tree");
        let search_range = byte_range(&source, outer);

        let references = call_reference_ranges_in_tree(&tree, Language::Scala, &search_range, 20);
        let names = references
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["matchCall", "directCall"]);
    }
    #[test]
    fn signature_context_handles_scala_brace_argument_block() {
        let source =
            "object App {\n  def target(value: Int): Int = value\n  val result = target { 1 }\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "target { "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 0);
    }
    #[test]
    fn signature_context_handles_scala_infix_call() {
        let source = "object App {\n  class Box { def combine(value: Int): Int = value }\n  val box = new Box\n  val result = box combine 1\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "box combine "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "combine"
        );
        assert_eq!(context.active_parameter, 0);
    }
    #[test]
    fn signature_context_handles_scala_postfix_operator_call() {
        let source = "object App {\n  class Box { def ! : Boolean = true }\n  val box = new Box\n  val result = box !\n}\n";
        let context =
            call_signature_context(&file("App.scala"), source, offset_after(source, "box !"))
                .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "!"
        );
        assert_eq!(context.active_parameter, 0);
    }
    #[test]
    fn scala_call_candidates_exclude_receivers_arguments_and_type_arguments() {
        let source = "object Calls { def caller(service: Service, value: Int, label: String) = service.curried[String](value)(label) }";
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("Scala syntax tree");
        let call = byte_range(source, "service.curried[String](value)(label)");

        let references = call_reference_ranges_in_tree(&tree, Language::Scala, &call, 20);
        let names = references
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["curried"]);
    }
    #[test]
    fn scala_constructor_candidates_exclude_qualifiers_arguments_and_type_arguments() {
        let source = "object Calls { def caller(value: Int) = new pkg.Box[String](value) }";
        let file = file("Calls.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("Scala syntax tree");
        let call = byte_range(source, "new pkg.Box[String](value)");

        let references = call_reference_ranges_in_tree(&tree, Language::Scala, &call, 20);
        let names = references
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["Box"]);
    }
    #[test]
    fn signature_context_counts_active_parameter_after_comma() {
        let source =
            "class A { int target(int left, int right) { return 0; } void f() { target(1, 2); } }";
        assert_signature_context("A.java", source, "1, ", "target", 1);
    }
    #[test]
    fn signature_context_handles_scala_postfix_call() {
        let source = "object App {\n  class Box { def ready: Boolean = true }\n  val box = new Box\n  val result = box ready\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "box ready"),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "ready"
        );
        assert_eq!(context.active_parameter, 0);
    }
}
