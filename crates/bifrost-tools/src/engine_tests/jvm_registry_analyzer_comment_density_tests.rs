#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_analysis::analyzer::comment_density::assert_projection_matches_direct;

    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("#2592: Scala synthetic constructor children stole class comment attribution")]
    fn scala_projection_filters_synthetic_children_for_attribution() {
        let stats = assert_projection_matches_direct(
            "Elem.scala",
            "/** Element header. */\n\
             class Elem(val name: String) {\n\
               // class implementation note\n\
               val label: String = name\n\
             }\n",
            "Elem",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (0, 0)
        );
        assert!(stats.span_lines > 0);
    }
    #[test]
    #[hardwon("#2592: Kotlin synthetic constructor children stole class comment attribution")]
    fn kotlin_projection_filters_synthetic_children_for_attribution() {
        let stats = assert_projection_matches_direct(
            "ResultRow.kt",
            "/** Row header. */\n\
             class ResultRow(private val values: List<Any>) {\n\
               // row implementation note\n\
               val size: Int = values.size\n\
             }\n",
            "ResultRow",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (1, 0)
        );
        assert!(stats.span_lines > 0);
    }
    #[test]
    #[hardwon(
        "#3357: overlapping Kotlin constructor ranges lost the secondary body comment attribution"
    )]
    fn kotlin_primary_constructor_overlap_does_not_capture_secondary_body() {
        let stats = assert_projection_matches_direct(
            "Widget.kt",
            "/** Widget header. */\n\
             class Widget(\n\
               val name: String\n\
             ) {\n\
               constructor() : this(\"default\") {\n\
                 // secondary body note\n\
                 check(name.isNotEmpty())\n\
               }\n\
             }\n",
            "Widget",
        );
        // The primary constructor's overlapping range is excluded from the
        // ownership contest, so its comment belongs to Widget. A secondary
        // constructor still owns its body comment, rather than dropping it
        // into the enclosing class after a blanket constructor exclusion.
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (1, 0)
        );
        assert_eq!(
            (
                stats.rolled_up_header_comment_lines,
                stats.rolled_up_inline_comment_lines,
            ),
            (1, 1)
        );
    }
    #[test]
    #[hardwon(
        "#3357: constructor property documentation was lost from its own and enclosing comment rollups"
    )]
    fn kotlin_constructor_property_keeps_its_attached_documentation() {
        let source = "/** Class documentation. */\nclass Widget(\n  /** Property documentation. */\n  val name: String\n)\n";
        let property = assert_projection_matches_direct("Widget.kt", source, "Widget.name");
        assert_eq!(
            (property.header_comment_lines, property.inline_comment_lines),
            (1, 0)
        );
        let class = assert_projection_matches_direct("Widget.kt", source, "Widget");
        assert_eq!(
            (class.header_comment_lines, class.inline_comment_lines),
            (1, 0)
        );
        assert_eq!(class.rolled_up_header_comment_lines, 2);
    }
}
