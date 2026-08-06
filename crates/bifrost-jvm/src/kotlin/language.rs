use tree_sitter_language::LanguageFn;

// SAFETY: build.rs compiles vendor/tree-sitter-kotlin/src with
// `-Dtree_sitter_kotlin=brokk_bifrost_tree_sitter_kotlin`, so the symbol linked here is
// the grammar's own generated entry point under a private name. Its C
// signature is `const TSLanguage *(void)`; the rename changes the symbol only,
// never the ABI, so this declaration matches the definition.
unsafe extern "C" {
    fn brokk_bifrost_tree_sitter_kotlin() -> *const ();
}

/// The pinned, vendored Tree-sitter Kotlin grammar, registered as the parser
/// for [`brokk_bifrost_core::analyzer::Language::Kotlin`] (issue #1236). The
/// tests below validate the native build and parser contract independently of
/// the analyzer integration.
// SAFETY: `brokk_bifrost_tree_sitter_kotlin` is tree-sitter's generated `tree_sitter_kotlin`
// under the private name (see the rename above). It returns a pointer to a
// `TSLanguage` in static storage that outlives the process, which is what
// `LanguageFn::from_raw` requires of the function it wraps.
pub const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(brokk_bifrost_tree_sitter_kotlin) };

#[cfg(test)]
mod tests {
    use super::LANGUAGE;
    use tree_sitter::{InputEdit, Node, Parser, Point, Tree};

    fn parser() -> Parser {
        let mut parser = Parser::new();
        parser
            .set_language(&LANGUAGE.into())
            .expect("Tree-sitter 0.25 must load the pinned Kotlin grammar");
        parser
    }

    fn parse(parser: &mut Parser, source: &str, old_tree: Option<&Tree>) -> Tree {
        parser
            .parse(source.as_bytes(), old_tree)
            .expect("Kotlin parser must return a tree")
    }

    fn point_for_byte(source: &str, byte: usize) -> Point {
        let prefix = &source[..byte];
        let row = prefix.bytes().filter(|byte| *byte == b'\n').count();
        let column = prefix
            .rsplit_once('\n')
            .map_or(prefix.len(), |(_, tail)| tail.len());
        Point::new(row, column)
    }

    fn find_named<'tree>(root: Node<'tree>, source: &str, kind: &str, text: &str) -> bool {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.is_named()
                && node.kind() == kind
                && node
                    .utf8_text(source.as_bytes())
                    .is_ok_and(|node_text| node_text.contains(text))
            {
                return true;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        false
    }

    fn assert_clean(label: &str, source: &str) -> Tree {
        let tree = parse(&mut parser(), source, None);
        assert!(
            !tree.root_node().has_error(),
            "{label} must parse without recovery:\n{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    #[test]
    fn kotlin_source_and_script_parse_without_recovery() {
        let kt = r#"package sample

sealed interface Result<out T> {
    data class Ok<T>(val value: T) : Result<T>
    data class Err(val reason: String) : Result<Nothing>
}

context(String)
fun <T : Any> T.render(): String = buildString {
    append(this@render)
    append(" from ")
    append(this@String)
}
"#;
        let kts = r#"plugins {
    kotlin("jvm") version "2.2.0"
}

dependencies {
    implementation(kotlin("stdlib"))
}

val greeting by extra("hello")
tasks.register("printGreeting") {
    doLast { println("$greeting from ${project.name}") }
}
"#;

        assert_clean(".kt source", kt);
        assert_clean(".kts script", kts);
    }

    #[test]
    fn malformed_source_recovers_trailing_declaration() {
        let source = r#"package sample

fun broken(value: Int): Int = when (value) {
    0 ->
    else -> value
}

fun recovered(): Int = 7
"#;
        let tree = parse(&mut parser(), source, None);
        assert!(
            tree.root_node().has_error(),
            "fixture must exercise recovery"
        );
        assert!(
            find_named(
                tree.root_node(),
                source,
                "function_declaration",
                "recovered"
            ),
            "recovery must retain the valid trailing function:\n{}",
            tree.root_node().to_sexp()
        );
    }

    #[test]
    fn incremental_reparse_matches_a_cold_parse() {
        let before = r#"package sample

object App {
    fun greet(name: String): String = "Hello, $name"
    val answer = 41
}
"#;
        let old_text = "val answer = 41";
        let new_text = "fun answer(): Int = 42";
        let after = before.replacen(old_text, new_text, 1);
        let start_byte = before.find(old_text).expect("edited declaration");
        let old_end_byte = start_byte + old_text.len();
        let new_end_byte = start_byte + new_text.len();

        let mut parser = parser();
        let mut old_tree = parse(&mut parser, before, None);
        old_tree.edit(&InputEdit {
            start_byte,
            old_end_byte,
            new_end_byte,
            start_position: point_for_byte(before, start_byte),
            old_end_position: point_for_byte(before, old_end_byte),
            new_end_position: point_for_byte(&after, new_end_byte),
        });

        let incremental = parse(&mut parser, &after, Some(&old_tree));
        let cold = parse(&mut parser, &after, None);
        assert!(!incremental.root_node().has_error());
        assert_eq!(
            incremental.root_node().to_sexp(),
            cold.root_node().to_sexp(),
            "incremental and cold parses must have identical structure"
        );
        let changed = old_tree.changed_ranges(&incremental).collect::<Vec<_>>();
        assert!(
            !changed.is_empty(),
            "structural edit must report a changed range"
        );
        assert!(
            changed.iter().all(|range| range.end_byte <= after.len()),
            "changed ranges must stay within the edited document: {changed:?}"
        );
    }
}
