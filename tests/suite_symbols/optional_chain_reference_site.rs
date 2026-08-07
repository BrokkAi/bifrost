//! Reference-site expansion across optional-chaining operators (#1781).
//!
//! `expand_reference_expression` used to assemble the reference expression from
//! raw bytes, so `?` stopped the leftward walk and `al.box?.text` reported the
//! site text `.text` with the receiver dropped. The site text must name the
//! same dotted chain that the non-optional spelling produces.

use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::Language;
use serde_json::{Value, json};

fn site_target(root: &std::path::Path, path: &str, source: &str, start: usize) -> String {
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = json!({"references": [{"path": path, "line": line, "column": column}]}).to_string();
    let value: Value = call_search_tool_json(root, "get_definitions_by_location", &args);
    value["results"][0]["reference"]["target"]
        .as_str()
        .unwrap_or_else(|| panic!("reference site for byte {start}: {value}"))
        .to_string()
}

#[test]
fn javascript_optional_chain_reference_site_keeps_the_whole_receiver_chain() {
    let source = r#"export function render(al, plain, bare) {
  const a = al.box?.text;
  const b = al?.box?.text;
  const c = plain.box.text;
  const d = bare;
  return [a, b, c, d];
}
"#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("chain.js", source)
        .build();
    let root = project.root();

    let dotted = site_target(
        root,
        "chain.js",
        source,
        source.find("text;\n  const d").expect("plain chain leaf"),
    );
    assert_eq!(dotted, "plain.box.text");

    let single_optional = site_target(
        root,
        "chain.js",
        source,
        source
            .find("text;\n  const b")
            .expect("single optional leaf"),
    );
    assert_eq!(
        single_optional, "al.box.text",
        "`al.box?.text` must keep its receiver chain"
    );

    let double_optional = site_target(
        root,
        "chain.js",
        source,
        source
            .find("text;\n  const c")
            .expect("double optional leaf"),
    );
    assert_eq!(
        double_optional, "al.box.text",
        "`al?.box?.text` must keep its receiver chain"
    );

    let non_chain = site_target(
        root,
        "chain.js",
        source,
        source
            .find("bare;\n  return")
            .expect("non-chain identifier"),
    );
    assert_eq!(non_chain, "bare");
}

#[test]
fn typescript_optional_chain_reference_site_keeps_the_whole_receiver_chain() {
    let source = r#"export function render(al: any): unknown {
  return al.box?.text;
}
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("chain.ts", source)
        .build();

    assert_eq!(
        site_target(
            project.root(),
            "chain.ts",
            source,
            source.find("text;").expect("optional chain leaf"),
        ),
        "al.box.text"
    );
}

#[test]
fn python_attribute_chain_reference_site_is_unchanged() {
    let source = r#"def render(al):
    return al.box.text
"#;
    let project = InlineTestProject::with_language(Language::Python)
        .file("chain.py", source)
        .build();

    assert_eq!(
        site_target(
            project.root(),
            "chain.py",
            source,
            source.find("text").expect("attribute leaf"),
        ),
        "al.box.text"
    );
}

#[test]
fn kotlin_safe_call_reference_site_keeps_the_whole_receiver_chain() {
    let source = r#"package app

class Box { val text: String = "" }
class Holder { val box: Box = Box() }

fun render(al: Holder): String? {
    return al.box?.text
}
"#;
    let project = InlineTestProject::with_language(Language::Kotlin)
        .file("Chain.kt", source)
        .build();

    assert_eq!(
        site_target(
            project.root(),
            "Chain.kt",
            source,
            source.rfind("text").expect("safe-call leaf"),
        ),
        "al.box.text"
    );
}

#[test]
fn csharp_null_conditional_reference_site_keeps_the_whole_receiver_chain() {
    let source = r#"namespace App {
    public class Box { public string Text = ""; }
    public class Holder { public Box Box = new Box(); }
    public class Renderer {
        public string Render(Holder al) {
            return al.Box?.Text;
        }
    }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Chain.cs", source)
        .build();

    assert_eq!(
        site_target(
            project.root(),
            "Chain.cs",
            source,
            source.find("Text;").expect("null-conditional leaf"),
        ),
        "al.Box.Text"
    );
}
