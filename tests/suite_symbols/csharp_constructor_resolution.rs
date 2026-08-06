use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::Language;
use serde_json::{Value, json};

fn lookup(root: &std::path::Path, path: &str, source: &str, start: usize) -> Value {
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = json!({
        "references": [{"path": path, "line": line, "column": column}],
    })
    .to_string();
    call_search_tool_json(root, "get_definitions_by_location", &args)
}

#[test]
fn csharp_generic_implicit_constructor_does_not_fall_back_to_nongeneric_constructor() {
    let source = r#"namespace Demo {
public class Item {
    public Item(System.Func<object> factory) {}
}
public class Item<TKey, TValue> {}
public class Consumer {
    public object Run() => new Item<string, string>();
}
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Types.cs", source)
        .build();
    let start = source
        .find("Item<string, string>")
        .expect("generic construction");
    let value = lookup(project.root(), "Types.cs", source, start);

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Demo.Item`2",
        "generic construction must resolve its exact owner type: {value}"
    );
    assert_ne!(
        result["definitions"][0]["fqn"], "Demo.Item.Item",
        "a constructor from the nongeneric owner must not be selected: {value}"
    );
}
