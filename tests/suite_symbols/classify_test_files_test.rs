use crate::common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

fn classify(root: &std::path::Path, paths: &[&str]) -> Value {
    call_search_tool_json(
        root,
        "classify_test_files",
        &json!({ "file_paths": paths }).to_string(),
    )
}

fn assert_classification(
    value: &Value,
    path: &str,
    expected_kind: &str,
    expected_contains_test_code: bool,
) {
    let classification = &value["classifications"][path];
    assert_eq!(classification["kind"], expected_kind, "{value}");
    assert_eq!(
        classification["contains_test_code"], expected_contains_test_code,
        "{value}"
    );
}

#[test]
fn classify_test_files_combines_path_conventions_with_semantic_detection() {
    let project = InlineTestProject::new()
        .file(
            "test/Core.Test/Auth/AutoFixture/Fixtures.cs",
            r#"
namespace Core.Test.Auth.AutoFixture
{
    public sealed class RegisterFinishRequestModelFixtures
    {
        public string Create() => "value";
    }
}
"#,
        )
        .file(
            "src/test/java/x/TestService.java",
            r#"
package x;

public class TestService {
    public String value() {
        return "ok";
    }
}
"#,
        )
        .file(
            "src/test/java/x/FooTest.java",
            r#"
package x;

import org.junit.jupiter.api.Test;

public class FooTest {
    @Test
    void works() {}
}
"#,
        )
        .file(
            "src/main/java/x/MainProject.java",
            r#"
package x;

import org.jetbrains.annotations.TestOnly;

public class MainProject {
    @TestOnly
    public String forTests(String value) {
        return value;
    }
}
"#,
        )
        .file(
            "src/lib.rs",
            r#"
pub fn answer() -> i32 {
    42
}

#[cfg(test)]
mod tests {
    #[test]
    fn answer_is_42() {
        assert_eq!(super::answer(), 42);
    }
}
"#,
        )
        .file(
            "pkg/foo_test.go",
            r#"
package pkg

import "testing"

func TestFoo(t *testing.T) {
}
"#,
        )
        .build();

    let value = classify(
        project.root(),
        &[
            "test/Core.Test/Auth/AutoFixture/Fixtures.cs",
            "src/test/java/x/TestService.java",
            "src/test/java/x/FooTest.java",
            "src/main/java/x/MainProject.java",
            "src/lib.rs",
            "pkg/foo_test.go",
        ],
    );

    assert_classification(
        &value,
        "test/Core.Test/Auth/AutoFixture/Fixtures.cs",
        "test_support",
        false,
    );
    assert_classification(
        &value,
        "src/test/java/x/TestService.java",
        "test_support",
        false,
    );
    assert_classification(&value, "src/test/java/x/FooTest.java", "test", true);
    assert_classification(
        &value,
        "src/main/java/x/MainProject.java",
        "production",
        false,
    );
    assert_classification(&value, "src/lib.rs", "ambiguous", true);
    assert_classification(&value, "pkg/foo_test.go", "test", true);
    assert_eq!(value["unresolved"], json!([]), "{value}");
}
