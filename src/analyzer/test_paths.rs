use crate::analyzer::Language;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTestVerdict {
    TestRoot,
    ProductionRoot,
    Ambiguous,
}

/// Directory-convention verdict for a workspace-relative path.
pub fn path_test_verdict(path: &str) -> PathTestVerdict {
    let normalized = normalize_path(path);
    let segments: Vec<&str> = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    if contains_jvm_src_pair(&segments, "test") || has_test_segment(&segments) {
        return PathTestVerdict::TestRoot;
    }

    if has_csharp_test_project_segment(&segments) {
        return PathTestVerdict::TestRoot;
    }

    if contains_jvm_src_pair(&segments, "main") {
        return PathTestVerdict::ProductionRoot;
    }

    PathTestVerdict::Ambiguous
}

/// Per-language filename-convention check on the basename.
pub fn has_test_filename_convention(path: &str, language: Language) -> bool {
    let normalized = normalize_path(path);
    let file_name = Path::new(&normalized)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let lower = file_name.to_ascii_lowercase();

    match language {
        Language::Go => lower.ends_with("_test.go"),
        Language::Python => {
            lower == "conftest.py"
                || (lower.starts_with("test_") && lower.ends_with(".py"))
                || lower.ends_with("_test.py")
        }
        Language::JavaScript | Language::TypeScript => has_js_ts_test_filename(&lower),
        Language::Java => {
            file_name.ends_with("Test.java")
                || file_name.ends_with("Tests.java")
                || file_name.ends_with("TestCase.java")
                || file_name.ends_with("IT.java")
        }
        Language::Scala => {
            file_name.ends_with("Test.scala")
                || file_name.ends_with("Spec.scala")
                || file_name.ends_with("Suite.scala")
        }
        Language::Kotlin => {
            file_name.ends_with("Test.kt")
                || file_name.ends_with("Tests.kt")
                || file_name.ends_with("Spec.kt")
        }
        Language::Ruby => {
            lower == "spec_helper.rb"
                || lower == "test_helper.rb"
                || lower.ends_with("_spec.rb")
                || lower.ends_with("_test.rb")
        }
        Language::Php => file_name.ends_with("Test.php"),
        Language::CSharp => file_name.ends_with("Test.cs") || file_name.ends_with("Tests.cs"),
        Language::Cpp => {
            (lower.ends_with("_test.cc")
                || lower.ends_with("_unittest.cc")
                || lower.starts_with("test_") && lower.ends_with(".cc"))
                || (lower.ends_with("_test.cpp")
                    || lower.ends_with("_unittest.cpp")
                    || lower.starts_with("test_") && lower.ends_with(".cpp"))
        }
        Language::Rust => false,
        Language::None => {
            lower.ends_with("_test.go")
                || lower == "conftest.py"
                || lower.starts_with("test_")
                || lower.ends_with("_test.py")
                || has_js_ts_test_filename(&lower)
                || file_name.ends_with("Test.java")
                || file_name.ends_with("Tests.java")
                || file_name.ends_with("TestCase.java")
                || file_name.ends_with("IT.java")
                || file_name.ends_with("Test.scala")
                || file_name.ends_with("Spec.scala")
                || file_name.ends_with("Suite.scala")
                || file_name.ends_with("Test.kt")
                || file_name.ends_with("Tests.kt")
                || file_name.ends_with("Spec.kt")
                || file_name.ends_with("Test.cs")
                || file_name.ends_with("Tests.cs")
                || file_name.ends_with("Test.php")
                || lower.ends_with("_unittest.cc")
                || lower.ends_with("_unittest.cpp")
                || lower == "spec_helper.rb"
                || lower == "test_helper.rb"
        }
    }
}

/// Test-root directory verdict OR filename convention.
pub fn is_test_like_path(path: &str, language: Language) -> bool {
    path_test_verdict(path) == PathTestVerdict::TestRoot
        || has_test_filename_convention(path, language)
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn has_test_segment(segments: &[&str]) -> bool {
    segments.iter().any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "test" | "tests" | "__tests__" | "spec" | "specs" | "testdata"
        )
    })
}

fn has_csharp_test_project_segment(segments: &[&str]) -> bool {
    segments.iter().any(|segment| {
        let lower = segment.to_ascii_lowercase();
        lower.ends_with(".test")
            || lower.ends_with(".tests")
            || lower.ends_with(".unittests")
            || lower.ends_with(".integrationtests")
    })
}

fn contains_jvm_src_pair(segments: &[&str], second: &str) -> bool {
    segments
        .windows(2)
        .any(|pair| pair[0] == "src" && pair[1] == second)
}

fn has_js_ts_test_filename(lower: &str) -> bool {
    lower.contains(".test.") || lower.contains(".spec.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csharp_test_project_under_test_root_is_test_root() {
        assert_eq!(
            PathTestVerdict::TestRoot,
            path_test_verdict("test/Core.Test/Auth/AutoFixture/Fixture.cs")
        );
    }

    #[test]
    fn jvm_src_test_is_test_root() {
        assert_eq!(
            PathTestVerdict::TestRoot,
            path_test_verdict("app/src/test/java/ai/brokk/testutil/TestService.java")
        );
    }

    #[test]
    fn jvm_src_main_is_production_root() {
        assert_eq!(
            PathTestVerdict::ProductionRoot,
            path_test_verdict("app/src/main/java/ai/brokk/project/MainProject.java")
        );
    }

    #[test]
    fn ordinary_src_file_is_ambiguous() {
        assert_eq!(PathTestVerdict::Ambiguous, path_test_verdict("src/lib.rs"));
    }

    #[test]
    fn go_test_file_has_filename_convention() {
        assert!(has_test_filename_convention(
            "pkg/foo_test.go",
            Language::Go
        ));
    }

    #[test]
    fn windows_style_src_test_is_test_root() {
        assert_eq!(
            PathTestVerdict::TestRoot,
            path_test_verdict("app\\src\\test\\Foo.java")
        );
    }

    #[test]
    fn pascal_case_java_suffixes_are_case_sensitive() {
        assert!(!has_test_filename_convention("Audit.java", Language::Java));
        assert!(!has_test_filename_convention("Latest.java", Language::Java));
        assert!(has_test_filename_convention("FooTest.java", Language::Java));
        assert!(has_test_filename_convention("FooIT.java", Language::Java));
    }

    #[test]
    fn pascal_case_csharp_suffixes_are_case_sensitive() {
        assert!(!has_test_filename_convention(
            "Contest.cs",
            Language::CSharp
        ));
    }

    #[test]
    fn pascal_case_scala_suffixes_are_case_sensitive() {
        assert!(has_test_filename_convention(
            "FooSpec.scala",
            Language::Scala
        ));
    }
}
