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
        Language::Cpp => has_cpp_test_filename(&lower),
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
                || has_cpp_test_filename(&lower)
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

/// C and C++ share one extension family, so their naming conventions are
/// decided together: the Google-style `_test`/`_unittest` suffixes and the
/// `test_` prefix on implementation files, plus the hyphenated `test-` prefix
/// that Dovecot, systemd and git use, which also names test-support headers
/// such as `test-lib.h`.
///
/// Every prefix rule carries its separator. That is what keeps coreutils'
/// `src/test.c` -- an implementation of the test(1) builtin -- production.
fn has_cpp_test_filename(lower: &str) -> bool {
    let Some((stem, extension)) = lower.rsplit_once('.') else {
        return false;
    };
    if !Language::Cpp.extensions().contains(&extension) {
        return false;
    }
    if stem.starts_with("test-") {
        return true;
    }
    matches!(extension, "c" | "cc" | "cpp")
        && (stem.starts_with("test_") || stem.ends_with("_test") || stem.ends_with("_unittest"))
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

    /// Issue #1575: `.c` maps to `Language::Cpp`, whose vocabulary only ever
    /// covered `.cc`/`.cpp`, so Dovecot-style `test-*.c` files were invisible to
    /// every test-classification surface.
    #[test]
    fn c_test_filename_conventions_are_recognized() {
        for path in [
            "src/lib/test-istream-concat.c",
            "src/anvil/test-connect-limit.c",
            "src/lib/test-lib.h",
            "test_foo.c",
            "foo_test.c",
            "foo_unittest.c",
        ] {
            assert!(has_test_filename_convention(path, Language::Cpp), "{path}");
        }
    }

    /// Near-misses: coreutils' `src/test.c` implements the test(1) builtin, and
    /// the remaining names merely contain "test" without a separator.
    #[test]
    fn c_production_filenames_are_not_test_files() {
        for path in [
            "src/test.c",
            "src/attest.c",
            "src/contest-limit.c",
            "src/latest.c",
        ] {
            assert!(!has_test_filename_convention(path, Language::Cpp), "{path}");
        }
    }

    #[test]
    fn kotlin_pascal_case_suffixes_are_recognized() {
        for path in ["SampleTest.kt", "SampleTests.kt", "SampleSpec.kt"] {
            assert!(
                has_test_filename_convention(path, Language::Kotlin),
                "{path}"
            );
        }
        assert!(!has_test_filename_convention("Sample.kt", Language::Kotlin));
        // Suffix-anchored, not substring: a production file merely containing
        // "Test" is not a test file.
        assert!(!has_test_filename_convention(
            "Testament.kt",
            Language::Kotlin
        ));
        // Case-sensitive, matching the other PascalCase JVM languages.
        assert!(!has_test_filename_convention(
            "sampletest.kt",
            Language::Kotlin
        ));
    }
}
