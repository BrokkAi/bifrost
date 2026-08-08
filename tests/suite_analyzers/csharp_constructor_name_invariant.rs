//! Issue #1800: a `constructor_declaration` whose name does not match its
//! enclosing type must not be minted as a member.
//!
//! An `#if !DEBUG` region between `try {}` and its `catch` clauses breaks the
//! tree-sitter parse chain: the trailing catch clauses re-parse at class-body
//! level as `constructor_declaration` nodes named `catch`, which used to reach
//! the index as real `Function` members (`search_symbols` reported two
//! `catch` functions on `MudBlazor.IJSRuntimeExtensions`).

use crate::common::InlineTestProject;
use brokk_bifrost::{CSharpAnalyzer, CodeUnitIndex, Language};

/// The w1_mud shape, reduced. Reproducing the misparse needs all three of:
/// an `#if !DEBUG` region between the `try` block and the rest of the catch
/// chain, a `catch (...) when (...)` filter clause after it, and further plain
/// catch clauses -- dropping the `when` filter, or leaving only one clause
/// after the guarded region, makes tree-sitter recover cleanly instead.
const PREPROC_GUARDED_CATCH: &str = r#"
namespace MudBlazor
{
    public static class IJSRuntimeExtensions
    {
        public static bool InvokeVoidAsyncWithErrorHandling(IJSRuntime jsRuntime)
        {
            try
            {
                return true;
            }
#if !DEBUG
            catch (JSException)
            {
                return false;
            }
#endif
            catch (InvalidOperationException) when (IsUnsupportedJavaScriptRuntime(jsRuntime))
            {
                return false;
            }
            catch (JSDisconnectedException)
            {
                return false;
            }
            catch (TaskCanceledException)
            {
                return false;
            }
#if !DEBUG
            catch (ObjectDisposedException)
            {
                return false;
            }
#endif
        }
    }
}
"#;

/// One entry per minted `CodeUnit`, so overload-distinct units with the same
/// fully qualified name stay visible instead of collapsing into a set.
fn declared_fq_names(source: &str) -> Vec<String> {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Input.cs", source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    analyzer
        .declarations(&project.file("Input.cs"))
        .iter()
        .map(|unit| unit.fq_name().to_string())
        .collect()
}

#[test]
fn preproc_guarded_catch_clauses_mint_no_members() {
    let fqs = declared_fq_names(PREPROC_GUARDED_CATCH);

    let bogus = fqs
        .iter()
        .filter(|fq| fq.rsplit('.').next() == Some("catch"))
        .collect::<Vec<_>>();
    assert!(
        bogus.is_empty(),
        "catch clauses re-parsed as constructors must not be minted: {bogus:#?} in {fqs:#?}"
    );

    // The enclosing declarations still index, so the assertion above is not
    // vacuously true because extraction gave up on the file.
    assert!(
        fqs.iter().any(|fq| fq == "MudBlazor.IJSRuntimeExtensions"),
        "enclosing class must still index: {fqs:#?}"
    );
}

#[test]
fn real_constructors_still_mint_in_nested_partial_and_generic_types() {
    let fqs = declared_fq_names(
        r#"
namespace Sample
{
    public partial class Owner
    {
        public Owner() { }

        public class Inner
        {
            public Inner(int value) { }
        }
    }

    public partial class Owner
    {
        public Owner(int value) { }
    }

    public class Box<T>
    {
        public Box(T value) { }
    }
}
"#,
    );

    for expected in [
        "Sample.Owner.Owner",
        "Sample.Owner$Inner.Inner",
        "Sample.Box`1.Box",
    ] {
        assert!(
            fqs.iter().any(|fq| fq == expected),
            "missing constructor {expected}: {fqs:#?}"
        );
    }

    // Both halves of the partial class contribute their own constructor.
    assert_eq!(
        fqs.iter().filter(|fq| *fq == "Sample.Owner.Owner").count(),
        2,
        "both partial-class constructors must index: {fqs:#?}"
    );
}
