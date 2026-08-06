//! #1730: C# answers import reachability authoritatively, so candidate
//! discovery can reject a file without materializing every declaration it
//! imports.
//!
//! Each of the ten completeness cases from the issue gets a positive fixture
//! (the reference is possible, so the verdict must not be `DoesNotReach`) and a
//! realistic near miss (the same shape with one detail changed, where the
//! verdict must be `DoesNotReach`). A near miss that merely deleted the source
//! file would prove nothing.

use crate::common::csharp_analyzer_with_files;
use brokk_bifrost::{ImportAnalysisProvider, ImportReachability};

fn verdict(files: &[(&str, &str)], source: &str, target: &str) -> ImportReachability {
    let (project, analyzer) = csharp_analyzer_with_files(files);
    let source_file = project.file(source);
    let target_file = project.file(target);
    let imports = analyzer.import_info_of(&source_file);
    analyzer.import_reachability(&source_file, &imports, &target_file)
}

/// A reachable pair may answer `Reaches` or `Unknown` -- both keep the
/// candidate -- but never `DoesNotReach`, which would drop a real usage.
fn assert_not_proven_unreachable(files: &[(&str, &str)], source: &str, target: &str) {
    let verdict = verdict(files, source, target);
    assert_ne!(
        verdict,
        ImportReachability::DoesNotReach,
        "{source} can reference {target}, so it must not be proved unreachable"
    );
}

fn assert_unreachable(files: &[(&str, &str)], source: &str, target: &str) {
    assert_eq!(
        verdict(files, source, target),
        ImportReachability::DoesNotReach,
        "{source} cannot reference {target}"
    );
}

fn assert_reaches(files: &[(&str, &str)], source: &str, target: &str) {
    assert_eq!(
        verdict(files, source, target),
        ImportReachability::Reaches,
        "{source} references {target}"
    );
}

// --- case 1: plain `using N;` overlap -------------------------------------

const WIDGET_LIB: &str = r#"
namespace Lib
{
    public class Widget { }
}
"#;

#[test]
fn plain_using_of_the_targets_namespace_reaches() {
    assert_reaches(
        &[
            ("Lib.cs", WIDGET_LIB),
            (
                "App.cs",
                r#"
using Lib;

namespace App
{
    public class Consumer { private Widget field; }
}
"#,
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

#[test]
fn plain_using_of_an_unrelated_namespace_is_unreachable() {
    assert_unreachable(
        &[
            ("Lib.cs", WIDGET_LIB),
            ("Other.cs", "namespace Other { public class Gadget { } }"),
            (
                "App.cs",
                r#"
using Other;

namespace App
{
    public class Consumer { private Gadget field; }
}
"#,
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

// --- case 2: same namespace with no `using` at all -------------------------

#[test]
fn same_namespace_with_no_using_reaches() {
    assert_reaches(
        &[
            ("Widget.cs", "namespace Shared { public class Widget { } }"),
            (
                "Consumer.cs",
                "namespace Shared { public class Consumer { private Widget field; } }",
            ),
        ],
        "Consumer.cs",
        "Widget.cs",
    );
}

#[test]
fn different_namespace_with_no_using_is_unreachable() {
    assert_unreachable(
        &[
            ("Widget.cs", "namespace Shared { public class Widget { } }"),
            (
                "Consumer.cs",
                "namespace Apart { public class Consumer { private int field; } }",
            ),
        ],
        "Consumer.cs",
        "Widget.cs",
    );
}

/// The proof reads every namespace the source declares into, not just the
/// first one. `namespace_of_file` names only the first (#1726), so a file that
/// opens `Zeta` before the shared namespace would otherwise look unreachable.
#[test]
fn second_namespace_of_a_multi_namespace_source_is_not_proven_unreachable() {
    assert_not_proven_unreachable(
        &[
            (
                "Widget.cs",
                r#"
namespace Shared
{
    public static class Widget
    {
        public static void Run(this string value) { }
    }
}
"#,
            ),
            (
                "Consumer.cs",
                r#"
namespace Zeta
{
    public class Unrelated { }
}

namespace Shared
{
    public class Consumer
    {
        public void Use(string value) { value.Run(); }
    }
}
"#,
            ),
        ],
        "Consumer.cs",
        "Widget.cs",
    );
}

// --- case 3: nested-namespace implicit visibility --------------------------

/// `namespace A.B` sees `A.*` with no `using`. The reference here is an
/// extension-method call, which never spells the declaring type, so only the
/// namespace rule can decide it.
const NESTED_EXTENSION_HOST: &str = r#"
namespace A
{
    public static class Ext
    {
        public static void Run(this string value) { }
    }
}
"#;

#[test]
fn nested_namespace_sees_its_parent_and_is_not_proven_unreachable() {
    assert_not_proven_unreachable(
        &[
            ("Ext.cs", NESTED_EXTENSION_HOST),
            (
                "Inner.cs",
                r#"
namespace A.B
{
    public class Inner
    {
        public void Use(string value) { value.Run(); }
    }
}
"#,
            ),
        ],
        "Inner.cs",
        "Ext.cs",
    );
}

#[test]
fn sibling_namespace_does_not_see_the_extension_host() {
    assert_unreachable(
        &[
            ("Ext.cs", NESTED_EXTENSION_HOST),
            (
                "Inner.cs",
                r#"
namespace X.Y
{
    public class Inner
    {
        public void Use(string value) { value.Run(); }
    }
}
"#,
            ),
        ],
        "Inner.cs",
        "Ext.cs",
    );
}

// --- case 4: fully qualified references ------------------------------------

const QUALIFIED_LIB: &str = r#"
namespace A.B
{
    public class Widget { }
}
"#;

#[test]
fn fully_qualified_reference_with_no_using_reaches() {
    assert_reaches(
        &[
            ("Lib.cs", QUALIFIED_LIB),
            (
                "App.cs",
                "namespace App { public class Consumer { private A.B.Widget field; } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

#[test]
fn fully_qualified_reference_to_a_different_type_is_unreachable() {
    assert_unreachable(
        &[
            ("Lib.cs", QUALIFIED_LIB),
            ("Gadget.cs", "namespace A.B { public class Gadget { } }"),
            (
                "App.cs",
                "namespace App { public class Consumer { private A.B.Gadget field; } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

// --- case 5: `global::` qualified references -------------------------------

#[test]
fn global_qualified_reference_reaches() {
    assert_reaches(
        &[
            ("Lib.cs", QUALIFIED_LIB),
            (
                "App.cs",
                "namespace App { public class Consumer { private global::A.B.Widget field; } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

#[test]
fn global_qualified_reference_to_a_different_type_is_unreachable() {
    assert_unreachable(
        &[
            ("Lib.cs", QUALIFIED_LIB),
            ("Gadget.cs", "namespace A.B { public class Gadget { } }"),
            (
                "App.cs",
                "namespace App { public class Consumer { private global::A.B.Gadget field; } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

// --- case 6: using aliases and namespace aliases ---------------------------

#[test]
fn using_alias_to_the_target_type_reaches() {
    assert_reaches(
        &[
            ("Lib.cs", QUALIFIED_LIB),
            (
                "App.cs",
                r#"
using W = A.B.Widget;

namespace App
{
    public class Consumer { private W field; }
}
"#,
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

/// A namespace alias brings the whole namespace into play even though the
/// spelling at the use site is the alias, so the verdict must stay open.
#[test]
fn namespace_alias_of_the_targets_namespace_is_not_proven_unreachable() {
    assert_not_proven_unreachable(
        &[
            ("Ext.cs", NESTED_EXTENSION_HOST),
            (
                "App.cs",
                r#"
using Shorthand = A;

namespace App
{
    public class Consumer
    {
        public void Use(string value) { value.Run(); }
    }
}
"#,
            ),
        ],
        "App.cs",
        "Ext.cs",
    );
}

#[test]
fn alias_to_an_unrelated_namespace_is_unreachable() {
    assert_unreachable(
        &[
            ("Ext.cs", NESTED_EXTENSION_HOST),
            ("Other.cs", "namespace Other { public class Gadget { } }"),
            (
                "App.cs",
                r#"
using Shorthand = Other;

namespace App
{
    public class Consumer
    {
        public void Use(string value) { value.Run(); }
    }
}
"#,
            ),
        ],
        "App.cs",
        "Ext.cs",
    );
}

// --- case 7: `global using`, which lives in other files --------------------

#[test]
fn global_using_from_another_file_is_not_proven_unreachable() {
    assert_not_proven_unreachable(
        &[
            ("GlobalUsings.cs", "global using Lib;\n"),
            (
                "Lib.cs",
                r#"
namespace Lib
{
    public static class Ext
    {
        public static void Run(this string value) { }
    }
}
"#,
            ),
            (
                "App.cs",
                r#"
namespace App
{
    public class Consumer
    {
        public void Use(string value) { value.Run(); }
    }
}
"#,
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

#[test]
fn global_using_of_an_unrelated_namespace_is_unreachable() {
    assert_unreachable(
        &[
            ("GlobalUsings.cs", "global using Other;\n"),
            ("Other.cs", "namespace Other { public class Gadget { } }"),
            (
                "Lib.cs",
                r#"
namespace Lib
{
    public static class Ext
    {
        public static void Run(this string value) { }
    }
}
"#,
            ),
            (
                "App.cs",
                r#"
namespace App
{
    public class Consumer
    {
        public void Use(string value) { value.Run(); }
    }
}
"#,
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

/// `global using static` also lives in another file, and its namespace has to
/// come from the workspace-level cell rather than from per-file import facts.
#[test]
fn global_using_static_from_another_file_is_not_proven_unreachable() {
    assert_not_proven_unreachable(
        &[
            ("GlobalUsings.cs", "global using static Lib.Helpers;\n"),
            (
                "Lib.cs",
                "namespace Lib { public static class Helpers { public static void Run() { } } }",
            ),
            (
                "App.cs",
                "namespace App { public class Consumer { public void Use() { Run(); } } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

#[test]
fn global_using_static_of_an_unrelated_type_is_unreachable() {
    assert_unreachable(
        &[
            ("GlobalUsings.cs", "global using static Other.Helpers;\n"),
            (
                "Other.cs",
                "namespace Other { public static class Helpers { public static void Run() { } } }",
            ),
            (
                "Lib.cs",
                "namespace Lib { public static class Tools { public static void Work() { } } }",
            ),
            (
                "App.cs",
                "namespace App { public class Consumer { public void Use() { Run(); } } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

// --- case 8: `using static` ------------------------------------------------

#[test]
fn using_static_of_the_target_type_reaches() {
    assert_reaches(
        &[
            (
                "Lib.cs",
                "namespace Lib { public static class Helpers { public static void Run() { } } }",
            ),
            (
                "App.cs",
                r#"
using static Lib.Helpers;

namespace App
{
    public class Consumer { public void Use() { Run(); } }
}
"#,
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

#[test]
fn using_static_of_an_unrelated_type_is_unreachable() {
    assert_unreachable(
        &[
            (
                "Other.cs",
                "namespace Other { public static class Helpers { public static void Run() { } } }",
            ),
            (
                "Lib.cs",
                "namespace Lib { public static class Tools { public static void Work() { } } }",
            ),
            (
                "App.cs",
                r#"
using static Other.Helpers;

namespace App
{
    public class Consumer { public void Use() { Run(); } }
}
"#,
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

// --- case 9: generic arity backtick spellings ------------------------------

const GENERIC_LIB: &str = r#"
namespace Lib
{
    public class Box<TFirst, TSecond> { }
}
"#;

/// A different arity is not a proof of difference: the proof compares names
/// with the arity stripped, so a `Box<T>` reference against a ``Box`2``
/// declaration stays undecided rather than becoming a wrong `DoesNotReach`.
#[test]
fn mismatched_generic_arity_is_not_proven_unreachable() {
    assert_not_proven_unreachable(
        &[
            ("Lib.cs", GENERIC_LIB),
            (
                "App.cs",
                "namespace App { public class Consumer { private Box<int> field; } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

/// The same fixture with only the referenced name changed: `Crate` and `Box`
/// differ once the arity is stripped from both, and the namespaces are
/// disjoint, so nothing can bind.
#[test]
fn generic_reference_to_a_different_name_is_unreachable() {
    assert_unreachable(
        &[
            ("Lib.cs", GENERIC_LIB),
            ("Crate.cs", "namespace Other { public class Crate<T> { } }"),
            (
                "App.cs",
                "namespace App { public class Consumer { private Crate<int> field; } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

// --- case 10: partial classes ----------------------------------------------

/// Both parts declare into the same namespace, so the other part's members are
/// visible without any spelling of the type name.
#[test]
fn partial_class_parts_in_one_namespace_reach_each_other() {
    assert_reaches(
        &[
            (
                "Widget.Part1.cs",
                "namespace Shared { public partial class Widget { public void First() { } } }",
            ),
            (
                "Widget.Part2.cs",
                "namespace Shared { public partial class Widget { public void Second() { First(); } } }",
            ),
        ],
        "Widget.Part2.cs",
        "Widget.Part1.cs",
    );
}

/// Same class name, different namespaces: two unrelated types, not two parts
/// of one.
#[test]
fn same_named_partial_classes_in_different_namespaces_are_unreachable() {
    assert_unreachable(
        &[
            (
                "Widget.Left.cs",
                "namespace Left { public partial class Widget { public void First() { } } }",
            ),
            (
                "Widget.Right.cs",
                "namespace Right { public partial class Widget { public void Second() { } } }",
            ),
        ],
        "Widget.Right.cs",
        "Widget.Left.cs",
    );
}

// --- nested types ----------------------------------------------------------

/// A nested type is spelled `Outer.Inner`, whose last segment is the nested
/// name rather than the outer one, so both have to count as names of the
/// target.
#[test]
fn nested_type_reference_is_not_proven_unreachable() {
    assert_not_proven_unreachable(
        &[
            (
                "Lib.cs",
                "namespace Lib { public class Outer { public class Inner { } } }",
            ),
            (
                "App.cs",
                "namespace App { public class Consumer { private Lib.Outer.Inner field; } }",
            ),
        ],
        "App.cs",
        "Lib.cs",
    );
}

// --- the verdict must survive the bool spelling ----------------------------

/// `could_import_file` is defined over the verdict, so a `Reaches` must still
/// read as `true` and everything else as `false`.
#[test]
fn could_import_file_agrees_with_the_verdict() {
    let files = [
        ("Lib.cs", WIDGET_LIB),
        (
            "App.cs",
            "using Lib;\nnamespace App { public class Consumer { private Widget field; } }",
        ),
        (
            "Apart.cs",
            "namespace Apart { public class Other { private int field; } }",
        ),
    ];
    let (project, analyzer) = csharp_analyzer_with_files(&files);
    let lib = project.file("Lib.cs");

    for (path, expected) in [("App.cs", true), ("Apart.cs", false)] {
        let source = project.file(path);
        let imports = analyzer.import_info_of(&source);
        let reaches =
            analyzer.import_reachability(&source, &imports, &lib) == ImportReachability::Reaches;
        assert_eq!(
            analyzer.could_import_file(&source, &imports, &lib),
            expected
        );
        assert_eq!(reaches, expected);
    }
}
