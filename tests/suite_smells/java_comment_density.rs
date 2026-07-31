use crate::common::InlineTestProject;
use brokk_bifrost::{IAnalyzer, JavaAnalyzer, Language};

/// Regression test for the cross-file header misattribution behind the
/// google-gson benchmark failure (own header 86 -> 0 for `com.google.gson.Gson`
/// after PR #1415). A Java package module fans out through `direct_children`
/// to same-package declarations in *other* files; their ranges are byte
/// offsets into those files' sources, so treating them as containment
/// candidates for this file's comments silently steals the class's own
/// Javadoc when a foreign declaration happens to span the same byte interval.
///
/// The fixture needs two files in one package: the sibling class must start
/// near byte zero and span past the target file's Javadoc bytes, which is
/// exactly the shape that made the shared flat declaration walk misattribute.
#[test]
fn java_class_javadoc_stays_with_its_class_despite_package_siblings() {
    let padding_methods: String = (0..20)
        .map(|index| format!("  public int method{index}() {{ return {index}; }}\n"))
        .collect();
    let big = format!("package com.example;\npublic class Big {{\n{padding_methods}}}\n");
    let target = "package com.example;\n\
                  \n\
                  /**\n\
                  \x20* Target header documentation.\n\
                  \x20* Second documentation line.\n\
                  \x20*/\n\
                  public final class Target {\n\
                  \x20 int field = 1;\n\
                  \n\
                  \x20 // trailing class-body note\n\
                  }\n";

    let project = InlineTestProject::with_language(Language::Java)
        .file("com/example/Big.java", big)
        .file("com/example/Target.java", target)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let stats = analyzer.comment_density_by_top_level(&project.file("com/example/Target.java"));
    assert_eq!(stats.len(), 1, "stats: {stats:#?}");
    assert_eq!(stats[0].fq_name, "com.example.Target");
    assert_eq!(
        (stats[0].header_comment_lines, stats[0].inline_comment_lines),
        (4, 1),
        "stats: {stats:#?}"
    );
}
