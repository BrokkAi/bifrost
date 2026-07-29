use brokk_bifrost::{
    CppAnalyzer, JavaAnalyzer, Language, ScalaAnalyzer, TestProject,
    searchtools::{FilePatternsParams, list_symbols},
};

use crate::common::InlineTestProject;

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

#[test]
fn list_symbols_preserves_package_headers() {
    let analyzer = fixture_analyzer();
    let params = FilePatternsParams {
        file_patterns: vec!["Packaged.java".to_string()],
    };

    let result = list_symbols(&analyzer, params);

    assert_eq!(1, result.files.len());
    assert_eq!("Packaged.java", result.files[0].path);
    assert_eq!(
        Some(&"# io.github.jbellis.brokk".to_string()),
        result.files[0].lines.first()
    );
    assert!(result.files[0].lines.contains(&"- Foo".to_string()));
    assert!(result.files[0].lines.contains(&"  - bar".to_string()));
}

#[test]
fn list_symbols_renders_scala_objects_idiomatically() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/ai/brokk/ScalaObjects.scala",
            r#"package ai.brokk

object ir {
  object PrimOp {
    case object AsClockOp
  }
}

object InstanceChoiceControl {
  def select: Unit = {}
}
"#,
        )
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    let result = list_symbols(
        &analyzer,
        FilePatternsParams {
            file_patterns: vec!["src/ai/brokk/ScalaObjects.scala".to_string()],
        },
    );

    assert_eq!(1, result.files.len());
    assert_eq!("src/ai/brokk/ScalaObjects.scala", result.files[0].path);
    assert!(
        result.files[0].lines.contains(&"- ir".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0].lines.contains(&"  - PrimOp".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0]
            .lines
            .contains(&"    - AsClockOp".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0]
            .lines
            .contains(&"- InstanceChoiceControl".to_string()),
        "{:#?}",
        result.files[0].lines
    );
    assert!(
        result.files[0].lines.contains(&"  - select".to_string()),
        "{:#?}",
        result.files[0].lines
    );
}

#[test]
fn list_symbols_includes_cpp_functions_macros_and_prototypes() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/detection/bootmgr/bootmgr_apple.c",
            r#"#include "bootmgr.h"
#include "common/io.h"

static const char* detectSecureBoot(void) {
    return NULL;
}

const char* ffDetectBootmgr(FFBootmgrResult* result) {
    return "iBoot";
}
"#,
        )
        .file(
            "src/detection/codec/codec.h",
            r#"#pragma once
#include "common/option.h"

#define FF_CODEC_UNKNOWN 0
#define FF_CODEC_NAME(x) ffCodecName_##x

const char* ffDetectCodec(void);
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let result = list_symbols(
        &analyzer,
        FilePatternsParams {
            file_patterns: vec![
                "src/detection/bootmgr/bootmgr_apple.c".to_string(),
                "src/detection/codec/codec.h".to_string(),
            ],
        },
    );

    assert_eq!(2, result.files.len(), "{:#?}", result.files);

    let bootmgr = result
        .files
        .iter()
        .find(|file| file.path == "src/detection/bootmgr/bootmgr_apple.c")
        .unwrap();
    assert!(
        bootmgr.lines.contains(&"- detectSecureBoot".to_string()),
        "{:#?}",
        bootmgr.lines
    );
    assert!(
        bootmgr.lines.contains(&"- ffDetectBootmgr".to_string()),
        "{:#?}",
        bootmgr.lines
    );

    let codec = result
        .files
        .iter()
        .find(|file| file.path == "src/detection/codec/codec.h")
        .unwrap();
    assert!(
        codec.lines.contains(&"- FF_CODEC_UNKNOWN".to_string()),
        "{:#?}",
        codec.lines
    );
    assert!(
        codec.lines.contains(&"- FF_CODEC_NAME".to_string()),
        "{:#?}",
        codec.lines
    );
    assert!(
        codec.lines.contains(&"- ffDetectCodec".to_string()),
        "{:#?}",
        codec.lines
    );
}
