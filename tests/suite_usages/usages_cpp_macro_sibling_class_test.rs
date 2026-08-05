use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, UsageFinder};
use brokk_bifrost::{CodeUnitType, CppAnalyzer, IAnalyzer, Language};
use std::collections::BTreeSet;
use std::sync::Arc;

fn token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

#[test]
fn authoritative_cpp_consecutive_macro_classes_keep_namespace_type_references() {
    let header = r#"#ifndef TINYXML2_INCLUDED
#define TINYXML2_INCLUDED
namespace tinyxml2 {
class TINYXML2_LIB XMLUtil {
 public:
  static const char* SkipWhiteSpace(const char* p) {
    while (*p) {
      if (*p == ' ') {
        ++p;
      }
    }
    return p;
  }
  static bool StringEqual(const char* p, const char* q) { return p == q; }
  class TINYXML2_LIB Helper {
   public:
    void Touch();
  };
  static void ToStr(int value, char* buffer);
 private:
  static const char* writeBoolTrue;
};

class TINYXML2_LIB XMLNode {
 public:
  virtual XMLNode* ShallowClone() const = 0;
  virtual bool ShallowEqual(const XMLNode* compare) const = 0;
};
}
#endif
"#;
    let consumer_source = r#"#include "tinyxml2.h"
namespace tinyxml2 {
XMLNode* clone_node(XMLNode* node) {
  return node->ShallowClone();
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("tinyxml2.h", header)
        .file("tinyxml2.cpp", consumer_source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let consumer = project.file("tinyxml2.cpp");
    let declarations = analyzer.get_all_declarations();
    let xml_node = declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "tinyxml2.XMLNode"
                && unit.source().rel_path().to_string_lossy() == "tinyxml2.h"
        })
        .cloned()
        .unwrap_or_else(|| panic!("missing namespace-level XMLNode: {declarations:#?}"));
    assert!(
        declarations
            .iter()
            .all(|unit| unit.fq_name() != "tinyxml2.XMLUtil$XMLNode"),
        "the later macro class must not inherit the prior class owner: {declarations:#?}"
    );

    let return_type = token_range(
        consumer_source,
        "XMLNode* clone_node(XMLNode* node) {",
        "XMLNode",
    );
    let line = consumer_source[..return_type.0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let line_start = consumer_source[..return_type.0]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let forward = brokk_bifrost::searchtools::get_declarations_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "tinyxml2.cpp".to_string(),
                line: Some(line),
                column: Some(consumer_source[line_start..return_type.0].chars().count() + 1),
            }],
        },
    );
    assert_eq!(forward.results.len(), 1, "{forward:#?}");
    assert_eq!(forward.results[0].status, "resolved", "{forward:#?}");
    assert!(
        forward.results[0]
            .declarations
            .iter()
            .any(|declaration| declaration.fqn.as_deref() == Some("tinyxml2.XMLNode")),
        "forward lookup must keep the namespace sibling owner: {forward:#?}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let result = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&xml_node),
            Some(&provider),
            1,
            1000,
        )
        .result;
    let inverse_ranges = result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.file == consumer)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        inverse_ranges.contains(&return_type),
        "authoritative inverse lookup must contain the exact return type: {inverse_ranges:#?}"
    );
}
