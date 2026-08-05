//! The analyzer-bound half of [`brokk_bifrost_cpp::graph::inverted`]'s tests.
//!
//! See [`super::resolver_tests`] for why they stayed on this side of the seam.

use crate::analyzer::usages::cpp_graph::shared::build_cpp_edges;
use brokk_bifrost_cpp::graph::CppGraphSource;
use brokk_bifrost_cpp::graph::resolver::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnitIndex, CppAnalyzer, Language, ProjectFile, TestProject};
    use std::fs;

    #[test]
    fn inverted_edges_keep_macro_return_alias_reference() {
        let source = r#"
namespace absl {
ABSL_NAMESPACE_BEGIN
template <typename T>
class beta_distribution {
 public:
  using result_type = T;
  class param_type {
   private:
    static RETURN_MACRO result_type Threshold() {
      return result_type(1);
    }
  };
};
ABSL_NAMESPACE_END
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp root");
        fs::write(root.join("beta.h"), source).expect("write fixture");
        let file = ProjectFile::new(&root, "beta.h");
        let analyzer = CppAnalyzer::from_project(TestProject::new(&root, Language::Cpp));
        let declarations = analyzer.get_all_declarations();
        let alias = declarations
            .iter()
            .find(|unit| unit.fq_name() == "absl.beta_distribution$result_type")
            .expect("result_type alias");
        let owner = declarations
            .iter()
            .find(|unit| unit.fq_name() == "absl.beta_distribution$param_type")
            .expect("param_type owner");
        let roots = std::iter::once(file.clone()).collect();
        let visibility =
            VisibilityIndex::build(&analyzer, CppGraphSource::from_source(&analyzer), &roots);
        let nodes = [alias.fq_name(), owner.fq_name()].into_iter().collect();

        let edges: crate::analyzer::usages::inverted_edges::UsageEdges = build_cpp_edges(
            &analyzer,
            std::slice::from_ref(&file),
            &visibility,
            &nodes,
            |_| true,
        );

        assert!(
            edges
                .edges
                .contains_key(&(owner.fq_name(), alias.fq_name())),
            "macro return type must produce an inverted owner-to-alias edge: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
    }
}
