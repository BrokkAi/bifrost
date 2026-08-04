use crate::common::InlineTestProject;
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::usages::{PythonExportUsageGraphStrategy, UsageAnalyzer};
use brokk_bifrost::{CodeUnit, Language, PythonAnalyzer};
use std::collections::BTreeSet;

fn definition(analyzer: &PythonAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn usage_hits(
    project: &crate::common::BuiltInlineTestProject,
    target_fqn: &str,
) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, target_fqn);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .unwrap_or_else(|_| panic!("graph should resolve usages for {target_fqn}"))
}

fn token_range_on_line(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing line {line:?}"));
    let token_offset = source[line_start..]
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} on line {line:?}"));
    let start = line_start + token_offset;
    (start, start + token.len())
}

#[test]
fn decorated_class_scoped_bare_return_annotation_hits_owned_alias_for_each_method() {
    let source = r#"
import abc

class ModelTrainerFutureBase:
    pass

class ModelTrainerBase:
    ModelFutureBase = ModelTrainerFutureBase

    @abc.abstractmethod
    def train(
        self,
        training_id: str,
    ) -> ModelFutureBase:
        raise NotImplementedError

    @abc.abstractmethod
    def get_model_future(self, training_id: str) -> ModelFutureBase:
        raise NotImplementedError
"#;
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", source)
        .build();

    let alias_hits = usage_hits(&project, "service.ModelTrainerBase.ModelFutureBase");
    let actual_ranges: BTreeSet<_> = alias_hits
        .iter()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    let expected_ranges = BTreeSet::from([
        token_range_on_line(source, "    ) -> ModelFutureBase:", "ModelFutureBase"),
        token_range_on_line(
            source,
            "    def get_model_future(self, training_id: str) -> ModelFutureBase:",
            "ModelFutureBase",
        ),
    ]);
    assert_eq!(
        actual_ranges, expected_ranges,
        "expected both abstract methods to hit the owned alias: {alias_hits:#?}"
    );
}

#[test]
fn nested_closure_annotation_attribute_uses_enclosing_typed_receiver() {
    let source = r#"
class RpcReturnType:
    pass

class RpcSignature:
    return_type: RpcReturnType

class RemoteRPCDescriptor:
    signature: RpcSignature

class OtherDescriptor:
    signature: RpcSignature

class Client:
    @classmethod
    def generate_inference_function(cls, method: RemoteRPCDescriptor):
        def infer_func(self) -> method.signature.return_type:
            raise NotImplementedError

        shadowed_lambda = lambda method: method.signature
        return infer_func

    @classmethod
    def wrong_owner(cls, other: OtherDescriptor):
        def infer_func(self) -> other.signature.return_type:
            raise NotImplementedError

        return infer_func

    @classmethod
    def shadowed(cls, method: RemoteRPCDescriptor):
        def infer_func(method: OtherDescriptor) -> method.signature.return_type:
            raise NotImplementedError

        return infer_func
"#;
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", source)
        .build();

    let hits = usage_hits(&project, "service.RemoteRPCDescriptor.signature");
    assert_eq!(hits.len(), 2, "{hits:#?}");
    let actual_ranges: BTreeSet<_> = hits
        .iter()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    assert_eq!(
        actual_ranges,
        BTreeSet::from([
            token_range_on_line(
                source,
                "        def infer_func(self) -> method.signature.return_type:",
                "signature",
            ),
            token_range_on_line(
                source,
                "        def infer_func(method: OtherDescriptor) -> method.signature.return_type:",
                "signature",
            ),
        ]),
        "{hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("other.signature.return_type")
                && !hit.snippet.contains("lambda method: method.signature")),
        "{hits:#?}"
    );
}

#[test]
fn nested_function_body_annotation_does_not_bind_same_named_class_member() {
    let source = r#"
class ModelFutureBase:
    pass

class ModelTrainerFutureBase:
    pass

class ModelTrainerBase:
    ModelFutureBase = ModelTrainerFutureBase

    def factory(self):
        def inner() -> ModelFutureBase:
            raise NotImplementedError

        return inner
"#;
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", source)
        .build();

    let owner_hits = usage_hits(&project, "service.ModelTrainerBase.ModelFutureBase");
    assert!(owner_hits.is_empty(), "{owner_hits:#?}");
}
