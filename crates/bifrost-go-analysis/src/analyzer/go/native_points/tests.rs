use crate::analyzer::go::native_points::*;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelRuntimeLimits;

use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::workspace::DependencyPackActivationOutcome;

use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

use brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext;

use brokk_bifrost_core::analyzer::config::GoAnalyzerConfig;

use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryConfig;

use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::model::Range;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    INTERACTIVE_TYPE_LOOKUP_BUDGET, ReceiverAnalysisBudget,
};
use brokk_bifrost_test_macros::hardwon;
use std::sync::Arc;
use tree_sitter::Parser;

const PROVIDER: &str = "provider/item.go";
const CALLER: &str = "consumer/use.go";

/// The live Go oracles in this file spawn the host Go toolchain, either
/// directly or through Go dependency discovery. The GitHub-hosted macOS
/// runners do not put `go` on PATH (#4953), so a test that needs an oracle
/// returns early instead of failing at the spawn.
fn go_toolchain_available() -> bool {
    std::process::Command::new("go")
        .arg("version")
        .output()
        .is_ok()
}

fn assert_go_discovery_completed(outcome: &DependencyPackActivationOutcome) {
    let Some(go) = outcome
        .ecosystems
        .iter()
        .find(|ecosystem| ecosystem.ecosystem == DependencyPackEcosystem::Go)
    else {
        panic!("live go tool setup failure: Go discovery was not attempted: {outcome:#?}");
    };
    assert!(
        go.discovery.complete,
        "live go tool setup failure: Go dependency discovery was incomplete: {outcome:#?}"
    );
}

fn fixture(source: &str) -> (BuiltInlineTestProject, GoAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(PROVIDER, "package vocabulary; type Item struct {}")
        .file(CALLER, source)
        .file("decoy/item.go", "package vocabulary; type Item struct {}")
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    (fixture, analyzer)
}

fn site(source: &str) -> ResolvedReferenceSite {
    site_for(source, "Item")
}

fn site_for(source: &str, identifier: &str) -> ResolvedReferenceSite {
    let start_byte = source.rfind(identifier).unwrap();
    let range = Range {
        start_byte,
        end_byte: start_byte + identifier.len(),
        start_line: 0,
        end_line: 0,
    };
    brokk_bifrost_analysis::analyzer::usages::common::build_reference_site(
        CALLER.into(),
        identifier.into(),
        range,
        start_byte,
        start_byte + identifier.len(),
    )
}

fn selector_field_start(source: &str, name: &str, ordinal: usize) -> usize {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("configure Go parser for the selected member site");
    let tree = parser.parse(source, None).expect("parse Go member fixture");
    let mut pending = vec![tree.root_node()];
    let mut found = 0;
    while let Some(node) = pending.pop() {
        if node.kind() == "selector_expression"
            && let Some(field) = node.child_by_field_name("field")
            && field
                .utf8_text(source.as_bytes())
                .expect("selector field text")
                == name
        {
            if found == ordinal {
                return field.start_byte();
            }
            found += 1;
        }
        pending.extend(
            (0..node.named_child_count())
                .rev()
                .filter_map(|index| node.named_child(index)),
        );
    }
    panic!("selector field {name:?} at ordinal {ordinal} is absent from the Go AST");
}

fn member_site(source: &str, operand_text: &str, field_name: &str) -> ResolvedReferenceSite {
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source).unwrap();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "selector_expression"
            && node
                .child_by_field_name("operand")
                .and_then(|operand| operand.utf8_text(source.as_bytes()).ok())
                == Some(operand_text)
            && let Some(field) = node.child_by_field_name("field")
            && field.utf8_text(source.as_bytes()).ok() == Some(field_name)
        {
            let start_byte = field.start_byte();
            let end_byte = field.end_byte();
            return ResolvedReferenceSite {
                path: CALLER.into(),
                text: field_name.into(),
                range: Range {
                    start_byte,
                    end_byte,
                    start_line: 0,
                    end_line: 0,
                },
                focus_start_byte: start_byte,
                focus_end_byte: end_byte,
            };
        }
        pending.extend(
            (0..node.named_child_count())
                .rev()
                .filter_map(|index| node.named_child(index)),
        );
    }
    panic!("selector {operand_text:?}.{field_name} is absent from the Go AST");
}

#[test]
#[hardwon(
    "a25945887125: reverse receiver confirmation missed parameter, typed-local, and field-chain bindings"
)]
fn go_point_receiver_anchor_selects_local_and_parameter_bindings() {
    let source = r#"package consumer
type Client struct{}
type Options struct { Client *Client }
type Connection struct { TunnelClient *Options }
type TestCase struct { Options *Options }
func parameter(parameterOpts *Options) { _ = parameterOpts.Client }
func local() { var localOpts *Options; _ = localOpts.Client }
func (c *Connection) chain() { _ = c.TunnelClient.Client }
func fieldInitializer(cases []TestCase) {
	for _, testCase := range cases {
		fieldOpts := testCase.Options
		_ = fieldOpts.Client
	}
}
func newOptions() *Options { return nil }
func callInitializer() {
	callOpts := newOptions()
	_ = callOpts.Client
}
func rangeOwner(cases []TestCase) {
	for _, tc := range cases {
		_ = tc.Options.Client
	}
}
"#;
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source).unwrap();

    for (operand, expected_name, expected_first_member, followup) in [
        ("parameterOpts", "parameterOpts", "Client", None),
        ("localOpts", "localOpts", "Client", None),
        ("tc.Options", "tc", "Options", Some("Client")),
    ] {
        let site = member_site(source, operand, "Client");
        let anchor = go_point_receiver_anchor(&site, &tree, source)
            .expect("selected member access has a receiver anchor");
        let binding = anchor
            .binding
            .expect("name-based receiver is anchored at its local binding");
        assert_eq!(
            &source[binding.declaration_start_byte..binding.declaration_end_byte],
            expected_name
        );
        assert_eq!(binding.member_name, expected_first_member);
        assert_eq!(binding.followup_member_name.as_deref(), followup);
    }

    // A spelled owner type takes the declared-type route, as the point operation
    // did before binding anchors: the binding route only follows an owner whose
    // type name and call callee are both unavailable.
    let chain_site = member_site(source, "c.TunnelClient", "Client");
    let chain_anchor = go_point_receiver_anchor(&chain_site, &tree, source)
        .expect("field-chain member access has a receiver anchor");
    assert!(chain_anchor.binding.is_none());
    assert_eq!(chain_anchor.owner_type_name.as_deref(), Some("Connection"));

    let local_site = member_site(source, "localOpts", "Client");
    let local_anchor = go_point_receiver_anchor(&local_site, &tree, source)
        .expect("typed local member access has a receiver anchor");
    let local_binding = local_anchor
        .binding
        .expect("typed local uses its declared binding");
    let line_before_local = &source[..local_binding.declaration_start_byte];
    assert!(line_before_local.ends_with("var "));

    let field_site = member_site(source, "fieldOpts", "Client");
    let field_anchor = go_point_receiver_anchor(&field_site, &tree, source)
        .expect("field-initialized local member access has a receiver anchor");
    let field_binding = field_anchor
        .binding
        .expect("field-initialized local uses its selected binding");
    let Some(GoPointBindingInitializer::FieldChain {
        root_declaration_start_byte,
        root_declaration_end_byte,
        member_names,
        ..
    }) = field_binding.initializer
    else {
        panic!("field initializer must preserve its root binding and field path");
    };
    assert_eq!(
        &source[root_declaration_start_byte..root_declaration_end_byte],
        "testCase"
    );
    assert_eq!(member_names, ["Options"]);

    let call_site = member_site(source, "callOpts", "Client");
    let call_anchor = go_point_receiver_anchor(&call_site, &tree, source)
        .expect("call-initialized local member access has a receiver anchor");
    let call_binding = call_anchor
        .binding
        .expect("call-initialized local uses its selected binding");
    let Some(GoPointBindingInitializer::CallResult {
        function_start_byte,
        function_end_byte,
    }) = call_binding.initializer
    else {
        panic!("call initializer must preserve the selected function range");
    };
    assert_eq!(
        &source[function_start_byte..function_end_byte],
        "newOptions"
    );
}

#[test]
#[hardwon("f24c78ded6c7: generic calls with arguments were rejected before keyed call lookup")]
fn go_point_call_anchor_reads_generic_invocations_with_arguments() {
    let source = r#"package consumer
func caller() {
	cache := New[string, struct{}](true)
	_ = cache
}
"#;
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source).unwrap();
    let cache = site_for(source, "cache");
    let reference = tree
        .root_node()
        .named_descendant_for_byte_range(cache.focus_start_byte, cache.focus_end_byte)
        .unwrap();

    assert_eq!(
        go_point_call_callee_reference(reference, reference, source),
        Some((
            source.find("New").unwrap(),
            source.find("New").unwrap() + "New".len()
        ))
    );
}

fn go_types_generic_answers(source: &str) -> std::collections::HashMap<String, String> {
    let oracle = r##"
package main

import (
    "go/ast"
    "go/importer"
    "go/parser"
    "go/token"
    "go/types"
    "encoding/json"
    "fmt"
    "os"
)

func main() {
    if len(os.Args) != 2 { panic("expected source file") }
    source, err := os.ReadFile(os.Args[1])
    if err != nil { panic(err) }
    fset := token.NewFileSet()
    file, err := parser.ParseFile(fset, "generic.go", source, 0)
    if err != nil { panic(err) }
    info := &types.Info{
        Types: make(map[ast.Expr]types.TypeAndValue),
        Defs: make(map[*ast.Ident]types.Object),
        Uses: make(map[*ast.Ident]types.Object),
        Selections: make(map[*ast.SelectorExpr]*types.Selection),
        Instances: make(map[*ast.Ident]types.Instance),
    }
    pkg, err := (&types.Config{Importer: importer.Default()}).Check(
        "example.test/native/consumer", fset, []*ast.File{file}, info,
    )
    if err != nil { panic(err) }
    if len(info.Defs) == 0 || len(info.Uses) == 0 || len(info.Types) == 0 ||
       len(info.Selections) < 3 || len(info.Instances) < 4 {
        panic(fmt.Sprintf("go/types did not populate the generic oracle maps: defs=%d uses=%d types=%d selections=%d instances=%d",
            len(info.Defs), len(info.Uses), len(info.Types), len(info.Selections), len(info.Instances)))
    }
    stringify := func(typ types.Type) string {
        return types.TypeString(typ, func(p *types.Package) string { return p.Path() })
    }
    answers := make(map[string]string)
    declarationNames := map[string]string{
        "fieldInt": "field-int",
        "fieldSlice": "field-slice",
        "receiverResult": "receiver-result",
        "constructedResult": "constructed-result",
        "cacheEntries": "cache-entries",
        "identityExplicit": "identity-explicit",
        "identityInferred": "identity-inferred",
        "sliceResult": "slice-result",
        "nestedResult": "nested-result",
        "inferredNested": "inferred-nested",
    }
    for identifier := range info.Instances {
        switch identifier.Name {
        case "Echo", "Wrap", "Nested", "InferNested":
        default:
            continue
        }
        answers["instance:"+identifier.Name] = "present"
    }
    if answers["instance:Echo"] == "" || answers["instance:Wrap"] == "" || answers["instance:Nested"] == "" ||
       answers["instance:InferNested"] == "" {
        panic(fmt.Sprintf("go/types Instances omitted explicit applications: %v", answers))
    }
    ast.Inspect(file, func(node ast.Node) bool {
        switch current := node.(type) {
        case *ast.SelectorExpr:
            if current.Sel.Name == "Value" || current.Sel.Name == "entries" {
                selection := info.Selections[current]
                if selection == nil || selection.Kind() != types.FieldVal {
                    panic(current.Sel.Name + " selector has no go/types field selection")
                }
            }
        case *ast.AssignStmt:
            if current.Tok != token.DEFINE { break }
            for index, left := range current.Lhs {
                identifier, ok := left.(*ast.Ident)
                if !ok || index >= len(current.Rhs) { continue }
                key, ok := declarationNames[identifier.Name]
                if !ok { continue }
                answers[key] = stringify(info.Types[current.Rhs[index]].Type)
            }
        case *ast.CallExpr:
            name := ""
            explicit := false
            switch function := current.Fun.(type) {
            case *ast.Ident:
                name = function.Name
            case *ast.IndexExpr:
                explicit = true
                if identifier, ok := function.X.(*ast.Ident); ok { name = identifier.Name }
            case *ast.IndexListExpr:
                explicit = true
                if identifier, ok := function.X.(*ast.Ident); ok { name = identifier.Name }
            case *ast.SelectorExpr:
                name = function.Sel.Name
            }
            switch name {
            case "Get":
                if selection := info.Selections[current.Fun.(*ast.SelectorExpr)]; selection == nil || selection.Kind() != types.MethodVal {
                    panic("Get selector has no go/types method selection")
                }
                answers["receiver-result"] = stringify(info.Types[current].Type)
            case "ExpiresAt":
                if selection := info.Selections[current.Fun.(*ast.SelectorExpr)]; selection == nil || selection.Kind() != types.MethodVal {
                    panic("ExpiresAt selector has no go/types method selection")
                }
                answers["constructed-result"] = stringify(info.Types[current].Type)
            case "Echo":
                key := "identity-inferred"
                if explicit { key = "identity-explicit" }
                answers[key] = stringify(info.Types[current].Type)
            case "Wrap":
                answers["slice-result"] = stringify(info.Types[current].Type)
            case "Nested":
                answers["nested-result"] = stringify(info.Types[current].Type)
            case "InferNested":
                answers["inferred-nested"] = stringify(info.Types[current].Type)
            }
        }
        return true
    })
    for _, instance := range []string{"Echo", "Wrap", "Nested", "InferNested"} {
        delete(answers, "instance:"+instance)
    }
    if len(answers) != 10 || pkg.Path() != "example.test/native/consumer" {
        panic(fmt.Sprintf("incomplete go/types cases: %v", answers))
    }
    encoded, err := json.Marshal(answers)
    if err != nil { panic(err) }
    if _, err := os.Stdout.Write(encoded); err != nil { panic(err) }
}
"##;
    let directory = tempfile::tempdir().expect("Go oracle temp directory");
    let path = directory.path().join("generic_oracle.go");
    std::fs::write(&path, oracle).expect("write go/types oracle");
    let source_path = directory.path().join("consumer.gosrc");
    std::fs::write(&source_path, source).expect("write Go type fixture");
    let output = std::process::Command::new("go")
        .args([
            "run",
            path.to_str().expect("oracle path is UTF-8"),
            source_path.to_str().expect("source path is UTF-8"),
        ])
        .env("GO111MODULE", "off")
        .output()
        .expect("the local Go toolchain runs the go/types oracle");
    assert!(
        output.status.success(),
        "go/types oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("go/types oracle emits a JSON type map")
}

fn complete(result: BoundedResolution<DefinitionLookupOutcome>) -> DefinitionLookupOutcome {
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    value
}

fn complete_with_evidence(
    result: BoundedResolution<GoNativeDefinitionResolution>,
) -> GoNativeDefinitionResolution {
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    value
}

#[test]
fn go_native_point_projects_direct_composite_type_shapes() {
    use brokk_bifrost_analysis::analyzer::resolution::{
        FactIntrinsicTypeDescriptor, FactProjectedTypeNodeForm, FactProjectedTypeShape,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes;
    type Projected = (
        Option<FactProjectedTypeShape>,
        Vec<FactIntrinsicTypeDescriptor>,
    );

    let source = "package p\nfunc f() {\n\tvar bytes []byte\n\tvar lookup map[string]int\n\tvar values [4]int\n\tvar callback func(int) string\n\tvar stream chan int\n\tconsume(bytes, lookup, values, callback, stream)\n}\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/shapes\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(CALLER);
    let cancellation = CancellationToken::default();
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse local composite type shape cases");
    let mut pending = vec![tree.root_node()];
    let mut arguments = std::collections::HashMap::new();
    while let Some(node) = pending.pop() {
        if node.kind() == "identifier"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "argument_list")
        {
            arguments.insert(source[node.start_byte()..node.end_byte()].to_owned(), node);
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    let mut request = match GoNativePointRequest::open_for_file(
        &analyzer,
        &file,
        analyzer.inner.semantic_model_overlay(),
        &cancellation,
    )
    .expect("open selected Go native point request")
    {
        GoNativePointRequestOpen::Ready(request) => request,
        GoNativePointRequestOpen::Unavailable { kind, message } => {
            panic!("selected Go point request unavailable: {kind}: {message}")
        }
        GoNativePointRequestOpen::Cancelled => panic!("selected Go point request cancelled"),
    };

    let mut resolve = |name: &str| {
        let node = arguments
            .get(name)
            .unwrap_or_else(|| panic!("AST has no argument reference for {name}"));
        let start = node.start_byte();
        let end = node.end_byte();
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: source[start..end].to_owned(),
            range: Range {
                start_byte: start,
                end_byte: end,
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            },
            focus_start_byte: start,
            focus_end_byte: end,
        };
        let mut projected = (None, Vec::new());
        let outcome = request.resolve_type_with_evidence(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: Some(&cancellation),
            },
            |evidence| {
                let intrinsics = match &evidence.value_types {
                    SelectedNativeTypes::Ready { intrinsic, .. } => intrinsic.to_vec(),
                    SelectedNativeTypes::Unavailable | SelectedNativeTypes::Cancelled => Vec::new(),
                };
                projected = (
                    evidence.answer.projected_type_shapes().first().cloned(),
                    intrinsics,
                );
            },
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("native type lookup did not complete for {name}: {outcome:?}")
        };
        assert!(
            matches!(
                value.status,
                TypeLookupStatus::Resolved | TypeLookupStatus::Incomplete
            ),
            "unexpected native type lookup status for {name}: {value:?}"
        );
        projected
    };

    let root_form = |projected: &Projected| {
        let (shape, _) = projected;
        let shape = shape.as_ref().expect("projected type shape");
        shape
            .nodes()
            .iter()
            .find(|node| node.slot() == shape.root_slot())
            .expect("shape root node")
            .form()
            .clone()
    };
    let assert_component = |projected: &Projected, slot, spelling: &str| {
        let (shape, intrinsics) = projected;
        let component = shape
            .as_ref()
            .expect("projected type shape")
            .nodes()
            .iter()
            .find(|node| node.slot() == slot)
            .expect("component node");
        assert_eq!(component.form(), &FactProjectedTypeNodeForm::Leaf);
        assert!(intrinsics.iter().any(|intrinsic| {
            intrinsic.identity() == component.identity() && intrinsic.spelling() == spelling
        }));
    };

    let bytes = resolve("bytes");
    let root = root_form(&bytes);
    let FactProjectedTypeNodeForm::Slice(element) = root else {
        panic!("[]byte must project as Slice: {root:?}")
    };
    // Go's predeclared byte alias resolves to the canonical uint8 intrinsic.
    assert_component(&bytes, element, "uint8");

    let lookup = resolve("lookup");
    let root = root_form(&lookup);
    let FactProjectedTypeNodeForm::Map { key, value } = root else {
        panic!("map[string]int must project as Map: {root:?}")
    };
    assert_component(&lookup, key, "string");
    assert_component(&lookup, value, "int");

    let values = resolve("values");
    let root = root_form(&values);
    let FactProjectedTypeNodeForm::Array(element) = root else {
        panic!("[4]int must project as Array: {root:?}")
    };
    assert_component(&values, element, "int");

    // This records the current boundary, not a goal: function signatures only
    // project the intrinsic leaf because they have no component rows, and
    // channels project Unsupported.
    let callback = resolve("callback");
    let root = root_form(&callback);
    assert_eq!(root, FactProjectedTypeNodeForm::Leaf);
    let (shape, intrinsics) = &callback;
    let shape = shape.as_ref().expect("function projected leaf shape");
    assert!(intrinsics.iter().any(|intrinsic| {
        intrinsic.identity()
            == shape
                .nodes()
                .iter()
                .find(|node| node.slot() == shape.root_slot())
                .expect("function root")
                .identity()
            && intrinsic.spelling() == "function-type"
    }));
    let stream = resolve("stream");
    assert_eq!(root_form(&stream), FactProjectedTypeNodeForm::Unsupported);
}

#[test]
fn go_native_point_request_reuses_operation_and_path_context_per_file() {
    // The points are value references. A type-name site answers no_type, so the
    // reuse check reads the imported type through the declared values instead.
    let source = "package consumer\n\nimport p \"example.test/native/provider\"\n\nvar First p.Item\nvar Second p.Item\nvar Third = First\nvar Fourth = Second\n";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let cancellation = CancellationToken::default();
    brokk_bifrost_analysis::analyzer::native_points::reset_native_point_operation_open_count_for_test();
    let mut request = match GoNativePointRequest::open(
        &analyzer,
        analyzer.inner.semantic_model_overlay(),
        &cancellation,
    )
    .unwrap()
    {
        GoNativePointRequestOpen::Ready(request) => request,
        GoNativePointRequestOpen::Unavailable { kind, message } => {
            panic!("selected Go point request unavailable: {kind}: {message}")
        }
        GoNativePointRequestOpen::Cancelled => panic!("selected Go point request was cancelled"),
    };
    assert_eq!(
        brokk_bifrost_analysis::analyzer::native_points::native_point_operation_open_count_for_test(
        ),
        1
    );

    let resolve_at = |request: &mut GoNativePointRequest<'_>, offset: usize, text: &str, budget| {
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: text.into(),
            range: Range {
                start_byte: offset,
                end_byte: offset + text.len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: offset,
            focus_end_byte: offset + text.len(),
        };
        request.resolve_type(BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget,
            cancellation: Some(&cancellation),
        })
    };
    let first_offset = source.rfind("First").expect("first selected value");
    let second_offset = source.rfind("Second").expect("second selected value");
    let limited = resolve_at(
        &mut request,
        first_offset,
        "First",
        ReceiverAnalysisBudget {
            max_scope_nodes: 0,
            ..ReceiverAnalysisBudget::default()
        },
    );
    assert!(
        matches!(&limited, BoundedResolution::Exceeded { .. }),
        "the first point honors its own zero scope budget: {limited:?}"
    );
    let BoundedResolution::Complete { value: first, .. } = resolve_at(
        &mut request,
        first_offset,
        "First",
        ReceiverAnalysisBudget::default(),
    ) else {
        panic!("the next point gets a fresh budget");
    };
    let hits_after_first = request
        .forward_candidate_artifacts
        .get(CALLER)
        .expect("the caller file owns its artifact cache")
        .cache_hit_count();
    let BoundedResolution::Complete {
        value: repeated_first,
        ..
    } = resolve_at(
        &mut request,
        first_offset,
        "First",
        ReceiverAnalysisBudget::default(),
    )
    else {
        panic!("a repeated point gets a fresh budget");
    };
    assert!(
        request
            .forward_candidate_artifacts
            .get(CALLER)
            .expect("the caller file owns its artifact cache")
            .cache_hit_count()
            > hits_after_first,
        "a repeated same-file point reuses immutable forward artifacts"
    );
    let hits_before_second = request
        .forward_candidate_artifacts
        .get(CALLER)
        .expect("the caller file owns its artifact cache")
        .cache_hit_count();
    let BoundedResolution::Complete { value: second, .. } = resolve_at(
        &mut request,
        second_offset,
        "Second",
        ReceiverAnalysisBudget::default(),
    ) else {
        panic!("the second point gets a fresh budget");
    };
    assert!(
        request
            .forward_candidate_artifacts
            .get(CALLER)
            .expect("the caller file owns its artifact cache")
            .cache_hit_count()
            > hits_before_second,
        "a distinct same-file point reuses immutable forward artifacts"
    );

    // Cache warmth may close the completion status, but it cannot change the
    // selected declaration for this exact imported type reference.
    assert_eq!(first.types.len(), 1, "{first:?}");
    assert_eq!(
        first.types[0].fqn, "example.test/native/provider.Item",
        "{first:?}"
    );
    for cached in [&repeated_first, &second] {
        assert_eq!(cached.types.len(), first.types.len(), "{cached:?}");
        for (expected, actual) in first.types.iter().zip(&cached.types) {
            assert_eq!(actual.fqn, expected.fqn, "{cached:?}");
            assert_eq!(actual.definitions, expected.definitions, "{cached:?}");
            assert_eq!(
                actual.semantic_model_id, expected.semantic_model_id,
                "{cached:?}"
            );
        }
    }
    assert_eq!(request.files.len(), 1, "one file context per touched path");
    assert_eq!(
        brokk_bifrost_analysis::analyzer::native_points::native_point_operation_open_count_for_test(
        ),
        1,
        "both points share the selected operation opened at request start"
    );
}

#[test]
#[hardwon("#3790: live Go discovery failures must surface as setup failures")]
fn go_native_point_binds_standard_package_and_external_member_identity() {
    // The standard library comes from the host Go toolchain. Without one the
    // qualifier is correctly incomplete, so this test needs `go` on PATH.
    if !go_toolchain_available() {
        return;
    }
    let source =
        "package consumer\n\nimport \"strings\"\n\nfunc use() {\n _ = strings.ToUpper(\"x\")\n}\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let config = AnalyzerConfig {
        go: GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                mode: GoDependencyDiscoveryMode::FullProduction,
                ..GoDependencyDiscoveryConfig::default()
            },
        },
        ..AnalyzerConfig::default()
    };
    let workspace = fixture.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
    let activation = SemanticModelActivationRequest {
        approximate_standard_libraries: Vec::new(),
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let cancellation = CancellationToken::default();
    let discovery = workspace.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Go],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    assert_go_discovery_completed(&discovery);
    assert_eq!(discovery.ecosystems.len(), 1);
    assert_eq!(
        discovery.ecosystems[0].ecosystem,
        DependencyPackEcosystem::Go
    );
    let analyzer = workspace.analyzer();
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse Go package member calls");
    let resolve_at = |needle: &str| {
        let start_byte = source.rfind(needle).expect("source contains focused token");
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: needle.into(),
            range: Range {
                start_byte,
                end_byte: start_byte + needle.len(),
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + needle.len(),
        };
        complete_with_evidence(resolve_go_definition_with_evidence_bounded(
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };

    let qualifier = resolve_at("strings").outcome;
    let Some(qualifier_binding) = qualifier.lexical_definition.as_ref() else {
        panic!("the package qualifier must bind to the selected import: {qualifier:?}");
    };
    assert_eq!(qualifier_binding.identifier, "strings");
    assert_eq!(
        &source[qualifier_binding.declaration_range.start_byte
            ..qualifier_binding.declaration_range.end_byte],
        "\"strings\""
    );

    let member_resolution = resolve_at("ToUpper");
    let member = member_resolution.outcome;
    assert_eq!(
        member.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "the standard-library member must carry an external identity: {member:?}"
    );
    assert_eq!(
        member.resolved_reference_target(),
        Some("strings.ToUpper"),
        "the member identity uses the selected Go import path"
    );
    assert!(
        member.diagnostics.iter().any(|diagnostic| {
            diagnostic.claim.as_ref().is_some_and(|claim| {
                claim.kind
                    == brokk_bifrost_analysis::analyzer::usages::get_definition::UnindexedClaimKind::ExternalBoundary
                    && claim.subjects == ["strings"]
            })
        }),
        "an unmodeled member may claim only its discovered package boundary: {member:?}"
    );
    assert!(
        member_resolution.exact_external_call.is_none(),
        "an absent strings model cannot prove exact call applicability"
    );
}

#[test]
fn go_native_point_resolves_modeled_external_receiver_through_field_type() {
    let source = r#"package consumer

import "sync"

type Pool struct { once sync.Once }

func (p *Pool) use() { p.once.Do(func() {}) }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let _catalog = activate_receiver_models_for_test(analyzer);
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse imported external receiver field call");
    let resolution = complete_with_evidence(resolve_go_definition_with_evidence_bounded(
        BoundedReceiverQuery {
            analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site_for(source, "Do"),
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_eq!(
        resolution.outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "the modeled external field method resolves to its exact package boundary: {:?}",
        resolution.outcome
    );
    assert_eq!(
        resolution.outcome.resolved_reference_target(),
        Some("sync.Once.Do")
    );
    assert_eq!(
        resolution.call_application,
        CallApplicationKind::BoundReceiver
    );
    assert!(resolution.exact_external_call.is_some());
}

#[test]
fn go_native_point_resolves_unqualified_calls_from_complete_source_inventory() {
    let source = format!(
        "package main\nfunc caller() {{ {} }}\n",
        (0..20)
            .map(|_| "go writePointer(&Cell{})")
            .collect::<Vec<_>>()
            .join("; ")
    );
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("main.go", &source)
        .file(
            "helper.go",
            "package main\ntype Cell struct {}\nfunc writePointer(cell *Cell) {}\n",
        )
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let go = workspace.analyzer();
    let start_byte = source.find("writePointer").expect("call callee");
    let site = ResolvedReferenceSite {
        path: "main.go".into(),
        text: "writePointer".into(),
        range: Range {
            start_byte,
            end_byte: start_byte + "writePointer".len(),
            start_line: 1,
            end_line: 1,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + "writePointer".len(),
    };
    let file = fixture.file("main.go");
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(&source)
        .expect("parse same-package call");

    let resolution = complete_with_evidence(resolve_go_definition_with_evidence_bounded(
        BoundedReceiverQuery {
            analyzer: go,
            file: &file,
            source: &source,
            tree: Some(&tree),
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_eq!(
        resolution.outcome.status,
        DefinitionLookupStatus::Resolved,
        "same-package source inventory resolves the call: {:?}",
        resolution.outcome
    );
    let [target] = resolution.outcome.definitions.as_slice() else {
        panic!("one same-package function target: {:?}", resolution.outcome);
    };
    assert_eq!(target.identifier(), "writePointer");
    assert_eq!(
        resolution.call_application,
        CallApplicationKind::PackageFunction
    );
}

#[test]
fn go_native_point_preserves_source_import_boundary_without_go_tool_context() {
    let source =
        "package consumer\n\nimport files \"os\"\n\nfunc use() { _, _ = files.Open(\"x\") }\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file(CALLER, source)
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse source-only external package call");
    let start_byte = source
        .rfind("Open")
        .expect("source contains package member");
    let site = ResolvedReferenceSite {
        path: CALLER.into(),
        text: "Open".into(),
        range: Range {
            start_byte,
            end_byte: start_byte + "Open".len(),
            start_line: 5,
            end_line: 5,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + "Open".len(),
    };
    let resolution = complete_with_evidence(resolve_go_definition_with_evidence_bounded(
        BoundedReceiverQuery {
            analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_eq!(
        resolution.outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "structured source import facts establish the external package boundary: {:?}",
        resolution.outcome
    );
    assert_eq!(
        resolution.outcome.resolved_reference_target(),
        Some("os.Open")
    );
    assert_eq!(
        resolution.call_application,
        CallApplicationKind::PackageFunction
    );
    assert!(resolution.exact_external_call.is_none());
}

#[test]
fn go_native_point_binds_model_backed_import_without_discovery() {
    let source = "package consumer\nimport \"example.com/acme/codec\"\nvar value wire.Buffer\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let _catalog = activate_receiver_models_for_test(analyzer);
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse model-backed Go import");
    let resolve_at = |identifier: &str| {
        complete_with_evidence(resolve_go_definition_with_evidence_bounded(
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site_for(source, identifier),
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };

    let qualifier = resolve_at("wire").outcome;
    let Some(binding) = qualifier.lexical_definition.as_ref() else {
        panic!("the exact model package identity binds the import: {qualifier:?}");
    };
    assert_eq!(binding.identifier, "wire");
    assert_eq!(
        &source[binding.declaration_range.start_byte..binding.declaration_range.end_byte],
        "\"example.com/acme/codec\""
    );

    let member = resolve_at("Buffer").outcome;
    assert_eq!(
        member.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "the package member uses the exact modeled import identity: {member:?}"
    );
    assert_eq!(
        member.resolved_reference_target(),
        Some("example.com/acme/codec.Buffer")
    );
}

#[test]
fn go_native_point_proves_os_file_close_from_model_backed_import() {
    let source = r#"package client

import "os"

func caller(file *os.File) {
	file.Close()
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    crate::analyzer::go::persist_live_go_sources_for_test(&analyzer);
    let _catalog = activate_receiver_models_for_test(&analyzer);
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse modeled os receiver call");
    let query = BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source,
        tree: Some(&tree),
        site: &site_for(source, "Close"),
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    };
    let resolution = GoNativeRolloutPoints.resolve_definition_with_evidence_bounded(query);
    let resolution = match resolution {
        BoundedResolution::Complete { value, .. } => {
            let external_callee_identity = external_callee_identity(value.1.as_ref());
            let call_application = value.1.as_ref().map_or(
                CallApplicationKind::Unknown,
                ExactExternalCallProof::call_application,
            );
            GoNativeDefinitionResolution {
                native_resolution: None,
                model_member_selection: None,
                outcome: value.0,
                call_application,
                exact_external_call: value.1,
                external_callee_identity,
            }
        }
        other => panic!("Go native structural receiver returned {other:?}"),
    };

    assert_eq!(
        resolution.outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "the modeled receiver is an exact external boundary: {:?}",
        resolution.outcome
    );
    assert_eq!(
        resolution
            .exact_external_call
            .as_ref()
            .map(ExactExternalCallProof::canonical_callee),
        Some("os.File.Close"),
        "the selected model-backed os import supplies exact receiver authority"
    );
}

#[test]
#[hardwon("#3790: live Go discovery failures must surface as setup failures")]
fn go_native_external_receiver_calls_use_typed_imported_models() {
    // Live Go discovery proves the environment; a small activated synthetic
    // pack supplies deterministic selected receiver declarations.
    if !go_toolchain_available() {
        return;
    }
    let source = r#"package consumer

import (
    "bytes"
	"image"
	"os"
	"strings"
)

func use() {
	var point image.Point
	_ = point.String()

	var builder strings.Builder
	builder.WriteString("x")

	var file *os.File
	_ = file.Close()
}

func pair() ([]byte, error) { return nil, nil }
func argumentShapes(args []byte) {
    var spreadBuffer bytes.Buffer
    spreadBuffer.Write(args...)
    var unknownBuffer bytes.Buffer
    unknownBuffer.Write(missing())
    var pairBuffer bytes.Buffer
    pairBuffer.Write(pair())
}
func variadicReceiver(variadicBuffer ...bytes.Buffer) {
    variadicBuffer.Write(nil)
}

func useUnknown[T interface{ Release() error }](receiver T) {
	_ = receiver.Release()
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let config = AnalyzerConfig {
        go: GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                mode: GoDependencyDiscoveryMode::FullProduction,
                ..GoDependencyDiscoveryConfig::default()
            },
        },
        ..AnalyzerConfig::default()
    };
    let workspace = fixture.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
    let activation = SemanticModelActivationRequest {
        approximate_standard_libraries: Vec::new(),
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let cancellation = CancellationToken::default();
    let discovery = workspace.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Go],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    assert_go_discovery_completed(&discovery);
    assert_eq!(discovery.ecosystems.len(), 1);
    let analyzer = workspace.analyzer();
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse external receiver calls");
    let _catalog = activate_receiver_models_for_test(analyzer);
    // GoTool confirms these packages; selected model packs declare their types.
    // Keep that provenance intact while minting through the native request.
    let go = resolve_analyzer::<GoAnalyzer>(analyzer).expect("Go delegate");
    let GoNativePointRequestOpen::Ready(mut request) =
        GoNativePointRequest::open(go, analyzer.semantic_model_overlay(), &cancellation).unwrap()
    else {
        panic!("native Go request")
    };
    let context = request
        .file_context(CALLER, &cancellation)
        .unwrap()
        .expect("selected file");
    for import in ["image", "os", "strings"] {
        assert!(
            context
                .selected_imports
                .iter()
                .any(|selected| selected.import_path == import
                    && matches!(
                        selected.provenance,
                        GoExternalPackageProvenance::GoTool { .. }
                    )),
            "{import}: {:?}",
            context.selected_imports
        );
    }
    drop(request);
    let resolve_at = |selector: &str| {
        let selector_start = source
            .find(selector)
            .expect("source contains focused receiver selector");
        assert_eq!(
            source.matches(selector).count(),
            1,
            "receiver selector `{selector}` is unique"
        );
        let member_offset = selector
            .rfind('.')
            .expect("receiver selector contains a member separator")
            + 1;
        let start_byte = selector_start + member_offset;
        let member = &selector[member_offset..];
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: member.into(),
            range: Range {
                start_byte,
                end_byte: start_byte + member.len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + member.len(),
        };
        complete_with_evidence(resolve_go_definition_with_evidence_bounded(
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };

    for (selector, expected) in [
        ("point.String", "image.Point.String"),
        ("builder.WriteString", "strings.Builder.WriteString"),
        ("file.Close", "os.File.Close"),
    ] {
        let resolution = resolve_at(selector);
        assert!(
            resolution
                .model_member_selection
                .as_ref()
                .is_some_and(
                    |selection| selection
                        .candidates
                        .iter()
                        .any(|candidate| candidate.selected
                            && format!(
                                "{}.{}",
                                candidate.owner.owner_fqn, candidate.declaration.name
                            ) == expected)
                ),
            "{selector} must select a real model owner on the GoTool-bound path"
        );
        assert_eq!(
            resolution.outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "{selector}: {:?}",
            resolution.outcome
        );
        assert_eq!(
            resolution.outcome.resolved_reference_target(),
            Some(expected),
            "{selector}: {:?}",
            resolution.outcome
        );
        assert_eq!(
            resolution
                .exact_external_call
                .as_ref()
                .map(ExactExternalCallProof::canonical_callee),
            Some(expected),
            "{selector} proof: {:?}",
            resolution.exact_external_call
        );
    }

    let unknown = resolve_at("receiver.Release");
    assert_eq!(
        unknown.outcome.status,
        DefinitionLookupStatus::Incomplete,
        "unknown receiver stays incomplete: {:?}",
        unknown.outcome
    );
    assert!(
        unknown.exact_external_call.is_none(),
        "unknown receiver has no exact model proof"
    );
    for selector in [
        "spreadBuffer.Write",
        "unknownBuffer.Write",
        "variadicBuffer.Write",
    ] {
        let resolution = resolve_at(selector);
        assert!(
            resolution.exact_external_call.is_none(),
            "{selector}: {resolution:?}"
        );
    }
    let pair = resolve_at("pairBuffer.Write");
    let proof = pair
        .exact_external_call
        .expect("known sole-call tuple has a receiver candidate");
    assert_eq!(proof.canonical_callee(), "bytes.Buffer.Write");
    assert_eq!(proof.parameter_count, 2);
}

#[test]
fn go_native_point_uses_selected_alias_and_canonical_package_name() {
    for source in [
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item",
        "package consumer; import \"example.test/native/provider\"; var Value vocabulary.Item",
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site(source);
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ));
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "source={source}, {outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "source={source}, {outcome:?}");
        let provider = fixture.file(PROVIDER);
        assert_eq!(outcome.definitions[0].source(), &provider);
        assert!(
            analyzer
                .declarations(&provider)
                .contains(&outcome.definitions[0])
        );
    }
}

#[test]
fn go_native_point_does_not_guess_package_basename_or_ignore_shadowing() {
    for source in [
        "package consumer; import \"example.test/native/provider\"; var Value provider.Item",
        "package consumer; import renamed \"example.test/native/provider\"; func use() { var renamed int; _ = renamed.Item }",
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site(source);
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ));
        assert!(
            outcome.definitions.is_empty(),
            "source={source}, {outcome:?}"
        );
        assert_ne!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:?}"
        );
    }
}

#[test]
fn go_native_point_preserves_cancel_budget_and_source_admission() {
    let source =
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let site = site(source);
    let cancellation = CancellationToken::new();
    let result = resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: Some(&cancellation),
        },
        || cancellation.cancel(),
    );
    assert!(
        matches!(result, BoundedResolution::Cancelled { .. }),
        "{result:?}"
    );
    let result = resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::tiny(),
            cancellation: None,
        },
        || {},
    );
    assert!(
        matches!(result, BoundedResolution::Exceeded { .. }),
        "{result:?}"
    );
    let outcome = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: "package consumer; var Value Item",
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
    assert_eq!(outcome.diagnostics[0].kind, "native_source_mismatch");
}

#[test]
fn go_native_point_unsaved_import_does_not_borrow_disk_package_membership() {
    let source =
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item";
    let (fixture, disk) = fixture(source);
    let file = fixture.file(CALLER);
    let changed = source.replace("native/provider", "native/decoy");
    let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
        fixture.project_dyn(),
    ));
    assert!(overlay.set(file.abs_path(), changed.clone()));
    let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    assert!(!analyzer.declarations(&file).is_empty());
    let site = site(&changed);
    let outcome = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: &changed,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert_eq!(std::fs::read_to_string(file.abs_path()).unwrap(), source);
}

fn unsaved(
    fixture: &BuiltInlineTestProject,
    disk: &GoAnalyzer,
    edits: &[(&str, &str)],
) -> GoAnalyzer {
    let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
        fixture.project_dyn(),
    ));
    for (path, source) in edits {
        assert!(overlay.set(fixture.file(path).abs_path(), (*source).to_owned()));
    }
    disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>)
}

fn resolve_last(
    analyzer: &GoAnalyzer,
    fixture: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
) -> DefinitionLookupOutcome {
    let start_byte = source.rfind(needle).unwrap();
    resolve_at(analyzer, fixture, path, source, start_byte, needle)
}

fn resolve_at(
    analyzer: &GoAnalyzer,
    fixture: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    start_byte: usize,
    reference: &str,
) -> DefinitionLookupOutcome {
    let site = ResolvedReferenceSite {
        path: path.into(),
        text: reference.into(),
        range: Range {
            start_byte,
            end_byte: start_byte + reference.len(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + reference.len(),
    };
    let file = fixture.file(path);
    complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ))
}

const UNPLACED: &str = "go-transient-placement-unproven";

fn reports_unplaced(outcome: &DefinitionLookupOutcome) -> bool {
    outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == UNPLACED)
}

#[test]
fn go_native_point_unsaved_body_edit_keeps_selected_package_membership() {
    let source =
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item";
    let (fixture, disk) = fixture(source);
    // The bytes through the imports are unchanged, so the Go tool would place
    // the edited file exactly where it placed the saved one.
    let changed = format!("{source}\nvar Other renamed.Item\n");
    let analyzer = unsaved(&fixture, &disk, &[(CALLER, &changed)]);
    let outcome = resolve_last(&analyzer, &fixture, CALLER, &changed, "Item");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].source(), &fixture.file(PROVIDER));
    assert!(!reports_unplaced(&outcome), "{outcome:?}");
    assert_eq!(
        std::fs::read_to_string(fixture.file(CALLER).abs_path()).unwrap(),
        source
    );
}

#[test]
fn go_native_point_reads_unsaved_package_peer_only_with_proven_placement() {
    const USE: &str = "consumer/use.go";
    const LOCAL: &str = "consumer/local.go";
    const OTHER: &str = "consumer/other.go";
    const UNRELATED: &str = "unrelated/other.go";
    let use_source = "package consumer\n\nvar Value Local\n\nvar Second Other\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(USE, use_source)
        .file(LOCAL, "package consumer\n\ntype Local struct{}\n")
        .file(OTHER, "package consumer\n\ntype Other struct{}\n")
        .file(UNRELATED, "package unrelated\n\ntype Elsewhere struct{}\n")
        .build();
    let disk = GoAnalyzer::new(fixture.project_dyn());
    let local = fixture.file(LOCAL);
    let other = fixture.file(OTHER);

    let body_edit = "package consumer\n\ntype Local struct{ Added int }\n";
    let analyzer = unsaved(&fixture, &disk, &[(LOCAL, body_edit)]);
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Local");
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].source(), &local);
    assert!(!reports_unplaced(&outcome), "{outcome:?}");
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Other");
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert!(!reports_unplaced(&outcome), "{outcome:?}");

    let unrelated_edit = "package unrelated\n\nimport \"strings\"\n\nvar _ = strings.ToUpper\n";
    let analyzer = unsaved(&fixture, &disk, &[(UNRELATED, unrelated_edit)]);
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Local");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].source(), &local);
    assert!(
        !reports_unplaced(&outcome),
        "an unrelated package has no effect: {outcome:?}"
    );

    // A new import changes what the Go tool reads for placement. The peer
    // keeps its declaration, but no selected membership vouches for it, so
    // the saved caller must report that gap instead of a settled answer.
    let header_edit = "package consumer\n\nimport \"strings\"\n\ntype Local struct{}\n\nvar _ = strings.ToUpper\n";
    let analyzer = unsaved(&fixture, &disk, &[(LOCAL, header_edit)]);
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Local");
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    // A saved peer's declaration is still found, but the unplaced file could
    // declare the same name in this package, so the answer names that gap.
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Other");
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].source(), &other);
    assert!(reports_unplaced(&outcome), "{outcome:?}");
    let outcome = resolve_last(&analyzer, &fixture, LOCAL, header_edit, "Local");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_projects_function_literal_results() {
    let source = r#"package consumer

type Other struct{}
func (Other) M() {}
func use() {
    mk := func() Other { return Other{} }
    mk().M()
    var (
        grouped = func() Other { return Other{} }
    )
    grouped().M()
}
"#;
    let (fixture, analyzer) = fixture(source);
    for ordinal in 0..2 {
        let outcome = resolve_at(
            &analyzer,
            &fixture,
            CALLER,
            source,
            selector_field_start(source, "M", ordinal),
            "M",
        );
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            "example.test/native/consumer.Other.M",
            "{outcome:?}"
        );
    }
}

#[test]
fn go_native_type_preserves_nominal_target_and_projects_predeclared_types() {
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;
    for (source, identifier) in [
        (
            "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item; func f() { _ = Value }",
            "Value",
        ),
        (
            "package consumer; func f(Item int) int { return Item }",
            "Item",
        ),
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site_for(source, identifier);
        let result = resolve_go_type_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        );
        let BoundedResolution::Complete { value, work } = result else {
            panic!("{result:?}")
        };
        assert!(work.scope_nodes > 0);
        if source.contains("renamed") {
            assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:?}");
            assert_eq!(value.types.len(), 1, "{value:?}");
            assert_eq!(value.types[0].definitions.len(), 1);
            let unit = &value.types[0].definitions[0];
            assert_eq!(unit.source(), &fixture.file(PROVIDER));
            assert_eq!(value.types[0].fqn, unit.fq_name().to_string());
        } else {
            assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:?}");
            assert_eq!(value.types.len(), 1, "{value:?}");
            assert_eq!(value.types[0].fqn, "int");
            assert!(value.types[0].definitions.is_empty());
        }
    }
}

#[test]
fn go_native_type_lookup_propagates_the_call_result_type_to_a_local_binding() {
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

    let source = r#"package main

func external() any { return nil }

func Run() {
    value := external()
    _ = value
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let file = fixture.file(CALLER);
    let site = site_for(source, "value");
    let result = resolve_go_type_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };

    assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:?}");
    assert_eq!(value.types.len(), 1, "{value:?}");
    assert_eq!(value.types[0].fqn, "any", "{value:?}");
    assert!(value.types[0].definitions.is_empty(), "{value:?}");
}

#[test]
fn go_native_definition_projects_parameters_receivers_and_locals() {
    use brokk_bifrost_core::analyzer::model::DeclarationKind;
    for (source, kind) in [
        (
            "package consumer; func f(Item int) int { return Item }",
            DeclarationKind::Parameter,
        ),
        (
            "package consumer; type T struct{}; func (Item T) f() T { return Item }",
            DeclarationKind::ReceiverParameter,
        ),
        (
            "package consumer; func f() { var Item int; _ = Item }",
            DeclarationKind::LocalVariable,
        ),
        (
            "package consumer; func f() { Item := 1; _ = Item }",
            DeclarationKind::LocalVariable,
        ),
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site(source);
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ));
        assert!(
            matches!(
                outcome.status,
                DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Incomplete
            ),
            "{outcome:?}"
        );
        assert!(
            outcome.definitions.is_empty(),
            "lexical binders are not workspace units: {outcome:?}"
        );
        let lexical = outcome
            .lexical_definition
            .expect("exact lexical source declaration");
        assert_eq!(lexical.kind, kind);
        assert_eq!(lexical.identifier, "Item");
        assert_eq!(lexical.source_file.as_ref(), Some(&file));
        assert_eq!(lexical.name_range.start_byte, source.find("Item").unwrap());
        assert_eq!(
            &source[lexical.name_range.start_byte..lexical.name_range.end_byte],
            "Item"
        );
    }
}

#[test]
fn go_native_definition_projects_type_switch_and_select_clause_binders() {
    use brokk_bifrost_core::analyzer::model::DeclarationKind;

    let source = "package consumer\nfunc inspect(value any, input <-chan int) {\n switch item := value.(type) {\n case int: _ = item\n default: _ = item\n }\n select {\n case item := <-input: _ = item\n }\n}";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse Go clause binders");
    for (reference, declaration) in [
        ("case int: _ = item", "item := value.(type)"),
        ("default: _ = item", "item := value.(type)"),
        ("case item := <-input: _ = item", "item := <-input"),
    ] {
        let start_byte = source
            .find(reference)
            .and_then(|start| start.checked_add(reference.rfind("item")?))
            .expect("clause reference");
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: "item".into(),
            range: Range {
                start_byte,
                end_byte: start_byte + "item".len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "item".len(),
        };
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ));
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:?}"
        );
        assert!(outcome.definitions.is_empty(), "{outcome:?}");
        let lexical = outcome.lexical_definition.expect("lexical clause binder");
        assert_eq!(lexical.kind, DeclarationKind::LocalVariable);
        assert_eq!(lexical.identifier, "item");
        let declaration_start = source.find(declaration).expect("clause declaration");
        assert_eq!(lexical.name_range.start_byte, declaration_start);
    }
}

#[test]
fn go_native_point_resolves_local_alias_field_through_matching_type_name() {
    let source = "package consumer; type status struct { disabledGroups []string }; type BlockingResolver struct { status *status }; func (r *BlockingResolver) setDisabledGroups(groups []string) { s := r.status; s.disabledGroups = groups }";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let reference = site_for(source, "disabledGroups");
    let outcome = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &reference,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert!(outcome.diagnostics.is_empty(), "{outcome:?}");
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.status.disabledGroups",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_method_through_named_receiver_field() {
    let source = r#"package consumer

type Helper struct{}
func (h Helper) UpdatePackageMetadata() error { return nil }
type Client struct { npmMetadataHelper Helper }
func (c *Client) Build() error {
    return c.npmMetadataHelper.UpdatePackageMetadata()
}
"#;
    let (fixture, analyzer) = fixture(source);

    let field = resolve_last(&analyzer, &fixture, CALLER, source, "npmMetadataHelper");
    assert_eq!(field.status, DefinitionLookupStatus::Resolved, "{field:?}");
    assert_eq!(field.definitions.len(), 1, "{field:?}");
    assert_eq!(
        field.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Client.npmMetadataHelper",
        "{field:?}"
    );

    let method = resolve_last(&analyzer, &fixture, CALLER, source, "UpdatePackageMetadata");
    assert_eq!(
        method.status,
        DefinitionLookupStatus::Resolved,
        "{method:?}"
    );
    assert_eq!(method.definitions.len(), 1, "{method:?}");
    assert_eq!(
        method.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Helper.UpdatePackageMetadata",
        "{method:?}"
    );
}

#[test]
fn go_native_point_types_direct_field_uses_the_selected_receiver_route() {
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

    let source = r#"package consumer

type baselineState struct { collect []string }
func (b *baselineState) values() []string { return b.collect }
"#;
    let (fixture, analyzer) = fixture(source);
    let definition = resolve_last(&analyzer, &fixture, CALLER, source, "collect");

    assert_eq!(
        definition.status,
        DefinitionLookupStatus::Resolved,
        "the receiver's exact direct field yields a complete typed route: {definition:?}"
    );
    assert_eq!(definition.definitions.len(), 1, "{definition:?}");
    assert_eq!(
        definition.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.baselineState.collect",
        "{definition:?}"
    );

    let file = fixture.file(CALLER);
    let site = site_for(source, "collect");
    let result = resolve_go_type_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:?}");
    assert_eq!(value.types.len(), 1, "{value:?}");
    assert_eq!(value.types[0].fqn, "[]string", "{value:?}");
}

#[test]
fn go_native_type_resolves_cross_file_named_parameter_and_local_types() {
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

    let types = r#"package main

type counters struct { total int }
type inner struct { counters counters }
type holder struct { inner *inner }
"#;
    let source = r#"package main

func update(holding *holder) {
    _ = holding.inner.counters
}

func local() {
    holding := &holder{inner: &inner{}}
    _ = holding.inner.counters
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file("types.go", types)
        .file("use.go", source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("use.go");
    let first_chain = source.find("holding.inner.counters").unwrap();
    let local_chain = source.rfind("holding.inner.counters").unwrap();

    for (name, start_byte, expected) in [
        ("holding", first_chain, "*example.test/native.holder"),
        ("holding", local_chain, "*example.test/native.holder"),
    ] {
        let site = ResolvedReferenceSite {
            path: "use.go".into(),
            text: name.into(),
            range: Range {
                start_byte,
                end_byte: start_byte + name.len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + name.len(),
        };
        let result = resolve_go_type_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        );
        let BoundedResolution::Complete { value, .. } = result else {
            panic!("type lookup for {name} did not complete: {result:?}")
        };
        assert_eq!(
            value.status,
            TypeLookupStatus::Resolved,
            "{name}: {value:?}"
        );
        assert_eq!(value.types.len(), 1, "{name}: {value:?}");
        assert_eq!(value.types[0].fqn, expected, "{name}: {value:?}");
    }
}

#[test]
fn go_native_point_types_common_operators_and_contextual_nil() {
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

    let source = r#"package consumer

func use(x int, y int, text string, enabled bool, pointer *int) {
    summed := x + y
    added := x + 1
    less := x < 1
    joined := text + "!"
    both := enabled && true
    either := enabled || false
    negated := -x
    positive := +x
    complement := ^x
    inverted := !enabled
    pointer = nil
    _ = []any{summed, added, less, joined, both, either, negated, positive, complement, inverted, pointer}
}
"#;
    let (fixture, analyzer) = fixture(source);

    for (name, expected) in [
        ("summed", "int"),
        ("added", "int"),
        ("less", "bool"),
        ("joined", "string"),
        ("both", "bool"),
        ("either", "bool"),
        ("negated", "int"),
        ("positive", "int"),
        ("complement", "int"),
        ("inverted", "bool"),
    ] {
        let site = site_for(source, name);
        let file = fixture.file(CALLER);
        let result = resolve_go_type_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        );
        let BoundedResolution::Complete { value, .. } = result else {
            panic!("type of {name} did not complete: {result:?}")
        };
        assert_eq!(
            value.status,
            TypeLookupStatus::Resolved,
            "{name}: {value:?}"
        );
        assert_eq!(value.types.len(), 1, "{name}: {value:?}");
        assert_eq!(value.types[0].fqn, expected, "{name}: {value:?}");
    }

    let site = site_for(source, "pointer");
    let file = fixture.file(CALLER);
    let result = resolve_go_type_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("contextual nil assignment did not retain its pointer type: {result:?}")
    };
    assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:?}");
    assert_eq!(value.types.len(), 1, "{value:?}");
    assert_eq!(value.types[0].fqn, "*int", "{value:?}");
}

#[test]
fn go_native_point_resolves_exact_shallower_field_with_complete_package_inventory() {
    let source = r#"package consumer

type C struct { ID string }
type B struct { C }
type A struct { ID string }
type Service struct { A; B }
func use(s Service) { _ = s.ID }
"#;
    let (fixture, analyzer) = fixture(source);
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "ID");

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.A.ID",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_lowers_anonymous_struct_type_body_owner() {
    let source = "package consumer\ntype Item struct{}\nvar value struct { Field Item }\n";
    let (fixture, analyzer) = fixture(source);
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Item");

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Item",
        "the field type reference inside the anonymous TypeBody retains its package target"
    );
}

#[test]
#[hardwon("0a185cf6f3eb: build-constrained package siblings lost native point incompleteness")]
fn go_native_point_keeps_frontier_open_for_unplaced_package_file() {
    let source = r#"package consumer

type C struct { ID string }
type B struct { C }
type A struct { ID string }
type Service struct { A; B }
func use(s Service) { _ = s.ID }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(PROVIDER, "package vocabulary; type Item struct {}")
        .file(CALLER, source)
        .file(
            "consumer/build_constrained.go",
            "//go:build bifrost_unselected\n\npackage consumer\n\nfunc (Service) ID() {}\n",
        )
        .file("decoy/item.go", "package vocabulary; type Item struct {}")
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let snapshot = analyzer
        .inner
        .selected_workspace_snapshots()
        .get("go")
        .cloned()
        .expect("selected Go snapshot");
    let profile = analyzer.context_profile_for_test().expect("Go profile");
    let context = analyzer
        .inner
        .analyzer_store()
        .selected_go_context(&snapshot, &profile)
        .unwrap()
        .expect("selected Go package context");
    // Reproduce a selected package publication that marks its member inventory
    // complete even though a saved sibling carries a build constraint.
    brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::mark_go_package_complete_for_test(
            analyzer.inner.analyzer_store(),
            context.context_id,
            "example.test/native/consumer",
        )
        .unwrap();
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "ID");

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "the excluded same-package method could shadow the promoted field: {outcome:?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "go-package-incomplete"),
        "the unplaced file must keep the structured package frontier open: {outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.A.ID",
        "the selected build's visible promoted field remains a partial answer"
    );
}

const REFUSED_SIBLING_CALLER: &str = r#"package consumer

type C struct { ID string }
type B struct { C }
type A struct { ID string }
type Service struct { A; B }
func use(s Service) { _ = s.ID }
"#;

/// An ordinary same-package file whose one long line makes source admission
/// refuse it. It is not indexed, so its `ID` method is invisible, yet it would
/// shadow the promoted field.
fn refused_package_member_fixture() -> crate::inline_project::BuiltInlineTestProject {
    let refused = format!(
        "package consumer\n\nfunc (Service) ID() {{}}\n\nvar blob = `{}`\n",
        "A".repeat(20_000)
    );
    InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(PROVIDER, "package vocabulary; type Item struct {}")
        .file(CALLER, REFUSED_SIBLING_CALLER)
        .file("consumer/refused.go", refused.as_str())
        .build()
}

fn assert_refused_member_keeps_frontier_open(outcome: &DefinitionLookupOutcome) {
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "the refused same-package method could shadow the promoted field: {outcome:?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "go-package-incomplete"),
        "the refused file must keep the structured package frontier open: {outcome:?}"
    );
}

#[test]
#[hardwon("#6650: a package member refused by source admission left same-package lookups complete")]
fn go_native_point_keeps_frontier_open_for_refused_package_file() {
    let fixture = refused_package_member_fixture();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, REFUSED_SIBLING_CALLER, "ID");
    assert_refused_member_keeps_frontier_open(&outcome);
}

#[test]
#[hardwon(
    "#6650: the tool context renamed the gap of an unselected member, hiding it from lookups"
)]
fn go_native_point_keeps_frontier_open_for_refused_package_file_in_tool_context() {
    if !go_toolchain_available() {
        eprintln!(
            "the tool-published context needs a Go toolchain; the toolless test covers the inventory"
        );
        return;
    }
    let fixture = refused_package_member_fixture();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    crate::analyzer::go::activate_go_tool_context_for_test(&fixture, &analyzer);
    let outcome = resolve_last(&analyzer, &fixture, CALLER, REFUSED_SIBLING_CALLER, "ID");
    assert_refused_member_keeps_frontier_open(&outcome);
}

#[test]
fn go_native_point_reports_shared_promoted_field_paths_as_ambiguous() {
    let source = r#"package consumer

type Shared struct{ ID string }
type Left struct{ Shared }
type Right struct{ Shared }
type Model struct{ Left; Right }

func use(model Model) { _ = model.ID }
"#;
    let (fixture, analyzer) = fixture(source);
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "ID");

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "{outcome:?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "ambiguous_definition"),
        "{outcome:?}"
    );
}

// A known range receiver and a promoted receiver must keep the same answer
// when unrelated methods share the spelling. The generic decoy's owner proof
// is deliberately unknown and must keep its ordinary demand path.
#[test]
fn go_native_point_owner_demand_keeps_direct_and_promoted_answers() {
    for (receiver, expected) in [("Good", "Good"), ("Wrapper", "Good")] {
        let source = format!(
            "package consumer; type Good struct {{}}; type Wrapper struct {{ Good }}; func (Good) Name() string {{ return \"good\" }}; func use(values []{receiver}) string {{ for _, value := range values {{ return value.Name() }}; return \"\" }}"
        );
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/native\n\ngo 1.22\n")
            .file(CALLER, &source)
            .file("consumer/decoy.go", "package consumer; type Decoy struct {}; func (Decoy) Name() string { return \"decoy\" }; type Generic[T any] struct {}; func (Generic[T]) Name() string { return \"generic\" }")
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        let outcome = resolve_last(&analyzer, &fixture, CALLER, &source, "Name");
        assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            format!("example.test/native/consumer.{expected}.Name"),
            "{outcome:?}"
        );
    }
}

#[test]
fn go_native_point_resolves_direct_method_selection() {
    let source = "package consumer; type Service struct {}; func (Service) Run() {}; func caller(service Service) { service.Run() }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Run");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Service.Run",
        "{outcome:?}"
    );
}

#[test]
#[hardwon(
    "1476df13bd6d: cli/cli pkg/cmd/discussion/comment/comment.go:148:17: function-valued field calls panic on positioned Go prefix metadata"
)]
fn go_native_point_function_valued_field_call_does_not_panic() {
    if !go_toolchain_available() {
        return;
    }
    let source = r#"package consumer
import "fmt"
type Options struct { Client func() (fmt.Stringer, error) }
func run(opts *Options) { c, err := opts.Client(); _, _ = c, err }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let config = AnalyzerConfig {
        go: GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                mode: GoDependencyDiscoveryMode::FullProduction,
                ..GoDependencyDiscoveryConfig::default()
            },
        },
        ..AnalyzerConfig::default()
    };
    let workspace = fixture.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
    let activation = SemanticModelActivationRequest {
        approximate_standard_libraries: Vec::new(),
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let cancellation = CancellationToken::default();
    let discovery = workspace.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Go],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    assert_go_discovery_completed(&discovery);
    let analyzer = workspace.analyzer();
    let file = fixture.file(CALLER);
    let point = site_for(source, "Client");
    let outcome = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer,
            file: &file,
            source,
            tree: None,
            site: &point,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: Some(&cancellation),
        },
        || {},
    ));
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Options.Client",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_method_expressions_with_exact_method_sets() {
    let caller_source = r#"package consumer

type Widget struct{}
func (Widget) Value() {}
func (*Widget) Pointer() {}

func caller(value Widget) {
	Widget.Value(value)
	(*Widget).Value(&value)
	(*Widget).Pointer(&value)
	Widget.Pointer(value)
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, caller_source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    crate::analyzer::go::persist_live_go_sources_for_test(&analyzer);

    let first_method_expression = "Widget.Value";
    let type_reference_start = caller_source.find(first_method_expression).unwrap();
    let type_outcome = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        caller_source,
        type_reference_start,
        "Widget",
    );
    assert_eq!(type_outcome.definitions.len(), 1, "{type_outcome:?}");
    assert_eq!(
        type_outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Widget",
        "the method-expression type resolves through its lexical declaration"
    );

    for (selector, expected) in [
        ("Widget.Value", "example.test/native/consumer.Widget.Value"),
        (
            "(*Widget).Value",
            "example.test/native/consumer.Widget.Value",
        ),
        (
            "(*Widget).Pointer",
            "example.test/native/consumer.Widget.Pointer",
        ),
    ] {
        let start_byte = caller_source.find(selector).unwrap() + selector.rfind('.').unwrap() + 1;
        let outcome = resolve_at(
            &analyzer,
            &fixture,
            CALLER,
            caller_source,
            start_byte,
            selector.rsplit('.').next().unwrap(),
        );
        assert_eq!(outcome.definitions.len(), 1, "{selector}: {outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            expected,
            "{selector}: {outcome:?}"
        );
    }

    let pointer_method_on_value_type = "Widget.Pointer";
    let start_byte = caller_source.rfind(pointer_method_on_value_type).unwrap()
        + pointer_method_on_value_type.rfind('.').unwrap()
        + 1;
    let outcome = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        caller_source,
        start_byte,
        "Pointer",
    );
    assert!(
        outcome.definitions.is_empty(),
        "T.M must not select a pointer-receiver method: {outcome:?}"
    );
    assert_ne!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "T.M must remain unresolved when M has only a pointer receiver: {outcome:?}"
    );
}

#[test]
#[hardwon("f24c78ded6c7: Go point receiver frontiers lacked peer-file declared type anchors")]
fn go_native_point_resolves_member_receivers_from_peer_type_anchors() {
    let caller_source = r#"package consumer

func exerciseLoad(getOpts options) {
	getOpts.loader.Load(nil)
	getOpts.loader.Load(nil)
}
"#;
    let test_source = r#"package consumer

func exerciseExpiresAt() {
	cache := NewCache[string, struct{}]()
	updatedItem := cache.Set()
	func() { updatedItem.ExpiresAt() }()
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(
            "consumer/options.go",
            "package consumer\ntype options struct { loader Loader }\n",
        )
        .file(
            "consumer/cache.go",
            "package consumer\n\
             type Loader interface { Load(*Cache) *Item }\n\
             type Cache struct{}\n\
             func NewCache[K comparable, V any]() *Cache { return &Cache{} }\n\
             func (c *Cache) Set() *Item { return &Item{} }\n",
        )
        .file(
            "consumer/item.go",
            "package consumer\ntype Item struct{}\nfunc (i *Item) ExpiresAt() {}\n",
        )
        .file(CALLER, caller_source)
        .file("consumer/cache_test.go", test_source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());

    for ordinal in 0..2 {
        let start_byte = selector_field_start(caller_source, "Load", ordinal);
        let outcome = resolve_at(
            &analyzer,
            &fixture,
            CALLER,
            caller_source,
            start_byte,
            "Load",
        );
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "Load #{ordinal}: {outcome:?}"
        );
        assert!(
            outcome.diagnostics.is_empty(),
            "Load #{ordinal}: {outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "Load #{ordinal}: {outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            "example.test/native/consumer.Loader.Load",
            "Load #{ordinal}: {outcome:?}"
        );
    }

    let start_byte = selector_field_start(test_source, "ExpiresAt", 0);
    let outcome = resolve_at(
        &analyzer,
        &fixture,
        "consumer/cache_test.go",
        test_source,
        start_byte,
        "ExpiresAt",
    );
    assert_eq!(outcome.definitions.len(), 1, "ExpiresAt: {outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Item.ExpiresAt",
        "ExpiresAt: {outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_field_through_range_clause_binder() {
    let source = r#"package history

type History struct { Revision string }

func visit(history []History) {
	for _, history := range history {
		_ = history.Revision
	}
}
"#;
    let path = "history.go";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(path, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, path, source, "Revision");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native.History.Revision",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_type_switch_and_select_case_binders() {
    let source = r#"package consumer

import db "example.test/native/db"

func inspect(value any, input <-chan int) {
    switch db := value.(type) {
    case int:
        _ = db
    default:
        _ = db
    }
    _ = db.Value
    select {
    case db := <-input:
        _ = db
    }
    _ = db.Value
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file("db/db.go", "package db\nvar Value int\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());

    for anchor in [
        "case int:\n        _ = ",
        "default:\n        _ = ",
        "case db := <-input:\n        _ = ",
    ] {
        let start_byte = source.find(anchor).unwrap() + anchor.len();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start_byte, "db");
        assert!(outcome.definitions.is_empty(), "{anchor}: {outcome:?}");
        assert_eq!(
            outcome
                .lexical_definition
                .as_ref()
                .map(|definition| definition.kind),
            Some(brokk_bifrost_core::analyzer::model::DeclarationKind::LocalVariable),
            "{anchor}: {outcome:?}"
        );
    }
}

#[test]
fn go_native_point_resolves_conversion_type_inside_go_1_26_new() {
    let source = "package consumer; type PackageURL struct {}; func FromString(p PackageURL) *PackageURL { return new(PackageURL(p)) }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "PackageURL");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.PackageURL",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_ordinary_new_type_argument() {
    let source = "package consumer; type Row struct {}; func allocate() { _ = new(Row) }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Row");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Row",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_does_not_resolve_shadowed_type_conversion_as_type() {
    let source = "package consumer; type PackageURL struct {}; func convert(PackageURL func(int)) { PackageURL(1) }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "PackageURL");

    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert_eq!(
        outcome
            .lexical_definition
            .as_ref()
            .map(|definition| definition.kind),
        Some(brokk_bifrost_core::analyzer::model::DeclarationKind::Parameter),
        "{outcome:?}"
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_keeps_field_reference_after_go_1_26_new() {
    let source = r#"package consumer

type Row struct {
	limit int
	ents  []int
}

func Build(rows []int, low int, high int) *Row {
	r := &Row{}
	r.limit = *new(max(low, high))
	r.ents = rows
	return r
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "ents");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Row.ents",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_fields_in_named_elided_container_literals() {
    let source = r#"package consumer

type Item struct { Field string }
type NamedArray [2]*Item
type NestedArray [1][1]*Item
type NamedSlice []Item
type NamedMap map[string]Item
type NamedKeyMap map[Item]string

var array = NamedArray{{Field: "array"}}
var nested = NestedArray{{{Field: "nested"}}}
var slice = NamedSlice{{Field: "slice"}}
var mapped = NamedMap{"item": {Field: "map"}}
var keyed = NamedKeyMap{{Field: "key"}: "value"}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());

    for occurrence in [
        "Field: \"array\"",
        "Field: \"nested\"",
        "Field: \"slice\"",
        "Field: \"map\"",
        "Field: \"key\"",
    ] {
        let start_byte = source.find(occurrence).unwrap();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start_byte, "Field");
        assert_eq!(outcome.definitions.len(), 1, "{occurrence}: {outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            "example.test/native/consumer.Item.Field",
            "{occurrence}: {outcome:?}"
        );
    }
}

#[test]
fn go_native_point_distinguishes_nested_map_keys_from_struct_field_labels() {
    let source = r#"package consumer

const NestedKey = "nested"

type Item struct { NestedKey string }

var maps = map[string]map[string]string{
	"outer": {NestedKey: "value"},
}
var direct = NestedKey
var items = map[string]Item{
	"outer": {NestedKey: "field"},
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let direct = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        source,
        source.find("direct = NestedKey").unwrap() + "direct = ".len(),
        "NestedKey",
    );
    assert_eq!(direct.definitions.len(), 1, "{direct:?}");
    let map_key = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        source,
        source.find("NestedKey: \"value\"").unwrap(),
        "NestedKey",
    );
    assert_eq!(map_key.definitions.len(), 1, "{map_key:?}");
    assert!(
        map_key.definitions[0]
            .fq_name()
            .to_string()
            .ends_with("._module_.NestedKey"),
        "{map_key:?}"
    );

    let field = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        source,
        source.find("NestedKey: \"field\"").unwrap(),
        "NestedKey",
    );
    assert_eq!(field.definitions.len(), 1, "{field:?}");
    assert_eq!(
        field.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Item.NestedKey",
        "{field:?}"
    );
}

#[test]
fn go_native_points_project_named_container_components_across_package_files() {
    let types = r#"package consumer

type Item struct { Field int }
type Key struct { KeyField int }
type rowStorage []Item
type Rows rowStorage
type lookupStorage map[Key]Item
type Lookup lookupStorage
type streamStorage chan Item
type ItemStream streamStorage
"#;
    let source = r#"package consumer

func use(rows Rows, lookup Lookup, stream ItemStream) {
	for index, row := range rows { _, _ = index, row.Field }
	for key, value := range lookup { _ = key.KeyField; _ = value.Field }
	for item := range stream { _ = item.Field }
	_ = Rows{{Field: 1}}
	_ = Lookup{Key{KeyField: 3}: {Field: 2}}
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file("consumer/types.go", types)
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());

    for occurrence in [
        "row.Field",
        "key.KeyField",
        "value.Field",
        "item.Field",
        "{Field: 1}",
        "{Field: 2}",
    ] {
        let identifier = if occurrence.contains("KeyField") {
            "KeyField"
        } else {
            "Field"
        };
        let start_byte = source.find(occurrence).unwrap() + occurrence.find(identifier).unwrap();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start_byte, identifier);
        assert_eq!(outcome.definitions.len(), 1, "{occurrence}: {outcome:?}");
        let expected_owner = if identifier == "KeyField" {
            "Key"
        } else {
            "Item"
        };
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            format!("example.test/native/consumer.{expected_owner}.{identifier}"),
            "{occurrence}: {outcome:?}"
        );
    }
}

#[test]
fn go_native_type_preserves_pointer_depth_and_nominal_identity() {
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;
    let source = "package consumer; type T struct{}; func f(Item *T) *T { return Item }";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let site = site(source);
    let result = resolve_go_type_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    assert!(
        matches!(
            value.status,
            TypeLookupStatus::Resolved | TypeLookupStatus::Incomplete
        ),
        "{value:?}"
    );
    assert_eq!(value.types.len(), 1, "{value:?}");
    assert_eq!(value.types[0].definitions.len(), 1);
    let unit = &value.types[0].definitions[0];
    assert_eq!(unit.source(), &file);
    assert_eq!(unit.terminal_name(), "T");
    assert_eq!(value.types[0].fqn, format!("*{}", unit.fq_name()));
}

#[test]
fn go_native_generic_type_answers_match_go_types_with_argument_inference() {
    // Every expected type answer comes from the host `go/types` oracle.
    if !go_toolchain_available() {
        return;
    }
    let source = r#"package consumer

type Number struct{}
type Box[T any] struct { Value T }
type Cache[K comparable, V any] struct { entries map[K]V }
type Item[T any] struct{}
func (c *Cache[Key, Value]) Get() Value { var zero Value; return zero }
func (c *Cache[Key, Value]) Put(key Key, value Value) *Item[Value] { return &Item[Value]{} }
func (item *Item[Value]) ExpiresAt() Value { var zero Value; return zero }
func NewCache[K comparable, V any]() *Cache[K, V] { return &Cache[K, V]{} }
func Echo[T any](value T) T { return value }
func Wrap[T any](value T) []T { return []T{value} }
func Nested[T any](value T) Box[[]T] { return Box[[]T]{Value: []T{value}} }
func use() {
    var boxInt Box[int]
    fieldInt := boxInt.Value
    var boxSlice Box[[]int]
    fieldSlice := boxSlice.Value
    var cache *Cache[string, Number]
    receiverResult := cache.Get()
    constructedCache := NewCache[string, Number]()
    constructedItem := constructedCache.Put("key", Number{})
    constructedResult := constructedItem.ExpiresAt()
    cacheEntries := cache.entries
    identityExplicit := Echo[Number](Number{})
    identityInferred := Echo(Number{})
    sliceResult := Wrap[Number](Number{})
    nestedResult := Nested[Number](Number{})
    inferredNested := InferNested(Box[Box[Number]]{})
    _, _, _, _, _, _, _, _, _, _ = fieldInt, fieldSlice, receiverResult, constructedResult, cacheEntries, identityExplicit, identityInferred, sliceResult, nestedResult, inferredNested
}
func InferNested[T any](box Box[Box[T]]) T { return box.Value.Value }
"#;
    let expected = [
        ("fieldInt", "field-int"),
        ("fieldSlice", "field-slice"),
        ("receiverResult", "receiver-result"),
        ("constructedResult", "constructed-result"),
        ("cacheEntries", "cache-entries"),
        ("identityExplicit", "identity-explicit"),
        ("identityInferred", "identity-inferred"),
        ("sliceResult", "slice-result"),
        ("nestedResult", "nested-result"),
        ("inferredNested", "inferred-nested"),
    ];
    let oracle = go_types_generic_answers(source);
    let (fixture, analyzer) = fixture(source);

    let type_reference_start = source.find("Value T").unwrap() + "Value ".len();
    let type_reference_site = ResolvedReferenceSite {
        path: CALLER.into(),
        text: "T".into(),
        range: Range {
            start_byte: type_reference_start,
            end_byte: type_reference_start + 1,
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: type_reference_start,
        focus_end_byte: type_reference_start + 1,
    };
    let type_reference = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &fixture.file(CALLER),
            source,
            tree: Some(
                &crate::analyzer::usages::get_definition::go::parse_go_tree(source)
                    .expect("parse generic type reference"),
            ),
            site: &type_reference_site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        type_reference.status,
        DefinitionLookupStatus::Resolved,
        "Box.Value's T reference resolves to its scoped generic formal: {type_reference:?}"
    );
    let lexical_formal = type_reference
        .lexical_definition
        .as_ref()
        .expect("the selected generic formal is a lexical declaration");
    assert_eq!(lexical_formal.identifier, "T");
    assert_eq!(
        &source[lexical_formal.name_range.start_byte..lexical_formal.name_range.end_byte],
        "T"
    );

    let get_tree = crate::analyzer::usages::get_definition::go::parse_go_tree(source)
        .expect("parse generic receiver result type");
    let mut pending = vec![get_tree.root_node()];
    let get_node = loop {
        let node = pending.pop().expect("Get has a method declaration");
        if node
            .child_by_field_name("name")
            .is_some_and(|name| name.utf8_text(source.as_bytes()).ok() == Some("Get"))
        {
            break node;
        }
        pending.extend((0..node.named_child_count()).filter_map(|i| node.named_child(i)));
    };
    let result_type = get_node
        .child_by_field_name("result")
        .expect("Get has a result type");
    let result_start = result_type.start_byte();
    let result_site = ResolvedReferenceSite {
        path: CALLER.into(),
        text: "Value".into(),
        range: Range {
            start_byte: result_start,
            end_byte: result_type.end_byte(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: result_start,
        focus_end_byte: result_type.end_byte(),
    };
    let result_definition = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &fixture.file(CALLER),
            source,
            tree: Some(&get_tree),
            site: &result_site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        result_definition.status,
        DefinitionLookupStatus::Resolved,
        "the renamed receiver formal binds inside the method result: {result_definition:?}"
    );
    assert_eq!(
        result_definition
            .lexical_definition
            .as_ref()
            .map(|definition| definition.identifier.as_str()),
        Some("Value")
    );

    let file = fixture.file(CALLER);
    let cancellation = CancellationToken::default();
    let mut native_request = match GoNativePointRequest::open(
        &analyzer,
        analyzer.inner.semantic_model_overlay(),
        &cancellation,
    )
    .expect("open the selected native Go point operation")
    {
        GoNativePointRequestOpen::Ready(request) => request,
        GoNativePointRequestOpen::Unavailable { kind, message } => {
            panic!("native Go point operation unavailable: {kind}: {message}")
        }
        GoNativePointRequestOpen::Cancelled => panic!("native Go point operation cancelled"),
    };

    for (declaration, oracle_key) in expected {
        let expected_type = &oracle[oracle_key];
        let (start, query_text) = match declaration {
            "fieldInt" => (selector_field_start(source, "Value", 0), "Value"),
            "fieldSlice" => (selector_field_start(source, "Value", 1), "Value"),
            "cacheEntries" => (selector_field_start(source, "entries", 0), "entries"),
            "receiverResult" => (source.find("cache.Get()").unwrap() + "cache.".len(), "Get"),
            "constructedResult" => (
                source.rfind("constructedItem.ExpiresAt()").unwrap() + "constructedItem.".len(),
                "ExpiresAt",
            ),
            "identityExplicit" => (source.find("Echo[Number]").unwrap(), "Echo"),
            "identityInferred" => (source.find("Echo(Number").unwrap(), "Echo"),
            "sliceResult" => (source.find("Wrap[Number]").unwrap(), "Wrap"),
            "nestedResult" => (source.find("Nested[Number]").unwrap(), "Nested"),
            "inferredNested" => (source.find("InferNested(Box").unwrap(), "InferNested"),
            _ => unreachable!("every oracle case has a selected expression"),
        };
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: query_text.into(),
            range: Range {
                start_byte: start,
                end_byte: start + query_text.len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start,
            focus_end_byte: start + query_text.len(),
        };
        let result = native_request.resolve_type(BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
            cancellation: Some(&cancellation),
        });
        let BoundedResolution::Complete { value: answer, .. } = result else {
            panic!("{declaration}: {result:?}")
        };
        assert_eq!(
            answer.status,
            brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus::Resolved,
            "{declaration} differs from go/types {expected_type}: {answer:?}"
        );
        assert_eq!(answer.types.len(), 1, "{declaration}: {answer:?}");
        assert_eq!(
            answer.types[0].fqn, *expected_type,
            "{declaration}: {answer:?}"
        );
    }
}

#[test]
fn go_native_point_keeps_generic_call_result_incomplete() {
    let source = r#"package consumer

type Result struct{}
func (Result) Maybe() {}
func Identity[T any](value T) T { return value }
func use() { Identity(Result{}).Maybe() }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Maybe");

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
}

#[test]
fn go_native_generic_inference_uses_fixed_arguments_on_variadic_signatures() {
    // The `go test` oracle below compiles the fixture with the host compiler.
    if !go_toolchain_available() {
        return;
    }
    let source = r#"package consumer

type Number struct{}
type Box[T any] struct { Value T }
func InferVariadic[T any](box Box[T], ignored ...T) T { return box.Value }
func use() {
    ignored := []Number{}
    result := InferVariadic(Box[Number]{}, ignored...)
    var _ Number = result
}
"#;
    let oracle_dir = tempfile::tempdir().expect("Go compiler oracle directory");
    std::fs::write(oracle_dir.path().join("variadic.go"), source)
        .expect("write variadic generic compiler oracle");
    let oracle = std::process::Command::new("go")
        .arg("test")
        .current_dir(oracle_dir.path())
        .env("GO111MODULE", "off")
        .output()
        .expect("the local Go compiler runs the variadic generic oracle");
    assert!(
        oracle.status.success(),
        "Go compiler rejected the inferred Number result: {}",
        String::from_utf8_lossy(&oracle.stderr)
    );

    let (fixture, analyzer) = fixture(source);
    let cancellation = CancellationToken::default();
    let mut native_request = match GoNativePointRequest::open(
        &analyzer,
        analyzer.inner.semantic_model_overlay(),
        &cancellation,
    )
    .expect("open selected native Go point operation")
    {
        GoNativePointRequestOpen::Ready(request) => request,
        GoNativePointRequestOpen::Unavailable { kind, message } => {
            panic!("native Go point operation unavailable: {kind}: {message}")
        }
        GoNativePointRequestOpen::Cancelled => panic!("native Go point operation cancelled"),
    };
    let start = source
        .find("InferVariadic(Box")
        .expect("variadic call expression");
    let site = ResolvedReferenceSite {
        path: CALLER.into(),
        text: "InferVariadic".into(),
        range: Range {
            start_byte: start,
            end_byte: start + "InferVariadic".len(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start,
        focus_end_byte: start + "InferVariadic".len(),
    };
    let BoundedResolution::Complete { value, .. } =
        native_request.resolve_type(BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &fixture.file(CALLER),
            source,
            tree: None,
            site: &site,
            budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
            cancellation: Some(&cancellation),
        })
    else {
        panic!("variadic generic type lookup did not complete")
    };
    assert_eq!(
        value.status,
        brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus::Resolved,
        "fixed generic parameter must determine the call result: {value:?}"
    );
    assert_eq!(value.types.len(), 1, "{value:?}");
    assert_eq!(
        value.types[0].fqn, "example.test/native/consumer.Number",
        "Go compiler accepted assignment of the result to Number"
    );
}

#[test]
#[hardwon("#5015: reassignment joins changed the Loader method-value work frontier")]
fn go_native_propagates_options_result_to_loader_method_value() {
    // The `go test` oracle below compiles the fixture with the host compiler.
    if !go_toolchain_available() {
        return;
    }
    let source = r#"package consumer

type Loader[K comparable, V any] interface {
    Load(cache *Cache[K, V], key K) *Item[K, V]
}
type Option[K comparable, V any] interface {
    apply(value options[K, V]) options[K, V]
}
type options[K comparable, V any] struct {
    loader Loader[K, V]
}
func applyOptions[K comparable, V any](value options[K, V], values ...Option[K, V]) options[K, V] {
    return value
}
type Item[K comparable, V any] struct{}
type Cache[K comparable, V any] struct {
    options options[K, V]
}
func (cache *Cache[K, V]) get(key K, values ...Option[K, V]) *Item[K, V] {
    getOpts := options[K, V]{loader: cache.options.loader}
    getOpts = applyOptions(getOpts, values...)
    _ = getOpts.loader.Load
    return getOpts.loader.Load(cache, key)
}
"#;
    let oracle_dir = tempfile::tempdir().expect("Go compiler oracle directory");
    std::fs::write(oracle_dir.path().join("cache.go"), source)
        .expect("write generic options fixture for Go compiler oracle");
    let oracle = std::process::Command::new("go")
        .arg("test")
        .current_dir(oracle_dir.path())
        .env("GO111MODULE", "off")
        .output()
        .expect("the local Go compiler runs the generic options oracle");
    assert!(
        oracle.status.success(),
        "Go compiler rejected the options[K,V] call: {}",
        String::from_utf8_lossy(&oracle.stderr)
    );

    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file("cache.go", source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let resolve_at = |start_byte: usize, budget: ReceiverAnalysisBudget| {
        let site = ResolvedReferenceSite {
            path: "cache.go".into(),
            text: "Load".into(),
            range: Range {
                start_byte,
                end_byte: start_byte + "Load".len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "Load".len(),
        };
        resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &fixture.file("cache.go"),
                source,
                tree: None,
                site: &site,
                budget,
                cancellation: None,
            },
            || {},
        )
    };
    let definition_at = |start_byte: usize, budget: ReceiverAnalysisBudget| {
        complete(resolve_at(start_byte, budget))
    };
    let method_value_start = source
        .find("_ = getOpts.loader.Load")
        .expect("generic Loader.Load method value")
        + "_ = getOpts.loader.".len();
    let default_method_value = resolve_at(method_value_start, ReceiverAnalysisBudget::default());
    let BoundedResolution::Complete {
        value: default_value,
        work: default_work,
    } = default_method_value
    else {
        panic!("default owner budget must complete the method-value query");
    };
    assert_eq!(default_value.status, DefinitionLookupStatus::Resolved);
    // The local value join follows both the options initializer and the
    // applyOptions write, including receiver arguments and defaults. Keep an
    // exact work pin so repeated expansion of that frontier remains visible.
    // The `options options[K, V]` field type resolves to the type directly
    // since #6925 kept field names out of type-syntax lookup.
    // Import-free point requests now use demand scheduling too. Keep its
    // work pinned alongside the exact method-value answer below.
    let expected_resolution_rounds = 107;
    assert_eq!(default_work.resolution_rounds, expected_resolution_rounds);
    let wide_method_value = resolve_at(
        method_value_start,
        ReceiverAnalysisBudget {
            max_summary_expansions: 512,
            max_scope_nodes: 16_384,
            ..ReceiverAnalysisBudget::default()
        },
    );
    let (method_value, method_value_work) = match wide_method_value {
        BoundedResolution::Complete { value, work } => (value, work),
        other => panic!("wide-budget method-value query did not finish: {other:?}"),
    };
    assert_eq!(
        method_value_work.resolution_rounds,
        expected_resolution_rounds
    );
    assert_eq!(
        method_value.status,
        DefinitionLookupStatus::Resolved,
        "the exact generic Loader receiver resolves without call applicability: {method_value:?}"
    );
    assert_eq!(method_value.definitions.len(), 1, "{method_value:?}");
    assert_eq!(default_value.definitions, method_value.definitions);
    assert_eq!(
        method_value.definitions[0].fq_name().to_string(),
        "example.test/native.Loader.Load",
        "{method_value:?}"
    );
    let invocation_start = source
        .rfind("getOpts.loader.Load(cache, key)")
        .expect("generic Loader.Load invocation")
        + "getOpts.loader.".len();
    let invocation = definition_at(
        invocation_start,
        ReceiverAnalysisBudget {
            max_summary_expansions: 512,
            max_scope_nodes: 16_384,
            ..ReceiverAnalysisBudget::default()
        },
    );
    assert_eq!(
        invocation.status,
        DefinitionLookupStatus::Resolved,
        "the static method binding is known; only Go interface dispatch remains open: {invocation:?}"
    );
    assert_eq!(invocation.definitions, method_value.definitions);
}

#[test]
fn go_native_point_projects_each_multi_result_call_position() {
    let source = r#"package consumer

type First struct{}
func (First) FirstResult() {}
type Second struct{}
func (Second) SecondResult() {}

func Pair() (First, Second) { return First{}, Second{} }
func use() {
    first, second := Pair()
    first.FirstResult()
    second.SecondResult()
}

#[test]
fn go_native_point_projects_results_of_function_typed_values() {
    let source = r#"package consumer

type Result struct{}
func (Result) FromFunctionValue() {}
func use(function func() Result) {
    function().FromFunctionValue()
}

#[test]
fn go_native_point_resolves_call_results_through_intermediate_and_promoted_types() {
    const CALLER_PATH: &str = "consumer/use.go";
    let caller = r#"package consumer

import api "example.test/native/api"

func use() {
    value := api.GetDirect()
    value.FromIntermediate()
    api.GetPromoted().FromPromoted()
}

#[test]
fn go_native_point_resolves_declared_function_and_method_call_results() {
    let source = r#"package consumer

type DirectType struct{}
func (DirectType) FromFunction() {}
func MakeDirect() DirectType { return DirectType{} }

type MethodType struct{}
func (MethodType) FromMethod() {}
type Factory struct{}
func (Factory) Get() MethodType { return MethodType{} }

type AssignedType struct{}
func (AssignedType) FromAssignment() {}
func MakeAssigned() AssignedType { return AssignedType{} }

func use(factory Factory) {
    MakeDirect().FromFunction()
    factory.Get().FromMethod()
    value := MakeAssigned()
    value.FromAssignment()
}

#[test]
fn go_native_point_resolves_fields_on_call_results() {
    let source = r#"package consumer

type Result struct{ Name string }
func Detect() Result { return Result{} }
func use() { _ = Detect().Name }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Name");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Result.Name",
        "{outcome:?}"
    );
}

#[test]
#[hardwon(
    "6c6570acd34a: a binder of a multi-value call's first result stayed Unknown (cli usages row 924)"
)]
fn go_native_point_resolves_first_result_of_multi_value_call_member() {
    let source = r#"package consumer

type Options struct{}
type CreateContext struct{}

func (c *CreateContext) Run() {}

func NewCreateContext(opts *Options) (*CreateContext, error) { return &CreateContext{}, nil }

func createRun(opts *Options) error {
	ctx, err := NewCreateContext(opts)
	if err != nil {
		return err
	}
	ctx.Run()
	return nil
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file("consumer/create.go", source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let start_byte = selector_field_start(source, "Run", 0);
    let outcome = resolve_at(
        &analyzer,
        &fixture,
        "consumer/create.go",
        source,
        start_byte,
        "Run",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.CreateContext.Run",
        "{outcome:?}"
    );
}

#[test]
#[hardwon(
    "a25945887125: a Go type-name site answered the named type natively where the incumbent answers no_type"
)]
fn go_native_type_name_site_answers_no_type_like_the_incumbent() {
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;
    let source = "package consumer; import renamed \"example.test/native/provider\"; func f(values []renamed.Item) {}";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let site = site(source);
    let result = resolve_go_type_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    assert_eq!(value.status, TypeLookupStatus::NoType, "{value:?}");
    assert!(value.types.is_empty(), "{value:?}");
    assert_eq!(value.diagnostics.len(), 1, "{value:?}");
    assert_eq!(
        value.diagnostics[0].kind, "go_no_supported_type",
        "{value:?}"
    );
    assert_eq!(
        value.diagnostics[0].message, "`Item` does not have a supported explicit Go type",
        "{value:?}"
    );
}

#[test]
#[hardwon(
    "#5074: anonymous table row receivers had no source field bridge and local test owners had no projection"
)]
fn go_native_point_resolves_anonymous_table_rows_and_local_type_owners() {
    let source = r#"package consumer
 type Options struct{}
 func (*Options) Run() {}
 type Client struct{}
 func (*Client) Send() {}
 func TestCreate() {
     tests := []struct { opts *Options; ctx struct { Client *Client } }{}
     for _, tt := range tests {
         opts := tt.opts
         opts.Run()
         tt.ctx.Client.Send()
     }
     type localOptions struct { opts *Options }
     local := localOptions{}
     local.opts.Run()
 }
"#;
    let (fixture, analyzer) = fixture(source);
    for (start, needle, expected) in [
        (
            source.find("opts.Run").unwrap() + "opts.".len(),
            "Run",
            "example.test/native/consumer.Options.Run",
        ),
        (
            source.find("Client.Send").unwrap() + "Client.".len(),
            "Send",
            "example.test/native/consumer.Client.Send",
        ),
        (
            source.rfind("local.opts.Run").unwrap() + "local.opts.".len(),
            "Run",
            "example.test/native/consumer.Options.Run",
        ),
    ] {
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start, needle);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:#?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
        assert_eq!(outcome.definitions[0].fq_name().to_string(), expected);
    }
    let owner = resolve_last(&analyzer, &fixture, CALLER, source, "localOptions");
    assert_eq!(owner.status, DefinitionLookupStatus::Resolved, "{owner:#?}");
    assert_eq!(owner.definitions.len(), 1, "{owner:#?}");
    assert_eq!(owner.definitions[0].identifier(), "localOptions");
}

#[test]
#[hardwon(
    "#6524: interface method names hid signature types; parenthesized conversions lost their type"
)]
fn go_native_interface_method_names_do_not_hide_signature_types() {
    let source = r#"package consumer
import vocabulary "example.test/native/provider"
type Result struct{}
type I interface {
    Result(Result) Result
    Item(vocabulary.Item) vocabulary.Item
}
type S struct { Result Result }
"#;
    let (fixture, analyzer) = fixture(source);
    for (needle, reference, expected_file, expected_name) in [
        ("Result) Result", "Result", CALLER, "Result"),
        ("Result\n", "Result", CALLER, "Result"),
        ("Item) vocabulary", "Item", PROVIDER, "Item"),
        ("Item\n", "Item", PROVIDER, "Item"),
        ("Result }", "Result", CALLER, "Result"),
    ] {
        let start = source.find(needle).unwrap();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start, reference);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{needle}: {outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{needle}: {outcome:?}");
        assert_eq!(
            outcome.definitions[0].source(),
            &fixture.file(expected_file)
        );
        assert_eq!(outcome.definitions[0].terminal_name(), expected_name);
        if expected_name == "Result" {
            assert!(outcome.definitions[0].is_class(), "{needle}: {outcome:?}");
        }
    }
}

#[test]
#[hardwon(
    "#6524: interface method names hid signature types; parenthesized conversions lost their type"
)]
#[hardwon("#7517: retyped parenthesized Go callees retained invalid field receiver origins")]
fn go_native_parenthesized_conversions_preserve_type_targets() {
    let source = r#"package consumer
import vocabulary "example.test/native/provider"
type Result struct{}
func identity(value Result) Result { return value }
func use(value Result, imported vocabulary.Item) {
    localPointer := (*Result)(nil)
    importedPointer := (*vocabulary.Item)(nil)
    localValue := (Result)(value)
    importedValue := (vocabulary.Item)(imported)
    functionValue := (identity)(value)
    _, _, _, _, _ = localPointer, importedPointer, localValue, importedValue, functionValue
}
"#;
    let (fixture, analyzer) = fixture(source);
    for (needle, reference, expected_file, expected_name) in [
        ("Result)(nil)", "Result", CALLER, "Result"),
        ("Item)(nil)", "Item", PROVIDER, "Item"),
        ("Result)(value)", "Result", CALLER, "Result"),
        ("Item)(imported)", "Item", PROVIDER, "Item"),
        ("identity)(value)", "identity", CALLER, "identity"),
    ] {
        let start = source.find(needle).unwrap();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start, reference);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{needle}: {outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{needle}: {outcome:?}");
        assert_eq!(
            outcome.definitions[0].source(),
            &fixture.file(expected_file)
        );
        assert_eq!(outcome.definitions[0].terminal_name(), expected_name);
        if expected_name == "Result" {
            assert!(outcome.definitions[0].is_class(), "{needle}: {outcome:?}");
        }
    }
    for (name, pointer, imported) in [
        ("localPointer", true, false),
        ("importedPointer", true, true),
        ("localValue", false, false),
        ("importedValue", false, true),
        ("functionValue", false, false),
    ] {
        let file = fixture.file(CALLER);
        let site = site_for(source, name);
        let result = resolve_go_type_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        );
        let BoundedResolution::Complete { value, .. } = result else {
            panic!("{name}: {result:?}");
        };
        assert_eq!(value.types.len(), 1, "{name}: {value:?}");
        let expected_file = fixture.file(if imported { PROVIDER } else { CALLER });
        assert_eq!(value.types[0].definitions.len(), 1, "{name}: {value:?}");
        let target = &value.types[0].definitions[0];
        assert_eq!(target.source(), &expected_file, "{name}: {value:?}");
        assert_eq!(
            target.terminal_name(),
            if imported { "Item" } else { "Result" }
        );
        assert_eq!(
            value.types[0].fqn,
            format!("{}{}", if pointer { "*" } else { "" }, target.fq_name()),
            "{name}: {value:?}"
        );
    }
}

#[test]
#[hardwon("#6482: superseding a bound interval must not certify an empty native answer")]
fn go_native_point_reports_superseded_interval_context() {
    let source = r#"package consumer; import renamed "example.test/native/provider"; var Value renamed.Item"#;
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let site = site(source);
    let query = BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source,
        tree: None,
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    };
    let before = complete(resolve_go_definition_bounded(query, || {}));
    assert_eq!(
        before.status,
        DefinitionLookupStatus::Resolved,
        "{before:?}"
    );
    let cancellation = CancellationToken::new();
    let GoNativePointRequestOpen::Ready(mut empty_request) =
        GoNativePointRequest::open_for_file(&analyzer, query.file, None, &cancellation).unwrap()
    else {
        panic!("the zero-row request must bind the current context before supersession");
    };
    let snapshot = analyzer.selected_snapshot_for_test().unwrap();
    let profile = analyzer.context_profile_for_test().unwrap();
    let outcome = complete(resolve_go_definition_bounded(query, || {
        let store = analyzer.inner.analyzer_store();
        let context = store
            .selected_go_context(&snapshot, &profile)
            .unwrap()
            .unwrap();
        store.conn.execute(move |conn| {
            assert_eq!(conn.execute("UPDATE go_context_publications SET valid_until=?2 WHERE context_id=?1 AND valid_until IS NULL", rusqlite::params![context.context_id, snapshot.revision]).unwrap(), 1);
        });
        assert!(
            analyzer
                .inner
                .analyzer_store()
                .selected_go_context(&snapshot, &profile)
                .unwrap()
                .is_none()
        );
    }));
    let empty = empty_request
        .operation
        .finish_native(
            Vec::<()>::new(),
            &brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion::Complete,
            &cancellation,
        )
        .unwrap();
    assert!(matches!(empty, SelectedResolutionOperationOutcome::Stale(
        brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionStale::NativeContextPublication { .. }
    )), "a superseded context cannot publish an empty native result");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "native_stale"
                && diagnostic.message.contains("NativeContextPublication")),
        "{outcome:?}"
    );
}

#[test]
#[hardwon(
    "#6524: build-excluded methods entered deferred lookup and made an interface binding incomplete"
)]
#[hardwon("#6524: a build-excluded method kept promoted-field lookup incomplete")]
fn go_native_point_excludes_nonparticipating_deferred_methods() {
    if !go_toolchain_available() {
        return;
    }
    let interface_source = r#"package consumer
import "sync"
var _ sync.Mutex
func shutdown(inner pluginClient) { inner.Shutdown() }
"#;
    let interface_declaration = "package consumer; type pluginClient interface { Shutdown() }";
    let interface_target = "example.test/native/consumer.pluginClient.Shutdown";
    for (source, declarations, implementation, member, expected) in [
        (
            interface_source,
            interface_declaration,
            "//go:build bifrost_c2_excluded\n\npackage consumer\ntype dynamicLibraryClient struct{}\nfunc (*dynamicLibraryClient) Shutdown() {}\n",
            "Shutdown",
            interface_target,
        ),
        (
            interface_source,
            interface_declaration,
            "//go:build cgo\n\npackage consumer\nimport \"C\"\ntype dynamicLibraryClient struct{}\nfunc (*dynamicLibraryClient) Shutdown() {}\n",
            "Shutdown",
            interface_target,
        ),
        (
            interface_source,
            interface_declaration,
            "package consumer\ntype dynamicLibraryClient struct{}\nfunc (*dynamicLibraryClient) Shutdown() {}\n",
            "Shutdown",
            interface_target,
        ),
        (
            "package consumer; func use(s Service) { _ = s.ID }",
            "package consumer; type C struct { ID string }; type B struct { C }; type A struct { ID string }; type Service struct { A; B }",
            "//go:build bifrost_c2_excluded\n\npackage consumer\nfunc (Service) ID() {}\n",
            "ID",
            "example.test/native/consumer.A.ID",
        ),
    ] {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/native\n\ngo 1.22\n")
            .file("consumer/abi.go", declarations)
            .file(CALLER, source)
            .file("consumer/loader.go", implementation)
            .file("nested/go.mod", "module example.test/other\n\ngo 1.22\n")
            .file("nested/abi.go", "package other; type Other struct{}")
            .file(
                "nested/loader.go",
                "//go:build bifrost_c2_excluded\n\npackage other\nfunc (Other) Shutdown() {}\n",
            )
            .build();
        let config = AnalyzerConfig {
            go: GoAnalyzerConfig {
                dependency_discovery: GoDependencyDiscoveryConfig {
                    mode: GoDependencyDiscoveryMode::FullProduction,
                    ..GoDependencyDiscoveryConfig::default()
                },
            },
            ..AnalyzerConfig::default()
        };
        let workspace = fixture.workspace_analyzer(config.clone());
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let activation = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let cancellation = CancellationToken::default();
        let discovery = workspace.activate_dependency_packs(
            &config,
            &[DependencyPackEcosystem::Go],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits: DependencyPackLimits::default(),
                cancellation: &cancellation,
            },
        );
        assert_go_discovery_completed(&discovery);

        let analyzer = workspace.analyzer();
        {
            use brokk_bifrost_analysis::analyzer::resolution::{
                SelectedTypedFactSource, SemanticId,
            };
            let GoNativePointRequestOpen::Ready(request) = GoNativePointRequest::open_for_file(
                resolve_analyzer::<GoAnalyzer>(analyzer).unwrap(),
                &fixture.file(CALLER),
                None,
                &cancellation,
            )
            .unwrap() else {
                panic!("caller context must be ready");
            };
            let mount = request
                .operation
                .mount_table()
                .mount_for_path("go", "nested/loader.go")
                .unwrap()
                .unwrap();
            let connection = request.operation.ready().inventory.connection();
            let key: u32 = connection.query_row(
                "SELECT s.semantic_key FROM main.resolution_semantic_sites s JOIN main.source_native_declaration_bridges b ON b.blob_id=s.blob_id AND b.source_site=s.source_site JOIN main.source_go_callables c ON c.blob_id=b.blob_id AND c.declaration_id=b.declaration_id JOIN temp.selected_resolution_mounts m ON m.blob_id=s.blob_id WHERE m.mount_ordinal=?1 AND s.semantic_role='definition' AND c.is_method=1 AND c.name='Shutdown'",
                [mount.ordinal().get()], |row| row.get(0),
            ).unwrap();
            let definition = SemanticId::local(mount.ordinal().get(), key);
            assert_eq!(
                request
                    .operation
                    .ready()
                    .typed_source()
                    .deferred_member_participation(&[definition], &cancellation)
                    .unwrap(),
                Some(vec![false]),
                "an excluded method in another domain must not participate"
            );
            assert_eq!(
                request.operation.bound_go_context_publications().len(),
                2,
                "the candidate domain must be bound for finish rechecks"
            );
        }
        let file = fixture.file(CALLER);
        let point = site_for(source, member);
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: None,
                site: &point,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: Some(&cancellation),
            },
            || {},
        ));
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{expected}: {outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            expected,
            "{outcome:?}"
        );
    }
}

/// Declaration coordinates select their published static value slot.
#[test]
#[hardwon("#7509: Go declaration-name type queries omitted the published declaration value slot")]
fn go_native_type_answers_select_declaration_values_and_references() {
    use crate::analyzer::go::type_identity_proof::{ObservedCarrierType, go_observed_value_type};
    use brokk_bifrost_analysis::analyzer::semantic::ObservedValueType;
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;
    let source = "package consumer\nfunc Source() string { return \"\" }\nfunc HasPrefix(p string) bool { return true }\nfunc run() { p := Source(); if HasPrefix(p) { return } }\n";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let cancellation = CancellationToken::default();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let mut declaration = None;
    let mut reference = None;
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "short_var_declaration" {
            declaration = node
                .child_by_field_name("left")
                .and_then(|left| left.named_child(0));
        }
        if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|function| {
                    function.utf8_text(source.as_bytes()).unwrap() == "HasPrefix"
                })
        {
            reference =
                brokk_bifrost_core::analyzer::tree_walk::named_children_by_field(node, "arguments")
                    .first()
                    .copied();
        }
        pending.extend((0..node.named_child_count()).filter_map(|index| node.named_child(index)));
    }
    let GoNativePointRequestOpen::Ready(mut request) = GoNativePointRequest::open_for_file(
        &analyzer,
        &file,
        analyzer.inner.semantic_model_overlay(),
        &cancellation,
    )
    .unwrap() else {
        panic!("native context available");
    };
    for (label, node) in [
        ("declaration", declaration.unwrap()),
        ("reference", reference.unwrap()),
    ] {
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: "p".into(),
            range: Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            },
            focus_start_byte: node.start_byte(),
            focus_end_byte: node.end_byte(),
        };
        let mut native = None;
        let result = request.resolve_type_with_evidence(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation: Some(&cancellation),
            },
            |answer| native = Some(go_observed_value_type(answer)),
        );
        let BoundedResolution::Complete { value: outcome, .. } = result else {
            panic!("bounded native query completes");
        };
        assert_eq!(
            outcome.status,
            TypeLookupStatus::Resolved,
            "{label}: {outcome:?}"
        );
        assert!(
            matches!(native, Some(ObservedCarrierType::Type(ObservedValueType::Named { canonical })) if canonical == "string"),
            "{label}: the selected native value slot proves the declared string type"
        );
    }
}

#[test]
#[hardwon("#7616: a call into a pack-modeled Go package published an empty Complete result type")]
fn go_native_modeled_package_results_retain_unindexed_external_frontier() {
    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence, SessionPackSource,
        SessionPackSourceKind, SourceFormat, acquire_active_semantic_models, compile_source,
    };

    // Test-only declaration authority. These signatures identify the external
    // package; native result types still require selected source declarations.
    let declarations = serde_json::json!({
        "schema_version": 8,
        "pack_id": "test.go-unindexed-results",
        "version": "0.1.0",
        "producer": {"name": "bifrost-engine-test", "version": "0.1.0"},
        "language": "go", "ecosystem": "go-stdlib",
        "compatibility": {"toolchains": []},
        "provenance": {"source": "https://pkg.go.dev/path/filepath", "revision": "go1.22"},
        "license": "BSD-3-Clause", "completeness": "partial",
        "safety": {"generated_code_only": false, "review_required": false},
        "shards": [{
            "id": "test.go-unindexed-results.shard",
            "activation": [{"configurations": ["test.go-unindexed-results"]}],
            "payload": {
                "kind": "declaration_facts",
                "types": [{
                    "id": "test.filepath", "name": "path/filepath", "type_kind": "module",
                    "visibility": "public", "aliases": ["filepath"],
                    "locator": {"kind": "artifact", "path": "path/filepath/test.go", "symbol": "path/filepath"}
                }],
                "members": [
                    {
                        "id": "test.filepath.rel", "owner": "test.filepath", "name": "Rel",
                        "member_kind": "function", "visibility": "public", "is_static": true,
                        "callable_family_complete": true,
                        "signature": {
                            "parameters": [
                                {"name": "base", "type": {"kind": "named", "name": "string"}},
                                {"name": "target", "type": {"kind": "named", "name": "string"}}
                            ],
                            "returns": {"kind": "tuple", "elements": [
                                {"kind": "named", "name": "string"}, {"kind": "named", "name": "error"}
                            ]}
                        },
                        "locator": {"kind": "artifact", "path": "path/filepath/test.go", "symbol": "path/filepath.Rel"}
                    },
                    {
                        "id": "test.filepath.base", "owner": "test.filepath", "name": "Base",
                        "member_kind": "function", "visibility": "public", "is_static": true,
                        "callable_family_complete": true,
                        "signature": {
                            "parameters": [{"name": "path", "type": {"kind": "named", "name": "string"}}],
                            "returns": {"kind": "named", "name": "string"}
                        },
                        "locator": {"kind": "artifact", "path": "path/filepath/test.go", "symbol": "path/filepath.Base"}
                    }
                ]
            }
        }]
    });
    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&declarations).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    for modeled in [true, false] {
        let source = r#"package consumer
import "path/filepath"
func f(p string) {
    rel, err := filepath.Rel("/srv/", p)
    base := filepath.Base(p)
    _, _, _ = rel, err, base
}
"#;
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/native\n\ngo 1.22\n")
            .file(CALLER, source)
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        if modeled {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: "test:go-unindexed-results".into(),
                    },
                )
                .unwrap();
            let activation = acquire_active_semantic_models(
                workspace.analyzer(),
                &catalog,
                None,
                &SemanticModelActivationRequest {
                    approximate_standard_libraries: vec![],
                    bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                    evidence: vec![SemanticModelActivationEvidence {
                        language: "go".into(),
                        ecosystem: "go-stdlib".into(),
                        configuration: Some("test.go-unindexed-results".into()),
                        package: None,
                        module: None,
                        toolchain: None,
                        target: None,
                        artifact_sha256: None,
                    }],
                    controls: vec![],
                    limits: SemanticModelRuntimeLimits::default(),
                },
                &cancellation,
            );
            assert!(matches!(activation, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelRuntimeOutcome::Ready { .. }), "{activation:?}");
        }
        let analyzer = workspace.analyzer();
        let file = fixture.file(CALLER);
        let GoNativePointRequestOpen::Ready(mut request) = GoNativePointRequest::open(
            resolve_analyzer::<GoAnalyzer>(analyzer).unwrap(),
            analyzer.semantic_model_overlay(),
            &cancellation,
        )
        .unwrap() else {
            panic!("native Go request must open")
        };
        for identifier in ["filepath", "rel", "err", "base"]
            .into_iter()
            .filter(|identifier| modeled || *identifier != "filepath")
        {
            let mut observed = false;
            let site = site_for(source, identifier);
            let outcome = request.resolve_type_with_evidence(
                BoundedReceiverQuery {
                    analyzer,
                    file: &file,
                    source,
                    tree: None,
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                |native| {
                    observed = true;
                    if identifier == "filepath" {
                        assert_eq!(native.answer.binding().completion(), &ResolutionCompletion::Complete);
                        assert!(native.answer.projected_frontiers().iter().all(|frontier| frontier.completion() == &ResolutionCompletion::Complete));
                        return;
                    }
                    assert!(
                        !native.answer.projected_frontiers().is_empty(),
                        "{:?}",
                        native.answer
                    );
                    for frontier in native.answer.projected_frontiers() {
                        if modeled {
                            assert_eq!(frontier.completion(), &ResolutionCompletion::Complete,
                                "modeled={modeled} {identifier}: {frontier:?}");
                            assert!(!frontier.possible_values().is_empty(), "{frontier:?}");
                        } else {
                            assert!(matches!(frontier.completion(), ResolutionCompletion::Incomplete(_)),
                                "modeled={modeled} {identifier}: {frontier:?}");
                        }
                        assert!(
                            !frontier.unindexed_external().is_empty(),
                            "modeled={modeled} {identifier}: {frontier:?}"
                        );
                        if !modeled {
                            let ResolutionCompletion::Incomplete(reasons) = frontier.completion() else { unreachable!() };
                            assert!(reasons.iter().all(|reason| !matches!(reason,
                                brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason::OpenBoundary {
                                    status: brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus::ExternalDeclaredUnindexed, ..
                                }
                            )), "presumed-import reasons must retain their prior shape: {frontier:?}");
                        }
                        // The marker's provider/member fields are intentionally private.
                        let external = format!("{:?}", frontier.unindexed_external());
                        assert!(
                            external.contains("path/filepath") && external.contains("member: Some"),
                            "{external}"
                        );
                    }
                },
            );
            assert!(observed, "native evidence must be read: {outcome:?}");
        }
    }
}
