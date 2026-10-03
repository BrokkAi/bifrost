use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::go_facts::GoCallableFact;
use brokk_bifrost_core::analyzer::model::StructuredTypeIdentityBuilder;
use brokk_bifrost_core::analyzer::model::{
    CodeUnitType, DispatchExtensibility, ImportInfo, ParameterMetadata, SignatureMetadata,
    StructuredImportPath, StructuredImportPathKind, StructuredTypeIdentity, StructuredTypeName,
};
use brokk_bifrost_core::analyzer::parsed_file::{ParsedFile, ParsedSourceFacts, SourceImportFact};
use brokk_bifrost_core::analyzer::rust_facts::RustItemSourceFacts;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceImportId};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{ParentIndex, TreeWalkAction};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use tree_sitter::{Node, Tree};

use crate::packages::{GO_MODULE_SCOPE_SEGMENT, canonical_go_package_name};
use crate::resolution::{GoResolutionBuilder, GoResolutionOutput};
use crate::structural::GO_STRUCTURAL_SPEC;

pub fn go_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

/// Whether a Go identifier is exported from its declaring package.
///
/// Go exposes only identifiers whose first character is uppercase. Keep this
/// predicate shared by declaration production and reference resolution so a
/// dot import cannot make a package-private name visible to another package.
pub fn go_identifier_is_exported(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}

/// Whether `name` is declared by Go's universe block as a type.
///
/// Keep this list beside the parser-backed declaration helpers so source
/// artifact production, hierarchy comparison, and exact type-identity proofs
/// agree on the language's predeclared type namespace. Callers must still
/// establish that the written name is not shadowed at its source location.
pub fn is_predeclared_go_type(name: &str) -> bool {
    matches!(
        name,
        "any"
            | "bool"
            | "byte"
            | "comparable"
            | "complex64"
            | "complex128"
            | "error"
            | "float32"
            | "float64"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "rune"
            | "string"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
    )
}

/// Intern one qualified-name segment in the process-global interner.
pub fn go_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Build the structured package prefix for a Go declaration.
///
/// A Go `package_name` is the canonical *import path* (e.g.
/// `github.com/brokk/bifrost/analyzer`), whose `/`-separated components are
/// file/directory steps. Each becomes a [`SegmentKind::Path`] segment, so a
/// component that itself contains a literal dot (`github.com`) stays a single
/// segment rather than being re-split on `.` by a downstream consumer. The
/// resulting [`FqName`] renders back to the exact legacy `package_name` string
/// (`/`-joined) via [`FqName::display`] -- but only when `package_name` is
/// already a clean import path.
///
/// This filters out empty path components (from a leading, trailing, or
/// doubled `/`), matching ordinary path-normalization semantics. That
/// filtering is a one-way collapse: `"a//b"` and `"a/b"` intern to the same
/// segments. `package_name` must therefore never contain an empty segment in
/// the first place, or this and the caller's own `/`-joined `package_name`
/// string will disagree, which trips the `CodeUnit::with_signature_and_fq`
/// round-trip assert (`#1189`, `crates/bifrost-core/src/analyzer/model.rs`).
/// `go_module_path_from_source` (`crates/bifrost-go/src/packages.rs`) is
/// responsible for upholding this at the parse boundary: it guarantees the
/// module path it extracts from `go.mod` is a single clean token with no
/// embedded whitespace or comment text, so a malformed `module` line (such
/// as one with a same-line `//` comment) can never reach this function as a
/// doubled slash.
pub fn go_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in package_name.split('/').filter(|c| !c.is_empty()) {
        fq.push(go_segment(component, SegmentKind::Path));
    }
    fq
}

pub fn determine_go_package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if package_child.kind() == "package_identifier" || package_child.kind() == "identifier"
            {
                return go_node_text(package_child, source).trim().to_string();
            }
        }
    }
    String::new()
}

/// Collect every import declaration from a Go source tree.
///
/// Both the persisted analyzer and whole-workspace usage graph need the same
/// structured import facts. Keeping the AST extraction here prevents the graph
/// index from having to reconstruct import aliases from source text later.
pub fn collect_go_import_infos(root: Node<'_>, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == "import_declaration" {
            collect_go_import_infos_from_declaration(child, source, &mut imports);
        }
    }
    imports
}

pub fn collect_go_import_infos_from_declaration(
    node: Node<'_>,
    source: &str,
    imports: &mut Vec<ImportInfo>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "import_spec" {
            if let Some(info) = parse_go_import_spec(child, source) {
                imports.push(info);
            }
            continue;
        }

        let mut nested_cursor = child.walk();
        for spec in child.named_children(&mut nested_cursor) {
            if spec.kind() == "import_spec"
                && let Some(info) = parse_go_import_spec(spec, source)
            {
                imports.push(info);
            }
        }
    }
}

/// The structured interpretation of one Go import spec shared by the primary
/// canonical and native projections.
pub(crate) struct GoImportSpecSyntax<'tree, 'source> {
    pub(crate) node: Node<'tree>,
    pub(crate) path: &'source str,
    pub(crate) segments: Vec<&'source str>,
    pub(crate) alias: Option<(&'source str, Node<'tree>)>,
}

pub(crate) fn parse_go_import_spec_syntax<'tree, 'source>(
    node: Node<'tree>,
    source: &'source str,
) -> Option<GoImportSpecSyntax<'tree, 'source>> {
    let path_node = node.child_by_field_name("path").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind().contains("string"))
    })?;
    let raw_path = go_node_text(path_node, source).trim();
    let path = raw_path
        .trim_matches('"')
        .trim_matches('`')
        .trim_matches('\'');
    if path.is_empty() {
        return None;
    }

    let alias = node
        .child_by_field_name("name")
        .map(|alias| (go_node_text(alias, source).trim(), alias));
    // A Go import path is one string-literal AST node, and '/' is Go's own
    // separator inside its value. Keep the split path in the shared record so
    // native lowering does not reconstruct it from the display DTO.
    let segments = path.split('/').collect();
    Some(GoImportSpecSyntax {
        node,
        path,
        segments,
        alias,
    })
}

pub(crate) fn parse_go_import_syntaxes<'tree, 'source>(
    node: Node<'tree>,
    source: &'source str,
) -> Vec<GoImportSpecSyntax<'tree, 'source>> {
    assert_eq!(node.kind(), "import_declaration");
    let mut specs = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_spec" {
            if let Some(syntax) = parse_go_import_spec_syntax(node, source) {
                specs.push(syntax);
            }
            continue;
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    specs
}

fn is_primary_import_spec(declaration: Node<'_>, spec: Node<'_>) -> bool {
    let parent = spec.parent().expect("Go import spec has a parent");
    parent.id() == declaration.id()
        || (parent.kind() == "import_spec_list"
            && parent
                .parent()
                .is_some_and(|owner| owner.id() == declaration.id()))
}

impl<'tree, 'source> GoImportSpecSyntax<'tree, 'source> {
    pub(crate) fn to_import_info(&self) -> ImportInfo {
        let identifier = Some(
            self.alias
                .map_or_else(
                    || {
                        self.segments
                            .last()
                            .copied()
                            .expect("Go import path has a segment")
                    },
                    |(alias, _)| alias,
                )
                .to_string(),
        );
        let alias = self.alias.map(|(alias, _)| alias.to_string());
        let raw_snippet = match alias.as_deref() {
            Some(alias) => format!("import {alias} \"{}\"", self.path),
            None => format!("import \"{}\"", self.path),
        };

        // A renamed import binds its alias token. Without one, the bound name
        // is the path's last component, spelled only inside the string literal.
        let binder_span = self
            .alias
            .map(|(_, alias)| brokk_bifrost_core::analyzer::common::node_span(alias));

        ImportInfo {
            raw_snippet,
            is_wildcard: false,
            is_global: false,
            identifier,
            alias,
            path: Some(StructuredImportPath {
                segments: self
                    .segments
                    .iter()
                    .map(|segment| (*segment).to_string())
                    .collect(),
                kind: Some(StructuredImportPathKind::Namespace),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: self.node.start_byte(),
            }),
            binder_span,
        }
    }
}

pub fn go_import_spec_parts<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<(&'source str, Option<&'source str>)> {
    let syntax = parse_go_import_spec_syntax(node, source)?;
    Some((syntax.path, syntax.alias.map(|(alias, _)| alias)))
}

pub fn go_import_spec_binding_name<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let (path, alias) = go_import_spec_parts(node, source)?;
    Some(alias.unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path)))
}

pub fn parse_go_import_spec(node: Node<'_>, source: &str) -> Option<ImportInfo> {
    Some(parse_go_import_spec_syntax(node, source)?.to_import_info())
}

pub fn go_embedded_struct_field<'tree>(
    field: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>)> {
    let mut cursor = field.walk();
    for child in field.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "raw_string_literal" | "interpreted_string_literal"
        ) {
            continue;
        }
        if let Some(name) = extract_go_type_name(child, source) {
            return Some((name, child));
        }
    }
    None
}

/// The declared field name of an embedded type is its final type identifier.
/// Follow grammar fields; type arguments are not part of the field name.
pub(crate) fn go_embedded_field_name_node(mut ty: Node<'_>) -> Option<Node<'_>> {
    loop {
        match ty.kind() {
            "type_identifier" => return Some(ty),
            "qualified_type" => return ty.child_by_field_name("name"),
            "generic_type" => ty = ty.child_by_field_name("type")?,
            _ => return None,
        }
    }
}

pub fn sole_spec_declaration_node<'tree>(
    spec: Node<'tree>,
    spec_kind: &str,
    declaration_kind: &str,
) -> Node<'tree> {
    let Some(parent) = spec.parent() else {
        return spec;
    };
    if parent.kind() != declaration_kind {
        return spec;
    }

    let mut cursor = parent.walk();
    let spec_count = parent
        .named_children(&mut cursor)
        .filter(|child| child.kind() == spec_kind)
        .take(2)
        .count();
    if spec_count == 1 { parent } else { spec }
}

pub fn go_type_signature(node: Node<'_>, source: &str) -> String {
    let Some(type_node) = node.child_by_field_name("type") else {
        return go_node_text(node, source).trim().to_string();
    };
    let mut pending = vec![type_node];
    while let Some(child) = pending.pop() {
        if !child.is_named() && child.kind() == "{" {
            let header = source[node.start_byte()..child.start_byte()].trim();
            return format!("{header} {{");
        }
        let mut cursor = child.walk();
        let children_start = pending.len();
        pending.extend(child.children(&mut cursor));
        pending[children_start..].reverse();
    }
    go_node_text(node, source).trim().to_string()
}

pub fn go_function_signature(node: Node<'_>, source: &str) -> (String, String) {
    let header = node
        .child_by_field_name("body")
        .and_then(|body| source.get(node.start_byte()..body.start_byte()))
        .map(str::trim)
        .filter(|header| !header.is_empty())
        .unwrap_or_else(|| go_node_text(node, source).trim());
    let parameter_text = go_rendered_parameter_text(node, source);
    if node.kind() == "method_declaration" || node.kind() == "function_declaration" {
        (format!("{header} {{ ... }}"), parameter_text)
    } else {
        (header.to_string(), parameter_text)
    }
}

pub fn go_interface_method_signature(node: Node<'_>, source: &str) -> (String, String) {
    (
        go_node_text(node, source).trim().to_string(),
        go_rendered_parameter_text(node, source),
    )
}

pub fn go_rendered_parameter_text(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("parameters")
        .map(|parameters| go_node_text(parameters, source).trim().to_string())
        .unwrap_or_else(|| "()".to_string())
}

/// The visibility a Go callable declares.
///
/// Go writes visibility into the identifier rather than into a modifier list,
/// so read the declaration's own `name` node through the shared
/// exported-identifier rule. An unexported name is visible to its declaring
/// package and to nothing else.
fn go_callable_declared_visibility(node: Node<'_>, source: &str) -> DeclaredVisibility {
    match node.child_by_field_name("name") {
        Some(name) if go_identifier_is_exported(go_node_text(name, source).trim()) => {
            DeclaredVisibility::Public
        }
        Some(_) => DeclaredVisibility::PackagePrivate,
        None => DeclaredVisibility::Unknown,
    }
}

pub fn go_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
    parameter_text: &str,
) -> SignatureMetadata {
    go_signature_metadata_with_identities(signature, node, source, parameter_text, None, None)
}

pub fn go_signature_metadata_with_identities(
    signature: String,
    node: Node<'_>,
    source: &str,
    parameter_text: &str,
    return_identity: Option<StructuredTypeIdentity>,
    receiver_identity: Option<StructuredTypeIdentity>,
) -> SignatureMetadata {
    let return_type = node
        .child_by_field_name("result")
        .filter(|result| result.kind() != "parameter_list");
    let receiver_type = go_method_receiver_type_node(node);
    let enrich = |metadata: SignatureMetadata| {
        metadata
            // Go has no static member modifier, and it states receiver binding
            // in the declaration's own shape instead: a `method_declaration`
            // carries a `receiver` field and an interface `method_elem` is
            // dispatched on the interface value that selects it, while a
            // package-level `function_declaration` is owned by its package and
            // binds nothing. Recording the absent static modifier is what lets
            // `receiver_contract_of` read that owner shape. Without it a Go
            // declaration reported no receiver contract at all,
            // `modeled_procedure_key_for_unit` refused to key it, no reviewed
            // summary could name a Go workspace callable, and every call to one
            // reported `callee_unkeyable` (#3455).
            .with_callable_modifiers(false, false, go_callable_declared_visibility(node, source))
            .with_return_type_text(go_callable_return_type_text(node, source))
            .with_return_type_identity(return_identity.clone().or_else(|| {
                return_type.and_then(|result| go_structured_type_identity(result, source))
            }))
            .with_result_type_identities(go_declared_result_type_identities(node, source))
            .with_extension_receiver_type_identity(receiver_identity.clone().or_else(|| {
                receiver_type.and_then(|receiver| go_structured_type_identity(receiver, source))
            }))
            .with_dispatch_extensibility(if node.kind() == "method_elem" {
                DispatchExtensibility::Open
            } else {
                DispatchExtensibility::Closed
            })
    };
    let Some(parameters_node) = node.child_by_field_name("parameters") else {
        return enrich(SignatureMetadata::new(signature, Vec::new()));
    };
    let raw = go_node_text(node, source);
    let leading_trim_bytes = raw.len().saturating_sub(raw.trim_start().len());
    let parameters_start = parameters_node
        .start_byte()
        .saturating_sub(node.start_byte())
        .saturating_sub(leading_trim_bytes);
    let parameters_end = parameters_start + parameter_text.len();
    if signature.get(parameters_start..parameters_end) != Some(parameter_text) {
        return enrich(SignatureMetadata::new(signature, Vec::new()));
    }
    let mut search_start = parameters_start;
    // The label and its declared type are collected together because this pass
    // drops parameters it cannot place in the rendered signature. Collecting
    // the types separately would misalign them with the labels that survived.
    let (parameters, parameter_type_identities): (Vec<_>, Vec<_>) = go_parameter_label_nodes(node)
        .into_iter()
        .filter_map(|label_node| {
            let label = go_node_text(label_node, source).trim();
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            let identity = go_parameter_declared_type(label_node)
                .and_then(|declared| go_structured_type_identity(declared, source));
            Some((
                ParameterMetadata::new(label, start_byte, end_byte),
                identity,
            ))
        })
        .unzip();
    enrich(
        SignatureMetadata::new(signature, parameters)
            .with_parameter_type_identities(parameter_type_identities),
    )
}

/// One structured identity per declared result of a multi-result callable.
///
/// `func f() T` states its result as a bare type node and is already described
/// by the single `return_type_identity`. `func f() (T, error)` states a
/// `parameter_list` instead, which that single field cannot represent, so a
/// caller asking what `b` is bound to in `b, _ := f()` previously got nothing
/// at all. Go also spells a named or parenthesized single result this way.
///
/// A declaration that names several results of one type, `(a, b T)`, declares
/// one identity per name, so the ordinals stay aligned with the call's
/// results. A result whose type does not resolve to a structured identity
/// stops the list rather than shifting every later ordinal onto the wrong
/// type.
fn go_declared_result_type_identities(node: Node<'_>, source: &str) -> Vec<StructuredTypeIdentity> {
    let Some(result) = node
        .child_by_field_name("result")
        .filter(|result| result.kind() == "parameter_list")
    else {
        return Vec::new();
    };
    let mut cursor = result.walk();
    let mut identities = Vec::new();
    for declaration in result.named_children(&mut cursor) {
        if !matches!(
            declaration.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let Some(identity) = declaration
            .child_by_field_name("type")
            .and_then(|kind| go_structured_type_identity(kind, source))
        else {
            return Vec::new();
        };
        let mut names = declaration.walk();
        let named = declaration
            .named_children(&mut names)
            .filter(|child| child.kind() == "identifier")
            .count()
            .max(1);
        identities.extend(std::iter::repeat_n(identity, named));
    }
    identities
}

pub fn go_method_receiver_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let receiver = node.child_by_field_name("receiver")?;
    let mut cursor = receiver.walk();
    let mut parameters = receiver
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "parameter_declaration");
    let parameter = parameters.next()?;
    if parameters.next().is_some() {
        return None;
    }
    parameter.child_by_field_name("type")
}

pub fn go_callable_return_type_text(node: Node<'_>, source: &str) -> Option<String> {
    node.child_by_field_name("result")
        .filter(|result| result.kind() != "parameter_list")
        .map(|result| go_node_text(result, source).trim().to_string())
        .filter(|result| !result.is_empty())
}

pub enum GoStructuredTypeFrame<'tree> {
    Visit(Node<'tree>),
    Pointer,
    Array,
    Slice,
    Map,
    Generic { argument_count: usize },
}

/// Preserve the parser-proven shape of a Go type without asking bounded
/// consumers to reconstruct it from the rendered declaration signature.
///
/// This is deliberately iterative: source can contain arbitrarily nested
/// pointer, container and generic wrappers, and indexing such a file must not
/// consume the Rust call stack.
pub fn go_structured_type_identity(node: Node<'_>, source: &str) -> Option<StructuredTypeIdentity> {
    go_structured_type_identity_with(node, source, || true)
}

pub fn go_structured_type_identity_bounded(
    node: Node<'_>,
    source: &str,
    visit: impl FnMut() -> bool,
) -> Option<StructuredTypeIdentity> {
    go_structured_type_identity_with(node, source, visit)
}

pub fn go_structured_type_identity_with(
    node: Node<'_>,
    source: &str,
    mut visit: impl FnMut() -> bool,
) -> Option<StructuredTypeIdentity> {
    let mut frames = vec![GoStructuredTypeFrame::Visit(node)];
    let mut values = Vec::new();
    let mut builder = StructuredTypeIdentityBuilder::default();

    while let Some(frame) = frames.pop() {
        match frame {
            GoStructuredTypeFrame::Visit(node) => {
                if !visit() {
                    return None;
                }
                match node.kind() {
                    "type_identifier" | "identifier" => {
                        let name = go_node_text(node, source).trim();
                        values.push(builder.named(StructuredTypeName::new(
                            vec![name.to_string()],
                            Vec::new(),
                            false,
                        )?)?);
                    }
                    "qualified_type" => {
                        let package = node.child_by_field_name("package")?;
                        let name = node.child_by_field_name("name")?;
                        let package = go_node_text(package, source).trim();
                        let name = go_node_text(name, source).trim();
                        values.push(builder.named(StructuredTypeName::new(
                            vec![package.to_string(), name.to_string()],
                            Vec::new(),
                            false,
                        )?)?);
                    }
                    "pointer_type" => {
                        frames.push(GoStructuredTypeFrame::Pointer);
                        frames.push(GoStructuredTypeFrame::Visit(go_type_wrapper_child(node)?));
                    }
                    "array_type" | "implicit_length_array_type" => {
                        frames.push(GoStructuredTypeFrame::Array);
                        frames.push(GoStructuredTypeFrame::Visit(
                            node.child_by_field_name("element")
                                .or_else(|| go_last_named_type_child(node))?,
                        ));
                    }
                    "slice_type" => {
                        frames.push(GoStructuredTypeFrame::Slice);
                        frames.push(GoStructuredTypeFrame::Visit(
                            node.child_by_field_name("element")
                                .or_else(|| go_last_named_type_child(node))?,
                        ));
                    }
                    "map_type" => {
                        let key = node.child_by_field_name("key")?;
                        let value = node.child_by_field_name("value")?;
                        frames.push(GoStructuredTypeFrame::Map);
                        frames.push(GoStructuredTypeFrame::Visit(value));
                        frames.push(GoStructuredTypeFrame::Visit(key));
                    }
                    "generic_type" => {
                        let base = node
                            .child_by_field_name("type")
                            .or_else(|| node.child_by_field_name("name"))
                            .or_else(|| node.named_child(0))?;
                        let arguments =
                            node.child_by_field_name("type_arguments").or_else(|| {
                                let mut cursor = node.walk();
                                node.named_children(&mut cursor)
                                    .find(|child| child.kind() == "type_arguments")
                            })?;
                        let mut argument_nodes = Vec::new();
                        let mut cursor = arguments.walk();
                        for argument in arguments.named_children(&mut cursor) {
                            argument_nodes.push(argument);
                        }
                        frames.push(GoStructuredTypeFrame::Generic {
                            argument_count: argument_nodes.len(),
                        });
                        for argument in argument_nodes.into_iter().rev() {
                            frames.push(GoStructuredTypeFrame::Visit(argument));
                        }
                        frames.push(GoStructuredTypeFrame::Visit(base));
                    }
                    "parenthesized_type" | "negated_type" => {
                        frames.push(GoStructuredTypeFrame::Visit(go_type_wrapper_child(node)?));
                    }
                    "interface_type" => {
                        if node.has_error() || node.is_missing() {
                            return None;
                        }
                        let mut cursor = node.walk();
                        for child in node.named_children(&mut cursor) {
                            if !visit() {
                                return None;
                            }
                            // Comments are parser extras and carry no type
                            // shape. Every other named child of an empty
                            // interface would be a method/type element or an
                            // unexpected parser node, so fail closed.
                            if child.kind() != "comment" {
                                return None;
                            }
                        }
                        values.push(builder.empty_interface()?);
                    }
                    "type_elem" => {
                        let mut cursor = node.walk();
                        let mut children = node.named_children(&mut cursor);
                        let child = children.next()?;
                        if children.next().is_some() {
                            return None;
                        }
                        frames.push(GoStructuredTypeFrame::Visit(child));
                    }
                    _ => return None,
                }
            }
            GoStructuredTypeFrame::Pointer => {
                let inner = values.pop()?;
                values.push(builder.pointer(inner)?);
            }
            GoStructuredTypeFrame::Array => {
                let inner = values.pop()?;
                values.push(builder.array(inner)?);
            }
            GoStructuredTypeFrame::Slice => {
                let inner = values.pop()?;
                values.push(builder.slice(inner)?);
            }
            GoStructuredTypeFrame::Map => {
                let value = values.pop()?;
                let key = values.pop()?;
                values.push(builder.map(key, value)?);
            }
            GoStructuredTypeFrame::Generic { argument_count } => {
                if values.len() < argument_count + 1 {
                    return None;
                }
                let arguments = values.split_off(values.len() - argument_count);
                let base = values.pop()?;
                values.push(builder.generic(base, arguments)?);
            }
        }
    }

    (values.len() == 1)
        .then(|| values.pop())
        .flatten()
        .and_then(|root| builder.finish(root))
}

pub fn go_type_wrapper_child(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("type").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).next()
    })
}

pub fn go_last_named_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

pub fn go_embedded_type_texts(node: Node<'_>, source: &str) -> Vec<String> {
    let mut embedded = go_embedded_type_nodes(node)
        .into_iter()
        .map(|candidate| go_node_text(candidate, source).trim().to_string())
        .filter(|candidate| !candidate.is_empty())
        .collect::<Vec<_>>();
    embedded.sort();
    embedded.dedup();
    embedded
}

pub fn go_embedded_type_identity(
    type_node: Node<'_>,
    source: &str,
) -> Option<StructuredTypeIdentity> {
    let mut identity = go_structured_type_identity(type_node, source)?;
    let Some(field) = type_node
        .parent()
        .filter(|parent| parent.kind() == "field_declaration")
    else {
        return Some(identity);
    };
    let pointer = (0..field.child_count()).any(|index| {
        field
            .child(index)
            .is_some_and(|child| !child.is_named() && child.kind() == "*")
    });
    if pointer {
        identity = identity.wrap_pointer()?;
    }
    Some(identity)
}

pub fn go_embedded_type_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "struct_type" => {
            let Some(fields) = named_children_of_kind(node, "field_declaration_list")
                .into_iter()
                .next()
            else {
                return Vec::new();
            };
            named_children_of_kind(fields, "field_declaration")
                .into_iter()
                .filter(|field| children_by_field(*field, "name").is_empty())
                .filter_map(|field| field.child_by_field_name("type"))
                .collect()
        }
        "interface_type" => named_children_of_kind(node, "type_elem")
            .into_iter()
            .filter_map(|element| {
                let children = named_children(element);
                let [embedded] = children.as_slice() else {
                    return None;
                };
                matches!(embedded.kind(), "type_identifier" | "qualified_type").then_some(*embedded)
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

pub fn named_children_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == kind)
        .collect()
}

pub fn children_by_field<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor).collect()
}

/// The declared type of the parameter a label node names.
///
/// A label is either the parameter's identifier or, for an unnamed
/// parameter, the type node itself. Walking up to the enclosing declaration
/// reads the `type` field in both cases, so one shared step answers both.
fn go_parameter_declared_type<'a>(label: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = Some(label);
    while let Some(node) = cursor {
        if matches!(
            node.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            return node.child_by_field_name("type");
        }
        cursor = node.parent();
    }
    None
}

pub fn go_parameter_label_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        match parameter.kind() {
            "parameter_declaration" | "variadic_parameter_declaration" => {
                let mut names = Vec::new();
                let mut children = parameter.walk();
                for child in parameter.named_children(&mut children) {
                    if child.kind() == "identifier" {
                        names.push(child);
                    }
                }
                if names.is_empty() && parameter.kind() == "variadic_parameter_declaration" {
                    labels.push(parameter);
                } else if names.is_empty() {
                    labels.push(
                        parameter
                            .child_by_field_name("type")
                            .or_else(|| {
                                parameter
                                    .named_child(parameter.named_child_count().saturating_sub(1))
                            })
                            .unwrap_or(parameter),
                    );
                } else {
                    labels.extend(names);
                }
            }
            _ => {}
        }
    }
    labels
}

pub fn go_value_signature(
    node: Node<'_>,
    source: &str,
    keyword: &str,
    name: &str,
    identifier_count: usize,
) -> String {
    let raw = go_node_text(node, source).trim();
    let after_keyword = raw.strip_prefix(keyword).map(str::trim).unwrap_or(raw);
    if identifier_count > 1 && after_keyword.contains('=') {
        return name.to_string();
    }

    let remainder = after_keyword
        .strip_prefix(name)
        .map(str::trim)
        .unwrap_or(after_keyword);
    let (type_part, value_part) = remainder
        .split_once('=')
        .map(|(left, right)| (left.trim(), Some(right.trim())))
        .unwrap_or((remainder.trim(), None));

    let mut signature = name.to_string();
    if !type_part.is_empty() {
        signature.push(' ');
        signature.push_str(type_part);
    }

    if let Some(value) = value_part
        && go_value_is_simple_literal(value)
    {
        signature.push_str(" = ");
        signature.push_str(value);
    }

    signature
}

pub fn extract_go_receiver_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" => {
                let type_node = child.child_by_field_name("type").unwrap_or(child);
                if let Some(name) = extract_go_type_name(type_node, source) {
                    return Some(name);
                }
            }
            _ => {
                if let Some(name) = extract_go_type_name(child, source) {
                    return Some(name);
                }
            }
        }
    }
    None
}

pub fn extract_go_type_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => {
            let text = go_node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "pointer_type" | "slice_type" | "array_type" | "generic_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_go_type_name(child, source))
        }
        "qualified_type" => node
            .child_by_field_name("name")
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor).last()
            })
            .and_then(|child| extract_go_type_name(child, source)),
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_go_type_name(child, source))
        }
    }
}

pub fn go_struct_field_suffix(node: Node<'_>, source: &str) -> String {
    let mut cursor = node.walk();
    let mut type_start = None;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "field_identifier" {
            continue;
        }
        type_start = Some(child.start_byte());
        break;
    }
    type_start
        .and_then(|start| source.get(start..node.end_byte()))
        .map(|suffix| format!(" {}", suffix.trim()))
        .unwrap_or_default()
}

pub fn go_field_inline_container_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "struct_type" | "interface_type"))
}

pub fn go_value_is_simple_literal(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "iota"
        || trimmed == "true"
        || trimmed == "false"
        || trimmed == "nil"
        || trimmed.parse::<i128>().is_ok()
        || trimmed.parse::<f64>().is_ok()
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
}

/// Whether a Go struct `field_declaration` is an embedded (anonymous) field.
pub fn go_field_declaration_is_embedded(node: Node<'_>) -> bool {
    node.child_by_field_name("name")
        .is_none_or(|name| name.kind() == "type_identifier")
}

pub fn parse_go_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let declared_package = determine_go_package_name(tree.root_node(), source);
    let package_name = canonical_go_package_name(file, &declared_package);
    parse_go_file_with_package_name(file, source, tree, declared_package, package_name)
}

pub fn parse_go_file_with_package_name(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    declared_package: String,
    package_name: String,
) -> ParsedFile {
    let mut parsed = ParsedFile::new(package_name);
    parsed.content_qualifier = declared_package;
    let root = tree.root_node();
    let parsed_package_name = parsed.package_name.clone();

    let structural_kinds = CompiledKinds::compile(
        &tree_sitter_go::LANGUAGE.into(),
        GO_STRUCTURAL_SPEC.kind_table(),
    );
    let call_site_context = GO_STRUCTURAL_SPEC.call_site_context(root, source);
    let mut state = GoPrimaryParseState::new(
        file,
        source,
        parsed_package_name,
        &mut parsed,
        root,
        &structural_kinds,
        &call_site_context,
    );
    walk_go_primary_tree(root, &mut state);
    state.finish();
    parsed
}

enum GoPrimaryFrame<'tree> {
    Enter {
        node: Node<'tree>,
        native_active: bool,
    },
    Exit {
        native_exit: bool,
    },
}

fn walk_go_primary_tree<'source, 'file, 'parsed, 'structural>(
    root: Node<'structural>,
    state: &mut GoPrimaryParseState<'source, 'file, 'parsed, 'structural>,
) where
    'source: 'structural,
{
    let mut stack = vec![GoPrimaryFrame::Enter {
        node: root,
        native_active: true,
    }];
    while let Some(frame) = stack.pop() {
        match frame {
            GoPrimaryFrame::Enter {
                node,
                native_active,
            } => {
                let native_action = state.enter_node(node, native_active);
                let (native_descend, native_exit) = match native_action {
                    TreeWalkAction::Descend => (true, false),
                    TreeWalkAction::DescendWithExit => (true, true),
                    TreeWalkAction::Skip => (false, false),
                    TreeWalkAction::Stop => break,
                };
                stack.push(GoPrimaryFrame::Exit { native_exit });
                let mut cursor = node.walk();
                let children = node
                    .children(&mut cursor)
                    .map(|child| GoPrimaryFrame::Enter {
                        node: child,
                        native_active: native_active && native_descend,
                    })
                    .collect::<Vec<_>>();
                stack.extend(children.into_iter().rev());
            }
            GoPrimaryFrame::Exit { native_exit } => state.exit_node(native_exit),
        }
    }
}

#[derive(Clone)]
struct GoFieldOwner {
    unit: CodeUnit,
    record_ranges: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GoMemberContainerKind {
    Struct,
    Interface,
}

fn member_container_kind(node: Node<'_>) -> Option<GoMemberContainerKind> {
    match node.kind() {
        "struct_type" => Some(GoMemberContainerKind::Struct),
        "interface_type" => Some(GoMemberContainerKind::Interface),
        _ => None,
    }
}

fn direct_member_child(node: Node<'_>, container_id: usize, kind: GoMemberContainerKind) -> bool {
    match kind {
        GoMemberContainerKind::Struct => {
            node.kind() == "field_declaration" && {
                let Some(field_list) = node.parent() else {
                    return false;
                };
                field_list.kind() == "field_declaration_list"
                    && field_list
                        .parent()
                        .is_some_and(|container| container.id() == container_id)
            }
        }
        GoMemberContainerKind::Interface => {
            matches!(node.kind(), "method_elem" | "type_elem")
                && node
                    .parent()
                    .is_some_and(|container| container.id() == container_id)
        }
    }
}

#[derive(Clone)]
enum GoDeclarationContext {
    TopLevel,
    TypeDeclaration,
    ValueDeclaration(&'static str),
    TypeOwnerPending {
        unit: CodeUnit,
        container_id: usize,
        kind: GoMemberContainerKind,
    },
    TypeOwner {
        unit: CodeUnit,
        container_id: usize,
        kind: GoMemberContainerKind,
    },
    FieldsPending {
        owner_list: usize,
        container_id: usize,
        kind: GoMemberContainerKind,
    },
    Fields {
        owner_list: usize,
        container_id: usize,
        kind: GoMemberContainerKind,
    },
    Inactive,
}

struct GoPrimaryParseState<'source, 'file, 'parsed, 'structural>
where
    'source: 'structural,
{
    file: &'file ProjectFile,
    source: &'source str,
    package_name: String,
    parsed: &'parsed mut ParsedFile,
    native: GoResolutionBuilder<'source, 'structural>,
    structural: StructuralFactCollector<'structural, 'structural>,
    structural_kinds: &'structural CompiledKinds,
    call_site_context: &'structural CallSiteContext,
    structural_parents: Vec<Option<u32>>,
    declaration_contexts: Vec<GoDeclarationContext>,
    field_owner_lists: Vec<Vec<GoFieldOwner>>,
    source_imports: Vec<SourceImportFact>,
    generic_imports: Vec<SourceImportId>,
    source_declaration_units: Vec<(SourceDeclarationId, CodeUnit)>,
}

impl<'source, 'file, 'parsed, 'structural> GoPrimaryParseState<'source, 'file, 'parsed, 'structural>
where
    'source: 'structural,
{
    fn new(
        file: &'file ProjectFile,
        source: &'source str,
        package_name: String,
        parsed: &'parsed mut ParsedFile,
        root: Node<'structural>,
        structural_kinds: &'structural CompiledKinds,
        call_site_context: &'structural CallSiteContext,
    ) -> Self {
        Self {
            file,
            source,
            package_name,
            parsed,
            native: GoResolutionBuilder::new(root, source),
            structural: StructuralFactCollector::new(
                &GO_STRUCTURAL_SPEC,
                source,
                call_site_context,
                ParentIndex::new(root),
                usize::MAX,
                None,
            ),
            structural_kinds,
            call_site_context,
            structural_parents: vec![None],
            declaration_contexts: vec![GoDeclarationContext::TopLevel],
            field_owner_lists: Vec::new(),
            source_imports: Vec::new(),
            generic_imports: Vec::new(),
            source_declaration_units: Vec::new(),
        }
    }

    fn enter_node(&mut self, node: Node<'structural>, native_active: bool) -> TreeWalkAction {
        self.native.capture_source_node(node);
        match node.kind() {
            "identifier" | "type_identifier" | "field_identifier" | "package_identifier" => {
                let text = go_node_text(node, self.source).trim();
                if !text.is_empty() {
                    self.parsed.type_identifiers.insert(text.to_string());
                }
            }
            _ => {}
        }

        let parent = self.structural_parents.last().copied().flatten();
        let structural_parent = self.admit_structural(node, parent);
        self.structural_parents.push(structural_parent);

        let context = self
            .declaration_contexts
            .last()
            .cloned()
            .expect("Go declaration context stack must have a root");
        let import_specs = (node.kind() == "import_declaration")
            .then(|| parse_go_import_syntaxes(node, self.source));
        let child_context = if let Some(specs) = import_specs.as_deref() {
            self.enter_import_declaration(node, context, specs)
        } else {
            self.register_declaration(node, context)
        };
        self.declaration_contexts.push(child_context);

        if native_active && node.is_named() {
            if let Some(specs) = import_specs.as_deref() {
                self.native.enter_import(node, specs)
            } else {
                self.native.enter(node)
            }
        } else {
            TreeWalkAction::Descend
        }
    }

    fn admit_structural(&mut self, node: Node<'_>, parent: Option<u32>) -> Option<u32> {
        let mut structural_parent = parent;
        if !node.is_named() {
            return structural_parent;
        }
        let Some(raw_kind) = self.structural_kinds.kind_of(&node) else {
            return structural_parent;
        };
        if !GO_STRUCTURAL_SPEC.should_extract(node, raw_kind) {
            return structural_parent;
        }
        let kind = GO_STRUCTURAL_SPEC.refine_kind(
            node,
            raw_kind,
            parent.map(|id| self.structural.normalized_kind(id)),
            self.source,
            self.call_site_context,
        );
        let fact_id = {
            let source_facts = self.native.source_collector_mut();
            self.structural
                .enter(node, kind, parent, source_facts)
                .expect("Go structural fact collection must remain unbounded")
        };
        {
            let source_facts = self.native.source_collector_mut();
            let mut sink = self.structural.role_sink(source_facts);
            GO_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
            self.structural
                .accept_roles(fact_id, sink.into_parts())
                .expect("Go structural role collection must remain unbounded");
        }
        structural_parent = Some(fact_id);
        structural_parent
    }

    fn register_declaration(
        &mut self,
        node: Node<'_>,
        context: GoDeclarationContext,
    ) -> GoDeclarationContext {
        match &context {
            GoDeclarationContext::TypeOwnerPending {
                unit,
                container_id,
                kind,
            } if node.id() == *container_id && member_container_kind(node) == Some(*kind) => {
                return GoDeclarationContext::TypeOwner {
                    unit: unit.clone(),
                    container_id: *container_id,
                    kind: *kind,
                };
            }
            GoDeclarationContext::FieldsPending {
                owner_list,
                container_id,
                kind,
            } if node.id() == *container_id && member_container_kind(node) == Some(*kind) => {
                return GoDeclarationContext::Fields {
                    owner_list: *owner_list,
                    container_id: *container_id,
                    kind: *kind,
                };
            }
            GoDeclarationContext::TypeOwnerPending { .. }
            | GoDeclarationContext::FieldsPending { .. } => {
                return GoDeclarationContext::Inactive;
            }
            _ => {}
        }
        match node.kind() {
            "function_declaration" if matches!(&context, GoDeclarationContext::TopLevel) => {
                self.register_function(node, None);
                GoDeclarationContext::Inactive
            }
            "method_declaration" if matches!(&context, GoDeclarationContext::TopLevel) => {
                self.register_method(node);
                GoDeclarationContext::Inactive
            }
            "type_declaration" if matches!(&context, GoDeclarationContext::TopLevel) => {
                GoDeclarationContext::TypeDeclaration
            }
            "var_declaration" if matches!(&context, GoDeclarationContext::TopLevel) => {
                GoDeclarationContext::ValueDeclaration("var")
            }
            "const_declaration" if matches!(&context, GoDeclarationContext::TopLevel) => {
                GoDeclarationContext::ValueDeclaration("const")
            }
            "type_spec" if matches!(&context, GoDeclarationContext::TypeDeclaration) => self
                .register_type_spec(node)
                .unwrap_or(GoDeclarationContext::Inactive),
            "type_alias" if matches!(&context, GoDeclarationContext::TypeDeclaration) => {
                self.register_type_alias(node);
                GoDeclarationContext::Inactive
            }
            "var_spec" | "const_spec"
                if matches!(&context, GoDeclarationContext::ValueDeclaration(_)) =>
            {
                if let GoDeclarationContext::ValueDeclaration(keyword) = context {
                    self.register_value_spec(node, keyword);
                }
                GoDeclarationContext::Inactive
            }
            "field_declaration" => match context {
                GoDeclarationContext::TypeOwner {
                    unit: parent,
                    container_id,
                    kind,
                } if direct_member_child(node, container_id, kind) => {
                    let owner_list = self.intern_field_owners(vec![GoFieldOwner {
                        unit: parent,
                        record_ranges: true,
                    }]);
                    self.register_field(node, owner_list)
                }
                GoDeclarationContext::Fields {
                    owner_list,
                    container_id,
                    kind,
                } if direct_member_child(node, container_id, kind) => {
                    self.register_field(node, owner_list)
                }
                _ => GoDeclarationContext::Inactive,
            },
            "method_elem" => match context {
                GoDeclarationContext::TypeOwner {
                    unit: parent,
                    container_id,
                    kind,
                } if direct_member_child(node, container_id, kind) => {
                    let owner_list = self.intern_field_owners(vec![GoFieldOwner {
                        unit: parent,
                        record_ranges: true,
                    }]);
                    self.register_interface_method(node, owner_list);
                    GoDeclarationContext::Inactive
                }
                GoDeclarationContext::Fields {
                    owner_list,
                    container_id,
                    kind,
                } if direct_member_child(node, container_id, kind) => {
                    self.register_interface_method(node, owner_list);
                    GoDeclarationContext::Inactive
                }
                _ => GoDeclarationContext::Inactive,
            },
            "type_elem" => match context {
                GoDeclarationContext::TypeOwner {
                    container_id,
                    kind: GoMemberContainerKind::Interface,
                    ..
                }
                | GoDeclarationContext::Fields {
                    container_id,
                    kind: GoMemberContainerKind::Interface,
                    ..
                } if direct_member_child(node, container_id, GoMemberContainerKind::Interface) => {
                    self.register_interface_embedding(node);
                    GoDeclarationContext::Inactive
                }
                _ => GoDeclarationContext::Inactive,
            },
            _ => context,
        }
    }

    fn enter_import_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        context: GoDeclarationContext,
        specs: &[GoImportSpecSyntax<'tree, 'source>],
    ) -> GoDeclarationContext {
        assert_eq!(node.kind(), "import_declaration");
        if !matches!(&context, GoDeclarationContext::TopLevel) {
            return self.register_declaration(node, context);
        }
        self.register_imports(node, specs);
        GoDeclarationContext::Inactive
    }

    fn register_imports<'tree>(
        &mut self,
        declaration: Node<'tree>,
        specs: &[GoImportSpecSyntax<'tree, 'source>],
    ) {
        for spec in specs
            .iter()
            .filter(|spec| is_primary_import_spec(declaration, spec.node))
        {
            let info = spec.to_import_info();
            let declaration = self.native.source_collector_mut().intern_node(spec.node);
            let alias_occurrence = spec
                .alias
                .map(|(_, alias)| self.native.source_collector_mut().intern_node(alias));
            let import = SourceImportFact::from_import(
                info,
                declaration,
                None,
                alias_occurrence,
                Vec::new(),
            );
            let id = SourceImportId::try_from_index(self.source_imports.len())
                .expect("Go source import ids must fit in a u32");
            self.source_imports.push(import);
            self.generic_imports.push(id);
        }
    }

    fn source_declaration(
        &mut self,
        owner: Node<'_>,
        name: Option<Node<'_>>,
        code_unit: CodeUnit,
    ) -> SourceDeclarationId {
        let declaration = self.native.declare_node(owner, name);
        self.source_declaration_units.push((declaration, code_unit));
        declaration
    }

    fn member_container_type(
        &self,
        node: Node<'_>,
    ) -> Option<brokk_bifrost_core::analyzer::go_facts::GoSourceTypeId> {
        let parent = node.parent()?;
        let container = if parent.kind() == "field_declaration_list" {
            parent.parent()?
        } else {
            parent
        };
        self.native.source_type_id(container)
    }

    fn register_function(&mut self, node: Node<'_>, parent: Option<CodeUnit>) -> Option<CodeUnit> {
        let file_scope = parent.is_none();
        let name_node = node.child_by_field_name("name")?;
        let name = go_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return None;
        }
        let short_name = parent
            .as_ref()
            .map(|parent| format!("{}.{}", parent.short_name(), name))
            .unwrap_or_else(|| name.to_string());
        let fq = match parent.as_ref() {
            Some(parent) => parent.fq().clone(),
            None => go_package_fq(&self.package_name),
        }
        .with_pushed(go_segment(name, SegmentKind::Member));
        let signature = node
            .child_by_field_name("parameters")
            .map(|parameters| go_node_text(parameters, self.source).trim().to_string());
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Function,
            self.package_name.clone(),
            short_name,
            signature,
            false,
            fq,
        );
        let top_level = parent.clone().unwrap_or_else(|| code_unit.clone());
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            parent,
            Some(top_level),
        );
        let (signature, parameter_text) = go_function_signature(node, self.source);
        let return_identity = node
            .child_by_field_name("result")
            .filter(|result| result.kind() != "parameter_list")
            .and_then(|result| self.native.source_type_id(result))
            .and_then(|type_id| self.native.source_type_identity(type_id));
        let receiver_type = go_method_receiver_type_node(node);
        let receiver_type_id =
            receiver_type.and_then(|receiver| self.native.source_type_id(receiver));
        let receiver_identity =
            receiver_type_id.and_then(|type_id| self.native.source_type_identity(type_id));
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            go_signature_metadata_with_identities(
                signature,
                node,
                self.source,
                &parameter_text,
                return_identity,
                receiver_identity,
            ),
        );
        let declaration = self.source_declaration(node, Some(name_node), code_unit.clone());
        let parameters = self.native.source_callable_parameters(node);
        let (results, result) = self.native.source_result_parameters(node);
        let body = node
            .child_by_field_name("body")
            .map(|body| self.native.source_collector_mut().intern_node(body));
        self.native
            .source_properties_mut()
            .add_callable(GoCallableFact {
                declaration,
                name: name.to_string(),
                owner: None,
                receiver: receiver_type_id,
                is_method: node.kind() == "method_declaration",
                parameters,
                results,
                result,
                body,
                file_scope,
            });
        Some(code_unit)
    }

    fn register_method(&mut self, node: Node<'_>) {
        let Some(receiver) = node.child_by_field_name("receiver") else {
            return;
        };
        let Some(receiver_name) = extract_go_receiver_name(receiver, self.source) else {
            return;
        };
        let parent_fq = go_package_fq(&self.package_name)
            .with_pushed(go_segment(&receiver_name, SegmentKind::Type));
        let parent = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Class,
            self.package_name.clone(),
            receiver_name,
            parent_fq,
        );
        self.register_function(node, Some(parent));
    }

    fn register_type_spec(&mut self, node: Node<'_>) -> Option<GoDeclarationContext> {
        let name_node = node.child_by_field_name("name")?;
        let type_node = node.child_by_field_name("type")?;
        let name = go_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return None;
        }
        let type_id = self
            .native
            .capture_source_type(type_node)
            .expect("Go type declaration has a source type fact");
        let fq = go_package_fq(&self.package_name).with_pushed(go_segment(name, SegmentKind::Type));
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Class,
            self.package_name.clone(),
            name.to_string(),
            fq,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            None,
            Some(code_unit.clone()),
        );
        let signature = go_type_signature(node, self.source);
        let signature_ordinal = self
            .parsed
            .add_signature(code_unit.clone(), signature.clone());
        if let Some(identity) = self.native.source_type_identity(type_id) {
            let metadata = SignatureMetadata::new(signature, Vec::new())
                .with_underlying_type_identity(Some(identity));
            self.parsed
                .add_metadata_for_signature(code_unit.clone(), signature_ordinal, metadata);
        }
        self.parsed.add_raw_supertypes(
            code_unit.clone(),
            go_embedded_type_texts(type_node, self.source),
        );
        for embedded in go_embedded_type_nodes(type_node) {
            let label = go_node_text(embedded, self.source).trim().to_string();
            let embedded_id = embedded
                .parent()
                .filter(|parent| parent.kind() == "field_declaration")
                .and_then(|field| self.native.capture_source_embedded_type(field, embedded))
                .or_else(|| self.native.capture_source_type(embedded));
            let Some(embedded_id) = embedded_id else {
                continue;
            };
            let Some(identity) = self.native.source_type_identity(embedded_id) else {
                continue;
            };
            let metadata =
                SignatureMetadata::new(label, Vec::new()).with_return_type_identity(Some(identity));
            self.parsed
                .add_metadata_for_signature(code_unit.clone(), signature_ordinal, metadata);
        }
        let declaration = self.source_declaration(node, Some(name_node), code_unit.clone());
        self.native
            .source_properties_mut()
            .add_type_declaration(declaration, name, type_id, true);
        Some(match member_container_kind(type_node) {
            Some(kind) => GoDeclarationContext::TypeOwnerPending {
                unit: code_unit,
                container_id: type_node.id(),
                kind,
            },
            None => GoDeclarationContext::Inactive,
        })
    }

    fn register_type_alias(&mut self, node: Node<'_>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = go_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let target = node
            .child_by_field_name("type")
            .and_then(|type_node| self.native.capture_source_type(type_node));
        let fq = go_package_fq(&self.package_name)
            .with_pushed(go_segment(GO_MODULE_SCOPE_SEGMENT, SegmentKind::Package))
            .with_pushed(go_segment(name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Field,
            self.package_name.clone(),
            format!("{GO_MODULE_SCOPE_SEGMENT}.{name}"),
            fq,
        );
        let range_node = sole_spec_declaration_node(node, "type_alias", "type_declaration");
        self.parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            self.source,
            None,
            Some(code_unit.clone()),
        );
        self.parsed.add_signature(
            code_unit.clone(),
            go_node_text(node, self.source).trim().to_string(),
        );
        self.parsed.mark_type_alias(code_unit.clone());
        let declaration = self.source_declaration(range_node, Some(name_node), code_unit);
        self.native
            .source_properties_mut()
            .add_alias(declaration, name, target);
    }

    fn register_value_spec(&mut self, node: Node<'_>, keyword: &'static str) {
        let names = children_by_field(node, "name");
        let identifier_count = names.len();
        let range_node = sole_spec_declaration_node(
            node,
            node.kind(),
            if keyword == "const" {
                "const_declaration"
            } else {
                "var_declaration"
            },
        );
        for name_node in names {
            let name = go_node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let fq = go_package_fq(&self.package_name)
                .with_pushed(go_segment(GO_MODULE_SCOPE_SEGMENT, SegmentKind::Package))
                .with_pushed(go_segment(name, SegmentKind::Member));
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.clone(),
                format!("{GO_MODULE_SCOPE_SEGMENT}.{name}"),
                fq,
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                range_node,
                self.source,
                None,
                Some(code_unit.clone()),
            );
            self.parsed.add_signature(
                code_unit.clone(),
                go_value_signature(node, self.source, keyword, name, identifier_count),
            );
            self.source_declaration(range_node, Some(name_node), code_unit);
        }
    }

    fn register_field(&mut self, node: Node<'_>, owner_list: usize) -> GoDeclarationContext {
        let owner_count = self.field_owner_lists[owner_list].len();
        let owner_type = self
            .member_container_type(node)
            .expect("Go field has a captured struct or interface owner");
        let names = children_by_field(node, "name");
        if names.is_empty() {
            if let Some((field_name, type_node)) = go_embedded_struct_field(node, self.source) {
                let type_id = self
                    .native
                    .capture_source_embedded_type(node, type_node)
                    .expect("Go embedded field has a source type fact");
                let mut declaration_id = None;
                for owner_index in 0..owner_count {
                    let owner = self.field_owner_lists[owner_list][owner_index].clone();
                    let fq = owner
                        .unit
                        .fq()
                        .clone()
                        .with_pushed(go_segment(&field_name, SegmentKind::Member));
                    let code_unit = CodeUnit::new_fq(
                        self.file.clone(),
                        CodeUnitType::Field,
                        self.package_name.clone(),
                        format!("{}.{}", owner.unit.short_name(), field_name),
                        fq,
                    );
                    if owner.record_ranges {
                        self.parsed.add_code_unit(
                            code_unit.clone(),
                            type_node,
                            self.source,
                            Some(owner.unit.clone()),
                            Some(owner.unit.clone()),
                        );
                    } else {
                        self.parsed.add_synthetic_code_unit(
                            code_unit.clone(),
                            Some(owner.unit.clone()),
                            Some(owner.unit.clone()),
                        );
                    }
                    let declaration = self.source_declaration(
                        node,
                        go_embedded_field_name_node(type_node),
                        code_unit.clone(),
                    );
                    if let Some(previous) = declaration_id {
                        assert_eq!(previous, declaration);
                    } else {
                        declaration_id = Some(declaration);
                    }
                    let type_text = go_node_text(type_node, self.source).trim().to_string();
                    let identity = self.native.source_type_identity(type_id);
                    self.parsed.add_signature_with_metadata(
                        code_unit,
                        SignatureMetadata::new(type_text.clone(), Vec::new())
                            .with_return_type_text(Some(type_text))
                            .with_return_type_identity(identity),
                    );
                }
                let declaration = declaration_id.expect("Go embedded field has a display owner");
                self.native.source_properties_mut().add_field(
                    declaration,
                    owner_type,
                    Some(type_id),
                    &field_name,
                    true,
                );
                let occurrence = self.native.source_collector_mut().intern_node(type_node);
                self.native
                    .source_properties_mut()
                    .add_embedding(owner_type, occurrence, type_id);
            }
            return GoDeclarationContext::Inactive;
        }

        let suffix = go_struct_field_suffix(node, self.source);
        let nested_type = go_field_inline_container_type(node);
        let type_node = node.child_by_field_name("type");
        let type_id = type_node.and_then(|type_node| self.native.capture_source_type(type_node));
        let mut nested_owners = Vec::new();
        for (index, name_node) in names.into_iter().enumerate() {
            let field_name = go_node_text(name_node, self.source).trim();
            if field_name.is_empty() {
                continue;
            }
            let mut declaration_id = None;
            for owner_index in 0..owner_count {
                let owner = self.field_owner_lists[owner_list][owner_index].clone();
                let fq = owner
                    .unit
                    .fq()
                    .clone()
                    .with_pushed(go_segment(field_name, SegmentKind::Member));
                let code_unit = CodeUnit::new_fq(
                    self.file.clone(),
                    CodeUnitType::Field,
                    self.package_name.clone(),
                    format!("{}.{}", owner.unit.short_name(), field_name),
                    fq,
                );
                if owner.record_ranges {
                    self.parsed.add_code_unit(
                        code_unit.clone(),
                        name_node,
                        self.source,
                        Some(owner.unit.clone()),
                        Some(owner.unit.clone()),
                    );
                } else {
                    self.parsed.add_synthetic_code_unit(
                        code_unit.clone(),
                        Some(owner.unit.clone()),
                        Some(owner.unit.clone()),
                    );
                }
                let declaration = self.source_declaration(node, Some(name_node), code_unit.clone());
                if let Some(previous) = declaration_id {
                    assert_eq!(previous, declaration);
                } else {
                    declaration_id = Some(declaration);
                }
                let type_text = type_node
                    .map(|type_node| go_node_text(type_node, self.source).trim().to_string())
                    .filter(|type_text| !type_text.is_empty());
                self.parsed.add_signature_with_metadata(
                    code_unit.clone(),
                    SignatureMetadata::new(format!("{field_name}{suffix}"), Vec::new())
                        .with_return_type_text(type_text)
                        .with_return_type_identity(
                            type_id.and_then(|type_id| self.native.source_type_identity(type_id)),
                        ),
                );
                if nested_type.is_some() {
                    nested_owners.push(GoFieldOwner {
                        unit: code_unit,
                        record_ranges: owner.record_ranges && index == 0,
                    });
                }
            }
            let declaration = declaration_id.expect("Go named field has a display owner");
            self.native.source_properties_mut().add_field(
                declaration,
                owner_type,
                type_id,
                field_name,
                false,
            );
        }
        if let Some(nested_type) = nested_type {
            let owner_list = self.intern_field_owners(nested_owners);
            GoDeclarationContext::FieldsPending {
                owner_list,
                container_id: nested_type.id(),
                kind: member_container_kind(nested_type)
                    .expect("inline Go field container must be struct or interface"),
            }
        } else {
            GoDeclarationContext::Inactive
        }
    }

    fn register_interface_method(&mut self, node: Node<'_>, owner_list: usize) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = go_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let signature = node
            .child_by_field_name("parameters")
            .map(|parameters| go_node_text(parameters, self.source).trim().to_string());
        let owner_type = self
            .member_container_type(node)
            .expect("Go interface method has a captured interface owner");
        let receiver_identity = None;
        let return_identity = node
            .child_by_field_name("result")
            .filter(|result| result.kind() != "parameter_list")
            .and_then(|result| self.native.source_type_id(result))
            .and_then(|type_id| self.native.source_type_identity(type_id));
        let mut declaration_id = None;
        for owner_index in 0..self.field_owner_lists[owner_list].len() {
            let owner = self.field_owner_lists[owner_list][owner_index].clone();
            let fq = owner
                .unit
                .fq()
                .clone()
                .with_pushed(go_segment(name, SegmentKind::Member));
            let code_unit = CodeUnit::with_signature_and_fq(
                self.file.clone(),
                CodeUnitType::Function,
                self.package_name.clone(),
                format!("{}.{}", owner.unit.short_name(), name),
                signature.clone(),
                false,
                fq,
            );
            if owner.record_ranges {
                self.parsed.add_code_unit(
                    code_unit.clone(),
                    node,
                    self.source,
                    Some(owner.unit.clone()),
                    Some(owner.unit.clone()),
                );
            } else {
                self.parsed.add_synthetic_code_unit(
                    code_unit.clone(),
                    Some(owner.unit.clone()),
                    Some(owner.unit.clone()),
                );
            }
            let declaration = self.source_declaration(node, Some(name_node), code_unit.clone());
            if let Some(previous) = declaration_id {
                assert_eq!(previous, declaration);
            } else {
                declaration_id = Some(declaration);
            }
            let (signature, parameter_text) = go_interface_method_signature(node, self.source);
            self.parsed.add_signature_with_metadata(
                code_unit,
                go_signature_metadata_with_identities(
                    signature,
                    node,
                    self.source,
                    &parameter_text,
                    return_identity.clone(),
                    receiver_identity.clone(),
                ),
            );
        }
        let declaration = declaration_id.expect("Go interface method has a display owner");
        let parameters = self.native.source_callable_parameters(node);
        let (results, result) = self.native.source_result_parameters(node);
        let body = None;
        self.native
            .source_properties_mut()
            .add_callable(GoCallableFact {
                declaration,
                name: name.to_string(),
                owner: Some(owner_type),
                receiver: None,
                is_method: true,
                parameters,
                results,
                result,
                body,
                file_scope: false,
            });
    }

    fn register_interface_embedding(&mut self, node: Node<'_>) {
        let owner = self
            .member_container_type(node)
            .expect("Go interface embedding has a captured interface owner");
        let type_id = self.native.source_type_id(node).or_else(|| {
            named_children(node)
                .into_iter()
                .find_map(|child| self.native.source_type_id(child))
        });
        let Some(type_id) = type_id else {
            return;
        };
        let occurrence = self.native.source_collector_mut().intern_node(node);
        self.native
            .source_properties_mut()
            .add_embedding(owner, occurrence, type_id);
    }

    fn intern_field_owners(&mut self, owners: Vec<GoFieldOwner>) -> usize {
        let owner_list = self.field_owner_lists.len();
        self.field_owner_lists.push(owners);
        owner_list
    }

    fn finish(self) {
        assert_eq!(self.declaration_contexts.len(), 1);
        assert_eq!(self.structural_parents, vec![None]);
        let structural = self
            .structural
            .finish()
            .expect("Go structural fact collection must finish");
        let native = self.native.finish();
        let GoResolutionOutput {
            facts,
            source_facts,
            go_source_facts,
            site_occurrences,
            declaration_sources,
        } = native;
        let source_imports = self.source_imports;
        let generic_imports = self.generic_imports;
        self.parsed.imports = generic_imports
            .iter()
            .map(|id| source_imports[id.index()].import_info(&source_facts))
            .collect();
        self.parsed.resolution_facts = facts;
        self.parsed.source_declaration_units = self.source_declaration_units;
        self.parsed.source_facts = Some(ParsedSourceFacts {
            js_ts: None,
            scala: None,
            php: None,
            cpp: None,
            go: Some(go_source_facts),
            java: None,
            ruby: None,
            python: None,
            declaration_visibilities: None,
            source_bytes: self.source.len(),
            occurrences: source_facts,
            structural,
            native_site_occurrences: site_occurrences,
            native_declaration_sources: declaration_sources,
            rust_declaration_properties: Vec::new(),
            rust_modules: None,
            rust_types: Vec::new(),
            rust_items: RustItemSourceFacts::default(),
            imports: source_imports,
            generic_imports,
            rust_import_contexts: Vec::new(),
        });
    }

    fn exit_node(&mut self, native_exit: bool) {
        if native_exit {
            self.native.exit();
        }
        self.declaration_contexts
            .pop()
            .expect("Go declaration context exit must balance");
        self.structural_parents
            .pop()
            .expect("Go structural parent exit must balance");
    }
}

#[cfg(test)]
mod coordinated_producer_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
    use std::collections::BTreeSet;
    use tree_sitter::Parser;

    fn parse(source: &str) -> ParsedFile {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar is valid");
        let tree = parser.parse(source, None).expect("Go source parses");
        let root = std::env::current_dir()
            .expect("test working directory")
            .join("bifrost-go-producer-tests");
        let file = ProjectFile::new(root, "sample.go");
        parse_go_file_with_package_name(&file, source, &tree, "p".to_string(), "p".to_string())
    }

    fn declaration_names(parsed: &ParsedFile) -> BTreeSet<String> {
        parsed
            .declarations()
            .iter()
            .map(|unit| unit.short_name().to_string())
            .collect()
    }

    #[test]
    fn multi_name_values_keep_one_whole_occurrence_and_distinct_name_occurrences() {
        let source = "package p\nvar alpha, beta int\nconst one, two = 1, 2\n";
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let rows = &facts.occurrences;
        let mut value_declarations = Vec::new();
        for (declaration, unit) in &parsed.source_declaration_units {
            if matches!(unit.short_name(), "_module_.alpha" | "_module_.beta") {
                value_declarations.push((*declaration, unit.short_name().to_string()));
            }
        }
        assert_eq!(value_declarations.len(), 2);
        let declarations = value_declarations
            .iter()
            .map(|(id, _)| {
                facts
                    .occurrences
                    .occurrence(facts.occurrences.declaration(*id).occurrence)
                    .range
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations[0], declarations[1]);
        let declaration_text = &source[declarations[0].start_byte..declarations[0].end_byte];
        assert_eq!(declaration_text, "var alpha, beta int");
        let names = value_declarations
            .iter()
            .map(|(id, _)| {
                let name = facts
                    .occurrences
                    .declaration(*id)
                    .name
                    .expect("name occurrence");
                rows.occurrence(name).range
            })
            .collect::<Vec<_>>();
        assert_ne!(names[0], names[1]);
        assert!(names.iter().all(|range| {
            range.start_byte >= declarations[0].start_byte
                && range.end_byte <= declarations[0].end_byte
        }));
        let native_declarations = facts
            .native_declaration_sources
            .iter()
            .map(|(_, declaration)| *declaration)
            .collect::<Vec<_>>();
        assert!(
            value_declarations
                .iter()
                .all(|(declaration, _)| native_declarations.contains(declaration))
        );
        assert_eq!(
            facts.native_site_occurrences.len(),
            parsed.resolution_facts.sites.len()
        );
        assert!(!facts.structural.nodes().is_empty());
    }

    #[test]
    fn untyped_consts_keep_native_bindings_without_fabricated_runtime_types() {
        let source = "package p\nconst one, two = 1, 2\n";
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let const_units = parsed
            .source_declaration_units
            .iter()
            .filter(|(_, unit)| matches!(unit.short_name(), "_module_.one" | "_module_.two"))
            .collect::<Vec<_>>();
        assert_eq!(const_units.len(), 2);
        for (id, _) in const_units {
            let (site, _) = facts
                .native_declaration_sources
                .iter()
                .find(|(_, native)| native == id)
                .expect("constant declaration retains its native binding");
            assert!(
                parsed
                    .resolution_facts
                    .binders
                    .iter()
                    .any(|binder| binder.declaration == *site)
            );
            assert!(!parsed.resolution_facts.gaps.iter().any(|gap| gap.site == *site
                && gap.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::InferredType),
                "constant declaration {site:?} has inferred-type gaps: {:#?}",
                parsed.resolution_facts.gaps.iter().filter(|gap| gap.site == *site).collect::<Vec<_>>());
        }
        assert!(
            parsed.resolution_facts.intrinsic_type_seeds.is_empty(),
            "untyped constant values must not acquire default runtime types"
        );
    }

    #[test]
    fn imports_keep_alias_forms_and_source_projection_links() {
        let source = concat!(
            "package p\n",
            "import (\n",
            "alias \"example.com/alias\"\n",
            ". \"example.com/dot\"\n",
            "_ \"example.com/blank\"\n",
            ")\n",
        );
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        assert_eq!(facts.imports.len(), 3);
        assert_eq!(facts.generic_imports.len(), 3);
        assert_eq!(parsed.imports.len(), 3);
        assert_eq!(
            parsed
                .imports
                .iter()
                .map(|import| import.raw_snippet.as_str())
                .collect::<Vec<_>>(),
            vec![
                "import alias \"example.com/alias\"",
                "import . \"example.com/dot\"",
                "import _ \"example.com/blank\"",
            ]
        );
        for (index, import) in facts.imports.iter().enumerate() {
            assert_eq!(import.target, None);
            assert!(import.alias_occurrence.is_some());
            let id = SourceImportId::try_from_index(index).expect("import id");
            assert_eq!(facts.generic_imports[index], id);
            assert_eq!(
                parsed.imports[index]
                    .path
                    .as_ref()
                    .map(|path| path.segments.len()),
                Some(2)
            );
            assert_eq!(
                import.import_info(&facts.occurrences).raw_snippet,
                parsed.imports[index].raw_snippet
            );
        }

        let alias_texts = facts
            .imports
            .iter()
            .map(|import| {
                let occurrence = facts
                    .occurrences
                    .occurrence(import.alias_occurrence.expect("Go import alias occurrence"));
                &source[occurrence.range.start_byte..occurrence.range.end_byte]
            })
            .collect::<Vec<_>>();
        assert_eq!(alias_texts, vec!["alias", ".", "_"]);

        assert_eq!(parsed.resolution_facts.root_imports.len(), 3);
        for import in &facts.imports {
            assert_eq!(
                parsed
                    .resolution_facts
                    .root_imports
                    .iter()
                    .filter(|root| facts.native_site_occurrences[root.site.index()]
                        == import.declaration)
                    .count(),
                1,
                "each named, dot and blank import retains its exact source occurrence"
            );
        }
        let dot_site = parsed
            .resolution_facts
            .root_imports
            .iter()
            .find(|root| {
                facts.native_site_occurrences[root.site.index()] == facts.imports[1].declaration
            })
            .expect("dot import root")
            .site;
        assert_eq!(
            facts.native_site_occurrences[dot_site.index()],
            facts.imports[1].declaration,
            "native dot-import route must retain the exact import-spec occurrence"
        );
        let dot_segments = parsed
            .resolution_facts
            .root_import_segments
            .iter()
            .filter(|segment| segment.import_site == dot_site)
            .map(|segment| {
                parsed.resolution_facts.names[segment.name.index()]
                    .spelling
                    .as_str()
            })
            .collect::<Vec<_>>();
        assert_eq!(dot_segments, vec!["example.com", "dot"]);

        let declaration_site = parsed
            .resolution_facts
            .sites
            .iter()
            .find(|site| {
                &source[site.start_byte..site.end_byte]
                    == "import (\nalias \"example.com/alias\"\n. \"example.com/dot\"\n_ \"example.com/blank\"\n)"
            })
            .expect("whole import declaration native site");
        assert!(parsed.resolution_facts.gaps.iter().any(|gap| {
            gap.site == declaration_site.id
                && gap.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedRoute
        }));
    }

    #[test]
    fn structural_admission_survives_native_unsupported_subtrees() {
        let source = "package p\nfunc f() { if true { missing() } }\n";
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        assert!(
            facts
                .structural
                .nodes()
                .iter()
                .any(|node| node.kind == NormalizedKind::Call)
        );
    }

    #[test]
    fn unsupported_type_descendants_do_not_leak_member_owners() {
        let source = concat!(
            "package p\n",
            "type M map[string]struct { Hidden int }\n",
            "type S []struct { Hidden int }\n",
            "type F func() interface { Hidden() }\n",
            "type Box[T interface { Constraint() }] struct { Value int }\n",
        );
        let parsed = parse(source);
        let names = declaration_names(&parsed);

        assert!(names.contains("M"));
        assert!(names.contains("S"));
        assert!(names.contains("F"));
        assert!(names.contains("Box"));
        assert!(names.contains("Box.Value"));
        for leaked in ["M.Hidden", "S.Hidden", "F.Hidden", "Box.Constraint"] {
            assert!(
                !names.contains(leaked),
                "unsupported descendant leaked: {leaked}"
            );
        }
    }

    #[test]
    fn type_and_embedded_metadata_share_the_original_display_signature() {
        let source = concat!(
            "package p\n",
            "type Base struct{}\n",
            "type Alias Base\n",
            "type Outer struct {\n",
            "    Base\n",
            "    Base\n",
            "}\n",
            "type Outer interface { Base }\n",
        );
        let parsed = parse(source);
        let outers = parsed
            .declarations()
            .iter()
            .filter(|unit| unit.is_class() && unit.identifier() == "Outer")
            .collect::<Vec<_>>();
        assert_eq!(outers.len(), 1, "same-FQ type alternatives share one unit");

        for outer in outers {
            let signatures = parsed
                .signatures
                .get(outer)
                .expect("Outer display signature");
            assert_eq!(signatures, &["Outer struct {", "Outer interface {"]);

            let metadata = parsed
                .signature_metadata
                .get(outer)
                .expect("Outer embedded metadata");
            assert_eq!(
                metadata.len(),
                2,
                "Base embeds deduplicate within each signature"
            );
            assert_eq!(metadata[0].label(), "Base");
            assert!(metadata[0].return_type_identity().is_some());
            assert_eq!(metadata[0], metadata[1]);
            assert_eq!(
                parsed.signature_metadata_signature_ordinals.get(outer),
                Some(&vec![0, 1])
            );
        }

        let alias = parsed
            .declarations()
            .iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Alias")
            .expect("Alias type declaration");
        assert_eq!(
            parsed.signatures.get(alias),
            Some(&vec!["Alias Base".to_string()])
        );
        let alias_metadata = parsed
            .signature_metadata
            .get(alias)
            .expect("Alias type metadata");
        assert_eq!(alias_metadata.len(), 1);
        assert_eq!(alias_metadata[0].label(), "Alias Base");
        assert!(alias_metadata[0].underlying_type_identity().is_some());
        assert_eq!(
            parsed.signature_metadata_signature_ordinals.get(alias),
            Some(&vec![0])
        );
    }

    #[test]
    fn inline_multi_name_containers_preserve_direct_and_synthetic_members() {
        let source = concat!(
            "package p\n",
            "type Outer struct {\n",
            "    A, B struct { Inner int }\n",
            "    C, D interface { Method() }\n",
            "}\n",
        );
        let parsed = parse(source);
        let names = declaration_names(&parsed);
        for name in [
            "Outer",
            "Outer.A",
            "Outer.B",
            "Outer.A.Inner",
            "Outer.B.Inner",
            "Outer.C",
            "Outer.D",
            "Outer.C.Method",
            "Outer.D.Method",
        ] {
            assert!(names.contains(name), "missing inline declaration: {name}");
        }

        let source_names = parsed
            .source_declaration_units
            .iter()
            .map(|(_, unit)| unit.short_name())
            .collect::<BTreeSet<_>>();
        assert!(source_names.contains("Outer.A.Inner"));
        assert!(source_names.contains("Outer.B.Inner"));
        assert!(source_names.contains("Outer.C.Method"));
        assert!(source_names.contains("Outer.D.Method"));

        let unit = |name: &str| {
            parsed
                .declarations()
                .iter()
                .find(|unit| unit.short_name() == name)
                .unwrap_or_else(|| panic!("missing declaration {name}"))
        };
        assert!(!parsed.declaration_ranges(unit("Outer.A.Inner")).is_empty());
        assert!(parsed.declaration_ranges(unit("Outer.B.Inner")).is_empty());
        assert!(!parsed.declaration_ranges(unit("Outer.C.Method")).is_empty());
        assert!(parsed.declaration_ranges(unit("Outer.D.Method")).is_empty());

        let source_declaration = |name: &str| {
            parsed
                .source_declaration_units
                .iter()
                .find(|(_, unit)| unit.short_name() == name)
                .map(|(declaration, _)| *declaration)
                .unwrap_or_else(|| panic!("missing source declaration {name}"))
        };
        assert_eq!(
            source_declaration("Outer.A.Inner"),
            source_declaration("Outer.B.Inner")
        );
        assert_eq!(
            source_declaration("Outer.C.Method"),
            source_declaration("Outer.D.Method")
        );
    }

    #[test]
    fn go_source_facts_capture_shapes_and_complete_callable_lists() {
        let source = concat!(
            "package p\n",
            "type Base struct{}\n",
            "type Alias = [4]*Base\n",
            "type Holder struct { *Base }\n",
            "func Run(a, b [4]*Base, tail ...chan<- Base) (Base, error) { }\n",
        );
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().expect("source facts");
        let go = facts.go.as_ref().expect("Go source facts");
        assert!(go.types.iter().any(|fact| matches!(
            &fact.shape,
            brokk_bifrost_core::analyzer::go_facts::GoSourceTypeShape::Array {
                length_text, ..
            } if length_text == "4"
        )));
        assert!(go.types.iter().any(|fact| matches!(
            &fact.shape,
            brokk_bifrost_core::analyzer::go_facts::GoSourceTypeShape::Channel {
                direction: brokk_bifrost_core::analyzer::go_facts::GoChannelDirection::Send,
                ..
            }
        )));
        let run = go
            .callables
            .iter()
            .find(|callable| callable.name == "Run")
            .expect("Run source callable");
        assert_eq!(run.parameters.as_ref().map(Vec::len), Some(3));
        assert_eq!(run.results.len(), 2);
        assert!(run.parameters.as_ref().unwrap()[2].variadic);
        assert!(go.aliases.iter().any(|alias| alias.name == "Alias"));
        let holder = go
            .declarations
            .iter()
            .find(|declaration| declaration.name == "Holder")
            .expect("Holder source type");
        let embedded = go
            .fields
            .iter()
            .find(|field| field.owner == holder.ty && field.embedded)
            .expect("Holder embedded field");
        assert!(matches!(
            embedded.ty.map(|id| &go.types[id.index()].shape),
            Some(brokk_bifrost_core::analyzer::go_facts::GoSourceTypeShape::Pointer(_))
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_go;

    /// Go declarations record the modifier facts the language states, so a Go
    /// workspace callable has a receiver contract and therefore a canonical
    /// procedure key (#3455).
    ///
    /// Go writes no static modifier, so the receiver contract is decided by
    /// the declaration's own shape: a package-level function binds nothing, a
    /// method states its receiver, and an interface method is dispatched on
    /// the interface value. Visibility is the exported-identifier rule.
    #[test]
    fn callable_metadata_records_go_receiver_contracts_structurally() {
        const SOURCE: &str = concat!(
            "package shop\n",
            "\n",
            "type Client struct{}\n",
            "\n",
            "func (c *Client) Send(orderID string) {}\n",
            "\n",
            "func (c Client) describe() string { return \"client\" }\n",
            "\n",
            "type Sender interface {\n",
            "\tDeliver(orderID string) error\n",
            "}\n",
            "\n",
            "func Total(orderID string, lines []int64) int64 { return 0 }\n",
            "\n",
            "func accumulate(lines []int64) int64 { return 0 }\n",
        );
        let tree = parse_go(SOURCE).expect("parse the Go fixture");
        // A real module root, so the canonical package identity is the import
        // path rather than whatever directory the temporary file happens to
        // sit in.
        let root = tempfile::TempDir::new().expect("temporary Go module root");
        std::fs::write(
            root.path().join("go.mod"),
            "module example.com/shop

go 1.22
",
        )
        .expect("write go.mod");
        let file = ProjectFile::new(root.path().to_path_buf(), "shop.go");
        let parsed = parse_go_file(&file, SOURCE, &tree);

        let modifiers = |fq_name: &str| {
            let (_, entries) = parsed
                .signature_metadata
                .iter()
                .find(|(unit, _)| unit.fq_name() == fq_name)
                .unwrap_or_else(|| {
                    panic!(
                        "missing Go declaration {fq_name}; recorded {:?}",
                        parsed
                            .signature_metadata
                            .keys()
                            .map(CodeUnit::fq_name)
                            .collect::<Vec<_>>()
                    )
                });
            let metadata = entries
                .first()
                .unwrap_or_else(|| panic!("{fq_name} carries no signature metadata"));
            assert!(
                metadata.callable_modifiers_recorded(),
                "{fq_name} must record that the walk read its declaration shape"
            );
            (
                metadata.callable_is_static(),
                metadata.callable_is_constructor(),
                metadata.callable_declared_visibility(),
                metadata.parameters().len(),
            )
        };

        assert_eq!(
            modifiers("example.com/shop.Total"),
            (false, false, Some(DeclaredVisibility::Public), 2),
            "an exported package function binds no receiver and is visible everywhere"
        );
        assert_eq!(
            modifiers("example.com/shop.accumulate"),
            (false, false, Some(DeclaredVisibility::PackagePrivate), 1),
            "an unexported package function is visible only inside its package"
        );
        assert_eq!(
            modifiers("example.com/shop.Client.Send"),
            (false, false, Some(DeclaredVisibility::Public), 1),
            "a pointer-receiver method states its receiver in the declaration"
        );
        assert_eq!(
            modifiers("example.com/shop.Client.describe"),
            (false, false, Some(DeclaredVisibility::PackagePrivate), 0),
            "a value-receiver method states its receiver too"
        );
        assert_eq!(
            modifiers("example.com/shop.Sender.Deliver"),
            (false, false, Some(DeclaredVisibility::Public), 1),
            "an interface method is dispatched on the interface value"
        );
    }
}
