//! Exact semantic packs from explicit C++ include roots.

use crate::CancellationToken;
use crate::analyzer::ProjectFile;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use crate::analyzer::cpp::CppAnalyzer;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, AuthoredPayload, AuthoredSemanticModelPack,
    AuthoredShard, BoundedDependencyDiagnostics, BoundedProducerDiagnostics, CatalogCoordinate,
    Compatibility, Completeness, DependencyArtifactRole, DependencyDiscoveryOutcome,
    DependencyDiscoveryProfile, DependencyPackAdapter, DependencyPackDiagnostic,
    DependencyPackDiagnosticSeverity, DependencyPackLimits, DependencyPackProduction,
    ExactDependencyArtifact, ExternalArtifactKind, HierarchyFact, HierarchyKind, ImplicitOperation,
    Locator, MemberFact, MemberIdentity, MemberKind, NameSelector, Parameter, Producer, Provenance,
    ReceiverFact, ResolvedDependency, ResolvedDependencyArtifact, Safety,
    SemanticModelActivationEvidence, Signature, StructuredTypeExpression, TypeCopySemantics,
    TypeFact, TypeIdentity, TypeKind, TypeMoveSemantics, TypeRef, TypeRefReferenceKind,
    TypeValueSemantics, Visibility, WildcardVariance, member_declaration_id, type_declaration_id,
};
use crate::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelOriginKind, SemanticModelOverlay,
    SemanticModelSymbolKind,
};
use crate::analyzer::structural::BoundaryStatus;
use crate::analyzer::topology::DependencyScope;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{Language, Project};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::model::{
    CppTemplateExpression, CppTemplateMetadata, CppTemplateParameterKind, CppTemplateTerm,
    StructuredTypeIdentity, StructuredTypeNodeId, StructuredTypeNodeView,
};
use brokk_bifrost_core::analyzer::project::decode_source_bytes;
use brokk_bifrost_cpp::compile_context::CppCompileContexts;
use brokk_bifrost_cpp::compile_context::CppExternalIncludeResolution;
use brokk_bifrost_cpp::declarations::{CppComparableNode, CppComparableSlot, CppParameterType};
use brokk_bifrost_cpp::external_declarations::{
    CppCallableExplicitness, CppExternalDeclarationCompleteness, CppExternalDeclarationLimits,
    CppExternalMemberKind, CppExternalVisibility, external_angle_include_paths,
    external_angle_include_paths_from_root, extract_external_declarations,
};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default)]
pub struct CppDependencyPackAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BasicStringConstructorRole {
    Copy,
    Move,
    CharacterData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BasicStringAssignmentRole {
    Copy,
    Move,
}

impl BasicStringAssignmentRole {
    fn operation(self) -> ImplicitOperation {
        match self {
            Self::Copy => ImplicitOperation::CopyAssignment,
            Self::Move => ImplicitOperation::MoveAssignment,
        }
    }
}

impl BasicStringConstructorRole {
    fn operation(self) -> ImplicitOperation {
        match self {
            Self::Copy => ImplicitOperation::CopyConstructor,
            Self::Move => ImplicitOperation::MoveConstructor,
            Self::CharacterData => ImplicitOperation::ValuePreservingConstructor,
        }
    }
}

/// Return the exact template parameter names of the standard library's primary
/// `std::basic_string` declaration. The names themselves are retained in the
/// pack, while the canonical identity and default relationships are proven by
/// the structured metadata terms.
fn exact_basic_string_template_parameters(
    name: &str,
    metadata: Option<&CppTemplateMetadata>,
) -> Option<Vec<String>> {
    if name != "std.basic_string" {
        return None;
    }
    let metadata = metadata?;
    if metadata.primary_name != "basic_string"
        || metadata.primary_fq_name != "std.basic_string"
        || metadata.alias_target.is_some()
        || !metadata.is_primary()
    {
        return None;
    }
    let [character, traits, allocator] = metadata.parameters.as_slice() else {
        return None;
    };
    if [character, traits, allocator]
        .into_iter()
        .any(|parameter| parameter.kind != CppTemplateParameterKind::Type || parameter.variadic)
        || character.default.is_some()
        || !template_default_relation(traits.default.as_ref(), "char_traits", &character.name)
        || !template_default_relation(allocator.default.as_ref(), "allocator", &character.name)
        || character.name == traits.name
        || character.name == allocator.name
        || traits.name == allocator.name
    {
        return None;
    }
    Some(
        metadata
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .collect(),
    )
}

/// Match one default template argument without consulting its rendered source
/// text. The extractor's term is a `template_type` whose argument list has one
/// parameter reference; this proves the default relation independently of the
/// parameter spelling chosen by a particular standard-library implementation.
fn template_default_relation(
    expression: Option<&CppTemplateExpression>,
    expected_base: &str,
    parameter_name: &str,
) -> bool {
    let Some(CppTemplateTerm::Node { kind, children }) = expression.map(|value| &value.term) else {
        return false;
    };
    if kind != "template_type" {
        return false;
    }
    let [base, arguments] = children.as_slice() else {
        return false;
    };
    if !matches!(
        base,
        CppTemplateTerm::Atom { kind, text }
            if kind == "identifier" && text == expected_base
    ) {
        return false;
    }
    let CppTemplateTerm::Node {
        kind: argument_kind,
        children: argument_children,
    } = arguments
    else {
        return false;
    };
    let [open, parameter, close] = argument_children.as_slice() else {
        return false;
    };
    matches!(
        (open, parameter, close),
        (
            CppTemplateTerm::Atom { kind: open_kind, text: open_text },
            CppTemplateTerm::Parameter(name),
            CppTemplateTerm::Atom { kind: close_kind, text: close_text },
        ) if argument_kind == "template_argument_list"
            && open_kind == "<"
            && open_text == "<"
            && name == parameter_name
            && close_kind == ">"
            && close_text == ">"
    )
}

fn basic_string_constructor_role(
    owner_name: &str,
    type_parameters: &[String],
    member: &brokk_bifrost_cpp::external_declarations::CppExternalMember,
) -> Option<BasicStringConstructorRole> {
    if member.kind != CppExternalMemberKind::Function
        || member.owner.as_deref() != Some(owner_name)
        || member.name != "basic_string"
        || member.return_type.is_some()
    {
        return None;
    }
    match member.parameter_types.as_deref()? {
        [CppParameterType::Structured(identity)] => {
            let root = identity.root_id();
            let (role, inner) = match identity.view(root)? {
                StructuredTypeNodeView::Reference(inner) => {
                    (BasicStringConstructorRole::Copy, inner)
                }
                StructuredTypeNodeView::RvalueReference(inner) => {
                    (BasicStringConstructorRole::Move, inner)
                }
                _ => return None,
            };
            is_basic_string_self_type(identity, inner).then_some(role)
        }
        [
            CppParameterType::Structured(character_data),
            CppParameterType::Structured(allocator),
        ] => {
            let [character_parameter, _, allocator_parameter] = type_parameters else {
                return None;
            };
            let Some(StructuredTypeNodeView::Pointer(character)) =
                character_data.view(character_data.root_id())
            else {
                return None;
            };
            let Some(StructuredTypeNodeView::Reference(allocator_type)) =
                allocator.view(allocator.root_id())
            else {
                return None;
            };
            let [
                CppComparableSlot::Shape(character_shape),
                CppComparableSlot::Shape(allocator_shape),
            ] = member.parameter_shapes.as_deref()?
            else {
                return None;
            };
            (member.explicitness == Some(CppCallableExplicitness::Implicit)
                && member.callable_arity
                    == Some(brokk_bifrost_core::analyzer::model::CallableArity::new(
                        1, 2, false,
                    ))
                && is_basic_string_type_parameter(character_data, character, character_parameter)
                && is_basic_string_type_parameter(allocator, allocator_type, allocator_parameter)
                && is_const_pointer_to_basic_string_type_parameter(
                    character_shape,
                    character_parameter,
                )
                && is_const_reference_to_basic_string_type_parameter(
                    allocator_shape,
                    allocator_parameter,
                ))
            .then_some(BasicStringConstructorRole::CharacterData)
        }
        _ => None,
    }
}

fn is_const_pointer_to_basic_string_type_parameter(
    shape: &brokk_bifrost_cpp::declarations::CppComparableParameter,
    parameter: &str,
) -> bool {
    let CppComparableNode::Pointer {
        inner,
        konst: false,
        volatil: false,
    } = shape.node(shape.root())
    else {
        return false;
    };
    comparable_basic_string_type_parameter(shape, *inner, parameter, true)
}

fn is_const_reference_to_basic_string_type_parameter(
    shape: &brokk_bifrost_cpp::declarations::CppComparableParameter,
    parameter: &str,
) -> bool {
    let CppComparableNode::Reference { inner } = shape.node(shape.root()) else {
        return false;
    };
    comparable_basic_string_type_parameter(shape, *inner, parameter, true)
}

fn comparable_basic_string_type_parameter(
    shape: &brokk_bifrost_cpp::declarations::CppComparableParameter,
    node: usize,
    parameter: &str,
    expected_const: bool,
) -> bool {
    let CppComparableNode::Named {
        name,
        primitive: false,
        konst,
        volatil: false,
    } = shape.node(node)
    else {
        return false;
    };
    *konst == expected_const
        && name.lexical_scope() == ["std", "basic_string"]
        && name.path() == [parameter]
        && !name.is_absolute()
}

fn is_basic_string_type_parameter(
    identity: &StructuredTypeIdentity,
    node: StructuredTypeNodeId,
    parameter: &str,
) -> bool {
    let Some(StructuredTypeNodeView::Named(name)) = identity.view(node) else {
        return false;
    };
    name.lexical_scope() == ["std", "basic_string"]
        && name.path() == [parameter]
        && !name.is_absolute()
}

fn basic_string_assignment_role(
    owner_name: &str,
    member: &brokk_bifrost_cpp::external_declarations::CppExternalMember,
) -> Option<BasicStringAssignmentRole> {
    if member.kind != CppExternalMemberKind::Function
        || member.owner.as_deref() != Some(owner_name)
        || member.name != "operator="
    {
        return None;
    }
    let return_type = member.return_type.as_ref()?;
    let Some(StructuredTypeNodeView::Reference(returned)) = return_type.view(return_type.root_id())
    else {
        return None;
    };
    if !is_basic_string_self_type(return_type, returned) {
        return None;
    }
    let [CppParameterType::Structured(identity)] = member.parameter_types.as_deref()? else {
        return None;
    };
    let root = identity.root_id();
    let (role, inner) = match identity.view(root)? {
        StructuredTypeNodeView::Reference(inner) => (BasicStringAssignmentRole::Copy, inner),
        StructuredTypeNodeView::RvalueReference(inner) => (BasicStringAssignmentRole::Move, inner),
        _ => return None,
    };
    is_basic_string_self_type(identity, inner).then_some(role)
}

fn is_basic_string_self_type(
    identity: &StructuredTypeIdentity,
    node: StructuredTypeNodeId,
) -> bool {
    let Some(StructuredTypeNodeView::Named(name)) = identity.view(node) else {
        return false;
    };
    let path = name.path();
    let scope = name.lexical_scope();
    scope == ["std", "basic_string"]
        && ((path == ["basic_string"] && !name.is_absolute()) || (path == ["std", "basic_string"]))
}

/// Refine one C++ route with explicit include and activated-pack evidence.
pub(crate) fn external_boundary_evidence(
    analyzer: &CppAnalyzer,
    overlay: Option<&SemanticModelOverlay>,
    file: &ProjectFile,
    name: &str,
) -> (BoundaryStatus, Option<String>) {
    let Some(resolved_headers) = directly_reached_external_headers(analyzer, file) else {
        return (BoundaryStatus::ExternalUnknown, None);
    };
    let Some(resolved_headers) = resolved_headers.headers() else {
        return (BoundaryStatus::ExternalUnknown, None);
    };
    if resolved_headers.is_empty() {
        return (BoundaryStatus::ExternalUnknown, None);
    }

    let matches = overlay
        .into_iter()
        .flat_map(|overlay| overlay.symbols_named(name).records)
        .filter(|symbol| symbol.language == "cpp")
        .filter(|symbol| symbol_is_in_headers(symbol, resolved_headers))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [symbol] => (BoundaryStatus::ExternalIndexed, Some(symbol.id.clone())),
        [] => (BoundaryStatus::ExternalDeclaredUnindexed, None),
        _ => (BoundaryStatus::ExternalIndexed, None),
    }
}

/// Whether a direct external include publishes one exact owner/member pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CppExternalMemberResolution {
    Indexed,
    DeclaredUnindexed,
    Absent,
    Unknown,
}

/// Exact active-model identity corresponding to one structurally resolved C++
/// external type occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CppExternalTypeModelResolution {
    Unique(String),
    Incomplete,
    Conflict,
}

/// Resolve one parser-derived C++ type occurrence through a directly reached
/// generated header model.
///
/// Only an explicitly qualified structured name is admitted. The matched
/// alias, its declared target, exact artifact provenance, and complete header
/// closure must all agree. A rendered spelling or terminal name alone can
/// therefore never select a model owner.
pub(crate) fn external_structured_type_model_resolution(
    analyzer: &CppAnalyzer,
    overlay: Option<&SemanticModelOverlay>,
    file: &ProjectFile,
    identity: &StructuredTypeIdentity,
) -> CppExternalTypeModelResolution {
    let Some(headers) = directly_reached_external_headers(analyzer, file) else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    let Some(headers) = headers.headers() else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    let Some(overlay) = overlay else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    let Some(name) = identity.nominal_name() else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    if !name.lexical_scope().is_empty() || name.path().len() < 2 {
        return CppExternalTypeModelResolution::Incomplete;
    }
    let qualified_name = name.path().join(".");
    let mut records = overlay
        .symbols_named(&qualified_name)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.language == "cpp"
                && symbol.owner_id.is_none()
                && symbol.qualified_name == qualified_name
                && symbol_is_in_headers(symbol, headers)
                && symbol.provenance.origin == SemanticModelOriginKind::ExactGeneratedOutput
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.id.cmp(&right.id));
    if records.len() > 1 || records.iter().any(|record| record.provenance.ambiguous) {
        return CppExternalTypeModelResolution::Conflict;
    }
    let [record] = records.as_slice() else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    if record.provenance.completeness != SemanticModelCompleteness::Complete
        || record.kind != SemanticModelSymbolKind::TypeAlias
    {
        return CppExternalTypeModelResolution::Incomplete;
    }
    let Some(underlying) = record.underlying_type.as_ref() else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    let [TypeRef::Declared { id, .. }] = underlying.referenced_types.as_slice() else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    let target = overlay.symbols_with_id(id);
    let [target] = target.records.as_slice() else {
        return CppExternalTypeModelResolution::Incomplete;
    };
    if target.owner_id.is_some()
        || target.language != "cpp"
        || target.provenance.pack_digest != record.provenance.pack_digest
        || target.provenance.origin != SemanticModelOriginKind::ExactGeneratedOutput
        || target.provenance.completeness != SemanticModelCompleteness::Complete
        || target.provenance.ambiguous
        || !symbol_is_in_headers(target, headers)
    {
        return CppExternalTypeModelResolution::Incomplete;
    }
    CppExternalTypeModelResolution::Unique(target.id.clone())
}

pub(crate) fn external_member_resolution(
    analyzer: &CppAnalyzer,
    overlay: Option<&SemanticModelOverlay>,
    file: &ProjectFile,
    owner_name: &str,
    member_name: &str,
) -> CppExternalMemberResolution {
    let Some(headers) = directly_reached_external_headers(analyzer, file) else {
        return CppExternalMemberResolution::Unknown;
    };
    let Some(headers) = headers.headers() else {
        return CppExternalMemberResolution::Unknown;
    };
    let mut matching_owner = false;
    let mut partial_owner = false;
    if let Some(overlay) = overlay {
        for owner in overlay
            .symbols_named(owner_name)
            .records
            .into_iter()
            .filter(|owner| {
                owner.language == "cpp"
                    && owner.owner_id.is_none()
                    && symbol_is_in_headers(owner, headers)
            })
        {
            matching_owner = true;
            partial_owner |= owner.provenance.completeness == SemanticModelCompleteness::Partial;
            if overlay
                .members_of(&owner.id)
                .records
                .into_iter()
                .any(|member| {
                    member.name == member_name
                        && member.visibility == Visibility::Public
                        && symbol_is_in_headers(member, headers)
                })
            {
                return CppExternalMemberResolution::Indexed;
            }
        }
    }
    if matching_owner && !partial_owner {
        CppExternalMemberResolution::Absent
    } else if headers.is_empty() {
        CppExternalMemberResolution::Unknown
    } else {
        CppExternalMemberResolution::DeclaredUnindexed
    }
}

fn directly_reached_external_headers(
    analyzer: &CppAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<ReachedExternalHeaders>> {
    let cancellation = analyzer.active_query_cancellation();
    let keep_going = || {
        !cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    };
    directly_reached_external_headers_while(analyzer, file, &keep_going)
}

fn directly_reached_external_headers_while(
    analyzer: &CppAnalyzer,
    file: &ProjectFile,
    keep_going: &impl Fn() -> bool,
) -> Option<Arc<ReachedExternalHeaders>> {
    let cell = analyzer.external_header_closure_cell(file);
    match cell.get_or_try_build_pool_independent_while(keep_going, || {
        Ok::<_, std::convert::Infallible>(build_directly_reached_external_headers(
            analyzer, file, keep_going,
        ))
    }) {
        Ok(outcome) => outcome,
        Err(never) => match never {},
    }
}

fn build_directly_reached_external_headers(
    analyzer: &CppAnalyzer,
    file: &ProjectFile,
    keep_going: &impl Fn() -> bool,
) -> Option<ReachedExternalHeaders> {
    if !keep_going() {
        return None;
    }
    analyzer.record_external_header_closure_build();
    // Runs on a cache miss only, nested inside whatever request scope the
    // caller opened (issue #2414 step 3).
    let scope = AnalyzerQueryScope::new(analyzer);
    let Some(syntax) = analyzer.prepared_syntax(scope.token(), file) else {
        return Some(ReachedExternalHeaders::Unavailable);
    };
    const MAX_CLOSURE_HEADERS: usize = 10_000;
    const MAX_CLOSURE_BYTES: usize = 32 * 1024 * 1024;
    let mut resolved_headers = Vec::new();
    let mut pending =
        external_angle_include_paths_from_root(syntax.source(), syntax.tree().root_node());
    let mut visited = crate::hash::HashSet::default();
    let mut bytes_read = 0usize;
    while let Some(include) = pending.pop() {
        if !keep_going() {
            return None;
        }
        match analyzer.resolve_external_angle_include(file, &include) {
            CppExternalIncludeResolution::Declared { root, header } => {
                if !visited.insert(header.clone()) {
                    continue;
                }
                if visited.len() > MAX_CLOSURE_HEADERS {
                    return Some(ReachedExternalHeaders::Unavailable);
                }
                let Ok(relative_path) = header.strip_prefix(&root) else {
                    return Some(ReachedExternalHeaders::Unavailable);
                };
                resolved_headers.push(ReachedExternalHeader {
                    dependency_name: root_dependency_name(&root),
                    relative_path: relative_path.to_path_buf(),
                });
                let Ok((header_source, raw_bytes)) = read_external_header(&header) else {
                    return Some(ReachedExternalHeaders::Unavailable);
                };
                bytes_read = bytes_read.saturating_add(raw_bytes);
                if bytes_read > MAX_CLOSURE_BYTES {
                    return Some(ReachedExternalHeaders::Unavailable);
                }
                analyzer.record_external_header_parse();
                pending.extend(external_angle_include_paths(&header_source));
            }
            CppExternalIncludeResolution::MissingCompileContext
            | CppExternalIncludeResolution::Conflicting => {
                return Some(ReachedExternalHeaders::Unavailable);
            }
            CppExternalIncludeResolution::Undeclared => {}
        }
    }
    resolved_headers.sort();
    resolved_headers.dedup();
    Some(ReachedExternalHeaders::Complete(resolved_headers))
}

#[derive(Debug)]
pub(super) enum ReachedExternalHeaders {
    Complete(Vec<ReachedExternalHeader>),
    Unavailable,
}

impl ReachedExternalHeaders {
    fn headers(&self) -> Option<&[ReachedExternalHeader]> {
        match self {
            Self::Complete(headers) => Some(headers),
            Self::Unavailable => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ReachedExternalHeader {
    dependency_name: String,
    relative_path: PathBuf,
}

fn symbol_is_in_headers(
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
    headers: &[ReachedExternalHeader],
) -> bool {
    let Some(path) = symbol.locator_path.as_deref() else {
        return false;
    };
    let package = symbol
        .provenance
        .activation
        .matched_evidence
        .package
        .as_ref()
        .map(|package| package.name.as_str());
    headers.iter().any(|header| {
        package == Some(header.dependency_name.as_str()) && header.relative_path == Path::new(path)
    })
}

impl DependencyPackAdapter for CppDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-cpp-headers"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: self.adapter_name().to_owned(),
            version: self.adapter_version().to_owned(),
        }
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        dependency.evidence.language == "cpp"
            && dependency
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ExternalArtifactKind::CppHeaderSourceSet)
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let artifacts = artifacts
            .iter()
            .filter(|artifact| artifact.kind() == ExternalArtifactKind::CppHeaderSourceSet)
            .collect::<Vec<_>>();
        if artifacts.len() != 1 {
            diagnostics.error(
                "cpp.artifact_count",
                None,
                "C++ dependency production requires exactly one header source set",
            );
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return DependencyPackProduction {
                pack: None,
                diagnostics,
                suppressed_diagnostics,
            };
        }
        let artifact = artifacts[0];
        let mut extracted_types = Vec::new();
        let mut extracted_members = Vec::new();
        let mut partial = false;
        for entry in artifact.source_entries() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                diagnostics.error(
                    "artifact.cancelled",
                    None,
                    "C++ header production was cancelled",
                );
                let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
                return DependencyPackProduction {
                    pack: None,
                    diagnostics,
                    suppressed_diagnostics,
                };
            }
            let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                partial = true;
                diagnostics.warning(
                    "cpp.header_not_utf8",
                    Some(entry.relative_path().to_owned()),
                    "C++ header is not UTF-8",
                );
                continue;
            };
            let extracted = extract_external_declarations(
                artifact.path(),
                Path::new(entry.relative_path()),
                source,
                CppExternalDeclarationLimits {
                    max_records: limits.max_records.saturating_sub(
                        extracted_types
                            .len()
                            .saturating_add(extracted_members.len()),
                    ),
                },
            );
            partial |= extracted.completeness == CppExternalDeclarationCompleteness::Partial;
            for diagnostic in extracted.diagnostics {
                diagnostics.warning(
                    diagnostic.code,
                    Some(entry.relative_path().to_owned()),
                    diagnostic.message,
                );
            }
            extracted_types.extend(extracted.types);
            extracted_members.extend(extracted.members);
            if extracted_types
                .len()
                .saturating_add(extracted_members.len())
                >= limits.max_records
            {
                partial = true;
                diagnostics.warning(
                    "cpp.external.record_limit",
                    Some(entry.relative_path().to_owned()),
                    format!(
                        "C++ header source set reached the declaration record limit {}",
                        limits.max_records
                    ),
                );
                break;
            }
        }

        let member_owner_sources = extracted_members
            .iter()
            .filter_map(|member| {
                member
                    .owner
                    .as_ref()
                    .map(|owner| (owner.clone(), member.source_path.clone()))
            })
            .collect::<crate::hash::HashSet<_>>();
        extracted_types.sort_by(|left, right| {
            left.name.cmp(&right.name).then_with(|| {
                member_owner_sources
                    .contains(&(right.name.clone(), right.source_path.clone()))
                    .cmp(
                        &member_owner_sources
                            .contains(&(left.name.clone(), left.source_path.clone())),
                    )
            })
        });
        extracted_types.dedup_by(|left, right| left.name == right.name);
        let basic_string_type_parameters = extracted_types
            .iter()
            .filter_map(|record| {
                (!record.is_type_alias)
                    .then(|| {
                        exact_basic_string_template_parameters(
                            &record.name,
                            record.template_metadata.as_ref(),
                        )
                    })
                    .flatten()
                    .map(|parameters| (record.name.clone(), parameters))
            })
            .collect::<HashMap<_, _>>();
        let mut constructor_candidates =
            HashMap::<(String, BasicStringConstructorRole), Vec<usize>>::default();
        let mut assignment_candidates =
            HashMap::<(String, BasicStringAssignmentRole), Vec<usize>>::default();
        for (index, member) in extracted_members.iter().enumerate() {
            for (owner_name, parameters) in &basic_string_type_parameters {
                if let Some(role) = basic_string_constructor_role(owner_name, parameters, member) {
                    constructor_candidates
                        .entry((owner_name.clone(), role))
                        .or_default()
                        .push(index);
                }
                if let Some(role) = basic_string_assignment_role(owner_name, member) {
                    assignment_candidates
                        .entry((owner_name.clone(), role))
                        .or_default()
                        .push(index);
                }
            }
        }
        let unique_constructor_roles = constructor_candidates
            .into_iter()
            .filter_map(|((owner, role), indices)| {
                (indices.len() == 1).then_some((indices[0], owner, role))
            })
            .collect::<Vec<_>>();
        let unique_constructor_roles_by_index = unique_constructor_roles
            .iter()
            .map(|(index, _, role)| (*index, *role))
            .collect::<HashMap<_, _>>();
        let unique_assignment_roles_by_index = assignment_candidates
            .into_iter()
            .filter_map(|((_, role), indices)| (indices.len() == 1).then_some((indices[0], role)))
            .collect::<HashMap<_, _>>();
        let type_ids = extracted_types
            .iter()
            .map(|record| {
                (
                    record.name.clone(),
                    type_declaration_id(TypeIdentity {
                        ecosystem: "cpp-headers",
                        name: &record.name,
                    }),
                )
            })
            .collect::<HashMap<_, _>>();
        let basic_string_type_id = basic_string_type_parameters
            .contains_key("std.basic_string")
            .then(|| type_ids.get("std.basic_string"))
            .flatten()
            .map(String::as_str);
        let mut types = extracted_types
            .into_iter()
            .map(|record| TypeFact {
                id: type_ids[&record.name].clone(),
                name: record.name.clone(),
                type_kind: if record.is_type_alias {
                    TypeKind::TypeAlias
                } else {
                    TypeKind::Class
                },
                visibility: match record.visibility {
                    CppExternalVisibility::Public => Visibility::Public,
                    CppExternalVisibility::Protected => Visibility::Protected,
                    CppExternalVisibility::Private => Visibility::Private,
                },
                is_abstract: false,
                is_sealed: false,
                has_explicit_type_terms: false,
                type_parameters: basic_string_type_parameters
                    .get(&record.name)
                    .cloned()
                    .unwrap_or_default(),
                type_parameter_constraints: Vec::new(),
                underlying_type: record
                    .underlying_type
                    .as_ref()
                    .and_then(|identity| pack_alias_type_ref(identity, basic_string_type_id))
                    .map(|target| StructuredTypeExpression {
                        display: "structured C++ alias target".to_owned(),
                        referenced_types: vec![target],
                    }),
                value_semantics: None,
                embedded_types: Vec::new(),
                hierarchy: record
                    .direct_bases
                    .into_iter()
                    .map(|name| HierarchyFact {
                        hierarchy_kind: HierarchyKind::Extends,
                        target: named_type(name),
                        declaration_ordinal: None,
                    })
                    .collect(),
                aliases: (record.source_name != record.name)
                    .then_some(record.source_name)
                    .into_iter()
                    .collect(),
                extension_surfaces: Vec::new(),
                guard: None,
                locator: Locator::Artifact {
                    path: stable_path(&record.source_path),
                    symbol: record.name,
                },
            })
            .collect::<Vec<_>>();

        let mut members = Vec::new();
        let mut emitted_constructor_ids =
            HashMap::<(String, BasicStringConstructorRole), String>::default();
        for (record_index, record) in extracted_members.into_iter().enumerate() {
            let Some(owner_name) = record.owner.as_deref() else {
                partial = true;
                diagnostics.warning(
                    "cpp.member_owner_unavailable",
                    Some(stable_path(&record.source_path)),
                    format!(
                        "C++ declaration `{}` has no indexed type owner",
                        record.qualified_name
                    ),
                );
                continue;
            };
            let Some(owner_id) = type_ids.get(owner_name) else {
                partial = true;
                diagnostics.warning(
                    "cpp.member_owner_missing",
                    Some(stable_path(&record.source_path)),
                    format!(
                        "C++ member `{}` has no emitted owner",
                        record.qualified_name
                    ),
                );
                continue;
            };
            let parameters = record
                .parameter_types
                .unwrap_or_default()
                .into_iter()
                .map(|parameter| match parameter {
                    CppParameterType::Structured(identity) => {
                        (pack_type_ref(&identity).unwrap_or_else(unknown_type), false)
                    }
                    CppParameterType::Ellipsis => (unknown_type(), true),
                    CppParameterType::Unstructured => (unknown_type(), false),
                })
                .collect::<Vec<_>>();
            let callable_arity = record.callable_arity;
            let parameter_types = parameters
                .iter()
                .map(|(r#type, _)| r#type.clone())
                .collect::<Vec<_>>();
            let parameter_variadics = parameters
                .iter()
                .map(|(_, variadic)| *variadic)
                .collect::<Vec<_>>();
            let return_type = record.return_type.as_ref().and_then(pack_type_ref);
            let constructor_role = unique_constructor_roles_by_index
                .get(&record_index)
                .copied();
            let assignment_role = unique_assignment_roles_by_index.get(&record_index).copied();
            let is_basic_string_constructor = basic_string_type_parameters.contains_key(owner_name)
                && record.name == "basic_string";
            let member_kind = match record.kind {
                CppExternalMemberKind::Function
                    if record.is_constructor || is_basic_string_constructor =>
                {
                    MemberKind::Constructor
                }
                CppExternalMemberKind::Function => MemberKind::Method,
                CppExternalMemberKind::Field => MemberKind::Field,
                CppExternalMemberKind::Macro => MemberKind::Macro,
            };
            let id = member_declaration_id(MemberIdentity {
                owner_id,
                kind: member_kind,
                is_static: false,
                parameter_arity: parameter_types.len(),
                name: &record.name,
                generic_arity: 0,
                parameter_types: &parameter_types,
                parameter_variadics: &parameter_variadics,
                return_type: return_type.as_ref(),
            });
            let signature = (record.kind == CppExternalMemberKind::Function).then(|| Signature {
                type_parameters: Vec::new(),
                parameters: parameters
                    .into_iter()
                    .enumerate()
                    .map(|(index, (r#type, variadic))| Parameter {
                        name: None,
                        r#type,
                        optional: !variadic
                            && callable_arity.is_some_and(|arity| {
                                index >= arity.required() && index < arity.total()
                            }),
                        variadic,
                        passing_mode: Default::default(),
                    })
                    .collect(),
                returns: return_type,
            });
            members.push(MemberFact {
                id: id.clone(),
                owner: owner_id.clone(),
                name: record.name,
                member_kind,
                visibility: match record.visibility {
                    CppExternalVisibility::Public => Visibility::Public,
                    CppExternalVisibility::Protected => Visibility::Protected,
                    CppExternalVisibility::Private => Visibility::Private,
                },
                is_static: false,
                is_abstract: false,
                is_virtual: false,
                implicit_operation: constructor_role
                    .map(BasicStringConstructorRole::operation)
                    .or_else(|| assignment_role.map(BasicStringAssignmentRole::operation)),
                callable_family_complete: false,
                signature,
                receiver: Some(ReceiverFact { pointer: false }),
                extension_receiver: None,
                extension_receiver_constraints: Vec::new(),
                aliases: Vec::new(),
                guard: None,
                locator: Locator::Artifact {
                    path: stable_path(&record.source_path),
                    symbol: record.qualified_name,
                },
            });
            if let Some(role) = constructor_role {
                emitted_constructor_ids.insert((owner_name.to_owned(), role), id.clone());
            }
        }
        members.sort_by(|left, right| left.id.cmp(&right.id));
        members.dedup_by(|left, right| left.id == right.id);

        for type_fact in &mut types {
            let Some(parameters) = basic_string_type_parameters.get(&type_fact.name) else {
                continue;
            };
            type_fact.type_parameters = parameters.clone();
            let copy_member = emitted_constructor_ids
                .get(&(type_fact.name.clone(), BasicStringConstructorRole::Copy))
                .cloned();
            let move_member = emitted_constructor_ids
                .contains_key(&(type_fact.name.clone(), BasicStringConstructorRole::Move));
            if copy_member.is_some() || move_member {
                type_fact.value_semantics = Some(TypeValueSemantics {
                    copy: copy_member.map(|member| TypeCopySemantics::ViaMember { member }),
                    move_semantics: move_member.then_some(TypeMoveSemantics::Invalidating),
                });
            }
        }

        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness =
            if partial || !diagnostics.is_empty() || suppressed_diagnostics.total() != 0 {
                Completeness::Partial
            } else {
                Completeness::Complete
            };
        let selector = dependency
            .evidence
            .package
            .as_ref()
            .map(|coordinate| NameSelector {
                name: coordinate.name.clone(),
                version: coordinate
                    .version
                    .as_ref()
                    .map(|version| format!("={version}")),
            });
        DependencyPackProduction {
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: "bifrost.external.cpp-headers".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                producer: self.producer(),
                language: "cpp".to_owned(),
                ecosystem: "cpp-headers".to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                provenance: Provenance {
                    source: format!("exact local C++ headers sha256:{}", artifact.sha256()),
                    revision: None,
                },
                license: "NOASSERTION".to_owned(),
                completeness,
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
                carried_sources: Vec::new(),
                cpp_portability: None,
                shards: vec![AuthoredShard {
                    id: "declarations.external".to_owned(),
                    activation: vec![ActivationSelector {
                        package: selector,
                        module: None,
                        toolchain: None,
                        targets: Vec::new(),
                        configurations: Vec::new(),
                        artifact_sha256: Some(artifact.sha256().to_owned()),
                    }],
                    payload: AuthoredPayload::DeclarationFacts {
                        types,
                        members,
                        relations: Vec::new(),
                    },
                }],
            }),
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

pub fn resolve_cpp_semantic_pack_dependencies(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let contexts = CppCompileContexts::load(project);
    let mut dependencies = Vec::new();
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    let header_sets = match discover_reachable_header_sets(
        project,
        &contexts,
        limits,
        cancellation,
        &mut diagnostics,
    ) {
        Ok(header_sets) => header_sets,
        Err(HeaderDiscoveryError::Cancelled) => {
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return DependencyDiscoveryOutcome {
                dependencies,
                diagnostics,
                suppressed_diagnostics,
                complete: false,
                cancelled: true,
                profile: DependencyDiscoveryProfile::default(),
            };
        }
        Err(HeaderDiscoveryError::Failed(message)) => {
            diagnostics.push(header_discovery_failed(None, message));
            Vec::new()
        }
    };
    let dependency_limit_hit = header_sets.len() > limits.max_dependencies;
    let undiscovered_dependencies = header_sets.len().saturating_sub(limits.max_dependencies);
    for (root, paths) in header_sets.into_iter().take(limits.max_dependencies) {
        let name = root_dependency_name(&root);
        dependencies.push(ResolvedDependency {
            id: name.clone(),
            evidence: SemanticModelActivationEvidence {
                language: "cpp".to_owned(),
                ecosystem: "cpp-headers".to_owned(),
                package: Some(CatalogCoordinate {
                    name,
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
            provenance: Vec::new(),
            artifacts: vec![ResolvedDependencyArtifact::source_set(
                DependencyArtifactRole::Declarations,
                ExternalArtifactKind::CppHeaderSourceSet,
                root,
                paths,
            )],
            scope: DependencyScope::Unknown,
            declared_by: None,
        });
    }
    if dependency_limit_hit {
        diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "limit.dependencies".to_owned(),
            dependency_id: None,
            location: None,
            message: format!(
                "C++ header discovery exceeded dependency limit {}",
                limits.max_dependencies
            ),
        });
    }
    let (diagnostics, mut suppressed_diagnostics) = diagnostics.finish();
    // Dependencies dropped by the dependency limit are not diagnostics. They
    // join the non-error bucket so `errors` stays an exact count of dropped
    // error-severity diagnostics.
    suppressed_diagnostics.warnings = suppressed_diagnostics
        .warnings
        .saturating_add(undiscovered_dependencies);
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered: 1,
            dependencies_resolved: dependencies.len(),
        },
        complete: diagnostics.is_empty() && suppressed_diagnostics.total() == 0,
        dependencies,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

fn root_dependency_name(root: &Path) -> String {
    let identity = lower_hex_string(&sha256_bytes(root.to_string_lossy().as_bytes()));
    format!("cpp-include-root-{identity}")
}

fn discover_reachable_header_sets(
    project: &dyn Project,
    contexts: &CppCompileContexts,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> Result<Vec<(PathBuf, Vec<PathBuf>)>, HeaderDiscoveryError> {
    let files = project.analyzable_files(Language::Cpp).map_err(|error| {
        HeaderDiscoveryError::Failed(format!("cannot list C++ source files: {error}"))
    })?;
    // An angle include reaches an external root only through the compile
    // contexts of the file that spells it: with no entry naming that file,
    // `resolve_external_angle_include` answers `MissingCompileContext` and the
    // traversal below drops the pair. That is the resolution rule, not a
    // shortcut around one, and it holds at every depth because a header
    // reached from a workspace source keeps that source's identity through the
    // whole closure. So the only sources worth reading are the ones the
    // database names.
    //
    // Reading and parsing all of them instead was serial startup latency
    // scaling with the workspace rather than with the header sets found: on
    // Godot, which ships no `compile_commands.json` at all, it read and parsed
    // 8,233 files in 31.5 seconds to discover nothing. Keep the span: it is
    // the only place that separates this cost from header-closure traversal.
    let workspace_file_count = files.len();
    let compiled_sources = files
        .into_iter()
        .filter(|file| !contexts.contexts_for(file).is_empty())
        .collect::<Vec<_>>();
    let mut pending = Vec::new();
    {
        let _scope = crate::profiling::scope_with(|| {
            format!(
                "cpp_headers.scan_workspace_sources[{} of {workspace_file_count} files]",
                compiled_sources.len()
            )
        });
        for file in compiled_sources {
            let source = match project.read_source(&file) {
                Ok(source) => source,
                Err(error) => {
                    diagnostics.push(header_discovery_failed(
                        Some(file.rel_path()),
                        format!("cannot read C++ source: {error}"),
                    ));
                    continue;
                }
            };
            pending.extend(
                external_angle_include_paths(&source)
                    .into_iter()
                    .map(|include| (file.clone(), include)),
            );
        }
    }
    let mut paths_by_root: HashMap<PathBuf, crate::hash::HashSet<PathBuf>> = HashMap::default();
    let mut visited = crate::hash::HashSet::default();
    let mut bytes_read = 0u64;
    while let Some((source_file, include)) = pending.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(HeaderDiscoveryError::Cancelled);
        }
        let CppExternalIncludeResolution::Declared { root, header } =
            contexts.resolve_external_angle_include(&source_file, &include)
        else {
            continue;
        };
        if !visited.insert(header.clone()) {
            continue;
        }
        let relative = header
            .strip_prefix(&root)
            .expect("compile-context containment keeps headers below their root")
            .to_path_buf();
        if relative.components().count() > limits.max_source_path_depth {
            return Err(HeaderDiscoveryError::Failed(format!(
                "C++ header source set exceeded path-depth limit {}",
                limits.max_source_path_depth
            )));
        }
        // Read before recording: a header this run could not read is not a
        // member of the source set it publishes, so the artifact a producer
        // later materializes names no path that already failed here.
        let (source, raw_bytes) = match read_external_header(&header) {
            Ok(source) => source,
            Err(error) => {
                diagnostics.push(header_discovery_failed(
                    Some(&header),
                    format!("cannot read external C++ header: {error}"),
                ));
                continue;
            }
        };
        let root_paths = paths_by_root.entry(root).or_default();
        root_paths.insert(relative);
        if root_paths.len() > limits.max_source_files_per_artifact {
            return Err(HeaderDiscoveryError::Failed(format!(
                "C++ header source set exceeded file limit {}",
                limits.max_source_files_per_artifact
            )));
        }
        bytes_read = bytes_read.saturating_add(raw_bytes as u64);
        if bytes_read > limits.max_total_artifact_bytes {
            return Err(HeaderDiscoveryError::Failed(format!(
                "C++ header discovery exceeded byte limit {}",
                limits.max_total_artifact_bytes
            )));
        }
        pending.extend(
            external_angle_include_paths(&source)
                .into_iter()
                .map(|include| (source_file.clone(), include)),
        );
    }
    let mut sets = paths_by_root
        .into_iter()
        .map(|(root, paths)| {
            let mut paths = paths.into_iter().collect::<Vec<_>>();
            paths.sort();
            (root, paths)
        })
        .collect::<Vec<_>>();
    sets.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(sets)
}

fn read_external_header(path: &Path) -> std::io::Result<(String, usize)> {
    let bytes = std::fs::read(path)?;
    let raw_bytes = bytes.len();
    decode_source_bytes(bytes).map(|source| (source, raw_bytes))
}

fn header_discovery_failed(
    location: Option<&Path>,
    message: impl Into<String>,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Error,
        code: "cpp.header_discovery_failed".to_owned(),
        dependency_id: None,
        location: location.map(|path| path.to_string_lossy().into_owned()),
        message: message.into(),
    }
}

enum HeaderDiscoveryError {
    Cancelled,
    Failed(String),
}

fn named_type(name: String) -> TypeRef {
    TypeRef::Named {
        name,
        arguments: Vec::new(),
        nullable: false,
    }
}

/// The pack type reference for a type the header extractor could not reduce to
/// a structured identity, and for a `...` pack, which has no type at all.
///
/// An unbounded wildcard is the model's own way to say "some type": it keeps
/// the parameter's position, and therefore the callable's arity and identity,
/// without inventing a type name that no declaration spells.
fn unknown_type() -> TypeRef {
    TypeRef::Wildcard {
        variance: WildcardVariance::Any,
        bound: None,
    }
}

/// Translate a parser-derived structured type into a pack type reference.
///
/// The two models line up node for node except in one place: C++ cv-qualifiers
/// are not part of either model, so `const T&` is published as a reference to
/// `T`, exactly as the rustdoc producer publishes `&mut T` and the C# producer
/// publishes an `in` parameter. A nominal name is published as the path the
/// declaration writes, joined by `.` like every other name in a pack; the
/// structured name's lexical scope is deliberately not folded in, because a
/// pack name asserts an identity and prefixing an enclosing scope onto an
/// unqualified spelling would assert one the header never proved.
fn pack_type_ref(identity: &StructuredTypeIdentity) -> Option<TypeRef> {
    enum Work {
        Visit(StructuredTypeNodeId),
        Pointer,
        LvalueReference,
        RvalueReference,
        Array,
        Slice,
        Map,
        Generic { argument_count: usize },
    }

    // A structured arena may share one child among several parents, while a
    // pack type reference is a tree. Expanding sharing is bounded work here
    // rather than unbounded materialization: a type past the bound is reported
    // as unknown instead of being expanded.
    const MAX_TRANSLATION_STEPS: usize = 8_192;

    let mut work = vec![Work::Visit(identity.root_id())];
    let mut values: Vec<TypeRef> = Vec::new();
    let mut steps = 0usize;
    while let Some(next) = work.pop() {
        steps += 1;
        if steps > MAX_TRANSLATION_STEPS {
            return None;
        }
        match next {
            Work::Visit(id) => match identity.view(id)? {
                StructuredTypeNodeView::Named(name) => {
                    let name = name.path().join(".");
                    debug_assert!(
                        !name.is_empty() && !name.chars().any(char::is_whitespace),
                        "structured type name components are parser identifiers: {name:?}"
                    );
                    values.push(named_type(name));
                }
                StructuredTypeNodeView::Pointer(inner) => {
                    work.push(Work::Pointer);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Reference(inner) => {
                    work.push(Work::LvalueReference);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::RvalueReference(inner) => {
                    work.push(Work::RvalueReference);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Array(inner) => {
                    work.push(Work::Array);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Slice(inner) => {
                    work.push(Work::Slice);
                    work.push(Work::Visit(inner));
                }
                StructuredTypeNodeView::Map { key, value } => {
                    work.push(Work::Map);
                    work.push(Work::Visit(value));
                    work.push(Work::Visit(key));
                }
                StructuredTypeNodeView::Generic { base, arguments } => {
                    work.push(Work::Generic {
                        argument_count: arguments.len(),
                    });
                    for argument in arguments.iter().rev() {
                        work.push(Work::Visit(*argument));
                    }
                    work.push(Work::Visit(base));
                }
            },
            Work::Pointer => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::Pointer { element });
            }
            Work::LvalueReference => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::ByRef {
                    element,
                    reference_kind: TypeRefReferenceKind::Lvalue,
                });
            }
            Work::RvalueReference => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::ByRef {
                    element,
                    reference_kind: TypeRefReferenceKind::Rvalue,
                });
            }
            Work::Array => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::Array { element });
            }
            Work::Slice => {
                let element = Box::new(values.pop()?);
                values.push(TypeRef::Slice { element });
            }
            Work::Map => {
                let value = Box::new(values.pop()?);
                let key = Box::new(values.pop()?);
                values.push(TypeRef::Map { key, value });
            }
            Work::Generic { argument_count } => {
                let start = values.len().checked_sub(argument_count)?;
                let arguments = values.split_off(start);
                let TypeRef::Named { name, nullable, .. } = values.pop()? else {
                    // Only a nominal type can carry pack type arguments.
                    return None;
                };
                values.push(TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                });
            }
        }
    }
    (values.len() == 1).then(|| values.pop()).flatten()
}

/// Translate an alias target while retaining the declaration identity of the
/// canonical C++ standard-library `basic_string` primary.
///
/// `pack_type_ref` deliberately publishes nominal names because most external
/// references cannot be proven to name one of the declarations in this source
/// set. An alias target is different only when the parser-derived structured
/// identity proves that its base is the canonical `std::basic_string` name and
/// the extracted source set contains the exact, reviewed primary declaration.
/// In that case, using `TypeRef::Declared` lets consumers follow the alias to
/// the generated declaration without matching a rendered spelling. All other
/// targets retain the ordinary named reference (or remain unknown when their
/// structured shape cannot be translated).
fn pack_alias_type_ref(
    identity: &StructuredTypeIdentity,
    basic_string_id: Option<&str>,
) -> Option<TypeRef> {
    let packed = pack_type_ref(identity)?;
    let Some(basic_string_id) = basic_string_id else {
        return Some(packed);
    };
    let base = match identity.view(identity.root_id())? {
        StructuredTypeNodeView::Named(_) => identity.root_id(),
        StructuredTypeNodeView::Generic { base, .. } => base,
        _ => return Some(packed),
    };
    let Some(StructuredTypeNodeView::Named(name)) = identity.view(base) else {
        return Some(packed);
    };
    if !is_canonical_basic_string_name(name) {
        return Some(packed);
    }
    let TypeRef::Named {
        arguments,
        nullable,
        ..
    } = packed
    else {
        return Some(packed);
    };
    Some(TypeRef::Declared {
        id: basic_string_id.to_owned(),
        arguments,
        nullable,
    })
}

/// Whether a parser-derived name resolves to the canonical `std::basic_string`
/// declaration at the alias's lexical site.
///
/// The unqualified form is accepted only from the `std` namespace captured by
/// the extractor. The qualified form must be rooted at the global namespace;
/// a same-named type in another lexical scope therefore remains a `Named`
/// reference instead of acquiring a declaration id by display-name matching.
fn is_canonical_basic_string_name(
    name: &brokk_bifrost_core::analyzer::model::StructuredTypeName,
) -> bool {
    if name.path() == ["std", "basic_string"] {
        // A qualified spelling without a leading `::` is still accepted at
        // global scope: there is no enclosing namespace in which a shadowing
        // `std` declaration could be found. Nested scopes are intentionally
        // declined because this producer has no resolver for qualified-name
        // shadowing.
        return name.lexical_scope().is_empty();
    }
    name.lexical_scope() == ["std"] && name.path() == ["basic_string"]
}

fn stable_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        SemanticBudget, SemanticCapability, SemanticEffect, SemanticGapImpact, SemanticOutcome,
        SemanticRequest, TransferKind, TransferOperation, ValueFlowKind,
    };
    use crate::analyzer::semantic_model::CompilerOptions;
    use crate::analyzer::semantic_model::{
        AuthoredPayload, CatalogOptions, ResolvedDependencyArtifactInput,
        SemanticModelActivationControl, SemanticModelActivationRequest, SemanticModelControlAction,
        SemanticModelControlScope, SemanticModelPackSelector, SemanticModelRuntimeLimits,
        SemanticModelRuntimeOutcome, SemanticPackCatalog, compile_pack, read_exact_source_set,
    };
    use crate::analyzer::usages::get_definition::DefinitionLookupRequest;
    use crate::analyzer::usages::get_definition::trace::{
        TraceCandidateRef, resolve_definition_batch_with_trace,
    };
    use crate::analyzer::{
        AnalyzerConfig, DependencyPackEcosystem, DependencyPackWorkspaceContext, Language,
        OverlayProject, Project, TestProject, WorkspaceAnalyzer,
    };
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::model::CppTemplateParameterMetadata;
    use brokk_bifrost_cpp::external_declarations::CppExternalDeclarationSet;
    use std::sync::Arc;

    fn extract_test_declarations(source: &str) -> CppExternalDeclarationSet {
        let temp = tempfile::tempdir().expect("temp root");
        extract_external_declarations(
            temp.path(),
            Path::new("basic_string"),
            source,
            CppExternalDeclarationLimits::default(),
        )
    }

    fn template_default(base: &str, parameter: &str) -> CppTemplateExpression {
        CppTemplateExpression {
            text: format!("{base}<{parameter}>"),
            term: CppTemplateTerm::Node {
                kind: "template_type".to_owned(),
                children: vec![
                    CppTemplateTerm::Atom {
                        kind: "identifier".to_owned(),
                        text: base.to_owned(),
                    },
                    CppTemplateTerm::Node {
                        kind: "template_argument_list".to_owned(),
                        children: vec![
                            CppTemplateTerm::Atom {
                                kind: "<".to_owned(),
                                text: "<".to_owned(),
                            },
                            CppTemplateTerm::Parameter(parameter.to_owned()),
                            CppTemplateTerm::Atom {
                                kind: ">".to_owned(),
                                text: ">".to_owned(),
                            },
                        ],
                    },
                ],
            },
        }
    }

    fn basic_string_metadata() -> CppTemplateMetadata {
        CppTemplateMetadata {
            primary_name: "basic_string".to_owned(),
            primary_fq_name: "std.basic_string".to_owned(),
            parameters: vec![
                CppTemplateParameterMetadata {
                    name: "C".to_owned(),
                    kind: CppTemplateParameterKind::Type,
                    variadic: false,
                    default: None,
                },
                CppTemplateParameterMetadata {
                    name: "Traits".to_owned(),
                    kind: CppTemplateParameterKind::Type,
                    variadic: false,
                    default: Some(template_default("char_traits", "C")),
                },
                CppTemplateParameterMetadata {
                    name: "Alloc".to_owned(),
                    kind: CppTemplateParameterKind::Type,
                    variadic: false,
                    default: Some(template_default("allocator", "C")),
                },
            ],
            specialization_arguments: Vec::new(),
            alias_target: None,
        }
    }

    #[test]
    fn basic_string_model_rejects_structured_template_near_misses() {
        let exact = basic_string_metadata();
        assert_eq!(
            Some(vec![
                "C".to_owned(),
                "Traits".to_owned(),
                "Alloc".to_owned()
            ]),
            exact_basic_string_template_parameters("std.basic_string", Some(&exact))
        );
        assert_eq!(
            None,
            exact_basic_string_template_parameters("custom.basic_string", Some(&exact)),
            "a same-named custom template is not the standard owner"
        );

        let mut wrong_arity = exact.clone();
        wrong_arity.parameters.pop();
        assert_eq!(
            None,
            exact_basic_string_template_parameters("std.basic_string", Some(&wrong_arity))
        );

        let mut wrong_traits = exact.clone();
        wrong_traits.parameters[1].default = Some(template_default("custom_traits", "C"));
        assert_eq!(
            None,
            exact_basic_string_template_parameters("std.basic_string", Some(&wrong_traits))
        );

        let mut wrong_allocator_parameter = exact;
        wrong_allocator_parameter.parameters[2].default =
            Some(template_default("allocator", "Traits"));
        assert_eq!(
            None,
            exact_basic_string_template_parameters(
                "std.basic_string",
                Some(&wrong_allocator_parameter),
            )
        );
    }

    #[test]
    fn basic_string_character_data_role_requires_exact_defaulted_allocator_shape() {
        let declarations = extract_test_declarations(
            r#"
            namespace std {
            template <class C, class Traits, class Alloc> class basic_string {
            public:
                basic_string(const C*, const Alloc& = Alloc());
                basic_string(const C&, const Alloc& = Alloc());
            };
            }
            "#,
        );
        let parameters = vec!["C".to_owned(), "Traits".to_owned(), "Alloc".to_owned()];
        let constructors = declarations
            .members
            .iter()
            .filter(|member| {
                member.owner.as_deref() == Some("std.basic_string") && member.name == "basic_string"
            })
            .collect::<Vec<_>>();

        assert_eq!(2, constructors.len(), "{declarations:#?}");
        assert_eq!(
            1,
            constructors
                .iter()
                .filter(|member| {
                    basic_string_constructor_role("std.basic_string", &parameters, member)
                        == Some(BasicStringConstructorRole::CharacterData)
                })
                .count(),
            "only the character pointer plus defaulted allocator constructor is implicit from one argument"
        );
        assert!(constructors.iter().all(|member| {
            basic_string_constructor_role("custom.basic_string", &parameters, member).is_none()
        }));

        let required_allocator = extract_test_declarations(
            r#"
            namespace std {
            template <class C, class Traits, class Alloc> class basic_string {
            public:
                basic_string(const C*, const Alloc&);
            };
            }
            "#,
        );
        let required_allocator = required_allocator
            .members
            .first()
            .unwrap_or_else(|| panic!("required allocator constructor: {required_allocator:#?}"));
        assert_eq!(
            None,
            basic_string_constructor_role("std.basic_string", &parameters, required_allocator),
            "a constructor requiring the allocator is not callable from one character-data argument"
        );

        for source in [
            "explicit basic_string(const C*, const Alloc& = Alloc());",
            "basic_string(C*, const Alloc& = Alloc());",
            "basic_string(const C*, Alloc& = Alloc());",
        ] {
            let near_miss = extract_test_declarations(&format!(
                "namespace std {{ template <class C, class Traits, class Alloc> class basic_string {{ public: {source} }}; }}"
            ));
            let near_miss = near_miss
                .members
                .first()
                .unwrap_or_else(|| panic!("near-miss constructor: {near_miss:#?}"));
            assert_eq!(
                None,
                basic_string_constructor_role("std.basic_string", &parameters, near_miss),
                "explicit or cv-mismatched constructors must not acquire the implicit preserving role: {near_miss:#?}"
            );
        }
    }

    #[test]
    fn basic_string_assignment_roles_require_unique_structured_self_parameters() {
        let declarations = extract_test_declarations(
            r#"
            namespace std {
            class basic_string {
            public:
                basic_string& operator=(const basic_string&);
                basic_string& operator=(basic_string&&);
                basic_string& operator=(const other_string&);
                basic_string& operator=(int);
            };
            class other_string {};
            }
            "#,
        );
        let assignments = declarations
            .members
            .iter()
            .filter(|member| {
                member.owner.as_deref() == Some("std.basic_string") && member.name == "operator="
            })
            .collect::<Vec<_>>();
        assert_eq!(4, assignments.len(), "{declarations:#?}");
        assert_eq!(
            1,
            assignments
                .iter()
                .filter(|member| {
                    basic_string_assignment_role("std.basic_string", member)
                        == Some(BasicStringAssignmentRole::Copy)
                })
                .count(),
            "copy assignment must have one exact self-reference candidate"
        );
        assert_eq!(
            1,
            assignments
                .iter()
                .filter(|member| {
                    basic_string_assignment_role("std.basic_string", member)
                        == Some(BasicStringAssignmentRole::Move)
                })
                .count(),
            "move assignment must have one exact self-reference candidate"
        );
        assert!(
            assignments.iter().any(|member| {
                basic_string_assignment_role("std.basic_string", member).is_none()
            }),
            "non-self overloads must not acquire an implicit assignment role"
        );
        assert!(
            basic_string_assignment_role("custom.basic_string", assignments[0]).is_none(),
            "a same-shaped overload on a different owner is not canonical basic_string"
        );

        let wrong_return = extract_test_declarations(
            r#"
            namespace std {
            class basic_string {
            public:
                void operator=(const basic_string&);
            };
            }
            "#,
        );
        let wrong_return = wrong_return
            .members
            .iter()
            .find(|member| member.name == "operator=")
            .unwrap_or_else(|| panic!("wrong-return assignment: {wrong_return:#?}"));
        assert_eq!(
            None,
            basic_string_assignment_role("std.basic_string", wrong_return),
            "a wrong-return-type overload must not acquire an implicit assignment role"
        );
    }

    #[test]
    fn discovers_and_produces_vector_type_and_member_facts() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <vector>\n")
            .expect("source");
        ProjectFile::new(root.clone(), "fake/include/vector")
            .write("namespace std { template <typename T> class vector { public: void push_back(const T&); }; }")
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root, Language::Cpp);
        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(discovery.complete, "{discovery:#?}");
        let [dependency] = discovery.dependencies.as_slice() else {
            panic!("one C++ include-root dependency: {discovery:#?}");
        };
        let ResolvedDependencyArtifactInput::SourceSet {
            root,
            relative_paths,
        } = &dependency.artifacts[0].input
        else {
            panic!("C++ dependency uses a source set");
        };
        let exact = read_exact_source_set(
            root,
            relative_paths,
            DependencyPackLimits::default().max_source_files_per_artifact,
            DependencyPackLimits::default().max_source_path_depth,
            &ArtifactProducerLimits::default(),
        )
        .expect("exact source set");
        let artifact = ExactDependencyArtifact::from_exact(
            DependencyArtifactRole::Declarations,
            ExternalArtifactKind::CppHeaderSourceSet,
            None,
            exact,
        );
        let production = CppDependencyPackAdapter.produce(
            dependency,
            &[artifact],
            &ArtifactProducerLimits::default(),
            None,
        );
        let pack = production.pack.expect("C++ pack");
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("declaration facts");
        };
        let vector = types
            .iter()
            .find(|fact| fact.name == "std.vector")
            .expect("vector type");
        assert!(
            members
                .iter()
                .any(|fact| fact.owner == vector.id && fact.name == "push_back")
        );
    }

    /// The pack type model carries a type's identity and shape, never a source
    /// spelling: a parameter written `const T&` must reach the pack as a
    /// reference to `T`, and the pack must validate.
    #[test]
    fn produced_header_pack_publishes_structured_parameter_types() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <vector>\n")
            .expect("source");
        ProjectFile::new(root.clone(), "fake/include/vector")
            .write(concat!(
                "namespace ns { class Widget; }\n",
                "namespace custom { class basic_string {}; using string = basic_string; }\n",
                "namespace std {\n",
                "template <class C, class Traits = char_traits<C>, class Alloc = allocator<C>>\n",
                "class basic_string {\n",
                "public:\n",
                "  basic_string(const basic_string&);\n",
                "  basic_string(basic_string&&);\n",
                "  basic_string(const C*, const Alloc& = Alloc());\n",
                "  basic_string& operator=(const basic_string&);\n",
                "  basic_string& operator=(basic_string&&);\n",
                "};\n",
                "using string = basic_string<char, char_traits<char>, allocator<char>>;\n",
                "template <typename T> class vector {\n",
                "public:\n",
                "  void push_back(const T& value);\n",
                "  void assign(const std::string& name, ns::Widget* widget);\n",
                "  void nest(const vector<int>& other);\n",
                "  void insert(int index);\n",
                "  void insert(const T& value);\n",
                "  void log(const char* format, ...);\n",
                "};\n",
                "}\n",
            ))
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root, Language::Cpp);
        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        let [dependency] = discovery.dependencies.as_slice() else {
            panic!("one C++ include-root dependency: {discovery:#?}");
        };
        let ResolvedDependencyArtifactInput::SourceSet {
            root,
            relative_paths,
        } = &dependency.artifacts[0].input
        else {
            panic!("C++ dependency uses a source set");
        };
        let exact = read_exact_source_set(
            root,
            relative_paths,
            DependencyPackLimits::default().max_source_files_per_artifact,
            DependencyPackLimits::default().max_source_path_depth,
            &ArtifactProducerLimits::default(),
        )
        .expect("exact source set");
        let production = CppDependencyPackAdapter.produce(
            dependency,
            &[ExactDependencyArtifact::from_exact(
                DependencyArtifactRole::Declarations,
                ExternalArtifactKind::CppHeaderSourceSet,
                None,
                exact,
            )],
            &ArtifactProducerLimits::default(),
            None,
        );
        let pack = production.pack.expect("C++ pack");
        if let Err(diagnostics) = compile_pack(&pack, &CompilerOptions::default()) {
            panic!("the produced pack must validate: {diagnostics:#?}");
        }
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("declaration facts");
        };
        let vector = types
            .iter()
            .find(|fact| fact.name == "std.vector")
            .expect("vector type");
        let basic_string = types
            .iter()
            .find(|fact| fact.name == "std.basic_string")
            .expect("basic_string type");
        assert_eq!(vec!["C", "Traits", "Alloc"], basic_string.type_parameters);
        let basic_string_members = members
            .iter()
            .filter(|fact| fact.owner == basic_string.id)
            .collect::<Vec<_>>();
        assert!(basic_string_members.iter().any(|member| {
            member.implicit_operation == Some(ImplicitOperation::CopyConstructor)
        }));
        assert!(basic_string_members.iter().any(|member| {
            member.implicit_operation == Some(ImplicitOperation::MoveConstructor)
        }));
        assert!(basic_string_members.iter().any(|member| {
            member.implicit_operation == Some(ImplicitOperation::ValuePreservingConstructor)
                && member.signature.as_ref().is_some_and(|signature| {
                    signature.parameters.len() == 2
                        && !signature.parameters[0].optional
                        && signature.parameters[1].optional
                })
        }));
        assert!(
            basic_string_members.iter().any(|member| {
                member.name == "operator="
                    && member.implicit_operation == Some(ImplicitOperation::CopyAssignment)
            }),
            "copy assignment role: {basic_string_members:#?}"
        );
        assert!(
            basic_string_members.iter().any(|member| {
                member.name == "operator="
                    && member.implicit_operation == Some(ImplicitOperation::MoveAssignment)
            }),
            "move assignment role: {basic_string_members:#?}"
        );
        assert!(matches!(
            &basic_string.value_semantics,
            Some(TypeValueSemantics {
                copy: Some(TypeCopySemantics::ViaMember { member }),
                move_semantics: Some(TypeMoveSemantics::Invalidating),
            }) if basic_string_members.iter().any(|candidate| candidate.id == *member)
        ));
        let string_alias = types
            .iter()
            .find(|fact| fact.name == "std.string")
            .expect("string alias");
        assert_eq!(TypeKind::TypeAlias, string_alias.type_kind);
        let Some(underlying) = string_alias.underlying_type.as_ref() else {
            panic!("structured string alias target: {string_alias:#?}");
        };
        let [
            TypeRef::Declared {
                id,
                arguments,
                nullable,
            },
        ] = underlying.referenced_types.as_slice()
        else {
            panic!("one declared string alias target: {underlying:#?}");
        };
        assert_eq!(
            type_declaration_id(TypeIdentity {
                ecosystem: "cpp-headers",
                name: "std.basic_string",
            }),
            *id
        );
        assert!(!nullable);
        assert_eq!(3, arguments.len());
        let custom_string_alias = types
            .iter()
            .find(|fact| fact.name == "custom.string")
            .expect("custom string alias");
        assert!(matches!(
            custom_string_alias
                .underlying_type
                .as_ref()
                .and_then(|underlying| underlying.referenced_types.first()),
            Some(TypeRef::Named { name, .. }) if name == "basic_string"
        ));
        let parameters = |name: &str, arity: usize| {
            members
                .iter()
                .filter(|fact| fact.owner == vector.id && fact.name == name)
                .filter_map(|fact| fact.signature.as_ref())
                .find(|signature| signature.parameters.len() == arity)
                .unwrap_or_else(|| panic!("`{name}` with {arity} parameters: {members:#?}"))
                .parameters
                .clone()
        };
        let by_reference = |element: TypeRef| Parameter {
            name: None,
            r#type: TypeRef::ByRef {
                element: Box::new(element),
                reference_kind: TypeRefReferenceKind::Lvalue,
            },
            optional: false,
            variadic: false,
            passing_mode: Default::default(),
        };

        assert_eq!(
            vec![by_reference(named_type("T".to_owned()))],
            parameters("push_back", 1),
            "a `const T&` parameter is a reference to `T`, not the text `const T&`"
        );
        assert_eq!(
            vec![
                by_reference(named_type("std.string".to_owned())),
                Parameter {
                    name: None,
                    r#type: TypeRef::Pointer {
                        element: Box::new(named_type("ns.Widget".to_owned())),
                    },
                    optional: false,
                    variadic: false,
                    passing_mode: Default::default(),
                },
            ],
            parameters("assign", 2),
            "qualification and pointer shape survive"
        );
        assert_eq!(
            vec![by_reference(TypeRef::Named {
                name: "vector".to_owned(),
                arguments: vec![named_type("int".to_owned())],
                nullable: false,
            })],
            parameters("nest", 1),
            "type arguments survive"
        );
        assert_eq!(
            vec![
                Parameter {
                    name: None,
                    r#type: TypeRef::Pointer {
                        element: Box::new(named_type("char".to_owned())),
                    },
                    optional: false,
                    variadic: false,
                    passing_mode: Default::default(),
                },
                Parameter {
                    name: None,
                    r#type: TypeRef::Wildcard {
                        variance: WildcardVariance::Any,
                        bound: None,
                    },
                    optional: false,
                    variadic: true,
                    passing_mode: Default::default(),
                },
            ],
            parameters("log", 2),
            "a `...` pack keeps its position without inventing a type name"
        );

        let insert_ids = members
            .iter()
            .filter(|fact| fact.owner == vector.id && fact.name == "insert")
            .map(|fact| fact.id.clone())
            .collect::<crate::hash::HashSet<_>>();
        assert_eq!(
            2,
            insert_ids.len(),
            "parameter types discriminate two `insert` overloads: {members:#?}"
        );
    }

    /// Every discovered header set, flattened to what a caller can observe:
    /// the dependency id, the include root relative to the workspace, and the
    /// header paths under it.
    fn discovered_header_sets(
        discovery: &DependencyDiscoveryOutcome,
        root: &Path,
    ) -> Vec<(String, String, Vec<String>)> {
        discovery
            .dependencies
            .iter()
            .map(|dependency| {
                let ResolvedDependencyArtifactInput::SourceSet {
                    root: set_root,
                    relative_paths,
                } = &dependency.artifacts[0].input
                else {
                    panic!("C++ dependency uses a source set");
                };
                (
                    dependency.id.clone(),
                    set_root
                        .strip_prefix(root)
                        .expect("an include root lies under the workspace")
                        .to_string_lossy()
                        .replace('\\', "/"),
                    relative_paths
                        .iter()
                        .map(|path| path.to_string_lossy().replace('\\', "/"))
                        .collect(),
                )
            })
            .collect()
    }

    /// An angle include resolves to an external root only through the compile
    /// contexts of the source file that spells it
    /// (`CppCompileContexts::resolve_external_angle_include` answers
    /// `MissingCompileContext` when the database names no entry for that file),
    /// and discovery keeps only `Declared` results. A workspace source the
    /// database does not name therefore contributes nothing at any depth --
    /// including through a header that does exist under a root some *other*
    /// source declares.
    ///
    /// This is the property that lets discovery skip reading and parsing those
    /// sources at all. It is checked here as behavior, on a fixture where the
    /// unnamed source's include would otherwise resolve.
    #[test]
    fn discovery_ignores_sources_the_compile_database_does_not_name() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <widget.h>\nint main() { return 0; }\n")
            .expect("named source");
        // Not in the database. `secret.h` exists under the same include root
        // main.cpp declares, so only the missing compile context keeps it out.
        ProjectFile::new(root.clone(), "src/unlisted.cpp")
            .write("#include <secret.h>\nint unlisted() { return 0; }\n")
            .expect("unnamed source");
        ProjectFile::new(root.clone(), "fake/include/widget.h")
            .write("#include <detail/inner.h>\nclass Widget {};\n")
            .expect("entry header");
        ProjectFile::new(root.clone(), "fake/include/detail/inner.h")
            .write("class Inner {};\n")
            .expect("nested header");
        ProjectFile::new(root.clone(), "fake/include/secret.h")
            .write("class Secret {};\n")
            .expect("unreached header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root.clone(), Language::Cpp);

        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(discovery.complete, "{discovery:#?}");
        assert!(discovery.diagnostics.is_empty(), "{discovery:#?}");
        let sets = discovered_header_sets(&discovery, &root);
        let [(_, set_root, paths)] = sets.as_slice() else {
            panic!("one C++ include-root dependency: {sets:#?}");
        };
        assert_eq!("fake/include", set_root);
        assert_eq!(
            &["detail/inner.h".to_string(), "widget.h".to_string()],
            paths.as_slice(),
            "only the named source's transitive closure is discovered"
        );
    }

    #[test]
    fn discovery_uses_project_decoding_for_named_sources() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let mut source = b"#include <widget.h>\n// legacy byte: ".to_vec();
        source.push(0xff);
        source.extend_from_slice(b"\n");
        std::fs::write(root.join("src/main.cpp"), source).expect("legacy-encoded source");
        ProjectFile::new(root.clone(), "fake/include/widget.h")
            .write("class Widget {};\n")
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root.clone(), Language::Cpp);

        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(discovery.complete, "{discovery:#?}");
        assert_eq!(
            vec![(
                root_dependency_name(&root.join("fake/include")),
                "fake/include".to_owned(),
                vec!["widget.h".to_owned()],
            )],
            discovered_header_sets(&discovery, &root)
        );
    }

    #[test]
    fn discovery_uses_unsaved_project_source_overlays() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let source = ProjectFile::new(root.clone(), "src/main.cpp");
        source
            .write("int main() { return 0; }\n")
            .expect("disk source");
        ProjectFile::new(root.clone(), "fake/include/widget.h")
            .write("class Widget {};\n")
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Cpp));
        let project = OverlayProject::new(base);
        assert!(project.set(
            source.abs_path(),
            "#include <widget.h>\nint main() { return 0; }\n".to_owned(),
        ));

        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(discovery.complete, "{discovery:#?}");
        assert_eq!(
            vec![(
                root_dependency_name(&root.join("fake/include")),
                "fake/include".to_owned(),
                vec!["widget.h".to_owned()],
            )],
            discovered_header_sets(&discovery, &root)
        );
    }

    #[test]
    fn discovery_decodes_legacy_external_headers_lossily() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <widget.h>\n")
            .expect("source");
        std::fs::create_dir_all(root.join("fake/include/detail"))
            .expect("external include directory");
        let mut header = b"#include <detail/inner.h>\n// legacy byte: ".to_vec();
        header.push(0xff);
        header.extend_from_slice(b"\nclass Widget {};\n");
        let raw_byte_limit = (header.len() + "class Inner {};\n".len()) as u64;
        std::fs::write(root.join("fake/include/widget.h"), header).expect("legacy-encoded header");
        ProjectFile::new(root.clone(), "fake/include/detail/inner.h")
            .write("class Inner {};\n")
            .expect("nested header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root.clone(), Language::Cpp);

        let limits = DependencyPackLimits {
            max_total_artifact_bytes: raw_byte_limit,
            ..DependencyPackLimits::default()
        };
        let discovery = resolve_cpp_semantic_pack_dependencies(&project, &limits, None);

        assert!(discovery.complete, "{discovery:#?}");
        assert_eq!(
            vec![(
                root_dependency_name(&root.join("fake/include")),
                "fake/include".to_owned(),
                vec!["detail/inner.h".to_owned(), "widget.h".to_owned()],
            )],
            discovered_header_sets(&discovery, &root)
        );
    }

    /// A source the database names but discovery cannot read is a hole in the
    /// answer, and it says so. Each read failure is charged to that file and
    /// bounded without discarding roots contributed by readable siblings.
    #[test]
    fn unreadable_named_sources_are_bounded_without_losing_readable_siblings() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(root.join("src/bad_one.cpp"), b"int bad_one() {\0}\n")
            .expect("first NUL-bearing source");
        std::fs::write(root.join("src/bad_two.cpp"), b"int bad_two() {\0}\n")
            .expect("second NUL-bearing source");
        ProjectFile::new(root.clone(), "src/good.cpp")
            .write("#include <widget.h>\n")
            .expect("readable source");
        ProjectFile::new(root.clone(), "fake/include/widget.h")
            .write("class Widget {};\n")
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(
                r#"[
                    {"directory":".","file":"src/bad_one.cpp","arguments":["clang++","-isystem","fake/include","-c","src/bad_one.cpp"]},
                    {"directory":".","file":"src/bad_two.cpp","arguments":["clang++","-isystem","fake/include","-c","src/bad_two.cpp"]},
                    {"directory":".","file":"src/good.cpp","arguments":["clang++","-isystem","fake/include","-c","src/good.cpp"]}
                ]"#,
            )
            .expect("database");
        let project = TestProject::new(root.clone(), Language::Cpp);
        let limits = DependencyPackLimits {
            max_diagnostics: 1,
            ..DependencyPackLimits::default()
        };

        let discovery = resolve_cpp_semantic_pack_dependencies(&project, &limits, None);

        assert!(!discovery.complete, "{discovery:#?}");
        assert_eq!(1, discovery.diagnostics.len(), "{discovery:#?}");
        assert_eq!(
            1,
            discovery.suppressed_diagnostics.total(),
            "{discovery:#?}"
        );
        let diagnostic = &discovery.diagnostics[0];
        assert_eq!("cpp.header_discovery_failed", diagnostic.code);
        assert_eq!(
            Some(Path::new("src/bad_one.cpp")),
            diagnostic.location.as_deref().map(Path::new)
        );
        assert_eq!(
            vec![(
                root_dependency_name(&root.join("fake/include")),
                "fake/include".to_owned(),
                vec!["widget.h".to_owned()],
            )],
            discovered_header_sets(&discovery, &root),
            "the readable source still contributes its include root"
        );
    }

    /// The same hole with no diagnostic cap in play, which is the shape a real
    /// workspace hits: the readable sibling contributes its whole include
    /// closure, the bad file surfaces exactly one error diagnostic charged to
    /// it, and nothing is suppressed.
    ///
    /// The last assertion is the one with a policy behind it. Discovery
    /// completeness is a fact about the dependency set rather than a gate on
    /// preparing it (#2887), so the header sets this run did resolve are still
    /// prepared and activated; what the incompleteness buys is
    /// `DependencyDiscoveryEvidence::truncated`, which keeps a name the
    /// unreadable file would have answered unproven rather than proved absent.
    /// That is why the answer has to survive the hole instead of being thrown
    /// away by an early return (#2750): after #2887 the resolved sets are what
    /// the workspace actually gets.
    #[test]
    fn an_unreadable_named_source_leaves_the_other_sources_discovered() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/good.cpp")
            .write("#include <widget.h>\nint good() { return 0; }\n")
            .expect("readable source");
        std::fs::write(root.join("src/binary.cpp"), b"int bad() {\0}\n")
            .expect("NUL-bearing source");
        ProjectFile::new(root.clone(), "fake/include/widget.h")
            .write("#include <detail/inner.h>\nclass Widget {};\n")
            .expect("entry header");
        ProjectFile::new(root.clone(), "fake/include/detail/inner.h")
            .write("class Inner {};\n")
            .expect("nested header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/good.cpp","arguments":["clang++","-isystem","fake/include","-c","src/good.cpp"]},{"directory":".","file":"src/binary.cpp","arguments":["clang++","-isystem","fake/include","-c","src/binary.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root.clone(), Language::Cpp);

        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(
            vec![(
                root_dependency_name(&root.join("fake/include")),
                "fake/include".to_owned(),
                vec!["detail/inner.h".to_owned(), "widget.h".to_owned()],
            )],
            discovered_header_sets(&discovery, &root),
            "the readable source still yields its whole include closure"
        );
        let [diagnostic] = discovery.diagnostics.as_slice() else {
            panic!("exactly one read failure: {discovery:#?}");
        };
        assert_eq!("cpp.header_discovery_failed", diagnostic.code);
        assert_eq!(
            DependencyPackDiagnosticSeverity::Error,
            diagnostic.severity,
            "{diagnostic:#?}"
        );
        assert_eq!(
            Some(Path::new("src/binary.cpp")),
            diagnostic.location.as_deref().map(Path::new),
            "the diagnostic is charged to the file it happened on"
        );
        assert_eq!(
            0,
            discovery.suppressed_diagnostics.total(),
            "{discovery:#?}"
        );
        assert!(
            !discovery.complete,
            "a read hole keeps the run incomplete: {discovery:#?}"
        );
    }

    /// An external header the traversal cannot read is dropped before its
    /// source set records it, so no artifact a producer later materializes
    /// names a path that already failed to read here. The readable header
    /// beside it stays a member of that set (#2750).
    #[test]
    fn an_unreadable_external_header_is_not_recorded_into_its_source_set() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <widget.h>\n#include <broken.h>\n")
            .expect("source");
        ProjectFile::new(root.clone(), "fake/include/widget.h")
            .write("class Widget {};\n")
            .expect("readable header");
        std::fs::write(root.join("fake/include/broken.h"), b"class Broken {\0};\n")
            .expect("NUL-bearing header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root.clone(), Language::Cpp);

        let discovery = resolve_cpp_semantic_pack_dependencies(
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(
            vec![(
                root_dependency_name(&root.join("fake/include")),
                "fake/include".to_owned(),
                vec!["widget.h".to_owned()],
            )],
            discovered_header_sets(&discovery, &root),
            "the unreadable header is not a member of the published set"
        );
        let [diagnostic] = discovery.diagnostics.as_slice() else {
            panic!("exactly one read failure: {discovery:#?}");
        };
        assert_eq!("cpp.header_discovery_failed", diagnostic.code);
        assert!(
            Path::new(
                diagnostic
                    .location
                    .as_deref()
                    .expect("the diagnostic names the header")
            )
            .ends_with("fake/include/broken.h"),
            "{diagnostic:#?}"
        );
        assert!(!discovery.complete, "{discovery:#?}");
    }

    #[test]
    fn dependency_limit_makes_discovery_incomplete() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/main.cpp")
            .write("#include <one.hpp>\n#include <two.hpp>\nint main() {}\n")
            .expect("source");
        ProjectFile::new(root.clone(), "first/include/one.hpp")
            .write("class One {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "second/include/two.hpp")
            .write("class Two {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","first/include","-isystem","second/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project = TestProject::new(root, Language::Cpp);
        let limits = DependencyPackLimits {
            max_dependencies: 1,
            ..DependencyPackLimits::default()
        };

        let discovery = resolve_cpp_semantic_pack_dependencies(&project, &limits, None);

        assert!(!discovery.complete, "{discovery:#?}");
        assert_eq!(1, discovery.dependencies.len());
        assert_eq!(1, discovery.suppressed_diagnostics.total());
        assert!(
            discovery
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.dependencies"),
            "{discovery:#?}"
        );
    }

    #[test]
    fn activated_header_pack_indexes_a_direct_external_member_route() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let source =
            "#include <vector>\nvoid add(std::vector<int>& values) { values.push_back(1); }\n";
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write(source).expect("source");
        ProjectFile::new(root.clone(), "fake/include/vector")
            .write("#include <bits/vector_impl>\n")
            .expect("entry header");
        ProjectFile::new(root.clone(), "fake/include/bits/vector_impl")
            .write("namespace std { template <typename T> class vector { public: void push_back(const T&); }; }")
            .expect("declaration header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let cancellation = CancellationToken::new();
        let start = source.find("push_back").expect("member start");
        let request = || DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + "push_back".len()),
        };
        let [(_, unindexed_trace)] = resolve_definition_batch_with_trace(
            workspace.analyzer(),
            vec![request()],
            file.clone(),
            Arc::from(source),
            &cancellation,
        )
        .try_into()
        .expect("one unindexed lookup");
        assert!(
            unindexed_trace.candidates.iter().any(|candidate| {
                candidate.boundary == BoundaryStatus::ExternalDeclaredUnindexed
            }),
            "{unindexed_trace:#?}"
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral catalog");
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: Vec::new(),
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: "bifrost.external.cpp-headers".to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        let outcome = workspace.activate_dependency_packs(
            &AnalyzerConfig::default(),
            &[DependencyPackEcosystem::Cpp],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits: DependencyPackLimits::default(),
                cancellation: &cancellation,
            },
        );
        assert!(outcome.complete(), "{outcome:#?}");
        assert!(matches!(
            outcome.runtime,
            Some(SemanticModelRuntimeOutcome::Ready { .. })
        ));
        let overlay = workspace
            .analyzer()
            .semantic_model_overlay()
            .expect("C++ overlay");
        let cpp = crate::analyzer::resolve_analyzer::<CppAnalyzer>(workspace.analyzer())
            .expect("C++ analyzer");
        assert!(
            external_member_resolution(cpp, Some(&overlay), &file, "std::vector", "push_back")
                == CppExternalMemberResolution::Indexed,
            "outcome={outcome:#?}\nsymbols={:#?}",
            overlay.symbols()
        );
        assert_eq!(
            CppExternalMemberResolution::Indexed,
            external_member_resolution(cpp, Some(&overlay), &file, "std.vector", "push_back")
        );
        assert_eq!(
            CppExternalMemberResolution::Absent,
            external_member_resolution(cpp, Some(&overlay), &file, "std.vector", "push_bak")
        );
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 2,
            },
            cpp.external_header_closure_work_counts_for_test(),
            "all external member and boundary lookups share one closure"
        );

        let [(lookup, trace)] = resolve_definition_batch_with_trace(
            workspace.analyzer(),
            vec![request()],
            file,
            Arc::from(source),
            &cancellation,
        )
        .try_into()
        .expect("one lookup");
        assert!(
            trace.candidates.iter().any(|candidate| {
                matches!(
                    &candidate.candidate,
                    TraceCandidateRef::ExternalRoute { name } if name == "push_back"
                ) && candidate.boundary == BoundaryStatus::ExternalIndexed
                    && candidate.external_target.is_some()
            }),
            "lookup={lookup:#?}\ntrace={trace:#?}"
        );
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 2,
            },
            cpp.external_header_closure_work_counts_for_test(),
            "a later forward batch reuses the published closure"
        );
    }

    #[test]
    fn activated_basic_string_pack_lowers_exact_copy_and_move_operations() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let source = concat!(
            "#include <string>\n",
            "std::string copy(std::string source) {\n",
            "  std::string copied = source;\n",
            "  std::string assigned;\n",
            "  assigned = source;\n",
            "  return copied;\n",
            "}\n",
            "std::string relay(std::string source) {\n",
            "  return source;\n",
            "}\n",
            "std::string relay_local(std::string source) {\n",
            "  std::string local = source;\n",
            "  return local;\n",
            "}\n",
            "std::string relay_const(const std::string source) {\n",
            "  return source;\n",
            "}\n",
            "std::string from_literal() {\n",
            "  return \"tainted\";\n",
            "}\n",
            "std::string from_wide_literal() {\n",
            "  return L\"tainted\";\n",
            "}\n",
        );
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write(source).expect("source");
        ProjectFile::new(root.clone(), "fake/include/string")
            .write(concat!(
                "namespace std {\n",
                "template <class C, class Traits = char_traits<C>, class Alloc = allocator<C>>\n",
                "class basic_string { public: basic_string(); basic_string(const basic_string&); basic_string(basic_string&&); basic_string(const C*, const Alloc& = Alloc()); basic_string& operator=(const basic_string&); basic_string& operator=(basic_string&&); };\n",
                "using string = basic_string<char, char_traits<char>, allocator<char>>;\n",
                "}\n",
            ))
            .expect("header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral catalog");
        let cancellation = CancellationToken::new();
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version"),
            evidence: Vec::new(),
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: "bifrost.external.cpp-headers".to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        let outcome = workspace.activate_dependency_packs(
            &AnalyzerConfig::default(),
            &[DependencyPackEcosystem::Cpp],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits: DependencyPackLimits::default(),
                cancellation: &cancellation,
            },
        );
        assert!(outcome.complete(), "{outcome:#?}");

        let snapshot = workspace.analyzer().active_semantic_model_snapshot();
        let _scope =
            AnalyzerQueryScope::with_active_semantic_model_snapshot(workspace.analyzer(), snapshot);
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("C++ semantic materialization")
        else {
            panic!("C++ semantic materialization must complete");
        };
        let copy = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("copy")
            })
            .expect("copy procedure");
        let transfers = copy
            .points()
            .iter()
            .flat_map(|point| point.events.windows(2))
            .filter(|events| {
                matches!(
                    (&events[0].effect, &events[1].effect),
                    (
                        SemanticEffect::Assignment { target, value },
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Transfer(transfer),
                            source,
                            target: flow_target,
                        }
                    ) if transfer.kind == TransferKind::Copy
                        && matches!(transfer.operation, TransferOperation::CallSite(_))
                        && source == value
                        && flow_target == target
                )
            })
            .count();
        assert_eq!(
            2, transfers,
            "exact copy construction and assignment must publish adjacent call-backed transfers: {copy:#?}",
        );

        let relay = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("relay")
            })
            .expect("relay procedure");
        let move_transfers = relay
            .points()
            .iter()
            .flat_map(|point| point.events.windows(2))
            .filter(|events| {
                matches!(
                    (&events[0].effect, &events[1].effect),
                    (
                        SemanticEffect::Assignment { target, value },
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Transfer(transfer),
                            source,
                            target: flow_target,
                        }
                    ) if transfer.kind
                        == TransferKind::Move {
                            invalidation: crate::analyzer::semantic::MoveInvalidation::Invalidated,
                        }
                        && matches!(transfer.operation, TransferOperation::CallSite(_))
                        && source == value
                        && flow_target == target
                )
            })
            .count();
        assert_eq!(
            1, move_transfers,
            "a by-value basic_string parameter return must publish one adjacent call-backed invalidating move: {relay:#?}",
        );
        assert_eq!(
            1,
            relay
                .points()
                .iter()
                .flat_map(|point| &point.events)
                .filter(|event| matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Return,
                        ..
                    }
                ))
                .count(),
            "the moved value must feed the procedure's normal return port: {relay:#?}",
        );
        assert!(
            !relay.gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::Values
                    && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
            }),
            "an exact parameter move return must not retain a return-transfer gap: {relay:#?}",
        );

        let relay_local = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("relay_local")
            })
            .expect("relay_local procedure");
        let local_copy_transfers = relay_local
            .points()
            .iter()
            .flat_map(|point| point.events.windows(2))
            .filter(|events| {
                matches!(
                    (&events[0].effect, &events[1].effect),
                    (
                        SemanticEffect::Assignment { target, value },
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Transfer(transfer),
                            source,
                            target: flow_target,
                        }
                    ) if transfer.kind == TransferKind::Copy
                        && matches!(transfer.operation, TransferOperation::CallSite(_))
                        && source == value
                        && flow_target == target
                )
            })
            .count();
        assert_eq!(
            1, local_copy_transfers,
            "named-local copy initialization remains an exact copy transfer: {relay_local:#?}",
        );
        assert_eq!(
            1,
            relay_local
                .gaps()
                .iter()
                .filter(|gap| {
                    gap.capability == SemanticCapability::Values
                        && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                })
                .count(),
            "returning a named local must retain its typed return-transfer gap: {relay_local:#?}",
        );

        let relay_const = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("relay_const")
            })
            .expect("relay_const procedure");
        assert!(
            !relay_const
                .points()
                .iter()
                .any(|point| point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Transfer(
                                crate::analyzer::semantic::ValueTransfer {
                                    kind: TransferKind::Move { .. },
                                    ..
                                }
                            ),
                            ..
                        }
                    )
                })),
            "a const by-value parameter cannot select the move constructor: {relay_const:#?}",
        );
        assert!(
            relay_const.gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::Values
                    && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
            }),
            "a const parameter return must retain typed return incompleteness: {relay_const:#?}",
        );

        let from_literal = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("from_literal")
            })
            .expect("from_literal procedure");
        assert!(
            from_literal.points().iter().any(|point| {
                point.events.windows(2).any(|events| {
                    matches!(
                        (&events[0].effect, &events[1].effect),
                        (
                            SemanticEffect::Assignment { target, value },
                            SemanticEffect::ValueFlow {
                                kind: ValueFlowKind::Transfer(transfer),
                                source,
                                target: flow_target,
                            }
                        ) if transfer.kind == TransferKind::Conversion {
                            preservation: crate::analyzer::semantic::ValuePreservation::Preserving,
                        }
                            && matches!(transfer.operation, TransferOperation::CallSite(_))
                            && source == value
                            && flow_target == target
                    )
                })
            }),
            "narrow character data must use the exact value-preserving constructor: {from_literal:#?}",
        );
        assert!(
            !from_literal.gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::Values
                    && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
            }),
            "an exact character-data return must not retain a return-transfer gap: {from_literal:#?}",
        );
        assert_eq!(
            1,
            from_literal
                .points()
                .iter()
                .flat_map(|point| &point.events)
                .filter(|event| matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Return,
                        ..
                    }
                ))
                .count(),
            "the exact character-data construction must feed the normal return port: {from_literal:#?}",
        );

        let from_wide_literal = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("from_wide_literal")
            })
            .expect("from_wide_literal procedure");
        assert!(
            !from_wide_literal
                .points()
                .iter()
                .any(|point| point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Transfer(_),
                            ..
                        }
                    )
                })),
            "a wide literal must not acquire the narrow character-data constructor: {from_wide_literal:#?}",
        );
        assert!(
            from_wide_literal.gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::Values
                    && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
            }),
            "the rejected wide-literal return must retain typed incompleteness: {from_wide_literal:#?}",
        );
    }

    #[test]
    fn interrupted_external_header_closure_is_not_published() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <one.hpp>\n").expect("source");
        ProjectFile::new(root.clone(), "fake/include/one.hpp")
            .write("#include <two.hpp>\nclass One {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "fake/include/two.hpp")
            .write("class Two {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let interrupted = directly_reached_external_headers_while(&analyzer, &file, &|| {
            checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3
        });
        assert!(interrupted.is_none(), "interrupted work is not an answer");
        let interrupted_counts = analyzer.external_header_closure_work_counts_for_test();
        assert_eq!(1, interrupted_counts.builds);

        let complete = directly_reached_external_headers_while(&analyzer, &file, &|| true)
            .expect("fresh query rebuilds");
        let Some(headers) = complete.headers() else {
            panic!("complete closure");
        };
        assert_eq!(2, headers.len());
        let complete_counts = analyzer.external_header_closure_work_counts_for_test();
        assert_eq!(2, complete_counts.builds);
        assert_eq!(
            interrupted_counts.external_header_parses + 2,
            complete_counts.external_header_parses
        );

        let cached = directly_reached_external_headers_while(&analyzer, &file, &|| true)
            .expect("cached closure");
        assert_eq!(2, cached.headers().expect("complete cached closure").len());
        assert_eq!(
            complete_counts,
            analyzer.external_header_closure_work_counts_for_test(),
            "completed work is published exactly once"
        );
    }

    #[test]
    fn unavailable_compile_context_is_cached_without_claiming_headers() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <missing.hpp>\n").expect("source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);

        for _ in 0..2 {
            let outcome = directly_reached_external_headers_while(&analyzer, &file, &|| true)
                .expect("stable unavailable outcome");
            assert!(outcome.headers().is_none());
        }
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 0,
            },
            analyzer.external_header_closure_work_counts_for_test()
        );
    }

    #[test]
    fn conflicting_compile_context_is_cached_without_claiming_one_header() {
        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <shared.hpp>\n").expect("source");
        ProjectFile::new(root.clone(), "first/include/shared.hpp")
            .write("class First {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "second/include/shared.hpp")
            .write("class Second {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(
                r#"[
                    {"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","first/include","-c","src/main.cpp"]},
                    {"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","second/include","-c","src/main.cpp"]}
                ]"#,
            )
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);

        for _ in 0..2 {
            let outcome = directly_reached_external_headers_while(&analyzer, &file, &|| true)
                .expect("stable conflicting outcome");
            assert!(outcome.headers().is_none());
        }
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 0,
            },
            analyzer.external_header_closure_work_counts_for_test()
        );
    }

    #[test]
    fn analyzer_update_discards_external_header_closure_state() {
        use crate::analyzer::IAnalyzer;
        use std::collections::BTreeSet;

        let temp = tempfile::tempdir().expect("temp root");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/main.cpp");
        file.write("#include <one.hpp>\n").expect("source");
        ProjectFile::new(root.clone(), "fake/include/one.hpp")
            .write("class One {};\n")
            .expect("first header");
        ProjectFile::new(root.clone(), "fake/include/two.hpp")
            .write("class Two {};\n")
            .expect("second header");
        ProjectFile::new(root.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-isystem","fake/include","-c","src/main.cpp"]}]"#)
            .expect("database");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);
        let first = directly_reached_external_headers_while(&analyzer, &file, &|| true)
            .expect("first closure");
        assert_eq!(1, first.headers().expect("complete first closure").len());

        file.write("#include <one.hpp>\n#include <two.hpp>\n")
            .expect("updated source");
        let updated = analyzer.update(&BTreeSet::from([file.clone()]));
        let second = directly_reached_external_headers_while(&updated, &file, &|| true)
            .expect("updated closure");
        assert_eq!(2, second.headers().expect("complete updated closure").len());
        assert_eq!(
            crate::analyzer::cpp::ExternalHeaderClosureWorkCounts {
                builds: 1,
                external_header_parses: 2,
            },
            updated.external_header_closure_work_counts_for_test()
        );
    }
}
